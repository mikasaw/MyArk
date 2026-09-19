// MyArk memory module: physical memory read / write + layout enumeration.
//
// Implements READ_PHYSICAL, WRITE_PHYSICAL, and QUERY_PHYSICAL_LAYOUT.
// Both access paths validate the target PA against the RAM ranges
// reported by MmGetPhysicalMemoryRanges -- MMIO / reserved / wrapped
// addresses are denied before any access. Writes additionally require
// the operator to opt in via the AllowPhysicalWrite registry value
// (default deny), because an arbitrary physical write can rewrite kernel
// state.
//
// Access mechanism (2026-09-15, S11.6): READ uses the documented
// MmCopyMemory(MM_COPY_MEMORY_PHYSICAL) -- MmMapIoSpace returns NULL for
// plain RAM pages on modern builds, which made every non-trivial read
// fail (the page-table walker hit the same wall, see memory_pagetable.c).
// WRITE cannot use MmCopyMemory (read-only primitive), so it maps the
// target through the \Device\PhysicalMemory section object and copies
// through the kernel VA; the view is 64 KiB-aligned because
// ZwMapViewOfSection enforces the section allocation granularity on
// SectionOffset. Neither path has any page-alignment requirement on the
// target PA itself.
//
// QUERY_PHYSICAL_LAYOUT walks the array returned by MmGetPhysicalMemoryRanges
// (a static structure populated by the kernel at boot). Each entry is
// copied into a caller-supplied buffer along with a total-physical
// accumulator so the table can show "X regions, Y total".

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "memory_module.h"

#if MYARK_MODULE_MEMORY

#define MYARK_REG_MEMORY_KEY_PATH \
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\MyArkCore\\Modules\\memory"
#define MYARK_REG_WRITE_ALLOW_VALUE  L"AllowPhysicalWrite"


//
// Policy gate for WRITE_PHYSICAL. Writing arbitrary physical addresses can
// rewrite kernel pool or page tables, so the default is deny; the operator
// must set HKLM\...\Services\MyArkCore\Modules\memory : AllowPhysicalWrite
// (REG_DWORD != 0) to opt in. Checked per call so the knob takes effect
// without a reboot. Reads the registry at PASSIVE_LEVEL (the sequential
// queue keeps every handler there).
//
static
BOOLEAN
MyArkMemoryPhysicalWriteAllowed(
    VOID)
{
    UNICODE_STRING        keyPath;
    UNICODE_STRING        valueName;
    OBJECT_ATTRIBUTES     oa;
    HANDLE                keyHandle = NULL;
    NTSTATUS              status;
    BOOLEAN               allowed = FALSE;
    UCHAR                 buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    ULONG                 resultLength = 0;

    RtlInitUnicodeString(&keyPath, MYARK_REG_MEMORY_KEY_PATH);
    RtlInitUnicodeString(&valueName, MYARK_REG_WRITE_ALLOW_VALUE);
    InitializeObjectAttributes(&oa,
                               &keyPath,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    if (!NT_SUCCESS(ZwOpenKey(&keyHandle, KEY_READ, &oa))) {
        return FALSE;
    }

    status = ZwQueryValueKey(keyHandle,
                             &valueName,
                             KeyValuePartialInformation,
                             buffer,
                             sizeof(buffer),
                             &resultLength);
    if (NT_SUCCESS(status)) {
        PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
        allowed = (info->Type == REG_DWORD) &&
                  (info->DataLength >= sizeof(ULONG)) &&
                  (*(PULONG)info->Data != 0);
    }

    ZwClose(keyHandle);
    return allowed;
}


//
// Validate that [Pa, Pa+Size) lies fully inside a RAM range reported by
// MmGetPhysicalMemoryRanges. Anything else (MMIO, device memory, holes,
// bogus wrapped addresses) is denied -- READ/WRITE_PHYSICAL must not
// become a device-memory or reserved-region primitive. Always frees the
// ranges array the kernel allocated for us.
//
static
NTSTATUS
MyArkMemoryValidatePhysicalRange(
    _In_ UINT64 Pa,
    _In_ SIZE_T Size)
{
    PPHYSICAL_MEMORY_RANGE ranges;
    UINT64                 end;

    if (Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    end = Pa + (UINT64)Size;
    if (end < Pa) {
        return STATUS_INVALID_PARAMETER;   // wrapped
    }

    ranges = MmGetPhysicalMemoryRanges();
    if (ranges == NULL) {
        return STATUS_ACCESS_DENIED;
    }

    for (ULONG i = 0;
         ranges[i].BaseAddress.QuadPart != 0 || ranges[i].NumberOfBytes.QuadPart != 0;
         i++) {
        UINT64 base = (UINT64)ranges[i].BaseAddress.QuadPart;
        UINT64 len  = (UINT64)ranges[i].NumberOfBytes.QuadPart;
        if (Pa >= base && end <= base + len) {
            ExFreePool(ranges);
            return STATUS_SUCCESS;
        }
    }

    ExFreePool(ranges);
    return STATUS_ACCESS_DENIED;
}


//
// Write Size bytes from Source to the physical address Pa through the
// \Device\PhysicalMemory section object. MmCopyMemory is read-only and
// MmMapIoSpace refuses plain RAM pages, so a section view is the only
// documented route for arbitrary physical writes. The view base must be
// aligned on the section allocation granularity (64 KiB) because
// ZwMapViewOfSection validates SectionOffset against it; the copy itself
// stays exactly on [Pa, Pa+Size), which the RAM-range gate validated.
// PASSIVE_LEVEL required (the sequential queue guarantees it).
//
#define MYARK_PHYS_VIEW_GRANULARITY 0x10000

static
NTSTATUS
MyArkMemoryWritePhysicalViaSection(
    _In_ UINT64 Pa,
    _In_ PVOID Source,
    _In_ SIZE_T Size)
{
    UNICODE_STRING     name;
    OBJECT_ATTRIBUTES  oa;
    HANDLE             section  = NULL;
    PVOID              base     = NULL;
    SIZE_T             viewSize = 0;
    LARGE_INTEGER      offset;
    UINT64             viewBase = Pa & ~((UINT64)MYARK_PHYS_VIEW_GRANULARITY - 1);
    UINT64             offInView = Pa - viewBase;
    NTSTATUS           status;

    RtlInitUnicodeString(&name, L"\\Device\\PhysicalMemory");
    InitializeObjectAttributes(&oa,
                               &name,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    status = ZwOpenSection(&section, SECTION_MAP_WRITE | SECTION_MAP_READ, &oa);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    offset.QuadPart = (LONGLONG)viewBase;
    viewSize = (SIZE_T)(offInView + Size);

    status = ZwMapViewOfSection(section,
                                ZwCurrentProcess(),
                                &base,
                                0,           // ZeroBits
                                0,           // CommitSize (unused for mapped sections)
                                &offset,     // SectionOffset in/out
                                &viewSize,
                                ViewUnmap,
                                0,           // AllocationType
                                PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        ZwClose(section);
        return status;
    }

    __try {
        RtlCopyMemory((PUCHAR)base + offInView, Source, Size);
        status = STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    ZwUnmapViewOfSection(ZwCurrentProcess(), base);
    ZwClose(section);
    return status;
}


//
// IOCTL_MYARK_MEMORY_READ_PHYSICAL handler.
//
// Clamps Size to MYARK_MEMORY_RW_MAX_BYTES, then copies Size bytes from
// the validated PA range into the output buffer's Data[] via
// MmCopyMemory(MM_COPY_MEMORY_PHYSICAL) -- no mapping, no unmapping, and
// no page-alignment requirement on the target PA.
//
NTSTATUS
MyArkMemoryIoctlReadPhysical(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    PMYARK_MEMORY_READ_PHYSICAL_INPUT  inBuf  = NULL;
    PMYARK_MEMORY_READ_PHYSICAL_OUTPUT outBuf = NULL;
    size_t                            inSize  = 0;
    NTSTATUS                          status;
    SIZE_T                            wantSize;
    UINT64                            pa;
    UINT32                            bytesRead = 0;

    UNREFERENCED_PARAMETER(Device);

    if (InputBufferLength < sizeof(MYARK_MEMORY_READ_PHYSICAL_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_MEMORY_READ_PHYSICAL_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Snapshot Pa before the output fetch: METHOD_BUFFERED means input and
    // output share one SystemBuffer, and RtlZeroMemory(outBuf) below would
    // otherwise wipe the input fields (the 2026-09-15 fix; the old code
    // silently read physical address 0 after the zero).
    //
    pa      = inBuf->Pa;
    wantSize = inBuf->Size;
    if (wantSize == 0 || wantSize > MYARK_MEMORY_RW_MAX_BYTES) {
        wantSize = MYARK_MEMORY_RW_MAX_BYTES;
    }
    if (OutputBufferLength < sizeof(MYARK_MEMORY_READ_PHYSICAL_OUTPUT) + wantSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Policy: only RAM ranges reported by the memory manager may be read.
    // MMIO / reserved / wrapped addresses are rejected before any mapping.
    //
    status = MyArkMemoryValidatePhysicalRange(pa, wantSize);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_MEMORY,
                    "ReadPhysical pa=0x%llX size=%llu: range denied (0x%08X)",
                    (unsigned long long)pa,
                    (unsigned long long)wantSize,
                    status);
        return STATUS_ACCESS_DENIED;
    }

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_MEMORY_READ_PHYSICAL_OUTPUT) + wantSize,
                                         (PVOID*)&outBuf,
                                         &OutputBufferLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(outBuf, sizeof(*outBuf));

    //
    // MmCopyMemory(MM_COPY_MEMORY_PHYSICAL) has no page-alignment
    // requirement and works for plain RAM pages where MmMapIoSpace
    // returns NULL. A short copy is reported as STATUS_INVALID_ADDRESS
    // with the actually-copied count in Copied -- honor it so a partial
    // read surfaces as PARTIAL_COPY in the in-band status instead of a
    // bare UNSUCCESSFUL.
    //
    {
        MM_COPY_ADDRESS src;
        SIZE_T          copied = 0;

        src.PhysicalAddress.QuadPart = (LONGLONG)pa;
        status = MmCopyMemory(outBuf->Data, src, wantSize,
                              MM_COPY_MEMORY_PHYSICAL, &copied);
        bytesRead = (NT_SUCCESS(status) || status == STATUS_INVALID_ADDRESS)
                        ? (UINT32)copied : 0;
        if (!NT_SUCCESS(status) && status != STATUS_INVALID_ADDRESS) {
            outBuf->Status = (UINT32)status;
            *BytesReturned = sizeof(*outBuf);
            TraceEvents(TRACE_LEVEL_WARNING,
                        MYARK_TRACE_MEMORY,
                        "ReadPhysical pa=0x%llX size=%llu: copy failed 0x%08X",
                        (unsigned long long)pa,
                        (unsigned long long)wantSize,
                        status);
            return STATUS_SUCCESS;
        }
    }

    outBuf->Status = (bytesRead == wantSize) ? (UINT32)STATUS_SUCCESS
                   : (bytesRead > 0)         ? (UINT32)STATUS_PARTIAL_COPY
                                             : (UINT32)STATUS_UNSUCCESSFUL;
    outBuf->BytesRead = bytesRead;

    *BytesReturned = sizeof(*outBuf) + bytesRead;

    TraceEvents(TRACE_LEVEL_VERBOSE,
                MYARK_TRACE_MEMORY,
                "ReadPhysical pa=0x%llX size=%llu -> %u bytes (status=0x%08X)",
                (unsigned long long)pa,
                (unsigned long long)wantSize,
                bytesRead,
                outBuf->Status);

    return STATUS_SUCCESS;
}


//
// IOCTL_MYARK_MEMORY_WRITE_PHYSICAL handler. Mirrors ReadPhysical but
// copies from the input buffer's Data[] into the kernel VA. The input
// carries the bytes so we fetch only the fixed-size header first and
// then re-fetch with the trailing Data[] length.
//
NTSTATUS
MyArkMemoryIoctlWritePhysical(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    PMYARK_MEMORY_WRITE_PHYSICAL_INPUT  inBuf  = NULL;
    PMYARK_MEMORY_WRITE_PHYSICAL_OUTPUT outBuf = NULL;
    size_t                             inSize  = 0;
    NTSTATUS                           status;
    SIZE_T                             wantSize;
    UINT64                             pa;
    UINT32                             bytesWritten = 0;

    UNREFERENCED_PARAMETER(Device);

    //
    // Hard policy gate first: physical writes are denied unless the
    // operator opted in via the AllowPhysicalWrite registry value, and
    // even then only inside validated RAM ranges. Fail closed with a
    // plain status so R3 surfaces "access denied" instead of a result
    // struct that looks like a completed write.
    //
    if (!MyArkMemoryPhysicalWriteAllowed()) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_MEMORY,
                    "WritePhysical denied: AllowPhysicalWrite not enabled");
        return STATUS_ACCESS_DENIED;
    }

    if (OutputBufferLength < sizeof(MYARK_MEMORY_WRITE_PHYSICAL_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (InputBufferLength < sizeof(MYARK_MEMORY_WRITE_PHYSICAL_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // FIELD_OFFSET (not sizeof) is the payload start: sizeof includes the
    // alignment padding after Data[1], which would make the tail payload
    // bytes unreachable and shift the copy window by 8 bytes.
    //
    wantSize = InputBufferLength - FIELD_OFFSET(MYARK_MEMORY_WRITE_PHYSICAL_INPUT, Data);
    if (wantSize == 0) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (wantSize > MYARK_MEMORY_RW_MAX_BYTES) {
        wantSize = MYARK_MEMORY_RW_MAX_BYTES;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        FIELD_OFFSET(MYARK_MEMORY_WRITE_PHYSICAL_INPUT, Data) + wantSize,
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Snapshot Pa AFTER the input fetch (inBuf is valid only from here on)
    // and BEFORE the output fetch: METHOD_BUFFERED means input and output
    // share one SystemBuffer, and RtlZeroMemory(outBuf) below would
    // otherwise wipe the Pa/Size fields (the trailing Data[] payload lives
    // beyond the 16-byte output header and survives).
    // 2026-09-15 lesson: an earlier revision snapshotted Pa *before* this
    // fetch and dereferenced the still-NULL inBuf -- six 0x3B bugchecks
    // (AV_MyArkCore!MyArkMemoryIoctlWritePhysical+0x149) in one night.
    //
    pa = inBuf->Pa;

    //
    // Same RAM-range policy as the read path, applied after the opt-in
    // gate above.
    //
    status = MyArkMemoryValidatePhysicalRange(pa, wantSize);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_MEMORY,
                    "WritePhysical pa=0x%llX size=%llu: range denied (0x%08X)",
                    (unsigned long long)pa,
                    (unsigned long long)wantSize,
                    status);
        return STATUS_ACCESS_DENIED;
    }

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_MEMORY_WRITE_PHYSICAL_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &OutputBufferLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(outBuf, sizeof(*outBuf));

    status = MyArkMemoryWritePhysicalViaSection(pa, inBuf->Data, wantSize);
    bytesWritten = NT_SUCCESS(status) ? (UINT32)wantSize : 0;
    if (!NT_SUCCESS(status)) {
        outBuf->Status = (UINT32)status;
        *BytesReturned = sizeof(*outBuf);
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_MEMORY,
                    "WritePhysical pa=0x%llX size=%llu: section write failed 0x%08X",
                    (unsigned long long)pa,
                    (unsigned long long)wantSize,
                    status);
        return STATUS_SUCCESS;
    }

    outBuf->Status       = (bytesWritten == wantSize) ? (UINT32)STATUS_SUCCESS : (UINT32)STATUS_PARTIAL_COPY;
    outBuf->BytesWritten = bytesWritten;

    *BytesReturned = sizeof(*outBuf);

    TraceEvents(TRACE_LEVEL_WARNING,
                MYARK_TRACE_MEMORY,
                "WritePhysical pa=0x%llX size=%llu -> %u bytes (status=0x%08X)",
                (unsigned long long)pa,
                (unsigned long long)wantSize,
                bytesWritten,
                outBuf->Status);

    return STATUS_SUCCESS;
}


//
// IOCTL_MYARK_MEMORY_QUERY_PHYSICAL_LAYOUT handler.
//
// MmGetPhysicalMemoryRanges returns a NULL-terminated array of
// PHYSICAL_MEMORY_RANGE entries; the array is allocated in nonpaged pool
// and is safe to walk at IRQL == PASSIVE_LEVEL. We stream the entries
// into the caller-provided output buffer, capping at the requested
// MaxEntries (default 256) and stopping early when the buffer is full.
//
NTSTATUS
MyArkMemoryIoctlQueryPhysicalLayout(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    PMYARK_MEMORY_PHYSICAL_LAYOUT_OUTPUT outBuf = NULL;
    PPHYSICAL_MEMORY_RANGE               ranges = NULL;
    size_t                               headerSize;
    NTSTATUS                             status;
    ULONG                                written = 0;
    ULONG                                cap;
    UINT64                               total  = 0;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);

    headerSize = FIELD_OFFSET(MYARK_MEMORY_PHYSICAL_LAYOUT_OUTPUT, Entries[0]);

    cap = MYARK_MEMORY_PHYSICAL_DEFAULT_MAX;
    if (OutputBufferLength < headerSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (OutputBufferLength > headerSize) {
        cap = (ULONG)((OutputBufferLength - headerSize) / sizeof(MYARK_MEMORY_PHYSICAL_REGION));
        if (cap > MYARK_MEMORY_PHYSICAL_HARD_CAP) {
            cap = MYARK_MEMORY_PHYSICAL_HARD_CAP;
        }
    }

    status = MyArkIoctlFetchOutputBuffer(Request, OutputBufferLength, (PVOID*)&outBuf, &OutputBufferLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(outBuf, headerSize);

    ranges = MmGetPhysicalMemoryRanges();
    if (ranges == NULL) {
        outBuf->Size  = (UINT32)headerSize;
        outBuf->Count = 0;
        outBuf->TotalPhysical = 0;
        *BytesReturned = headerSize;
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_MEMORY,
                    "QueryPhysicalLayout: MmGetPhysicalMemoryRanges returned NULL");
        return STATUS_SUCCESS;
    }

    for (ULONG i = 0; ranges[i].BaseAddress.QuadPart != 0 && written < cap; i++) {
        PMYARK_MEMORY_PHYSICAL_REGION row = &outBuf->Entries[written];
        row->BasePa = (UINT64)ranges[i].BaseAddress.QuadPart;
        row->Size   = (UINT64)ranges[i].NumberOfBytes.QuadPart;
        row->Type   = MYARK_MEMORY_REGION_PHYSICAL;
        row->Reserved = 0;
        total += row->Size;
        written++;
    }

    ExFreePool(ranges);

    outBuf->Size           = (UINT32)(headerSize + written * sizeof(MYARK_MEMORY_PHYSICAL_REGION));
    outBuf->Count          = written;
    outBuf->TotalPhysical  = total;

    *BytesReturned = outBuf->Size;

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_MEMORY,
                "QueryPhysicalLayout: %u regions, %llu total bytes",
                written,
                (unsigned long long)total);

    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_MEMORY