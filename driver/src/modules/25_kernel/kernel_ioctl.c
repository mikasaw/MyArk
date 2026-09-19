// MyArk kernel module: IOCTL handlers + KeServiceDescriptorTable walker.

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkKernelIoctl.h"
#include "../../../shared/driver/MyArkPoolAlloc.h"
#include "kernel_descriptor.h"
#include "kernel_internal.h"

#if MYARK_MODULE_KERNEL

PVOID    g_MyArkKernelKeServiceDescriptorTable = NULL;
UINT64   g_MyArkKernelNtoskrnlTextBase = 0;
UINT64   g_MyArkKernelNtoskrnlTextEnd = 0;

static
NTSTATUS
MyArkKernelResolveSsdtBase(
    _Out_ PKSERVICE_TABLE_DESCRIPTOR TableOut)
//
// Resolve KeServiceDescriptorTable at IOCTL time. The symbol is exported
// by ntoskrnl but not declared in any public WDK 28000 header, so we fall
// through MmGetSystemRoutineAddress and verify the page is readable before
// touching the limit + table fields.
//
{
    RtlZeroMemory(TableOut, sizeof(*TableOut));

    if (g_MyArkKernelKeServiceDescriptorTable == NULL) {
        UNICODE_STRING name;
        RtlInitUnicodeString(&name, L"KeServiceDescriptorTable");
        g_MyArkKernelKeServiceDescriptorTable = MmGetSystemRoutineAddress(&name);
    }

    if (g_MyArkKernelKeServiceDescriptorTable == NULL) {
        return STATUS_NOT_FOUND;
    }

    if (!MmIsAddressValid(g_MyArkKernelKeServiceDescriptorTable)) {
        g_MyArkKernelKeServiceDescriptorTable = NULL;
        return STATUS_INVALID_ADDRESS;
    }

    //
    // The first field (Limit, UINT32) and the second field (Base, PUINT8)
    // are page-aligned and the kernel guarantees the descriptor stays
    // resident throughout the system lifetime, so a single IsAddressValid
    // probe on the descriptor pointer is enough -- the pointed-to Base
    // table will be probed row-by-row inside the walker.
    //
    PKSERVICE_TABLE_DESCRIPTOR local = (PKSERVICE_TABLE_DESCRIPTOR)g_MyArkKernelKeServiceDescriptorTable;
    TableOut->Limit = local->Limit;
    TableOut->Base = local->Base;
    TableOut->Number = local->Number;
    TableOut->Unused = local->Unused;
    return STATUS_SUCCESS;
}

static
ULONG
MyArkKernelReadDwellBytes(
    _In_  PVOID  ServiceAddress,
    _Out_writes_bytes_(8) PUCHAR OutBytes)
//
// Copy up to 8 bytes from a kernel-side trampoline for the R3 dump.
// Returns the byte count actually copied (0 when the source is unmapped).
// KNOWN_ISSUES B4 residual: MmIsAddressValid only reports this instant --
// the page can still fault on the actual access -- so the read goes
// through MmCopyMemory instead. PASSIVE_LEVEL required (the sequential
// queue guarantees it).
//
{
    MM_COPY_ADDRESS src;
    SIZE_T copied = 0;

    if (ServiceAddress == NULL) {
        return 0;
    }

    src.VirtualAddress = ServiceAddress;
    if (!NT_SUCCESS(MmCopyMemory(OutBytes, src, 8,
                                 MM_COPY_MEMORY_VIRTUAL, &copied))) {
        return 0;
    }
    return (ULONG)copied;
}

//
// Fault-safe 8-byte kernel read (KNOWN_ISSUES B4): MmIsAddressValid only
// reports this instant -- the page can still fault on the actual access
// (bugchecked 0x3B on no-SMEP CPUs when the walk crossed a page boundary).
// MmCopyMemory tolerates unmapped / paged-out / cross-page sources.
// PASSIVE_LEVEL required (the sequential queue guarantees it).
//
static
BOOLEAN
MyArkKernelReadSlot64(
    _In_  PVOID   Slot,
    _Out_ UINT64 *ValueOut)
{
    MM_COPY_ADDRESS src;
    SIZE_T          copied = 0;

    src.VirtualAddress = Slot;
    NTSTATUS status = MmCopyMemory(ValueOut, src, sizeof(UINT64),
                                   MM_COPY_MEMORY_VIRTUAL, &copied);
    return NT_SUCCESS(status) && copied == sizeof(UINT64);
}


static
ULONG
MyArkKernelWalkSsdt(
    _In_    PKSERVICE_TABLE_DESCRIPTOR Table,
    _In_    UINT64                    TextBase,
    _In_    UINT64                    TextEnd,
    _Out_writes_(MaxEntries) PMYARK_KERNEL_SSDT_ENTRY OutEntries,
    _In_    ULONG                    MaxEntries,
    _Out_   PULONG                   TotalSeenOut)
//
// Read each SSDT row and emit one MYARK_KERNEL_SSDT_ENTRY per populated
// service. Modern Win10+ SSDT entries store signed-32-bit relative offsets
// (Base[i] = entry[i] + (UINT64)&entry[i]); we treat them as PVOID-sized
// here and let the caller decide whether to add the table base.
//
// The routine address is Table->Base + the signed 4-byte entry value; the
// caller supplies the suspect range (ntoskrnl for QUERY_SSDT, the win32k
// module union for the shadow table).
//
{
    *TotalSeenOut = 0;

    if (Table == NULL || Table->Base == NULL || Table->Limit == 0) {
        return 0;
    }
    if (!MmIsAddressValid((PVOID)Table->Base)) {
        return 0;
    }

    PUCHAR entryBase = Table->Base;
    UINT32 limit = Table->Limit;
    ULONG written = 0;
    const ULONG HARD_CAP = MYARK_KERNEL_SSDT_HARD_CAP;

    //
    // x64 Win10+ layout (both ntoskrnl and win32k shadow tables): each
    // entry is a 4-byte signed offset; the routine lives at Table->Base +
    // offset. An 8-byte stride would interleave neighbouring entries and
    // flag everything SUSPECT (observed on the win32k table, 2026-09-15).
    //
    for (UINT32 i = 0; i < limit && i < HARD_CAP && written < MaxEntries; i++) {
        PVOID slot = (PVOID)(entryBase + (SIZE_T)i * sizeof(UINT32));

        ULONG raw32 = 0;
        MM_COPY_ADDRESS src;
        SIZE_T copied = 0;
        src.VirtualAddress = slot;
        if (!NT_SUCCESS(MmCopyMemory(&raw32, src, sizeof(UINT32),
                                     MM_COPY_MEMORY_VIRTUAL, &copied))
            || copied != sizeof(UINT32)) {
            continue;
        }
        if (raw32 == 0) {
            continue;
        }

        UINT64 serviceAddress = (UINT64)(UINT_PTR)entryBase + (LONG)raw32;

        PMYARK_KERNEL_SSDT_ENTRY row = &OutEntries[written];
        RtlZeroMemory(row, sizeof(*row));

        row->ServiceIndex = i;
        row->ServiceAddress = serviceAddress;

        UINT32 flags = MYARK_KERNEL_SSDT_FLAG_POPULATED;

        if (serviceAddress != 0
            && TextBase != 0
            && TextEnd != 0
            && (serviceAddress < TextBase || serviceAddress >= TextEnd)) {
            flags |= MYARK_KERNEL_SSDT_FLAG_SUSPECT;
        }

        //
        // Conservative "hooked" heuristic: bit 0 of a service address on
        // x64 looks weird (the kernel .text is page-aligned and starts at
        // its image base). Combined with SUSPECT this is a strong tell.
        //
        if ((serviceAddress & 0x1ULL) != 0) {
            flags |= MYARK_KERNEL_SSDT_FLAG_HOOK;
        }

        row->Flags = flags;

        if (serviceAddress != 0) {
            UCHAR dwell[8] = { 0 };
            ULONG dwellBytes = MyArkKernelReadDwellBytes((PVOID)serviceAddress, dwell);
            if (dwellBytes != 0) {
                RtlCopyMemory(row->DwellBytes, dwell, 8);
                row->DwellBytesSize = dwellBytes;
            } else {
                row->DwellBytesSize = 0;
            }
        } else {
            row->DwellBytesSize = 0;
        }

        written++;
    }

    *TotalSeenOut = (ULONG)limit;
    return written;
}

VOID
MyArkKernelEnsureNtoskrnlBounds(
    VOID)
//
// Lazy ntoskrnl .text bounds resolution. Without -- the simplest path is
// to set the bounds to 0 and let R3 do the suspect-range comparison on
// its end (R3 has access to a known-good SSDT map and can flag entries
// without the kernel needing to parse PE headers).
//
// The upper bound is a fixed 16 MiB ceiling covering the whole image on
// every supported build; if the base is unresolvable the bounds stay 0
// (meaning "R3 only").
//
{
    if (g_MyArkKernelNtoskrnlTextBase != 0 && g_MyArkKernelNtoskrnlTextEnd != 0) {
        return;
    }

    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"PsNtosImageBase");
    PUCHAR* imageBaseRef = (PUCHAR*)MmGetSystemRoutineAddress(&name);
    if (imageBaseRef == NULL || !MmIsAddressValid(imageBaseRef)) {
        //
        // Fallback (R1-4): PsNtosImageBase is a data export and
        // MmGetSystemRoutineAddress may refuse it. Any kernel text
        // address maps back to the ntoskrnl image base via
        // RtlPcToFileHeader.
        //
        PVOID hdrBase = NULL;
        PVOID (NTAPI *RtlPcToFileHeaderFn)(PVOID PcValue, PVOID *BaseOfImage) = NULL;
        RtlPcToFileHeaderFn = (PVOID (NTAPI *)(PVOID, PVOID *))MmGetSystemRoutineAddress(
            &(UNICODE_STRING)RTL_CONSTANT_STRING(L"RtlPcToFileHeader"));
        if (RtlPcToFileHeaderFn == NULL) {
            return;
        }
        if (RtlPcToFileHeaderFn((PVOID)MmGetSystemRoutineAddress, &hdrBase) != NULL
            && hdrBase != NULL) {
            g_MyArkKernelNtoskrnlTextBase = (UINT64)(UINT_PTR)hdrBase;
            g_MyArkKernelNtoskrnlTextEnd = g_MyArkKernelNtoskrnlTextBase + 0x1000000ULL;
        }
        return;
    }

    PUCHAR base = *imageBaseRef;
    if (base == NULL || !MmIsAddressValid(base)) {
        return;
    }

    //
    // Use a conservative approximation: treat the entire ntoskrnl image
    // (base .. base + imageSize) as the safe range. The image size comes
    // from MmSizeOfSystemImage when exposed; otherwise we over-report the
    // upper bound and R3 keeps doing the strict comparison.
    //
    //
    // 16 MiB ceiling -- generous upper bound for the ntoskrnl image on
    // every supported build (1903 image ~11 MiB). Do NOT dereference the
    // MmSizeOfSystemImage export as data here: it is a FUNCTION, and
    // reading its prologue as a size once shrank this bound below the
    // .data section (2026-09-15, broke the shadow-table scan).
    //
    UINT64 base64 = (UINT64)base;
    g_MyArkKernelNtoskrnlTextBase = base64;
    g_MyArkKernelNtoskrnlTextEnd = base64 + 0x1000000ULL;
}

NTSTATUS
MyArkKernelIoctlQuerySsdt(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
//
// QUERY_SSDT: one row per populated SSDT entry. The walker flags entries
// whose service address lies outside ntoskrnl .text as SUSPECT.
//
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                status;
    PMYARK_KERNEL_QUERY_SSDT_INPUT          inBuf = NULL;
    size_t                                  inSize = 0;
    PVOID                                   outBuf = NULL;
    size_t                                  outSize = 0;

    if (InputBufferLength < sizeof(MYARK_KERNEL_QUERY_SSDT_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_KERNEL_QUERY_SSDT_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_KERNEL_QUERY_SSDT_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_KERNEL_QUERY_SSDT_OUTPUT out = (PMYARK_KERNEL_QUERY_SSDT_OUTPUT)outBuf;
    RtlZeroMemory(outBuf, FIELD_OFFSET(MYARK_KERNEL_QUERY_SSDT_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                                - FIELD_OFFSET(MYARK_KERNEL_QUERY_SSDT_OUTPUT, Entries[0]))
                               / sizeof(MYARK_KERNEL_SSDT_ENTRY));
    if (inBuf->MaxEntries != 0 && inBuf->MaxEntries < maxEntries) {
        maxEntries = inBuf->MaxEntries;
    }
    if (maxEntries > MYARK_KERNEL_SSDT_HARD_CAP) {
        maxEntries = MYARK_KERNEL_SSDT_HARD_CAP;
    }
    if (maxEntries == 0) {
        out->Size = (UINT32)FIELD_OFFSET(MYARK_KERNEL_QUERY_SSDT_OUTPUT, Entries[0]);
        out->Count = 0;
        *BytesReturned = out->Size;
        return STATUS_BUFFER_TOO_SMALL;
    }

    KSERVICE_TABLE_DESCRIPTOR table = { 0 };
    status = MyArkKernelResolveSsdtBase(&table);
    if (!NT_SUCCESS(status)) {
        out->Size = (UINT32)FIELD_OFFSET(MYARK_KERNEL_QUERY_SSDT_OUTPUT, Entries[0]);
        out->Count = 0;
        out->KeServiceDescriptorTable = 0;
        *BytesReturned = out->Size;
        return status;
    }

    MyArkKernelEnsureNtoskrnlBounds();

    ULONG totalSeen = 0;
    ULONG written = MyArkKernelWalkSsdt(&table,
                                        g_MyArkKernelNtoskrnlTextBase,
                                        g_MyArkKernelNtoskrnlTextEnd,
                                        out->Entries,
                                        maxEntries,
                                        &totalSeen);

    out->Size              = (UINT32)(FIELD_OFFSET(MYARK_KERNEL_QUERY_SSDT_OUTPUT, Entries[0])
                                      + written * sizeof(MYARK_KERNEL_SSDT_ENTRY));
    out->Count             = written;
    out->TotalSeen         = totalSeen;
    out->KeServiceDescriptorTable = (UINT64)g_MyArkKernelKeServiceDescriptorTable;
    out->NtoskrnlTextBase  = g_MyArkKernelNtoskrnlTextBase;
    out->NtoskrnlTextEnd   = g_MyArkKernelNtoskrnlTextEnd;
    out->EntryStructSize   = (UINT32)sizeof(MYARK_KERNEL_SSDT_ENTRY);
    out->Reserved1         = 0;

    *BytesReturned = out->Size;
    return STATUS_SUCCESS;
}

//
// Shadow SSDT (R2-3). The win32k service table is not exported and the
// classic KTHREAD->ServiceTable route needs per-build offsets, so the
// driver instead locates KeServiceDescriptorTableShadow inside the
// ntoskrnl image (adjacent descriptor pair -- see the finder below) and
// walks the win32k table it points at. The suspect range spans every
// loaded win32k* module (routines spill into win32kfull), resolved via
// the loaded-module list below.
//

//
// Loaded-kernel-module list entry (SystemModuleInformation = 11).
// x64 kernel layout: ImageBase@16, ImageSize@24, FullPathName[256]@36.
//
typedef struct _MYARK_SYS_MODULE_ENTRY {
    HANDLE  Section;            // +0
    PVOID   MappedBase;         // +8
    PVOID   ImageBase;          // +16
    ULONG   ImageSize;          // +24
    ULONG   Flags;              // +28
    USHORT  LoadCount;          // +32
    USHORT  __Unused;           // +34
    ULONG   __Pad0;             // +36  (x64 kernel layout: path at +40,
    UCHAR   FullPathName[256];  // verified against the 1903 list -- 296 stride)
} MYARK_SYS_MODULE_ENTRY;

//
// Union bounds of every loaded win32k* module (win32k.sys / win32kbase.sys /
// win32kfull.sys). Returns FALSE when none is loaded.
//
static
BOOLEAN
MyArkKernelWin32kBounds(
    _Out_ PUINT64 BaseOut,
    _Out_ PUINT64 EndOut)
{
    typedef NTSTATUS (NTAPI *QUERY_FN)(ULONG, PVOID, ULONG, PULONG);
    QUERY_FN query = (QUERY_FN)MmGetSystemRoutineAddress(
        &(UNICODE_STRING)RTL_CONSTANT_STRING(L"ZwQuerySystemInformation"));
    if (query == NULL) {
        return FALSE;
    }

    ULONG needed = 0;
    NTSTATUS status = query(11, NULL, 0, &needed);
    if (needed == 0 || needed > 4 * 1024 * 1024) {
        return FALSE;
    }

    PUCHAR buf = (PUCHAR)MyArkAllocatePool(NonPagedPoolNx, needed, 'SmhK');
    if (buf == NULL) {
        return FALSE;
    }
    status = query(11, buf, needed, &needed);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buf, 'SmhK');
        return FALSE;
    }

    ULONG count = *(PULONG)buf;
    BOOLEAN found = FALSE;
    UINT64 lo = 0;
    UINT64 hi = 0;

    PUCHAR it = buf + 8;    // RTL_PROCESS_MODULES: NumberOfModules, then entries
    for (ULONG i = 0; i < count && it + sizeof(MYARK_SYS_MODULE_ENTRY) <= buf + needed; i++) {
        MYARK_SYS_MODULE_ENTRY *m = (MYARK_SYS_MODULE_ENTRY *)it;
        it += sizeof(MYARK_SYS_MODULE_ENTRY);

        //
        // Tail name after the last backslash. FullPathName is a fixed 256
        // byte field and always NUL-terminated per the API contract; the
        // scan still stops at the field end to stay safe on rogue input.
        //
        PCSTR tail = NULL;
        for (ULONG c = 0; c < sizeof(m->FullPathName) && m->FullPathName[c]; c++) {
            if (m->FullPathName[c] == '\\') {
                tail = (PCSTR)&m->FullPathName[c + 1];
            }
        }
        if (tail == NULL) {
            continue;
        }

        //
        // "win32k*.sys" -- covers win32k.sys (10 chars), win32kbase.sys,
        // win32kfull.sys.
        //
        SIZE_T len = strlen(tail);
        if (len < 10 || _strnicmp(tail, "win32k", 6) != 0
            || _strnicmp(tail + len - 4, ".sys", 4) != 0) {
            continue;
        }

        UINT64 b = (UINT64)(UINT_PTR)m->ImageBase;
        UINT64 e = b + m->ImageSize;
        if (!found || b < lo) {
            lo = b;
        }
        if (!found || e > hi) {
            hi = e;
        }
        found = TRUE;
    }

    ExFreePoolWithTag(buf, 'SmhK');
    if (found && hi > lo) {
        *BaseOut = lo;
        *EndOut = hi;
        return TRUE;
    }
    return FALSE;
}

//
// Locate KeServiceDescriptorTableShadow inside the NTOSKRNL image (R2-3).
// The shadow descriptor table does NOT live in the win32k modules: it is
// an ntoskrnl .data array of two KSERVICE_TABLE_DESCRIPTORs -- [0] for the
// native table, [1] for win32k. Scanning the win32k modules for a
// {Limit, pad, Base} shape only finds false positives (string pools,
// word ramps -- observed 2026-09-15). The nt-side pair is a much tighter
// anchor:
//   [0]: Limit plausible, Base inside the ntoskrnl image
//   [1]: Limit plausible, Base inside the win32k* module union
//        Number (arg table) inside win32k* or NULL
//
//
// Score a candidate table: a REAL service table's entries decode into
// win32k code -- inside the module union but far from the table itself
// (code sections, not the adjacent .data). Guards against both the
// string-pool false positive (targets adjacent to the table) and the
// layout-drift false pair (targets outside the union entirely; observed
// 2026-09-16, Limit matched 0x4EA but every target sat 6 MiB below the
// union). Returns the plausible count among the first 32 entries.
//
static
ULONG
MyArkKernelScoreShadowCandidate(
    _In_ UINT64 TableBase,
    _In_ UINT64 UnionBase,
    _In_ UINT64 UnionEnd)
{
    ULONG plausible = 0;
    for (ULONG i = 0; i < 32; i++) {
        LONG raw = 0;
        MM_COPY_ADDRESS src;
        SIZE_T copied = 0;
        src.VirtualAddress = (PVOID)(UINT_PTR)(TableBase + (UINT64)i * 4);
        if (!NT_SUCCESS(MmCopyMemory(&raw, src, sizeof(LONG),
                                     MM_COPY_MEMORY_VIRTUAL, &copied))
            || copied != sizeof(LONG)) {
            continue;
        }
        if (raw == 0 || (raw & 0xFF00FF00) == 0) {
            continue;   // empty slot / ASCII-pair pool content
        }
        UINT64 target = TableBase + (UINT64)(INT64)raw;
        if (target >= UnionBase && target < UnionEnd
            && TableBase - target > 0x1000
            && target - TableBase > 0x1000) {
            plausible++;
        }
    }
    return plausible;
}

#define MYARK_KERNEL_SHADOW_PAIRS        4
#define MYARK_KERNEL_SHADOW_MIN_SCORE    24   // of 32 sampled entries

static
BOOLEAN
MyArkKernelFindShadowDescriptor(
    _In_ UINT64 NtosBase,
    _In_ ULONG NtosSize,
    _In_ UINT64 W32kBase,
    _In_ UINT64 W32kEnd,
    _Out_ PKSERVICE_TABLE_DESCRIPTOR TableOut)
{
    RtlZeroMemory(TableOut, sizeof(*TableOut));

    PUCHAR chunk = (PUCHAR)MyArkAllocatePool(NonPagedPoolNx,
                                             0x1000 + 0x40, 'DhsK');
    if (chunk == NULL) {
        return FALSE;
    }

    BOOLEAN found = FALSE;
    UINT64 limit = NtosSize;
    UINT64 off = 0;

    while (off + 0x40 <= limit) {
        ULONG chunkLen = 0x1000;
        if (off + chunkLen > limit) {
            chunkLen = (ULONG)(limit - off);
        }
        MM_COPY_ADDRESS src;
        SIZE_T copied = 0;
        src.VirtualAddress = (PVOID)(UINT_PTR)(NtosBase + off);
        if (!NT_SUCCESS(MmCopyMemory(chunk, src, chunkLen,
                                     MM_COPY_MEMORY_VIRTUAL, &copied))
            || copied < 0x40) {
            off += 0x1000;   // unreadable window: skip a page
            continue;
        }

        ULONG usable = (ULONG)copied;
        for (ULONG p = 0; p + 0x40 <= usable; p += 8) {
            //
            // Layout verified against a live 18362 target via KDNET
            // (dt/dq nt!KeServiceDescriptorTableShadow):
            //   +0x00 Base   (ptr)      +0x08 zero (qword)
            //   +0x10 Limit  (u32 in qword, high half 0)
            //   +0x18 Args   (ptr)      -- descriptor is 0x20 bytes;
            //   shadow[0] = native table (Base/Args inside ntoskrnl),
            //   shadow[1] = win32k table (Base/Args inside win32k*).
            //
            UINT64 base0 = *(UINT64 *)&chunk[p];
            if (base0 < NtosBase || base0 >= NtosBase + NtosSize) {
                continue;
            }
            if (*(UINT64 *)&chunk[p + 8] != 0) {
                continue;
            }
            UINT64 limit0 = *(UINT64 *)&chunk[p + 0x10];
            if ((limit0 >> 32) != 0
                || limit0 < MYARK_KERNEL_SHADOW_LIMIT_MIN
                || limit0 > MYARK_KERNEL_SHADOW_LIMIT_MAX) {
                continue;
            }
            UINT64 args0 = *(UINT64 *)&chunk[p + 0x18];
            if (args0 < NtosBase || args0 >= NtosBase + NtosSize) {
                continue;
            }

            UINT64 base1 = *(UINT64 *)&chunk[p + 0x20];
            if (base1 < W32kBase || base1 >= W32kEnd) {
                continue;
            }
            if (*(UINT64 *)&chunk[p + 0x28] != 0) {
                continue;
            }
            UINT64 limit1 = *(UINT64 *)&chunk[p + 0x30];
            if ((limit1 >> 32) != 0
                || limit1 < MYARK_KERNEL_SHADOW_LIMIT_MIN
                || limit1 > MYARK_KERNEL_SHADOW_LIMIT_MAX) {
                continue;
            }
            UINT64 args1 = *(UINT64 *)&chunk[p + 0x38];
            if (args1 != 0 && (args1 < W32kBase || args1 >= W32kEnd)) {
                continue;
            }

            //
            // Score inline and take the first candidate that decodes like
            // a service table; junk pairs are unlimited in principle, so
            // a fixed candidate array could evict the real one.
            //
            if (MyArkKernelScoreShadowCandidate(base1, W32kBase, W32kEnd)
                >= MYARK_KERNEL_SHADOW_MIN_SCORE) {
                TableOut->Limit = (ULONG)limit1;
                TableOut->Base = (PUINT8)(UINT_PTR)base1;
                TableOut->Number = (PUINT8)(UINT_PTR)args1;
                TableOut->Unused = NULL;
                found = TRUE;
            }
        }
        if (found) {
            break;
        }
        off += 0x1000 - 0x40;   // overlap so straddling pairs stay visible
    }

    ExFreePoolWithTag(chunk, 'DhsK');
    return found;
}

NTSTATUS
MyArkKernelIoctlQueryShadowSsdt(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
//
// QUERY_SHADOW_SSDT: locate the win32k service table by shape-scanning
// the win32k module range, then walk it with the QUERY_SSDT row format.
//
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    PMYARK_KERNEL_QUERY_SHADOW_OUTPUT outBuf = NULL;
    size_t outSize = 0;
    NTSTATUS status = MyArkIoctlFetchOutputBuffer(Request,
        FIELD_OFFSET(MYARK_KERNEL_QUERY_SHADOW_OUTPUT, Entries[0]),
        (PVOID *)&outBuf,
        &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ULONG maxEntries = (ULONG)((outSize
        - FIELD_OFFSET(MYARK_KERNEL_QUERY_SHADOW_OUTPUT, Entries[0]))
        / sizeof(MYARK_KERNEL_SSDT_ENTRY));
    if (maxEntries > MYARK_KERNEL_SHADOW_HARD_CAP) {
        maxEntries = MYARK_KERNEL_SHADOW_HARD_CAP;
    }

    UINT64 w32kBase = 0;
    UINT64 w32kEnd = 0;
    if (!MyArkKernelWin32kBounds(&w32kBase, &w32kEnd)) {
        return STATUS_NOT_FOUND;              // no win32k* module loaded
    }

    MyArkKernelEnsureNtoskrnlBounds();
    UINT64 ntosBase = g_MyArkKernelNtoskrnlTextBase;
    ULONG ntosSize = (ULONG)(g_MyArkKernelNtoskrnlTextEnd - ntosBase);
    if (ntosBase == 0 || ntosSize == 0 || ntosSize > 0x10000000UL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    KSERVICE_TABLE_DESCRIPTOR table;
    if (!MyArkKernelFindShadowDescriptor(ntosBase, ntosSize,
                                         w32kBase, w32kEnd,
                                         &table)
        || table.Base == NULL || table.Limit == 0) {
        return STATUS_PROCEDURE_NOT_FOUND;    // module there, pair absent
    }

    ULONG totalSeen = 0;
    ULONG written = MyArkKernelWalkSsdt(&table,
                                        w32kBase,
                                        w32kEnd,
                                        outBuf->Entries,
                                        maxEntries,
                                        &totalSeen);

    outBuf->Size = (UINT32)(FIELD_OFFSET(MYARK_KERNEL_QUERY_SHADOW_OUTPUT, Entries[0])
                            + written * sizeof(MYARK_KERNEL_SSDT_ENTRY));
    outBuf->Count = written;
    outBuf->TotalSeen = totalSeen;
    outBuf->TableLimit = table.Limit;
    outBuf->ShadowTableBase = (UINT64)(UINT_PTR)table.Base;
    outBuf->Win32kBase = w32kBase;
    outBuf->Win32kSize = (UINT32)(w32kEnd - w32kBase);
    outBuf->EntryStructSize = (UINT32)sizeof(MYARK_KERNEL_SSDT_ENTRY);

    *BytesReturned = outBuf->Size;
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_KERNEL
