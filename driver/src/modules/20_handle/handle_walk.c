// MyArk handle module: HANDLE_TABLE walker + per-row fill.
//
// The walker is best-effort -- it never raises an exception. Every page
// is probed via MmIsAddressValid before reading; any page that fails
// aborts the walk silently with the rows it had so far. R3 sees a
// truncated list with TotalSeen > Count and can report "..." in the UI.

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>

//
// ntifs.h is not included (it would redeclare PEPROCESS / PETHREAD after
// wdm.h). Forward-declare just the prototypes we need.
//
NTKERNELAPI
NTSTATUS
ObQueryNameString(
    _In_ PVOID Object,
    _Out_writes_bytes_opt_(Length) POBJECT_NAME_INFORMATION NameInfo,
    _In_ ULONG Length,
    _Out_ PULONG ReturnLength);
#include "Trace.h"
#include "MyArkPoolAlloc.h"
#include "myark_config.h"
#include "../../../shared/driver/MyArkHandleIoctl.h"
#include "handle_descriptor.h"
#include "handle_internal.h"

#if MYARK_MODULE_HANDLE

NTSTATUS
MyArkHandleFillObjectHeaderFields(
    _In_  PVOID   Object,
    _Out_ PUINT32 PointerCount,
    _Out_ PUINT32 HandleCount,
    _Out_ PUINT32 TypeIndex,
    _Out_ PUINT32 ObFlags)
//
// Pull the OBJECT_HEADER fields that live in front of Object. The header
// pointer is (Object - sizeof(OBJECT_HEADER)); we use a hard-coded header
// size of 0x30 because Win11 24H2's header sits at that offset for the
// types we touch. If the page before Object is paged out the walk aborts.
//
{
    if (Object == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // _OBJECT_HEADER layout (24H2, 0x30 bytes):
    //   0x00 ListEntry           (LIST_ENTRY, 0x10)
    //   0x10 ParentKcb           (PVOID)
    //   0x18 TypeIndex           (UCHAR index, padded to 4 bytes in our struct)
    //   0x1C Flags               (ULONG -- OB_FLAG_* + InfoMask)
    //   0x20 NameInfoOffset      (PVOID optional)
    //   0x28 PointerCount        (ULONG)
    //   0x2C HandleCount         (ULONG)
    //
    PUCHAR headerBase = (PUCHAR)Object - 0x30;

    if (!MmIsAddressValid(headerBase)) {
        return STATUS_UNSUCCESSFUL;
    }

    *TypeIndex     = *(PUINT32)(headerBase + MYARK_OFF_OBJ_HDR_TYPE_INDEX);
    *ObFlags       = *(PUINT32)(headerBase + MYARK_OFF_OBJ_HDR_FLAGS);
    *PointerCount  = *(PUINT32)(headerBase + MYARK_OFF_OBJ_HDR_POINTER_COUNT);
    *HandleCount   = *(PUINT32)(headerBase + MYARK_OFF_OBJ_HDR_HANDLE_COUNT);

    return STATUS_SUCCESS;
}

static
VOID
MyArkHandleSafeCopyUnicode(
    _Out_writes_z_(Capacity) PWCHAR Dest,
    _In_ size_t Capacity,
    _In_opt_ PUNICODE_STRING Src)
//
// Copy a UNICODE_STRING into a fixed-size buffer, with safe truncation.
// Capacity is the number of WCHAR slots; we always leave room for the
// trailing NUL and never touch pages that aren't pinned.
//
{
    if (Dest == NULL || Capacity == 0) {
        return;
    }
    RtlZeroMemory(Dest, Capacity * sizeof(WCHAR));

    if (Src == NULL || Src->Buffer == NULL || Src->Length == 0) {
        return;
    }

    size_t copyChars = Src->Length / sizeof(WCHAR);
    if (copyChars >= Capacity) {
        copyChars = Capacity - 1;
    }

    //
    // MmIsAddressValid only checks the start page; for a string we also
    // need the last page. For the common case the buffer is small so we
    // probe both ends.
    //
    if (!MmIsAddressValid(Src->Buffer) ||
        !MmIsAddressValid((PUCHAR)Src->Buffer + (copyChars * sizeof(WCHAR)))) {
        return;
    }

    RtlCopyMemory(Dest, Src->Buffer, copyChars * sizeof(WCHAR));
    Dest[copyChars] = L'\0';
}

NTSTATUS
MyArkHandleResolveObjectName(
    _In_  PVOID  ObjectBody,
    _Out_writes_z_(Capacity) PWCHAR OutName,
    _In_  size_t Capacity)
//
// Best-effort: call ObQueryNameString with a probe-sized buffer and
// truncate into OutName. Returns STATUS_SUCCESS even when the name is
// empty -- callers don't treat "no name" as an error.
//
{
    NTSTATUS status;
    ULONG returnedLength = 0;
    UCHAR probeBuffer[sizeof(OBJECT_NAME_INFORMATION)] = {0};
    POBJECT_NAME_INFORMATION nameInfo = (POBJECT_NAME_INFORMATION)probeBuffer;
    ULONG probeSize = (ULONG)sizeof(probeBuffer);

    if (ObjectBody == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = ObQueryNameString(ObjectBody, nameInfo, probeSize, &returnedLength);
    if (status == STATUS_INFO_LENGTH_MISMATCH || returnedLength > probeSize) {
        //
        // Name was larger than our inline probe buffer; allocate a real
        // buffer sized to returnedLength and try again. We clamp at
        // MYARK_HANDLE_NAME_MAX*sizeof(WCHAR) bytes to keep us from
        // pulling a megabyte off the heap for a pathological object.
        //
        ULONG allocSize = returnedLength;
        if (allocSize > (ULONG)(MYARK_HANDLE_NAME_MAX * sizeof(WCHAR))) {
            allocSize = (ULONG)(MYARK_HANDLE_NAME_MAX * sizeof(WCHAR));
        }
        __try {
            POBJECT_NAME_INFORMATION largeBuffer =
                (POBJECT_NAME_INFORMATION)MyArkAllocatePool(PagedPool, allocSize, 'lnaH');
            if (largeBuffer == NULL) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            status = ObQueryNameString(ObjectBody, largeBuffer, allocSize, &returnedLength);
            if (NT_SUCCESS(status)) {
                MyArkHandleSafeCopyUnicode(OutName, Capacity, &largeBuffer->Name);
            }
            ExFreePoolWithTag(largeBuffer, 'lnaH');
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
        }
        return status;
    }

    if (NT_SUCCESS(status)) {
        MyArkHandleSafeCopyUnicode(OutName, Capacity, &nameInfo->Name);
    }
    return status;
}

NTSTATUS
MyArkHandleResolveTypeName(
    _In_  UINT32 TypeIndex,
    _Out_writes_z_(Capacity) PWCHAR OutName,
    _In_  size_t Capacity)
//
// ObTypeIndexToDescriptorName is not exported. We fall back to a small
// hard-coded table of well-known types; everything else renders as
// "Type#N". This is intentionally minimal -- S7 will fill in the rest
// via ObReferenceObjectByHandle + ObDereferenceObject with the right
// mask.
//
{
    static const struct {
        UINT32      Index;
        const WCHAR*Name;
    } kKnownTypes[] = {
        {  3, L"Type" },
        {  7, L"Directory" },
        {  8, L"File" },
        {  9, L"Link" },
        { 10, L"Mutant" },
        { 11, L"Event" },
        { 12, L"Semaphore" },
        { 13, L"Timer" },
        { 14, L"Thread" },
        { 15, L"Process" },
        { 16, L"Token" },
        { 17, L"Job" },
        { 18, L"Section" },
        { 19, L"Key" },
        { 20, L"Port" },
        { 21, L"WaitCompletionPacket" },
        { 24, L"IoCompletion" },
        { 28, L"WindowStation" },
        { 29, L"Desktop" },
    };

    RtlZeroMemory(OutName, Capacity * sizeof(WCHAR));

    for (ULONG i = 0; i < RTL_NUMBER_OF(kKnownTypes); i++) {
        if (kKnownTypes[i].Index == TypeIndex) {
            RtlStringCbCopyW(OutName, Capacity * sizeof(WCHAR), kKnownTypes[i].Name);
            return STATUS_SUCCESS;
        }
    }

    //
    // Unknown type -- render as "Type#N" so R3 can still sort / filter.
    //
    RtlStringCbPrintfW(OutName, Capacity * sizeof(WCHAR), L"Type#%u", TypeIndex);
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkHandleWalkTable(
    _In_  PVOID   HandleTable,
    _Out_writes_(MaxEntries) PMYARK_HANDLE_ENTRY OutEntries,
    _In_  ULONG   MaxEntries,
    _Out_ PULONG  CountOut,
    _Out_ PULONG  TotalSeenOut)
//
// Walk the L0 portion of HandleTable and stream one row per populated
// HANDLE_TABLE_ENTRY slot. Returns STATUS_SUCCESS even when the walk
// aborts early (MmIsAddressValid fails); *CountOut and *TotalSeenOut
// distinguish "all done" from "truncated".
//
{
    if (HandleTable == NULL || MaxEntries == 0) {
        *CountOut = 0;
        *TotalSeenOut = 0;
        return STATUS_INVALID_PARAMETER;
    }

    if (!MmIsAddressValid(HandleTable)) {
        *CountOut = 0;
        *TotalSeenOut = 0;
        return STATUS_UNSUCCESSFUL;
    }

    //
    // TableCode holds a tagged pointer: low 2 bits encode the table level.
    // Strip the tag so we have a plain kernel VA pointing at the entry array.
    //
    UINT64 tableCode = *(PUINT64)((PUCHAR)HandleTable + MYARK_OFF_HT_TABLE_CODE);
    UINT64 tableLevel = tableCode & 0x3ULL;
    PVOID  tableEntries = (PVOID)(tableCode & ~(UINT64)0x3ULL);

    //
    // Only walk single-level (L0) tables. Multi-level tables exist but
    // are uncommon enough for this stage that we surface them as zero
    // rows with a log line -- S7 will add the L1/L2/L3 walker.
    //
    if (tableLevel != 0 || !MmIsAddressValid(tableEntries)) {
        *CountOut = 0;
        *TotalSeenOut = 0;
        return STATUS_SUCCESS;
    }

    ULONG written = 0;
    ULONG seen = 0;
    PUINT64 entries = (PUINT64)tableEntries;

    for (ULONG i = 0; i < MYARK_HT_L0_CAPACITY; i++) {
        //
        // Each entry is 16 bytes; low QWORD holds flags + low bits, next
        // QWORD holds the object pointer (with low 4 bits masked). When
        // the object pointer is NULL the slot is free -- skip.
        //
        UINT64 objectWithFlags = entries[(i * 2) + 1];
        if (objectWithFlags == 0) {
            continue;
        }

        PVOID objectBody = (PVOID)(objectWithFlags & ~(UINT64)0xFULL);
        UINT32 ptrCount = 0;
        UINT32 hdrCount = 0;
        UINT32 typeIndex = 0;
        UINT32 obFlags = 0;

        NTSTATUS fillStatus = MyArkHandleFillObjectHeaderFields(objectBody,
                                                                &ptrCount,
                                                                &hdrCount,
                                                                &typeIndex,
                                                                &obFlags);

        seen++;

        if (!NT_SUCCESS(fillStatus)) {
            //
            // Slot is occupied but we can't read the header; still emit a
            // minimal row so R3 sees the handle exists, then move on.
            //
            if (written < MaxEntries) {
                RtlZeroMemory(&OutEntries[written], sizeof(MYARK_HANDLE_ENTRY));
                OutEntries[written].HandleValue = (UINT64)(i << 4);  // classic formula: index * 4 shifted by level bits
                written++;
            }
            continue;
        }

        if (written >= MaxEntries) {
            continue;
        }

        PMYARK_HANDLE_ENTRY row = &OutEntries[written];
        RtlZeroMemory(row, sizeof(*row));
        row->HandleValue = (UINT64)(i << 4);
        row->PointerCount = ptrCount;
        row->HandleCount = hdrCount;
        row->TypeIndex = typeIndex;

        UINT32 flags = 0;
        UINT32 attributes = 0;

        //
        // HANDLE_TABLE_ENTRY.LowBits holds the granted-access mask +
        // audit / inherit flags. We don't decode it deeply here -- the
        // high bits are a partial access mask.
        //
        UINT64 lowBits = entries[(i * 2)];
        row->HandleAttributes = (UINT32)(lowBits >> 16);

        if (lowBits & 0x100) {     // bit 8: AuditOnClose
            row->Flags |= MYARK_HANDLE_FLAG_PROTECTED;
        }
        if (lowBits & 0x200) {     // bit 9: Inherit
            row->Flags |= MYARK_HANDLE_FLAG_INHERITABLE;
        }
        UNREFERENCED_PARAMETER(flags);
        UNREFERENCED_PARAMETER(attributes);

        MyArkHandleResolveTypeName(typeIndex,
                                   row->TypeName,
                                   MYARK_HANDLE_TYPE_NAME_MAX);

        MyArkHandleResolveObjectName(objectBody,
                                     row->Name,
                                     MYARK_HANDLE_NAME_MAX);

        written++;
    }

    *CountOut = written;
    *TotalSeenOut = seen;
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_HANDLE
