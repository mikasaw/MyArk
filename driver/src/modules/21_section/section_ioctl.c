// MyArk section module: IOCTL handlers + ControlArea walker.

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "MyArkPoolAlloc.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkSectionIoctl.h"
#include "section_descriptor.h"
#include "section_internal.h"

#if MYARK_MODULE_SECTION

NTSTATUS
PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);

static
VOID
MyArkSectionSafeCopyUnicode(
    _Out_writes_z_(Capacity) PWCHAR Dest,
    _In_ size_t Capacity,
    _In_opt_ PUNICODE_STRING Src)
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

    if (!MmIsAddressValid(Src->Buffer) ||
        !MmIsAddressValid((PUCHAR)Src->Buffer + (copyChars * sizeof(WCHAR)))) {
        return;
    }

    RtlCopyMemory(Dest, Src->Buffer, copyChars * sizeof(WCHAR));
    Dest[copyChars] = L'\0';
}

static
NTSTATUS
MyArkSectionFillEntryFromControlArea(
    _In_  PVOID ControlArea,
    _In_  UINT32 PidFilter,
    _Out_ PMYARK_SECTION_ENTRY Row)
{
    RtlZeroMemory(Row, sizeof(*Row));
    Row->ControlAreaAddress = (UINT64)ControlArea;

    PVOID fileObject = *(PVOID*)((PUCHAR)ControlArea + MYARK_OFF_CA_FILE_OBJECT);
    Row->FileObjectAddress = (UINT64)fileObject;

    UINT32 flags = *(PUINT32)((PUCHAR)ControlArea + MYARK_OFF_CA_FLAGS);
    UINT32 rowFlags = 0;

    if (flags & MYARK_CA_FLAG_IMAGE) {
        rowFlags |= MYARK_SECTION_FLAG_IMAGE;
    }
    if (flags & MYARK_CA_FLAG_MAPPED_FILE) {
        rowFlags |= MYARK_SECTION_FLAG_MAPPED_FILE;
    }
    if (flags & MYARK_CA_FLAG_PAGEFILE) {
        rowFlags |= MYARK_SECTION_FLAG_PAGEFILE;
    }

    if (fileObject != NULL && MmIsAddressValid(fileObject)) {
        PUNICODE_STRING name = (PUNICODE_STRING)((PUCHAR)fileObject + MYARK_OFF_FO_FILENAME);
        MyArkSectionSafeCopyUnicode(Row->Name,
                                    MYARK_SECTION_NAME_MAX,
                                    name);
    } else {
        RtlStringCbCopyW(Row->Name, sizeof(Row->Name), L"<pagefile>");
    }

    UINT64 sectionSize = *(PUINT64)((PUCHAR)ControlArea + MYARK_OFF_CA_SECTION_SIZE_LOW);
    Row->SizeInBytes = sectionSize;

    //
    // Heuristic PID attribution -- shared sections don't have a single
    // owner. We attach the caller's Pid to every row, which lets R3 at
    // least filter by it; anything that needs cross-process mapping
    // should join with QUERY_FILE_MAPPINGS.
    //
    Row->Pid = PidFilter;

    //
    // Mark Remote when the FileObject lives in a different process's
    // address space than the caller. Conservative -- we only flag it
    // when we can't pin a single owner. R3 surfaces this as
    // REMOTE_MAPPING_UNSUPPORTED.
    //
    if (fileObject == NULL && (flags & MYARK_CA_FLAG_PAGEFILE) == 0) {
        rowFlags |= MYARK_SECTION_FLAG_REMOTE;
    }

    Row->Flags = rowFlags;
    Row->Protection = 0;       // not directly visible from ControlArea
    Row->BaseAddress = 0;      // would require MmSectionViewTable lookup
    return STATUS_SUCCESS;
}

static
ULONG
MyArkSectionWalkGlobal(
    _Out_writes_(MaxEntries) PMYARK_SECTION_ENTRY OutEntries,
    _In_  ULONG MaxEntries,
    _Out_ PULONG TotalSeenOut)
//
// Walk MmControlAreaListHead and stream one row per ControlArea. Used
// by both QUERY_PROCESS (filter by Pid at the call site) and
// QUERY_FILE_MAPPINGS (no filter).
//
{
    PLIST_ENTRY head = g_MyArkSectionMmControlAreaListHead;
    if (head == NULL || !MmIsAddressValid(head)) {
        *TotalSeenOut = 0;
        return 0;
    }

    PLIST_ENTRY current = head->Flink;
    ULONG written = 0;
    ULONG seen = 0;
    const ULONG HARD_CAP = 16384;   // never walk more than this; lists are usually ~hundreds

    while (current != NULL
           && current != head
           && seen < HARD_CAP
           && written < MaxEntries) {

        PVOID controlArea = (PVOID)((PUCHAR)current - MYARK_OFF_CA_LIST_ENTRY);
        seen++;

        if (MmIsAddressValid(controlArea)) {
            MYARK_SECTION_ENTRY row;
            NTSTATUS st = MyArkSectionFillEntryFromControlArea(controlArea,
                                                               0,
                                                               &row);
            if (NT_SUCCESS(st)) {
                OutEntries[written] = row;
                written++;
            }
        }

        current = current->Flink;
    }

    *TotalSeenOut = seen;
    return written;
}

//
// Global pointer to the resolved MmControlAreaListHead. Initialized in
// MyArkSectionInit via MmGetSystemRoutineAddress.
//
PLIST_ENTRY g_MyArkSectionMmControlAreaListHead = NULL;

NTSTATUS
MyArkSectionIoctlQueryProcess(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
//
// QUERY_PROCESS: list the sections this Pid has touched. We don't have a
// fast VAD-walk in this module (memory module owns that), so we walk the
// global list and tag each entry with the caller's Pid as the "owner"
// -- R3 joins with the file-mapping list to dedupe shared sections.
//
{
    UNREFERENCED_PARAMETER(Device);

    if (InputBufferLength < sizeof(MYARK_SECTION_QUERY_PROCESS_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    NTSTATUS                                       status;
    PMYARK_SECTION_QUERY_PROCESS_INPUT             inBuf = NULL;
    size_t                                         inSize = 0;
    PVOID                                          outBuf = NULL;
    size_t                                         outSize = 0;

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_SECTION_QUERY_PROCESS_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_SECTION_QUERY_PROCESS_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_SECTION_QUERY_PROCESS_OUTPUT out = (PMYARK_SECTION_QUERY_PROCESS_OUTPUT)outBuf;
    RtlZeroMemory(outBuf, FIELD_OFFSET(MYARK_SECTION_QUERY_PROCESS_OUTPUT, Entries[0]));

    HANDLE pidHandle = (inBuf->Pid == 0)
                           ? PsGetCurrentProcessId()
                           : UlongToHandle(inBuf->Pid);

    PEPROCESS proc = NULL;
    status = PsLookupProcessByProcessId(pidHandle, &proc);
    if (!NT_SUCCESS(status) || proc == NULL) {
        out->Size = (UINT32)FIELD_OFFSET(MYARK_SECTION_QUERY_PROCESS_OUTPUT, Entries[0]);
        out->Count = 0;
        *BytesReturned = out->Size;
        return STATUS_NOT_FOUND;
    }

    ULONG maxEntries = (ULONG)((OutputBufferLength
                                - FIELD_OFFSET(MYARK_SECTION_QUERY_PROCESS_OUTPUT, Entries[0]))
                               / sizeof(MYARK_SECTION_ENTRY));
    if (inBuf->MaxEntries != 0 && inBuf->MaxEntries < maxEntries) {
        maxEntries = inBuf->MaxEntries;
    }
    if (maxEntries > MYARK_SECTION_HARD_CAP) {
        maxEntries = MYARK_SECTION_HARD_CAP;
    }
    if (maxEntries == 0) {
        out->Size = (UINT32)FIELD_OFFSET(MYARK_SECTION_QUERY_PROCESS_OUTPUT, Entries[0]);
        out->Count = 0;
        *BytesReturned = out->Size;
        return STATUS_BUFFER_TOO_SMALL;
    }

    ULONG totalSeen = 0;
    ULONG written = MyArkSectionWalkGlobal(out->Entries, maxEntries, &totalSeen);

    //
    // Re-stamp each row with the caller's Pid and count remote flags.
    //
    ULONG remoteCount = 0;
    for (ULONG i = 0; i < written; i++) {
        out->Entries[i].Pid = inBuf->Pid;
        if (out->Entries[i].Flags & MYARK_SECTION_FLAG_REMOTE) {
            remoteCount++;
        }
    }

    out->Size                  = (UINT32)(FIELD_OFFSET(MYARK_SECTION_QUERY_PROCESS_OUTPUT, Entries[0])
                                         + written * sizeof(MYARK_SECTION_ENTRY));
    out->Count                 = written;
    out->TotalSeen             = totalSeen;
    out->RemoteUnsupportedCount = remoteCount;
    *BytesReturned             = out->Size;
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkSectionIoctlQueryFileMappings(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
//
// QUERY_FILE_MAPPINGS: every ControlArea + backing FileObject on the
// global list. Used by R3 to render the "who has this file mapped" view.
//
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                            status;
    PMYARK_SECTION_QUERY_FILE_MAPPINGS_INPUT            inBuf = NULL;
    size_t                                              inSize = 0;
    PVOID                                               outBuf = NULL;
    size_t                                              outSize = 0;

    if (InputBufferLength < sizeof(MYARK_SECTION_QUERY_FILE_MAPPINGS_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_SECTION_QUERY_FILE_MAPPINGS_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_SECTION_QUERY_FILE_MAPPINGS_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_SECTION_QUERY_FILE_MAPPINGS_OUTPUT out = (PMYARK_SECTION_QUERY_FILE_MAPPINGS_OUTPUT)outBuf;
    RtlZeroMemory(outBuf, FIELD_OFFSET(MYARK_SECTION_QUERY_FILE_MAPPINGS_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                                - FIELD_OFFSET(MYARK_SECTION_QUERY_FILE_MAPPINGS_OUTPUT, Entries[0]))
                               / sizeof(MYARK_FILE_MAPPING_ENTRY));
    if (inBuf->MaxEntries != 0 && inBuf->MaxEntries < maxEntries) {
        maxEntries = inBuf->MaxEntries;
    }
    if (maxEntries > MYARK_SECTION_HARD_CAP) {
        maxEntries = MYARK_SECTION_HARD_CAP;
    }
    if (maxEntries == 0) {
        out->Size = (UINT32)FIELD_OFFSET(MYARK_SECTION_QUERY_FILE_MAPPINGS_OUTPUT, Entries[0]);
        out->Count = 0;
        *BytesReturned = out->Size;
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Walk the global list -- MYARK_FILE_MAPPING_ENTRY overlaps the
    // MYARK_SECTION_ENTRY layout up to the Name[] field, so we can write
    // into the same buffer after computing the right offsets. Cast
    // through a temporary first so the compiler does not complain about
    // pointer-to-pointer size mismatch.
    //
    ULONG totalSeen = 0;
    MYARK_SECTION_ENTRY* tmpRows = (MYARK_SECTION_ENTRY*)MyArkAllocatePool(
        PagedPool,
        maxEntries * sizeof(MYARK_SECTION_ENTRY),
        'tmpS');
    if (tmpRows == NULL) {
        out->Size = (UINT32)FIELD_OFFSET(MYARK_SECTION_QUERY_FILE_MAPPINGS_OUTPUT, Entries[0]);
        out->Count = 0;
        *BytesReturned = out->Size;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ULONG sectionWritten = MyArkSectionWalkGlobal(tmpRows, maxEntries, &totalSeen);

    for (ULONG i = 0; i < sectionWritten; i++) {
        PMYARK_FILE_MAPPING_ENTRY dest = &out->Entries[i];
        RtlZeroMemory(dest, sizeof(*dest));
        dest->ControlAreaAddress = tmpRows[i].ControlAreaAddress;
        dest->FileObjectAddress  = tmpRows[i].FileObjectAddress;
        dest->SizeInBytes        = tmpRows[i].SizeInBytes;
        dest->Flags              = tmpRows[i].Flags;
        dest->ReferenceCount     = *(PUINT32)((PUCHAR)(PVOID)tmpRows[i].ControlAreaAddress
                                              + MYARK_OFF_CA_SECTION_REFS)
                                + *(PUINT32)((PUCHAR)(PVOID)tmpRows[i].ControlAreaAddress
                                              + MYARK_OFF_CA_USER_REFS);
        RtlCopyMemory(dest->FilePath,
                      tmpRows[i].Name,
                      sizeof(dest->FilePath));
    }

    ExFreePoolWithTag(tmpRows, 'tmpS');

    out->Size      = (UINT32)(FIELD_OFFSET(MYARK_SECTION_QUERY_FILE_MAPPINGS_OUTPUT, Entries[0])
                              + sectionWritten * sizeof(MYARK_FILE_MAPPING_ENTRY));
    out->Count     = sectionWritten;
    out->TotalSeen = totalSeen;
    *BytesReturned = out->Size;
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_SECTION
