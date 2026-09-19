// MyArk handle module: IOCTL handlers.
//
// Two entry points match the IOCTL table in handle_descriptor.c:
//
//   MyArkHandleIoctlEnumProcessHandles -- ENUM_PROCESS_HANDLES
//   MyArkHandleIoctlQueryHandle        -- QUERY_HANDLE
//
// Both resolve the target process to its EPROCESS, read ObjectTable, then
// delegate to MyArkHandleWalkTable (handle_walk.c). QUERY_HANDLE accepts
// a single handle value and emits one row even when the slot is sparse --
// the caller wants a deep single-handle view, not a snapshot.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkHandleIoctl.h"
#include "handle_descriptor.h"
#include "handle_internal.h"

#if MYARK_MODULE_HANDLE

NTSTATUS
PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);

NTSTATUS
MyArkHandleIoctlEnumProcessHandles(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
//
// ENUM_PROCESS_HANDLES: stream the handle table of one process.
// Caller passes Pid (0 = current process) + an optional MaxEntries hint.
// Output buffer holds MYARK_HANDLE_ENUM_OUTPUT + variable Entries[].
//
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                status;
    PMYARK_HANDLE_ENUM_INPUT                inBuf = NULL;
    size_t                                  inSize = 0;
    PVOID                                   outBuf = NULL;
    size_t                                  outSize = 0;

    if (InputBufferLength < sizeof(MYARK_HANDLE_ENUM_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_HANDLE_ENUM_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_HANDLE_ENUM_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_HANDLE_ENUM_OUTPUT out = (PMYARK_HANDLE_ENUM_OUTPUT)outBuf;
    RtlZeroMemory(outBuf, FIELD_OFFSET(MYARK_HANDLE_ENUM_OUTPUT, Entries[0]));

    HANDLE pidHandle = (inBuf->Pid == 0)
                           ? PsGetCurrentProcessId()
                           : UlongToHandle(inBuf->Pid);

    PEPROCESS proc = NULL;
    status = PsLookupProcessByProcessId(pidHandle, &proc);
    if (!NT_SUCCESS(status) || proc == NULL) {
        out->Size = (UINT32)FIELD_OFFSET(MYARK_HANDLE_ENUM_OUTPUT, Entries[0]);
        out->Count = 0;
        *BytesReturned = out->Size;
        return STATUS_NOT_FOUND;
    }

    //
    // DereferenceObject is the official cleanup, but the kernel keeps the
    // EPROCESS pinned while the process is alive -- we just need the
    // pointer to be valid for the duration of the walk.
    //
    PVOID objectTable = *(PVOID*)((PUCHAR)proc + MYARK_OFF_EPROCESS_OBJECT_TABLE);
    if (objectTable == NULL) {
        out->Size = (UINT32)FIELD_OFFSET(MYARK_HANDLE_ENUM_OUTPUT, Entries[0]);
        out->Count = 0;
        *BytesReturned = out->Size;
        return STATUS_SUCCESS;
    }

    //
    // Compute the row capacity from the buffer size, clamped by the
    // caller's MaxEntries + the module hard cap.
    //
    ULONG maxEntries = (ULONG)((OutputBufferLength
                                - FIELD_OFFSET(MYARK_HANDLE_ENUM_OUTPUT, Entries[0]))
                               / sizeof(MYARK_HANDLE_ENTRY));
    if (inBuf->MaxEntries != 0 && inBuf->MaxEntries < maxEntries) {
        maxEntries = inBuf->MaxEntries;
    }
    if (maxEntries > MYARK_HANDLE_HARD_CAP) {
        maxEntries = MYARK_HANDLE_HARD_CAP;
    }
    if (maxEntries == 0) {
        out->Size = (UINT32)FIELD_OFFSET(MYARK_HANDLE_ENUM_OUTPUT, Entries[0]);
        out->Count = 0;
        *BytesReturned = out->Size;
        return STATUS_BUFFER_TOO_SMALL;
    }

    ULONG written = 0;
    ULONG totalSeen = 0;
    status = MyArkHandleWalkTable(objectTable,
                                  out->Entries,
                                  maxEntries,
                                  &written,
                                  &totalSeen);

    out->Size       = (UINT32)(FIELD_OFFSET(MYARK_HANDLE_ENUM_OUTPUT, Entries[0])
                               + written * sizeof(MYARK_HANDLE_ENTRY));
    out->Count      = written;
    out->TotalSeen  = totalSeen;
    *BytesReturned  = out->Size;

    return status;
}

NTSTATUS
MyArkHandleIoctlQueryHandle(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
//
// QUERY_HANDLE: deep view of one (Pid, HandleValue) pair. Walks the table
// to find the slot, then resolves OBJECT_HEADER fields + object name.
//
{
    UNREFERENCED_PARAMETER(Device);

    if (OutputBufferLength < sizeof(MYARK_HANDLE_QUERY_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (InputBufferLength < sizeof(MYARK_HANDLE_QUERY_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    NTSTATUS                                status;
    PMYARK_HANDLE_QUERY_INPUT               inBuf = NULL;
    size_t                                  inSize = 0;
    PMYARK_HANDLE_QUERY_OUTPUT              outBuf = NULL;
    size_t                                  outSize = 0;

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_HANDLE_QUERY_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_HANDLE_QUERY_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(outBuf, sizeof(*outBuf));

    HANDLE pidHandle = (inBuf->Pid == 0)
                           ? PsGetCurrentProcessId()
                           : UlongToHandle(inBuf->Pid);

    PEPROCESS proc = NULL;
    status = PsLookupProcessByProcessId(pidHandle, &proc);
    if (!NT_SUCCESS(status) || proc == NULL) {
        outBuf->Status = (UINT32)STATUS_NOT_FOUND;
        *BytesReturned = sizeof(*outBuf);
        return STATUS_SUCCESS;
    }

    PVOID objectTable = *(PVOID*)((PUCHAR)proc + MYARK_OFF_EPROCESS_OBJECT_TABLE);
    if (objectTable == NULL) {
        outBuf->Status = (UINT32)STATUS_NOT_FOUND;
        *BytesReturned = sizeof(*outBuf);
        return STATUS_SUCCESS;
    }

    if (!MmIsAddressValid(objectTable)) {
        outBuf->Status = (UINT32)STATUS_UNSUCCESSFUL;
        *BytesReturned = sizeof(*outBuf);
        return STATUS_SUCCESS;
    }

    UINT64 tableCode = *(PUINT64)((PUCHAR)objectTable + MYARK_OFF_HT_TABLE_CODE);
    UINT64 tableLevel = tableCode & 0x3ULL;
    PVOID  tableEntries = (PVOID)(tableCode & ~(UINT64)0x3ULL);

    if (tableLevel != 0 || !MmIsAddressValid(tableEntries)) {
        outBuf->Status = (UINT32)STATUS_NOT_SUPPORTED;
        *BytesReturned = sizeof(*outBuf);
        return STATUS_SUCCESS;
    }

    //
    // Compute the slot index from the handle value. Classic formula:
    //   slot = (value >> 2) & ((1 << 10) - 1)   for L0 tables
    //
    UINT64 slot = ((inBuf->HandleValue >> 2) & (MYARK_HT_L0_CAPACITY - 1));
    PUINT64 entries = (PUINT64)tableEntries;

    UINT64 objectWithFlags = entries[(slot * 2) + 1];
    PVOID  objectBody = (PVOID)(objectWithFlags & ~(UINT64)0xFULL);

    if (objectBody == NULL) {
        outBuf->Status = (UINT32)STATUS_NOT_FOUND;
        *BytesReturned = sizeof(*outBuf);
        return STATUS_SUCCESS;
    }

    UINT32 ptrCount = 0, hdrCount = 0, typeIndex = 0, obFlags = 0;
    NTSTATUS fillStatus = MyArkHandleFillObjectHeaderFields(objectBody,
                                                            &ptrCount,
                                                            &hdrCount,
                                                            &typeIndex,
                                                            &obFlags);
    outBuf->Status       = fillStatus;
    outBuf->PointerCount = ptrCount;
    outBuf->HandleCount  = hdrCount;
    outBuf->TypeIndex    = typeIndex;
    outBuf->GrantedAccess = (UINT32)(entries[(slot * 2)] >> 16);
    outBuf->Flags        = (obFlags & MYARK_OBJ_HDR_FLAG_NAME_INFO)
                              ? MYARK_HANDLE_FLAG_PROTECTED
                              : 0;

    MyArkHandleResolveTypeName(typeIndex,
                               outBuf->TypeName,
                               MYARK_HANDLE_TYPE_NAME_MAX);

    MyArkHandleResolveObjectName(objectBody,
                                 outBuf->Name,
                                 MYARK_HANDLE_NAME_MAX);

    *BytesReturned = sizeof(*outBuf);
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_HANDLE
