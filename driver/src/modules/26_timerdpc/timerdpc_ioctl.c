// timerdpc R0 IOCTL handlers: thin wrappers around the walk engine.

#include "myark_config.h"
#include "timerdpc_descriptor.h"
#include "timerdpc_internal.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../../shared/driver/MyArkTimerIoctl.h"

#if MYARK_MODULE_TIMERDPC

NTSTATUS
MyArkTimerDpcIoctlQueryTimer(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    NTSTATUS status;
    PVOID outBuf = NULL;
    SIZE_T outSize = 0;
    SIZE_T headSize = FIELD_OFFSET(MYARK_TIMER_QUERY_OUTPUT, Entries[0]);
    ULONG bytesReturned = 0;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);

    if (OutputBufferLength < headSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request, headSize, &outBuf, &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkTdpEnsureInit();
    RtlZeroMemory(outBuf, headSize);
    if (!NT_SUCCESS(status)) {
        ((PMYARK_TIMER_QUERY_OUTPUT)outBuf)->Status = MYARK_TDP_STATUS_NO_OFFSETS;
        ((PMYARK_TIMER_QUERY_OUTPUT)outBuf)->EntryStructSize =
            (UINT32)sizeof(MYARK_TIMER_ENTRY);
        *BytesReturned = headSize;
        return STATUS_SUCCESS;
    }

    (VOID)MyArkTimerDpcWalkTimers((PUCHAR)outBuf, outSize, &bytesReturned);
    *BytesReturned = bytesReturned;
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkTimerDpcIoctlQueryDpc(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    NTSTATUS status;
    PVOID outBuf = NULL;
    SIZE_T outSize = 0;
    SIZE_T headSize = FIELD_OFFSET(MYARK_DPC_QUERY_OUTPUT, Entries[0]);
    ULONG bytesReturned = 0;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);

    if (OutputBufferLength < headSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request, headSize, &outBuf, &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkTdpEnsureInit();
    RtlZeroMemory(outBuf, headSize);
    if (!NT_SUCCESS(status)) {
        ((PMYARK_DPC_QUERY_OUTPUT)outBuf)->Status = MYARK_TDP_STATUS_NO_OFFSETS;
        ((PMYARK_DPC_QUERY_OUTPUT)outBuf)->EntryStructSize =
            (UINT32)sizeof(MYARK_DPC_ENTRY);
        *BytesReturned = headSize;
        return STATUS_SUCCESS;
    }

    (VOID)MyArkTimerDpcWalkDpcs((PUCHAR)outBuf, outSize, &bytesReturned);
    *BytesReturned = bytesReturned;
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_TIMERDPC