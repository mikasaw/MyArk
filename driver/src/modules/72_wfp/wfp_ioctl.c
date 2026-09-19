// wfp R0 IOCTL handlers.
//
// ENUMERATE_CALLOUTS - read-only; in S7.3 returns Count=0 stub.
// ADD_CALLOUT        - reserved; STATUS_NOT_IMPLEMENTED.
// REMOVE_CALLOUT     - reserved; STATUS_NOT_IMPLEMENTED.

#include "wfp_descriptor.h"
#include "../../dispatch/ioctl_helpers.h"
#include "../../../shared/driver/MyArkWfpIoctl.h"
#include "myark_config.h"

#if MYARK_MODULE_WFP

static NTSTATUS MyArkWfpStubReserved(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    NTSTATUS                     status;
    PMYARK_WFP_CALLOUT_OP_INPUT  in_buf;
    size_t                       in_size = sizeof(MYARK_WFP_CALLOUT_OP_INPUT);

    UNREFERENCED_PARAMETER(Device);

    if (InputBufferLength < in_size) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request, in_size, (PVOID*)&in_buf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    UNREFERENCED_PARAMETER(in_buf);
    *BytesReturned = 0;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS MyArkWfpIoctlEnumerateCallouts(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    NTSTATUS                            status;
    PMYARK_WFP_ENUMERATE_CALLOUTS_OUTPUT out_buf;
    size_t                              out_size = sizeof(MYARK_WFP_ENUMERATE_CALLOUTS_OUTPUT);

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);

    if (OutputBufferLength < out_size) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchOutputBuffer(Request, out_size, (PVOID*)&out_buf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(out_buf, out_size);
    out_buf->Count = 0;  // R0 FwpsCalloutEnumerate deferred; S7.x-fix

    *BytesReturned = out_size;
    return STATUS_SUCCESS;
}

NTSTATUS MyArkWfpIoctlAddCallout(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    UNREFERENCED_PARAMETER(OutputBufferLength);
    return MyArkWfpStubReserved(Device, Request, InputBufferLength, BytesReturned);
}

NTSTATUS MyArkWfpIoctlRemoveCallout(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    UNREFERENCED_PARAMETER(OutputBufferLength);
    return MyArkWfpStubReserved(Device, Request, InputBufferLength, BytesReturned);
}

#endif // MYARK_MODULE_WFP
