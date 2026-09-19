// alpc R0 IOCTL handlers.
//
// ENUMERATE_PORTS - R0 read-only walk; in S7.3 returns Count=0 stub.
// CLOSE_PORT      - reserved; returns STATUS_NOT_IMPLEMENTED.

#include "alpc_descriptor.h"
#include "../../dispatch/ioctl_helpers.h"
#include "../../../shared/driver/MyArkAlpcIoctl.h"
#include "myark_config.h"

#if MYARK_MODULE_ALPC

NTSTATUS MyArkAlpcIoctlEnumeratePorts(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    NTSTATUS                       status;
    PMYARK_ALPC_PORTS_OUTPUT       out_buf;
    size_t                         out_size = sizeof(MYARK_ALPC_PORTS_OUTPUT);

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
    out_buf->Count = 0;  // R0 ALPC walk deferred; S7.x-fix

    *BytesReturned = out_size;
    return STATUS_SUCCESS;
}

NTSTATUS MyArkAlpcIoctlClosePort(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    NTSTATUS                  status;
    PMYARK_ALPC_CLOSE_INPUT   in_buf;
    size_t                    in_size = sizeof(MYARK_ALPC_CLOSE_INPUT);

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(OutputBufferLength);

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

#endif // MYARK_MODULE_ALPC
