// bugcheck R0 IOCTL handlers.
//
// QUERY        - Returns HasRecord=0 stub (last bugcheck record query deferred
//                to S7.x-fix because KeBugCheckEx metadata is volatile across
//                boots).
// RENDER_DIAG  - Returns STATUS_NOT_IMPLEMENTED in S7.3 because direct
//                framebuffer access requires the Hyper-V VMBus child device.

#include "bugcheck_descriptor.h"
#include "../../dispatch/ioctl_helpers.h"
#include "../../../shared/driver/MyArkBugcheckIoctl.h"
#include "myark_config.h"

#if MYARK_MODULE_BUGCHECK

NTSTATUS MyArkBugcheckIoctlQuery(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    NTSTATUS                      status;
    PMYARK_BUGCHECK_QUERY_OUTPUT  out_buf;
    size_t                        out_size = sizeof(MYARK_BUGCHECK_QUERY_OUTPUT);

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
    out_buf->HasRecord = 0;

    *BytesReturned = out_size;
    return STATUS_SUCCESS;
}

NTSTATUS MyArkBugcheckIoctlRenderDiag(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    NTSTATUS                        status;
    PMYARK_BUGCHECK_RENDER_INPUT    in_buf;
    size_t                          in_size = sizeof(MYARK_BUGCHECK_RENDER_INPUT);

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

#endif // MYARK_MODULE_BUGCHECK
