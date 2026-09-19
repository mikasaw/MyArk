// hwid R0 IOCTL handlers.
//
// ENUMERATE_MJ   - R0 read-only walk of driver MajorFunction tables.
//                  In S7.3 returns Count=0 (the full IoDriverObjectType
//                  walk depends on Win11 25H2's shifted offsets; deferred
//                  to S7.x-fix).
// REPLACE_MJ     - reserved; returns STATUS_NOT_IMPLEMENTED.

#include "hwid_descriptor.h"
#include "../../dispatch/ioctl_helpers.h"
#include "../../../shared/driver/MyArkHwidIoctl.h"
#include "myark_config.h"

#if MYARK_MODULE_HWID

NTSTATUS MyArkHwidIoctlEnumerateMj(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    NTSTATUS                            status;
    PMYARK_HWID_ENUMERATE_MJ_INPUT      in_buf;
    PMYARK_HWID_ENUMERATE_MJ_OUTPUT     out_buf;
    size_t                              in_size  = sizeof(MYARK_HWID_ENUMERATE_MJ_INPUT);
    size_t                              out_size = sizeof(MYARK_HWID_ENUMERATE_MJ_OUTPUT);

    UNREFERENCED_PARAMETER(Device);

    if (InputBufferLength < in_size || OutputBufferLength < out_size) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request, in_size, (PVOID*)&in_buf);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request, out_size, (PVOID*)&out_buf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(out_buf, out_size);
    out_buf->Count = 0;  // R0 walk deferred; S7.x-fix

    *BytesReturned = out_size;
    return STATUS_SUCCESS;
}

NTSTATUS MyArkHwidIoctlReplaceMj(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    NTSTATUS                       status;
    PMYARK_HWID_REPLACE_MJ_INPUT   in_buf;
    size_t                         in_size = sizeof(MYARK_HWID_REPLACE_MJ_INPUT);

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

#endif // MYARK_MODULE_HWID
