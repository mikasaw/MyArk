// kernel-ext R0 IOCTL handlers.
//
// QUERY_WIN11_INFO      - returns STATUS_NOT_IMPLEMENTED in S7.3 (R3 has
//                         NtQuerySystemInformation already; this IOCTL is
//                         reserved for the R0 25H2-specific class path).
// READ_SYSCALL_TABLE    - returns STATUS_NOT_IMPLEMENTED for S7.3; the
//                         full table walk depends on Win11 25H2's shifted
//                         offsets and is deferred to S7.x-fix.

#include "kernel_ext_descriptor.h"
#include "../../dispatch/ioctl_helpers.h"
#include "../../../shared/driver/MyArkKernelExtIoctl.h"
#include "myark_config.h"

#if MYARK_MODULE_KERNEL_EXT

NTSTATUS MyArkKernelExtIoctlQueryWin11Info(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    NTSTATUS                status;
    PMYARK_KERNEL_EXT_QUERY_INPUT  in_buf;
    PMYARK_KERNEL_EXT_QUERY_OUTPUT out_buf;
    size_t                  in_size  = sizeof(MYARK_KERNEL_EXT_QUERY_INPUT);
    size_t                  out_size = sizeof(MYARK_KERNEL_EXT_QUERY_OUTPUT);

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
    out_buf->Status         = (UINT32)STATUS_NOT_IMPLEMENTED;
    out_buf->BytesReturned  = 0;
    out_buf->Data[0]        = 0;

    *BytesReturned = out_size;
    return STATUS_SUCCESS;
}

NTSTATUS MyArkKernelExtIoctlReadSyscallTable(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    NTSTATUS                                status;
    PMYARK_KERNEL_EXT_SYSCALL_TABLE_OUTPUT  out_buf;
    size_t                                  out_size = sizeof(MYARK_KERNEL_EXT_SYSCALL_TABLE_OUTPUT);

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
    out_buf->Count     = 0;

    *BytesReturned = out_size;
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_KERNEL_EXT
