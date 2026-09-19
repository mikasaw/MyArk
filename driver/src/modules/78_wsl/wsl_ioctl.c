// wsl R0 IOCTL handlers.
//
// ENUMERATE_SILOS - R0 read-only walk; in S7.3 returns Count=0 stub.

#include "wsl_descriptor.h"
#include "../../dispatch/ioctl_helpers.h"
#include "../../../shared/driver/MyArkWslIoctl.h"
#include "myark_config.h"

#if MYARK_MODULE_WSL

NTSTATUS MyArkWslIoctlEnumerateSilos(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    NTSTATUS                       status;
    PMYARK_WSL_SILOS_OUTPUT        out_buf;
    size_t                         out_size = sizeof(MYARK_WSL_SILOS_OUTPUT);

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
    out_buf->Count = 0;  // R0 silo walk deferred; S7.x-fix

    *BytesReturned = out_size;
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_WSL
