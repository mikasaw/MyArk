// MyArk preflight module: IOCTL handlers.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkPreflightIoctl.h"
#include "preflight_descriptor.h"
#include "preflight_internal.h"

#if MYARK_MODULE_PREFLIGHT

//
// HEALTH: emit the environment health snapshot. The driver fills the
// kernel-side fields (kernel base / size / note); R3 merges in OS
// version + bcdedit + Defender state via its own fallback.
//
NTSTATUS
MyArkPreflightIoctlHealth(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);

    NTSTATUS                                  status;
    PVOID                                     outBuf = NULL;
    size_t                                    outSize = 0;

    if (OutputBufferLength < sizeof(MYARK_PREFLIGHT_HEALTH_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_PREFLIGHT_HEALTH_OUTPUT),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_PREFLIGHT_HEALTH_OUTPUT out = (PMYARK_PREFLIGHT_HEALTH_OUTPUT)outBuf;
    status = MyArkPreflightCollectKernelInfo(out);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *BytesReturned = sizeof(MYARK_PREFLIGHT_HEALTH_OUTPUT);
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_PREFLIGHT