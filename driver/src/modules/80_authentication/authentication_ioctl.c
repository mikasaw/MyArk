// authentication R0 IOCTL handlers.
//
// VERIFY_FILE - in S7.3 returns NOT_SIGNED stub; the full SeSinglePrivilegeCheck
//               + WinVerifyTrust-from-kernel path is deferred to S7.x-fix
//               because WinVerifyTrust is not officially callable from R0.

#include "authentication_descriptor.h"
#include "../../dispatch/ioctl_helpers.h"
#include "../../../shared/driver/MyArkAuthenticationIoctl.h"
#include "myark_config.h"

#if MYARK_MODULE_AUTHENTICATION

static VOID MyArkAuthenticationFillNotSigned(
    _Out_ PMYARK_AUTHENTICATION_VERIFY_OUTPUT out)
{
    RtlZeroMemory(out, sizeof(*out));
    out->Status = MYARK_AUTHENTICATION_NOT_SIGNED;
    out->Flags  = 0;
}

NTSTATUS MyArkAuthenticationIoctlVerifyFile(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    NTSTATUS                                status;
    PMYARK_AUTHENTICATION_VERIFY_INPUT      in_buf;
    PMYARK_AUTHENTICATION_VERIFY_OUTPUT     out_buf;
    size_t                                  in_size  = sizeof(MYARK_AUTHENTICATION_VERIFY_INPUT);
    size_t                                  out_size = sizeof(MYARK_AUTHENTICATION_VERIFY_OUTPUT);

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

    UNREFERENCED_PARAMETER(in_buf);
    MyArkAuthenticationFillNotSigned(out_buf);

    *BytesReturned = out_size;
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_AUTHENTICATION
