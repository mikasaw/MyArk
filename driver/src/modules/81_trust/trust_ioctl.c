// MyArk trust module: IOCTL handlers.
//
// Both IOCTLs run in kernel-mode but delegate the actual cryptographic
// verification to wintrust.dll (resolved via MmGetSystemRoutineAddress).
// For S7.3 we ship a scaffolding reply so R3 can probe the IOCTL; the
// R3 client is the primary verification path (WinVerifyTrust in R3).
//
// The NOT_SIGNED return is the conservative default until the kernel-side
// wintrust wrapper is wired up (planned for S7.3-fix).

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkTrustIoctl.h"
#include "trust_descriptor.h"
#include "trust_internal.h"

#if MYARK_MODULE_TRUST

static
NTSTATUS
MyArkTrustFillNotSigned(
    _Out_ PMYARK_TRUST_VERIFY_OUTPUT Out)
{
    RtlZeroMemory(Out, sizeof(*Out));
    Out->Status = MYARK_TRUST_NOT_SIGNED;
    Out->Flags = 0;
    Out->NotBefore = 0;
    Out->NotAfter = 0;
    Out->Subject[0] = L'\0';
    Out->Issuer[0] = L'\0';
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkTrustIoctlVerifyPe(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                  status;
    PMYARK_TRUST_VERIFY_INPUT                 inBuf = NULL;
    size_t                                    inSize = 0;
    PVOID                                     outBuf = NULL;
    size_t                                    outSize = 0;

    if (InputBufferLength < sizeof(MYARK_TRUST_VERIFY_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_TRUST_VERIFY_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (OutputBufferLength < sizeof(MYARK_TRUST_VERIFY_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_TRUST_VERIFY_OUTPUT),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkTrustFillNotSigned((PMYARK_TRUST_VERIFY_OUTPUT)outBuf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *BytesReturned = sizeof(MYARK_TRUST_VERIFY_OUTPUT);
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkTrustIoctlVerifyCatalog(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                  status;
    PMYARK_TRUST_VERIFY_INPUT                 inBuf = NULL;
    size_t                                    inSize = 0;
    PVOID                                     outBuf = NULL;
    size_t                                    outSize = 0;

    if (InputBufferLength < sizeof(MYARK_TRUST_VERIFY_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_TRUST_VERIFY_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (OutputBufferLength < sizeof(MYARK_TRUST_VERIFY_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_TRUST_VERIFY_OUTPUT),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkTrustFillNotSigned((PMYARK_TRUST_VERIFY_OUTPUT)outBuf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *BytesReturned = sizeof(MYARK_TRUST_VERIFY_OUTPUT);
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_TRUST