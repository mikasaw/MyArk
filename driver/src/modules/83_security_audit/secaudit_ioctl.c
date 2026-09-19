// MyArk security-audit module: IOCTL handlers.
//
// All three handlers populate their respective output struct with a
// best-effort scaffolding report. The R3 client overlays the real WMI /
// bcdedit / EFI readings via its own fallback path.

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkSecurityAuditIoctl.h"
#include "secaudit_descriptor.h"
#include "secaudit_internal.h"

#if MYARK_MODULE_SECURITY_AUDIT

static
NTSTATUS
MyArkSecurityAuditFillNote(
    _Out_writes_(MYARK_SECURITY_AUDIT_NOTE_MAX) PWCHAR Destination,
    _In_                                        PCWSTR Source)
{
    return RtlStringCchCopyW(Destination,
                              MYARK_SECURITY_AUDIT_NOTE_MAX,
                              Source);
}

NTSTATUS
MyArkSecurityAuditIoctlDefender(
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

    if (OutputBufferLength < sizeof(MYARK_SECURITY_AUDIT_DEFENDER_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_SECURITY_AUDIT_DEFENDER_OUTPUT),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_SECURITY_AUDIT_DEFENDER_OUTPUT out = (PMYARK_SECURITY_AUDIT_DEFENDER_OUTPUT)outBuf;
    RtlZeroMemory(out, sizeof(*out));
    status = MyArkSecurityAuditFillNote(out->Note, L"defender: R3 overlays WMI");
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *BytesReturned = sizeof(MYARK_SECURITY_AUDIT_DEFENDER_OUTPUT);
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkSecurityAuditIoctlSecureBoot(
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

    if (OutputBufferLength < sizeof(MYARK_SECURITY_AUDIT_SECURE_BOOT_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_SECURITY_AUDIT_SECURE_BOOT_OUTPUT),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_SECURITY_AUDIT_SECURE_BOOT_OUTPUT out = (PMYARK_SECURITY_AUDIT_SECURE_BOOT_OUTPUT)outBuf;
    RtlZeroMemory(out, sizeof(*out));
    status = MyArkSecurityAuditFillNote(out->Note, L"secure_boot: R3 reads EFI variable");
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *BytesReturned = sizeof(MYARK_SECURITY_AUDIT_SECURE_BOOT_OUTPUT);
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkSecurityAuditIoctlTrustedBoot(
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

    if (OutputBufferLength < sizeof(MYARK_SECURITY_AUDIT_TRUSTED_BOOT_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_SECURITY_AUDIT_TRUSTED_BOOT_OUTPUT),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_SECURITY_AUDIT_TRUSTED_BOOT_OUTPUT out = (PMYARK_SECURITY_AUDIT_TRUSTED_BOOT_OUTPUT)outBuf;
    RtlZeroMemory(out, sizeof(*out));
    status = MyArkSecurityAuditFillNote(out->Note, L"trusted_boot: R3 reads measured-boot log");
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *BytesReturned = sizeof(MYARK_SECURITY_AUDIT_TRUSTED_BOOT_OUTPUT);
    return STATUS_SUCCESS;
}


//
// POSTURE (R3-6): read-only platform security posture snapshot.
//
NTSTATUS
MyArkSecurityAuditIoctlPosture(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    NTSTATUS status;
    PVOID    outBuf = NULL;
    size_t   outSize = 0;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);

    if (OutputBufferLength < sizeof(MYARK_SECURITY_AUDIT_POSTURE_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_SECURITY_AUDIT_POSTURE_OUTPUT),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkSecurityAuditPosture(
        (PMYARK_SECURITY_AUDIT_POSTURE_OUTPUT)outBuf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *BytesReturned = sizeof(MYARK_SECURITY_AUDIT_POSTURE_OUTPUT);
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_SECURITY_AUDIT
