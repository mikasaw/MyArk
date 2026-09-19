// MyArk security-audit module: descriptor + IOCTL table.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../../shared/driver/MyArkSecurityAuditIoctl.h"
#include "secaudit_descriptor.h"
#include "secaudit_internal.h"

#if MYARK_MODULE_SECURITY_AUDIT

static MYARK_IOCTL_ENTRY g_SecurityAuditIoctls[] = {
    {
        IOCTL_MYARK_SECURITY_AUDIT_DEFENDER,
        MyArkSecurityAuditIoctlDefender,
        "IOCTL_MYARK_SECURITY_AUDIT_DEFENDER",
        0,
        0
    },
    {
        IOCTL_MYARK_SECURITY_AUDIT_SECURE_BOOT,
        MyArkSecurityAuditIoctlSecureBoot,
        "IOCTL_MYARK_SECURITY_AUDIT_SECURE_BOOT",
        0,
        0
    },
    {
        IOCTL_MYARK_SECURITY_AUDIT_TRUSTED_BOOT,
        MyArkSecurityAuditIoctlTrustedBoot,
        "IOCTL_MYARK_SECURITY_AUDIT_TRUSTED_BOOT",
        0,
        0
    },
    {
        IOCTL_MYARK_SECURITY_AUDIT_POSTURE,
        MyArkSecurityAuditIoctlPosture,
        "IOCTL_MYARK_SECURITY_AUDIT_POSTURE",
        0,
        0
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_SecurityAudit = {
    "security_audit",                              // ModuleName
    "Security audit - Defender / Secure Boot / Trusted Boot (3 IOCTLs)",
    MYARK_SECURITY_AUDIT_MODULE_ID,               // ModuleId ('SECA')
    RTL_NUMBER_OF(g_SecurityAuditIoctls),          // IoctlCount
    g_SecurityAuditIoctls,                         // Ioctls
    MyArkSecurityAuditInit,                        // Init
    MyArkSecurityAuditCleanup,                     // Cleanup
    FALSE                                          // Initialized (set by loader)
};

NTSTATUS
MyArkSecurityAuditInit(
    void)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_SECAUDIT,
                "MyArkSecurityAuditInit: security-audit module linked (%lu IOCTLs)",
                (unsigned long)g_MyArkModule_SecurityAudit.IoctlCount);
    return STATUS_SUCCESS;
}

VOID
MyArkSecurityAuditCleanup(
    void)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_SECAUDIT,
                "MyArkSecurityAuditCleanup: security-audit module torn down");
}

#endif // MYARK_MODULE_SECURITY_AUDIT