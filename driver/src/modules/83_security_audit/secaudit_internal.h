// MyArk security-audit module: internal helpers.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "../../../shared/driver/MyArkSecurityAuditIoctl.h"

#if MYARK_MODULE_SECURITY_AUDIT

#define MYARK_TRACE_SECAUDIT                MYARK_TRACE_MODULE

NTSTATUS
MyArkSecurityAuditPosture(
    _Out_ PMYARK_SECURITY_AUDIT_POSTURE_OUTPUT Output);

#endif // MYARK_MODULE_SECURITY_AUDIT