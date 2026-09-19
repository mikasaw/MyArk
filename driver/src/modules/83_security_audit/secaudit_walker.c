// MyArk security-audit module: scaffolding helper (R3 overlays the real readings).

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "module_registry.h"
#include "myark_config.h"
#include "../../../shared/driver/MyArkSecurityAuditIoctl.h"
#include "secaudit_descriptor.h"
#include "secaudit_internal.h"

#if MYARK_MODULE_SECURITY_AUDIT

#pragma warning(push)
#pragma warning(disable: 4201 4100)

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
MyArkSecurityAuditMarkScaffold(
    _Out_writes_(MYARK_SECURITY_AUDIT_NOTE_MAX) PWCHAR Note)
{
    return RtlStringCchCopyW(Note,
                              MYARK_SECURITY_AUDIT_NOTE_MAX,
                              L"security-audit: scaffolding (R3 overlays real values)");
}

#pragma warning(pop)

#endif // MYARK_MODULE_SECURITY_AUDIT