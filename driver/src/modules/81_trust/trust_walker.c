// MyArk trust module: scaffolding walker (no kernel walk for S7.3).

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "module_registry.h"
#include "myark_config.h"
#include "../../../shared/driver/MyArkTrustIoctl.h"
#include "trust_descriptor.h"
#include "trust_internal.h"

#if MYARK_MODULE_TRUST

#pragma warning(push)
#pragma warning(disable: 4201 4100)

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
MyArkTrustMarkScaffold(
    _Out_writes_(MYARK_TRUST_SUBJECT_MAX) PWCHAR Subject)
{
    RtlStringCchCopyW(Subject,
                      MYARK_TRUST_SUBJECT_MAX,
                      L"trust: scaffolding (R3 WinVerifyTrust is primary)");
    return STATUS_SUCCESS;
}

#pragma warning(pop)

#endif // MYARK_MODULE_TRUST