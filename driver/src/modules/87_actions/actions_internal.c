// MyArk actions module: safety-token validation + output header init.

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "module_registry.h"
#include "myark_config.h"
#include "../../../shared/driver/MyArkActionsIoctl.h"
#include "actions_descriptor.h"
#include "actions_internal.h"
#include "../../dispatch/safety_token.h"

#if MYARK_MODULE_ACTIONS

#pragma warning(push)
#pragma warning(disable: 4201)

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
MyArkActionsValidateToken(
    _In_ PMYARK_SAFETY_TOKEN Token,
    _In_ UINT32             ExpectedOperation,
    _In_ UINT32             ExpectedPid)
{
    //
    // Delegates to the core HMAC validator: Magic/Pid/Operation binding,
    // timestamp freshness window, and HMAC-SHA256 digest verification
    // keyed with the per-boot session key (see dispatch/safety_token.c).
    //
    return MyArkSafetyTokenValidate(Token, ExpectedOperation, ExpectedPid);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
MyArkActionsInitOutputHeader(
    _Out_ PMYARK_ACTION_OUTPUT Header,
    _In_  UINT32               ResultCode,
    _In_  UINT32               ExecutedTier,
    _In_  PCSTR                AuditMessage)
{
    RtlZeroMemory(Header, sizeof(*Header));
    Header->Size = (UINT32)sizeof(MYARK_ACTION_OUTPUT);
    Header->ResultCode = ResultCode;
    Header->ExecutedTier = ExecutedTier;
    KeQuerySystemTime(&Header->Timestamp);
    if (AuditMessage != NULL) {
        RtlStringCbCopyA((NTSTRSAFE_PSTR)Header->AuditMessage,
                         sizeof(Header->AuditMessage),
                         AuditMessage);
    }
}

#pragma warning(pop)

#endif // MYARK_MODULE_ACTIONS
