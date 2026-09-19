// MyArk actions module: internal helpers (safety-token validation +
// per-action tier resolution).

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "../../../shared/driver/MyArkActionsIoctl.h"

#if MYARK_MODULE_ACTIONS

#define MYARK_TRACE_ACTIONS                  MYARK_TRACE_MODULE

//
// Validate the supplied MYARK_SAFETY_TOKEN. In Mode A (static-only) the
// check is intentionally lenient: Magic must be 'MARK', Pid/Operation
// must be non-zero, the timestamp must be sane, and the 32-byte
// Signature must contain at least one non-zero byte. The cryptographic
// signature check is wired up in the VM verification stage where a real
// signing key is provisioned.
//
// Returns STATUS_SUCCESS when the token is well-formed enough to gate
// the action; STATUS_ACCESS_DENIED otherwise.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
MyArkActionsValidateToken(
    _In_ PMYARK_SAFETY_TOKEN Token,
    _In_ UINT32             ExpectedOperation,
    _In_ UINT32             ExpectedPid);

//
// Mark the supplied MYARK_ACTION_OUTPUT header with a successful
// "deferred" result (Mode A semantics: R0 acks the request after
// validating the safety token, the destructive path is exercised in
// VM verification). Writes the timestamp, fills AuditMessage with a
// short prefix string, and sets ResultCode/ExecutedTier to the
// supplied values.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
MyArkActionsInitOutputHeader(
    _Out_ PMYARK_ACTION_OUTPUT Header,
    _In_  UINT32               ResultCode,
    _In_  UINT32               ExecutedTier,
    _In_  PCSTR                AuditMessage);

#endif // MYARK_MODULE_ACTIONS
