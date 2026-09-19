// redirect internal types + R2-9 engine API.
//
// FLT-typed prototypes (MyArkRedirectFilePreCreate / MyArkRedirectCmCallback)
// intentionally live in the .c files that already include fltKernel.h first
// (filemon_monitor.c declares the pre-create prototype locally); this header
// stays ntddk-only so the S7.3 handlers can include it safely.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "../../../shared/driver/MyArkRedirectIoctl.h"

#if MYARK_MODULE_REDIRECT

#define MYARK_TRACE_REDIRECT "[redirect] "

VOID MyArkRedirectMarkScaffold(VOID);

// -- R2-9 redirect engine (redirect_engine.c) ------------------------------

// Two-phase SET_RULES: Stage validates + resolves the rule list out of the
// shared input buffer, Commit swaps it live (and registers/unregisters the
// Cm callback to match the armed REG-rule count).
NTSTATUS
MyArkRedirectStageRules(
    _In_ const MYARK_REDIRECT_RULE* Rules,
    _In_ UINT32 Count,
    _In_ UINT32 Flags);

NTSTATUS
MyArkRedirectCommitRules(
    _Out_ PUINT32 Accepted,
    _Out_ PUINT32 FileRules,
    _Out_ PUINT32 RegRules);

VOID
MyArkRedirectQueryStatus(
    _Out_ PMYARK_REDIRECT_STATUS_OUTPUT Output);

// Zeroes engine state (module Init).
VOID
MyArkRedirectEngineInit(
    VOID);

// Clears rules and unregisters the Cm callback (module cleanup).
VOID
MyArkRedirectEngineTeardown(
    VOID);

NTSTATUS
MyArkRedirectCmCallback(
    _In_ PVOID CallbackContext,
    _In_ PVOID NotificationClassRaw,
    _In_ PVOID Argument2);

#endif
