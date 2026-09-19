// MyArk safety module: internal helpers (gate table + step checks).

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "../../../shared/driver/MyArkSafetyIoctl.h"

#if MYARK_MODULE_SAFETY

#define MYARK_TRACE_SAFETY                   MYARK_TRACE_MODULE

//
// Required-step mask per operation. The gate approves a request only if
// the caller's StepFlags includes every bit in the corresponding mask.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
UINT32
MyArkSafetyRequiredSteps(
    _In_ UINT32 OperationCode);

_IRQL_requires_max_(PASSIVE_LEVEL)
UINT32
MyArkSafetyEvaluate(
    _In_ UINT32 OperationCode,
    _In_ UINT32 StepFlags,
    _Out_ PUINT32 FailedStep);

#endif // MYARK_MODULE_SAFETY