// MyArk safety module: shared internal helpers (gate table + step checks).

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "module_registry.h"
#include "myark_config.h"
#include "../../../shared/driver/MyArkSafetyIoctl.h"
#include "safety_descriptor.h"
#include "safety_internal.h"

#if MYARK_MODULE_SAFETY

#pragma warning(push)
#pragma warning(disable: 4201)

_IRQL_requires_max_(PASSIVE_LEVEL)
UINT32
MyArkSafetyRequiredSteps(
    _In_ UINT32 OperationCode)
{
    //
    // Each operation demands its own 6-step combo. Conservative defaults:
    // every dangerous op requires AUTHENTICATED + CONFIRM_DIALOG +
    // TOKEN_PRESENTED + TARGET_RESOLVED + AUDIT_LOGGED. Only the
    // review-timeout is optional.
    //
    UINT32 baseMask = MYARK_SAFETY_STEP_AUTHENTICATED
                    | MYARK_SAFETY_STEP_CONFIRM_DIALOG
                    | MYARK_SAFETY_STEP_TOKEN_PRESENTED
                    | MYARK_SAFETY_STEP_TARGET_RESOLVED
                    | MYARK_SAFETY_STEP_AUDIT_LOGGED;

    switch (OperationCode) {
    case MYARK_SAFETY_OP_KILL_PROCESS:
    case MYARK_SAFETY_OP_TERMINATE_THREAD:
    case MYARK_SAFETY_OP_INJECT_DLL:
    case MYARK_SAFETY_OP_DELETE_FILE:
    case MYARK_SAFETY_OP_CLEAR_CALLBACK:
    case MYARK_SAFETY_OP_MUTATE_TOKEN:
        return baseMask;

    default:
        //
        // Unknown op -- require all 6 steps as the most conservative policy.
        //
        return MYARK_SAFETY_STEP_AUTHENTICATED
             | MYARK_SAFETY_STEP_CONFIRM_DIALOG
             | MYARK_SAFETY_STEP_TOKEN_PRESENTED
             | MYARK_SAFETY_STEP_TARGET_RESOLVED
             | MYARK_SAFETY_STEP_AUDIT_LOGGED
             | MYARK_SAFETY_STEP_REVIEW_TIMEOUT;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
UINT32
MyArkSafetyEvaluate(
    _In_ UINT32 OperationCode,
    _In_ UINT32 StepFlags,
    _Out_ PUINT32 FailedStep)
{
    UINT32 required = MyArkSafetyRequiredSteps(OperationCode);

    //
    // Walk each step bit (lowest 6 bits) and report the first unset bit.
    //
    for (UINT32 i = 0; i < 6; i++) {
        UINT32 mask = (UINT32)1 << i;
        if ((required & mask) != 0 && (StepFlags & mask) == 0) {
            if (FailedStep != NULL) {
                *FailedStep = i + 1;
            }
            return MYARK_SAFETY_DECISION_DENY;
        }
    }

    return MYARK_SAFETY_DECISION_APPROVE;
}

#pragma warning(pop)

#endif // MYARK_MODULE_SAFETY