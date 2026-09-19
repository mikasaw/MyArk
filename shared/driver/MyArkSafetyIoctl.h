// MyArk safety module: shared IOCTL protocol between R0 and R3.
//
// Function range 0xD00..0xD0F reserved for the safety (6-step gate)
// module (S7.3). Safety is R3-primary: the 6-step gate policy engine
// lives in R3, but the driver publishes a gate-state IOCTL so the
// policy engine can ask the driver whether a dangerous operation is
// currently permitted.
//
// History: the module originally sat at function 0x800, which collided
// with the core GET_VERSION code; the ioctl registry rejected the
// duplicate and EVAL_GATE was unreachable (KNOWN_ISSUES S6b). Moved to
// the free 0xD00 block (2026-09-15).
//
// The 1 IOCTL:
//
//   0xD00  EVAL_GATE         - Evaluate the 6-step gate for a request
//
// All 1 IOCTLs use the MyArk METHOD_BUFFERED convention.

#pragma once

#include <ntddk.h>
#include <wdf.h>

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_SAFETY_MODULE_ID                0x53414645UL  // 'SAFE' ASCII (LE)

//
// 1 IOCTL (function range 0xD00..0xD0F). Method/Access match the rest of
// the driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_SAFETY_EVAL_GATE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xD00, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// EVAL_GATE input: operation code + 6-step flags (each step must be set
// before the gate approves the request).
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_SAFETY_EVAL_INPUT {
    UINT32  OperationCode;                        // see MYARK_SAFETY_OP_*
    UINT32  Reserved1;
    UINT32  StepFlags;                             // bit i = step i completed
    UINT32  Reserved2;
    UINT64  TargetId;
    UINT64  Reserved3;
} MYARK_SAFETY_EVAL_INPUT, *PMYARK_SAFETY_EVAL_INPUT;

//
// EVAL_GATE output: gate result.
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_SAFETY_EVAL_OUTPUT {
    UINT32  Decision;                             // 0 = approve, 1 = deny, 2 = require-token
    UINT32  FailedStep;                           // when Decision=1, the first unmet step
    UINT32  Reserved1;
    UINT32  Reserved2;
} MYARK_SAFETY_EVAL_OUTPUT, *PMYARK_SAFETY_EVAL_OUTPUT;

#define MYARK_SAFETY_DECISION_APPROVE         0
#define MYARK_SAFETY_DECISION_DENY            1
#define MYARK_SAFETY_DECISION_REQUIRE_TOKEN    2

//
// Operation codes.
//
#define MYARK_SAFETY_OP_KILL_PROCESS          1
#define MYARK_SAFETY_OP_TERMINATE_THREAD      2
#define MYARK_SAFETY_OP_INJECT_DLL            3
#define MYARK_SAFETY_OP_DELETE_FILE           4
#define MYARK_SAFETY_OP_CLEAR_CALLBACK        5
#define MYARK_SAFETY_OP_MUTATE_TOKEN          6

//
// 6-step gate bits.
//
#define MYARK_SAFETY_STEP_AUTHENTICATED       0x00000001UL
#define MYARK_SAFETY_STEP_CONFIRM_DIALOG      0x00000002UL
#define MYARK_SAFETY_STEP_TOKEN_PRESENTED     0x00000004UL
#define MYARK_SAFETY_STEP_TARGET_RESOLVED     0x00000008UL
#define MYARK_SAFETY_STEP_AUDIT_LOGGED        0x00000010UL
#define MYARK_SAFETY_STEP_REVIEW_TIMEOUT      0x00000020UL