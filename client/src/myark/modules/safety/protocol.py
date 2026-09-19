"""
safety R3 - protocol data structures (ctypes mirrors of MyArkSafetyIoctl.h).
"""

from __future__ import annotations

import ctypes

from myark.protocol.core import _ctl_code


# Function code 0xD00 (mirrors MyArkSafetyIoctl.h). Originally 0x800,
# which collided with core GET_VERSION and made EVAL_GATE unreachable.
IOCTL_MYARK_SAFETY_EVAL_GATE = _ctl_code(0xD00)


SAFETY_DECISION_APPROVE = 0
SAFETY_DECISION_DENY = 1
SAFETY_DECISION_REQUIRE_TOKEN = 2


SAFETY_OP_KILL_PROCESS = 1
SAFETY_OP_TERMINATE_THREAD = 2
SAFETY_OP_INJECT_DLL = 3
SAFETY_OP_DELETE_FILE = 4
SAFETY_OP_CLEAR_CALLBACK = 5
SAFETY_OP_MUTATE_TOKEN = 6


SAFETY_STEP_AUTHENTICATED = 0x01
SAFETY_STEP_CONFIRM_DIALOG = 0x02
SAFETY_STEP_TOKEN_PRESENTED = 0x04
SAFETY_STEP_TARGET_RESOLVED = 0x08
SAFETY_STEP_AUDIT_LOGGED = 0x10
SAFETY_STEP_REVIEW_TIMEOUT = 0x20


class MYARK_SAFETY_EVAL_INPUT(ctypes.Structure):
    _fields_ = [
        ("OperationCode", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("StepFlags", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint32),
        ("TargetId", ctypes.c_uint64),
        ("Reserved3", ctypes.c_uint64),
    ]


class MYARK_SAFETY_EVAL_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Decision", ctypes.c_uint32),
        ("FailedStep", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint32),
    ]


SAFETY_OP_NAMES = {
    SAFETY_OP_KILL_PROCESS: "kill_process",
    SAFETY_OP_TERMINATE_THREAD: "terminate_thread",
    SAFETY_OP_INJECT_DLL: "inject_dll",
    SAFETY_OP_DELETE_FILE: "delete_file",
    SAFETY_OP_CLEAR_CALLBACK: "clear_callback",
    SAFETY_OP_MUTATE_TOKEN: "mutate_token",
}

SAFETY_STEP_NAMES = [
    "authenticated",
    "confirm_dialog",
    "token_presented",
    "target_resolved",
    "audit_logged",
    "review_timeout",
]