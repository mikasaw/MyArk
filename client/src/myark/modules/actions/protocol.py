"""
actions R3 - protocol data structures (ctypes mirrors of MyArkActionsIoctl.h).

Mirrors ``shared/driver/MyArkActionsIoctl.h`` -- every structure here has
the exact same field order, type and size as the kernel struct. The IOCTL
codes match the kernel-side ``CTL_CODE(FILE_DEVICE_UNKNOWN, 0x87X,
METHOD_BUFFERED, FILE_ANY_ACCESS)`` formula with FILE_DEVICE_UNKNOWN=0x22.

The actions module is the only Stage-5 mixed module (R0 + R3 fallback).
The tiered-degradation policy lives in ``parser.py``: every action
defaults to a host-friendly R3 implementation and only consults the
driver when ``ArkClient.open_or_null()`` succeeds AND the action is
one of the R0-fallback-friendly cases (KILL / TERMINATE_THREAD /
INJECT_DLL / DUMP_MEMORY).  R0-only actions (SET_TOKEN, HIDE_PROCESS,
PROTECT_PROCESS) have no R3 fallback and raise
:class:`R3FallbackUnavailable` when the driver is not installed.
"""

from __future__ import annotations

import ctypes

from myark.protocol.core import _ctl_code


# ---------------------------------------------------------------------------
# Module identity + IOCTL function codes (mirror MyArkActionsIoctl.h).
# ---------------------------------------------------------------------------

MYARK_ACTIONS_MODULE_ID = 0x4143544E  # 'ACTN' ASCII (LE)

IOCTL_MYARK_ACTION_KILL_PROCESS     = _ctl_code(0x870)
IOCTL_MYARK_ACTION_TERMINATE_THREAD = _ctl_code(0x871)
IOCTL_MYARK_ACTION_INJECT_DLL       = _ctl_code(0x872)
IOCTL_MYARK_ACTION_DUMP_MEMORY      = _ctl_code(0x873)
IOCTL_MYARK_ACTION_SET_TOKEN        = _ctl_code(0x874)
IOCTL_MYARK_ACTION_HIDE_PROCESS     = _ctl_code(0x875)
IOCTL_MYARK_ACTION_PROTECT_PROCESS  = _ctl_code(0x876)


# IOCTL function ranges used by the verifier and tier-resolver.
ACTIONS_IOCTL_FUNCTIONS = {
    "kill_process":      0x870,
    "terminate_thread":  0x871,
    "inject_dll":        0x872,
    "dump_memory":       0x873,
    "set_token":         0x874,
    "hide_process":      0x875,
    "protect_process":   0x876,
}


# ---------------------------------------------------------------------------
# Safety-token magic + signature size (mirror MyArkActionsIoctl.h).
# ---------------------------------------------------------------------------

MYARK_SAFETY_TOKEN_MAGIC          = 0x4D41524B  # 'MARK' ASCII (LE)
MYARK_SAFETY_TOKEN_SIGNATURE_SIZE = 32


# ---------------------------------------------------------------------------
# Operation codes carried in MYARK_SAFETY_TOKEN.Operation (mirror
# MYARK_ACTION_OP_* in MyArkActionsIoctl.h).
# ---------------------------------------------------------------------------

MYARK_ACTION_OP_KILL_PROCESS     = 1
MYARK_ACTION_OP_TERMINATE_THREAD = 2
MYARK_ACTION_OP_INJECT_DLL       = 3
MYARK_ACTION_OP_DUMP_MEMORY      = 4
MYARK_ACTION_OP_SET_TOKEN        = 5
MYARK_ACTION_OP_HIDE_PROCESS     = 6
MYARK_ACTION_OP_PROTECT_PROCESS  = 7


ACTIONS_OP_NAMES = {
    MYARK_ACTION_OP_KILL_PROCESS:     "kill_process",
    MYARK_ACTION_OP_TERMINATE_THREAD: "terminate_thread",
    MYARK_ACTION_OP_INJECT_DLL:       "inject_dll",
    MYARK_ACTION_OP_DUMP_MEMORY:      "dump_memory",
    MYARK_ACTION_OP_SET_TOKEN:        "set_token",
    MYARK_ACTION_OP_HIDE_PROCESS:     "hide_process",
    MYARK_ACTION_OP_PROTECT_PROCESS:  "protect_process",
}

ACTIONS_NAME_TO_OP = {v: k for k, v in ACTIONS_OP_NAMES.items()}


# ---------------------------------------------------------------------------
# Result codes + tier codes returned in MYARK_ACTION_OUTPUT (mirror
# MYARK_ACTION_RESULT_* / MYARK_ACTION_TIER_* in MyArkActionsIoctl.h).
# ---------------------------------------------------------------------------

MYARK_ACTION_RESULT_APPROVED         = 0
MYARK_ACTION_RESULT_DENIED           = 1
MYARK_ACTION_RESULT_DENIED_NO_TOKEN  = 2
MYARK_ACTION_RESULT_DENIED_STEPS     = 3
MYARK_ACTION_RESULT_DEFERRED         = 4   # Mode A: R0 ack, real exec on VM
MYARK_ACTION_RESULT_FAILED           = 5
MYARK_ACTION_RESULT_R3_FALLBACK      = 6

MYARK_ACTION_TIER_R0       = 0
MYARK_ACTION_TIER_R3       = 1
MYARK_ACTION_TIER_DEFERRED = 2

ACTIONS_RESULT_NAMES = {
    MYARK_ACTION_RESULT_APPROVED:        "approved",
    MYARK_ACTION_RESULT_DENIED:          "denied",
    MYARK_ACTION_RESULT_DENIED_NO_TOKEN: "denied_no_token",
    MYARK_ACTION_RESULT_DENIED_STEPS:    "denied_steps",
    MYARK_ACTION_RESULT_DEFERRED:        "deferred",
    MYARK_ACTION_RESULT_FAILED:          "failed",
    MYARK_ACTION_RESULT_R3_FALLBACK:     "r3_fallback",
}

ACTIONS_TIER_NAMES = {
    MYARK_ACTION_TIER_R0:       "r0",
    MYARK_ACTION_TIER_R3:       "r3",
    MYARK_ACTION_TIER_DEFERRED: "deferred",
}


# Which actions have an R3 fallback (the rest are R0-only). The dict
# mirrors the plan-v3 table verbatim.
ACTIONS_R0_FALLBACK_AVAILABLE = frozenset({
    "kill_process",
    "terminate_thread",
    "inject_dll",
    "dump_memory",
})


# ---------------------------------------------------------------------------
# Token-type + protect-flag enums (mirror MyArkActionsIoctl.h).
# ---------------------------------------------------------------------------

MYARK_ACTION_TOKEN_TYPE_PRIMARY       = 0
MYARK_ACTION_TOKEN_TYPE_IMPERSONATION  = 1

ACTIONS_TOKEN_TYPE_NAMES = {
    MYARK_ACTION_TOKEN_TYPE_PRIMARY:      "primary",
    MYARK_ACTION_TOKEN_TYPE_IMPERSONATION: "impersonation",
}

MYARK_ACTION_PROTECT_FLAG_NONE   = 0x00000000
MYARK_ACTION_PROTECT_FLAG_SIGNED = 0x00000001
MYARK_ACTION_PROTECT_FLAG_LSA    = 0x00000002
MYARK_ACTION_PROTECT_FLAG_WINTCB = 0x00000004


# ---------------------------------------------------------------------------
# Sizes used by the WCHAR buffers + DUMP_MEMORY byte cap.
# ---------------------------------------------------------------------------

MYARK_ACTION_KILL_MAX_REASON_CHARS = 256
MYARK_ACTION_DLL_PATH_MAX_CHARS    = 260            # MAX_PATH
MYARK_ACTION_DUMP_MAX_BYTES        = 4096


# ---------------------------------------------------------------------------
# MYARK_SAFETY_TOKEN (mirror _MYARK_SAFETY_TOKEN).
# Layout: 4 UINT32 (Magic, Pid, Operation, Reserved1) + LARGE_INTEGER
#         Timestamp + 32-byte Signature + 16-byte Reserved2 = 72 bytes.
# ---------------------------------------------------------------------------

class MYARK_SAFETY_TOKEN(ctypes.Structure):
    _fields_ = [
        ("Magic",      ctypes.c_uint32),
        ("Pid",        ctypes.c_uint32),
        ("Operation",  ctypes.c_uint32),
        ("Reserved1",  ctypes.c_uint32),
        ("Timestamp",  ctypes.c_int64),
        ("Signature",  ctypes.c_uint8 * MYARK_SAFETY_TOKEN_SIGNATURE_SIZE),
        ("Reserved2",  ctypes.c_uint8 * 16),
    ]


# ---------------------------------------------------------------------------
# MYARK_ACTION_OUTPUT (mirror _MYARK_ACTION_OUTPUT).
# Layout: 4 UINT32 + LARGE_INTEGER + 64-byte AuditMessage = 88 bytes.
# ---------------------------------------------------------------------------

class MYARK_ACTION_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size",          ctypes.c_uint32),
        ("ResultCode",    ctypes.c_uint32),
        ("ExecutedTier",  ctypes.c_uint32),
        ("Reserved1",     ctypes.c_uint32),
        ("Timestamp",     ctypes.c_int64),
        ("AuditMessage",  ctypes.c_uint8 * 64),
    ]


# ---------------------------------------------------------------------------
# Per-action input/output structs (mirror _MYARK_ACTION_*_INPUT / _OUTPUT).
# ---------------------------------------------------------------------------

class MYARK_ACTION_KILL_INPUT(ctypes.Structure):
    _fields_ = [
        ("Token",      MYARK_SAFETY_TOKEN),
        ("Pid",        ctypes.c_uint32),
        ("ExitCode",   ctypes.c_uint32),
        ("Reserved1",  ctypes.c_uint32),
        ("Reserved2",  ctypes.c_uint32),
        ("Reason",     ctypes.c_wchar * MYARK_ACTION_KILL_MAX_REASON_CHARS),
    ]


class MYARK_ACTION_KILL_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Header",     MYARK_ACTION_OUTPUT),
        ("Pid",        ctypes.c_uint32),
        ("ExitCode",   ctypes.c_uint32),
        ("Reserved1",  ctypes.c_uint32),
        ("Reserved2",  ctypes.c_uint32),
    ]


class MYARK_ACTION_TERMINATE_THREAD_INPUT(ctypes.Structure):
    _fields_ = [
        ("Token",      MYARK_SAFETY_TOKEN),
        ("Pid",        ctypes.c_uint32),
        ("Tid",        ctypes.c_uint32),
        ("ExitCode",   ctypes.c_uint32),
        ("Reserved1",  ctypes.c_uint32),
    ]


class MYARK_ACTION_TERMINATE_THREAD_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Header",     MYARK_ACTION_OUTPUT),
        ("Pid",        ctypes.c_uint32),
        ("Tid",        ctypes.c_uint32),
        ("ExitCode",   ctypes.c_uint32),
        ("Reserved1",  ctypes.c_uint32),
    ]


class MYARK_ACTION_INJECT_DLL_INPUT(ctypes.Structure):
    _fields_ = [
        ("Token",      MYARK_SAFETY_TOKEN),
        ("Pid",        ctypes.c_uint32),
        ("Reserved1",  ctypes.c_uint32),
        ("Reserved2",  ctypes.c_uint32),
        ("Reserved3",  ctypes.c_uint32),
        ("DllPath",    ctypes.c_wchar * MYARK_ACTION_DLL_PATH_MAX_CHARS),
    ]


class MYARK_ACTION_INJECT_DLL_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Header",              MYARK_ACTION_OUTPUT),
        ("Pid",                 ctypes.c_uint32),
        ("Reserved1",           ctypes.c_uint32),
        ("RemoteThreadHandle",  ctypes.c_uint64),
    ]


class MYARK_ACTION_DUMP_MEMORY_INPUT(ctypes.Structure):
    _fields_ = [
        ("Token",      MYARK_SAFETY_TOKEN),
        ("Pid",        ctypes.c_uint32),
        ("Reserved1",  ctypes.c_uint32),
        ("Address",    ctypes.c_uint64),
        ("Size",       ctypes.c_uint64),
    ]


class MYARK_ACTION_DUMP_MEMORY_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Header",         MYARK_ACTION_OUTPUT),
        ("Pid",            ctypes.c_uint32),
        ("BytesReturned",  ctypes.c_uint32),
        ("Address",        ctypes.c_uint64),
        ("Data",           ctypes.c_uint8 * MYARK_ACTION_DUMP_MAX_BYTES),
    ]


class MYARK_ACTION_SET_TOKEN_INPUT(ctypes.Structure):
    _fields_ = [
        ("Token",      MYARK_SAFETY_TOKEN),
        ("Pid",        ctypes.c_uint32),
        ("TokenType",  ctypes.c_uint32),
        ("Reserved1",  ctypes.c_uint32),
        ("Reserved2",  ctypes.c_uint32),
    ]


class MYARK_ACTION_SET_TOKEN_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Header",     MYARK_ACTION_OUTPUT),
        ("Pid",        ctypes.c_uint32),
        ("TokenType",  ctypes.c_uint32),
        ("Reserved1",  ctypes.c_uint32),
        ("Reserved2",  ctypes.c_uint32),
    ]


class MYARK_ACTION_HIDE_PROCESS_INPUT(ctypes.Structure):
    _fields_ = [
        ("Token",      MYARK_SAFETY_TOKEN),
        ("Pid",        ctypes.c_uint32),
        ("Reserved1",  ctypes.c_uint32),
        ("Reserved2",  ctypes.c_uint32),
        ("Reserved3",  ctypes.c_uint32),
    ]


class MYARK_ACTION_HIDE_PROCESS_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Header",     MYARK_ACTION_OUTPUT),
        ("Pid",        ctypes.c_uint32),
        ("Reserved1",  ctypes.c_uint32),
        ("Reserved2",  ctypes.c_uint32),
        ("Reserved3",  ctypes.c_uint32),
    ]


class MYARK_ACTION_PROTECT_PROCESS_INPUT(ctypes.Structure):
    _fields_ = [
        ("Token",      MYARK_SAFETY_TOKEN),
        ("Pid",        ctypes.c_uint32),
        ("Flags",      ctypes.c_uint32),
        ("Reserved1",  ctypes.c_uint32),
        ("Reserved2",  ctypes.c_uint32),
    ]


class MYARK_ACTION_PROTECT_PROCESS_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Header",     MYARK_ACTION_OUTPUT),
        ("Pid",        ctypes.c_uint32),
        ("Flags",      ctypes.c_uint32),
        ("Reserved1",  ctypes.c_uint32),
        ("Reserved2",  ctypes.c_uint32),
    ]


__all__ = [
    "MYARK_ACTIONS_MODULE_ID",
    "IOCTL_MYARK_ACTION_KILL_PROCESS",
    "IOCTL_MYARK_ACTION_TERMINATE_THREAD",
    "IOCTL_MYARK_ACTION_INJECT_DLL",
    "IOCTL_MYARK_ACTION_DUMP_MEMORY",
    "IOCTL_MYARK_ACTION_SET_TOKEN",
    "IOCTL_MYARK_ACTION_HIDE_PROCESS",
    "IOCTL_MYARK_ACTION_PROTECT_PROCESS",
    "ACTIONS_IOCTL_FUNCTIONS",
    "MYARK_SAFETY_TOKEN_MAGIC",
    "MYARK_SAFETY_TOKEN_SIGNATURE_SIZE",
    "MYARK_ACTION_OP_KILL_PROCESS",
    "MYARK_ACTION_OP_TERMINATE_THREAD",
    "MYARK_ACTION_OP_INJECT_DLL",
    "MYARK_ACTION_OP_DUMP_MEMORY",
    "MYARK_ACTION_OP_SET_TOKEN",
    "MYARK_ACTION_OP_HIDE_PROCESS",
    "MYARK_ACTION_OP_PROTECT_PROCESS",
    "ACTIONS_OP_NAMES",
    "ACTIONS_NAME_TO_OP",
    "MYARK_ACTION_RESULT_APPROVED",
    "MYARK_ACTION_RESULT_DENIED",
    "MYARK_ACTION_RESULT_DENIED_NO_TOKEN",
    "MYARK_ACTION_RESULT_DENIED_STEPS",
    "MYARK_ACTION_RESULT_DEFERRED",
    "MYARK_ACTION_RESULT_FAILED",
    "MYARK_ACTION_RESULT_R3_FALLBACK",
    "MYARK_ACTION_TIER_R0",
    "MYARK_ACTION_TIER_R3",
    "MYARK_ACTION_TIER_DEFERRED",
    "ACTIONS_RESULT_NAMES",
    "ACTIONS_TIER_NAMES",
    "ACTIONS_R0_FALLBACK_AVAILABLE",
    "MYARK_ACTION_TOKEN_TYPE_PRIMARY",
    "MYARK_ACTION_TOKEN_TYPE_IMPERSONATION",
    "ACTIONS_TOKEN_TYPE_NAMES",
    "MYARK_ACTION_PROTECT_FLAG_NONE",
    "MYARK_ACTION_PROTECT_FLAG_SIGNED",
    "MYARK_ACTION_PROTECT_FLAG_LSA",
    "MYARK_ACTION_PROTECT_FLAG_WINTCB",
    "MYARK_ACTION_KILL_MAX_REASON_CHARS",
    "MYARK_ACTION_DLL_PATH_MAX_CHARS",
    "MYARK_ACTION_DUMP_MAX_BYTES",
    "MYARK_SAFETY_TOKEN",
    "MYARK_ACTION_OUTPUT",
    "MYARK_ACTION_KILL_INPUT",
    "MYARK_ACTION_KILL_OUTPUT",
    "MYARK_ACTION_TERMINATE_THREAD_INPUT",
    "MYARK_ACTION_TERMINATE_THREAD_OUTPUT",
    "MYARK_ACTION_INJECT_DLL_INPUT",
    "MYARK_ACTION_INJECT_DLL_OUTPUT",
    "MYARK_ACTION_DUMP_MEMORY_INPUT",
    "MYARK_ACTION_DUMP_MEMORY_OUTPUT",
    "MYARK_ACTION_SET_TOKEN_INPUT",
    "MYARK_ACTION_SET_TOKEN_OUTPUT",
    "MYARK_ACTION_HIDE_PROCESS_INPUT",
    "MYARK_ACTION_HIDE_PROCESS_OUTPUT",
    "MYARK_ACTION_PROTECT_PROCESS_INPUT",
    "MYARK_ACTION_PROTECT_PROCESS_OUTPUT",
]