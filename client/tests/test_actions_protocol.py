"""
Tests for the actions module's IOCTL protocol layout (R3 ctypes vs. R0 C).
"""

from __future__ import annotations

import ctypes

import pytest

from myark.protocol.core import FILE_DEVICE_UNKNOWN, METHOD_BUFFERED
from myark.modules.actions import protocol as P


ACTIONS_IOCTL_TABLE = [
    ("IOCTL_MYARK_ACTION_KILL_PROCESS",     0x870, P.IOCTL_MYARK_ACTION_KILL_PROCESS),
    ("IOCTL_MYARK_ACTION_TERMINATE_THREAD", 0x871, P.IOCTL_MYARK_ACTION_TERMINATE_THREAD),
    ("IOCTL_MYARK_ACTION_INJECT_DLL",       0x872, P.IOCTL_MYARK_ACTION_INJECT_DLL),
    ("IOCTL_MYARK_ACTION_DUMP_MEMORY",      0x873, P.IOCTL_MYARK_ACTION_DUMP_MEMORY),
    ("IOCTL_MYARK_ACTION_SET_TOKEN",        0x874, P.IOCTL_MYARK_ACTION_SET_TOKEN),
    ("IOCTL_MYARK_ACTION_HIDE_PROCESS",     0x875, P.IOCTL_MYARK_ACTION_HIDE_PROCESS),
    ("IOCTL_MYARK_ACTION_PROTECT_PROCESS",  0x876, P.IOCTL_MYARK_ACTION_PROTECT_PROCESS),
]


@pytest.mark.parametrize("name,function,value", ACTIONS_IOCTL_TABLE)
def test_actions_ioctl_codes_match_ctl_formula(name, function, value):
    expected = (FILE_DEVICE_UNKNOWN << 16) | (function << 2) | METHOD_BUFFERED
    assert value == expected


def test_actions_ioctl_in_range():
    """Function range 0x870..0x876 (S8.1 reserved)."""
    for name, function, value in ACTIONS_IOCTL_TABLE:
        function_part = (value >> 2) & 0xFFF
        assert 0x870 <= function_part <= 0x876


def test_actions_module_id_is_actn():
    assert P.MYARK_ACTIONS_MODULE_ID == 0x4143544E


def test_safety_token_magic_is_mark():
    assert P.MYARK_SAFETY_TOKEN_MAGIC == 0x4D41524B
    assert P.MYARK_SAFETY_TOKEN_SIGNATURE_SIZE == 32


def test_safety_token_size():
    """MYARK_SAFETY_TOKEN: 4*UINT32 + LARGE_INTEGER + 32 + 16 = 72 bytes."""
    assert ctypes.sizeof(P.MYARK_SAFETY_TOKEN) == 72


def test_safety_token_field_order():
    fields = [f[0] for f in P.MYARK_SAFETY_TOKEN._fields_]
    expected = [
        "Magic",
        "Pid",
        "Operation",
        "Reserved1",
        "Timestamp",
        "Signature",
        "Reserved2",
    ]
    assert fields == expected


def test_action_output_size():
    """MYARK_ACTION_OUTPUT: 4*UINT32 + LARGE_INTEGER + 64 = 88 bytes."""
    assert ctypes.sizeof(P.MYARK_ACTION_OUTPUT) == 88


def test_action_output_field_order():
    fields = [f[0] for f in P.MYARK_ACTION_OUTPUT._fields_]
    expected = [
        "Size",
        "ResultCode",
        "ExecutedTier",
        "Reserved1",
        "Timestamp",
        "AuditMessage",
    ]
    assert fields == expected


def test_kill_input_size():
    """MYARK_ACTION_KILL_INPUT = 72 (token) + 16 (4 UINT32) + 512 (WCHAR[256]) = 600."""
    assert ctypes.sizeof(P.MYARK_ACTION_KILL_INPUT) == 600


def test_kill_output_size():
    """MYARK_ACTION_KILL_OUTPUT = 88 (header) + 16 (4 UINT32) = 104."""
    assert ctypes.sizeof(P.MYARK_ACTION_KILL_OUTPUT) == 104


def test_terminate_thread_input_size():
    """MYARK_ACTION_TERMINATE_THREAD_INPUT = 72 + 16 = 88 bytes."""
    assert ctypes.sizeof(P.MYARK_ACTION_TERMINATE_THREAD_INPUT) == 88


def test_terminate_thread_output_size():
    """MYARK_ACTION_TERMINATE_THREAD_OUTPUT = 88 + 16 = 104 bytes."""
    assert ctypes.sizeof(P.MYARK_ACTION_TERMINATE_THREAD_OUTPUT) == 104


def test_inject_dll_input_size():
    """MYARK_ACTION_INJECT_DLL_INPUT = 72 + 16 + 520 (WCHAR[260]) = 608 bytes."""
    assert ctypes.sizeof(P.MYARK_ACTION_INJECT_DLL_INPUT) == 608


def test_inject_dll_output_size():
    """MYARK_ACTION_INJECT_DLL_OUTPUT = 88 + 4 + 4 + 8 = 104 bytes."""
    assert ctypes.sizeof(P.MYARK_ACTION_INJECT_DLL_OUTPUT) == 104


def test_dump_memory_input_size():
    """MYARK_ACTION_DUMP_MEMORY_INPUT = 72 + 4 + 4 + 8 + 8 = 96 bytes."""
    assert ctypes.sizeof(P.MYARK_ACTION_DUMP_MEMORY_INPUT) == 96


def test_dump_memory_output_size():
    """MYARK_ACTION_DUMP_MEMORY_OUTPUT = 88 + 4 + 4 + 8 + 4096 = 4200 bytes."""
    assert ctypes.sizeof(P.MYARK_ACTION_DUMP_MEMORY_OUTPUT) == 4200


def test_set_token_input_size():
    """MYARK_ACTION_SET_TOKEN_INPUT = 72 + 16 = 88 bytes."""
    assert ctypes.sizeof(P.MYARK_ACTION_SET_TOKEN_INPUT) == 88


def test_set_token_output_size():
    """MYARK_ACTION_SET_TOKEN_OUTPUT = 88 + 16 = 104 bytes."""
    assert ctypes.sizeof(P.MYARK_ACTION_SET_TOKEN_OUTPUT) == 104


def test_hide_process_input_size():
    """MYARK_ACTION_HIDE_PROCESS_INPUT = 72 + 16 = 88 bytes."""
    assert ctypes.sizeof(P.MYARK_ACTION_HIDE_PROCESS_INPUT) == 88


def test_hide_process_output_size():
    """MYARK_ACTION_HIDE_PROCESS_OUTPUT = 88 + 16 = 104 bytes."""
    assert ctypes.sizeof(P.MYARK_ACTION_HIDE_PROCESS_OUTPUT) == 104


def test_protect_process_input_size():
    """MYARK_ACTION_PROTECT_PROCESS_INPUT = 72 + 16 = 88 bytes."""
    assert ctypes.sizeof(P.MYARK_ACTION_PROTECT_PROCESS_INPUT) == 88


def test_protect_process_output_size():
    """MYARK_ACTION_PROTECT_PROCESS_OUTPUT = 88 + 16 = 104 bytes."""
    assert ctypes.sizeof(P.MYARK_ACTION_PROTECT_PROCESS_OUTPUT) == 104


def test_op_codes_match_protocol_header():
    """Mirror MYARK_ACTION_OP_* values from MyArkActionsIoctl.h."""
    assert P.MYARK_ACTION_OP_KILL_PROCESS == 1
    assert P.MYARK_ACTION_OP_TERMINATE_THREAD == 2
    assert P.MYARK_ACTION_OP_INJECT_DLL == 3
    assert P.MYARK_ACTION_OP_DUMP_MEMORY == 4
    assert P.MYARK_ACTION_OP_SET_TOKEN == 5
    assert P.MYARK_ACTION_OP_HIDE_PROCESS == 6
    assert P.MYARK_ACTION_OP_PROTECT_PROCESS == 7


def test_op_names_round_trip():
    """ACTIONS_OP_NAMES and ACTIONS_NAME_TO_OP are mutual inverses."""
    for op, name in P.ACTIONS_OP_NAMES.items():
        assert P.ACTIONS_NAME_TO_OP[name] == op
    for name, op in P.ACTIONS_NAME_TO_OP.items():
        assert P.ACTIONS_OP_NAMES[op] == name


def test_op_names_complete():
    """ACTIONS_OP_NAMES covers all 7 op codes."""
    assert set(P.ACTIONS_OP_NAMES.keys()) == {
        P.MYARK_ACTION_OP_KILL_PROCESS,
        P.MYARK_ACTION_OP_TERMINATE_THREAD,
        P.MYARK_ACTION_OP_INJECT_DLL,
        P.MYARK_ACTION_OP_DUMP_MEMORY,
        P.MYARK_ACTION_OP_SET_TOKEN,
        P.MYARK_ACTION_OP_HIDE_PROCESS,
        P.MYARK_ACTION_OP_PROTECT_PROCESS,
    }


def test_ioctl_functions_complete():
    """ACTIONS_IOCTL_FUNCTIONS covers all 7 action names."""
    assert set(P.ACTIONS_IOCTL_FUNCTIONS.keys()) == set(P.ACTIONS_OP_NAMES.values())
    assert set(P.ACTIONS_IOCTL_FUNCTIONS.values()) == {code for _, code, _ in ACTIONS_IOCTL_TABLE}


def test_r3_fallback_set_matches_plan_v3():
    """ACTIONS_R0_FALLBACK_AVAILABLE must contain exactly the 4 plan-v3 actions."""
    assert P.ACTIONS_R0_FALLBACK_AVAILABLE == frozenset({
        "kill_process",
        "terminate_thread",
        "inject_dll",
        "dump_memory",
    })


def test_result_code_values():
    assert P.MYARK_ACTION_RESULT_APPROVED == 0
    assert P.MYARK_ACTION_RESULT_DENIED == 1
    assert P.MYARK_ACTION_RESULT_DENIED_NO_TOKEN == 2
    assert P.MYARK_ACTION_RESULT_DENIED_STEPS == 3
    assert P.MYARK_ACTION_RESULT_DEFERRED == 4
    assert P.MYARK_ACTION_RESULT_FAILED == 5
    assert P.MYARK_ACTION_RESULT_R3_FALLBACK == 6


def test_tier_code_values():
    assert P.MYARK_ACTION_TIER_R0 == 0
    assert P.MYARK_ACTION_TIER_R3 == 1
    assert P.MYARK_ACTION_TIER_DEFERRED == 2


def test_result_names_complete():
    """ACTIONS_RESULT_NAMES covers all 7 result codes."""
    assert set(P.ACTIONS_RESULT_NAMES.keys()) == {
        P.MYARK_ACTION_RESULT_APPROVED,
        P.MYARK_ACTION_RESULT_DENIED,
        P.MYARK_ACTION_RESULT_DENIED_NO_TOKEN,
        P.MYARK_ACTION_RESULT_DENIED_STEPS,
        P.MYARK_ACTION_RESULT_DEFERRED,
        P.MYARK_ACTION_RESULT_FAILED,
        P.MYARK_ACTION_RESULT_R3_FALLBACK,
    }


def test_tier_names_complete():
    assert set(P.ACTIONS_TIER_NAMES.keys()) == {
        P.MYARK_ACTION_TIER_R0,
        P.MYARK_ACTION_TIER_R3,
        P.MYARK_ACTION_TIER_DEFERRED,
    }


def test_token_type_enum():
    assert P.MYARK_ACTION_TOKEN_TYPE_PRIMARY == 0
    assert P.MYARK_ACTION_TOKEN_TYPE_IMPERSONATION == 1
    assert P.ACTIONS_TOKEN_TYPE_NAMES[P.MYARK_ACTION_TOKEN_TYPE_PRIMARY] == "primary"
    assert P.ACTIONS_TOKEN_TYPE_NAMES[P.MYARK_ACTION_TOKEN_TYPE_IMPERSONATION] == "impersonation"


def test_protect_flags_unique_powers_of_two():
    flags = {
        P.MYARK_ACTION_PROTECT_FLAG_NONE,
        P.MYARK_ACTION_PROTECT_FLAG_SIGNED,
        P.MYARK_ACTION_PROTECT_FLAG_LSA,
        P.MYARK_ACTION_PROTECT_FLAG_WINTCB,
    }
    assert flags == {0x0, 0x1, 0x2, 0x4}


def test_dump_max_bytes_4k():
    assert P.MYARK_ACTION_DUMP_MAX_BYTES == 4096


def test_max_path_for_dll_path():
    assert P.MYARK_ACTION_DLL_PATH_MAX_CHARS == 260


def test_kill_max_reason_chars():
    assert P.MYARK_ACTION_KILL_MAX_REASON_CHARS == 256