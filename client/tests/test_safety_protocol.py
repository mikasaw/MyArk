"""
Tests for the safety module's IOCTL protocol layout (R3 ctypes vs. R0 C).
"""

from __future__ import annotations

import ctypes

import pytest

from myark.protocol.core import FILE_DEVICE_UNKNOWN, METHOD_BUFFERED
from myark.modules.safety import protocol as P


SAFETY_IOCTL_TABLE = [
    ("IOCTL_MYARK_SAFETY_EVAL_GATE", 0xD00, P.IOCTL_MYARK_SAFETY_EVAL_GATE),
]


@pytest.mark.parametrize("name,function,value", SAFETY_IOCTL_TABLE)
def test_safety_ioctl_codes_match_ctl_formula(name, function, value):
    expected = (FILE_DEVICE_UNKNOWN << 16) | (function << 2) | METHOD_BUFFERED
    assert value == expected


def test_safety_ioctl_in_range():
    """Safety owns the 0xD00..0xD0F block (moved off colliding 0x800)."""
    for name, function, value in SAFETY_IOCTL_TABLE:
        function_part = (value >> 2) & 0xFFF
        assert 0xD00 <= function_part <= 0xD0F


def test_safety_eval_input_size():
    """MYARK_SAFETY_EVAL_INPUT = 4 * uint32 + 2 * uint64 = 16 + 16 = 32 bytes."""
    assert ctypes.sizeof(P.MYARK_SAFETY_EVAL_INPUT) == 32


def test_safety_eval_output_size():
    """MYARK_SAFETY_EVAL_OUTPUT = 4 * uint32 = 16 bytes."""
    assert ctypes.sizeof(P.MYARK_SAFETY_EVAL_OUTPUT) == 16


def test_safety_op_constants():
    assert P.SAFETY_OP_KILL_PROCESS == 1
    assert P.SAFETY_OP_TERMINATE_THREAD == 2
    assert P.SAFETY_OP_INJECT_DLL == 3
    assert P.SAFETY_OP_DELETE_FILE == 4
    assert P.SAFETY_OP_CLEAR_CALLBACK == 5
    assert P.SAFETY_OP_MUTATE_TOKEN == 6


def test_safety_step_constants():
    assert P.SAFETY_STEP_AUTHENTICATED == 0x01
    assert P.SAFETY_STEP_CONFIRM_DIALOG == 0x02
    assert P.SAFETY_STEP_TOKEN_PRESENTED == 0x04
    assert P.SAFETY_STEP_TARGET_RESOLVED == 0x08
    assert P.SAFETY_STEP_AUDIT_LOGGED == 0x10
    assert P.SAFETY_STEP_REVIEW_TIMEOUT == 0x20


def test_safety_decision_constants():
    assert P.SAFETY_DECISION_APPROVE == 0
    assert P.SAFETY_DECISION_DENY == 1
    assert P.SAFETY_DECISION_REQUIRE_TOKEN == 2


def test_safety_op_names_complete():
    """SAFETY_OP_NAMES must cover every SAFETY_OP_* constant."""
    assert set(P.SAFETY_OP_NAMES.keys()) == {
        P.SAFETY_OP_KILL_PROCESS,
        P.SAFETY_OP_TERMINATE_THREAD,
        P.SAFETY_OP_INJECT_DLL,
        P.SAFETY_OP_DELETE_FILE,
        P.SAFETY_OP_CLEAR_CALLBACK,
        P.SAFETY_OP_MUTATE_TOKEN,
    }


def test_safety_step_names_complete():
    """SAFETY_STEP_NAMES must list exactly 6 step names (one per required-step bit)."""
    assert len(P.SAFETY_STEP_NAMES) == 6