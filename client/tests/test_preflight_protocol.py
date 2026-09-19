"""
Tests for the preflight module's IOCTL protocol layout (R3 ctypes vs. R0 C).
"""

from __future__ import annotations

import ctypes

import pytest

from myark.protocol.core import FILE_DEVICE_UNKNOWN, METHOD_BUFFERED
from myark.modules.preflight import protocol as P


PREFLIGHT_IOCTL_TABLE = [
    ("IOCTL_MYARK_PREFLIGHT_HEALTH", 0x7C0, P.IOCTL_MYARK_PREFLIGHT_HEALTH),
]


@pytest.mark.parametrize("name,function,value", PREFLIGHT_IOCTL_TABLE)
def test_preflight_ioctl_codes_match_ctl_formula(name, function, value):
    expected = (FILE_DEVICE_UNKNOWN << 16) | (function << 2) | METHOD_BUFFERED
    assert value == expected


def test_preflight_ioctl_in_range():
    for name, function, value in PREFLIGHT_IOCTL_TABLE:
        function_part = (value >> 2) & 0xFFF
        assert 0x7C0 <= function_part <= 0x7CF


def test_preflight_health_output_size():
    """MYARK_PREFLIGHT_HEALTH_OUTPUT = 8 * uint32 + 2 * uint64 + 128 * wchar = 32 + 16 + 256 = 304 bytes."""
    assert ctypes.sizeof(P.MYARK_PREFLIGHT_HEALTH_OUTPUT) == 304


def test_preflight_field_order():
    fields = [f[0] for f in P.MYARK_PREFLIGHT_HEALTH_OUTPUT._fields_]
    expected = [
        "MajorVersion",
        "MinorVersion",
        "BuildNumber",
        "Revision",
        "IsTestSigning",
        "IsSecureBoot",
        "IsDriverSigned",
        "Flags",
        "KernelBase",
        "KernelSize",
        "Note",
    ]
    assert fields == expected


def test_preflight_flag_constants():
    assert P.PREFLIGHT_FLAG_SAFE_MODE == 0x00000001
    assert P.PREFLIGHT_FLAG_DEBUG == 0x00000002