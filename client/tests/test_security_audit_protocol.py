"""
Tests for the security-audit module's IOCTL protocol layout (R3 ctypes vs. R0 C).
"""

from __future__ import annotations

import ctypes

import pytest

from myark.protocol.core import FILE_DEVICE_UNKNOWN, METHOD_BUFFERED
from myark.modules.security_audit import protocol as P


SECAUDIT_IOCTL_TABLE = [
    ("IOCTL_MYARK_SECURITY_AUDIT_DEFENDER",     0x7D0, P.IOCTL_MYARK_SECURITY_AUDIT_DEFENDER),
    ("IOCTL_MYARK_SECURITY_AUDIT_SECURE_BOOT",  0x7D1, P.IOCTL_MYARK_SECURITY_AUDIT_SECURE_BOOT),
    ("IOCTL_MYARK_SECURITY_AUDIT_TRUSTED_BOOT", 0x7D2, P.IOCTL_MYARK_SECURITY_AUDIT_TRUSTED_BOOT),
]


@pytest.mark.parametrize("name,function,value", SECAUDIT_IOCTL_TABLE)
def test_secaudit_ioctl_codes_match_ctl_formula(name, function, value):
    expected = (FILE_DEVICE_UNKNOWN << 16) | (function << 2) | METHOD_BUFFERED
    assert value == expected


def test_secaudit_ioctl_in_range():
    for name, function, value in SECAUDIT_IOCTL_TABLE:
        function_part = (value >> 2) & 0xFFF
        assert 0x7D0 <= function_part <= 0x7DF


def test_secaudit_defender_output_size():
    """4 * uint32 + 128 * wchar = 16 + 256 = 272 bytes."""
    assert ctypes.sizeof(P.MYARK_SECURITY_AUDIT_DEFENDER_OUTPUT) == 272


def test_secaudit_secure_boot_output_size():
    """2 * uint32 + 128 * wchar = 8 + 256 = 264 bytes."""
    assert ctypes.sizeof(P.MYARK_SECURITY_AUDIT_SECURE_BOOT_OUTPUT) == 264


def test_secaudit_trusted_boot_output_size():
    """4 * uint32 + 128 * wchar = 16 + 256 = 272 bytes."""
    assert ctypes.sizeof(P.MYARK_SECURITY_AUDIT_TRUSTED_BOOT_OUTPUT) == 272


def test_secaudit_field_orders():
    assert [f[0] for f in P.MYARK_SECURITY_AUDIT_DEFENDER_OUTPUT._fields_] == [
        "IsInstalled", "IsRunning", "IsRealTimeProtectionEnabled", "Reserved", "Note",
    ]
    assert [f[0] for f in P.MYARK_SECURITY_AUDIT_SECURE_BOOT_OUTPUT._fields_] == [
        "IsEnabled", "Reserved", "Note",
    ]
    assert [f[0] for f in P.MYARK_SECURITY_AUDIT_TRUSTED_BOOT_OUTPUT._fields_] == [
        "IsMeasuredBootEnabled", "IsEventLogPresent", "Reserved1", "Reserved2", "Note",
    ]