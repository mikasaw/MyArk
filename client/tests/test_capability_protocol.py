"""
Tests for the capability module's IOCTL protocol layout (R3 ctypes vs. R0 C).

Verifies that ``client/src/myark/modules/capability/protocol.py`` mirrors
``shared/driver/MyArkCapabilityIoctl.h`` byte-for-byte:

  * IOCTL function code lives in the capability range (0x7E0) and uses
    the MyArk METHOD_BUFFERED + FILE_ANY_ACCESS formula on top of
    FILE_DEVICE_UNKNOWN.
  * The ctypes struct has the same size / field order as the kernel
    struct.

The driver does not need to be loaded for any of these tests.
"""

from __future__ import annotations

import ctypes

import pytest

from myark.protocol.core import FILE_DEVICE_UNKNOWN, METHOD_BUFFERED
from myark.modules.capability import protocol as P


# ---------------------------------------------------------------------------
# IOCTL code range + accessor coverage.
# ---------------------------------------------------------------------------

CAPABILITY_IOCTL_TABLE = [
    ("IOCTL_MYARK_CAPABILITY_REPORT", 0x7E0, P.IOCTL_MYARK_CAPABILITY_REPORT),
]


@pytest.mark.parametrize("name,function,value", CAPABILITY_IOCTL_TABLE)
def test_capability_ioctl_codes_match_ctl_formula(name, function, value):
    """Each IOCTL must equal ``CTL_CODE(FILE_DEVICE_UNKNOWN, function, METHOD_BUFFERED, FILE_ANY_ACCESS)``."""
    expected = (FILE_DEVICE_UNKNOWN << 16) | (function << 2) | METHOD_BUFFERED
    assert value == expected, f"{name}: expected 0x{expected:08X}, got 0x{value:08X}"


def test_capability_ioctl_is_in_module_range():
    """All capability IOCTLs live in 0x7E0..0x7EF."""
    for name, function, value in CAPABILITY_IOCTL_TABLE:
        device_part = (value >> 16) & 0xFFFF
        function_part = (value >> 2) & 0xFFF
        assert device_part == FILE_DEVICE_UNKNOWN
        assert 0x7E0 <= function_part <= 0x7EF, f"{name}: function 0x{function_part:X} not in capability range"


# ---------------------------------------------------------------------------
# Struct sizes + alignment (ctypes vs. expected kernel layout).
# ---------------------------------------------------------------------------

def test_capability_module_entry_size():
    """MYARK_CAPABILITY_MODULE_ENTRY has 4 * uint32 + 32 * c_wchar = 16 + 64 = 80 bytes."""
    assert ctypes.sizeof(P.MYARK_CAPABILITY_MODULE_ENTRY) == 80


def test_capability_report_output_header_size():
    """MYARK_CAPABILITY_REPORT_OUTPUT header (everything before Entries[0]) is 8 * uint32 = 32 bytes."""
    assert P.HEADER_SIZE_CAPABILITY_REPORT == 32


def test_capability_report_buffer_size_formula():
    """Buffer size = header + count * entry_size."""
    assert P.capability_report_buffer_size(0) == 32
    assert P.capability_report_buffer_size(1) == 32 + 80
    assert P.capability_report_buffer_size(64) == 32 + 64 * 80


def test_capability_module_entry_field_order():
    """Field order must mirror the kernel struct: ModuleId / IoctlCount / Flags / Reserved / ModuleName."""
    fields = [f[0] for f in P.MYARK_CAPABILITY_MODULE_ENTRY._fields_]
    assert fields == ["ModuleId", "IoctlCount", "Flags", "Reserved", "ModuleName"]


def test_capability_module_name_is_wchar_array():
    """ModuleName must be a UTF-16LE WCHAR array of length 32 (= MYARK_CAPABILITY_NAME_MAX)."""
    name_field = P.MYARK_CAPABILITY_MODULE_ENTRY._fields_[-1]
    assert name_field[0] == "ModuleName"
    assert name_field[1] == ctypes.c_wchar * 32


# ---------------------------------------------------------------------------
# Flag bit constants (mirror MYARK_CAPABILITY_FLAG_*).
# ---------------------------------------------------------------------------

def test_capability_flag_constants():
    assert P.CAPABILITY_FLAG_R0 == 0x00000001
    assert P.CAPABILITY_FLAG_R3 == 0x00000002
    assert P.CAPABILITY_FLAG_ENABLED == 0x00000004


# ---------------------------------------------------------------------------
# Sanity check: report ctypes layout does not drift.
# ---------------------------------------------------------------------------

def test_capability_report_output_field_order():
    fields = [f[0] for f in P.MYARK_CAPABILITY_REPORT_OUTPUT._fields_]
    expected = [
        "DriverVersionMajor",
        "DriverVersionMinor",
        "DriverVersionBuild",
        "Reserved",
        "TotalModules",
        "TotalIoctls",
        "Reserved2",
        "Reserved3",
        "Entries",
    ]
    assert fields == expected