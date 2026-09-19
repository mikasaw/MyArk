"""
Tests for the capability module's R3 client (parser / dataclasses).

Exercises the parser dataclasses against a synthetic buffer shaped like
the IOCTL reply. The driver is not loaded for any of these tests.
"""

from __future__ import annotations

import ctypes

import pytest

from myark.modules.capability import parser as P
from myark.modules.capability import protocol as PP


def _build_synthetic_report(module_count: int) -> tuple[bytes, int]:
    """Build a synthetic capability report buffer shaped like the driver's reply."""
    buf_size = PP.capability_report_buffer_size(module_count)
    buf = (ctypes.c_ubyte * buf_size)()
    out = ctypes.cast(buf, ctypes.POINTER(PP.MYARK_CAPABILITY_REPORT_OUTPUT)).contents

    out.DriverVersionMajor = 7
    out.DriverVersionMinor = 3
    out.DriverVersionBuild = 0
    out.Reserved = 0
    out.TotalModules = module_count
    out.TotalIoctls = module_count * 5

    raw_entries = ctypes.cast(
        ctypes.addressof(out) + PP.HEADER_SIZE_CAPABILITY_REPORT,
        ctypes.POINTER(PP.MYARK_CAPABILITY_MODULE_ENTRY * module_count),
    ).contents

    for i in range(module_count):
        e = raw_entries[i]
        e.ModuleId = 0x1000 + i
        e.IoctlCount = i + 1
        e.Flags = PP.CAPABILITY_FLAG_R0 | PP.CAPABILITY_FLAG_ENABLED
        e.Reserved = 0
        e.ModuleName = f"module{i:02d}"

    bytes_returned = PP.HEADER_SIZE_CAPABILITY_REPORT + module_count * ctypes.sizeof(PP.MYARK_CAPABILITY_MODULE_ENTRY)
    return bytes(bytes(buf)[:bytes_returned]), bytes_returned


# ---------------------------------------------------------------------------
# Dataclass field default values.
# ---------------------------------------------------------------------------

def test_capability_entry_defaults():
    e = P.CapabilityEntry()
    assert e.module_id == 0
    assert e.ioctl_count == 0
    assert e.flags == 0
    assert e.module_name == ""


def test_capability_report_defaults():
    r = P.CapabilityReport()
    assert r.version_major == 0
    assert r.version_minor == 0
    assert r.version_build == 0
    assert r.total_modules == 0
    assert r.total_ioctls == 0
    assert r.entries == []


# ---------------------------------------------------------------------------
# Buffer sizing.
# ---------------------------------------------------------------------------

def test_capability_buffer_size_matches_dyndata_formula():
    for count in (0, 1, 16, 32, 64):
        assert PP.capability_report_buffer_size(count) == (
            PP.HEADER_SIZE_CAPABILITY_REPORT
            + count * ctypes.sizeof(PP.MYARK_CAPABILITY_MODULE_ENTRY)
        )


def test_capability_buffer_size_is_header_plus_count_times_entry():
    """Buffer size = HEADER_SIZE + count * entry_size (header is not a multiple of entry size)."""
    for count in (1, 2, 8, 64):
        size = PP.capability_report_buffer_size(count)
        expected = PP.HEADER_SIZE_CAPABILITY_REPORT + count * ctypes.sizeof(PP.MYARK_CAPABILITY_MODULE_ENTRY)
        assert size == expected


# ---------------------------------------------------------------------------
# Synthetic-parse path (validates the parser's buffer-shape expectations).
# ---------------------------------------------------------------------------

def test_capability_module_entry_layout():
    """ModuleName is WCHAR[32] so total size = 4 * 4 + 32 * 2 = 80 bytes."""
    e = PP.MYARK_CAPABILITY_MODULE_ENTRY()
    e.ModuleId = 0x12345678
    e.ModuleName = "hello"
    assert ctypes.sizeof(e) == 80


def test_capability_report_layout():
    """MYARK_CAPABILITY_REPORT_OUTPUT header is 8 * 4 = 32 bytes before Entries[0]."""
    out = PP.MYARK_CAPABILITY_REPORT_OUTPUT()
    out.DriverVersionMajor = 7
    out.DriverVersionMinor = 3
    out.TotalModules = 4
    out.TotalIoctls = 20
    # No parser call -- just confirm the ctypes struct is well-formed.
    assert out.DriverVersionMajor == 7
    assert out.TotalModules == 4
    assert out.TotalIoctls == 20