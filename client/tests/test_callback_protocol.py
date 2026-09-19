"""
Tests for the callback module's IOCTL protocol layout (R3 ctypes vs. R0 C).

Verifies that ``client/src/myark/modules/callback/protocol.py`` mirrors
``shared/driver/MyArkCallbackIoctl.h`` byte-for-byte:

  * IOCTL function codes occupy the callback range (0x710..0x719) and use
    the MyArk METHOD_BUFFERED + FILE_ANY_ACCESS formula on top of
    FILE_DEVICE_UNKNOWN.
  * Every IOCTL name maps to the expected function code so R3 / R0 stay
    in sync.
  * Each ctypes struct has the same size / field order as the kernel
    struct.

The driver does not need to be loaded for any of these tests.
"""

from __future__ import annotations

import ctypes

import pytest

from myark.protocol.core import FILE_DEVICE_UNKNOWN, METHOD_BUFFERED
from myark.modules.callback import protocol as P


# ---------------------------------------------------------------------------
# IOCTL code range + accessor coverage.
# ---------------------------------------------------------------------------

CALLBACK_IOCTL_TABLE = [
    ("IOCTL_MYARK_CALLBACK_QUERY_PS",    0x710, P.IOCTL_MYARK_CALLBACK_QUERY_PS),
    ("IOCTL_MYARK_CALLBACK_QUERY_CM",    0x711, P.IOCTL_MYARK_CALLBACK_QUERY_CM),
    ("IOCTL_MYARK_CALLBACK_QUERY_OB",    0x712, P.IOCTL_MYARK_CALLBACK_QUERY_OB),
    ("IOCTL_MYARK_CALLBACK_QUERY_IMAGE", 0x713, P.IOCTL_MYARK_CALLBACK_QUERY_IMAGE),
    ("IOCTL_MYARK_CALLBACK_QUERY_DBG",   0x714, P.IOCTL_MYARK_CALLBACK_QUERY_DBG),
    ("IOCTL_MYARK_CALLBACK_ENUMERATE",   0x715, P.IOCTL_MYARK_CALLBACK_ENUMERATE),
    ("IOCTL_MYARK_CALLBACK_REMOVE",      0x716, P.IOCTL_MYARK_CALLBACK_REMOVE),
    ("IOCTL_MYARK_CALLBACK_RESTORE",     0x717, P.IOCTL_MYARK_CALLBACK_RESTORE),
    ("IOCTL_MYARK_CALLBACK_BACKUP",      0x718, P.IOCTL_MYARK_CALLBACK_BACKUP),
    ("IOCTL_MYARK_CALLBACK_STATS",       0x719, P.IOCTL_MYARK_CALLBACK_STATS),
]


class TestIoctlCodes:
    @pytest.mark.parametrize("name, function, code", CALLBACK_IOCTL_TABLE,
                             ids=[row[0] for row in CALLBACK_IOCTL_TABLE])
    def test_function_in_callback_range(self, name: str, function: int, code: int) -> None:
        """Each function code must occupy 0x710..0x719."""
        assert 0x710 <= function <= 0x719, f"{name}: function 0x{function:X} outside callback range"

    @pytest.mark.parametrize("name, function, code", CALLBACK_IOCTL_TABLE,
                             ids=[row[0] for row in CALLBACK_IOCTL_TABLE])
    def test_code_decodes_back_to_function(self, name: str, function: int, code: int) -> None:
        """CTL_CODE decoding must round-trip back to the function byte."""
        assert (code >> 16) == FILE_DEVICE_UNKNOWN
        assert (code & 0x3) == METHOD_BUFFERED
        decoded = (code >> 2) & 0xFFF
        assert decoded == function, f"{name}: decoded 0x{decoded:X} != function 0x{function:X}"

    def test_codes_distinct(self) -> None:
        codes = {row[2] for row in CALLBACK_IOCTL_TABLE}
        assert len(codes) == len(CALLBACK_IOCTL_TABLE), "duplicate callback IOCTL code"

    def test_all_ten_ioctls_present(self) -> None:
        assert len(CALLBACK_IOCTL_TABLE) == 10, "callback must ship exactly 10 IOCTLs"


# ---------------------------------------------------------------------------
# ctypes struct sizes match the kernel layout (R0 side uses FIELD_OFFSET
# arithmetic so the protocol is always size-stable; the R3 side just needs
# to agree).
# ---------------------------------------------------------------------------

class TestStructSizes:
    def test_ps_entry_size(self) -> None:
        # Index(4)+SubType(4)+Flags(4)+Reserved0(4)+Callback(8)+DriverName(32) == 56
        assert ctypes.sizeof(P.MYARK_CALLBACK_PS_ENTRY) == 56

    def test_cm_entry_size(self) -> None:
        # Index(4)+Flags(4)+Reserved0(4)+Reserved1(4)+Callback(8)+Cookie(8)+
        # DriverName(32)+Altitude(64) = 128
        assert ctypes.sizeof(P.MYARK_CALLBACK_CM_ENTRY) == 128

    def test_ob_entry_size(self) -> None:
        # Index(4)+Operation(4)+Flags(4)+Reserved0(4)+Callback(8)+Altitude(8)+
        # Cookie(8)+DriverName(32)+AltitudeString(64) = 136
        assert ctypes.sizeof(P.MYARK_CALLBACK_OB_ENTRY) == 136

    def test_image_entry_size(self) -> None:
        # Index(4)+Flags(4)+Reserved0(4)+Reserved1(4)+Callback(8)+DriverName(32) == 56
        assert ctypes.sizeof(P.MYARK_CALLBACK_IMAGE_ENTRY) == 56

    def test_dbg_entry_size(self) -> None:
        # Index(4)+SubType(4)+Flags(4)+Reserved0(4)+Object(8)+DriverName(32) == 56
        assert ctypes.sizeof(P.MYARK_CALLBACK_DBG_ENTRY) == 56

    def test_enum_entry_size(self) -> None:
        # Category(4)+SubType(4)+Index(4)+Flags(4)+Callback(8)+Cookie(8)+
        # DriverName(32)+Altitude(64) = 128
        assert ctypes.sizeof(P.MYARK_CALLBACK_ENUM_ENTRY) == 128

    def test_stats_output_size(self) -> None:
        # 8 x UINT32 (32)
        assert ctypes.sizeof(P.MYARK_CALLBACK_STATS_OUTPUT) == 32


# ---------------------------------------------------------------------------
# Header sizes used by parser.py to allocate receive buffers.
# ---------------------------------------------------------------------------

class TestHeaderSizes:
    def test_query_input_size(self) -> None:
        # All QUERY_*_INPUT structs are 16 bytes (4 UINT32 fields).
        assert ctypes.sizeof(P.MYARK_CALLBACK_QUERY_PS_INPUT) == 16
        assert ctypes.sizeof(P.MYARK_CALLBACK_QUERY_CM_INPUT) == 16
        assert ctypes.sizeof(P.MYARK_CALLBACK_QUERY_OB_INPUT) == 16
        assert ctypes.sizeof(P.MYARK_CALLBACK_QUERY_IMAGE_INPUT) == 16
        assert ctypes.sizeof(P.MYARK_CALLBACK_QUERY_DBG_INPUT) == 16
        assert ctypes.sizeof(P.MYARK_CALLBACK_ENUMERATE_INPUT) == 16
        assert ctypes.sizeof(P.MYARK_CALLBACK_BACKUP_INPUT) == 16

    def test_remove_input_size(self) -> None:
        assert ctypes.sizeof(P.MYARK_CALLBACK_REMOVE_INPUT) == 16
        assert ctypes.sizeof(P.MYARK_CALLBACK_RESTORE_INPUT) == 16
        assert ctypes.sizeof(P.MYARK_CALLBACK_REMOVE_OUTPUT) == 16
        assert ctypes.sizeof(P.MYARK_CALLBACK_RESTORE_OUTPUT) == 16


# ---------------------------------------------------------------------------
# Round-trip: write a fixed set of fields and read them back from bytes().
# ---------------------------------------------------------------------------

class TestRoundTrip:
    def test_ps_entry_round_trip(self) -> None:
        e = P.MYARK_CALLBACK_PS_ENTRY()
        e.Index = 3
        e.SubType = P.CALLBACK_PS_SUBTYPE_PROCESS
        e.Flags = P.CALLBACK_FLAG_POPULATED | P.CALLBACK_FLAG_SUSPECT
        e.Callback = 0xFFFFF80012345678

        raw = bytes(e)
        rebuilt = P.MYARK_CALLBACK_PS_ENTRY.from_buffer_copy(raw)
        assert rebuilt.Index == 3
        assert rebuilt.SubType == P.CALLBACK_PS_SUBTYPE_PROCESS
        assert rebuilt.Flags == (P.CALLBACK_FLAG_POPULATED | P.CALLBACK_FLAG_SUSPECT)
        assert rebuilt.Callback == 0xFFFFF80012345678

    def test_cm_entry_round_trip(self) -> None:
        e = P.MYARK_CALLBACK_CM_ENTRY()
        e.Index = 7
        e.Flags = P.CALLBACK_FLAG_POPULATED | P.CALLBACK_FLAG_ALTITUDE
        e.Callback = 0xFFFFF80011223344
        e.Cookie = 0xCAFEBABE_DEADBEEF

        rebuilt = P.MYARK_CALLBACK_CM_ENTRY.from_buffer_copy(bytes(e))
        assert rebuilt.Index == 7
        assert rebuilt.Flags == (P.CALLBACK_FLAG_POPULATED | P.CALLBACK_FLAG_ALTITUDE)
        assert rebuilt.Callback == 0xFFFFF80011223344
        assert rebuilt.Cookie == 0xCAFEBABE_DEADBEEF

    def test_stats_round_trip(self) -> None:
        s = P.MYARK_CALLBACK_STATS_OUTPUT()
        s.PsCount = 5
        s.CmCount = 3
        s.ObCount = 2
        s.ImageCount = 1
        s.DbgCount = 4
        s.TotalCount = 15

        rebuilt = P.MYARK_CALLBACK_STATS_OUTPUT.from_buffer_copy(bytes(s))
        assert rebuilt.PsCount == 5
        assert rebuilt.CmCount == 3
        assert rebuilt.ObCount == 2
        assert rebuilt.ImageCount == 1
        assert rebuilt.DbgCount == 4
        assert rebuilt.TotalCount == 15


# ---------------------------------------------------------------------------
# Constants exposed by protocol.py.
# ---------------------------------------------------------------------------

class TestConstants:
    def test_category_bits_distinct(self) -> None:
        bits = {P.CALLBACK_CATEGORY_PS,
                P.CALLBACK_CATEGORY_CM,
                P.CALLBACK_CATEGORY_OB,
                P.CALLBACK_CATEGORY_IMAGE,
                P.CALLBACK_CATEGORY_DBG}
        assert len(bits) == 5

    def test_flag_bits_distinct(self) -> None:
        bits = {P.CALLBACK_FLAG_NONE,
                P.CALLBACK_FLAG_POPULATED,
                P.CALLBACK_FLAG_SUSPECT,
                P.CALLBACK_FLAG_HOOK,
                P.CALLBACK_FLAG_UNSIGNED,
                P.CALLBACK_FLAG_ALTITUDE}
        assert len(bits) == 6

    def test_ps_subtype_distinct(self) -> None:
        ids = {P.CALLBACK_PS_SUBTYPE_PROCESS,
               P.CALLBACK_PS_SUBTYPE_THREAD,
               P.CALLBACK_PS_SUBTYPE_IMAGE}
        assert len(ids) == 3

    def test_ob_operation_distinct(self) -> None:
        ids = {P.CALLBACK_OB_OPERATION_PROCESS,
               P.CALLBACK_OB_OPERATION_THREAD}
        assert len(ids) == 2

    def test_dbg_subtype_distinct(self) -> None:
        ids = {P.CALLBACK_DBG_SUBTYPE_DEBUG,
               P.CALLBACK_DBG_SUBTYPE_BOUND}
        assert len(ids) == 2


__all__ = []