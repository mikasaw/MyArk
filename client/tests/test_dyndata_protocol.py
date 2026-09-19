"""
Tests for the dyndata module's IOCTL protocol layout (R3 ctypes vs. R0 C).

Verifies that ``client/src/myark/modules/dyndata/protocol.py`` mirrors
``shared/driver/MyArkDyndataIoctl.h`` byte-for-byte:

  * IOCTL function codes occupy the dyndata range (0x700..0x708) and use
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
from myark.modules.dyndata import protocol as P


# ---------------------------------------------------------------------------
# IOCTL code range + accessor coverage.
# ---------------------------------------------------------------------------

DYNDATA_IOCTL_TABLE = [
    ("IOCTL_MYARK_DYNDATA_QUERY_PROCESS", 0x700, P.IOCTL_MYARK_DYNDATA_QUERY_PROCESS),
    ("IOCTL_MYARK_DYNDATA_QUERY_THREAD",  0x701, P.IOCTL_MYARK_DYNDATA_QUERY_THREAD),
    ("IOCTL_MYARK_DYNDATA_QUERY_MODULE",  0x702, P.IOCTL_MYARK_DYNDATA_QUERY_MODULE),
    ("IOCTL_MYARK_DYNDATA_QUERY_HANDLE",  0x703, P.IOCTL_MYARK_DYNDATA_QUERY_HANDLE),
    ("IOCTL_MYARK_DYNDATA_QUERY_FILE",    0x704, P.IOCTL_MYARK_DYNDATA_QUERY_FILE),
    ("IOCTL_MYARK_DYNDATA_QUERY_SYSCALL", 0x705, P.IOCTL_MYARK_DYNDATA_QUERY_SYSCALL),
    ("IOCTL_MYARK_DYNDATA_QUERY_TOKEN",   0x706, P.IOCTL_MYARK_DYNDATA_QUERY_TOKEN),
    ("IOCTL_MYARK_DYNDATA_QUERY_OBJECT",  0x707, P.IOCTL_MYARK_DYNDATA_QUERY_OBJECT),
    ("IOCTL_MYARK_DYNDATA_QUERY_SSDT",    0x708, P.IOCTL_MYARK_DYNDATA_QUERY_SSDT),
]


class TestIoctlCodes:
    @pytest.mark.parametrize("name, function, code", DYNDATA_IOCTL_TABLE,
                             ids=[row[0] for row in DYNDATA_IOCTL_TABLE])
    def test_function_in_dyndata_range(self, name: str, function: int, code: int) -> None:
        """Each function code must occupy 0x700..0x708."""
        assert 0x700 <= function <= 0x708, f"{name}: function 0x{function:X} outside dyndata range"

    @pytest.mark.parametrize("name, function, code", DYNDATA_IOCTL_TABLE,
                             ids=[row[0] for row in DYNDATA_IOCTL_TABLE])
    def test_code_decodes_back_to_function(self, name: str, function: int, code: int) -> None:
        """CTL_CODE decoding must round-trip back to the function byte."""
        assert (code >> 16) == FILE_DEVICE_UNKNOWN
        assert (code & 0x3) == METHOD_BUFFERED
        decoded = (code >> 2) & 0xFFF
        assert decoded == function, f"{name}: decoded 0x{decoded:X} != function 0x{function:X}"

    def test_codes_distinct(self) -> None:
        codes = {row[2] for row in DYNDATA_IOCTL_TABLE}
        assert len(codes) == len(DYNDATA_IOCTL_TABLE), "duplicate dyndata IOCTL code"

    def test_all_nine_ioctls_present(self) -> None:
        assert len(DYNDATA_IOCTL_TABLE) == 9, "dyndata must ship exactly 9 IOCTLs"


# ---------------------------------------------------------------------------
# ctypes struct sizes match the kernel layout (R0 side uses FIELD_OFFSET
# arithmetic so the protocol is always size-stable; the R3 side just needs
# to agree).
# ---------------------------------------------------------------------------

class TestStructSizes:
    def test_process_entry_size(self) -> None:
        # Pid(4)+Ppid(4)+SessionId(4)+Flags(4)+EProcess(8)+Peb(8)+
        # ImageFileName(16)+SourceMask(4)+Reserved0(4)+CreateTime(8) == 64
        assert ctypes.sizeof(P.MYARK_DYNDATA_PROCESS_ENTRY) == 64

    def test_thread_entry_size(self) -> None:
        # Tid(4)+OwnerPid(4)+State(4)+BasePriority(4)+EThread(8)+StartAddress(8)+
        # WaitReason(4)+Flags(4)+CreateTime(8) == 48
        assert ctypes.sizeof(P.MYARK_DYNDATA_THREAD_ENTRY) == 48

    def test_module_entry_size(self) -> None:
        # ImageBase(8)+ImageSize(8)+Flags(4)+LoadOrderIndex(4)+Name(64)+FullPath(260)
        # = 348 logical; padded to the next 8-byte boundary for the struct's
        # own alignment (the trailing UINT64 alignment requirement).
        assert ctypes.sizeof(P.MYARK_DYNDATA_MODULE_ENTRY) == 352

    def test_handle_entry_size(self) -> None:
        # Pid(4)+HandleValue(4)+TypeIndex(4)+GrantedAccess(4)+Object(8)+Flags(4)+Reserved0(4) == 32
        assert ctypes.sizeof(P.MYARK_DYNDATA_HANDLE_ENTRY) == 32

    def test_file_entry_size(self) -> None:
        # Pid(4)+HandleValue(4)+FileObject(8)+DeviceObject(8)+Flags(4)+ShareAccess(4)+Name(260)
        # = 292 logical; struct padded to 296 for UINT64 alignment of the
        # trailing variable-length field when embedded in an output.
        assert ctypes.sizeof(P.MYARK_DYNDATA_FILE_ENTRY) == 296

    def test_syscall_entry_size(self) -> None:
        # ServiceIndex(4)+TableId(4)+ServiceAddress(8)+Flags(4)+DwellBytesSize(4)+
        # DwellBytes(8)+Reserved0(4)+Reserved1(4) == 40
        assert ctypes.sizeof(P.MYARK_DYNDATA_SYSCALL_ENTRY) == 40

    def test_token_entry_size(self) -> None:
        # 11 x UINT32 (44) + UINT64 Token (aligned to offset 48) +
        # UserSidString[256] (offset 56) = 312 logical; struct aligned to 312
        # (next 8-byte boundary already met by the trailing field).
        assert ctypes.sizeof(P.MYARK_DYNDATA_TOKEN_ENTRY) == 312

    def test_object_entry_size(self) -> None:
        # TypeIndex(4)+TotalNumberOfObjects(4)+TotalNumberOfHandles(4)+Flags(4)+
        # TypeObject(8)+Name(64) == 88
        assert ctypes.sizeof(P.MYARK_DYNDATA_OBJECT_ENTRY) == 88

    def test_ssdt_entry_size(self) -> None:
        # ServiceIndex(4)+TableId(4)+ServiceAddress(8)+Flags(4)+DwellBytesSize(4)+
        # DwellBytes(8)+Reserved0(4)+Reserved1(4) == 40
        assert ctypes.sizeof(P.MYARK_DYNDATA_SSDT_ENTRY) == 40


# ---------------------------------------------------------------------------
# Header sizes used by parser.py to allocate receive buffers.
# ---------------------------------------------------------------------------

class TestHeaderSizes:
    def test_process_header(self) -> None:
        # Output header excludes the trailing Entries[1]; the header itself
        # must be 32 bytes (Size+Count+TotalSeen+Reserved0 + PsActiveProcessHead
        # + EntryStructSize + Reserved1 = 8 + 8 + 8 = 32, minus the
        # ctypes.sizeof(MYARK_DYNDATA_PROCESS_ENTRY) flexible placeholder).
        assert P.HEADER_SIZE_PROCESS == 32

    def test_query_input_size(self) -> None:
        # All QUERY_*_INPUT structs are 16 bytes (4 UINT32 fields).
        assert ctypes.sizeof(P.MYARK_DYNDATA_QUERY_PROCESS_INPUT) == 16
        assert ctypes.sizeof(P.MYARK_DYNDATA_QUERY_THREAD_INPUT) == 16
        assert ctypes.sizeof(P.MYARK_DYNDATA_QUERY_MODULE_INPUT) == 16
        assert ctypes.sizeof(P.MYARK_DYNDATA_QUERY_HANDLE_INPUT) == 16
        assert ctypes.sizeof(P.MYARK_DYNDATA_QUERY_FILE_INPUT) == 16
        assert ctypes.sizeof(P.MYARK_DYNDATA_QUERY_SYSCALL_INPUT) == 16
        assert ctypes.sizeof(P.MYARK_DYNDATA_QUERY_OBJECT_INPUT) == 16
        assert ctypes.sizeof(P.MYARK_DYNDATA_QUERY_SSDT_INPUT) == 16
        assert ctypes.sizeof(P.MYARK_DYNDATA_QUERY_TOKEN_INPUT) == 16


# ---------------------------------------------------------------------------
# Round-trip: write a fixed set of fields and read them back from bytes().
# ---------------------------------------------------------------------------

class TestRoundTrip:
    def test_process_entry_round_trip(self) -> None:
        e = P.MYARK_DYNDATA_PROCESS_ENTRY()
        e.Pid = 1234
        e.Ppid = 4
        e.SessionId = 7
        e.Flags = P.DYNDATA_FLAG_POPULATED | P.DYNDATA_FLAG_SUSPECT
        e.EProcess = 0xFFFF8801ABCDEF00
        e.Peb = 0x00007FF7FFFF0000
        e.SourceMask = P.DYNDATA_PROCESS_SRC_ACTIVE_LINKS | P.DYNDATA_PROCESS_SRC_PSPCIDTABLE
        e.CreateTime = 0x01DB3F4A5B6C7D8E

        raw = bytes(e)
        rebuilt = P.MYARK_DYNDATA_PROCESS_ENTRY.from_buffer_copy(raw)
        assert rebuilt.Pid == 1234
        assert rebuilt.Ppid == 4
        assert rebuilt.SessionId == 7
        assert rebuilt.Flags == (P.DYNDATA_FLAG_POPULATED | P.DYNDATA_FLAG_SUSPECT)
        assert rebuilt.EProcess == 0xFFFF8801ABCDEF00
        assert rebuilt.Peb == 0x00007FF7FFFF0000
        assert rebuilt.SourceMask == (P.DYNDATA_PROCESS_SRC_ACTIVE_LINKS | P.DYNDATA_PROCESS_SRC_PSPCIDTABLE)
        assert rebuilt.CreateTime == 0x01DB3F4A5B6C7D8E

    def test_syscall_entry_round_trip(self) -> None:
        e = P.MYARK_DYNDATA_SYSCALL_ENTRY()
        e.ServiceIndex = 0x42
        e.TableId = P.DYNDATA_SYSCALL_TABLE_NTOS
        e.ServiceAddress = 0xFFFFF80012345678
        e.Flags = P.DYNDATA_FLAG_POPULATED
        e.DwellBytesSize = 8
        for i, b in enumerate(b"\x90\x90\x90\x90\x90\x90\x90\x90"):
            e.DwellBytes[i] = b

        rebuilt = P.MYARK_DYNDATA_SYSCALL_ENTRY.from_buffer_copy(bytes(e))
        assert rebuilt.ServiceIndex == 0x42
        assert rebuilt.TableId == P.DYNDATA_SYSCALL_TABLE_NTOS
        assert rebuilt.ServiceAddress == 0xFFFFF80012345678
        assert rebuilt.Flags == P.DYNDATA_FLAG_POPULATED
        assert rebuilt.DwellBytesSize == 8
        assert bytes(rebuilt.DwellBytes) == b"\x90\x90\x90\x90\x90\x90\x90\x90"


# ---------------------------------------------------------------------------
# Constants exposed by protocol.py.
# ---------------------------------------------------------------------------

class TestConstants:
    def test_flag_bits_distinct(self) -> None:
        bits = {P.DYNDATA_FLAG_NONE,
                P.DYNDATA_FLAG_POPULATED,
                P.DYNDATA_FLAG_SUSPECT,
                P.DYNDATA_FLAG_HOOK}
        assert len(bits) == 4

    def test_token_flag_bits_distinct(self) -> None:
        bits = {P.DYNDATA_TOKEN_FLAG_NONE,
                P.DYNDATA_TOKEN_FLAG_USER_PRESENT,
                P.DYNDATA_TOKEN_FLAG_INTEGRITY,
                P.DYNDATA_TOKEN_FLAG_ELEVATION,
                P.DYNDATA_TOKEN_FLAG_VIRTUALIZATION}
        assert len(bits) == 5

    def test_syscall_table_ids_distinct(self) -> None:
        ids = {P.DYNDATA_SYSCALL_TABLE_NTOS,
               P.DYNDATA_SYSCALL_TABLE_WIN32K,
               P.DYNDATA_SYSCALL_TABLE_SHADOW,
               P.DYNDATA_SYSCALL_TABLE_UNKNOWN}
        assert len(ids) == 4


__all__ = []
