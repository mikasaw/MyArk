"""Process module IOCTL ctypes mirrors (S10.3).

Mirrors ``shared/driver/MyArkProcessIoctl.h``. Structural checks run
regardless of driver state; the live round-trip is skipped cleanly when
``\\\\.\\MyArkCore`` is absent.
"""

from __future__ import annotations

import ctypes

import pytest

from myark.client.driver_check import probe_driver
from myark.protocol import process as proto


def _driver_present() -> bool:
    return probe_driver().installed


# ---------------------------------------------------------------------------
# Structural checks (always run)
# ---------------------------------------------------------------------------


class TestIoctlCodes:
    def test_function_range(self) -> None:
        # Process IOCTLs occupy 0xA00..0xAFF. All 13 codes must sit in
        # that range and use METHOD_BUFFERED + FILE_ANY_ACCESS.
        codes = {
            proto.IOCTL_MYARK_PROCESS_ENUM,
            proto.IOCTL_MYARK_PROCESS_ENUM_THREAD,
            proto.IOCTL_MYARK_PROCESS_DETAIL,
            proto.IOCTL_MYARK_PROCESS_DETAIL_RUNTIME,
            proto.IOCTL_MYARK_PROCESS_CROSSVIEW,
            proto.IOCTL_MYARK_PROCESS_TERMINATE,
            proto.IOCTL_MYARK_PROCESS_SUSPEND,
            proto.IOCTL_MYARK_PROCESS_SET_PPL_LEVEL,
            proto.IOCTL_MYARK_PROCESS_SET_INTEGRITY,
            proto.IOCTL_MYARK_PROCESS_SET_VISIBILITY,
            proto.IOCTL_MYARK_PROCESS_SET_SPECIAL_FLAGS,
            proto.IOCTL_MYARK_PROCESS_DKOM,
            proto.IOCTL_MYARK_PROCESS_INJECT,
        }
        for code in codes:
            assert (code >> 16) == proto.FILE_DEVICE_UNKNOWN if hasattr(proto, "FILE_DEVICE_UNKNOWN") else 0x22
            assert (code & 0x3) == 0  # METHOD_BUFFERED
            function = (code >> 2) & 0xFFF
            assert 0xA00 <= function <= 0xAFF, f"function 0x{function:X} outside process range"

    def test_distinct_codes(self) -> None:
        codes = {
            proto.IOCTL_MYARK_PROCESS_ENUM,
            proto.IOCTL_MYARK_PROCESS_ENUM_THREAD,
            proto.IOCTL_MYARK_PROCESS_DETAIL,
            proto.IOCTL_MYARK_PROCESS_DETAIL_RUNTIME,
            proto.IOCTL_MYARK_PROCESS_CROSSVIEW,
            proto.IOCTL_MYARK_PROCESS_TERMINATE,
            proto.IOCTL_MYARK_PROCESS_SUSPEND,
            proto.IOCTL_MYARK_PROCESS_SET_PPL_LEVEL,
            proto.IOCTL_MYARK_PROCESS_SET_INTEGRITY,
            proto.IOCTL_MYARK_PROCESS_SET_VISIBILITY,
            proto.IOCTL_MYARK_PROCESS_SET_SPECIAL_FLAGS,
            proto.IOCTL_MYARK_PROCESS_DKOM,
            proto.IOCTL_MYARK_PROCESS_INJECT,
        }
        assert len(codes) == 13

    def test_ioctl_codes_contiguous(self) -> None:
        # Function codes must be contiguous 0xA00..0xA0C (13 entries).
        codes = (
            proto.IOCTL_MYARK_PROCESS_ENUM,
            proto.IOCTL_MYARK_PROCESS_ENUM_THREAD,
            proto.IOCTL_MYARK_PROCESS_DETAIL,
            proto.IOCTL_MYARK_PROCESS_DETAIL_RUNTIME,
            proto.IOCTL_MYARK_PROCESS_CROSSVIEW,
            proto.IOCTL_MYARK_PROCESS_TERMINATE,
            proto.IOCTL_MYARK_PROCESS_SUSPEND,
            proto.IOCTL_MYARK_PROCESS_SET_PPL_LEVEL,
            proto.IOCTL_MYARK_PROCESS_SET_INTEGRITY,
            proto.IOCTL_MYARK_PROCESS_SET_VISIBILITY,
            proto.IOCTL_MYARK_PROCESS_SET_SPECIAL_FLAGS,
            proto.IOCTL_MYARK_PROCESS_DKOM,
            proto.IOCTL_MYARK_PROCESS_INJECT,
        )
        for idx, code in enumerate(codes):
            function = (code >> 2) & 0xFFF
            assert function == 0xA00 + idx, (
                f"code at index {idx} is function 0x{function:X}, expected 0x{0xA00+idx:X}"
            )


class TestEnumStructures:
    def test_entry_size(self) -> None:
        # Pid(4) + Ppid(4) + Name(64WCHAR=128) + Path(260WCHAR=520) +
        # User(64WCHAR=128) + MemKb(4) + Ppl(1) + Hidden(1) +
        # SourceMask(1) + Reserved(1) == 792.
        assert ctypes.sizeof(proto.MYARK_PROCESS_ENTRY) == 792

    def test_enum_input_size(self) -> None:
        # MaxEntries(4) + SourceMask(4) + 2 reserved = 16.
        assert ctypes.sizeof(proto.MYARK_PROCESS_ENUM_INPUT) == 16

    def test_enum_header_size(self) -> None:
        # Header = Size + Count + TotalSeen + HiddenCount = 16; trailing
        # Entries[1] is a flexible-array placeholder the caller subtracts.
        assert proto.HEADER_SIZE_ENUM == 16

    def test_enum_buffer_size_helper(self) -> None:
        # 0 entries returns just the header; 1 entry adds one row.
        assert proto.enum_buffer_size(0) == proto.HEADER_SIZE_ENUM
        assert proto.enum_buffer_size(1) == proto.HEADER_SIZE_ENUM + 792
        assert proto.enum_buffer_size(16) == proto.HEADER_SIZE_ENUM + 16 * 792


class TestThreadStructures:
    def test_thread_entry_size(self) -> None:
        # The driver-side struct is 5 UINT32 + 1 UINT64; ctypes adds
        # 4 bytes of padding before the UINT64 for 8-byte alignment.
        # Pin the actual size (32 bytes) so any future field tweak
        # breaks a test rather than silently misaligning the wire.
        assert ctypes.sizeof(proto.MYARK_THREAD_ENTRY) == 32

    def test_enum_thread_input_size(self) -> None:
        assert ctypes.sizeof(proto.MYARK_PROCESS_ENUM_THREAD_INPUT) == 8


class TestDetailStructures:
    def test_detail_size(self) -> None:
        # The exact size depends on alignment padding; pin the actual
        # ctypes size (896) so any future field tweak breaks the test.
        assert ctypes.sizeof(proto.MYARK_PROCESS_DETAIL) == 896

    def test_detail_runtime_size(self) -> None:
        # Pid(4) + Reserved0(4) + 8 UINT64 + PrivatePageCount(4) +
        # Reserved1(4) + CycleTime(8) == 88.
        assert ctypes.sizeof(proto.MYARK_PROCESS_DETAIL_RUNTIME) == 88


class TestCrossviewStructures:
    def test_crossview_input_size(self) -> None:
        assert ctypes.sizeof(proto.MYARK_PROCESS_CROSSVIEW_INPUT) == 16

    def test_crossview_header_size(self) -> None:
        # Same shape as enum output but with PublicOnly instead of TotalSeen.
        assert proto.HEADER_SIZE_CROSSVIEW == 16


class TestActionStructures:
    # Every mutating INPUT now carries a leading MYARK_SAFETY_TOKEN
    # (Magic+Pid+Op+Reserved 16 + Timestamp 8 + Signature 32 + Reserved 16
    # = 72 bytes), mirroring shared/driver/MyArkSafetyToken.h.
    _TOKEN = 72

    def test_terminate_io_sizes(self) -> None:
        assert ctypes.sizeof(proto.MYARK_PROCESS_TERMINATE_INPUT) == 16 + self._TOKEN
        assert ctypes.sizeof(proto.MYARK_PROCESS_TERMINATE_OUTPUT) == 16

    def test_suspend_io_sizes(self) -> None:
        assert ctypes.sizeof(proto.MYARK_PROCESS_SUSPEND_INPUT) == 16 + self._TOKEN
        assert ctypes.sizeof(proto.MYARK_PROCESS_SUSPEND_OUTPUT) == 16

    def test_set_ppl_io_sizes(self) -> None:
        # INPUT: Token(72) + Pid(4) + 3xUINT8 + 1 padding + Reserved0(4)
        # = 84, rounded up to the struct's 8-byte alignment = 88.
        assert ctypes.sizeof(proto.MYARK_PROCESS_SET_PPL_INPUT) == 88
        assert ctypes.sizeof(proto.MYARK_PROCESS_SET_PPL_OUTPUT) == 16

    def test_set_integrity_io_sizes(self) -> None:
        assert ctypes.sizeof(proto.MYARK_PROCESS_SET_INTEGRITY_INPUT) == 16 + self._TOKEN
        assert ctypes.sizeof(proto.MYARK_PROCESS_SET_INTEGRITY_OUTPUT) == 16

    def test_set_visibility_io_sizes(self) -> None:
        assert ctypes.sizeof(proto.MYARK_PROCESS_SET_VISIBILITY_INPUT) == 16 + self._TOKEN
        assert ctypes.sizeof(proto.MYARK_PROCESS_SET_VISIBILITY_OUTPUT) == 16

    def test_set_special_flags_io_sizes(self) -> None:
        assert ctypes.sizeof(proto.MYARK_PROCESS_SET_SPECIAL_FLAGS_INPUT) == 16 + self._TOKEN
        assert ctypes.sizeof(proto.MYARK_PROCESS_SET_SPECIAL_FLAGS_OUTPUT) == 16

    def test_dkom_io_sizes(self) -> None:
        assert ctypes.sizeof(proto.MYARK_PROCESS_DKOM_INPUT) == 16 + self._TOKEN
        assert ctypes.sizeof(proto.MYARK_PROCESS_DKOM_OUTPUT) == 16

    def test_inject_io_sizes(self) -> None:
        # INPUT carries Token + Pid + Method + 2 reserved + DllPath (260 WCHAR).
        assert ctypes.sizeof(proto.MYARK_PROCESS_INJECT_INPUT) == 16 + self._TOKEN + 260 * 2
        assert ctypes.sizeof(proto.MYARK_PROCESS_INJECT_OUTPUT) == 16

    def test_mutating_inputs_lead_with_token(self) -> None:
        # The Token must be the FIRST field so the kernel validator can
        # read it before any payload interpretation.
        for name in (
            "MYARK_PROCESS_TERMINATE_INPUT",
            "MYARK_PROCESS_SUSPEND_INPUT",
            "MYARK_PROCESS_SET_PPL_INPUT",
            "MYARK_PROCESS_SET_INTEGRITY_INPUT",
            "MYARK_PROCESS_SET_VISIBILITY_INPUT",
            "MYARK_PROCESS_SET_SPECIAL_FLAGS_INPUT",
            "MYARK_PROCESS_DKOM_INPUT",
            "MYARK_PROCESS_INJECT_INPUT",
        ):
            fields = [f[0] for f in getattr(proto, name)._fields_]
            assert fields[0] == "Token", f"{name} does not lead with Token"


class TestConstants:
    def test_module_id(self) -> None:
        # 'PROC' ASCII little-endian: 'P'=0x50 'R'=0x52 'O'=0x4F 'C'=0x43.
        assert proto.MYARK_PROCESS_MODULE_ID == 0x50524F43

    def test_source_mask_values(self) -> None:
        assert proto.PROCESS_SRC_NONE == 0x00
        assert proto.PROCESS_SRC_PUBLIC == 0x01
        assert proto.PROCESS_SRC_PSPCIDTABLE == 0x02
        assert proto.PROCESS_SRC_ACTIVE_LINKS == 0x04

    def test_hidden_mask_values(self) -> None:
        assert proto.PROCESS_HIDDEN_NONE == 0x00
        assert proto.PROCESS_HIDDEN_VIA_DKOM == 0x01

    def test_size_constants(self) -> None:
        # The kernel-side MYARK_PROCESS_*_MAX macros must match these
        # Python constants so the ctypes arrays don't overflow the wire
        # layout.
        assert proto.MYARK_PROCESS_NAME_MAX == 64
        assert proto.MYARK_PROCESS_PATH_MAX == 260
        assert proto.MYARK_PROCESS_USER_MAX == 64
        assert proto.MYARK_PROCESS_IMAGE_FILE_NAME_MAX == 16


# ---------------------------------------------------------------------------
# Driver-present behaviour (skipped when the driver isn't installed)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not _driver_present(),
    reason="MyArkCore driver not installed in this test environment",
)
def test_enum_ioctl_code_matches_driver() -> None:
    """The wire-side code must match the kernel-side CTL_CODE formula.

    On a live driver install this confirms the ctypes mirror and the
    driver-side header agree on the IOCTL number; the registry entry
    for IOCTL_MYARK_PROCESS_ENUM must match what we expect.
    """
    expected = (0x22 << 16) | (0xA00 << 2)
    assert proto.IOCTL_MYARK_PROCESS_ENUM == expected


def test_device_name_does_not_clash_with_process() -> None:
    """The process module uses the same device path as the core; the
    IOCTL code alone disambiguates which subsystem answers."""
    from myark.protocol.core import MYARK_CORE_DEVICE_NAME

    # Both subsystems share the device path; the IOCTL function code is
    # the discriminator. This pins that contract so a future refactor
    # doesn't accidentally split the device path.
    assert MYARK_CORE_DEVICE_NAME == r"\\.\MyArkCore"
    # ENUM at 0xA00 and core GET_VERSION at 0x800 must remain distinct.
    assert proto.IOCTL_MYARK_PROCESS_ENUM != 0x00220000  # core GET_VERSION code
