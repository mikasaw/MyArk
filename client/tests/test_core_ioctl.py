"""Core IOCTL ctypes mirrors + ArkClient smoke tests (S1.4).

The driver side isn't installed in every test environment, so the
``test_open_driver`` cases skip cleanly when ``\\\\.\\MyArkCore`` is absent --
this matches the S1.4 acceptance ("允许 SKIPPED"). Structural checks for the
ctypes protocol run regardless of driver state.
"""

from __future__ import annotations

import ctypes
import os

import pytest

from myark.client import ark_client
from myark.client.ark_client import DriverNotInstalledError, open_driver
from myark.client.driver_check import is_admin, probe_driver
from myark.protocol import core as proto


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _driver_present() -> bool:
    """Best-effort probe without forcing a hard failure on access denied."""
    return probe_driver().installed


# ---------------------------------------------------------------------------
# Structural checks (always run)
# ---------------------------------------------------------------------------


class TestIoctlCodes:
    def test_function_range(self) -> None:
        # Core IOCTLs occupy 0x800..0x8FF. The codes below must all sit
        # in that range and use METHOD_BUFFERED + FILE_ANY_ACCESS.
        for code in (
            proto.IOCTL_MYARK_CORE_GET_VERSION,
            proto.IOCTL_MYARK_CORE_QUERY_MODULES,
            proto.IOCTL_MYARK_CORE_QUERY_CAPABILITIES,
            proto.IOCTL_MYARK_CORE_GET_LOG,
            proto.IOCTL_MYARK_CORE_SET_LOG_CONFIG,
            proto.IOCTL_MYARK_CORE_GET_SESSION_KEY,
        ):
            assert (code >> 16) == proto.FILE_DEVICE_UNKNOWN
            assert (code & 0x3) == proto.METHOD_BUFFERED
            function = (code >> 2) & 0xFFF
            assert 0x800 <= function <= 0x8FF, f"function 0x{function:X} outside core range"

    def test_distinct_codes(self) -> None:
        codes = {
            proto.IOCTL_MYARK_CORE_GET_VERSION,
            proto.IOCTL_MYARK_CORE_QUERY_MODULES,
            proto.IOCTL_MYARK_CORE_QUERY_CAPABILITIES,
            proto.IOCTL_MYARK_CORE_GET_LOG,
            proto.IOCTL_MYARK_CORE_SET_LOG_CONFIG,
            proto.IOCTL_MYARK_CORE_GET_SESSION_KEY,
        }
        assert len(codes) == 6


class TestVersionStructure:
    def test_size(self) -> None:
        # Size + 4 x UINT32 + WCHAR[64] == 4 + 16 + 128 == 148.
        assert ctypes.sizeof(proto.MYARK_CORE_VERSION_OUTPUT) == 148

    def test_round_trip(self) -> None:
        v = proto.MYARK_CORE_VERSION_OUTPUT(
            Size=148,
            CoreProtocolVersion=1,
            ModuleProtocolVersion=1,
            BuildNumber=42,
            ActiveModuleCount=3,
            DisplayName="hello",
        )
        rebuilt = proto.MYARK_CORE_VERSION_OUTPUT.from_buffer_copy(bytes(v))
        assert rebuilt.Size == 148
        assert rebuilt.BuildNumber == 42
        assert rebuilt.DisplayName == "hello"


class TestModuleInfoStructure:
    def test_size(self) -> None:
        # ModuleId(4) + Name(32) + Description(128) + State(4) +
        # IoctlCount(4) + LastError(4) == 176.
        assert ctypes.sizeof(proto.MYARK_CORE_MODULE_INFO) == 176

    def test_header_size(self) -> None:
        # Header must be exactly the Size + Count fields; the trailing
        # Modules[1] is a flexible-array placeholder the client subtracts.
        assert proto.HEADER_SIZE_MODULE_LIST == 8


class TestCapabilityStructure:
    def test_size(self) -> None:
        # IoctlCode(4) + Name(64) + ModuleId(4) == 72.
        assert ctypes.sizeof(proto.MYARK_CORE_CAPABILITY_ENTRY) == 72
        assert proto.HEADER_SIZE_CAPABILITY == 8


class TestLogStructures:
    def test_record_size(self) -> None:
        # Sequence(4) + Level(4) + Timestamp(8) + Module(16) + Message(192) == 224.
        assert ctypes.sizeof(proto.MYARK_CORE_LOG_RECORD) == 224
        assert proto.HEADER_SIZE_LOG == 8

    def test_input_size(self) -> None:
        # Cursor(4) + MaxRecords(4) == 8.
        assert ctypes.sizeof(proto.MYARK_CORE_LOG_INPUT) == 8

    def test_config_size(self) -> None:
        assert ctypes.sizeof(proto.MYARK_CORE_LOG_CONFIG) == 12


# ---------------------------------------------------------------------------
# Driver-handle behaviour (skipped when the driver isn't installed)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not _driver_present(),
    reason="MyArkCore driver not installed in this test environment",
)
def test_open_driver_returns_arkclient() -> None:
    client = open_driver()
    try:
        assert isinstance(client, ark_client.ArkClient)
        assert client.handle not in (0, -1)
    finally:
        client.close()


@pytest.mark.skipif(
    not _driver_present(),
    reason="MyArkCore driver not installed in this test environment",
)
def test_open_driver_context_manager() -> None:
    with open_driver() as client:
        assert client.handle not in (0, -1)
    assert client.handle == 0


# ---------------------------------------------------------------------------
# Driver-absent behaviour (always run; verifies the error path)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    _driver_present(),
    reason="driver is installed -- the absent-driver path is not exercised",
)
def test_open_driver_raises_when_driver_missing() -> None:
    # Acceptance criterion from MyArk-S1.4: open_driver() must surface the
    # missing driver as an OSError-derived exception.
    with pytest.raises(OSError):
        open_driver()
    with pytest.raises(DriverNotInstalledError):
        open_driver()


@pytest.mark.skipif(
    _driver_present(),
    reason="driver is installed -- the absent-driver path is not exercised",
)
def test_probe_driver_reports_missing() -> None:
    probe = probe_driver()
    assert probe.installed is False
    assert probe.version_output is None


def test_device_name_constant() -> None:
    # The user-mode device path must match what sc create / INF installs.
    assert proto.MYARK_CORE_DEVICE_NAME == r"\\.\MyArkCore"


def test_is_admin_returns_bool() -> None:
    """is_admin() must always return a Python bool and never raise.

    The function wraps shell32.IsUserAnAdmin; on exotic hosts where shell32
    cannot be loaded it returns False instead of bubbling the ctypes error.
    The CLI / UI branch on this boolean to show an elevation hint, so the
    return type contract is what they actually depend on.
    """
    result = is_admin()
    assert isinstance(result, bool)