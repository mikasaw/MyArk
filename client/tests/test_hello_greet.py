"""Hello module IOCTL ctypes mirrors + ArkClient smoke tests (S10.3).

Structural checks for the HELLO_GREET IOCTL (WCHAR variant of HELLO_PING)
run regardless of driver state. The live round-trip is skipped cleanly
when ``\\\\.\\MyArkCore`` is absent, matching the existing
``test_core_ioctl.py`` pattern.
"""

from __future__ import annotations

import ctypes

import pytest

from myark.client.ark_client import DriverNotInstalledError, open_driver
from myark.client.driver_check import probe_driver
from myark.modules.hello import (
    IOCTL_MYARK_HELLO_GREET,
    IOCTL_MYARK_HELLO_PING,
    MYARK_HELLO_GREET_INPUT,
    MYARK_HELLO_GREET_OUTPUT,
    MYARK_HELLO_PING_INPUT,
    MYARK_HELLO_PING_OUTPUT,
    _greet_via_client,
    _ping_via_client,
)


def _driver_present() -> bool:
    return probe_driver().installed


# ---------------------------------------------------------------------------
# Structural checks (always run)
# ---------------------------------------------------------------------------


class TestIoctlCodes:
    def test_function_range(self) -> None:
        # Hello IOCTLs occupy 0x900..0x9FF. Both PING (0x900) and GREET
        # (0x901) must sit in that range, with the expected access flags.
        for code in (IOCTL_MYARK_HELLO_PING, IOCTL_MYARK_HELLO_GREET):
            assert (code >> 16) == 0x22  # FILE_DEVICE_UNKNOWN
            assert (code & 0x3) == 0      # METHOD_BUFFERED
            function = (code >> 2) & 0xFFF
            assert 0x900 <= function <= 0x9FF

    def test_distinct_codes(self) -> None:
        # PING and GREET must not collide on the IOCTL code.
        assert IOCTL_MYARK_HELLO_PING != IOCTL_MYARK_HELLO_GREET


class TestPingStructures:
    def test_input_size(self) -> None:
        # Name is a 64-byte CHAR array.
        assert ctypes.sizeof(MYARK_HELLO_PING_INPUT) == 64

    def test_output_size(self) -> None:
        # Greeting(128) + BuildNumber(4) + ModuleId(4) + TickCount(4) == 140.
        assert ctypes.sizeof(MYARK_HELLO_PING_OUTPUT) == 140


class TestGreetStructures:
    def test_input_size(self) -> None:
        # Name is a 64-slot WCHAR array => 128 bytes.
        assert ctypes.sizeof(MYARK_HELLO_GREET_INPUT) == 128

    def test_output_size(self) -> None:
        # Greeting(128 WCHAR) + BuildNumber(4) + ModuleId(4) + Timestamp(8)
        # == 256 + 16 == 272. The struct is intentionally wider than PING
        # so the wire layout differs.
        assert ctypes.sizeof(MYARK_HELLO_GREET_OUTPUT) == 272

    def test_round_trip(self) -> None:
        g = MYARK_HELLO_GREET_OUTPUT(
            Greeting="hello world",
            BuildNumber=1,
            ModuleId=0x48454C4C,
            Timestamp=0xCAFEBABE_DEADBEEF,
        )
        rebuilt = MYARK_HELLO_GREET_OUTPUT.from_buffer_copy(bytes(g))
        assert rebuilt.Greeting == "hello world"
        assert rebuilt.BuildNumber == 1
        assert rebuilt.ModuleId == 0x48454C4C
        assert rebuilt.Timestamp == 0xCAFEBABE_DEADBEEF


# ---------------------------------------------------------------------------
# Driver-handle behaviour (skipped when the driver isn't installed)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not _driver_present(),
    reason="MyArkCore driver not installed in this test environment",
)
def test_greet_via_client_smoke() -> None:
    """A successful _greet_via_client returns the expected fields."""
    with open_driver() as client:
        out = _greet_via_client(client, "S10.3")
        # Greeting must be non-empty and start with "Hello, ".
        greeting = out.Greeting.split("\x00", 1)[0]
        assert greeting.startswith("Hello, "), greeting
        # BuildNumber is fixed at MYARK_CORE_DRIVER_BUILD_NUMBER (== 1).
        assert out.BuildNumber >= 1
        # ModuleId is the 'HELL' ASCII constant 0x48454C4C.
        assert out.ModuleId == 0x48454C4C
        # Timestamp must be > 0 -- the kernel hands back the QPC tick.
        assert out.Timestamp > 0


@pytest.mark.skipif(
    _driver_present(),
    reason="driver is installed -- the absent-driver path is not exercised",
)
def test_greet_via_client_raises_when_driver_missing() -> None:
    """The absent-driver path bubbles OSError-derived DriverNotInstalledError."""
    with pytest.raises(OSError):
        # Reuse a fake client-like object so we don't depend on a real handle.
        class _NoHandle:
            def ioctl(self, *_args, **_kwargs):
                raise DriverNotInstalledError("no driver")

        _greet_via_client(_NoHandle(), "x")  # type: ignore[arg-type]
