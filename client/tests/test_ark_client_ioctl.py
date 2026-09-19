"""Integration-style tests: the REAL ArkClient over a faked transport.

``transport.device_io_control`` is the only seam between ``ArkClient`` and
kernel32, so monkeypatching it exercises the true client: buffer sizing,
short reads, list-count clamping and OSError mapping. The per-module
``test_*_client.py`` suites mock ``ArkClient`` itself -- which is exactly
how a whole client-API drift (module code calling a method that no longer
existed) once hid behind a green suite. This file is the guard against
that class of regression.
"""

from __future__ import annotations

import ctypes
import struct

import pytest

from myark.client import transport
from myark.client.ark_client import (
    ArkClient,
    DriverCallError,
    DriverError,
    DriverNotInstalledError,
)
from myark.protocol.core import (
    HEADER_SIZE_CAPABILITY,
    HEADER_SIZE_LOG,
    HEADER_SIZE_MODULE_LIST,
    IOCTL_MYARK_CORE_GET_LOG,
    IOCTL_MYARK_CORE_QUERY_CAPABILITIES,
    IOCTL_MYARK_CORE_QUERY_MODULES,
    MYARK_CORE_CAPABILITY_ENTRY,
    MYARK_CORE_CAPABILITY_OUTPUT,
    MYARK_CORE_LOG_INPUT,
    MYARK_CORE_LOG_OUTPUT,
    MYARK_CORE_LOG_RECORD,
    MYARK_CORE_MODULE_INFO,
    MYARK_CORE_MODULE_LIST_OUTPUT,
    MYARK_CORE_VERSION_OUTPUT,
)


class _FakeTransport:
    """Scriptable stand-in for ``transport.device_io_control``.

    Each scripted step is either an ``OSError`` (raised, like a failed
    DeviceIoControl) or a ``(payload_bytes, bytes_returned)`` tuple. The
    fake honours the real transport's contract: it never returns more than
    the caller's ``out_size`` bytes.
    """

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.script: list = []

    def __call__(self, handle: int, ioctl_code: int, in_buffer, out_size: int):
        self.calls.append({
            "handle": handle,
            "code": ioctl_code,
            "in_bytes": in_buffer,
            "out_size": out_size,
        })
        step = self.script.pop(0)
        if isinstance(step, OSError):
            raise step
        payload, returned = step
        n = min(returned, out_size)
        out = bytes(payload[:n])
        return out, n


@pytest.fixture()
def fake_transport(monkeypatch) -> _FakeTransport:
    fake = _FakeTransport()
    monkeypatch.setattr(transport, "device_io_control", fake)
    return fake


def _client() -> ArkClient:
    return ArkClient(handle=0xDEADBEEF)


def _module_entry(name: bytes, state: int = 1) -> MYARK_CORE_MODULE_INFO:
    return MYARK_CORE_MODULE_INFO(
        ModuleId=0x1,
        ModuleName=name.ljust(32, b"\x00"),
        ModuleDescription=b"test".ljust(128, b"\x00"),
        State=state,
        IoctlCount=1,
        LastError=0,
    )


def _module_list_payload(count_field: int, entries: list[MYARK_CORE_MODULE_INFO]) -> bytes:
    header = struct.pack("<II", HEADER_SIZE_MODULE_LIST, count_field)
    return header + b"".join(bytes(e) for e in entries)


# ---------------------------------------------------------------------------
# ArkClient.ioctl -- the public raw surface every module calls.
# ---------------------------------------------------------------------------


class TestIoctlRawSurface:
    def test_roundtrip_fills_out_buf_and_returns_bytes_written(self, fake_transport):
        out = MYARK_CORE_VERSION_OUTPUT()
        payload = bytes(MYARK_CORE_VERSION_OUTPUT(
            Size=ctypes.sizeof(MYARK_CORE_VERSION_OUTPUT),
            CoreProtocolVersion=1,
            ModuleProtocolVersion=2,
            BuildNumber=7,
            ActiveModuleCount=35,
        ))
        fake_transport.script = [(payload, len(payload))]

        returned = _client().ioctl(0x800, b"", out)

        assert returned == ctypes.sizeof(MYARK_CORE_VERSION_OUTPUT)
        assert out.CoreProtocolVersion == 1
        assert out.BuildNumber == 7
        assert out.ActiveModuleCount == 35

    def test_short_read_returns_actual_count(self, fake_transport):
        out = (ctypes.c_ubyte * 64)()
        fake_transport.script = [(bytes(range(10)), 10)]

        returned = _client().ioctl(0x1234, None, out)

        assert returned == 10
        assert bytes(out[:10]) == bytes(range(10))
        assert returned != len(out)

    def test_bytes_returned_over_buffer_size_is_clamped(self, fake_transport):
        # A misbehaving driver claiming more bytes than the buffer holds
        # must not overflow the caller's buffer.
        out = (ctypes.c_ubyte * 8)()
        fake_transport.script = [(bytes(range(200)), 200)]

        returned = _client().ioctl(0x1234, None, out)

        assert returned == 8
        assert bytes(out) == bytes(range(8))

    @pytest.mark.parametrize("bad_in", [None, b"", (ctypes.c_ubyte * 0)()])
    def test_empty_inputs_forwarded_as_empty_bytes(self, fake_transport, bad_in):
        out = MYARK_CORE_VERSION_OUTPUT()
        fake_transport.script = [
            (bytes(ctypes.sizeof(MYARK_CORE_VERSION_OUTPUT)), ctypes.sizeof(MYARK_CORE_VERSION_OUTPUT)),
        ]

        _client().ioctl(0x800, bad_in, out)

        assert fake_transport.calls[0]["in_bytes"] == b""

    def test_struct_and_array_inputs_pack_to_bytes(self, fake_transport):
        out = (ctypes.c_ubyte * 4)()
        fake_transport.script = [(b"\x00" * 4, 4)]

        _client().ioctl(0x1234, MYARK_CORE_LOG_INPUT(Cursor=3, MaxRecords=9), out)

        assert fake_transport.calls[0]["in_bytes"] == bytes(MYARK_CORE_LOG_INPUT(Cursor=3, MaxRecords=9))

    def test_oserror_maps_to_driver_call_error(self, fake_transport):
        fake_transport.script = [OSError(87, "bad parameter")]
        out = (ctypes.c_ubyte * 16)()

        with pytest.raises(DriverCallError) as excinfo:
            _client().ioctl(0x1234, None, out)

        assert isinstance(excinfo.value, DriverError)
        assert excinfo.value.errno == 87

    def test_calls_reach_the_same_handle(self, fake_transport):
        out = (ctypes.c_ubyte * 4)()
        fake_transport.script = [(b"\x00" * 4, 4)]
        client = _client()

        client.ioctl(0x1234, None, out)

        assert fake_transport.calls[0]["handle"] == 0xDEADBEEF


# ---------------------------------------------------------------------------
# Two-shot list queries: probe -> allocate -> parse, with Count clamping.
# ---------------------------------------------------------------------------


class TestQueryModulesClamping:
    def test_header_probe_falls_back_to_64_and_clamps_count(self, fake_transport):
        # Probe fails with ERROR_INSUFFICIENT_BUFFER (0x7A): client falls
        # back to a 64-entry buffer. The driver then claims 200 entries --
        # parsing must clamp to the allocated 64, never read past buf.
        fake_transport.script = [
            OSError(0x7A, "ERROR_INSUFFICIENT_BUFFER"),
            (_module_list_payload(200, [_module_entry(b"m%d" % i) for i in range(200)]), 0x7FFFFFF),
        ]

        result = _client().query_modules()

        assert len(result) == 64
        assert result[0].ModuleName.rstrip(b"\x00") == b"m0"
        assert fake_transport.calls[1]["out_size"] == (
            HEADER_SIZE_MODULE_LIST + 64 * ctypes.sizeof(MYARK_CORE_MODULE_INFO)
        )

    def test_populated_header_caps_buffer_to_reported_count(self, fake_transport):
        # Probe succeeds and reports Count=2: the second call must size the
        # buffer for exactly 2 entries and return exactly 2 rows.
        fake_transport.script = [
            (struct.pack("<II", HEADER_SIZE_MODULE_LIST, 2), HEADER_SIZE_MODULE_LIST),
            (_module_list_payload(2, [_module_entry(b"m0"), _module_entry(b"m1")]), 2 * ctypes.sizeof(MYARK_CORE_MODULE_INFO) + HEADER_SIZE_MODULE_LIST),
        ]

        result = _client().query_modules()

        assert len(result) == 2
        assert [m.ModuleName.rstrip(b"\x00") for m in result] == [b"m0", b"m1"]
        assert fake_transport.calls[1]["out_size"] == (
            HEADER_SIZE_MODULE_LIST + 2 * ctypes.sizeof(MYARK_CORE_MODULE_INFO)
        )

    def test_zero_count_short_circuits_without_second_call(self, fake_transport):
        fake_transport.script = [
            (struct.pack("<II", HEADER_SIZE_MODULE_LIST, 0), HEADER_SIZE_MODULE_LIST),
        ]

        assert _client().query_modules() == []
        assert len(fake_transport.calls) == 1


class TestQueryCapabilitiesClamping:
    def _cap_entry(self, ioctl_code: int) -> MYARK_CORE_CAPABILITY_ENTRY:
        return MYARK_CORE_CAPABILITY_ENTRY(IoctlCode=ioctl_code, Name=b"c".ljust(64, b"\x00"), ModuleId=1)

    def test_probe_fallback_clamps_claimed_count(self, fake_transport):
        entries = [self._cap_entry(0x100 + i) for i in range(80)]
        fake_transport.script = [
            OSError(0x7A, "ERROR_INSUFFICIENT_BUFFER"),
            (
                struct.pack("<II", HEADER_SIZE_CAPABILITY, 80) + b"".join(bytes(e) for e in entries),
                HEADER_SIZE_CAPABILITY + 80 * ctypes.sizeof(MYARK_CORE_CAPABILITY_ENTRY),
            ),
        ]

        result = _client().query_capabilities()

        assert len(result) == 64
        assert result[0].IoctlCode == 0x100


class TestGetLogClamping:
    def test_claimed_count_over_max_records_is_clamped(self, fake_transport):
        record = MYARK_CORE_LOG_RECORD(Sequence=1, Level=2, Timestamp=3, Module=b"m".ljust(16, b"\x00"))
        fake_transport.script = [
            (
                struct.pack("<II", HEADER_SIZE_LOG, 9) + bytes(record) * 9,
                HEADER_SIZE_LOG + 9 * ctypes.sizeof(MYARK_CORE_LOG_RECORD),
            ),
        ]

        result = _client().get_log(cursor=0, max_records=4)

        assert len(result) == 4
        assert fake_transport.calls[0]["in_bytes"] == bytes(MYARK_CORE_LOG_INPUT(Cursor=0, MaxRecords=4))
        assert fake_transport.calls[0]["out_size"] == HEADER_SIZE_LOG + 4 * ctypes.sizeof(MYARK_CORE_LOG_RECORD)


# ---------------------------------------------------------------------------
# Open / probe translation.
# ---------------------------------------------------------------------------


class TestOpenErrorTranslation:
    def test_missing_device_maps_to_driver_not_installed(self, monkeypatch):
        def _boom(_path):
            raise OSError(2, "ERROR_FILE_NOT_FOUND")

        monkeypatch.setattr(transport, "create_file", _boom)
        with pytest.raises(DriverNotInstalledError):
            ArkClient.open()

    def test_access_denied_keeps_distinct_message(self, monkeypatch):
        def _boom(_path):
            raise OSError(5, "ERROR_ACCESS_DENIED")

        monkeypatch.setattr(transport, "create_file", _boom)
        with pytest.raises(DriverError) as excinfo:
            ArkClient.open()

        assert "Administrator" in str(excinfo.value)
