"""SAFETY_TOKEN hardening: HMAC signing parity with the kernel validator.

The kernel (driver/src/dispatch/safety_token.c) computes
HMAC-SHA256(session_key, Magic|Pid|Operation|Timestamp) over a 20-byte
little-endian message and enforces a +/-120 s freshness window on the
FILETIME-scale Timestamp. These tests pin the R3 side of that contract:
message layout, signature round-trip, token embedding, and the session
key delivery path through the real ArkClient over a faked transport.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import struct

import pytest

from myark.client import transport
from myark.client.ark_client import ArkClient
from myark.client.safety_token import (
    compute_signature,
    fetch_session_key,
    mac_message,
    nt_filetime_now,
)
from myark.protocol.core import (
    IOCTL_MYARK_CORE_GET_SESSION_KEY,
    MYARK_SAFETY_TOKEN_KEY_SIZE,
    MYARK_SAFETY_TOKEN_MAGIC,
    MYARK_SAFETY_TOKEN_SIGNATURE_SIZE,
    MYARK_SAFETY_TOKEN,
    MYARK_CORE_SESSION_KEY_OUTPUT,
)

KEY = bytes(range(32))


# ---------------------------------------------------------------------------
# Message layout -- must match the kernel memcpy layout byte for byte.
# ---------------------------------------------------------------------------


class TestMacMessage:
    def test_message_is_20_bytes(self) -> None:
        assert len(mac_message(1, 2, 3, 4)) == 20

    def test_message_layout_matches_kernel(self) -> None:
        # Magic(4 LE) | Pid(4 LE) | Operation(4 LE) | Timestamp(8 LE i64).
        msg = mac_message(MYARK_SAFETY_TOKEN_MAGIC, 1234, 7, 0x1122334455667788)
        assert msg[:4] == struct.pack("<I", MYARK_SAFETY_TOKEN_MAGIC)
        assert msg[4:8] == struct.pack("<I", 1234)
        assert msg[8:12] == struct.pack("<I", 7)
        assert msg[12:20] == struct.pack("<q", 0x1122334455667788)

    def test_signature_matches_reference_hmac(self) -> None:
        msg = mac_message(MYARK_SAFETY_TOKEN_MAGIC, 42, 3, 17000000000000000)
        expected = hmac.new(KEY, msg, hashlib.sha256).digest()
        assert compute_signature(KEY, 42, 3, 17000000000000000) == expected

    def test_signature_binds_every_field(self) -> None:
        base = compute_signature(KEY, 42, 3, 17000000000000000)
        assert compute_signature(KEY, 43, 3, 17000000000000000) != base
        assert compute_signature(KEY, 42, 4, 17000000000000000) != base
        assert compute_signature(KEY, 42, 3, 17000000000000001) != base
        assert compute_signature(bytes(32), 42, 3, 17000000000000000) != base

    def test_wrong_key_size_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            compute_signature(b"short", 1, 1, 1)


# ---------------------------------------------------------------------------
# Timestamp scale -- kernel compares against KeQuerySystemTime (100ns).
# ---------------------------------------------------------------------------


class TestTimestamp:
    def test_filetime_now_is_in_kernel_scale(self) -> None:
        now = nt_filetime_now()
        # FILETIME around 2026 is ~1.34e17; Unix time_ns would be ~1.78e18.
        assert 1.0e17 < now < 5.0e17

    def test_timestamp_fits_large_integer(self) -> None:
        token = MYARK_SAFETY_TOKEN()
        token.Timestamp = nt_filetime_now()
        assert token.Timestamp > 0


# ---------------------------------------------------------------------------
# SafetyToken.build parity.
# ---------------------------------------------------------------------------


class TestSafetyTokenBuild:
    def test_build_with_key_is_hmac_signed(self) -> None:
        from myark.modules.actions.parser import SafetyToken

        t = SafetyToken(pid=42, operation=3)
        wire = t.build(KEY)
        expected = compute_signature(KEY, 42, 3, t.timestamp)
        assert bytes(wire.Signature) == expected

    def test_build_without_key_keeps_placeholder(self) -> None:
        from myark.modules.actions.parser import SafetyToken

        wire = SafetyToken(pid=1, operation=1).build()
        assert any(b != 0 for b in wire.Signature)

    def test_explicit_signature_wins_over_key(self) -> None:
        from myark.modules.actions.parser import SafetyToken

        t = SafetyToken(pid=1, operation=1, signature=b"\xAB" * 32)
        wire = t.build(KEY)
        assert bytes(wire.Signature) == b"\xAB" * 32

    def test_wire_struct_size(self) -> None:
        # Magic(4)+Pid(4)+Op(4)+Reserved(4)+Timestamp(8)+Sig(32)+Reserved(16).
        assert ctypes.sizeof(MYARK_SAFETY_TOKEN) == 72


# ---------------------------------------------------------------------------
# Session-key delivery through the real ArkClient (faked transport).
# ---------------------------------------------------------------------------


class TestSessionKeyDelivery:
    def test_get_session_key_roundtrip(self, monkeypatch) -> None:
        calls = {}

        def fake_dio(handle, code, in_bytes, out_size):
            calls["code"] = code
            out = MYARK_CORE_SESSION_KEY_OUTPUT(
                Size=ctypes.sizeof(MYARK_CORE_SESSION_KEY_OUTPUT),
                KeyLength=32,
            )
            for i, b in enumerate(KEY):
                out.Key[i] = b
            return bytes(out), ctypes.sizeof(MYARK_CORE_SESSION_KEY_OUTPUT)

        monkeypatch.setattr(transport, "device_io_control", fake_dio)
        out = ArkClient(handle=1).get_session_key()

        assert calls["code"] == IOCTL_MYARK_CORE_GET_SESSION_KEY
        assert bytes(out.Key) == KEY
        assert fetch_session_key(ArkClient(handle=1)) == KEY

    def test_session_key_output_size(self) -> None:
        assert ctypes.sizeof(MYARK_CORE_SESSION_KEY_OUTPUT) == 40
        assert MYARK_SAFETY_TOKEN_KEY_SIZE == MYARK_SAFETY_TOKEN_SIGNATURE_SIZE
