"""Session-key retrieval + HMAC-SHA256 safety-token signing (R3 side).

The kernel validator (``driver/src/dispatch/safety_token.c``) checks every
mutating IOCTL's ``MYARK_SAFETY_TOKEN`` as:

    message   = Magic (u32 LE) | Pid (u32 LE) | Operation (u32 LE) |
                Timestamp (i64 LE, FILETIME 100ns since 1601-01-01)
    Signature = HMAC-SHA256(session_key, message)

The session key is generated per boot inside the driver and served through
``IOCTL_MYARK_CORE_GET_SESSION_KEY`` -- reachable only from an elevated
process because the device SDDL restricts the device to
SYSTEM/Administrators. Timestamps must land within +/-120 s of kernel
time, which is why :func:`nt_filetime_now` converts from the Unix clock
instead of the raw ``time.time_ns()`` nanosecond reading.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
import time

from ..protocol.core import (
    MYARK_SAFETY_TOKEN_KEY_SIZE,
    MYARK_SAFETY_TOKEN_MAGIC,
    MYARK_SAFETY_TOKEN_SIGNATURE_SIZE,
)

# Seconds between the Windows FILETIME epoch (1601-01-01) and the Unix
# epoch (1970-01-01); KeQuerySystemTime reads the former.
WINDOWS_EPOCH_OFFSET_S = 11644473600


def nt_filetime_now() -> int:
    """Current time in 100-ns units since 1601-01-01 (kernel clock scale)."""
    return int((time.time() + WINDOWS_EPOCH_OFFSET_S) * 10_000_000)


def mac_message(magic: int, pid: int, operation: int, timestamp: int) -> bytes:
    """The exact 20-byte buffer the kernel HMACs (see MyArkSafetyToken.h)."""
    return struct.pack("<IIIq", magic, pid, operation, timestamp)


def compute_signature(
    session_key: bytes,
    pid: int,
    operation: int,
    timestamp: int,
    magic: int = MYARK_SAFETY_TOKEN_MAGIC,
) -> bytes:
    """HMAC-SHA256 the token fields; must match the kernel digest exactly."""
    if len(session_key) != MYARK_SAFETY_TOKEN_KEY_SIZE:
        raise ValueError(
            f"session key must be {MYARK_SAFETY_TOKEN_KEY_SIZE} bytes, "
            f"got {len(session_key)}"
        )
    return hmac.new(
        session_key,
        mac_message(magic, pid, operation, timestamp),
        hashlib.sha256,
    ).digest()[:MYARK_SAFETY_TOKEN_SIGNATURE_SIZE]


def fetch_session_key(client) -> bytes:
    """Fetch the per-boot session key from the driver.

    Raises ``DriverCallError`` / ``OSError`` when the driver is absent or
    the caller is not elevated -- callers treat that as "cannot sign".
    """
    out = client.get_session_key()
    key = bytes(out.Key)
    return key[: out.KeyLength] if out.KeyLength else key


__all__ = [
    "WINDOWS_EPOCH_OFFSET_S",
    "nt_filetime_now",
    "mac_message",
    "compute_signature",
    "fetch_session_key",
]
