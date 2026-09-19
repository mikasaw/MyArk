"""
trust R3 - parser + R3 fallback (WinVerifyTrust is the primary path).
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Optional

from myark.client.ark_client import ArkClient, DriverError

from . import protocol as P


@dataclass
class VerifyResult:
    status: int = 0
    status_name: str = ""
    flags: int = 0
    subject: str = ""
    issuer: str = ""
    source: str = ""  # "r0" or "r3-fallback"


def _status_name(status: int) -> str:
    return {
        P.TRUST_TRUSTED: "trusted",
        P.TRUST_UNTRUSTED: "untrusted",
        P.TRUST_NOT_SIGNED: "not_signed",
    }.get(status, "unknown")


def _r3_fallback(file_path: str) -> VerifyResult:
    """R3 fallback: report not-signed. The full WinVerifyTrust integration is S7.3-fix."""
    return VerifyResult(
        status=P.TRUST_NOT_SIGNED,
        status_name="not_signed",
        flags=0,
        subject="",
        issuer="",
        source="r3-fallback",
    )


def _send_verify(client: Optional[ArkClient],
                 ioctl_code: int,
                 file_path: str,
                 flags: int) -> Optional[VerifyResult]:
    if client is None:
        return None

    in_size = ctypes.sizeof(P.MYARK_TRUST_VERIFY_INPUT)
    in_buf = (ctypes.c_ubyte * in_size)()
    in_struct = ctypes.cast(in_buf, ctypes.POINTER(P.MYARK_TRUST_VERIFY_INPUT)).contents
    path_bytes = file_path[: P.MYARK_TRUST_VERIFY_INPUT.FilePath.size - 1]
    for i, ch in enumerate(path_bytes):
        in_struct.FilePath[i] = ch
    in_struct.Flags = flags

    out_size = ctypes.sizeof(P.MYARK_TRUST_VERIFY_OUTPUT)
    out_buf = (ctypes.c_ubyte * out_size)()

    try:
        bytes_returned = client.ioctl(ioctl_code, in_buf, out_buf)
    except (DriverError, OSError):
        return None
    if bytes_returned < out_size:
        return None

    out = ctypes.cast(out_buf, ctypes.POINTER(P.MYARK_TRUST_VERIFY_OUTPUT)).contents
    return VerifyResult(
        status=out.Status,
        status_name=_status_name(out.Status),
        flags=out.Flags,
        subject=out.Subject,
        issuer=out.Issuer,
        source="r0",
    )


def verify_pe(client: Optional[ArkClient], file_path: str, flags: int = 0) -> VerifyResult:
    r3 = _r3_fallback(file_path)
    r0 = _send_verify(client, P.IOCTL_MYARK_TRUST_VERIFY_PE, file_path, flags)
    return r0 if r0 is not None else r3


def verify_catalog(client: Optional[ArkClient], file_path: str, flags: int = 0) -> VerifyResult:
    r3 = _r3_fallback(file_path)
    r0 = _send_verify(client, P.IOCTL_MYARK_TRUST_VERIFY_CATALOG, file_path, flags)
    return r0 if r0 is not None else r3


__all__ = [
    "VerifyResult",
    "verify_pe",
    "verify_catalog",
]