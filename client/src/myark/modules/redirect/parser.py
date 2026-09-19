"""
redirect R3 - parser + R3 fallback.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Optional

from myark.client.ark_client import ArkClient, DriverError

from . import protocol as P


@dataclass
class RedirectEntry:
    original_address: int = 0
    redirect_address: int = 0
    redirect_type: int = 0
    driver_name: str = ""


@dataclass
class RedirectReport:
    count: int = 0
    entries: list = None
    source: str = ""

    def __post_init__(self):
        if self.entries is None:
            self.entries = []


def _r3_fallback() -> RedirectReport:
    return RedirectReport(count=0, entries=[], source="r3-fallback")


def _send_inspect(client: Optional[ArkClient]) -> Optional[RedirectReport]:
    if client is None:
        return None
    out_size = ctypes.sizeof(P.MYARK_REDIRECT_INSPECT_OUTPUT)
    out_buf = (ctypes.c_ubyte * out_size)()
    try:
        bytes_returned = client.ioctl(
            P.IOCTL_MYARK_REDIRECT_INSPECT, (ctypes.c_ubyte * 0)(), out_buf
        )
    except (DriverError, OSError):
        return None
    if bytes_returned < out_size:
        return None
    out = ctypes.cast(out_buf, ctypes.POINTER(P.MYARK_REDIRECT_INSPECT_OUTPUT)).contents
    return RedirectReport(count=out.Count, entries=[], source="r0")


def inspect_redirects(client: Optional[ArkClient]) -> RedirectReport:
    r3 = _r3_fallback()
    r0 = _send_inspect(client)
    return r0 if r0 is not None else r3


def apply_redirect(client: Optional[ArkClient], original: int,
                   target: int, redirect_type: int) -> bool:
    """Mutating IOCTL: reserved for S7.3-fix. Returns False for S7.3."""
    return False


__all__ = [
    "RedirectEntry", "RedirectReport",
    "inspect_redirects", "apply_redirect",
]
