"""
wsl R3 - parser + R3 fallback.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Optional

from myark.client.ark_client import ArkClient, DriverError

from . import protocol as P


@dataclass
class SiloEntry:
    silo_address: int = 0
    silo_id: int = 0
    flags: int = 0
    distro_count: int = 0
    distro_name: str = ""


@dataclass
class WslReport:
    count: int = 0
    silos: list = None
    source: str = ""

    def __post_init__(self):
        if self.silos is None:
            self.silos = []


def _r3_fallback() -> WslReport:
    return WslReport(count=0, silos=[], source="r3-fallback")


def _send_enumerate(client: Optional[ArkClient]) -> Optional[WslReport]:
    if client is None:
        return None

    out_size = ctypes.sizeof(P.MYARK_WSL_SILOS_OUTPUT)
    out_buf = (ctypes.c_ubyte * out_size)()

    try:
        bytes_returned = client.ioctl(
            P.IOCTL_MYARK_WSL_ENUMERATE_SILOS, (ctypes.c_ubyte * 0)(), out_buf
        )
    except (DriverError, OSError):
        return None
    if bytes_returned < out_size:
        return None

    out = ctypes.cast(out_buf, ctypes.POINTER(P.MYARK_WSL_SILOS_OUTPUT)).contents
    return WslReport(count=out.Count, silos=[], source="r0")


def enumerate_silos(client: Optional[ArkClient]) -> WslReport:
    r3 = _r3_fallback()
    r0 = _send_enumerate(client)
    return r0 if r0 is not None else r3


__all__ = ["SiloEntry", "WslReport", "enumerate_silos"]
