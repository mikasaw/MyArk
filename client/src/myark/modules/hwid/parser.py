"""
hwid R3 - parser + R3 fallback.

For S7.3 the R0 IOCTL is a stub (Count=0). R3 fallback synthesises a
report that says "0 drivers enumerated, source=r3-fallback".
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Optional

from myark.client.ark_client import ArkClient, DriverError

from . import protocol as P


@dataclass
class DriverMjTable:
    major_functions: list = None  # list of 28 uint64 addresses
    driver_name: str = ""

    def __post_init__(self):
        if self.major_functions is None:
            self.major_functions = []


@dataclass
class HwidReport:
    count: int = 0
    drivers: list = None  # list of DriverMjTable
    source: str = ""  # "r0" or "r3-fallback"

    def __post_init__(self):
        if self.drivers is None:
            self.drivers = []


def _r3_fallback() -> HwidReport:
    return HwidReport(count=0, drivers=[], source="r3-fallback")


def _send_enumerate(client: Optional[ArkClient]) -> Optional[HwidReport]:
    if client is None:
        return None

    in_size = ctypes.sizeof(P.MYARK_HWID_ENUMERATE_MJ_INPUT)
    in_buf = (ctypes.c_ubyte * in_size)()

    out_size = ctypes.sizeof(P.MYARK_HWID_ENUMERATE_MJ_OUTPUT)
    out_buf = (ctypes.c_ubyte * out_size)()

    try:
        bytes_returned = client.ioctl(
            P.IOCTL_MYARK_HWID_ENUMERATE_MJ, in_buf, out_buf
        )
    except (DriverError, OSError):
        return None
    if bytes_returned < out_size:
        return None

    out = ctypes.cast(out_buf, ctypes.POINTER(P.MYARK_HWID_ENUMERATE_MJ_OUTPUT)).contents
    return HwidReport(count=out.Count, drivers=[], source="r0")


def enumerate_mj(client: Optional[ArkClient]) -> HwidReport:
    r3 = _r3_fallback()
    r0 = _send_enumerate(client)
    return r0 if r0 is not None else r3


def replace_mj(client: Optional[ArkClient], driver_name: str,
               major_function_code: int, new_address: int) -> bool:
    """Mutating IOCTL: reserved for S7.3-fix. Returns False for S7.3."""
    return False


__all__ = ["DriverMjTable", "HwidReport", "enumerate_mj", "replace_mj"]
