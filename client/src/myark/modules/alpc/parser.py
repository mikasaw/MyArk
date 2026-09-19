"""
alpc R3 - parser + R3 fallback.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Optional

from myark.client.ark_client import ArkClient, DriverError

from . import protocol as P


@dataclass
class PortEntry:
    port_address: int = 0
    port_id: int = 0
    owner_process_id: int = 0
    flags: int = 0
    port_name: str = ""


@dataclass
class AlpcReport:
    count: int = 0
    ports: list = None  # list of PortEntry
    source: str = ""

    def __post_init__(self):
        if self.ports is None:
            self.ports = []


def _r3_fallback() -> AlpcReport:
    return AlpcReport(count=0, ports=[], source="r3-fallback")


def _send_enumerate(client: Optional[ArkClient]) -> Optional[AlpcReport]:
    if client is None:
        return None

    out_size = ctypes.sizeof(P.MYARK_ALPC_PORTS_OUTPUT)
    out_buf = (ctypes.c_ubyte * out_size)()

    try:
        bytes_returned = client.ioctl(
            P.IOCTL_MYARK_ALPC_ENUMERATE_PORTS, (ctypes.c_ubyte * 0)(), out_buf
        )
    except (DriverError, OSError):
        return None
    if bytes_returned < out_size:
        return None

    out = ctypes.cast(out_buf, ctypes.POINTER(P.MYARK_ALPC_PORTS_OUTPUT)).contents
    return AlpcReport(count=out.Count, ports=[], source="r0")


def enumerate_ports(client: Optional[ArkClient]) -> AlpcReport:
    r3 = _r3_fallback()
    r0 = _send_enumerate(client)
    return r0 if r0 is not None else r3


def close_port(client: Optional[ArkClient], port_id: int) -> bool:
    """Mutating IOCTL: reserved for S7.3-fix. Returns False for S7.3."""
    return False


__all__ = ["PortEntry", "AlpcReport", "enumerate_ports", "close_port"]
