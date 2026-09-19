"""
bugcheck R3 - parser + R3 fallback.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Optional

from myark.client.ark_client import ArkClient, DriverError

from . import protocol as P


@dataclass
class BugcheckRecord:
    bug_check_code: int = 0
    parameter1: int = 0
    parameter2: int = 0
    parameter3: int = 0
    parameter4: int = 0
    timestamp: int = 0


@dataclass
class BugcheckQueryReport:
    has_record: bool = False
    record: BugcheckRecord = None
    source: str = ""

    def __post_init__(self):
        if self.record is None:
            self.record = BugcheckRecord()


def _r3_fallback_query() -> BugcheckQueryReport:
    return BugcheckQueryReport(has_record=False, record=BugcheckRecord(), source="r3-fallback")


def _send_query(client: Optional[ArkClient]) -> Optional[BugcheckQueryReport]:
    if client is None:
        return None
    out_size = ctypes.sizeof(P.MYARK_BUGCHECK_QUERY_OUTPUT)
    out_buf = (ctypes.c_ubyte * out_size)()
    try:
        bytes_returned = client.ioctl(
            P.IOCTL_MYARK_BUGCHECK_QUERY, (ctypes.c_ubyte * 0)(), out_buf
        )
    except (DriverError, OSError):
        return None
    if bytes_returned < out_size:
        return None
    out = ctypes.cast(out_buf, ctypes.POINTER(P.MYARK_BUGCHECK_QUERY_OUTPUT)).contents
    rec = BugcheckRecord(
        bug_check_code=out.Record.BugCheckCode,
        parameter1=out.Record.Parameter1,
        parameter2=out.Record.Parameter2,
        parameter3=out.Record.Parameter3,
        parameter4=out.Record.Parameter4,
        timestamp=out.Record.Timestamp,
    )
    return BugcheckQueryReport(
        has_record=(out.HasRecord != 0),
        record=rec,
        source="r0",
    )


def query_last_bugcheck(client: Optional[ArkClient]) -> BugcheckQueryReport:
    r3 = _r3_fallback_query()
    r0 = _send_query(client)
    return r0 if r0 is not None else r3


def render_diagnostic(client: Optional[ArkClient], text: str,
                      x: int = 0, y: int = 0,
                      fg: int = 0xFFFFFF, bg: int = 0x000000) -> bool:
    """Stub for S7.3; always returns False."""
    return False


__all__ = [
    "BugcheckRecord",
    "BugcheckQueryReport",
    "query_last_bugcheck",
    "render_diagnostic",
]
