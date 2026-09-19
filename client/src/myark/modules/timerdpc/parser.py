"""
timerdpc R3 - parser: per-CPU timer table / DPC queue snapshots.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass, field
from typing import Optional

from myark.client.ark_client import ArkClient, DriverError

from . import protocol as P


@dataclass
class TimerEntry:
    timer: int = 0
    due_time: int = 0
    dpc: int = 0
    routine: int = 0
    context: int = 0
    cpu: int = 0
    period: int = 0
    flags: int = 0
    owner: str = ""

    @property
    def suspect(self) -> bool:
        return bool(self.flags & P.TIMER_FLAG_SUSPECT)

    @property
    def nt_routine(self) -> bool:
        return bool(self.flags & P.TIMER_FLAG_NTROUTINE)


@dataclass
class TimerReport:
    count: int = 0
    status: int = P.TDP_STATUS_NO_OFFSETS
    timers: list = None

    def __post_init__(self):
        if self.timers is None:
            self.timers = []


@dataclass
class DpcEntry:
    dpc: int = 0
    routine: int = 0
    context: int = 0
    cpu: int = 0
    queue_type: int = 0
    flags: int = 0
    owner: str = ""


@dataclass
class DpcReport:
    count: int = 0
    status: int = P.TDP_STATUS_NO_OFFSETS
    dpcs: list = None

    def __post_init__(self):
        if self.dpcs is None:
            self.dpcs = []


def _decode(buf) -> str:
    return bytes(buf).split(b"\x00")[0].decode("utf-8", "replace")


def _entry_size_ok(actual: int, expected: int) -> bool:
    # Forward-compat guard: never interpret rows with a foreign stride.
    return actual == expected


def _fetch(client: Optional[ArkClient], code: int, out_size: int):
    if client is None:
        return None
    out_buf = (ctypes.c_ubyte * out_size)()
    try:
        bytes_returned = client.ioctl(code, (ctypes.c_ubyte * 0)(), out_buf)
    except (DriverError, OSError):
        return None
    if bytes_returned < 16:
        return None
    return out_buf, bytes_returned


def query_timers(client: Optional[ArkClient]) -> TimerReport:
    """0x8A4: every pending kernel timer, per CPU, Dpc decoded."""
    entry = ctypes.sizeof(P.MYARK_TIMER_ENTRY)
    out_size = ctypes.sizeof(P.MYARK_TIMER_QUERY_OUTPUT) \
        + (P.TIMER_HARD_CAP - 1) * entry
    got = _fetch(client, P.IOCTL_MYARK_TIMER_QUERY, out_size)
    if got is None:
        return TimerReport()
    out_buf, _returned = got
    out = ctypes.cast(out_buf,
                      ctypes.POINTER(P.MYARK_TIMER_QUERY_OUTPUT)).contents
    if not _entry_size_ok(out.EntryStructSize, entry):
        return TimerReport(status=out.Status)
    report = TimerReport(count=out.Count, status=out.Status)
    for i in range(min(out.Count, P.TIMER_HARD_CAP)):
        row = ctypes.cast(
            ctypes.addressof(out.Entries[0]) + i * entry,
            ctypes.POINTER(P.MYARK_TIMER_ENTRY),
        ).contents
        report.timers.append(TimerEntry(
            timer=row.Timer, due_time=row.DueTime, dpc=row.Dpc,
            routine=row.Routine, context=row.Context, cpu=row.Cpu,
            period=row.Period, flags=row.Flags, owner=_decode(row.Owner),
        ))
    return report


def query_dpcs(client: Optional[ArkClient]) -> DpcReport:
    """0x8A5: per-CPU DPC queue snapshot (transient; may be empty)."""
    entry = ctypes.sizeof(P.MYARK_DPC_ENTRY)
    out_size = ctypes.sizeof(P.MYARK_DPC_QUERY_OUTPUT) \
        + (P.DPC_HARD_CAP - 1) * entry
    got = _fetch(client, P.IOCTL_MYARK_DPC_QUERY, out_size)
    if got is None:
        return DpcReport()
    out_buf, _returned = got
    out = ctypes.cast(out_buf,
                      ctypes.POINTER(P.MYARK_DPC_QUERY_OUTPUT)).contents
    if not _entry_size_ok(out.EntryStructSize, entry):
        return DpcReport(status=out.Status)
    report = DpcReport(count=out.Count, status=out.Status)
    for i in range(min(out.Count, P.DPC_HARD_CAP)):
        row = ctypes.cast(
            ctypes.addressof(out.Entries[0]) + i * entry,
            ctypes.POINTER(P.MYARK_DPC_ENTRY),
        ).contents
        report.dpcs.append(DpcEntry(
            dpc=row.Dpc, routine=row.Routine, context=row.Context,
            cpu=row.Cpu, queue_type=row.QueueType, flags=row.Flags,
            owner=_decode(row.Owner),
        ))
    return report


__all__ = [
    "TimerEntry", "TimerReport", "DpcEntry", "DpcReport",
    "query_timers", "query_dpcs",
]
