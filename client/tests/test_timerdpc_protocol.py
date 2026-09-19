"""
timerdpc (R3-3) protocol layout + parser tests.
"""

from __future__ import annotations

import ctypes

from myark.modules.timerdpc import protocol as P


def test_ioctl_codes():
    expected_a4 = ((0x22 << 16) | (0x8A4 << 2) | 0) & 0xFFFFFFFF
    expected_a5 = ((0x22 << 16) | (0x8A5 << 2) | 0) & 0xFFFFFFFF
    assert P.IOCTL_MYARK_TIMER_QUERY == expected_a4
    assert P.IOCTL_MYARK_DPC_QUERY == expected_a5


def test_struct_layouts():
    # Mirror of the C_ASSERTs in MyArkTimerIoctl.h.
    assert ctypes.sizeof(P.MYARK_TIMER_ENTRY) == 104
    assert ctypes.sizeof(P.MYARK_TIMER_QUERY_OUTPUT) == 120
    assert ctypes.sizeof(P.MYARK_DPC_ENTRY) == 88
    assert ctypes.sizeof(P.MYARK_DPC_QUERY_OUTPUT) == 104


def _fake_client(payload: bytes):
    class _Fake:
        def ioctl(self, _code, _in_buf, out_buf):
            n = min(len(payload), len(out_buf))
            out_buf[:n] = payload[:n]
            return n

    return _Fake()


def test_query_timers_parses_rows():
    from myark.modules.timerdpc import parser as W
    entry = P.MYARK_TIMER_ENTRY()
    entry.Timer = 0xFFFF8A897D6FDD70
    entry.DueTime = 0x800000001001003C
    entry.Routine = 0xFFFFF80684F428E0
    entry.Cpu = 2
    entry.Period = 1000
    entry.Flags = P.TIMER_FLAG_SUSPECT
    entry.Owner = b"evilroot.sys"
    head = P.MYARK_TIMER_QUERY_OUTPUT()
    head.Count = 1
    head.Status = P.TDP_STATUS_OK
    head.EntryStructSize = 104
    head.Entries[0] = entry
    raw = bytes(head) + bytes(entry)
    report = W.query_timers(_fake_client(raw))
    assert report.status == P.TDP_STATUS_OK
    assert report.count == 1
    assert report.timers[0].owner == "evilroot.sys"
    assert report.timers[0].suspect
    assert report.timers[0].period == 1000


def test_query_dpcs_empty_queue_is_ok():
    from myark.modules.timerdpc import parser as W
    head = P.MYARK_DPC_QUERY_OUTPUT()
    head.Count = 0
    head.Status = P.TDP_STATUS_OK
    head.EntryStructSize = 88
    raw = bytes(head)
    report = W.query_dpcs(_fake_client(raw))
    assert report.count == 0 and report.status == P.TDP_STATUS_OK


def test_error_paths_return_unsupported():
    from myark.modules.timerdpc import parser as W

    class _Boom:
        def ioctl(self, *_a):
            raise OSError("driver offline")

    assert W.query_timers(_Boom()).status == P.TDP_STATUS_NO_OFFSETS
    assert W.query_dpcs(_Boom()).status == P.TDP_STATUS_NO_OFFSETS
    assert W.query_timers(None).count == 0
    assert W.query_dpcs(None).count == 0
