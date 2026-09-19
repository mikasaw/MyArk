"""
timerdpc R3 - protocol data structures.

Mirror of shared/driver/MyArkTimerIoctl.h (R3-3, 0x8A4/0x8A5).
"""

from __future__ import annotations

import ctypes

from myark.protocol.core import _ctl_code


IOCTL_MYARK_TIMER_QUERY = _ctl_code(0x8A4)
IOCTL_MYARK_DPC_QUERY = _ctl_code(0x8A5)

TIMERDPC_OWNER_MAX = 48
TIMER_HARD_CAP = 512
DPC_HARD_CAP = 256

TDP_STATUS_OK = 0x0
TDP_STATUS_NO_OFFSETS = 0x1
TDP_STATUS_NO_MODULELIST = 0x2

TIMER_FLAG_EXPIRY = 0x1
TIMER_FLAG_NO_DPC = 0x2
TIMER_FLAG_NTROUTINE = 0x4
TIMER_FLAG_SUSPECT = 0x8

DPC_FLAG_THREADED = 0x1
DPC_FLAG_NTROUTINE = 0x2
DPC_FLAG_SUSPECT = 0x4


class MYARK_TIMER_ENTRY(ctypes.Structure):
    _fields_ = [
        ("Timer", ctypes.c_uint64),
        ("DueTime", ctypes.c_uint64),
        ("Dpc", ctypes.c_uint64),
        ("Routine", ctypes.c_uint64),
        ("Context", ctypes.c_uint64),
        ("Cpu", ctypes.c_uint32),
        ("Period", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Owner", ctypes.c_char * TIMERDPC_OWNER_MAX),
    ]


class MYARK_TIMER_QUERY_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Count", ctypes.c_uint32),
        ("Status", ctypes.c_uint32),
        ("EntryStructSize", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Entries", MYARK_TIMER_ENTRY * 1),
    ]


class MYARK_DPC_ENTRY(ctypes.Structure):
    _fields_ = [
        ("Dpc", ctypes.c_uint64),
        ("Routine", ctypes.c_uint64),
        ("Context", ctypes.c_uint64),
        ("Cpu", ctypes.c_uint32),
        ("QueueType", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Owner", ctypes.c_char * TIMERDPC_OWNER_MAX),
    ]


class MYARK_DPC_QUERY_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Count", ctypes.c_uint32),
        ("Status", ctypes.c_uint32),
        ("EntryStructSize", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Entries", MYARK_DPC_ENTRY * 1),
    ]


assert ctypes.sizeof(MYARK_TIMER_ENTRY) == 104
assert ctypes.sizeof(MYARK_TIMER_QUERY_OUTPUT) == 120
assert ctypes.sizeof(MYARK_DPC_ENTRY) == 88
assert ctypes.sizeof(MYARK_DPC_QUERY_OUTPUT) == 104
