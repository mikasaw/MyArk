"""
redirect R3 - protocol data structures.
"""

from __future__ import annotations

import ctypes

from myark.protocol.core import _ctl_code


IOCTL_MYARK_REDIRECT_INSPECT = _ctl_code(0x740)
IOCTL_MYARK_REDIRECT_APPLY = _ctl_code(0x741)


REDIRECT_NAME_MAX = 64
REDIRECT_HARD_CAP = 64

REDIRECT_TYPE_NONE = 0
REDIRECT_TYPE_IRP = 1
REDIRECT_TYPE_CM = 2
REDIRECT_TYPE_OB = 3


class MYARK_REDIRECT_INSPECT_INPUT(ctypes.Structure):
    _fields_ = [
        ("TargetPid", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint64),
    ]


class MYARK_REDIRECT_ENTRY(ctypes.Structure):
    _fields_ = [
        ("OriginalAddress", ctypes.c_uint64),
        ("RedirectAddress", ctypes.c_uint64),
        ("RedirectType", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("DriverName", ctypes.c_wchar * REDIRECT_NAME_MAX),
    ]


class MYARK_REDIRECT_INSPECT_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Count", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Entries", MYARK_REDIRECT_ENTRY * 1),
    ]


class MYARK_REDIRECT_APPLY_INPUT(ctypes.Structure):
    _fields_ = [
        ("OriginalAddress", ctypes.c_uint64),
        ("RedirectAddress", ctypes.c_uint64),
        ("RedirectType", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
    ]
