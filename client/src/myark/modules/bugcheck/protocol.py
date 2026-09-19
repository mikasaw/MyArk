"""
bugcheck R3 - protocol data structures.
"""

from __future__ import annotations

import ctypes

from myark.protocol.core import _ctl_code


IOCTL_MYARK_BUGCHECK_QUERY = _ctl_code(0x760)
IOCTL_MYARK_BUGCHECK_RENDER_DIAG = _ctl_code(0x761)


BUGCHECK_TEXT_MAX = 256


class MYARK_BUGCHECK_RECORD(ctypes.Structure):
    _fields_ = [
        ("BugCheckCode", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Parameter1", ctypes.c_uint64),
        ("Parameter2", ctypes.c_uint64),
        ("Parameter3", ctypes.c_uint64),
        ("Parameter4", ctypes.c_uint64),
        ("Timestamp", ctypes.c_uint64),
    ]


class MYARK_BUGCHECK_QUERY_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("HasRecord", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Record", MYARK_BUGCHECK_RECORD),
    ]


class MYARK_BUGCHECK_RENDER_INPUT(ctypes.Structure):
    _fields_ = [
        ("ForegroundColor", ctypes.c_uint32),
        ("BackgroundColor", ctypes.c_uint32),
        ("X", ctypes.c_uint32),
        ("Y", ctypes.c_uint32),
        ("Text", ctypes.c_wchar * BUGCHECK_TEXT_MAX),
    ]
