"""
hwid R3 - protocol data structures (ctypes mirrors of MyArkHwidIoctl.h).
"""

from __future__ import annotations

import ctypes

from myark.protocol.core import _ctl_code


IOCTL_MYARK_HWID_ENUMERATE_MJ = _ctl_code(0x750)
IOCTL_MYARK_HWID_REPLACE_MJ = _ctl_code(0x751)


HWID_NAME_MAX = 64
HWID_MJ_COUNT = 28  # IRP_MJ_MAX + 1
HWID_HARD_CAP = 64


class MYARK_HWID_ENUMERATE_MJ_INPUT(ctypes.Structure):
    _fields_ = [
        ("DriverIndexHint", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint64),
    ]


class MYARK_HWID_MJ_ENTRY(ctypes.Structure):
    _fields_ = [
        ("DriverName", ctypes.c_wchar * HWID_NAME_MAX),
        ("MajorFunction", ctypes.c_uint64 * HWID_MJ_COUNT),
    ]


class MYARK_HWID_ENUMERATE_MJ_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Count", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Entries", MYARK_HWID_MJ_ENTRY * 1),
    ]


class MYARK_HWID_REPLACE_MJ_INPUT(ctypes.Structure):
    _fields_ = [
        ("DriverName", ctypes.c_wchar * HWID_NAME_MAX),
        ("MajorFunctionCode", ctypes.c_uint32),
        ("NewAddress", ctypes.c_uint64),
    ]
