"""
mutation R3 - protocol data structures.
"""

from __future__ import annotations

import ctypes

from myark.protocol.core import _ctl_code


IOCTL_MYARK_MUTATION_INSPECT_TOKEN = _ctl_code(0x730)
IOCTL_MYARK_MUTATION_SET_TOKEN = _ctl_code(0x731)


MUTATION_TOKEN_FLAG_VALID = 0x1
MUTATION_TOKEN_FLAG_ADMIN = 0x2
MUTATION_TOKEN_FLAG_SYSTEM = 0x4


class MYARK_MUTATION_INSPECT_TOKEN_INPUT(ctypes.Structure):
    _fields_ = [
        ("ProcessId", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint64),
    ]


class MYARK_MUTATION_INSPECT_TOKEN_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("TokenFlags", ctypes.c_uint32),
        ("IntegrityLevel", ctypes.c_uint32),
        ("IsElevated", ctypes.c_uint32),
        ("IsUacRestricted", ctypes.c_uint32),
        ("TokenAddress", ctypes.c_uint64),
        ("Reserved", ctypes.c_uint64),
    ]


class MYARK_MUTATION_SET_TOKEN_INPUT(ctypes.Structure):
    _fields_ = [
        ("ProcessId", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("TokenHandle", ctypes.c_uint64),
        ("Reserved2", ctypes.c_uint64),
    ]
