"""
authentication R3 - protocol data structures.
"""

from __future__ import annotations

import ctypes

from myark.protocol.core import _ctl_code


IOCTL_MYARK_AUTHENTICATION_VERIFY_FILE = _ctl_code(0x7A0)


AUTHENTICATION_PATH_MAX = 260
AUTHENTICATION_SUBJECT_MAX = 128
AUTHENTICATION_ISSUER_MAX = 128

AUTHENTICATION_TRUSTED = 0
AUTHENTICATION_UNTRUSTED = 1
AUTHENTICATION_NOT_SIGNED = 2

AUTHENTICATION_FLAG_CATALOG = 0x1
AUTHENTICATION_FLAG_EMBEDDED = 0x2


class MYARK_AUTHENTICATION_VERIFY_INPUT(ctypes.Structure):
    _fields_ = [
        ("FilePath", ctypes.c_wchar * AUTHENTICATION_PATH_MAX),
    ]


class MYARK_AUTHENTICATION_VERIFY_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Status", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("Subject", ctypes.c_wchar * AUTHENTICATION_SUBJECT_MAX),
        ("Issuer", ctypes.c_wchar * AUTHENTICATION_ISSUER_MAX),
        ("NotBefore", ctypes.c_uint64),
        ("NotAfter", ctypes.c_uint64),
    ]
