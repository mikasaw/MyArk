"""
trust R3 - protocol data structures (ctypes mirrors of MyArkTrustIoctl.h).
"""

from __future__ import annotations

import ctypes

from myark.protocol.core import _ctl_code


IOCTL_MYARK_TRUST_VERIFY_PE = _ctl_code(0x7B0)
IOCTL_MYARK_TRUST_VERIFY_CATALOG = _ctl_code(0x7B1)


TRUST_TRUSTED = 0
TRUST_UNTRUSTED = 1
TRUST_NOT_SIGNED = 2


TRUST_FLAG_CATALOG = 0x00000001
TRUST_FLAG_EMBEDDED = 0x00000002
TRUST_FLAG_TIMESTAMP = 0x00000004


class MYARK_TRUST_VERIFY_INPUT(ctypes.Structure):
    _fields_ = [
        ("FilePath", ctypes.c_wchar * 260),
        ("Flags", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
    ]


class MYARK_TRUST_VERIFY_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Status", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("Subject", ctypes.c_wchar * 128),
        ("Issuer", ctypes.c_wchar * 128),
        ("NotBefore", ctypes.c_uint64),
        ("NotAfter", ctypes.c_uint64),
    ]