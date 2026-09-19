"""
wsl R3 - protocol data structures (ctypes mirrors of MyArkWslIoctl.h).
"""

from __future__ import annotations

import ctypes

from myark.protocol.core import _ctl_code


IOCTL_MYARK_WSL_ENUMERATE_SILOS = _ctl_code(0x780)


WSL_DISTRO_NAME_MAX = 64
WSL_HARD_CAP = 16

WSL_FLAG_ACTIVE = 0x1
WSL_FLAG_DEFAULT = 0x2


class MYARK_WSL_SILO_ENTRY(ctypes.Structure):
    _fields_ = [
        ("SiloAddress", ctypes.c_uint64),
        ("SiloId", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("DistroCount", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("DistroName", ctypes.c_wchar * WSL_DISTRO_NAME_MAX),
    ]


class MYARK_WSL_SILOS_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Count", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Entries", MYARK_WSL_SILO_ENTRY * 1),
    ]
