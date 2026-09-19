"""
alpc R3 - protocol data structures (ctypes mirrors of MyArkAlpcIoctl.h).
"""

from __future__ import annotations

import ctypes

from myark.protocol.core import _ctl_code


IOCTL_MYARK_ALPC_ENUMERATE_PORTS = _ctl_code(0x790)
IOCTL_MYARK_ALPC_CLOSE_PORT = _ctl_code(0x791)


ALPC_NAME_MAX = 64
ALPC_HARD_CAP = 128

ALPC_FLAG_CONNECTED = 0x1
ALPC_FLAG_SERVER = 0x2


class MYARK_ALPC_PORT_ENTRY(ctypes.Structure):
    _fields_ = [
        ("PortAddress", ctypes.c_uint64),
        ("PortId", ctypes.c_uint32),
        ("OwnerProcessId", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("PortName", ctypes.c_wchar * ALPC_NAME_MAX),
    ]


class MYARK_ALPC_PORTS_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Count", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Entries", MYARK_ALPC_PORT_ENTRY * 1),
    ]


class MYARK_ALPC_CLOSE_INPUT(ctypes.Structure):
    _fields_ = [
        ("PortId", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint64),
    ]
