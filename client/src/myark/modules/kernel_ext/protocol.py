"""
kernel_ext R3 - protocol data structures (ctypes mirrors of MyArkKernelExtIoctl.h).
"""

from __future__ import annotations

import ctypes

from myark.protocol.core import _ctl_code


IOCTL_MYARK_KERNEL_EXT_QUERY_WIN11_INFO = _ctl_code(0x7F0)
IOCTL_MYARK_KERNEL_EXT_READ_SYSCALL_TABLE = _ctl_code(0x7F1)


KERNEL_EXT_WIN11_INFO_BASE = 0xAD  # Win11 25H2 new info classes start at 0xAD


class MYARK_KERNEL_EXT_QUERY_INPUT(ctypes.Structure):
    _fields_ = [
        ("SystemInformationClass", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint64),
    ]


class MYARK_KERNEL_EXT_QUERY_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Status", ctypes.c_uint32),
        ("BytesReturned", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint64),
        ("Data", ctypes.c_ubyte * 1),
    ]


class MYARK_KERNEL_EXT_SYSCALL_ENTRY(ctypes.Structure):
    _fields_ = [
        ("SyscallIndex", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Address", ctypes.c_uint64),
    ]


class MYARK_KERNEL_EXT_SYSCALL_TABLE_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Count", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Entries", MYARK_KERNEL_EXT_SYSCALL_ENTRY * 1),
    ]
