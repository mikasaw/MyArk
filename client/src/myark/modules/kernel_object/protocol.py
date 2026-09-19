"""
kernel_object R3 - protocol data structures (ctypes mirrors of
MyArkKernelObjectIoctl.h).
"""

from __future__ import annotations

import ctypes

from myark.protocol.core import _ctl_code


IOCTL_MYARK_KOBJ_ENUM_DIRECTORY = _ctl_code(0x910)
IOCTL_MYARK_KOBJ_IPC_SUMMARY = _ctl_code(0x911)

KOBJ_NAME_MAX = 64
KOBJ_TYPE_MAX = 32
KOBJ_DIR_CAP = 256
KOBJ_PIPE_CAP = 256
KOBJ_MAILSLOT_CAP = 64
KOBJ_PATH_MAX = 96

KOBJ_DIR_FLAG_TRUNCATED = 0x1
KOBJ_IPC_PIPE_TRUNCATED = 0x1
KOBJ_IPC_MAILSLOT_TRUNCATED = 0x1


class MYARK_KOBJ_ENTRY(ctypes.Structure):
    _fields_ = [
        ("Name", ctypes.c_wchar * KOBJ_NAME_MAX),
        ("TypeName", ctypes.c_wchar * KOBJ_TYPE_MAX),
    ]


class MYARK_KOBJ_DIRECTORY_INPUT(ctypes.Structure):
    _fields_ = [
        ("PathLength", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("DirectoryPath", ctypes.c_wchar * KOBJ_PATH_MAX),
    ]


class MYARK_KOBJ_DIRECTORY_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Count", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("OpenStatus", ctypes.c_uint32),
        ("WalkStatus", ctypes.c_uint32),
        ("Entries", MYARK_KOBJ_ENTRY * KOBJ_DIR_CAP),
    ]


class MYARK_KOBJ_IPC_SUMMARY_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("PipeCount", ctypes.c_uint32),
        ("PipeFlags", ctypes.c_uint32),
        ("PipeOpenStatus", ctypes.c_uint32),
        ("MailslotCount", ctypes.c_uint32),
        ("MailslotFlags", ctypes.c_uint32),
        ("MailslotOpenStatus", ctypes.c_uint32),
        ("PipeWalkStatus", ctypes.c_uint32),
        ("MailslotWalkStatus", ctypes.c_uint32),
        ("Pipes", MYARK_KOBJ_ENTRY * KOBJ_PIPE_CAP),
        ("Mailslots", MYARK_KOBJ_ENTRY * KOBJ_MAILSLOT_CAP),
    ]
