"""
win32k R3 - protocol data structures (ctypes mirrors of MyArkWin32kIoctl.h).
"""

from __future__ import annotations

import ctypes

from myark.protocol.core import _ctl_code


IOCTL_MYARK_WIN32K_ENUMERATE_GUI_THREADS = _ctl_code(0x770)
IOCTL_MYARK_WIN32K_ENUMERATE_HOOKS = _ctl_code(0x771)


WIN32K_THREAD_NAME_MAX = 64
WIN32K_HARD_CAP = 64

WIN32K_FLAG_HAS_WINDOW = 0x1
WIN32K_FLAG_HAS_MONITOR = 0x2


class MYARK_WIN32K_GUI_THREAD_ENTRY(ctypes.Structure):
    _fields_ = [
        ("ThreadId", ctypes.c_uint32),
        ("ProcessId", ctypes.c_uint32),
        ("ThreadAddress", ctypes.c_uint64),
        ("MessageQueueAddress", ctypes.c_uint64),
        ("Flags", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("ThreadName", ctypes.c_wchar * WIN32K_THREAD_NAME_MAX),
    ]


class MYARK_WIN32K_GUI_THREADS_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Count", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Entries", MYARK_WIN32K_GUI_THREAD_ENTRY * 1),
    ]


class MYARK_WIN32K_HOOK_ENTRY(ctypes.Structure):
    _fields_ = [
        ("SyscallIndex", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("OriginalAddress", ctypes.c_uint64),
        ("CurrentAddress", ctypes.c_uint64),
        ("ModuleName", ctypes.c_wchar * WIN32K_THREAD_NAME_MAX),
    ]


class MYARK_WIN32K_HOOKS_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Count", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Entries", MYARK_WIN32K_HOOK_ENTRY * 1),
    ]
