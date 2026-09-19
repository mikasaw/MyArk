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


# --- R3-10a: USER handle table (user32!gSharedInfo.aheList) -----------------

IOCTL_MYARK_WIN32K_ENUM_USER_HANDLES = _ctl_code(0x772)

WIN32K_HANDLE_CAP = 2048

# Classic win32k TYPE_* user-object ids.
WIN32K_TYPE_FREE = 0
WIN32K_TYPE_WINDOW = 1
WIN32K_TYPE_MENU = 2
WIN32K_TYPE_ICON = 3
WIN32K_TYPE_SETWINDOWPOS = 4
WIN32K_TYPE_HOOK = 5
WIN32K_TYPE_CLIPDATA = 6
WIN32K_TYPE_CALLPROC = 7
WIN32K_TYPE_ACCELTABLE = 8
WIN32K_TYPE_DDEACCESS = 9
WIN32K_TYPE_DDECONV = 10
WIN32K_TYPE_DDERTACK = 11
WIN32K_TYPE_MONITOR = 12
WIN32K_TYPE_KBDLAYOUT = 13

WIN32K_TYPE_NAMES = {
    0: "Free", 1: "Window", 2: "Menu", 3: "Icon", 4: "SetWindowPos",
    5: "Hook", 6: "ClipData", 7: "CallProc", 8: "AccelTable",
    9: "DdeAccess", 10: "DdeConv", 11: "DdeRTrack", 12: "Monitor",
    13: "KbdLayout", 14: "KbdFile", 16: "DdeTheip", 17: "Desk",
}


class MYARK_WIN32K_USER_HANDLE_ENTRY(ctypes.Structure):
    _fields_ = [
        ("Index", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("KernelObject", ctypes.c_uint64),
        ("UserPointer", ctypes.c_uint64),
    ]


class MYARK_WIN32K_USER_HANDLES_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Count", ctypes.c_uint32),
        ("DiagStatus", ctypes.c_uint32),
        ("SharedInfo", ctypes.c_uint64),
        ("AheList", ctypes.c_uint64),
        ("HeEntrySize", ctypes.c_uint32),
        ("ScannedSlots", ctypes.c_uint32),
        ("Truncated", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Win32kBase", ctypes.c_uint64),
        ("KernelAheList", ctypes.c_uint64),
        ("KernelPsi", ctypes.c_uint64),
        ("PsiMatch", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint32),
        ("Entries", MYARK_WIN32K_USER_HANDLE_ENTRY * WIN32K_HANDLE_CAP),
    ]


# --- R3-10b-iii: session timers (win32kbase!gTimerHashTable) ----------------

IOCTL_MYARK_WIN32K_ENUM_TIMERS = _ctl_code(0x773)

WIN32K_TIMER_CAP = 256


class MYARK_WIN32K_TIMER_ENTRY(ctypes.Structure):
    _fields_ = [
        ("Index", ctypes.c_uint32),
        ("TimerId", ctypes.c_uint32),
        ("ElapseMs", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("Pti", ctypes.c_uint64),
        ("TimerProc", ctypes.c_uint64),
        ("Window", ctypes.c_uint64),
        ("Node", ctypes.c_uint64),
    ]


class MYARK_WIN32K_TIMERS_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Count", ctypes.c_uint32),
        ("DiagStatus", ctypes.c_uint32),
        ("TimerHashTable", ctypes.c_uint64),
        ("SessionBase", ctypes.c_uint64),
        ("BucketCount", ctypes.c_uint32),
        ("NodeSize", ctypes.c_uint32),
        ("ScannedBuckets", ctypes.c_uint32),
        ("Truncated", ctypes.c_uint32),
        ("TimerHashRva", ctypes.c_uint64),
        ("Reserved2", ctypes.c_uint32),
        ("Reserved3", ctypes.c_uint32),
        ("Reserved4", ctypes.c_uint64),
        ("Entries", MYARK_WIN32K_TIMER_ENTRY * WIN32K_TIMER_CAP),
    ]
