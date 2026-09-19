"""
win32k protocol ctypes layout tests.
"""

from __future__ import annotations

import ctypes

import pytest

from myark.modules.win32k import protocol as P


def test_ioctl_codes_match_kt():
    raw_t = 0x770
    raw_h = 0x771
    expected_t = ((0x22 << 16) | (raw_t << 2) | 0) & 0xFFFFFFFF
    expected_h = ((0x22 << 16) | (raw_h << 2) | 0) & 0xFFFFFFFF
    assert P.IOCTL_MYARK_WIN32K_ENUMERATE_GUI_THREADS == expected_t
    assert P.IOCTL_MYARK_WIN32K_ENUMERATE_HOOKS == expected_h


def test_constants():
    assert P.WIN32K_THREAD_NAME_MAX == 64
    assert P.WIN32K_HARD_CAP == 64


def test_flag_constants():
    assert P.WIN32K_FLAG_HAS_WINDOW == 0x1
    assert P.WIN32K_FLAG_HAS_MONITOR == 0x2


def test_gui_thread_entry_layout():
    e_size = ctypes.sizeof(P.MYARK_WIN32K_GUI_THREAD_ENTRY)
    # 4 + 4 + 8 + 8 + 4 + 4 + 64*2 = 160
    assert e_size == 160


def test_gui_threads_output_layout():
    out_size = ctypes.sizeof(P.MYARK_WIN32K_GUI_THREADS_OUTPUT)
    # 4 + 4 + 1 entry of 160 = 168
    assert out_size == 168


def test_hook_entry_layout():
    e_size = ctypes.sizeof(P.MYARK_WIN32K_HOOK_ENTRY)
    # 4 + 4 + 8 + 8 + 64*2 = 152
    assert e_size == 152


def test_hooks_output_layout():
    out_size = ctypes.sizeof(P.MYARK_WIN32K_HOOKS_OUTPUT)
    # 4 + 4 + 1 entry of 152 = 160
    assert out_size == 160


def test_struct_can_be_instantiated():
    e = P.MYARK_WIN32K_GUI_THREAD_ENTRY()
    e.ThreadId = 1234
    e.ProcessId = 5678
    e.Flags = P.WIN32K_FLAG_HAS_WINDOW
    e.ThreadName = "explorer.exe"
    assert e.ThreadId == 1234
    assert e.Flags == 0x1


def test_hook_can_be_instantiated():
    h = P.MYARK_WIN32K_HOOK_ENTRY()
    h.SyscallIndex = 0x1000
    h.Flags = 0x1
    h.OriginalAddress = 0xFFFFF80000001000
    h.CurrentAddress = 0xFFFFF80012345000
    h.ModuleName = "evil.dll"
    assert h.SyscallIndex == 0x1000
    assert h.ModuleName == "evil.dll"
