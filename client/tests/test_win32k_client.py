"""
win32k client (parser) tests.
"""

from __future__ import annotations

from myark.modules.win32k import parser as P
from myark.modules.win32k import protocol as PP


def test_gui_threads_report_defaults():
    r = P.GuiThreadsReport()
    assert r.count == 0
    assert r.threads == []
    assert r.source == ""


def test_hooks_report_defaults():
    r = P.HooksReport()
    assert r.count == 0
    assert r.hooks == []
    assert r.source == ""


def test_gui_thread_defaults():
    t = P.GuiThread()
    assert t.thread_id == 0
    assert t.process_id == 0
    assert t.flags == 0
    assert t.thread_name == ""


def test_hook_entry_defaults():
    h = P.HookEntry()
    assert h.syscall_index == 0
    assert h.flags == 0
    assert h.module_name == ""


def test_enumerate_gui_threads_r3_fallback_when_no_driver():
    r = P.enumerate_gui_threads(None)
    assert r.source == "r3-fallback"
    assert r.count == 0


def test_enumerate_hooks_r3_fallback_when_no_driver():
    r = P.enumerate_hooks(None)
    assert r.source == "r3-fallback"
    assert r.count == 0


def test_gui_thread_can_be_constructed():
    t = P.GuiThread(
        thread_id=1234,
        process_id=5678,
        flags=PP.WIN32K_FLAG_HAS_WINDOW,
        thread_name="explorer.exe",
    )
    assert t.thread_id == 1234
    assert t.flags == 0x1


def test_hook_entry_can_be_constructed():
    h = P.HookEntry(
        syscall_index=0x1000,
        flags=0x1,
        original_address=0xFFFFF80000001000,
        current_address=0xFFFFF80012345000,
        module_name="evil.dll",
    )
    assert h.module_name == "evil.dll"
    assert h.flags == 0x1
