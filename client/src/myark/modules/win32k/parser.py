"""
win32k R3 - parser + R3 fallback.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Optional

from myark.client.ark_client import ArkClient, DriverError

from . import protocol as P


@dataclass
class GuiThread:
    thread_id: int = 0
    process_id: int = 0
    flags: int = 0
    thread_name: str = ""


@dataclass
class GuiThreadsReport:
    count: int = 0
    threads: list = None
    source: str = ""

    def __post_init__(self):
        if self.threads is None:
            self.threads = []


@dataclass
class HookEntry:
    syscall_index: int = 0
    flags: int = 0
    original_address: int = 0
    current_address: int = 0
    module_name: str = ""


@dataclass
class HooksReport:
    count: int = 0
    hooks: list = None
    source: str = ""

    def __post_init__(self):
        if self.hooks is None:
            self.hooks = []


def _r3_fallback_threads() -> GuiThreadsReport:
    return GuiThreadsReport(count=0, threads=[], source="r3-fallback")


def _r3_fallback_hooks() -> HooksReport:
    return HooksReport(count=0, hooks=[], source="r3-fallback")


def _send_threads(client: Optional[ArkClient]) -> Optional[GuiThreadsReport]:
    if client is None:
        return None
    out_size = ctypes.sizeof(P.MYARK_WIN32K_GUI_THREADS_OUTPUT)
    out_buf = (ctypes.c_ubyte * out_size)()
    try:
        bytes_returned = client.ioctl(
            P.IOCTL_MYARK_WIN32K_ENUMERATE_GUI_THREADS, (ctypes.c_ubyte * 0)(), out_buf
        )
    except (DriverError, OSError):
        return None
    if bytes_returned < out_size:
        return None
    out = ctypes.cast(out_buf, ctypes.POINTER(P.MYARK_WIN32K_GUI_THREADS_OUTPUT)).contents
    return GuiThreadsReport(count=out.Count, threads=[], source="r0")


def _send_hooks(client: Optional[ArkClient]) -> Optional[HooksReport]:
    if client is None:
        return None
    out_size = ctypes.sizeof(P.MYARK_WIN32K_HOOKS_OUTPUT)
    out_buf = (ctypes.c_ubyte * out_size)()
    try:
        bytes_returned = client.ioctl(
            P.IOCTL_MYARK_WIN32K_ENUMERATE_HOOKS, (ctypes.c_ubyte * 0)(), out_buf
        )
    except (DriverError, OSError):
        return None
    if bytes_returned < out_size:
        return None
    out = ctypes.cast(out_buf, ctypes.POINTER(P.MYARK_WIN32K_HOOKS_OUTPUT)).contents
    return HooksReport(count=out.Count, hooks=[], source="r0")


def enumerate_gui_threads(client: Optional[ArkClient]) -> GuiThreadsReport:
    r3 = _r3_fallback_threads()
    r0 = _send_threads(client)
    return r0 if r0 is not None else r3


def enumerate_hooks(client: Optional[ArkClient]) -> HooksReport:
    r3 = _r3_fallback_hooks()
    r0 = _send_hooks(client)
    return r0 if r0 is not None else r3


__all__ = [
    "GuiThread", "GuiThreadsReport",
    "HookEntry", "HooksReport",
    "enumerate_gui_threads", "enumerate_hooks",
]
