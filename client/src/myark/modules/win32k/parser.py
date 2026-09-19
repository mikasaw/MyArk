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


# --- R3-10a: USER handle table (user32!gSharedInfo) -------------------------


@dataclass
class UserHandleEntry:
    index: int = 0
    type: int = 0
    type_name: str = ""
    flags: int = 0
    kernel_object: int = 0
    user_pointer: int = 0


@dataclass
class UserHandlesReport:
    count: int = 0
    diag_status: int = 0
    truncated: int = 0
    shared_info: int = 0
    ahe_list: int = 0
    he_entry_size: int = 0
    scanned_slots: int = 0
    entries: list = None
    source: str = "r0"

    def __post_init__(self):
        if self.entries is None:
            self.entries = []


def enum_user_handles(client: Optional[ArkClient]) -> UserHandlesReport:
    if client is None:
        raise ConnectionError("driver not available")

    out_size = ctypes.sizeof(P.MYARK_WIN32K_USER_HANDLES_OUTPUT)
    out_buf = P.MYARK_WIN32K_USER_HANDLES_OUTPUT()
    bytes_returned = client.ioctl(P.IOCTL_MYARK_WIN32K_ENUM_USER_HANDLES,
                                  (ctypes.c_ubyte * 0)(), out_buf)
    if bytes_returned < out_size:
        raise ConnectionError(
            f"short read: {bytes_returned} < {out_size}")
    rows = []
    for i in range(min(out_buf.Count, len(out_buf.Entries))):
        e = out_buf.Entries[i]
        rows.append(UserHandleEntry(
            index=e.Index,
            type=e.Type,
            type_name=P.WIN32K_TYPE_NAMES.get(e.Type, f"Type{e.Type}"),
            flags=e.Flags,
            kernel_object=e.KernelObject,
            user_pointer=e.UserPointer,
        ))
    return UserHandlesReport(
        count=out_buf.Count,
        diag_status=out_buf.DiagStatus,
        truncated=out_buf.Truncated,
        shared_info=out_buf.SharedInfo,
        ahe_list=out_buf.AheList,
        he_entry_size=out_buf.HeEntrySize,
        scanned_slots=out_buf.ScannedSlots,
        entries=rows,
    )


__all__ = [
    "GuiThread", "GuiThreadsReport",
    "HookEntry", "HooksReport",
    "UserHandleEntry", "UserHandlesReport",
    "enumerate_gui_threads", "enumerate_hooks", "enum_user_handles",
]
