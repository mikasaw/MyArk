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
    win32k_base: int = 0
    kernel_ahe_list: int = 0
    kernel_psi: int = 0
    psi_match: int = 0
    rsv2: int = 0
    entries: list = None
    source: str = "r0"

    def __post_init__(self):
        if self.entries is None:
            self.entries = []

    @property
    def heap_derived(self) -> bool:
        # PsiMatch bit1: desktop-heap base derived AND >=1 row
        # self-validated against it (driver-side hdr check).
        return bool(self.psi_match & 2)

    @property
    def canonical_rows(self) -> int:
        return sum(1 for e in self.entries
                   if e.kernel_object >= 0xFFFF800000000000)

    @property
    def rsv2_text(self) -> str:
        # Human decode of the Reserved2 breadcrumb (MyArkWin32kIoctl.h).
        if self.rsv2 == 0:
            return ("proven" if self.heap_derived
                    else "scan-not-run/no-profile-row")
        stage = self.rsv2 & 0xFF
        if not (self.rsv2 & 0x100):
            return f"resolver-stage-{stage}"
        return {
            0x11: "no-W32PROCESS",
            0x12: "no-structural-candidate",
            0x13: "candidates-but-0-rows-validated",
            0x14: "scan-aborted",
        }.get(stage, f"heap-stage-{stage:#x}")


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
        win32k_base=out_buf.Win32kBase,
        kernel_ahe_list=out_buf.KernelAheList,
        kernel_psi=out_buf.KernelPsi,
        psi_match=out_buf.PsiMatch,
        rsv2=out_buf.Reserved2,
        entries=rows,
    )


# --- R3-10b-iii: session timers (win32kbase!gTimerHashTable) ----------------


@dataclass
class TimerEntry:
    index: int = 0
    timer_id: int = 0
    elapse_ms: int = 0
    flags: int = 0
    pti: int = 0
    timer_proc: int = 0
    window: int = 0
    node: int = 0

    @property
    def kind(self) -> str:
        return "window" if self.window else "thread"


@dataclass
class TimersReport:
    count: int = 0
    diag_status: int = 0
    truncated: int = 0
    timer_hash_table: int = 0
    session_base: int = 0
    bucket_count: int = 0
    node_size: int = 0
    scanned_buckets: int = 0
    timer_hash_rva: int = 0
    rsv2: int = 0
    entries: list = None
    source: str = "r0"

    def __post_init__(self):
        if self.entries is None:
            self.entries = []


def enum_timers(client: Optional[ArkClient]) -> TimersReport:
    if client is None:
        raise ConnectionError("driver not available")

    out_size = ctypes.sizeof(P.MYARK_WIN32K_TIMERS_OUTPUT)
    out_buf = P.MYARK_WIN32K_TIMERS_OUTPUT()
    bytes_returned = client.ioctl(P.IOCTL_MYARK_WIN32K_ENUM_TIMERS,
                                  (ctypes.c_ubyte * 0)(), out_buf)
    if bytes_returned < out_size:
        raise ConnectionError(
            f"short read: {bytes_returned} < {out_size}")
    rows = []
    for i in range(min(out_buf.Count, len(out_buf.Entries))):
        e = out_buf.Entries[i]
        rows.append(TimerEntry(
            index=e.Index,
            timer_id=e.TimerId,
            elapse_ms=e.ElapseMs,
            flags=e.Flags,
            pti=e.Pti,
            timer_proc=e.TimerProc,
            window=e.Window,
            node=e.Node,
        ))
    return TimersReport(
        count=out_buf.Count,
        diag_status=out_buf.DiagStatus,
        truncated=out_buf.Truncated,
        timer_hash_table=out_buf.TimerHashTable,
        session_base=out_buf.SessionBase,
        bucket_count=out_buf.BucketCount,
        node_size=out_buf.NodeSize,
        scanned_buckets=out_buf.ScannedBuckets,
        timer_hash_rva=out_buf.TimerHashRva,
        rsv2=out_buf.Reserved2,
        entries=rows,
    )


# --- R3-10c: WinEvent hook list (win32kbase!gpWinEventHooks) -----------------


@dataclass
class EventHookEntry:
    index: int = 0
    event_min: int = 0
    event_max: int = 0
    flags_internal: int = 0
    id_process: int = 0
    id_thread: int = 0
    handle: int = 0
    callback: int = 0
    node: int = 0


@dataclass
class EventHooksReport:
    count: int = 0
    diag_status: int = 0
    truncated: int = 0
    list_head: int = 0
    session_base: int = 0
    node_size: int = 0
    win_event_hooks_rva: int = 0
    rsv2: int = 0
    entries: list = None
    source: str = "r0"

    def __post_init__(self):
        if self.entries is None:
            self.entries = []

    @property
    def gated(self) -> bool:
        # STATUS_NOT_IMPLEMENTED = build without an EVENTHOOK calibration.
        return self.diag_status == 0xC0000002


def enum_eventhooks(client: Optional[ArkClient]) -> EventHooksReport:
    if client is None:
        raise ConnectionError("driver not available")

    out_size = ctypes.sizeof(P.MYARK_WIN32K_EVENTHOOKS_OUTPUT)
    out_buf = P.MYARK_WIN32K_EVENTHOOKS_OUTPUT()
    bytes_returned = client.ioctl(P.IOCTL_MYARK_WIN32K_ENUM_EVENTHOOKS,
                                  (ctypes.c_ubyte * 0)(), out_buf)
    if bytes_returned < out_size:
        raise ConnectionError(
            f"short read: {bytes_returned} < {out_size}")
    rows = []
    for i in range(min(out_buf.Count, len(out_buf.Entries))):
        e = out_buf.Entries[i]
        rows.append(EventHookEntry(
            index=e.Index,
            event_min=e.EventMin,
            event_max=e.EventMax,
            flags_internal=e.FlagsInternal,
            id_process=e.IdProcess,
            id_thread=e.IdThread,
            handle=e.Handle,
            callback=e.Callback,
            node=e.Node,
        ))
    return EventHooksReport(
        count=out_buf.Count,
        diag_status=out_buf.DiagStatus,
        truncated=out_buf.Truncated,
        list_head=out_buf.ListHead,
        session_base=out_buf.SessionBase,
        node_size=out_buf.NodeSize,
        win_event_hooks_rva=out_buf.WinEventHooksRva,
        rsv2=out_buf.Reserved2,
        entries=rows,
    )


__all__ = [
    "GuiThread", "GuiThreadsReport",
    "HookEntry", "HooksReport",
    "UserHandleEntry", "UserHandlesReport",
    "TimerEntry", "TimersReport",
    "EventHookEntry", "EventHooksReport",
    "enumerate_gui_threads", "enumerate_hooks", "enum_user_handles",
    "enum_timers", "enum_eventhooks",
]
