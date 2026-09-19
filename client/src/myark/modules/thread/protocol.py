"""MyArk thread module: R3 client for the thread IOCTLs.

Mirrors ``shared/driver/MyArkThreadIoctl.h`` on the Python side. The
ctypes structs and IOCTL codes here must match the driver-side layout
exactly; mismatches show up as ``OSError: [Errno 22] Invalid argument``
from ``DeviceIoControl``.

Functions in this module:
- ``enum_threads(client, pid, max_entries)``   -- IOCTL_MYARK_THREAD_ENUM
- ``detail(client, tid)``                      -- IOCTL_MYARK_THREAD_DETAIL
- ``detail_runtime(client, tid)``              -- IOCTL_MYARK_THREAD_DETAIL_RUNTIME
- ``crossview(client, pid, tid_filter)``       -- IOCTL_MYARK_THREAD_CROSSVIEW
- ``terminate(client, tid, exit_code, force)`` -- IOCTL_MYARK_THREAD_TERMINATE

The IOCTLs follow the MyArk ``CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA1x, 0, 0)``
pattern: function range 0xA10..0xA14, METHOD_BUFFERED, FILE_ANY_ACCESS.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass, field
from typing import Optional

from myark.client.ark_client import ArkClient, DriverCallError, DriverError


# ---------------------------------------------------------------------------
# IOCTL codes (mirror shared/driver/MyArkThreadIoctl.h).
# ---------------------------------------------------------------------------
# CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, function, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
# => (0x22 << 16) | (function << 2) | 0
_IOCTL_BASE = (0x22 << 16)

IOCTL_MYARK_THREAD_ENUM           = _IOCTL_BASE | (0xA10 << 2)
IOCTL_MYARK_THREAD_DETAIL         = _IOCTL_BASE | (0xA11 << 2)
IOCTL_MYARK_THREAD_DETAIL_RUNTIME = _IOCTL_BASE | (0xA12 << 2)
IOCTL_MYARK_THREAD_CROSSVIEW      = _IOCTL_BASE | (0xA13 << 2)
IOCTL_MYARK_THREAD_TERMINATE      = _IOCTL_BASE | (0xA14 << 2)


# ---------------------------------------------------------------------------
# Source / hidden / anomaly masks (mirror MYARK_THREAD_SRC_* / HIDDEN_* / ANOMALY_*).
# ---------------------------------------------------------------------------
SRC_PUBLIC      = 0x01
SRC_THREADLIST  = 0x02
SRC_PSPCIDTABLE = 0x04

HIDDEN_NONE     = 0x00
HIDDEN_VIA_DKOM = 0x01

ANOMALY_NONE                  = 0x00
ANOMALY_START_OUTSIDE_MODULE  = 0x01


# ---------------------------------------------------------------------------
# Constants from MyArkThreadIoctl.h
# ---------------------------------------------------------------------------
MODULE_NAME_MAX = 64
START_PATH_MAX  = 260

# KTHREAD_STATE enum (subset used for pretty labels)
KTHREAD_STATE_NAMES = {
    0: "Initialized",
    1: "Ready",
    2: "Running",
    3: "Standby",
    4: "Terminated",
    5: "Waiting",
    6: "Transition",
    7: "DeferredReady",
    8: "GateWait",
}

# KWAIT_REASON subset
KWAIT_REASON_NAMES = {
    0:  "Executive",
    1:  "FreePage",
    2:  "PageIn",
    3:  "PoolAllocation",
    4:  "DelayExecution",
    5:  "Suspended",
    6:  "UserRequest",
    7:  "WrExecutive",
    8:  "WrFreePage",
    9:  "WrPageIn",
    10: "WrPoolAllocation",
    11: "WrDelayExecution",
    12: "WrSuspended",
    13: "WrUserRequest",
    14: "WrEventPair",
    15: "WrQueue",
    16: "WrLpcReceive",
    17: "WrLpcReply",
    18: "WrVirtualMemory",
    19: "WrPageOut",
    20: "WrRendezvous",
    21: "WrKeyedEvent",
    22: "WrTerminated",
    23: "WrProcessInSwap",
    24: "WrCpuRateControl",
    25: "WrCalloutStack",
    26: "WrKernel",
    27: "WrResource",
    28: "WrPushLock",
    29: "WrMutex",
    30: "WrQuantumEnd",
    31: "WrDispatchInt",
    32: "WrPreempted",
    33: "WrYieldExecution",
    34: "WrFastMutex",
    35: "WrGuardedMutex",
    36: "WrRundown",
    37: "WrAlertByThreadId",
    38: "WrDeferredPreempt",
}


# ---------------------------------------------------------------------------
# ctypes structs (must mirror the R0 side byte-for-byte).
# ---------------------------------------------------------------------------

class MYARK_THREAD_ENTRY(ctypes.Structure):
    """One row of ENUM / CROSSVIEW output."""
    _fields_ = [
        ("Tid",                  ctypes.c_uint32),
        ("Pid",                  ctypes.c_uint32),
        ("StartAddress",         ctypes.c_uint64),
        ("Module",               ctypes.c_wchar * MODULE_NAME_MAX),
        ("State",                ctypes.c_uint8),
        ("Anomaly",              ctypes.c_uint8),
        ("Reserved0",            ctypes.c_uint8),
        ("Reserved1",            ctypes.c_uint8),
        ("Priority",             ctypes.c_uint32),
        ("WaitReason",           ctypes.c_uint32),
        ("CreateTime",           ctypes.c_uint64),
        ("EThreadKernelAddress", ctypes.c_uint64),
    ]


class MYARK_THREAD_ENUM_INPUT(ctypes.Structure):
    _fields_ = [
        ("Pid",        ctypes.c_uint32),
        ("MaxEntries", ctypes.c_uint32),
        ("Reserved0",  ctypes.c_uint32),
        ("Reserved1",  ctypes.c_uint32),
    ]


class MYARK_THREAD_ENUM_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size",         ctypes.c_uint32),
        ("Count",        ctypes.c_uint32),
        ("OwnerPid",     ctypes.c_uint32),
        ("AnomalyCount", ctypes.c_uint32),
        ("Entries",      MYARK_THREAD_ENTRY * 1),
    ]


class MYARK_THREAD_DETAIL(ctypes.Structure):
    _fields_ = [
        ("Tid",                       ctypes.c_uint32),
        ("OwnerPid",                  ctypes.c_uint32),
        ("State",                     ctypes.c_uint32),
        ("Priority",                  ctypes.c_uint32),
        ("BasePriority",              ctypes.c_uint32),
        ("WaitReason",                ctypes.c_uint32),
        ("Anomaly",                   ctypes.c_uint32),
        ("Reserved0",                 ctypes.c_uint32),
        ("CreateTime",                ctypes.c_uint64),
        ("StartAddress",              ctypes.c_uint64),
        ("Win32StartAddress",         ctypes.c_uint64),
        ("EThreadKernelAddress",      ctypes.c_uint64),
        ("EProcessKernelAddress",     ctypes.c_uint64),
        ("UniqueThreadIdOffset",      ctypes.c_uint32),
        ("ThreadListEntryOffset",     ctypes.c_uint32),
        ("StateOffset",               ctypes.c_uint32),
        ("PriorityOffset",            ctypes.c_uint32),
        ("WaitReasonOffset",          ctypes.c_uint32),
        ("CreateTimeOffset",          ctypes.c_uint32),
        ("StartAddressOffset",        ctypes.c_uint32),
        ("ApcStateProcessOffset",     ctypes.c_uint32),
        ("Module",                    ctypes.c_wchar * MODULE_NAME_MAX),
        ("StartAddressModulePath",    ctypes.c_wchar * START_PATH_MAX),
    ]


class MYARK_THREAD_DETAIL_RUNTIME(ctypes.Structure):
    _fields_ = [
        ("Tid",              ctypes.c_uint32),
        ("Reserved0",        ctypes.c_uint32),
        ("KernelTime",       ctypes.c_uint64),
        ("UserTime",         ctypes.c_uint64),
        ("CycleTime",        ctypes.c_uint64),
        ("ContextSwitches",  ctypes.c_uint32),
        ("Reserved1",        ctypes.c_uint32),
        ("StateFlags",       ctypes.c_uint32),
        ("Reserved2",        ctypes.c_uint32),
    ]


class MYARK_THREAD_CROSSVIEW_INPUT(ctypes.Structure):
    _fields_ = [
        ("Tid",       ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint32),
    ]


class MYARK_THREAD_CROSSVIEW_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size",        ctypes.c_uint32),
        ("Count",       ctypes.c_uint32),
        ("HiddenCount", ctypes.c_uint32),
        ("PublicOnly",  ctypes.c_uint32),
        ("Entries",     MYARK_THREAD_ENTRY * 1),
    ]


class MYARK_THREAD_TERMINATE_INPUT(ctypes.Structure):
    _fields_ = [
        ("Tid",      ctypes.c_uint32),
        ("ExitCode", ctypes.c_uint32),
        ("Force",    ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
    ]


class MYARK_THREAD_TERMINATE_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Tid",            ctypes.c_uint32),
        ("Status",         ctypes.c_uint32),
        ("UsedR0Fallback", ctypes.c_uint32),
        ("Reserved",       ctypes.c_uint32),
    ]


# ---------------------------------------------------------------------------
# Parser helpers
# ---------------------------------------------------------------------------

def _clean_wstr(raw) -> str:
    """ctypes c_wchar arrays expose the embedded NUL via __getitem__."""
    if raw is None:
        return ""
    if hasattr(raw, "__iter__"):
        out = []
        for ch in raw:
            if ch == "\x00":
                break
            out.append(ch)
        return "".join(out)
    return str(raw)


def _state_name(state: int) -> str:
    return KTHREAD_STATE_NAMES.get(int(state) & 0xFF, f"state={int(state)}")


def _wait_name(reason: int) -> str:
    return KWAIT_REASON_NAMES.get(int(reason) & 0xFF, f"wait={int(reason)}")


@dataclass
class ThreadRow:
    tid: int
    pid: int
    start_address: int
    module: str
    state: int
    state_name: str
    anomaly: int
    priority: int
    wait_reason: int
    wait_name: str
    create_time: int
    ethread_addr: int

    @classmethod
    def from_entry(cls, e: MYARK_THREAD_ENTRY) -> "ThreadRow":
        return cls(
            tid=int(e.Tid),
            pid=int(e.Pid),
            start_address=int(e.StartAddress),
            module=_clean_wstr(e.Module),
            state=int(e.State),
            state_name=_state_name(int(e.State)),
            anomaly=int(e.Anomaly),
            priority=int(e.Priority),
            wait_reason=int(e.WaitReason),
            wait_name=_wait_name(int(e.WaitReason)),
            create_time=int(e.CreateTime),
            ethread_addr=int(e.EThreadKernelAddress),
        )


@dataclass
class EnumResult:
    rows: list[ThreadRow] = field(default_factory=list)
    owner_pid: int = 0
    anomaly_count: int = 0
    bytes_used: int = 0


@dataclass
class CrossviewResult:
    rows: list[ThreadRow] = field(default_factory=list)
    public_only: int = 0
    hidden_count: int = 0
    bytes_used: int = 0


def _parse_enum_output(raw: bytes) -> EnumResult:
    if len(raw) < 16:
        return EnumResult()
    hdr_size = 16  # Size + Count + OwnerPid + AnomalyCount
    out_struct = MYARK_THREAD_ENUM_OUTPUT.from_buffer_copy(raw[:hdr_size])
    count = int(out_struct.Count)
    entry_size = ctypes.sizeof(MYARK_THREAD_ENTRY)
    rows: list[ThreadRow] = []
    for i in range(count):
        offset = hdr_size + i * entry_size
        if offset + entry_size > len(raw):
            break
        e = MYARK_THREAD_ENTRY.from_buffer_copy(raw[offset:offset + entry_size])
        rows.append(ThreadRow.from_entry(e))
    return EnumResult(
        rows=rows,
        owner_pid=int(out_struct.OwnerPid),
        anomaly_count=int(out_struct.AnomalyCount),
        bytes_used=int(out_struct.Size),
    )


def _parse_crossview_output(raw: bytes) -> CrossviewResult:
    if len(raw) < 16:
        return CrossviewResult()
    hdr_size = 16
    out_struct = MYARK_THREAD_CROSSVIEW_OUTPUT.from_buffer_copy(raw[:hdr_size])
    count = int(out_struct.Count)
    entry_size = ctypes.sizeof(MYARK_THREAD_ENTRY)
    rows: list[ThreadRow] = []
    for i in range(count):
        offset = hdr_size + i * entry_size
        if offset + entry_size > len(raw):
            break
        e = MYARK_THREAD_ENTRY.from_buffer_copy(raw[offset:offset + entry_size])
        rows.append(ThreadRow.from_entry(e))
    return CrossviewResult(
        rows=rows,
        public_only=int(out_struct.PublicOnly),
        hidden_count=int(out_struct.HiddenCount),
        bytes_used=int(out_struct.Size),
    )


# ---------------------------------------------------------------------------
# Public API -- one function per IOCTL.
# ---------------------------------------------------------------------------

# Default upper bound for ENUM_THREAD / CROSSVIEW: matches driver cap (256 entries)
# plus a generous headroom for buffer sizing.
_ENUM_DEFAULT_BUFFER = 64 * 1024


def enum_threads(
    client: ArkClient,
    pid: int,
    max_entries: int = 256,
) -> EnumResult:
    """Run IOCTL_MYARK_THREAD_ENUM and return parsed rows."""
    inp = MYARK_THREAD_ENUM_INPUT(Pid=pid, MaxEntries=max_entries, Reserved0=0, Reserved1=0)
    buf_size = 16 + max_entries * ctypes.sizeof(MYARK_THREAD_ENTRY)
    buf_size = min(buf_size, _ENUM_DEFAULT_BUFFER)
    buf = (ctypes.c_ubyte * buf_size)()
    client.ioctl(IOCTL_MYARK_THREAD_ENUM, bytes(inp), buf)
    return _parse_enum_output(bytes(buf))


def detail(client: ArkClient, tid: int) -> MYARK_THREAD_DETAIL:
    """Run IOCTL_MYARK_THREAD_DETAIL; returns the raw struct."""
    out = MYARK_THREAD_DETAIL()
    client.ioctl(IOCTL_MYARK_THREAD_DETAIL, ctypes.c_uint32(tid).tobytes(), out)
    return out


def detail_runtime(client: ArkClient, tid: int) -> MYARK_THREAD_DETAIL_RUNTIME:
    """Run IOCTL_MYARK_THREAD_DETAIL_RUNTIME; returns the raw struct."""
    out = MYARK_THREAD_DETAIL_RUNTIME()
    client.ioctl(IOCTL_MYARK_THREAD_DETAIL_RUNTIME, ctypes.c_uint32(tid).tobytes(), out)
    return out


def crossview(
    client: ArkClient,
    pid: int,
    tid_filter: int = 0,
) -> CrossviewResult:
    """Run IOCTL_MYARK_THREAD_CROSSVIEW for a Pid (with optional Tid filter).

    The cross-view input carries a TID filter; the Pid is supplied via the
    input's Reserved0 slot per the driver-side protocol extension
    (see thread_ioctl.c).
    """
    inp = MYARK_THREAD_CROSSVIEW_INPUT(
        Tid=tid_filter,
        Reserved0=pid,
        Reserved1=0,
        Reserved2=0,
    )
    buf = (ctypes.c_ubyte * _ENUM_DEFAULT_BUFFER)()
    client.ioctl(IOCTL_MYARK_THREAD_CROSSVIEW, bytes(inp), buf)
    return _parse_crossview_output(bytes(buf))


def _terminate_r3_fallback(tid: int, exit_code: int) -> int:
    """OpenThread + TerminateThread as the user-mode fallback path.

    Returns the Win32 status as a 32-bit unsigned int (0 == success). On
    any failure (insufficient rights, etc.) the caller surfaces the error
    and skips the driver roundtrip.
    """
    import ctypes as _ct
    THREAD_TERMINATE = 0x0001
    h = _ct.windll.kernel32.OpenThread(THREAD_TERMINATE, False, tid)
    if not h:
        return _ct.GetLastError() or 0xFFFFFFFF
    try:
        ok = _ct.windll.kernel32.TerminateThread(h, exit_code)
        return 0 if ok else (_ct.GetLastError() or 0xFFFFFFFF)
    finally:
        _ct.windll.kernel32.CloseHandle(h)


def terminate(
    client: ArkClient,
    tid: int,
    exit_code: int = 0,
    force: bool = False,
) -> MYARK_THREAD_TERMINATE_OUTPUT:
    """Kill one thread.

    Strategy: try the R3 fallback (OpenThread + TerminateThread) first; if
    that fails -- e.g. the thread is in a PPL-protected process -- fall
    through to the driver-side IOCTL. The driver's UsedR0Fallback field
    tells the caller which path actually ran.
    """
    inp = MYARK_THREAD_TERMINATE_INPUT(
        Tid=tid, ExitCode=exit_code, Force=1 if force else 0, Reserved=0,
    )
    out = MYARK_THREAD_TERMINATE_OUTPUT()

    r3_status = _terminate_r3_fallback(tid, exit_code)
    if r3_status == 0:
        out.Tid = tid
        out.Status = 0
        out.UsedR0Fallback = 0
        return out

    client.ioctl(IOCTL_MYARK_THREAD_TERMINATE, inp, out)
    return out


__all__ = [
    "IOCTL_MYARK_THREAD_ENUM",
    "IOCTL_MYARK_THREAD_DETAIL",
    "IOCTL_MYARK_THREAD_DETAIL_RUNTIME",
    "IOCTL_MYARK_THREAD_CROSSVIEW",
    "IOCTL_MYARK_THREAD_TERMINATE",
    "SRC_PUBLIC", "SRC_THREADLIST", "SRC_PSPCIDTABLE",
    "HIDDEN_NONE", "HIDDEN_VIA_DKOM",
    "ANOMALY_NONE", "ANOMALY_START_OUTSIDE_MODULE",
    "MODULE_NAME_MAX", "START_PATH_MAX",
    "KTHREAD_STATE_NAMES", "KWAIT_REASON_NAMES",
    "MYARK_THREAD_ENTRY", "MYARK_THREAD_DETAIL", "MYARK_THREAD_DETAIL_RUNTIME",
    "ThreadRow", "EnumResult", "CrossviewResult",
    "enum_threads", "detail", "detail_runtime", "crossview", "terminate",
]
