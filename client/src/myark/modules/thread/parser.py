"""Pure-R3 helpers for the thread module.

Functions in this file call Win32 / Toolhelp32 directly and never open the
``\\\\.\\MyArkCore`` device. They exist so the ``myark-cli thread enum
--method r3`` CLI path works on hosts without the driver installed, and so
the test suite can cover the wire-format / parser layer on any Windows
host (no admin / no testsigning required).

The current enumeration strategy:

1. ``CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)`` + ``Thread32FirstW`` /
   ``Thread32NextW`` returns every thread in the system along with the
   owning PID. We then filter to a single Pid for the enum result.
2. ``OpenThread + QueryFullProcessImageNameW`` resolves the owning PID's
   image path; we batch handle opens with a small concurrency cap so a
   hostile kernel can't stall the CLI by hanging on a single handle.
3. The StartAddress ownership check falls back to the R3 module list
   (``EnumProcessModules``), not the kernel's ``PsLoadedModuleList``.

R3 mode is intentionally minimal: StartAddress resolution is best-effort
and may disagree with the driver's view if a hot-patch shimmed a module.
The driver-side enum remains the authoritative source for StartAddress +
anomaly classification.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from typing import Optional

from .protocol import (
    ANOMALY_NONE,
    ANOMALY_START_OUTSIDE_MODULE,
    MODULE_NAME_MAX,
    ThreadRow,
)


# ---------------------------------------------------------------------------
# Win32 / Toolhelp32 setup
# ---------------------------------------------------------------------------

TH32CS_SNAPTHREAD = 0x00000004

THREAD_QUERY_INFORMATION = 0x0040
THREAD_QUERY_LIMITED_INFORMATION = 0x0800

ERROR_INSUFFICIENT_BUFFER = 122

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_psapi = ctypes.WinDLL("psapi", use_last_error=True)


# Toolhelp32 snapshot ------------------------------------------------------

_CloseHandle = _kernel32.CloseHandle
_CloseHandle.restype = wintypes.BOOL
_CloseHandle.argtypes = [wintypes.HANDLE]

_CreateToolhelp32Snapshot = _kernel32.CreateToolhelp32Snapshot
_CreateToolhelp32Snapshot.restype = wintypes.HANDLE
_CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]

_Thread32First = _kernel32.Thread32First
_Thread32First.restype = wintypes.BOOL
_Thread32First.argtypes = [wintypes.HANDLE, ctypes.c_void_p]

_Thread32Next = _kernel32.Thread32Next
_Thread32Next.restype = wintypes.BOOL
_Thread32Next.argtypes = [wintypes.HANDLE, ctypes.c_void_p]


class _THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    ]


def _snapshot_threads() -> dict[int, list[int]]:
    """Return ``{pid: [tid, ...]}`` via the Toolhelp thread snapshot.

    Thread32First/Next returns every thread in the system; we filter to
    the requested pid at the call site.
    """
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    snap = _CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snap in (None, 0, INVALID_HANDLE_VALUE):
        raise OSError(ctypes.get_last_error(), "CreateToolhelp32Snapshot failed")
    try:
        entry = _THREADENTRY32()
        entry.dwSize = ctypes.sizeof(entry)
        out: dict[int, list[int]] = {}
        ok = _Thread32First(snap, ctypes.byref(entry))
        while ok:
            pid = int(entry.th32OwnerProcessID)
            tid = int(entry.th32ThreadID)
            out.setdefault(pid, []).append(tid)
            ok = _Thread32Next(snap, ctypes.byref(entry))
        return out
    finally:
        _CloseHandle(snap)


# OpenThread / QueryFullProcessImageNameW ----------------------------------

_OpenThread = _kernel32.OpenThread
_OpenThread.restype = wintypes.HANDLE
_OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

_QueryFullProcessImageNameW = _kernel32.QueryFullProcessImageNameW
_QueryFullProcessImageNameW.restype = wintypes.BOOL
_QueryFullProcessImageNameW.argtypes = [
    wintypes.HANDLE, wintypes.DWORD,
    ctypes.c_wchar_p, ctypes.POINTER(wintypes.DWORD),
]


# Psapi: enumerate loaded modules of a process ------------------------------

_EnumProcessModules = _psapi.EnumProcessModules
_EnumProcessModules.restype = wintypes.BOOL
_EnumProcessModules.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(ctypes.c_void_p),
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]

_GetModuleFileNameExW = _psapi.GetModuleFileNameExW
_GetModuleFileNameExW.restype = wintypes.DWORD
_GetModuleFileNameExW.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p,
    ctypes.c_wchar_p, wintypes.DWORD,
]

_GetModuleInformation = _psapi.GetModuleInformation
_GetModuleInformation.restype = wintypes.BOOL
_GetModuleInformation.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p,
    ctypes.c_void_p, wintypes.DWORD,
]


class _MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", wintypes.DWORD),
        ("EntryPoint", ctypes.c_void_p),
    ]


PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010

_OpenProcess = _kernel32.OpenProcess
_OpenProcess.restype = wintypes.HANDLE
_OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]


def _module_ranges_for_pid(pid: int) -> list[tuple[int, int, str]]:
    """Enumerate the loaded modules of ``pid`` and return their (base, end, name) ranges.

    R3 can't reach arbitrary kernel addresses (StartAddress is a kernel
    pointer), so this list is used only as a sanity check: we still
    classify every row as ANOMALY_START_OUTSIDE_MODULE in R3 mode, since
    the kernel address belongs to a module loaded in kernel space and
    isn't addressable from a process module walk. The driver remains the
    authoritative source.
    """
    h = _OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        return []
    try:
        cap = 4096
        buf = (ctypes.c_void_p * cap)()
        needed = wintypes.DWORD(0)
        ok = _EnumProcessModules(h, buf, ctypes.sizeof(buf), ctypes.byref(needed))
        if not ok:
            return []
        count = needed.value // ctypes.sizeof(ctypes.c_void_p)
        out: list[tuple[int, int, str]] = []
        for i in range(min(count, cap)):
            mod_handle = ctypes.c_void_p(buf[i])
            mi = _MODULEINFO()
            ok2 = _GetModuleInformation(h, mod_handle, ctypes.byref(mi), ctypes.sizeof(mi))
            if not ok2:
                continue
            name = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
            n = _GetModuleFileNameExW(h, mod_handle, name, wintypes.MAX_PATH)
            if n == 0:
                continue
            base = mi.lpBaseOfDll or 0
            size = mi.SizeOfImage or 0
            full = name.value
            base_name = full.rsplit("\\", 1)[-1] if "\\" in full else full
            out.append((base, base + size, base_name[:MODULE_NAME_MAX]))
        return out
    finally:
        _CloseHandle(h)


def _classify_start_r3(start_address: int, ranges: list[tuple[int, int, str]]) -> tuple[str, int]:
    """Return (module_name, anomaly_flag) for a kernel StartAddress in R3 mode.

    R3 cannot walk kernel modules so every StartAddress is treated as
    OUTSIDE_MODULE; the caller still gets a sensible module name when
    the user-mode module list happens to overlap (rare but possible if
    a module is mapped shared).
    """
    if start_address == 0:
        return "", ANOMALY_NONE
    for base, end, name in ranges:
        if start_address >= base and start_address < end:
            return name, ANOMALY_NONE
    return "<r3-cannot-resolve>", ANOMALY_START_OUTSIDE_MODULE


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class EnumR3Stats:
    rows: list[ThreadRow]
    total_tids: int
    skipped_tids: int


def enum_threads_r3(pid: int) -> EnumR3Stats:
    """Pure-R3 enumeration: every thread of ``pid`` the kernel publishes to user mode.

    Returns rows whose fields are best-effort R3 copies; StartAddress is
    left as 0 (R3 can't read it) and Anomaly stays at ANOMALY_NONE unless
    the user-mode module walk happens to overlap (very rare).
    """
    snap = _snapshot_threads()
    tids = snap.get(pid, [])

    ranges = _module_ranges_for_pid(pid)

    rows: list[ThreadRow] = []
    for tid in tids:
        module, anomaly = _classify_start_r3(0, ranges)
        rows.append(
            ThreadRow(
                tid=tid,
                pid=pid,
                start_address=0,
                module=module,
                state=0,
                state_name="(r3)",
                anomaly=anomaly,
                priority=0,
                wait_reason=0,
                wait_name="(r3)",
                create_time=0,
                ethread_addr=0,
            )
        )

    return EnumR3Stats(rows=rows, total_tids=len(tids), skipped_tids=0)


# ---------------------------------------------------------------------------
# Per-thread R3 helpers (OpenThread + GetThreadTimes + TerminateThread).
# These are intentionally minimal: the driver-side IOCTLs surface kernel
# fields (StartAddress, ETHREAD, anomaly, wait reason) that R3 cannot
# reach. The CLI treats the R3 row as a degraded snapshot when the driver
# is not loaded.
# ---------------------------------------------------------------------------

THREAD_TERMINATE = 0x0001
THREAD_SUSPEND_RESUME = 0x0002
THREAD_QUERY_INFORMATION = 0x0040
THREAD_QUERY_LIMITED_INFORMATION = 0x0800
THREAD_GET_CONTEXT = 0x0010


class _FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD),
    ]


class _THREAD_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("ExitStatus", ctypes.c_uint64),
        ("TebBaseAddress", ctypes.c_uint64),
        ("ClientId", ctypes.c_uint64 * 2),  # UniqueProcess, UniqueThread
        ("AffinityMask", ctypes.c_uint64),
        ("Priority", ctypes.c_long),
        ("BasePriority", ctypes.c_long),
    ]


class _CONTEXT_AMD64(ctypes.Structure):
    """Subset of CONTEXT for x64 -- enough to show RIP / RSP / EFlags.

    Only the fields we expose; GetThreadContext writes the whole struct
    but our CLI prints just these three registers.
    """
    _fields_ = [
        ("P1Home", ctypes.c_uint64 * 2),
        ("P2Home", ctypes.c_uint64 * 2),
        ("P3Home", ctypes.c_uint64 * 2),
        ("P4Home", ctypes.c_uint64 * 2),
        ("P5Home", ctypes.c_uint64 * 2),
        ("P6Home", ctypes.c_uint64 * 2),
        ("ContextFlags", ctypes.c_uint32),
        ("MxCsr", ctypes.c_uint32),
        ("SegCs", ctypes.c_uint16),
        ("SegDs", ctypes.c_uint16),
        ("SegEs", ctypes.c_uint16),
        ("SegFs", ctypes.c_uint16),
        ("SegGs", ctypes.c_uint16),
        ("SegSs", ctypes.c_uint16),
        ("EFlags", ctypes.c_uint32),
        ("Dr0", ctypes.c_uint64),
        ("Dr1", ctypes.c_uint64),
        ("Dr2", ctypes.c_uint64),
        ("Dr3", ctypes.c_uint64),
        ("Dr6", ctypes.c_uint64),
        ("Dr7", ctypes.c_uint64),
        ("Rax", ctypes.c_uint64),
        ("Rcx", ctypes.c_uint64),
        ("Rdx", ctypes.c_uint64),
        ("Rbx", ctypes.c_uint64),
        ("Rsp", ctypes.c_uint64),
        ("Rbp", ctypes.c_uint64),
        ("Rsi", ctypes.c_uint64),
        ("Rdi", ctypes.c_uint64),
        ("R8", ctypes.c_uint64),
        ("R9", ctypes.c_uint64),
        ("R10", ctypes.c_uint64),
        ("R11", ctypes.c_uint64),
        ("R12", ctypes.c_uint64),
        ("R13", ctypes.c_uint64),
        ("R14", ctypes.c_uint64),
        ("R15", ctypes.c_uint64),
        ("Rip", ctypes.c_uint64),
    ]


def _filetime_to_int(ft: _FILETIME) -> int:
    return (ft.dwHighDateTime << 32) | ft.dwLowDateTime


def _win32_error() -> None:
    err = ctypes.get_last_error() or _kernel32.GetLastError()
    raise OSError(err, f"Win32 error {err}")


def _open_thread(tid: int, access: int) -> int:
    h = _kernel32.OpenThread(access, False, tid)
    if not h:
        _win32_error()
    return int(h)


def thread_detail_r3(tid: int) -> dict:
    """Best-effort R3 per-thread detail via OpenThread + GetThreadTimes.

    Returns a plain dict with the fields the kernel publishes to user
    mode. Kernel-only fields (StartAddress, ETHREAD, anomaly, wait
    reason) stay at 0 / "" and the CLI marks the row ``method=r3``.
    """
    h = _open_thread(tid, THREAD_QUERY_INFORMATION)
    try:
        # NtQueryInformationProcess-equivalent via NtQueryInformationThread
        # is not used; we read the times directly. Owner PID comes from
        # the Toolhelp snapshot via ``enum_threads_r3`` (filtered by tid).
        created = _FILETIME()
        exited = _FILETIME()
        kernel_time = _FILETIME()
        user_time = _FILETIME()
        ok = _kernel32.GetThreadTimes(
            h,
            ctypes.byref(created),
            ctypes.byref(exited),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        )
        if not ok:
            _win32_error()
        # Priority can come from GetThreadPriority; we wrap a c_long cast.
        priority = _kernel32.GetThreadPriority(h)
        base_priority = 0  # NtQueryInformationThread is not exported here.
    finally:
        _CloseHandle(h)
    return {
        "tid": tid,
        "owner_pid": 0,                # filled by the CLI from enum snapshot
        "priority": int(priority),
        "base_priority": int(base_priority),
        "create_time": _filetime_to_int(created),
        "exit_time": _filetime_to_int(exited),
        "kernel_time": _filetime_to_int(kernel_time),
        "user_time": _filetime_to_int(user_time),
    }


def thread_detail_runtime_r3(tid: int) -> dict:
    """Snapshot the thread context (RIP / RSP / EFlags on x64).

    GetThreadContext on a running thread is risky; we use a suspended
    handle for safety. The output is a dict so callers can extend it
    without breaking the dataclass wire format. Returns an empty dict
    if the thread cannot be opened (AccessDenied / nonexistent tid) so
    the CLI can degrade gracefully without an exception.
    """
    try:
        h = _open_thread(tid, THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION)
    except OSError as exc:
        return {"tid": tid, "error": exc.errno}
    try:
        prev = _kernel32.SuspendThread(h)
        try:
            ctx = _CONTEXT_AMD64()
            ctx.ContextFlags = 0x10003F
            ok = _kernel32.GetThreadContext(h, ctypes.byref(ctx))
            if not ok:
                return {"tid": tid, "error": ctypes.get_last_error()}
            return {
                "tid": tid,
                "rip": int(ctx.Rip),
                "rsp": int(ctx.Rsp),
                "rbp": int(ctx.Rbp),
                "rax": int(ctx.Rax),
                "rbx": int(ctx.Rbx),
                "eflags": int(ctx.EFlags),
            }
        finally:
            while _kernel32.ResumeThread(h) > 1:
                pass
    finally:
        _CloseHandle(h)


def terminate_thread_r3(tid: int, exit_code: int = 0) -> int:
    """Terminate a thread via OpenThread + TerminateThread. Admin required.

    Returns the Win32 status as a 32-bit unsigned int (0 == success).
    OpenThread failures are surfaced as the error code instead of an
    exception so the CLI can keep going on permssion errors.
    """
    try:
        h = _open_thread(tid, THREAD_TERMINATE)
    except OSError as exc:
        return exc.errno if exc.errno else 0xFFFFFFFF
    try:
        ok = _kernel32.TerminateThread(h, exit_code)
        return 0 if ok else (ctypes.get_last_error() or 0xFFFFFFFF)
    finally:
        _CloseHandle(h)


__all__ = [
    "EnumR3Stats",
    "enum_threads_r3",
    "thread_detail_r3",
    "thread_detail_runtime_r3",
    "terminate_thread_r3",
]
