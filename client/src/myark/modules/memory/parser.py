"""
memory R3 - parser / backend (kernel32 ReadProcessMemory / WriteProcessMemory / EnumProcessModules)

R3 implementation, no .sys required. Uses dataclass MemoryRegion for
data; full VAD walk needs the driver.
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes
from typing import List, Optional

from .protocol import (
    MemoryRegion,
    MemoryError,
    AccessDeniedError,
    win32_error,
    PROCESS_VM_READ,
    PROCESS_VM_WRITE,
    PROCESS_VM_OPERATION,
    PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION,
    PAGE_READWRITE,
)

# ===== DLL =====
kernel32 = ctypes.windll.kernel32
psapi = ctypes.WinDLL("psapi.dll")

# ===== argtypes / restype (Python 3.14 ctypes strict) =====
DWORD = ctypes.wintypes.DWORD
BOOL = ctypes.wintypes.BOOL
HANDLE = ctypes.wintypes.HANDLE
LPDWORD = ctypes.POINTER(ctypes.wintypes.DWORD)
LPVOID = ctypes.c_void_p
LPCVOID = ctypes.c_void_p

kernel32.OpenProcess.argtypes = [DWORD, BOOL, DWORD]
kernel32.OpenProcess.restype = HANDLE

kernel32.CloseHandle.argtypes = [HANDLE]
kernel32.CloseHandle.restype = BOOL

kernel32.ReadProcessMemory.argtypes = [HANDLE, LPCVOID, LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.ReadProcessMemory.restype = BOOL

kernel32.WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = BOOL

psapi.EnumProcessModules.argtypes = [HANDLE, LPVOID, DWORD, LPDWORD]
psapi.EnumProcessModules.restype = BOOL

psapi.GetModuleFileNameExW.argtypes = [HANDLE, LPVOID, ctypes.c_wchar_p, DWORD]
psapi.GetModuleFileNameExW.restype = DWORD

psapi.GetModuleInformation.argtypes = [HANDLE, LPVOID, LPVOID, DWORD]
psapi.GetModuleInformation.restype = BOOL


class _MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", LPVOID),
        ("SizeOfImage", DWORD),
        ("EntryPoint", LPVOID),
    ]


def _open_process(pid: int, access: int) -> int:
    h = kernel32.OpenProcess(access, False, pid)
    if not h:
        win32_error()
    return int(h)


def _close_handle(handle: int) -> None:
    if handle:
        kernel32.CloseHandle(handle)


def read_memory(pid: int, addr: int, size: int) -> bytes:
    """Read ``size`` bytes from PID ``pid`` at virtual address ``addr``.

    Raises ``AccessDeniedError`` on Win32 error 5 (caller lacks
    PROCESS_VM_READ). Returns up to ``size`` bytes -- partial reads are
    not retried.
    """
    h = _open_process(pid, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)
    try:
        buf = (ctypes.c_ubyte * size)()
        got = ctypes.c_size_t(0)
        if not kernel32.ReadProcessMemory(h, addr, buf, size, ctypes.byref(got)):
            win32_error()
        actual = min(got.value, size)
        return bytes(buf[:actual])
    finally:
        _close_handle(h)


def write_memory(pid: int, addr: int, data: bytes) -> int:
    """Write ``data`` to PID ``pid`` at virtual address ``addr``.

    Returns the number of bytes actually written. Requires admin
    (``PROCESS_VM_WRITE`` is only granted to admin over protected
    processes).
    """
    h = _open_process(pid, PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION)
    try:
        written = ctypes.c_size_t(0)
        if not kernel32.WriteProcessMemory(h, addr, data, len(data), ctypes.byref(written)):
            win32_error()
        return written.value
    finally:
        _close_handle(h)


def query_memory_regions(pid: int) -> List[MemoryRegion]:
    """Enumerate the loaded modules of ``pid`` via ``EnumProcessModules``.

    This is the R3 stand-in for a VAD walk: each row carries the base
    address, size, and full path of one module the loader has placed.
    Free / reserved regions the loader hasn't claimed are not visible
    from R3.
    """
    h = _open_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
    try:
        cap = 4096
        buf = (LPVOID * cap)()
        needed = ctypes.wintypes.DWORD(0)
        ok = psapi.EnumProcessModules(h, ctypes.cast(buf, LPVOID), cap * ctypes.sizeof(LPVOID), ctypes.byref(needed))
        if not ok:
            win32_error()
        count = needed.value // ctypes.sizeof(LPVOID)
        out: List[MemoryRegion] = []
        for i in range(min(count, cap)):
            mod_handle = buf[i]
            mi = _MODULEINFO()
            if not psapi.GetModuleInformation(h, mod_handle, ctypes.byref(mi), ctypes.sizeof(mi)):
                continue
            name_buf = ctypes.create_unicode_buffer(260)
            n = psapi.GetModuleFileNameExW(h, mod_handle, name_buf, 260)
            if n == 0:
                continue
            full = name_buf.value
            base_name = full.rsplit("\\", 1)[-1] if "\\" in full else full
            out.append(
                MemoryRegion(
                    pid=pid,
                    base_address=int(mi.lpBaseOfDll or 0),
                    size=int(mi.SizeOfImage or 0),
                    name=base_name,
                    path=full,
                )
            )
        return out
    finally:
        _close_handle(h)


__all__ = [
    "read_memory",
    "write_memory",
    "query_memory_regions",
]