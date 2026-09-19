"""
module R3 - parser / backend (psapi EnumProcessModules + GetModuleFileNameExW)

Pure R3 implementation. Driver-side PEB walks that surface unlinked
modules are out of scope here.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
from typing import List

from .protocol import (
    ModuleRow,
    ModuleError,
    AccessDeniedError,
    PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION,
)


ERROR_ACCESS_DENIED = 5


kernel32 = ctypes.windll.kernel32
psapi = ctypes.WinDLL("psapi.dll")

DWORD = ctypes.wintypes.DWORD
BOOL = ctypes.wintypes.BOOL
HANDLE = ctypes.wintypes.HANDLE
LPDWORD = ctypes.POINTER(ctypes.wintypes.DWORD)
LPVOID = ctypes.c_void_p


kernel32.OpenProcess.argtypes = [DWORD, BOOL, DWORD]
kernel32.OpenProcess.restype = HANDLE

kernel32.CloseHandle.argtypes = [HANDLE]
kernel32.CloseHandle.restype = BOOL

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
        err = ctypes.get_last_error() or ctypes.GetLastError()
        if err == ERROR_ACCESS_DENIED:
            raise AccessDeniedError(
                f"OpenProcess({pid}, 0x{access:X}) failed: access denied (Win32 error 5)"
            )
        raise ModuleError(
            f"OpenProcess({pid}, 0x{access:X}) failed: Win32 error {err}"
        )
    return int(h)


def _close_handle(handle: int) -> None:
    if handle:
        kernel32.CloseHandle(handle)


def enumerate_modules(pid: int) -> List[ModuleRow]:
    """Enumerate the loaded modules of ``pid`` via ``EnumProcessModules``.

    Returns a list of :class:`ModuleRow` objects, one per module. Each
    row carries the load address, image size, entry point, base file
    name, and full path.

    Raises
    ------
    AccessDeniedError
        Win32 error 5 -- the caller does not have
        ``PROCESS_QUERY_INFORMATION``/``PROCESS_QUERY_LIMITED_INFORMATION``
        over ``pid`` (PPL / protected processes refuse).
    ModuleError
        Other Win32 failure during the enumeration.
    """
    try:
        h = _open_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION)
    except AccessDeniedError:
        h = _open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION)
    try:
        cap = 4096
        buf = (LPVOID * cap)()
        needed = ctypes.wintypes.DWORD(0)
        ok = psapi.EnumProcessModules(
            h,
            ctypes.cast(buf, LPVOID),
            cap * ctypes.sizeof(LPVOID),
            ctypes.byref(needed),
        )
        if not ok:
            err = ctypes.get_last_error() or ctypes.GetLastError()
            if err == ERROR_ACCESS_DENIED:
                raise AccessDeniedError(
                    f"EnumProcessModules({pid}) failed: access denied (Win32 error 5)"
                )
            raise ModuleError(
                f"EnumProcessModules({pid}) failed: Win32 error {err}"
            )
        count = needed.value // ctypes.sizeof(LPVOID)
        out: List[ModuleRow] = []
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
                ModuleRow(
                    pid=pid,
                    base_address=int(mi.lpBaseOfDll or 0),
                    size=int(mi.SizeOfImage or 0),
                    entry_point=int(mi.EntryPoint or 0),
                    name=base_name,
                    path=full,
                )
            )
        return out
    finally:
        _close_handle(h)


__all__ = [
    "enumerate_modules",
]