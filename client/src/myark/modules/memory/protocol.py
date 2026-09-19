"""
memory R3 - protocol data structures (dataclass, no ctypes wire format).

R3-only memory module: no .sys driver required. Uses dataclass to
avoid Python 3.14 ctypes strict typing incompatibilities with
c_wchar field assignment.

Only ``MemoryRegion`` is exposed here -- the wire-format ctypes structs
for the R0 driver (MYARK_MEMORY_* ctypes classes) live in the legacy
``__init__`` shim while the rest of the module is migrated to this
file.
"""

from __future__ import annotations

from dataclasses import dataclass


# ===== Process access rights (subset used here) =====
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# ===== Memory protection bits =====
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40


@dataclass
class MemoryRegion:
    """One loaded module of a process (R3 EnumProcessModules row).

    The full virtual-address-region (VAD) tree needs the driver; R3
    only sees the modules the loader has placed in the process.
    """
    pid: int = 0
    base_address: int = 0
    size: int = 0
    name: str = ""
    path: str = ""


class MemoryError(Exception):
    """R3 memory module exception."""


class AccessDeniedError(MemoryError):
    """Win32 error 5."""


def win32_error() -> None:
    import ctypes
    err = ctypes.get_last_error() or ctypes.windll.kernel32.GetLastError()
    if err == 5:
        raise AccessDeniedError(f"Access denied (Win32 error {err})")
    raise MemoryError(f"Win32 error {err}")


__all__ = [
    "MemoryRegion",
    "MemoryError",
    "AccessDeniedError",
    "win32_error",
    "PROCESS_VM_READ",
    "PROCESS_VM_WRITE",
    "PROCESS_VM_OPERATION",
    "PROCESS_QUERY_INFORMATION",
    "PROCESS_QUERY_LIMITED_INFORMATION",
    "PAGE_READWRITE",
    "PAGE_EXECUTE_READWRITE",
]