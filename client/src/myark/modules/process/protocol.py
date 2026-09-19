"""
process R3 - protocol data structures (dataclass, not ctypes).

Python 3.14 ctypes strict typing breaks c_wchar array field assignment.
Using dataclass avoids the issue: row.name = "explorer.exe" just works.
"""
from dataclasses import dataclass


# ===== Process access rights =====
PROCESS_TERMINATE = 0x0001
PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_ALL_ACCESS = 0x001F0000 | 0xFFF

# ===== Thread access rights =====
THREAD_TERMINATE = 0x0001
THREAD_SUSPEND_RESUME = 0x0002
THREAD_QUERY_INFORMATION = 0x0040

# ===== Token information classes =====
TokenIntegrityLevel = 25

# ===== Memory =====
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40

# ===== Integrity levels =====
INTEGRITY_LEVEL_SYSTEM = 0x40000
INTEGRITY_LEVEL_HIGH = 0x30000
INTEGRITY_LEVEL_MEDIUM = 0x20000
INTEGRITY_LEVEL_LOW = 0x10000


@dataclass
class ProcessRow:
    """One process row (R3)."""
    pid: int = 0
    ppid: int = 0
    name: str = ""
    path: str = ""
    session_id: int = 0
    thread_count: int = 0


@dataclass
class ThreadRow:
    """One thread row (R3)."""
    tid: int = 0
    owner_pid: int = 0
    base_priority: int = 0


@dataclass
class ProcessDetail:
    """Process details (R3)."""
    pid: int = 0
    ppid: int = 0
    name: str = ""
    path: str = ""
    session_id: int = 0
    exit_code: int = 0
    priority_class: int = 0
    thread_count: int = 0


class ProcessError(Exception):
    """R3 process module exception."""
    pass


class AccessDeniedError(ProcessError):
    """Win32 error 5."""
    pass


def win32_error():
    err = ctypes_error()
    if err == 5:
        raise AccessDeniedError(f"Access denied (Win32 error {err})")
    raise ProcessError(f"Win32 error {err}")


def ctypes_error():
    import ctypes
    return ctypes.get_last_error() or ctypes.windll.kernel32.GetLastError()