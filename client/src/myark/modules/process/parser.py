"""
process R3 - parser / backend (psapi + toolhelp + kernel32 + advapi32)

R3 implementation, no .sys required. Uses dataclass for data containers
(Python 3.14 ctypes strict typing incompatible with c_wchar field
assignment). Every Win32 call sets ``argtypes`` / ``restype`` explicitly
so the strict ctypes conversion in Python 3.14 does not silently
misinterpret parameter types (that was the source of error 87 from
OpenProcess on the self PID).
"""
import ctypes
import ctypes.wintypes
from typing import List

from .protocol import (
    ProcessRow, ThreadRow, ProcessDetail,
    PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION,
    PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SUSPEND_RESUME,
    THREAD_SUSPEND_RESUME,
    TokenIntegrityLevel, PAGE_READWRITE,
    INTEGRITY_LEVEL_SYSTEM, INTEGRITY_LEVEL_HIGH,
    INTEGRITY_LEVEL_MEDIUM, INTEGRITY_LEVEL_LOW,
    ProcessError, AccessDeniedError, win32_error,
)

# ===== DLL =====
psapi = ctypes.WinDLL("psapi.dll")
kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32
ntdll = ctypes.windll.ntdll

# ===== toolhelp constants =====
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPTHREAD = 0x00000004

# ===== argtypes / restype (Python 3.14 ctypes strict) =====
ULONG_PTR = ctypes.c_size_t
DWORD = ctypes.wintypes.DWORD
BOOL = ctypes.wintypes.BOOL
LPCVOID = ctypes.c_void_p
LPVOID = ctypes.c_void_p
HANDLE = ctypes.wintypes.HANDLE
LPDWORD = ctypes.POINTER(ctypes.wintypes.DWORD)
LPULONG = ctypes.POINTER(ctypes.wintypes.ULONG)
PULONG_PTR = ctypes.POINTER(ULONG_PTR)
LPCWSTR = ctypes.c_wchar_p
LPWSTR = ctypes.c_wchar_p
LPCTSTR = ctypes.c_char_p

kernel32.OpenProcess.argtypes = [DWORD, BOOL, DWORD]
kernel32.OpenProcess.restype = HANDLE

kernel32.CloseHandle.argtypes = [HANDLE]
kernel32.CloseHandle.restype = BOOL

kernel32.CreateToolhelp32Snapshot.argtypes = [DWORD, DWORD]
kernel32.CreateToolhelp32Snapshot.restype = HANDLE

kernel32.Process32FirstW.argtypes = [HANDLE, ctypes.c_void_p]
kernel32.Process32FirstW.restype = BOOL

kernel32.Process32NextW.argtypes = [HANDLE, ctypes.c_void_p]
kernel32.Process32NextW.restype = BOOL

kernel32.Thread32First.argtypes = [HANDLE, ctypes.c_void_p]
kernel32.Thread32First.restype = BOOL

kernel32.Thread32Next.argtypes = [HANDLE, ctypes.c_void_p]
kernel32.Thread32Next.restype = BOOL

kernel32.GetExitCodeProcess.argtypes = [HANDLE, LPDWORD]
kernel32.GetExitCodeProcess.restype = BOOL

kernel32.GetPriorityClass.argtypes = [HANDLE]
kernel32.GetPriorityClass.restype = DWORD

kernel32.QueryFullProcessImageNameW.argtypes = [HANDLE, DWORD, LPWSTR, LPDWORD]
kernel32.QueryFullProcessImageNameW.restype = BOOL

kernel32.ProcessIdToSessionId.argtypes = [DWORD, LPDWORD]
kernel32.ProcessIdToSessionId.restype = BOOL

kernel32.ReadProcessMemory.argtypes = [HANDLE, LPCVOID, LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.ReadProcessMemory.restype = BOOL

kernel32.WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = BOOL

kernel32.TerminateProcess.argtypes = [HANDLE, ctypes.c_uint]
kernel32.TerminateProcess.restype = BOOL

kernel32.OpenThread.argtypes = [DWORD, BOOL, DWORD]
kernel32.OpenThread.restype = HANDLE

kernel32.SuspendThread.argtypes = [HANDLE]
kernel32.SuspendThread.restype = DWORD

kernel32.ResumeThread.argtypes = [HANDLE]
kernel32.ResumeThread.restype = DWORD

kernel32.GetThreadTimes.argtypes = [HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
kernel32.GetThreadTimes.restype = BOOL

kernel32.VirtualAllocEx.argtypes = [HANDLE, LPVOID, ctypes.c_size_t, DWORD, DWORD]
kernel32.VirtualAllocEx.restype = LPVOID

kernel32.VirtualFreeEx.argtypes = [HANDLE, LPVOID, ctypes.c_size_t, DWORD]
kernel32.VirtualFreeEx.restype = BOOL

kernel32.GetProcAddressW = kernel32.GetProcAddress
kernel32.GetProcAddressW.argtypes = [HANDLE, LPCWSTR]
kernel32.GetProcAddressW.restype = LPVOID

kernel32.CreateRemoteThread.argtypes = [HANDLE, ctypes.c_void_p, ctypes.c_size_t, LPVOID, LPVOID, DWORD, LPDWORD]
kernel32.CreateRemoteThread.restype = HANDLE

ntdll.NtQueryInformationProcess.argtypes = [HANDLE, ctypes.c_int, LPVOID, ctypes.c_uint, PULONG_PTR]
ntdll.NtQueryInformationProcess.restype = ctypes.c_long

advapi32.OpenProcessToken.argtypes = [HANDLE, DWORD, ctypes.POINTER(HANDLE)]
advapi32.OpenProcessToken.restype = BOOL

advapi32.SetTokenInformation.argtypes = [HANDLE, ctypes.c_int, LPVOID, DWORD]
advapi32.SetTokenInformation.restype = BOOL


# ===== ctypes structs =====
class PROCESSENTRY32W(ctypes.Structure):
    """toolhelp Process32FirstW structure."""
    _fields_ = [
        ("dwSize", ctypes.c_uint),
        ("cntUsage", ctypes.c_uint),
        ("th32ProcessID", ctypes.c_uint),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", ctypes.c_uint),
        ("cntThreads", ctypes.c_uint),
        ("th32ParentProcessID", ctypes.c_uint),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", ctypes.c_uint),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


class THREADENTRY32(ctypes.Structure):
    """toolhelp Thread32FirstW structure."""
    _fields_ = [
        ("dwSize", ctypes.c_uint),
        ("cntUsage", ctypes.c_uint),
        ("th32ThreadID", ctypes.c_uint),
        ("th32OwnerProcessID", ctypes.c_uint),
        ("tpBasePri", ctypes.c_long),
        ("tpDeltaPri", ctypes.c_long),
        ("dwFlags", ctypes.c_uint),
    ]


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    """NtQueryInformationProcess(ProcessBasicInformation) structure."""
    _fields_ = [
        ("ExitStatus", ctypes.c_uint64),
        ("PebBaseAddress", ctypes.c_uint64),
        ("AffinityMask", ctypes.c_uint64),
        ("BasePriority", ctypes.c_long),
        ("UniqueProcessId", ctypes.c_uint64),
        ("InheritedFromUniqueProcessId", ctypes.c_uint64),
    ]


class TOKEN_MANDATORY_LABEL(ctypes.Structure):
    """TOKEN_MANDATORY_LABEL structure."""
    _fields_ = [
        ("Label", ctypes.c_uint64),  # SID_AND_ATTRIBUTES union; we set Label.Sid.
    ]


def _open_process(pid, access=PROCESS_QUERY_INFORMATION | PROCESS_VM_READ):
    h = kernel32.OpenProcess(access, False, pid)
    if not h:
        win32_error()
    return h


def _close_handle(handle):
    if handle:
        kernel32.CloseHandle(handle)


def enum_processes() -> List[ProcessRow]:
    """List all processes (CreateToolhelp32Snapshot)."""
    h = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    INVALID_HANDLE = ctypes.wintypes.HANDLE(-1).value
    if h == INVALID_HANDLE:
        win32_error()

    entries: List[ProcessRow] = []
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    try:
        if kernel32.Process32FirstW(h, ctypes.byref(entry)):
            while True:
                path = entry.szExeFile
                name = path.rsplit("\\", 1)[-1] if "\\" in path else path
                entries.append(ProcessRow(
                    pid=entry.th32ProcessID,
                    ppid=entry.th32ParentProcessID,
                    name=name,
                    path=path,
                    session_id=_get_session_id(entry.th32ProcessID),
                    thread_count=entry.cntThreads,
                ))
                if not kernel32.Process32NextW(h, ctypes.byref(entry)):
                    break
    finally:
        _close_handle(h)
    return entries


def enum_threads(pid: int) -> List[ThreadRow]:
    """List all threads for a PID."""
    h = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    INVALID_HANDLE = ctypes.wintypes.HANDLE(-1).value
    if h == INVALID_HANDLE:
        win32_error()

    entries: List[ThreadRow] = []
    entry = THREADENTRY32()
    entry.dwSize = ctypes.sizeof(THREADENTRY32)
    try:
        if kernel32.Thread32First(h, ctypes.byref(entry)):
            while True:
                if entry.th32OwnerProcessID == pid:
                    entries.append(ThreadRow(
                        tid=entry.th32ThreadID,
                        owner_pid=entry.th32OwnerProcessID,
                        base_priority=entry.tpBasePri,
                    ))
                if not kernel32.Thread32Next(h, ctypes.byref(entry)):
                    break
    finally:
        _close_handle(h)
    return entries


def process_detail(pid: int) -> ProcessDetail:
    """Get process details (R3 OpenProcess + QueryFullProcessImageNameW).

    Raises ``AccessDeniedError`` on Win32 error 5, ``ProcessError`` on any
    other failure. The CLI handler is responsible for translating those
    into a friendly error message.
    """
    h = _open_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION)
    try:
        exit_code = ctypes.c_uint()
        kernel32.GetExitCodeProcess(h, ctypes.byref(exit_code))

        priority = kernel32.GetPriorityClass(h)

        buf = ctypes.create_unicode_buffer(260)
        size = ctypes.wintypes.DWORD(260)
        if not kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            win32_error()
        path = buf.value
        name = path.rsplit("\\", 1)[-1] if "\\" in path else path

        threads = enum_threads(pid)

        sid = ctypes.c_uint(0)
        kernel32.ProcessIdToSessionId(pid, ctypes.byref(sid))

        return ProcessDetail(
            pid=pid,
            name=name,
            path=path,
            session_id=sid.value,
            exit_code=exit_code.value,
            priority_class=priority,
            thread_count=len(threads),
        )
    finally:
        _close_handle(h)


def read_process_memory(pid: int, addr: int, size: int) -> bytes:
    """Read process virtual memory (R3 ReadProcessMemory).

    Raises ``AccessDeniedError`` on Win32 error 5 (caller has insufficient
    rights to open the target process). Returns whatever bytes the kernel
    was willing to copy if the read is partially satisfied.
    """
    h = _open_process(pid, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)
    try:
        if addr == 0:
            pbi = PROCESS_BASIC_INFORMATION()
            ret = ntdll.NtQueryInformationProcess(
                h, 0,
                ctypes.byref(pbi),
                ctypes.sizeof(pbi),
                None,
            )
            if ret != 0:
                raise ProcessError(f"NtQueryInformationProcess failed (status {ret})")
            addr = pbi.PebBaseAddress

        buf = (ctypes.c_ubyte * size)()
        got = ctypes.c_size_t(0)
        if not kernel32.ReadProcessMemory(h, addr, buf, size, ctypes.byref(got)):
            win32_error()
        actual = min(got.value, size)
        return bytes(buf[:actual])
    finally:
        _close_handle(h)


def terminate_process(pid: int, exit_code: int = 1):
    """Terminate process (R3 TerminateProcess)."""
    h = _open_process(pid, PROCESS_TERMINATE)
    try:
        if not kernel32.TerminateProcess(h, exit_code):
            win32_error()
    finally:
        _close_handle(h)


def suspend_thread(tid: int) -> int:
    """Suspend a thread."""
    h = kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, tid)
    if not h:
        win32_error()
    try:
        prev = kernel32.SuspendThread(h)
        if prev == ctypes.c_uint(-1).value:
            win32_error()
        return prev
    finally:
        _close_handle(h)


def resume_thread(tid: int) -> int:
    """Resume a thread."""
    h = kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, tid)
    if not h:
        win32_error()
    try:
        prev = kernel32.ResumeThread(h)
        if prev == ctypes.c_uint(-1).value:
            win32_error()
        return prev
    finally:
        _close_handle(h)


def set_integrity_level(pid: int, level: int):
    """Set process integrity level (admin only).

    Build a minimal TOKEN_MANDATORY_LABEL whose embedded SID carries the
    requested integrity sub-authority. The SID layout is the standard
    NT-authority SID: Revision=1, SubAuthCount=1, IdentifierAuthority =
    SECURITY_NT_AUTHORITY (5), SubAuthority[0] = level. The owner
    attributes DWORD stays zero.
    """
    h = _open_process(pid, PROCESS_QUERY_INFORMATION)
    try:
        token = HANDLE()
        if not advapi32.OpenProcessToken(h, 0x0080, ctypes.byref(token)):
            win32_error()
        try:
            # Build SID: header(8 bytes) + 1 subauthority(4 bytes) = 12 bytes.
            # SECURITY_MANDATORY_LABEL_AUTHORITY = {0,0,0,0,0,16}; full SID
            # is S-1-16-<level>.
            sid_buf = (ctypes.c_ubyte * 12)(
                1,                       # Revision
                1,                       # SubAuthorityCount
                0, 0, 0, 0, 0, 16,       # IdentifierAuthority
                0, 0, 0, 0,              # SubAuthority[0] (filled below)
            )
            ctypes.memmove(
                ctypes.addressof(sid_buf) + 8,
                ctypes.byref(ctypes.c_uint32(level & 0xFFFFFFFF)),
                4,
            )

            # TOKEN_MANDATORY_LABEL = {SID_AND_ATTRIBUTES Label}; on x64
            # SID_AND_ATTRIBUTES = {PSID Sid; DWORD Attributes;}, padded to
            # 16 bytes. We embed the SID pointer at offset 0 and leave the
            # attributes DWORD zero.
            label_buf = (ctypes.c_ubyte * 16)()
            ctypes.memset(label_buf, 0, 16)
            sid_ptr = ctypes.cast(sid_buf, ctypes.c_void_p).value
            ctypes.memmove(
                ctypes.addressof(label_buf),
                ctypes.byref(ctypes.c_uint64(sid_ptr & 0xFFFFFFFFFFFFFFFF)),
                8,
            )

            ok = advapi32.SetTokenInformation(
                token, TokenIntegrityLevel,
                ctypes.cast(label_buf, ctypes.c_void_p),
                16,
            )
            if not ok:
                win32_error()
        finally:
            _close_handle(token)
    finally:
        _close_handle(h)


def inject_dll(pid: int, dll_path: str) -> int:
    """Inject DLL (R3 CreateRemoteThread + LoadLibraryW)."""
    h = _open_process(
        pid,
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
    )
    try:
        # LoadLibraryW takes a wide-char string in the target process. Encode
        # as UTF-16-LE + NUL terminator.
        path_bytes = dll_path.encode("utf-16-le") + b"\x00\x00"
        path_len = len(path_bytes)
        remote_mem = kernel32.VirtualAllocEx(h, None, path_len, 0x3000, PAGE_READWRITE)
        if not remote_mem:
            win32_error()
        try:
            written = ctypes.c_size_t(0)
            if not kernel32.WriteProcessMemory(h, remote_mem, path_bytes, path_len, ctypes.byref(written)):
                win32_error()

            # Resolve LoadLibraryW via ctypes' own attribute lookup --
            # GetProcAddress on a WinDLL handle trips Python 3.14 strict
            # ctypes' HANDLE conversion (overflow on the module base).
            load_library = ctypes.cast(kernel32.LoadLibraryW, ctypes.c_void_p).value
            if not load_library:
                raise ProcessError("Failed to find LoadLibraryW")

            thread_id = ctypes.wintypes.DWORD(0)
            handle = kernel32.CreateRemoteThread(
                h, None, 0, load_library, remote_mem, 0, ctypes.byref(thread_id)
            )
            if not handle:
                win32_error()
            _close_handle(handle)
            return thread_id.value
        finally:
            kernel32.VirtualFreeEx(h, remote_mem, 0, 0x8000)
    finally:
        _close_handle(h)


def _get_session_id(pid: int) -> int:
    sid = ctypes.c_uint(0)
    if kernel32.ProcessIdToSessionId(pid, ctypes.byref(sid)):
        return sid.value
    return 0


__all__ = [
    "enum_processes",
    "enum_threads",
    "process_detail",
    "read_process_memory",
    "terminate_process",
    "suspend_thread",
    "resume_thread",
    "set_integrity_level",
    "inject_dll",
    "_get_session_id",
]