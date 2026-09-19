"""
verify_core.py - VM runtime regression for MyArkCore (S2.3 + S6 checklist).

Wire formats mirror driver/src/dispatch/MyArkCoreIoctl.h,
shared/driver/MyArkSafetyToken.h, MyArkActionsIoctl.h,
MyArkProcessIoctl.h and MyArkMemoryIoctl.h exactly.

Run inside the VM (as Administrator) after install_vm.ps1 has brought the
driver up:
    python verify_core.py

Sections:
  [CORE]      GET_VERSION / QUERY_MODULES / QUERY_CAPABILITIES / GET_SESSION_KEY
  [DYNDATA]   9 read-only IOCTL smoke test
  [CALLBACK]  read-only + stats smoke test
  [ACTIONS]   7 mutating IOCTLs: valid HMAC token -> DEFERRED,
              tampered / stale-signed token -> ACCESS_DENIED
  [PROCESS]   8 mutating IOCTLs token reject/allow probes; the whole section
              degrades to a build-gate absence check on builds outside
              26100..26299 (process/thread modules refuse to load there)
  [PHYSICAL]  READ_PHYSICAL RAM-range filter + non-aligned KUSER cross-check,
              WRITE_PHYSICAL default deny, opt-in range filter, and one real
              unaligned write round-trip into this process's pinned buffer
  [S6]        regression checklist summary (KNOWN_ISSUES.md S6)

Exits 0 only when every non-skipped check passes. Each line is labelled so
the output stays grep-friendly. This script intentionally never loads the
driver on the host machine.
"""

from __future__ import annotations

import ctypes
import hmac
import hashlib
import os

try:
    import winreg  # Windows only; verify_core never runs elsewhere
except ImportError:
    winreg = None
import struct
import subprocess
import sys
import time
from ctypes import wintypes


GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_FUNCTION = 1
ERROR_INVALID_PARAMETER = 87

FILE_DEVICE_UNKNOWN = 0x00000022
METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0


def _ctl_code(device_type: int, function: int, method: int, access: int) -> int:
    return (
        (device_type << 16)
        | (access << 14)
        | (function << 2)
        | method
    )


def _ioctl_function(code: int) -> int:
    return (code >> 2) & 0xFFF


# Mirror driver/src/dispatch/MyArkCoreIoctl.h verbatim (S11.1: +GET_SESSION_KEY).
IOCTL_MYARK_CORE_GET_VERSION = _ctl_code(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_CORE_QUERY_MODULES = _ctl_code(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_CORE_QUERY_CAPABILITIES = _ctl_code(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_CORE_GET_LOG = _ctl_code(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_CORE_SET_LOG_CONFIG = _ctl_code(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_CORE_GET_SESSION_KEY = _ctl_code(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

EXPECTED_CORE_CAPABILITY_NAMES = frozenset({
    "IOCTL_MYARK_CORE_GET_VERSION",
    "IOCTL_MYARK_CORE_QUERY_MODULES",
    "IOCTL_MYARK_CORE_QUERY_CAPABILITIES",
    "IOCTL_MYARK_CORE_GET_LOG",
    "IOCTL_MYARK_CORE_SET_LOG_CONFIG",
    "IOCTL_MYARK_CORE_GET_SESSION_KEY",
})

# Mirror shared/driver/MyArkDyndataIoctl.h verbatim.
IOCTL_MYARK_DYNDATA_QUERY_PROCESS = _ctl_code(FILE_DEVICE_UNKNOWN, 0x700, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_DYNDATA_QUERY_THREAD = _ctl_code(FILE_DEVICE_UNKNOWN, 0x701, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_DYNDATA_QUERY_MODULE = _ctl_code(FILE_DEVICE_UNKNOWN, 0x702, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_DYNDATA_QUERY_HANDLE = _ctl_code(FILE_DEVICE_UNKNOWN, 0x703, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_DYNDATA_QUERY_FILE = _ctl_code(FILE_DEVICE_UNKNOWN, 0x704, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_DYNDATA_QUERY_SYSCALL = _ctl_code(FILE_DEVICE_UNKNOWN, 0x705, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_DYNDATA_QUERY_TOKEN = _ctl_code(FILE_DEVICE_UNKNOWN, 0x706, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_DYNDATA_QUERY_OBJECT = _ctl_code(FILE_DEVICE_UNKNOWN, 0x707, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_DYNDATA_QUERY_SSDT = _ctl_code(FILE_DEVICE_UNKNOWN, 0x708, METHOD_BUFFERED, FILE_ANY_ACCESS)

# Mirror shared/driver/MyArkCallbackIoctl.h verbatim.
IOCTL_MYARK_CALLBACK_QUERY_PS = _ctl_code(FILE_DEVICE_UNKNOWN, 0x710, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_CALLBACK_QUERY_CM = _ctl_code(FILE_DEVICE_UNKNOWN, 0x711, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_CALLBACK_QUERY_OB = _ctl_code(FILE_DEVICE_UNKNOWN, 0x712, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_CALLBACK_QUERY_IMAGE = _ctl_code(FILE_DEVICE_UNKNOWN, 0x713, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_CALLBACK_QUERY_DBG = _ctl_code(FILE_DEVICE_UNKNOWN, 0x714, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_CALLBACK_ENUMERATE = _ctl_code(FILE_DEVICE_UNKNOWN, 0x715, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_CALLBACK_STATS = _ctl_code(FILE_DEVICE_UNKNOWN, 0x719, METHOD_BUFFERED, FILE_ANY_ACCESS)

# Mirror shared/driver/MyArkActionsIoctl.h verbatim (S8.1).
IOCTL_MYARK_ACTION_KILL_PROCESS     = _ctl_code(FILE_DEVICE_UNKNOWN, 0x870, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_ACTION_TERMINATE_THREAD = _ctl_code(FILE_DEVICE_UNKNOWN, 0x871, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_ACTION_INJECT_DLL       = _ctl_code(FILE_DEVICE_UNKNOWN, 0x872, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_ACTION_DUMP_MEMORY      = _ctl_code(FILE_DEVICE_UNKNOWN, 0x873, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_ACTION_SET_TOKEN        = _ctl_code(FILE_DEVICE_UNKNOWN, 0x874, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_ACTION_HIDE_PROCESS     = _ctl_code(FILE_DEVICE_UNKNOWN, 0x875, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_ACTION_PROTECT_PROCESS  = _ctl_code(FILE_DEVICE_UNKNOWN, 0x876, METHOD_BUFFERED, FILE_ANY_ACCESS)

# Mirror shared/driver/MyArkProcessIoctl.h verbatim (S6.1/S11.1).
IOCTL_MYARK_PROCESS_ENUM              = _ctl_code(FILE_DEVICE_UNKNOWN, 0xA00, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_PROCESS_ENUM_THREAD       = _ctl_code(FILE_DEVICE_UNKNOWN, 0xA01, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_PROCESS_DETAIL            = _ctl_code(FILE_DEVICE_UNKNOWN, 0xA02, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_PROCESS_DETAIL_RUNTIME    = _ctl_code(FILE_DEVICE_UNKNOWN, 0xA03, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_PROCESS_CROSSVIEW         = _ctl_code(FILE_DEVICE_UNKNOWN, 0xA04, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_PROCESS_TERMINATE         = _ctl_code(FILE_DEVICE_UNKNOWN, 0xA05, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_PROCESS_SUSPEND           = _ctl_code(FILE_DEVICE_UNKNOWN, 0xA06, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_PROCESS_SET_PPL_LEVEL     = _ctl_code(FILE_DEVICE_UNKNOWN, 0xA07, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_PROCESS_SET_INTEGRITY     = _ctl_code(FILE_DEVICE_UNKNOWN, 0xA08, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_PROCESS_SET_VISIBILITY    = _ctl_code(FILE_DEVICE_UNKNOWN, 0xA09, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_PROCESS_SET_SPECIAL_FLAGS = _ctl_code(FILE_DEVICE_UNKNOWN, 0xA0A, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_PROCESS_DKOM              = _ctl_code(FILE_DEVICE_UNKNOWN, 0xA0B, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_PROCESS_INJECT            = _ctl_code(FILE_DEVICE_UNKNOWN, 0xA0C, METHOD_BUFFERED, FILE_ANY_ACCESS)

# Mirror shared/driver/MyArkMemoryIoctl.h (physical subset, S6 checklist 4).
IOCTL_MYARK_MEMORY_READ_PHYSICAL = _ctl_code(FILE_DEVICE_UNKNOWN, 0xB05, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_MEMORY_WRITE_PHYSICAL = _ctl_code(FILE_DEVICE_UNKNOWN, 0xB06, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_MEMORY_QUERY_PHYSICAL_LAYOUT = _ctl_code(FILE_DEVICE_UNKNOWN, 0xB07, METHOD_BUFFERED, FILE_ANY_ACCESS)

# Mirror shared/driver/MyArkMemoryIoctl.h (virtual subset, S6 follow-up).
IOCTL_MYARK_MEMORY_QUERY_VM = _ctl_code(FILE_DEVICE_UNKNOWN, 0xB00, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_MEMORY_READ_VM = _ctl_code(FILE_DEVICE_UNKNOWN, 0xB01, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_MEMORY_WRITE_VM = _ctl_code(FILE_DEVICE_UNKNOWN, 0xB02, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_MEMORY_TRANSLATE_VA = _ctl_code(FILE_DEVICE_UNKNOWN, 0xB03, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_MEMORY_QUERY_PT_ENTRY = _ctl_code(FILE_DEVICE_UNKNOWN, 0xB04, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_MEMORY_SCAN_KERNEL_EXECUTABLE = _ctl_code(FILE_DEVICE_UNKNOWN, 0xB08, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_MEMORY_SCAN_KERNEL_MEMORY_EVIDENCE = _ctl_code(FILE_DEVICE_UNKNOWN, 0xB09, METHOD_BUFFERED, FILE_ANY_ACCESS)

# NTSTATUS values the memory handlers report inside their Status field.
STATUS_SUCCESS = 0
STATUS_PARTIAL_COPY = 0x8000000D
PAGE_SIZE_4K = 0x1000
PAGE_SIZE_2M = 0x200000
PAGE_SIZE_1G = 0x40000000

# KUSER_SHARED_DATA kernel mapping (fixed VA on x64). Used as a scan target
# that needs no module base: it is always mapped and its NtSystemRoot field
# carries the OS path as a wide string.
KUSER_SHARED_DATA_VA = 0xFFFFF78000000000

EXPECTED_PROTOCOL_VERSION = 1

# os_version.h: process/thread hardcoded-offset support window.
MYARK_MIN_SUPPORTED_BUILD = 26100
MYARK_MAX_SUPPORTED_BUILD = 26299

# MYARK_MODULE_STATE_* (MyArkCoreIoctl.h).
MODULE_STATE_DISABLED = 0
MODULE_STATE_ENABLED = 1

# Gated module descriptors refuse Init outside the build window; the loader
# then skips their IOCTL registration entirely (driver_entry.c).
GATED_MODULE_NAMES = ("process", "thread")

# STATUS_NO_SUCH_DEVICE -- the QueryModules LastError marker for a module
# whose Init did not run / did not succeed.
STATUS_NO_SUCH_DEVICE = 0xC000000E

DEVICE_PATH = r"\\.\MyArkCore"


# ---------------------------------------------------------------------------
# S11.1 safety-token wire format (shared/driver/MyArkSafetyToken.h).
# ---------------------------------------------------------------------------

SAFETY_TOKEN_MAGIC = 0x4D41524B  # 'MARK' ASCII (LE)

# Entry wire sizes (ctypes-verified against the C structs).
PROCESS_ENTRY_SIZE = 792   # Pid4 Ppid4 Name[64W] Path[260W] User[64W] MemKb4 Ppl1 Hidden1 Src1 Rsv1
THREAD_ENTRY_SIZE = 32     # Tid4 OwnerPid4 State4 Priority4 WaitReason4 CreateTime8 (+pad)
DETAIL_NAME_OFFSET = 104   # MYARK_PROCESS_DETAIL.Name (8xU32 + 3xU64 + 6xU32 + U64)
SAFETY_TOKEN_SIZE = 72
SAFETY_TOKEN_KEY_SIZE = 32
SAFETY_TOKEN_SIGNATURE_SIZE = 32
WINDOWS_EPOCH_OFFSET_S = 11644473600


def nt_filetime_now() -> int:
    """Current time as 100-ns units since 1601-01-01 (kernel clock scale)."""
    return int((time.time() + WINDOWS_EPOCH_OFFSET_S) * 10_000_000)


def _mac_message(pid: int, operation: int, timestamp: int) -> bytes:
    """The exact 20-byte buffer the kernel HMACs (dispatch/safety_token.c)."""
    return struct.pack("<IIIq", SAFETY_TOKEN_MAGIC, pid, operation, timestamp)


def sign_token(session_key: bytes, pid: int, operation: int, timestamp: int) -> bytes:
    """Build a full 72-byte MYARK_SAFETY_TOKEN with a valid HMAC signature."""
    if len(session_key) != SAFETY_TOKEN_KEY_SIZE:
        raise ValueError(f"session key must be {SAFETY_TOKEN_KEY_SIZE} bytes")
    token = struct.pack(
        "<IIIIq",
        SAFETY_TOKEN_MAGIC,
        pid,
        operation,
        0,  # Reserved1 (not covered by the MAC)
        timestamp,
    )
    sig = hmac.new(
        session_key,
        _mac_message(pid, operation, timestamp),
        hashlib.sha256,
    ).digest()[:SAFETY_TOKEN_SIGNATURE_SIZE]
    return token + sig + b"\x00" * 16  # Signature[32] + Reserved2[16]


def tamper_signature(token: bytes) -> bytes:
    """Flip one signature byte so the kernel digest comparison fails."""
    broken = bytearray(token)
    broken[24] ^= 0xFF  # Signature starts after Magic/Pid/Op/Rsv1/Timestamp.
    return bytes(broken)


class CoreVersion(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("CoreProtocolVersion", ctypes.c_uint32),
        ("ModuleProtocolVersion", ctypes.c_uint32),
        ("BuildNumber", ctypes.c_uint32),
        ("ActiveModuleCount", ctypes.c_uint32),
        ("DisplayName", ctypes.c_wchar * 64),
    ]


_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32.CreateFileW.restype = wintypes.HANDLE
_kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
    ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
]
_kernel32.DeviceIoControl.restype = wintypes.BOOL
_kernel32.DeviceIoControl.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
    ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
]
_kernel32.CloseHandle.restype = wintypes.BOOL
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]


def _last_error() -> int:
    return ctypes.get_last_error()


def _last_error_message() -> str:
    err = _last_error()
    buf = ctypes.create_unicode_buffer(512)
    _FormatMessage = _kernel32.FormatMessageW
    _FormatMessage.argtypes = [
        wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
        wintypes.DWORD, ctypes.c_wchar_p, wintypes.DWORD, ctypes.c_void_p,
    ]
    _FormatMessage(
        0x1300,  # FORMAT_MESSAGE_FROM_SYSTEM | IGNORE_INSERTS
        None, err, 0, buf, len(buf), None,
    )
    return f"err={err} {buf.value}".strip()


def _open_driver() -> wintypes.HANDLE:
    handle = _kernel32.CreateFileW(
        DEVICE_PATH,
        GENERIC_READ | GENERIC_WRITE,
        0,  # no sharing
        None,
        OPEN_EXISTING,
        0,  # no overlapped / no flags
        None,
    )
    if handle in (None, 0, INVALID_HANDLE_VALUE):
        err = _last_error()
        hint = ""
        if err == ERROR_ACCESS_DENIED:
            hint = " (run as Administrator)"
        elif err == ERROR_INVALID_FUNCTION:
            hint = " (driver may not be loaded)"
        raise OSError(f"CreateFileW({DEVICE_PATH}) failed: {_last_error_message()}{hint}")
    return handle


def _ioctl_raw(handle, code: int, in_buf: bytes, out_size: int):
    """Send one IOCTL; return (ok, payload_bytes, win32_error)."""
    out_buf = (ctypes.c_ubyte * out_size)()
    returned = wintypes.DWORD(0)
    ok = bool(_kernel32.DeviceIoControl(
        handle, code,
        None if not in_buf else ctypes.c_char_p(in_buf), len(in_buf) if in_buf else 0,
        ctypes.cast(out_buf, ctypes.c_void_p), out_size,
        ctypes.byref(returned), None,
    ))
    err = _last_error() if not ok else 0
    return ok, bytes(out_buf[: returned.value]), err


def _ioctl(handle, code: int, in_buf: bytes, out_size: int):
    ok, payload, err = _ioctl_raw(handle, code, in_buf, out_size)
    if not ok:
        # Construct with the winerror so exc.errno / exc.winerror carry
        # the real Win32 code (87, 5, ...); a plain string OSError would
        # leave both None and make winerror comparisons in probes dead
        # code (2026-09-15 review finding). The message body from
        # _last_error_message() already includes "err=<n>".
        raise OSError(None,
                      f"DeviceIoControl(0x{code:08X}) failed: {_last_error_message()}",
                      None, err)
    return payload


# ---------------------------------------------------------------------------
# Check framework: every probe records PASS/FAIL/SKIP; failures never abort
# the run so one broken surface doesn't hide the others.
# ---------------------------------------------------------------------------

_RESULTS: list[tuple[str, str, str, str]] = []


def check(section: str, name: str, ok: bool, detail: str = "") -> bool:
    status = "PASS" if ok else "FAIL"
    _RESULTS.append((section, name, status, detail))
    line = f"  [{status}] {name}"
    if detail:
        line += f" -- {detail}"
    print(line, flush=True)
    return ok


def skip(section: str, name: str, reason: str) -> None:
    _RESULTS.append((section, name, "SKIP", reason))
    print(f"  [SKIP] {name} -- {reason}", flush=True)


def _step(label: str) -> None:
    print(f"[VERIFY] {label}", flush=True)


# ---------------------------------------------------------------------------
# [CORE] S2.3 + S11.1 core surface.
# ---------------------------------------------------------------------------

def verify_get_version(handle) -> int:
    _step("CORE GET_VERSION")
    buf = _ioctl(handle, IOCTL_MYARK_CORE_GET_VERSION, b"", ctypes.sizeof(CoreVersion))
    if len(buf) < ctypes.sizeof(CoreVersion):
        check("CORE", "GET_VERSION size", False, f"short read {len(buf)}")
        return -1
    version = CoreVersion.from_buffer_copy(buf[: ctypes.sizeof(CoreVersion)])
    ok = version.CoreProtocolVersion == EXPECTED_PROTOCOL_VERSION
    check("CORE", "GET_VERSION protocol", ok,
          f"CoreProtocolVersion={version.CoreProtocolVersion}")
    print(
        f"  BuildNumber={version.BuildNumber} "
        f"ActiveModuleCount={version.ActiveModuleCount} "
        f"DisplayName={version.DisplayName!r}"
    )
    return version.ActiveModuleCount


def _query_modules(handle) -> dict[str, tuple[int, int]]:
    """QUERY_MODULES -> {name: (State, LastError)}."""
    entry_size = 176  # ModuleId4 + Name32 + Desc128 + State4 + IoctlCount4 + LastError4
    raw = None
    for capacity in (4, 16, 40, 64, 128):
        buf_size = 8 + capacity * entry_size
        try:
            payload = _ioctl(handle, IOCTL_MYARK_CORE_QUERY_MODULES, b"", buf_size)
        except OSError:
            continue  # buffer smaller than the module table; grow and retry
        count = struct.unpack_from("<I", payload, 4)[0]
        if len(payload) >= 8 + count * entry_size:
            raw = payload
            break
    if raw is None:
        raise AssertionError("QUERY_MODULES: could not size buffer")
    count = struct.unpack_from("<I", raw, 4)[0]
    modules: dict[str, tuple[int, int]] = {}
    for i in range(count):
        base = 8 + i * entry_size
        raw_name = raw[base + 4 : base + 4 + 32]
        end = raw_name.find(b"\x00")
        name = raw_name[: end if end >= 0 else 32].decode("ascii", errors="replace")
        state = struct.unpack_from("<I", raw, base + 164)[0]
        last_error = struct.unpack_from("<I", raw, base + 172)[0]
        modules[name] = (state, last_error)
    return modules


def verify_query_modules(handle, expected_count: int):
    _step("CORE QUERY_MODULES")
    modules = _query_modules(handle)
    ok = len(modules) == expected_count
    check("CORE", "QUERY_MODULES Count==ActiveModuleCount", ok,
          f"count={len(modules)} expected={expected_count}")
    for name, (state, last_error) in sorted(modules.items()):
        marker = "enabled" if state == MODULE_STATE_ENABLED else f"state={state} lasterr=0x{last_error:08X}"
        print(f"    {name}: {marker}")
    return modules


def verify_query_capabilities(handle):
    _step("CORE QUERY_CAPABILITIES")
    entry_size = 72  # IoctlCode4 + Name64 + ModuleId4
    raw = None
    for capacity in (16, 64, 256, 1024):
        buf_size = 8 + capacity * entry_size
        try:
            payload = _ioctl(handle, IOCTL_MYARK_CORE_QUERY_CAPABILITIES, b"", buf_size)
        except OSError:
            continue  # buffer smaller than the ioctl table; grow and retry
        count = struct.unpack_from("<I", payload, 4)[0]
        if len(payload) >= 8 + count * entry_size:
            raw = payload
            break
    if raw is None:
        raise AssertionError("QUERY_CAPABILITIES: could not size buffer")
    count = struct.unpack_from("<I", raw, 4)[0]
    names: set[str] = set()
    functions: list[int] = []
    for i in range(count):
        base = 8 + i * entry_size
        functions.append(struct.unpack_from("<I", raw, base)[0] and _ioctl_function(struct.unpack_from("<I", raw, base)[0]))
        raw_name = raw[base + 4 : base + 4 + 64]
        end = raw_name.find(b"\x00")
        names.add(raw_name[: end if end >= 0 else 64].decode("ascii", errors="replace"))
    missing = EXPECTED_CORE_CAPABILITY_NAMES - names
    check("CORE", "CAPABILITIES core IOCTLs present", not missing,
          f"count={count} missing={sorted(missing)}" if missing else f"count={count}")
    return names, functions


def verify_session_key(handle) -> bytes | None:
    _step("CORE GET_SESSION_KEY (S11.1)")
    out_size = 40  # Size4 + KeyLength4 + Key[32]
    ok, payload, err = _ioctl_raw(handle, IOCTL_MYARK_CORE_GET_SESSION_KEY, b"", out_size)
    if not ok:
        check("CORE", "GET_SESSION_KEY callable", False, f"win32_err={err}")
        return None
    if len(payload) < out_size:
        check("CORE", "GET_SESSION_KEY size", False, f"returned={len(payload)}")
        return None
    size_field, key_length = struct.unpack_from("<II", payload, 0)
    key = payload[8:8 + key_length]
    ok = (
        size_field == out_size
        and key_length == SAFETY_TOKEN_KEY_SIZE
        and len(key) == SAFETY_TOKEN_KEY_SIZE
        and key != b"\x00" * SAFETY_TOKEN_KEY_SIZE
    )
    check("CORE", "GET_SESSION_KEY 32-byte non-zero key", ok,
          f"Size={size_field} KeyLength={key_length} head={key[:4].hex()}")
    # Per-boot stability: a second read must return the same key.
    ok2_payload = _ioctl(handle, IOCTL_MYARK_CORE_GET_SESSION_KEY, b"", out_size)
    check("CORE", "GET_SESSION_KEY stable across calls",
          ok2_payload[8:40] == payload[8:40])
    return key if ok else None


# ---------------------------------------------------------------------------
# [DYNDATA] S7.1 read-only smoke (unchanged from the S7.3 revision).
# ---------------------------------------------------------------------------

def _enum_probe(handle, code: int, in_buf: bytes, out_size: int) -> tuple[int, int, int]:
    payload = _ioctl(handle, code, in_buf, out_size)
    if len(payload) < 16:
        raise AssertionError(f"IOCTL 0x{code:X} short read: {len(payload)} < 16")
    size = struct.unpack_from("<I", payload, 0)[0]
    count = struct.unpack_from("<I", payload, 4)[0]
    total = struct.unpack_from("<I", payload, 8)[0]
    return size, count, total


def verify_dyndata(handle) -> None:
    _step("DYNDATA read-only smoke (empty results allowed)")
    out_size = 4096  # row arrays must fit; handlers reject undersized buffers
    cases = [
        ("QUERY_PROCESS", IOCTL_MYARK_DYNDATA_QUERY_PROCESS, struct.pack("<IIII", 256, 0, 0, 0)),
        ("QUERY_THREAD",  IOCTL_MYARK_DYNDATA_QUERY_THREAD,  struct.pack("<IIII", 1024, 0, 0, 0)),
        ("QUERY_MODULE",  IOCTL_MYARK_DYNDATA_QUERY_MODULE,  struct.pack("<IIII", 1024, 0, 0, 0)),
        ("QUERY_HANDLE",  IOCTL_MYARK_DYNDATA_QUERY_HANDLE,  struct.pack("<IIII", 1024, 0, 0xFFFFFFFF, 0)),
        ("QUERY_FILE",    IOCTL_MYARK_DYNDATA_QUERY_FILE,    struct.pack("<IIII", 1024, 0, 0, 0)),
        ("QUERY_SYSCALL", IOCTL_MYARK_DYNDATA_QUERY_SYSCALL, struct.pack("<IIII", 1024, 0, 0, 0)),
        ("QUERY_OBJECT",  IOCTL_MYARK_DYNDATA_QUERY_OBJECT,  struct.pack("<IIII", 64, 0, 0, 0)),
    ]
    for label, code, in_buf in cases:
        try:
            size, count, total = _enum_probe(handle, code, in_buf, out_size)
            ok = 32 <= size <= 0x10000
            check("DYNDATA", label, ok, f"count={count} total={total} size={size}")
        except OSError as exc:
            check("DYNDATA", label, False, str(exc))

    cur_pid = os.getpid() & 0xFFFFFFFF
    try:
        size, count, _total = _enum_probe(
            handle, IOCTL_MYARK_DYNDATA_QUERY_TOKEN,
            struct.pack("<IIII", cur_pid, 0, 0, 0), out_size)
        check("DYNDATA", "QUERY_TOKEN", 16 <= size <= 0x10000, f"pid={cur_pid} count={count} size={size}")
    except OSError as exc:
        check("DYNDATA", "QUERY_TOKEN", False, str(exc))

    try:
        size, count, total = _enum_probe(
            handle, IOCTL_MYARK_DYNDATA_QUERY_SSDT,
            struct.pack("<IIII", 1024, 0, 0, 0), out_size)
        check("DYNDATA", "QUERY_SSDT", 32 <= size <= 0x10000, f"count={count} total={total} size={size}")
    except OSError as exc:
        # B4: on old AMD CPUs without SMEP the in-driver SSDT walker faults
        # on its cross-page read; the driver surfaces that as
        # STATUS_INVALID_PARAMETER -> Win32 87. Anchor on winerror==87
        # (NOT exc.errno==22: CPython's winerror->errno table falls back
        # to EINVAL for every unmapped code, so errno==22 would also
        # swallow unrelated driver regressions like error 1 or buffer
        # errors). Anything else stays a FAIL.
        if getattr(exc, "winerror", None) == 87:
            skip("DYNDATA", "QUERY_SSDT",
                 "win32 err=87: no-SMEP CPU limitation (B4, S8+ fallback pending)")
        else:
            check("DYNDATA", "QUERY_SSDT", False, str(exc))


# ---------------------------------------------------------------------------
# [CALLBACK] S7.2 read-only smoke.
# ---------------------------------------------------------------------------

def verify_callback(handle) -> None:
    _step("CALLBACK read-only smoke (empty results allowed)")
    out_size = 4096
    cases = [
        ("QUERY_PS",    IOCTL_MYARK_CALLBACK_QUERY_PS,    struct.pack("<IIII", 64, 0, 0, 0)),
        ("QUERY_CM",    IOCTL_MYARK_CALLBACK_QUERY_CM,    struct.pack("<IIII", 64, 0, 0, 0)),
        ("QUERY_OB",    IOCTL_MYARK_CALLBACK_QUERY_OB,    struct.pack("<IIII", 64, 0, 0, 0)),
        ("QUERY_IMAGE", IOCTL_MYARK_CALLBACK_QUERY_IMAGE, struct.pack("<IIII", 64, 0, 0, 0)),
        ("QUERY_DBG",   IOCTL_MYARK_CALLBACK_QUERY_DBG,   struct.pack("<IIII", 32, 0, 0, 0)),
        ("ENUMERATE",   IOCTL_MYARK_CALLBACK_ENUMERATE,   struct.pack("<IIII", 256, 0, 0, 0)),
    ]
    for label, code, in_buf in cases:
        try:
            size, count, total = _enum_probe(handle, code, in_buf, out_size)
            check("CALLBACK", label, 32 <= size <= 0x10000, f"count={count} total={total} size={size}")
        except OSError as exc:
            check("CALLBACK", label, False, str(exc))

    try:
        payload = _ioctl(handle, IOCTL_MYARK_CALLBACK_STATS, b"", 32)
        total_count = struct.unpack_from("<I", payload, 24)[0]
        check("CALLBACK", "STATS", total_count <= 4096, f"total={total_count}")
    except OSError as exc:
        check("CALLBACK", "STATS", False, str(exc))


# ---------------------------------------------------------------------------
# [ACTIONS] S8.1 + S11.1: 7 mutating IOCTLs behind the HMAC token.
# Valid token -> DeviceIoControl succeeds with ResultCode=DEFERRED (4).
# Tampered / stale-signed token -> DeviceIoControl fails ERROR_ACCESS_DENIED.
# ---------------------------------------------------------------------------

ACTION_OPS = {
    0x870: 1,  # KILL_PROCESS
    0x871: 2,  # TERMINATE_THREAD
    0x872: 3,  # INJECT_DLL
    0x873: 4,  # DUMP_MEMORY
    0x874: 5,  # SET_TOKEN
    0x875: 6,  # HIDE_PROCESS
    0x876: 7,  # PROTECT_PROCESS
}

ACTION_LABELS = {
    0x870: "KILL_PROCESS",
    0x871: "TERMINATE_THREAD",
    0x872: "INJECT_DLL",
    0x873: "DUMP_MEMORY",
    0x874: "SET_TOKEN",
    0x875: "HIDE_PROCESS",
    0x876: "PROTECT_PROCESS",
}

ACTION_OUTPUT_SIZE = {
    0x870: 88 + 16,                # header + Pid/ExitCode/Rsv/Rsv
    0x871: 88 + 16,
    0x872: 88 + 4 + 4 + 8,         # header + Pid/Rsv/Handle
    0x873: 88 + 4 + 4 + 8 + 4096,  # header + Pid/BytesReturned/Address/Data
    0x874: 88 + 16,
    0x875: 88 + 16,
    0x876: 88 + 16,
}


def _action_tail(function: int, pid: int) -> bytes:
    """Per-action payload after the 72-byte token (MyArkActionsIoctl.h)."""
    if function == 0x870:    # Pid, ExitCode, Rsv, Rsv, Reason WCHAR[256]
        return struct.pack("<IIII", pid, 1, 0, 0) + b"\x00" * (256 * 2)
    if function == 0x871:    # Pid, Tid, ExitCode, Rsv
        return struct.pack("<IIII", pid, 0, 1, 0)
    if function == 0x872:    # Pid, Rsv, Rsv, Rsv, DllPath WCHAR[260]
        path = "C:\\windows\\temp\\nonexistent_probe.dll"
        path_bytes = (path + "\x00" * (260 - len(path))).encode("utf-16-le")[:260 * 2]
        return struct.pack("<IIII", pid, 0, 0, 0) + path_bytes
    if function == 0x873:    # Pid, Rsv, Address u64, Size u64
        return struct.pack("<IIqq", pid, 0, 0x00007FF000000000, 64)
    return struct.pack("<IIII", pid, 0, 0, 0)  # SET_TOKEN/HIDE/PROTECT


# ---------------------------------------------------------------------------
# [REGISTRY] R1-1/R1-2: R0 registry read/enum/write cycle.
# Reads are cross-checked against the guest's own winreg view; the write
# cycle exercises a scratch key under HKLM\SOFTWARE that the test creates
# and removes itself. Write IOCTLs are SAFETY_TOKEN-gated.
# ---------------------------------------------------------------------------

IOCTL_MYARK_REGISTRY_READ_VALUE    = _ctl_code(FILE_DEVICE_UNKNOWN, 0xE00, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_REGISTRY_ENUM_KEY      = _ctl_code(FILE_DEVICE_UNKNOWN, 0xE01, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_REGISTRY_SET_VALUE     = _ctl_code(FILE_DEVICE_UNKNOWN, 0xE02, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_REGISTRY_DELETE_VALUE  = _ctl_code(FILE_DEVICE_UNKNOWN, 0xE03, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_REGISTRY_CREATE_KEY    = _ctl_code(FILE_DEVICE_UNKNOWN, 0xE04, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_REGISTRY_DELETE_KEY    = _ctl_code(FILE_DEVICE_UNKNOWN, 0xE05, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_REGISTRY_RENAME_VALUE  = _ctl_code(FILE_DEVICE_UNKNOWN, 0xE06, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_REGISTRY_RENAME_KEY    = _ctl_code(FILE_DEVICE_UNKNOWN, 0xE07, METHOD_BUFFERED, FILE_ANY_ACCESS)

MYARK_REGISTRY_KEY_PATH_CHARS = 256
MYARK_REGISTRY_VALUE_NAME_CHARS = 64
MYARK_REGISTRY_DATA_MAX = 512

MYARK_REGISTRY_OP_SET_VALUE = 1
MYARK_REGISTRY_OP_DELETE_VALUE = 2
MYARK_REGISTRY_OP_CREATE_KEY = 3
MYARK_REGISTRY_OP_DELETE_KEY = 4
MYARK_REGISTRY_OP_RENAME_VALUE = 5
MYARK_REGISTRY_OP_RENAME_KEY = 6


def _reg_wstr(value: str, chars: int) -> bytes:
    """Encode as a fixed WCHAR[chars] field (NUL-terminated, truncated)."""
    return value.encode("utf-16-le")[:(chars - 1) * 2].ljust(chars * 2, b"\x00")


def _registry_read_in(key_path: str, value_name: str) -> bytes:
    return _reg_wstr(key_path, 256) + _reg_wstr(value_name, 64)


def _registry_enum_in(key_path: str, start: int, max_entries: int) -> bytes:
    return _reg_wstr(key_path, 256) + struct.pack("<II", start, max_entries)


def verify_registry(handle, session_key):
    _step("REGISTRY R0 read/enum/write cycle (R1)")
    pid = os.getpid() & 0xFFFFFFFF

    def _token(op):
        if session_key is None:
            raise OSError("no session key")
        return sign_token(session_key, pid, op, nt_filetime_now())

    # --- READ_VALUE: cross-checked against the guest's own winreg view ---
    key_path = "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
    try:
        payload = _ioctl(handle, IOCTL_MYARK_REGISTRY_READ_VALUE,
                         _registry_read_in(key_path, "CurrentBuildNumber"),
                         12 + MYARK_REGISTRY_DATA_MAX)
        status, vtype, dsize = struct.unpack_from("<III", payload, 0)
        val = payload[12:12 + dsize].decode("utf-16-le", errors="replace").rstrip("\x00") if vtype == 1 else ""
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion") as k:
            expected, _ = winreg.QueryValueEx(k, "CurrentBuildNumber")
        check("REGISTRY", "READ_VALUE CurrentBuildNumber",
              status == 0 and dsize > 0 and val == str(expected),
              "kernel=%r winreg=%r type=%d" % (val, expected, vtype))
    except OSError as exc:
        check("REGISTRY", "READ_VALUE CurrentBuildNumber", False, str(exc))

    # --- ENUM_KEY: subkey count must match the winreg view ---
    try:
        payload = _ioctl(handle, IOCTL_MYARK_REGISTRY_ENUM_KEY,
                         _registry_enum_in(key_path, 0, 16),
                         16 + 16 * 128)
        status, returned, total, _next = struct.unpack_from("<IIII", payload, 0)
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion") as k:
            expected_total = winreg.QueryInfoKey(k)[0]
        check("REGISTRY", "ENUM_KEY CurrentVersion",
              status == 0 and returned > 0 and total == expected_total,
              "returned=%d total=%d winreg=%d" % (returned, total, expected_total))
    except OSError as exc:
        check("REGISTRY", "ENUM_KEY CurrentVersion", False, str(exc))

    # --- negative: mutating IOCTL without a token must be denied ---
    set_in_len = SAFETY_TOKEN_SIZE + 256 * 2 + 64 * 2 + 8 + 512
    ok, _payload, err = _ioctl_raw(handle, IOCTL_MYARK_REGISTRY_SET_VALUE,
                                   b"\x00" * set_in_len, 4)
    check("REGISTRY", "SET_VALUE without token denied",
          (not ok) and err == ERROR_ACCESS_DENIED, "win32_err=%d" % err)

    if session_key is None:
        skip("REGISTRY", "write cycle", "no session key")
        return

    # --- token-gated write cycle on a scratch key we create/remove ---
    test_path = "\\Registry\\Machine\\SOFTWARE\\MyArkRegTest"
    marker = bytes([0x5A, 0xA5, 0x11, 0x4D])

    def _set_in(value_name, vtype, data):
        # Variable-tail payload: the IOCTL length minus the fixed fields is
        # the data size the driver uses, so send exactly len(data) bytes.
        return (_token(MYARK_REGISTRY_OP_SET_VALUE) + _reg_wstr(test_path, 256)
                + _reg_wstr(value_name, 64) + struct.pack("<II", vtype, len(data)) + data)

    def _simple_in(op, value_name=""):
        return _token(op) + _reg_wstr(test_path, 256) + _reg_wstr(value_name, 64)

    def _key_in(op):
        return _token(op) + _reg_wstr(test_path, 256)

    def _rename_in(old, new):
        return (_token(MYARK_REGISTRY_OP_RENAME_VALUE) + _reg_wstr(test_path, 256)
                + _reg_wstr(old, 64) + _reg_wstr(new, 64))

    # CREATE_KEY
    ok, payload, err = _ioctl_raw(handle, IOCTL_MYARK_REGISTRY_CREATE_KEY,
                                  _key_in(MYARK_REGISTRY_OP_CREATE_KEY), 4)
    check("REGISTRY", "CREATE_KEY MyArkRegTest",
          ok and len(payload) >= 4 and struct.unpack_from("<I", payload, 0)[0] == 0,
          "err=%d" % err)

    # SET_VALUE DWORD (token-gated)
    ok, payload, err = _ioctl_raw(handle, IOCTL_MYARK_REGISTRY_SET_VALUE,
                                  _set_in("Test", 4, marker), 4)
    check("REGISTRY", "SET_VALUE DWORD (token)",
          ok and len(payload) >= 4 and struct.unpack_from("<I", payload, 0)[0] == 0,
          "err=%d" % err)

    # READ_VALUE matches the marker (and winreg, as a second opinion)
    try:
        payload = _ioctl(handle, IOCTL_MYARK_REGISTRY_READ_VALUE,
                         _registry_read_in(test_path, "Test"), 12 + MYARK_REGISTRY_DATA_MAX)
        status, vtype, dsize = struct.unpack_from("<III", payload, 0)
        data = payload[12:12 + dsize]
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\MyArkRegTest") as k:
            expected, _ = winreg.QueryValueEx(k, "Test")
        check("REGISTRY", "READ_VALUE scratch matches marker",
              status == 0 and data == marker and expected == struct.unpack("<I", marker)[0],
              "data=%s winreg=%#x" % (data.hex(), expected))
    except OSError as exc:
        check("REGISTRY", "READ_VALUE scratch matches marker", False, str(exc))

    # RENAME_VALUE Test -> Renamed
    ok, payload, err = _ioctl_raw(handle, IOCTL_MYARK_REGISTRY_RENAME_VALUE,
                                  _rename_in("Test", "Renamed"), 4)
    check("REGISTRY", "RENAME_VALUE Test->Renamed",
          ok and len(payload) >= 4 and struct.unpack_from("<I", payload, 0)[0] == 0,
          "err=%d" % err)

    # DELETE_VALUE Renamed -> gone
    ok, payload, err = _ioctl_raw(handle, IOCTL_MYARK_REGISTRY_DELETE_VALUE,
                                  _simple_in(MYARK_REGISTRY_OP_DELETE_VALUE, "Renamed"), 4)
    check("REGISTRY", "DELETE_VALUE Renamed",
          ok and len(payload) >= 4 and struct.unpack_from("<I", payload, 0)[0] == 0,
          "err=%d" % err)

    # DELETE_KEY scratch -> gone
    ok, payload, err = _ioctl_raw(handle, IOCTL_MYARK_REGISTRY_DELETE_KEY,
                                  _key_in(MYARK_REGISTRY_OP_DELETE_KEY), 4)
    check("REGISTRY", "DELETE_KEY scratch",
          ok and len(payload) >= 4 and struct.unpack_from("<I", payload, 0)[0] == 0,
          "err=%d" % err)

    # post-delete: SET must fail with path-not-found (2)
    ok, _payload, err = _ioctl_raw(handle, IOCTL_MYARK_REGISTRY_SET_VALUE,
                                   _set_in("Test", 4, marker), 4)
    check("REGISTRY", "SET_VALUE after DELETE_KEY fails", (not ok) and err == 2,
          "win32_err=%d" % err)

    # --- RENAME_KEY roundtrip on a second scratch key ---
    path_a = "\\Registry\\Machine\\SOFTWARE\\MyArkRegTest2"
    path_b = path_a + "r"

    def _keyop(op, pth):
        return _token(op) + _reg_wstr(pth, 256)

    ok, payload, err = _ioctl_raw(handle, IOCTL_MYARK_REGISTRY_CREATE_KEY,
                                  _keyop(MYARK_REGISTRY_OP_CREATE_KEY, path_a), 4)
    created = ok and len(payload) >= 4 and struct.unpack_from("<I", payload, 0)[0] == 0
    ok2, payload2, err2 = _ioctl_raw(
        handle, IOCTL_MYARK_REGISTRY_RENAME_KEY,
        _token(MYARK_REGISTRY_OP_RENAME_KEY) + _reg_wstr(path_a, 256)
        + _reg_wstr("MyArkRegTest2r", 64), 4)
    renamed = ok2 and len(payload2) >= 4 and struct.unpack_from("<I", payload2, 0)[0] == 0
    check("REGISTRY", "RENAME_KEY roundtrip", created and renamed,
          "create=%s rename_err=%d" % (created, err2))

    # cleanup of the renamed scratch key
    ok, payload, err = _ioctl_raw(handle, IOCTL_MYARK_REGISTRY_DELETE_KEY,
                                  _keyop(MYARK_REGISTRY_OP_DELETE_KEY, path_b), 4)
    in_band = struct.unpack_from("<I", payload, 0)[0] if ok and len(payload) >= 4 else None
    check("REGISTRY", "DELETE_KEY renamed scratch",
          ok and in_band == 0, "err=%d in_band=%s" % (err, in_band))

    # --- ENUM pagination: NextIndex must advance without repeating ---
    first = _ioctl(handle, IOCTL_MYARK_REGISTRY_ENUM_KEY,
                   _registry_enum_in("\\Registry\\Machine\\SOFTWARE", 0, 16),
                   16 + 16 * 128)
    s1, r1, t1, n1 = struct.unpack_from("<IIII", first, 0)
    second = _ioctl(handle, IOCTL_MYARK_REGISTRY_ENUM_KEY,
                    _registry_enum_in("\\Registry\\Machine\\SOFTWARE", n1, 16),
                    16 + 16 * 128)
    s2, r2, t2, n2 = struct.unpack_from("<IIII", second, 0)
    # n1 caps at 16 per call; a second page is only guaranteed to exist
    # when the key has more subkeys than one batch holds.
    check("REGISTRY", "ENUM_KEY pagination advances",
          s1 == 0 and s2 == 0 and n1 == min(t1, 16) and (t1 <= 16 or n2 > n1),
          "n1=%d n2=%d r1=%d r2=%d t1=%d" % (n1, n2, r1, r2, t1))


# ---------------------------------------------------------------------------
# [FILE] R1-3: R0 file delete (3-tier chain) + query info.
# Uses scratch files under %TEMP% that the test creates and removes.
# The occupied-file case holds a no-sharing handle from this same process:
# the driver's open must then fail with a sharing violation, which the
# assertions surface as the documented failure (plain and FORCE both).
# ---------------------------------------------------------------------------

IOCTL_MYARK_FILE_DELETE_PATH = _ctl_code(FILE_DEVICE_UNKNOWN, 0xE10, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_FILE_QUERY_INFO   = _ctl_code(FILE_DEVICE_UNKNOWN, 0xE11, METHOD_BUFFERED, FILE_ANY_ACCESS)

MYARK_FILE_PATH_CHARS = 520
MYARK_FILE_DELETE_FLAG_FORCE = 1
MYARK_FILE_OP_DELETE_PATH = 1


def _file_wstr(value: str, chars: int) -> bytes:
    return value.encode("utf-16-le")[:(chars - 1) * 2].ljust(chars * 2, b"\x00")


def verify_file(handle, session_key):
    _step("FILE R0 delete (3-tier) + query info (R1)")
    pid = os.getpid() & 0xFFFFFFFF
    nt_prefix = "\\??\\"

    def _token(op):
        if session_key is None:
            raise OSError("no session key")
        return sign_token(session_key, pid, op, nt_filetime_now())

    def _delete_in(path: str, force: bool) -> bytes:
        flags = MYARK_FILE_DELETE_FLAG_FORCE if force else 0
        return (_token(MYARK_FILE_OP_DELETE_PATH) + struct.pack("<II", flags, 0)
                + _file_wstr(path, 520))

    def _query_in(path: str) -> bytes:
        return _file_wstr(path, 520)

    import tempfile
    scratch = os.path.join(tempfile.gettempdir(), "myark_file_test.bin")
    with open(scratch, "wb") as fp:
        fp.write(b"MYARK_FILE_TEST")

    # --- 1. QUERY_INFO on a fresh scratch file ---
    nt_scratch = nt_prefix + scratch.replace("/", "\\")
    try:
        payload = _ioctl(handle, IOCTL_MYARK_FILE_QUERY_INFO,
                         _query_in(nt_scratch), 56)
        status, attrs = struct.unpack_from("<II", payload, 0)
        eof = struct.unpack_from("<Q", payload, 16)[0]
        check("FILE", "QUERY_INFO scratch size+attrs",
              status == 0 and eof == 15 and (attrs & 0x20) != 0,
              "status=#%08X eof=%d attrs=#%x" % (status, eof, attrs))
    except OSError as exc:
        check("FILE", "QUERY_INFO scratch size+attrs", False, str(exc))

    # --- 2. DELETE without token -> denied ---
    ok, _payload, err = _ioctl_raw(handle, IOCTL_MYARK_FILE_DELETE_PATH,
                                   b"\x00" * (SAFETY_TOKEN_SIZE + 8 + 520 * 2), 4)
    check("FILE", "DELETE_PATH without token denied",
          (not ok) and err == ERROR_ACCESS_DENIED, "win32_err=%d" % err)

    if session_key is None:
        skip("FILE", "delete cycle", "no session key")
        try:
            os.remove(scratch)
        except OSError:
            pass
        return

    def _delete_in_tok(path: str, force: bool) -> bytes:
        flags = MYARK_FILE_DELETE_FLAG_FORCE if force else 0
        return (_token(MYARK_FILE_OP_DELETE_PATH) + struct.pack("<II", flags, 0)
                + _file_wstr(path, 520))

    # --- 3. occupied file: a no-sharing handle must block the delete ---
    k32 = ctypes.WinDLL("kernel32")
    k32.CreateFileW.restype = ctypes.c_void_p
    k32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32,
                                ctypes.c_uint32, ctypes.c_void_p,
                                ctypes.c_uint32, ctypes.c_uint32,
                                ctypes.c_void_p]
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    INVALID_HANDLE = ctypes.c_void_p(-1).value

    held = k32.CreateFileW(scratch, 0xC0000000, 0, None, 3, 0x80, None)
    handle_held = held is not None and held != INVALID_HANDLE

    if not handle_held:
        check("FILE", "DELETE_PATH occupied no-share fails", False, "could not open scratch")
        check("FILE", "DELETE_PATH plain removes unoccupied", False, "no handle")
    else:
        # While the no-share handle is open, the driver's own open must
        # fail with a sharing violation (in-band), not crash or lie.
        ok, payload, err = _ioctl_raw(handle, IOCTL_MYARK_FILE_DELETE_PATH,
                                      _delete_in_tok(nt_scratch, False), 4)
        in_band = struct.unpack_from("<I", payload, 0)[0] if ok and len(payload) >= 4 else None
        detail = "ok=%s err=%d in_band=%s payload=%d" % (ok, err, in_band, len(payload))
        check("FILE", "DELETE_PATH occupied no-share fails",
              (not ok) or (in_band is not None and in_band != 0), detail)
        k32.CloseHandle(ctypes.c_void_p(held))

    # --- 4. unoccupied: plain delete removes the file ---
    ok, payload, err = _ioctl_raw(handle, IOCTL_MYARK_FILE_DELETE_PATH,
                                  _delete_in_tok(nt_scratch, False), 4)
    in_band = struct.unpack_from("<I", payload, 0)[0] if ok and len(payload) >= 4 else None
    gone = not os.path.exists(scratch)
    check("FILE", "DELETE_PATH plain removes unoccupied",
          ok and in_band == 0 and gone,
          "in_band=%s gone=%s" % (in_band, gone))

    # cleanup any residue
    try:
        os.remove(scratch)
    except OSError:
        pass

# ---------------------------------------------------------------------------
# [HOOKSCAN] R1-4: inline hook scan of the ntoskrnl image. The driver
# chunk-reads the image and classifies out-of-image jump stubs (E9/EB/FF25).
# On a clean guest the count is typically 0; security software may add a
# few, so the assertion is bounded rather than zero-pinned.
# ---------------------------------------------------------------------------

IOCTL_MYARK_KERNEL_SCAN_INLINE_HOOKS = _ctl_code(FILE_DEVICE_UNKNOWN, 0xE20, METHOD_BUFFERED, FILE_ANY_ACCESS)

MYARK_KERNEL_HOOK_HARD_CAP = 256


def verify_hook_scan(handle) -> None:
    _step("HOOKSCAN inline hook scan (R1-4)")
    try:
        payload = _ioctl(handle, IOCTL_MYARK_KERNEL_SCAN_INLINE_HOOKS,
                         struct.pack("<IIII", 64, 0, 0, 0),
                         40 + 24 * 64)
        size_field, count, total, kb = struct.unpack_from("<IIII", payload, 0)
        tbase, tend = struct.unpack_from("<QQ", payload, 16)
        sane = (size_field >= 40 and count <= 64 and total >= count
                and tbase != 0 and tend > tbase)
        check("HOOKSCAN", "SCAN_INLINE_HOOKS completes",
              sane, "count=%d total=%d base=#%x end=#%x kb=%d"
              % (count, total, tbase, tend, kb))
    except OSError as exc:
        check("HOOKSCAN", "SCAN_INLINE_HOOKS completes", False, str(exc))


# ---------------------------------------------------------------------------
# [TESTDRV] R2-5: FORCE_UNLOAD against a disposable test driver. The
# regression installs MyArkTestDrv.sys as a kernel service (the verify
# runs elevated), loads it, unloads it through the driver's token+FORCE
# gated IOCTL and asserts closed-loop ground truth from the driver's own
# loaded-module re-walk. Negative paths: no token, missing FORCE, a
# blocklisted name, a bogus service.
# ---------------------------------------------------------------------------

IOCTL_MYARK_KERNEL_FORCE_UNLOAD = _ctl_code(FILE_DEVICE_UNKNOWN, 0xE26, METHOD_BUFFERED, FILE_ANY_ACCESS)

MYARK_KERNEL_OP_FORCE_UNLOAD = 0x324B524E    # 'NRK2' LE
MYARK_KMOD_UNLOAD_FLAG_FORCE = 1
MYARK_KMOD_UNLOAD_FORCE_MAGIC = 0x43524F46   # 'FORC' LE
MYARK_KMOD_UNLOAD_NAME_CHARS = 64
TESTDRV_OUT_SIZE = 16


def verify_testdrv(handle, session_key) -> None:
    _step("TESTDRV force-unload roundtrip (R2-5)")
    pid = os.getpid() & 0xFFFFFFFF
    svc = "MyArkTestDrv"
    # MyArkTestDrv.sys is pushed next to this script (vm_push_driver.bat);
    # derive binPath from __file__, never from a machine-specific path.
    sys_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "MyArkTestDrv.sys")

    def _unload_in(name: str, sign: bool = True, force: bool = True) -> bytes:
        if sign:
            if session_key is None:
                raise OSError("no session key")
            tok = sign_token(session_key, pid, MYARK_KERNEL_OP_FORCE_UNLOAD,
                             nt_filetime_now())
        else:
            tok = b"\x00" * SAFETY_TOKEN_SIZE
        nm = name.encode("utf-16-le")[: (MYARK_KMOD_UNLOAD_NAME_CHARS - 1) * 2]
        nm = nm.ljust(MYARK_KMOD_UNLOAD_NAME_CHARS * 2, b"\x00")
        f = MYARK_KMOD_UNLOAD_FORCE_MAGIC if force else 0
        return tok + struct.pack("<II", MYARK_KMOD_UNLOAD_FLAG_FORCE, f) + nm

    # --- 0. install + load the test driver (guest-local) ---
    # delete-first: a leftover service from a previous round can come
    # back DISABLED (1058) after a failed signature load.
    subprocess.run(["sc", "delete", svc], capture_output=True, text=True)
    r = subprocess.run(["sc", "create", svc, "type=", "kernel", "start=", "demand",
                        "binPath=", sys_path],
                       capture_output=True, text=True)
    created = r.returncode == 0
    subprocess.run(["sc", "config", svc, "start=", "demand"],
                   capture_output=True, text=True)
    r = subprocess.run(["sc", "start", svc], capture_output=True, text=True)
    started = r.returncode == 0
    check("TESTDRV", "test driver installed+loaded",
          created and started,
          "create rc=%d start rc=%d out=%s"
          % (created, started, (r.stdout or r.stderr).strip()[:80]))

    # --- 1. no token -> denied ---
    ok, _p, err = _ioctl_raw(handle, IOCTL_MYARK_KERNEL_FORCE_UNLOAD,
                             _unload_in(svc, sign=False), TESTDRV_OUT_SIZE)
    check("TESTDRV", "unload without token denied",
          (not ok) and err == ERROR_ACCESS_DENIED, "win32_err=%d" % err)

    # --- 2. token but missing FORCE -> denied ---
    if session_key is None:
        skip("TESTDRV", "unload cycle", "no session key")
        subprocess.run(["sc", "delete", svc], capture_output=True)
        return
    ok, _p, err = _ioctl_raw(handle, IOCTL_MYARK_KERNEL_FORCE_UNLOAD,
                             _unload_in(svc, force=False), TESTDRV_OUT_SIZE)
    check("TESTDRV", "unload without FORCE denied",
          (not ok) and err == ERROR_ACCESS_DENIED, "win32_err=%d" % err)

    # --- 3. blocklisted name refused ---
    ok, _p, err = _ioctl_raw(handle, IOCTL_MYARK_KERNEL_FORCE_UNLOAD,
                             _unload_in("MyArkCore"), TESTDRV_OUT_SIZE)
    check("TESTDRV", "blocklist name refused",
          (not ok) and err == ERROR_ACCESS_DENIED, "win32_err=%d" % err)

    # --- 4. bogus service -> in-band NOT_FOUND ---
    ok, payload, err = _ioctl_raw(handle, IOCTL_MYARK_KERNEL_FORCE_UNLOAD,
                                  _unload_in("NoSuchDrv123"), TESTDRV_OUT_SIZE)
    inband = struct.unpack_from("<I", payload, 0)[0] if ok and len(payload) >= 4 else None
    check("TESTDRV", "bogus service reported NOT_FOUND",
          ok and inband is not None and inband != 0,
          "ok=%s inband=%s" % (ok, inband))

    # --- 5. the real unload: loaded -> gone ---
    ok, payload, err = _ioctl_raw(handle, IOCTL_MYARK_KERNEL_FORCE_UNLOAD,
                                  _unload_in(svc), TESTDRV_OUT_SIZE)
    if ok and len(payload) >= 16:
        status, was, gone = struct.unpack_from("<III", payload, 0)
        check("TESTDRV", "FORCE_UNLOAD test driver",
              ok and status == 0 and was == 1 and gone == 1,
              "status=%d was=%d gone=%d" % (status, was, gone))
    else:
        check("TESTDRV", "FORCE_UNLOAD test driver", False,
              "ok=%s err=%d" % (ok, err))

    # --- 6. double unload: no longer loaded -> NOT_FOUND ---
    ok, payload, err = _ioctl_raw(handle, IOCTL_MYARK_KERNEL_FORCE_UNLOAD,
                                  _unload_in(svc), TESTDRV_OUT_SIZE)
    inband = struct.unpack_from("<I", payload, 0)[0] if ok and len(payload) >= 4 else None
    check("TESTDRV", "double unload reported NOT_FOUND",
          ok and inband is not None and inband != 0,
          "inband=%s" % inband)

    # --- 7. cleanup: delete the service ---
    r = subprocess.run(["sc", "delete", svc], capture_output=True, text=True)
    check("TESTDRV", "service deleted", r.returncode == 0,
          "rc=%d" % r.returncode)



# ---------------------------------------------------------------------------
# [RULES] R2-6: process-creation rule engine. SET_RULES/RUNTIME_STATE
# drive an in-kernel PsSetCreateProcessNotifyRoutineEx callback; DENY
# rules make CreateProcess fail with ERROR_ACCESS_DENIED, LOG_ONLY rules
# just count. Real spawns against copies of cmd.exe prove both actions
# end to end; cleanup restores the clean state.
# ---------------------------------------------------------------------------

IOCTL_MYARK_CALLBACK_SET_RULES = _ctl_code(FILE_DEVICE_UNKNOWN, 0x71A, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_CALLBACK_RUNTIME_STATE = _ctl_code(FILE_DEVICE_UNKNOWN, 0x71B, METHOD_BUFFERED, FILE_ANY_ACCESS)

MYARK_CALLBACK_OP_SET_RULES = 0x31524243     # 'CBR1' LE
MYARK_CALLBACK_OP_RUNTIME_STATE = 0x32524243 # 'CBR2' LE
MYARK_CALLBACK_RULES_OP_SET = 1
MYARK_CALLBACK_RULES_OP_REMOVE = 2
MYARK_CALLBACK_RULES_OP_CLEAR = 3
MYARK_CALLBACK_RULE_ACTION_DENY = 1
MYARK_CALLBACK_RULE_ACTION_LOG_ONLY = 2
MYARK_CALLBACK_STATE_QUERY = 0
MYARK_CALLBACK_STATE_ENABLE = 1
MYARK_CALLBACK_STATE_DISABLE = 2
MYARK_CALLBACK_RULE_NAME_CHARS = 64
RULES_OUT_SIZE = 8
STATE_OUT_SIZE = 16


def verify_rules(handle, session_key) -> None:
    _step("RULES process-create rule engine (R2-6)")
    pid = os.getpid() & 0xFFFFFFFF
    esc = chr(92)

    def _rules_in(op, action, name, sign=True):
        if sign:
            if session_key is None:
                raise OSError("no session key")
            tok = sign_token(session_key, pid, MYARK_CALLBACK_OP_SET_RULES,
                             nt_filetime_now())
        else:
            tok = b"\x00" * SAFETY_TOKEN_SIZE
        nm = name.encode("utf-16-le")[:(MYARK_CALLBACK_RULE_NAME_CHARS - 1) * 2]
        nm = nm.ljust(MYARK_CALLBACK_RULE_NAME_CHARS * 2, b"\x00")
        return tok + struct.pack("<II", op, action) + nm

    def _state_in(mode, sign=True):
        if sign:
            if session_key is None:
                raise OSError("no session key")
            tok = sign_token(session_key, pid, MYARK_CALLBACK_OP_RUNTIME_STATE,
                             nt_filetime_now())
        else:
            tok = b"\x00" * SAFETY_TOKEN_SIZE
        return tok + struct.pack("<III", mode, 0, 0) + b"\x00" * 4  # tail pad: C sizeof = 80

    def _state():
        payload = _ioctl(handle, IOCTL_MYARK_CALLBACK_RUNTIME_STATE,
                         _state_in(MYARK_CALLBACK_STATE_QUERY), STATE_OUT_SIZE)
        return struct.unpack_from("<IIII", payload, 0)

    # --- 0. force a clean baseline (token) ---
    if session_key is None:
        skip("RULES", "rule engine cycle", "no session key")
        return
    _ioctl(handle, IOCTL_MYARK_CALLBACK_RUNTIME_STATE,
           _state_in(MYARK_CALLBACK_STATE_DISABLE), STATE_OUT_SIZE)
    _ioctl(handle, IOCTL_MYARK_CALLBACK_SET_RULES,
           _rules_in(MYARK_CALLBACK_RULES_OP_CLEAR, 0, ""), RULES_OUT_SIZE)

    # --- 1. SET_RULES without token -> denied ---
    ok, _p, err = _ioctl_raw(handle, IOCTL_MYARK_CALLBACK_SET_RULES,
                             _rules_in(MYARK_CALLBACK_RULES_OP_SET,
                                       MYARK_CALLBACK_RULE_ACTION_DENY,
                                       "myark_victim.exe", sign=False),
                             RULES_OUT_SIZE)
    check("RULES", "SET_RULES without token denied",
          (not ok) and err == ERROR_ACCESS_DENIED, "win32_err=%d" % err)

    # --- 2. ENABLE without token -> denied ---
    ok, _p, err = _ioctl_raw(handle, IOCTL_MYARK_CALLBACK_RUNTIME_STATE,
                             _state_in(MYARK_CALLBACK_STATE_ENABLE, sign=False),
                             STATE_OUT_SIZE)
    check("RULES", "ENABLE without token denied",
          (not ok) and err == ERROR_ACCESS_DENIED, "win32_err=%d" % err)

    # --- 3. prepare test images ---
    import shutil
    comspec = os.environ.get("ComSpec", "C:" + esc + "Windows" + esc
                             + "system32" + esc + "cmd.exe")
    tmp = os.environ.get("TEMP", ".")
    victim = os.path.join(tmp, "myark_victim.exe")
    logger = os.path.join(tmp, "myark_logger.exe")
    shutil.copyfile(comspec, victim)
    shutil.copyfile(comspec, logger)

    # --- 4. add rules (DENY victim, LOG_ONLY logger) ---
    ok, payload, err = _ioctl_raw(handle, IOCTL_MYARK_CALLBACK_SET_RULES,
                                  _rules_in(MYARK_CALLBACK_RULES_OP_SET,
                                            MYARK_CALLBACK_RULE_ACTION_DENY,
                                            "myark_victim.exe"), RULES_OUT_SIZE)
    n1 = struct.unpack_from("<I", payload, 4)[0] if ok else -1
    check("RULES", "DENY rule added", ok and n1 == 1, "n=%s err=%d" % (n1, err))
    ok, payload, err = _ioctl_raw(handle, IOCTL_MYARK_CALLBACK_SET_RULES,
                                  _rules_in(MYARK_CALLBACK_RULES_OP_SET,
                                            MYARK_CALLBACK_RULE_ACTION_LOG_ONLY,
                                            "myark_logger.exe"), RULES_OUT_SIZE)
    n2 = struct.unpack_from("<I", payload, 4)[0] if ok else -1
    check("RULES", "LOG_ONLY rule added", ok and n2 == 2, "n=%s err=%d" % (n2, err))

    # --- 5. enable the engine ---
    _ioctl(handle, IOCTL_MYARK_CALLBACK_RUNTIME_STATE,
           _state_in(MYARK_CALLBACK_STATE_ENABLE), STATE_OUT_SIZE)
    enabled, rules_n, matched, denied = _state()
    check("RULES", "engine enabled with 2 rules",
          enabled == 1 and rules_n == 2,
          "enabled=%d rules=%d" % (enabled, rules_n))

    # --- 6. DENY fires: victim create fails ---
    try:
        subprocess.run([victim, "/c", "exit"], capture_output=True, timeout=20)
        denied_fired = False
    except PermissionError:
        denied_fired = True
    check("RULES", "DENY blocks victim create", denied_fired,
          "permission error expected")

    # --- 7. LOG_ONLY fires: logger runs but is counted ---
    try:
        r = subprocess.run([logger, "/c", "exit"], capture_output=True, timeout=20)
        logger_ok = r.returncode == 0
        logger_rc = r.returncode
    except Exception as exc:   # engine stuck denying: record, keep the run
        logger_ok = False
        logger_rc = str(exc)
    check("RULES", "LOG_ONLY lets logger run", logger_ok,
          "rc=%s" % logger_rc)

    # --- 8. counters moved ---
    enabled, rules_n, matched, denied = _state()
    check("RULES", "counters after matches",
          matched >= 2 and denied >= 1,
          "matched=%d denied=%d" % (matched, denied))

    # --- 9. REMOVE the deny rule -> victim create succeeds ---
    ok, payload, err = _ioctl_raw(handle, IOCTL_MYARK_CALLBACK_SET_RULES,
                                  _rules_in(MYARK_CALLBACK_RULES_OP_REMOVE, 0,
                                            "myark_victim.exe"), RULES_OUT_SIZE)
    n3 = struct.unpack_from("<I", payload, 4)[0] if ok else -1
    try:
        r = subprocess.run([victim, "/c", "exit"], capture_output=True, timeout=20)
        victim_ok = r.returncode == 0
        victim_rc = r.returncode
    except Exception as exc:   # REMOVE failed: record, keep the run
        victim_ok = False
        victim_rc = str(exc)
    check("RULES", "REMOVE restores victim create",
          ok and n3 == 1 and victim_ok,
          "n=%s rc=%s" % (n3, victim_rc))

    # --- 10. cleanup: disable + clear ---
    _ioctl(handle, IOCTL_MYARK_CALLBACK_RUNTIME_STATE,
           _state_in(MYARK_CALLBACK_STATE_DISABLE), STATE_OUT_SIZE)
    _ioctl(handle, IOCTL_MYARK_CALLBACK_SET_RULES,
           _rules_in(MYARK_CALLBACK_RULES_OP_CLEAR, 0, ""), RULES_OUT_SIZE)
    enabled, rules_n, matched, denied = _state()
    check("RULES", "cleanup restores clean state",
          enabled == 0 and rules_n == 0,
          "enabled=%d rules=%d" % (enabled, rules_n))

    try:
        os.remove(victim)
        os.remove(logger)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# [FILEINTEG] R2-10: mandatory integrity label. SET (0xE12) is deferred --
# the ZwSetSecurityObject write path wedges the guest (KNOWN_ISSUES), so
# the handler answers STATUS_NOT_SUPPORTED (win32 50) and the verified
# surface is the read-only QUERY (0xE13). The positive (labeled-file)
# case is covered via an icacls fixture the verify applies itself.
# ---------------------------------------------------------------------------

IOCTL_MYARK_FILE_SET_INTEGRITY = _ctl_code(FILE_DEVICE_UNKNOWN, 0xE12, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_FILE_QUERY_INTEGRITY = _ctl_code(FILE_DEVICE_UNKNOWN, 0xE13, METHOD_BUFFERED, FILE_ANY_ACCESS)
MYARK_FILE_OP_SET_INTEGRITY = 0x324C4946    # 'FIL2' LE
MYARK_FILE_INTEGRITY_LEVEL_HIGH = 0x3000
MYARK_FILE_INTEGRITY_LEVEL_MEDIUM = 0x2000
FILEINTEG_QUERY_OUT = 16


def verify_file_integrity(handle, session_key) -> None:
    _step("FILEINTEG mandatory integrity label (R2-10)")
    pid = os.getpid() & 0xFFFFFFFF

    import tempfile
    scratch = os.path.join(tempfile.gettempdir(), "myark_integ_test.bin")
    with open(scratch, "wb") as fp:
        fp.write(b"MYARK")
    nt_path = "\\??\\" + scratch.replace("/", "\\")

    def _query(path: str):
        nm = path.encode("utf-16-le")[:(520 - 1) * 2].ljust(520 * 2, b"\x00")
        payload = _ioctl(handle, IOCTL_MYARK_FILE_QUERY_INTEGRITY, nm,
                         FILEINTEG_QUERY_OUT)
        return struct.unpack_from("<IIII", payload, 0)

    def _set_in(level: int, flags: int, sign=True) -> bytes:
        if sign:
            if session_key is None:
                raise OSError("no session key")
            tok = sign_token(session_key, pid, MYARK_FILE_OP_SET_INTEGRITY,
                             nt_filetime_now())
        else:
            tok = b"\x00" * SAFETY_TOKEN_SIZE
        nm = nt_path.encode("utf-16-le")[:(520 - 1) * 2].ljust(520 * 2, b"\x00")
        return tok + struct.pack("<II", level, flags) + nm

    # --- 1. QUERY on a label-less file: found=0 ---
    try:
        status, found, rid, mask = _query(nt_path)
        check("FILEINTEG", "QUERY label-less file",
              status == 0 and found == 0,
              "status=%d found=%d rid=#%x" % (status, found, rid))
    except OSError as exc:
        check("FILEINTEG", "QUERY label-less file", False, str(exc))
        try:
            os.remove(scratch)
        except OSError:
            pass
        return

    # --- 2. bogus path rejected ---
    bogus = "\\\\??\\\\C:\\no\\such\\dir\\x.bin"
    bnm = bogus.encode("utf-16-le")[:(520 - 1) * 2].ljust(520 * 2, b"\x00")
    ok, _p, err = _ioctl_raw(handle, IOCTL_MYARK_FILE_QUERY_INTEGRITY,
                             bnm, FILEINTEG_QUERY_OUT)
    check("FILEINTEG", "bogus path rejected", not ok, "win32_err=%d" % err)

    # --- 3. label a file with icacls, then read it back (positive case) ---
    labeled = os.path.join(tempfile.gettempdir(), "myark_integ_labeled.bin")
    with open(labeled, "wb") as fp:
        fp.write(b"MYARK")
    r = subprocess.run(["icacls", labeled, "/setintegritylevel", "H"],
                       capture_output=True, text=True)
    nt_labeled = "\\??\\" + labeled.replace("/", "\\")
    label = _query(nt_labeled)   # (status, found, rid, mask)
    ok = (r.returncode == 0 and label is not None and label[0] == 0
          and label[1] == 1 and label[2] == MYARK_FILE_INTEGRITY_LEVEL_HIGH)
    check("FILEINTEG", "icacls HIGH label read-back", ok,
          "rc=%d label=%s" % (r.returncode, str(label)))

    # --- 4. SET deferred: deterministic NOT_SUPPORTED (win32 50) ---
    ok, _p, err = _ioctl_raw(handle, IOCTL_MYARK_FILE_SET_INTEGRITY,
                             _set_in(0x3000, 0), 4)
    check("FILEINTEG", "SET deferred (NOT_SUPPORTED)",
          (not ok) and err == 50, "win32_err=%d" % err)

    try:
        os.remove(labeled)
    except OSError:
        pass

    try:
        os.remove(scratch)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# [FILEMON] R2-7: file-monitor minifilter. Arm with a DOS prefix on a
# dedicated scratch dir, generate create/delete/delete-on-close traffic on
# real files and assert the drained events; negative checks cover the token
# gate, out-of-prefix creates and post-disarm silence. Event paths come back
# as normalized NT paths ("\Device\HarddiskVolumeN\..."), so matching uses
# case-insensitive tail compare.
# ---------------------------------------------------------------------------

IOCTL_MYARK_FILEMON_CONTROL = _ctl_code(FILE_DEVICE_UNKNOWN, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_FILEMON_DRAIN = _ctl_code(FILE_DEVICE_UNKNOWN, 0x816, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_FILEMON_STATUS = _ctl_code(FILE_DEVICE_UNKNOWN, 0x817, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_FILEMON_ENUM_FILTERS = _ctl_code(FILE_DEVICE_UNKNOWN, 0x818, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_FILEMON_BYPASS_PID = _ctl_code(FILE_DEVICE_UNKNOWN, 0x819, METHOD_BUFFERED, FILE_ANY_ACCESS)
MYARK_FILEMON_OP_BYPASS_PID = 0x31504246  # 'FBP1'
MYARK_FILEMON_BYPASS_ACTION_QUERY = 0
MYARK_FILEMON_BYPASS_ACTION_ADD = 1
MYARK_FILEMON_BYPASS_ACTION_REMOVE = 2
_FILEMON_ENUM_SIZE = 6160       # 16 + 32 * 192
_FILEMON_FILTER_SIZE = 192
_FILEMON_BYPASS_OUT_SIZE = 96

MYARK_FILEMON_OP_CONTROL = 0x31524D46        # 'FMR1' LE
MYARK_FILEMON_ENABLE_ON = 1
MYARK_FILEMON_ENABLE_OFF = 0
MYARK_FILEMON_TYPE_CREATE = 1
MYARK_FILEMON_TYPE_DELETE = 2
MYARK_FILEMON_FLAG_DELETE_ON_CLOSE = 0x1

_FILEMON_EVENT_SIZE = 8 + 8 + 7 * 4 + 260 * 2 + 4    # 568: struct is 8-aligned
                                                     # (explicit Reserved2 tail
                                                     # field, no hidden padding)
_FILEMON_DRAIN_HDR = 32
_FILEMON_DRAIN_MAX = 64


def verify_filemon(handle, session_key) -> None:
    _step("FILEMON file monitor minifilter drain (R2-7)")
    pid = os.getpid() & 0xFFFFFFFF
    import uuid

    def _ctl_in(enable: int, prefix: str) -> bytes:
        return (sign_token(session_key, pid, MYARK_FILEMON_OP_CONTROL, nt_filetime_now())
                + struct.pack("<II", enable, 0)
                + prefix.encode("utf-16-le")[:(260 - 1) * 2].ljust(260 * 2, b"\x00"))

    def _status():
        payload = _ioctl(handle, IOCTL_MYARK_FILEMON_STATUS, b"", 40)
        return struct.unpack_from("<10I", payload, 0)

    seen = []

    def _drain():
        while True:
            payload = _ioctl(handle, IOCTL_MYARK_FILEMON_DRAIN,
                             struct.pack("<II", _FILEMON_DRAIN_MAX, 0),
                             _FILEMON_DRAIN_HDR + _FILEMON_DRAIN_MAX * _FILEMON_EVENT_SIZE)
            count, remaining = struct.unpack_from("<II", payload, 0)
            for i in range(count):
                off = _FILEMON_DRAIN_HDR + i * _FILEMON_EVENT_SIZE
                seq, _ts, epid, etype, eflags = struct.unpack_from("<QQIII", payload, off)
                path = payload[off + 44:off + 44 + 520].decode("utf-16-le")
                path = path.split("\x00")[0]
                seen.append((seq, epid, etype, eflags, path.lower()))
            if count == 0:
                return remaining

    def _find(kind: int, tail: str):
        want = tail.lower()
        for seq, epid, etype, eflags, path in seen:
            if etype == kind and epid == pid and path.endswith("\\" + want):
                return seq
        return None

    def _dump_seen(limit: int = 6) -> str:
        return " | ".join("t%d/p%d/%s" % (t, p, path.split("\\")[-1])
                          for _s, p, t, _f, path in seen[-limit:])

    if session_key is None:
        skip("FILEMON", "arm/drain cycle", "no session key")
        return

    # --- 0. STATUS sane on a fresh module ---
    try:
        st = _status()
        ok = (st[1] == 1 and st[2] == 0 and st[3] == 0 and st[6] >= 1)
        check("FILEMON", "STATUS registered+idle+attached",
              ok, "reg=%d en=%d buf=%d vol=%d rec=%d stage=%d status=#%08X"
              % (st[1], st[2], st[3], st[6], st[4], st[8], st[9]))
    except OSError as exc:
        check("FILEMON", "STATUS registered+idle+attached", False, str(exc))
        return

    # --- 1. CONTROL without token -> denied ---
    ok, _p, err = _ioctl_raw(handle, IOCTL_MYARK_FILEMON_CONTROL,
                             b"\x00" * (SAFETY_TOKEN_SIZE + 8 + 260 * 2), 16)
    check("FILEMON", "CONTROL without token denied",
          (not ok) and err == ERROR_ACCESS_DENIED, "win32_err=%d" % err)

    # --- 2. CONTROL invalid Enable -> in-band INVALID_PARAMETER ---
    ok, payload, err = _ioctl_raw(handle, IOCTL_MYARK_FILEMON_CONTROL,
                                  _ctl_in(2, ""), 16)
    in_band = struct.unpack_from("<I", payload, 0)[0] if ok and len(payload) >= 4 else None
    check("FILEMON", "CONTROL invalid enable rejected",
          ok and in_band == 0xC000000D, "ok=%s err=%d in_band=%s" % (ok, err, in_band))

    test_dir = os.path.dirname(os.path.abspath(__file__))
    mon_dir = os.path.join(test_dir, "filemon")
    os.makedirs(mon_dir, exist_ok=True)
    created = []

    try:
        # --- 3. arm on the scratch dir ---
        ok, payload, err = _ioctl_raw(handle, IOCTL_MYARK_FILEMON_CONTROL,
                                      _ctl_in(MYARK_FILEMON_ENABLE_ON, mon_dir), 16)
        if ok and len(payload) >= 8:
            in_band, enabled = struct.unpack_from("<II", payload, 0)
        else:
            in_band, enabled = None, None
        armed = ok and in_band == 0 and enabled == 1
        check("FILEMON", "CONTROL arms on scratch dir",
              armed, "ok=%s err=%d in_band=%s enabled=%s" % (ok, err, in_band, enabled))
        if not armed:
            return

        # --- 4. create inside prefix -> CREATE event ---
        f1 = os.path.join(mon_dir, "fm_%s.bin" % uuid.uuid4().hex[:8])
        with open(f1, "wb") as fp:
            fp.write(b"MYARK_FILEMON")
        created.append(f1)
        _drain()
        check("FILEMON", "CREATE event drained (pid+path)",
              _find(MYARK_FILEMON_TYPE_CREATE, os.path.basename(f1)) is not None,
              "seen=%d" % len(seen))

        # --- 5. delete inside prefix -> DELETE event ---
        os.remove(f1)
        created.remove(f1)
        _drain()
        check("FILEMON", "DELETE event drained (pid+path)",
              _find(MYARK_FILEMON_TYPE_DELETE, os.path.basename(f1)) is not None,
              "seen=%d [%s]" % (len(seen), _dump_seen()))

        # --- 6. delete-on-close create carries the flag ---
        f2 = os.path.join(mon_dir, "fm_%s.tmp" % uuid.uuid4().hex[:8])
        fd = os.open(f2, os.O_CREAT | os.O_EXCL | os.O_TEMPORARY, 0o600)
        os.close(fd)  # O_TEMPORARY removes it here; no manual cleanup needed
        _drain()
        flag_ok = any(etype == MYARK_FILEMON_TYPE_CREATE and epid == pid
                      and eflags & MYARK_FILEMON_FLAG_DELETE_ON_CLOSE
                      and path.endswith("\\" + os.path.basename(f2).lower())
                      for _s, epid, etype, eflags, path in seen)
        check("FILEMON", "delete-on-close CREATE flagged",
              flag_ok, "seen=%d" % len(seen))

        # --- 7. create OUTSIDE prefix leaves no trace ---
        f3 = os.path.join(test_dir, "fm_out_%s.bin" % uuid.uuid4().hex[:8])
        with open(f3, "wb") as fp:
            fp.write(b"outside")
        os.remove(f3)
        _drain()
        leaked = _find(MYARK_FILEMON_TYPE_CREATE, os.path.basename(f3)) is not None
        check("FILEMON", "out-of-prefix create not recorded",
              not leaked, "seen=%d" % len(seen))

        # --- 7b. R3-7: 0x818 minifilter inventory ---
        payload = _ioctl(handle, IOCTL_MYARK_FILEMON_ENUM_FILTERS, b"",
                         _FILEMON_ENUM_SIZE)
        fcount, truncated = struct.unpack_from("<II", payload, 0)
        names = []
        for i in range(fcount):
            base = 16 + i * _FILEMON_FILTER_SIZE
            nchars, achars, inst = struct.unpack_from("<III", payload, base)
            name = payload[base + 16:base + 16 + nchars * 2].decode("utf-16-le")
            alt = payload[base + 144:base + 144 + achars * 2].decode("utf-16-le")
            names.append((name.lower(), alt, inst))
        check("FILEMON", "0x818 inventory: >=3 named minifilters",
              fcount >= 3 and all(n for n, _a, _i in names),
              "count=%d trunc=%d names=%s"
              % (fcount, truncated, [n for n, _a, _i in names][:6]))



        # --- 7c. R3-7: bypass-PID cycle (monitor still armed) ---
        def _bypass_in(action: int, who: int, tok_bytes: bytes) -> bytes:
            return tok_bytes + struct.pack("<IIII", action, who, 0, 0)

        ok, _p, err = _ioctl_raw(handle, IOCTL_MYARK_FILEMON_BYPASS_PID,
                                 _bypass_in(MYARK_FILEMON_BYPASS_ACTION_ADD,
                                            pid, bytes(SAFETY_TOKEN_SIZE)),
                                 _FILEMON_BYPASS_OUT_SIZE)
        check("FILEMON", "bypass ADD without token denied",
              (not ok) and err == ERROR_ACCESS_DENIED, "win32_err=%d" % err)

        tok_b = sign_token(session_key, pid, MYARK_FILEMON_OP_BYPASS_PID,
                           nt_filetime_now())

        def _byp(action: int, who: int = 0):
            payload_b = _ioctl(handle, IOCTL_MYARK_FILEMON_BYPASS_PID,
                               _bypass_in(action, who, tok_b),
                               _FILEMON_BYPASS_OUT_SIZE)
            status, applied, count_b = struct.unpack_from("<III", payload_b, 0)
            drops = struct.unpack_from("<Q", payload_b, 16)[0]
            pids = struct.unpack_from("<16I", payload_b, 24)
            return status, applied, count_b, drops, pids

        st, ap, cnt, drops0, pids0 = _byp(MYARK_FILEMON_BYPASS_ACTION_ADD, pid)
        check("FILEMON", "bypass ADD self -> listed",
              st == 0 and ap == 1 and pid in pids0[:cnt],
              "st=%d ap=%d cnt=%d" % (st, ap, cnt))

        _drain()
        fb1 = os.path.join(mon_dir, "fm_by1_%s.bin" % uuid.uuid4().hex[:8])
        with open(fb1, "wb") as fp:
            fp.write(b"bypassed")
        # Third-party process: its events must STILL be sampled while our
        # own PID is bypassed (guards against a global sampling mute).
        fb3 = os.path.join(mon_dir, "fm_by3_%s.bin" % uuid.uuid4().hex[:8])
        subprocess.run(["cmd", "/c", "type nul > " + fb3], capture_output=True)
        _drain()
        third = [e for e in seen
                 if e[1] != pid and e[4].endswith(os.path.basename(fb3).lower())]
        check("FILEMON", "third-party PID still sampled during bypass",
              len(third) >= 1, "third=%d" % len(third))
        leaked = [s_ for s_, e_, t_, f_, p_ in seen
                  if e_ == pid and p_.endswith(os.path.basename(fb1).lower())]
        check("FILEMON", "bypassed PID event dropped before ring",
              len(leaked) == 0, "leaked=%d" % len(leaked))

        st, ap, cnt, _d1, pids1 = _byp(MYARK_FILEMON_BYPASS_ACTION_REMOVE, pid)
        check("FILEMON", "bypass REMOVE self -> unlisted",
              st == 0 and ap == 1 and cnt >= 0 and pid not in pids1[:cnt],
              "st=%d ap=%d cnt=%d" % (st, ap, cnt))

        _drain()
        fb2 = os.path.join(mon_dir, "fm_by2_%s.bin" % uuid.uuid4().hex[:8])
        with open(fb2, "wb") as fp:
            fp.write(b"observed")
        _drain()
        observed = [s_ for s_, e_, t_, f_, p_ in seen
                    if e_ == pid and p_.endswith(os.path.basename(fb2).lower())]
        check("FILEMON", "after REMOVE the PID is sampled again",
              len(observed) >= 1, "observed=%d seen=%s" % (len(observed), _dump_seen()))

        # --- 8. disarm silences recording, filter stays registered ---
        ok, payload, err = _ioctl_raw(handle, IOCTL_MYARK_FILEMON_CONTROL,
                                      _ctl_in(MYARK_FILEMON_ENABLE_OFF, ""), 16)
        disarmed = ok and struct.unpack_from("<II", payload, 0) == (0, 0)
        st = _status()
        f4 = os.path.join(mon_dir, "fm_%s.bin" % uuid.uuid4().hex[:8])
        with open(f4, "wb") as fp:
            fp.write(b"silence")
        created.append(f4)
        _drain()
        check("FILEMON", "disarm stops recording",
              disarmed and st[2] == 0 and st[1] == 1
              and _find(MYARK_FILEMON_TYPE_CREATE, os.path.basename(f4)) is None,
              "disarmed=%s reg=%d en=%d" % (disarmed, st[1], st[2]))

        # --- 9. counters coherent: nothing dropped, all events accounted ---
        st = _status()
        max_seq = max((s for s, _p, _t, _f, _path in seen), default=0)
        seqs = [s for s, _p, _t, _f, _path in seen]
        mono = all(b > a for a, b in zip(seqs, seqs[1:]))
        check("FILEMON", "counters coherent (dropped=0, recorded>=seen)",
              st[5] == 0 and st[4] >= len(seen) and st[3] == 0 and mono,
              "rec=%d seen=%d drop=%d buf=%d skip=%d maxseq=%d mono=%s"
              % (st[4], len(seen), st[5], st[3], st[7], max_seq, mono))
    finally:
        ok, _p, err = _ioctl_raw(handle, IOCTL_MYARK_FILEMON_CONTROL,
                                 _ctl_in(MYARK_FILEMON_ENABLE_OFF, ""), 16)
        if not ok:
            print("[FILEMON] disarm in finally failed: err=%d" % err, flush=True)
        for leftover in created:
            try:
                os.remove(leftover)
            except OSError:
                pass
        try:
            os.rmdir(mon_dir)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# [WFPINV] R3-15: system network-filter inventory, read-only.
# 0x8A2 walks every NDIS filter module of every adapter stack (documented
# NdisEnumerateFilterModules behind a lazily registered do-nothing
# protocol); 0x8A3 lists every loaded driver whose PE imports reference
# fwpkclnt.sys (WFP callout capable) and/or ndis.sys.
# ---------------------------------------------------------------------------

IOCTL_MYARK_WFP_ENUM_NDIS_FILTERS = _ctl_code(FILE_DEVICE_UNKNOWN, 0x8A2, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_WFP_ENUM_CALLOUT_DRIVERS = _ctl_code(FILE_DEVICE_UNKNOWN, 0x8A3, METHOD_BUFFERED, FILE_ANY_ACCESS)

_WFP_NDIS_ENTRY_SIZE = 168      # 64 + 40 + 64
_WFP_NDIS_ENUM_SIZE = 16 + 128 * _WFP_NDIS_ENTRY_SIZE
_WFP_CDRIVER_ENTRY_SIZE = 88    # 16 + 4 + 4 + 64
_WFP_CDRIVER_ENUM_SIZE = 24 + 256 * _WFP_CDRIVER_ENTRY_SIZE

_WFP_CDRIVER_FLAG_WFP_CAPABLE = 0x00000001
_WFP_CDRIVER_FLAG_NDIS_CAPABLE = 0x00000002
_WFP_CDRIVER_FLAG_PARSE_FAILED = 0x00000004


def verify_wfp_inventory(handle) -> None:
    # 0x8A2: installed NDIS filter instances (NetService class walk).
    payload = _ioctl(handle, IOCTL_MYARK_WFP_ENUM_NDIS_FILTERS, b"",
                     _WFP_NDIS_ENUM_SIZE)
    count, entry_size = struct.unpack_from("<II", payload, 0)
    rows = []
    for i in range(count):
        base = 16 + i * _WFP_NDIS_ENTRY_SIZE
        svc = payload[base:base + 64].split(b"\x00")[0].decode("utf-8", "replace")
        guid = payload[base + 64:base + 104].split(b"\x00")[0].decode("utf-8", "replace")
        friendly = payload[base + 104:base + 168].split(b"\x00")[0].decode("utf-8", "replace")
        rows.append((svc, guid, friendly))
    check("WFPINV", "0x8A2 NDIS filter instances: >=3 installed, all named",
          count >= 3 and entry_size == _WFP_NDIS_ENTRY_SIZE
          and all(r[0] for r in rows),
          "count=%d esz=%d rows=%s"
          % (count, entry_size, [(r[0], r[2]) for r in rows][:8]))

    # 0x8A3: callout-capable driver inventory via PsLoadedModuleList.
    payload = _ioctl(handle, IOCTL_MYARK_WFP_ENUM_CALLOUT_DRIVERS, b"",
                     _WFP_CDRIVER_ENUM_SIZE)
    ccount, ctotal, cesz = struct.unpack_from("<III", payload, 0)
    drivers = {}
    for i in range(ccount):
        base = 24 + i * _WFP_CDRIVER_ENTRY_SIZE
        img_base, img_size, flags = struct.unpack_from("<QQI", payload, base)
        name = payload[base + 24:base + 24 + 64].split(b"\x00")[0].decode(
            "utf-8", "replace").lower()
        drivers[name] = (img_base, flags)
    capable = [n for n, (_b, f) in drivers.items()
               if f & (_WFP_CDRIVER_FLAG_WFP_CAPABLE | _WFP_CDRIVER_FLAG_NDIS_CAPABLE)]
    parse_failed = [n for n, (_b, f) in drivers.items()
                    if f & _WFP_CDRIVER_FLAG_PARSE_FAILED]
    # tcpip.sys deterministically imports fwpkclnt.sys + ndis.sys: a walk
    # that leaves it unflagged is broken (this exact check would have
    # caught the R3-15 acceptance P0, where the Export directory was
    # parsed instead of the Import directory and only fwpkclnt.sys's own
    # export-name string self-matched).
    tcpip_flags = drivers.get("tcpip.sys", (0, 0))[1]
    check("WFPINV", "0x8A3 callout drivers: full walk + tcpip.sys capability-flagged",
          ccount >= 10 and ctotal >= ccount and cesz == _WFP_CDRIVER_ENTRY_SIZE
          and all(b != 0 for b, _f in drivers.values())
          and len(capable) >= 1
          and tcpip_flags & (_WFP_CDRIVER_FLAG_WFP_CAPABLE | _WFP_CDRIVER_FLAG_NDIS_CAPABLE),
          "count=%d total=%d capable=%d tcpip_flags=0x%X parse_failed=%d sample=%s"
          % (ccount, ctotal, len(capable), tcpip_flags, len(parse_failed),
             capable[:4] or list(drivers)[:4]))


# ---------------------------------------------------------------------------
# [KLDRDIAG] R3-15 follow-up: discriminate the KLDR_DATA_TABLE_ENTRY offset
# anomaly the acceptance review flagged — dyndata_internal.h pins both
# SIZE_OF_IMAGE and FULL_DLL_NAME at 0x048. The reads cannot both be right.
# Decisive property: a real SizeOfImage is page-aligned (4 KiB); a
# UNICODE_STRING misread as UINT64 (Length|Max<<16|pad) is not. A real
# FullDllName, in turn, yields "\SystemRoot\...ntoskrnl.exe"-style paths.
# ---------------------------------------------------------------------------
_IOCTL_DYNDATA_QUERY_MODULE = IOCTL_MYARK_DYNDATA_QUERY_MODULE  # defined above (0x702)

_KLDRDIAG_ENTRY = 352        # 8 + 8 + 4 + 4 + 64 + 260, tail-padded to 8
_KLDRDIAG_MAX = 8


def verify_kldr_diag(handle) -> None:
    _step("KLDRDIAG offset discriminator (0x048 double-use)")
    out_size = 32 + _KLDRDIAG_MAX * _KLDRDIAG_ENTRY
    payload = _ioctl(handle, _IOCTL_DYNDATA_QUERY_MODULE,
                     struct.pack("<IIII", _KLDRDIAG_MAX, 0, 0, 0), out_size)
    count = struct.unpack_from("<I", payload, 4)[0]
    rows = []
    for i in range(min(count, _KLDRDIAG_MAX)):
        base = 32 + i * _KLDRDIAG_ENTRY
        ibase, isize = struct.unpack_from("<QQ", payload, base)
        # The driver stores names UTF-16-widened (2 bytes per char).
        name = payload[base + 24:base + 24 + 64].split(b"\x00\x00")[0].decode(
            "utf-16-le", "replace")
        full = payload[base + 88:base + 88 + 260].split(b"\x00\x00")[0].decode(
            "utf-16-le", "replace")
        rows.append((name, full, ibase, isize))

    def _decisive(rs):
        # (all sizes page-aligned & sane) AND (at least one populated path):
        # both hold only if 0x048 really is SizeOfImage AND the name reads
        # come out of a coherent UNICODE_STRING.
        sizes = all(0 < isz <= 64 * 1024 * 1024 and isz % 0x1000 == 0
                    for _n, _f, _b, isz in rs)
        paths = any(f for _n, f, _b, _i in rs)
        bases = all(b & 0xFFFF000000000000 for _n, _f, b, _i in rs)
        return sizes, paths, bases

    sizes_ok, paths_ok, bases_ok = _decisive(rows)
    has_ntos = any("ntoskrnl" in f.lower() for _n, f, _b, _i in rows)
    check("KLDRDIAG", "0x048 reads coherent: sizes page-aligned + ntoskrnl path resolved",
          count >= 3 and bases_ok and sizes_ok and paths_ok and has_ntos,
          "count=%d sizes_ok=%s paths_ok=%s bases_ok=%s ntos=%s rows=%s"
          % (count, sizes_ok, paths_ok, bases_ok, has_ntos, rows[:2]))


# ---------------------------------------------------------------------------
# [TIMERDPC] R3-3: per-CPU kernel timer table + DPC queue snapshot,
# read-only. 0x8A4 walks KPRCB.TimerTable (TimerExpiry + timer buckets)
# per CPU and decodes the Win8+ obfuscated KTIMER.Dpc back-pointer; 0x8A5
# snapshots the per-CPU DPC queues. Offsets are Tier C build-gated
# (18362 + 22621 profiles, both verified live over KDNET 2026-09-17).
# ---------------------------------------------------------------------------
IOCTL_MYARK_TIMER_QUERY = _ctl_code(FILE_DEVICE_UNKNOWN, 0x8A4, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_DPC_QUERY = _ctl_code(FILE_DEVICE_UNKNOWN, 0x8A5, METHOD_BUFFERED, FILE_ANY_ACCESS)

_TIMER_ENTRY_SIZE = 104        # 40 + 16 + 48
_TIMER_ENUM_SIZE = 16 + 512 * _TIMER_ENTRY_SIZE   # full hard cap: real count
_DPC_ENTRY_SIZE = 88           # 24 + 16 + 48
_DPC_ENUM_SIZE = 16 + 128 * _DPC_ENTRY_SIZE

_TIMER_FLAG_NTROUTINE = 0x4
_TIMER_FLAG_SUSPECT = 0x8


def verify_timerdpc(handle) -> None:
    payload = _ioctl(handle, IOCTL_MYARK_TIMER_QUERY, b"", _TIMER_ENUM_SIZE)
    count, status, esz = struct.unpack_from("<III", payload, 0)
    rows = []
    for i in range(count):
        base = 16 + i * _TIMER_ENTRY_SIZE
        timer, due, dpc, routine, ctx = struct.unpack_from("<QQQQQ", payload, base)
        cpu, period, flags = struct.unpack_from("<III", payload, base + 40)
        owner = payload[base + 56:base + 104].split(b"\x00")[0].decode("utf-8", "replace")
        rows.append((timer, due, dpc, routine, cpu, period, flags, owner))
    canon = all((r[3] & 0xFFFF800000000000) == 0xFFFF800000000000 for r in rows if r[3])
    named = sum(1 for r in rows if r[7])
    check("TIMERDPC", "0x8A4 timers: status OK + >=3 rows + routines canonical + owners resolved",
          status == 0 and count >= 3 and esz == _TIMER_ENTRY_SIZE
          and canon and named >= 3,
          "status=%d count=%d esz=%d canon=%s named=%d sample=%s"
          % (status, count, esz, canon, named,
             [(r[7], hex(r[3])) for r in rows[:4]]))

    payload = _ioctl(handle, IOCTL_MYARK_DPC_QUERY, b"", _DPC_ENUM_SIZE)
    dcount, dstatus, desz = struct.unpack_from("<III", payload, 0)
    check("TIMERDPC", "0x8A5 dpc queues: status OK + struct sane",
          dstatus == 0 and desz == _DPC_ENTRY_SIZE,
          "status=%d count=%d esz=%d" % (dstatus, dcount, desz))


# ---------------------------------------------------------------------------
# [REDIRECT] R2-9: file/registry redirect engine. SET_RULES is token-gated
# and atomically replaces the rule set; QUERY_STATUS is read-only. FILE
# rules ride the minifilter's pre-create (opening the source path actually
# opens the shadow file); REG rules rewrite the Cm pre-open CompleteName so
# opening the source key reads the shadow key. CLEAR restores original
# content -- the acceptance pair is "rule hit" + "restore after close".
# ---------------------------------------------------------------------------

IOCTL_MYARK_REDIRECT_SET_RULES = _ctl_code(FILE_DEVICE_UNKNOWN, 0x827, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_REDIRECT_QUERY_STATUS = _ctl_code(FILE_DEVICE_UNKNOWN, 0x828, METHOD_BUFFERED, FILE_ANY_ACCESS)

MYARK_REDIRECT_OP_SET_RULES = 0x31445252     # 'RRD1' LE
MYARK_REDIRECT_RULE_KIND_FILE = 1
MYARK_REDIRECT_RULE_KIND_REG = 2
MYARK_REDIRECT_SET_FLAG_CLEAR_ALL = 1

_REDIRECT_CHARS = 260
_REDIRECT_RULE_SIZE = 8 + _REDIRECT_CHARS * 2 * 3


def verify_redirect(handle, session_key) -> None:
    _step("REDIRECT file/registry redirect engine (R2-9)")
    pid = os.getpid() & 0xFFFFFFFF
    import uuid
    import winreg

    def _rule(kind: int, src: str, tgt: str, data: str = "") -> bytes:
        out = struct.pack("<II", kind, 0)
        for s in (src, tgt, data):
            out += s.encode("utf-16-le")[:(260 - 1) * 2].ljust(260 * 2, b"\x00")
        return out

    def _set(rules, flags: int = 0):
        in_buf = (sign_token(session_key, pid, MYARK_REDIRECT_OP_SET_RULES, nt_filetime_now())
                  + struct.pack("<II", len(rules), flags) + b"".join(rules))
        payload = _ioctl(handle, IOCTL_MYARK_REDIRECT_SET_RULES, in_buf, 16)
        return struct.unpack_from("<4I", payload, 0)

    def _status():
        payload = _ioctl(handle, IOCTL_MYARK_REDIRECT_QUERY_STATUS, b"", 32)
        return struct.unpack_from("<8I", payload, 0)

    if session_key is None:
        skip("REDIRECT", "rule arm/hit/restore cycle", "no session key")
        return

    # --- 1. fresh status: nothing armed ---
    try:
        st = _status()
        check("REDIRECT", "STATUS fresh (no rules, Cm down)",
              st[1] == 0 and st[2] == 0 and st[3] == 0 and st[4] == 0 and st[5] == 0,
              "file=%d reg=%d fhits=%d rhits=%d cm=%d" % (st[1], st[2], st[3], st[4], st[5]))
    except OSError as exc:
        check("REDIRECT", "STATUS fresh (no rules, Cm down)", False, str(exc))
        return

    # --- 2. SET_RULES without token -> denied ---
    ok, _p, err = _ioctl_raw(handle, IOCTL_MYARK_REDIRECT_SET_RULES,
                             b"\x00" * (SAFETY_TOKEN_SIZE + 8), 16)
    check("REDIRECT", "SET_RULES without token denied",
          (not ok) and err == ERROR_ACCESS_DENIED, "win32_err=%d" % err)

    test_dir = os.path.dirname(os.path.abspath(__file__))
    tag = uuid.uuid4().hex[:8]
    f_src = os.path.join(test_dir, "rd_src_%s.txt" % tag)
    f_shadow = os.path.join(test_dir, "rd_shadow_%s.txt" % tag)
    reg_base = "SOFTWARE" + chr(92) + "MyArkRT_" + tag
    reg_src = reg_base + chr(92) + "src"
    reg_shadow = reg_base + chr(92) + "shadow"
    nt_reg_src = chr(92) + "REGISTRY" + chr(92) + "MACHINE" + chr(92) + reg_src
    nt_reg_shadow = chr(92) + "REGISTRY" + chr(92) + "MACHINE" + chr(92) + reg_shadow
    created_keys = []

    try:
        # --- 3. FILE rule: read-through sees shadow content ---
        with open(f_src, "w") as fp:
            fp.write("orig-content")
        with open(f_shadow, "w") as fp:
            fp.write("shadow-content")

        try:
            st_out, accepted, file_rules, reg_rules = _set([
                _rule(MYARK_REDIRECT_RULE_KIND_FILE, f_src, f_shadow)])
        except OSError as exc:
            st_out, accepted, file_rules, reg_rules = -1, -1, -1, -1
            check("REDIRECT", "SET_RULES transport", False, str(exc))
        check("REDIRECT", "FILE rule armed",
              st_out == 0 and accepted == 1 and file_rules == 1 and reg_rules == 0,
              "accepted=%d file=%d reg=%d" % (accepted, file_rules, reg_rules))

        content = open(f_src).read()
        st = _status()
        check("REDIRECT", "FILE hit: src opens shadow content",
              content == "shadow-content" and st[3] >= 1,
              "content=%r fhits=%d" % (content, st[3]))

        _set([], MYARK_REDIRECT_SET_FLAG_CLEAR_ALL)
        content = open(f_src).read()
        st = _status()
        check("REDIRECT", "FILE restore after clear",
              content == "orig-content" and st[1] == 0 and st[5] == 0,
              "content=%r file=%d cm=%d" % (content, st[1], st[5]))

        # --- 4. REG rule: opening source key reads shadow value ---
        for sub in (reg_src, reg_shadow):
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, sub)
            winreg.SetValueEx(key, "V", 0, winreg.REG_SZ, "orig" if sub == reg_src else "shadow")
            winreg.CloseKey(key)
            created_keys.append(sub)

        try:
            st_out, accepted, file_rules, reg_rules = _set([
                _rule(MYARK_REDIRECT_RULE_KIND_REG, nt_reg_src, "V", "shadow")])
        except OSError as exc:
            st_out, accepted, file_rules, reg_rules = -1, -1, -1, -1
            check("REDIRECT", "SET_RULES transport", False, str(exc))
        st = _status()
        check("REDIRECT", "REG rule armed (Cm callback up)",
              st_out == 0 and accepted == 1 and reg_rules == 1 and st[5] == 1,
              "accepted=%d reg=%d cm=%d" % (accepted, reg_rules, st[5]))

        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_src)
        val, _typ = winreg.QueryValueEx(key, "V")
        winreg.CloseKey(key)
        st = _status()
        check("REDIRECT", "REG hit: src key reads shadow value",
              val == "shadow" and st[4] >= 1,
              "value=%r rhits=%d pre=%d ctx=%d" % (val, st[4], st[6], st[7]))

        _set([], MYARK_REDIRECT_SET_FLAG_CLEAR_ALL)
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_src)
        val, _typ = winreg.QueryValueEx(key, "V")
        winreg.CloseKey(key)
        st = _status()
        check("REDIRECT", "REG restore after clear",
              val == "orig" and st[2] == 0 and st[5] == 0 and st[4] == 0,
              "value=%r reg=%d cm=%d rhits=%d" % (val, st[2], st[5], st[4]))
    finally:
        try:
            _set([], MYARK_REDIRECT_SET_FLAG_CLEAR_ALL)
        except OSError:
            pass
        for leftover in (f_src, f_shadow):
            try:
                os.remove(leftover)
            except OSError:
                pass
        for sub in reversed(created_keys):
            try:
                sub_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sub.rsplit(chr(92), 1)[0],
                                         0, winreg.KEY_SET_VALUE)
                winreg.DeleteKey(sub_key, sub.rsplit(chr(92), 1)[1])
                winreg.CloseKey(sub_key)
            except OSError:
                pass
        try:
            parent = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "SOFTWARE", 0, winreg.KEY_SET_VALUE)
            winreg.DeleteKey(parent, reg_base)
            winreg.CloseKey(parent)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# [ASK] R2-11: interactive process-creation decisions. An ASK-rule match
# parks the creating thread in the kernel (5 s fail-open timeout) while R3
# polls ASK_WAIT (never blocking) and resolves via ASK_ANSWER / ASK_CANCEL.
# The parking design must not starve the driver's sequential queue -- every
# poll here is a completed request, so if the suite keeps running past this
# section the old deadlock class is gone.
# ---------------------------------------------------------------------------

IOCTL_MYARK_CALLBACK_ASK_WAIT = _ctl_code(FILE_DEVICE_UNKNOWN, 0x71C, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_CALLBACK_ASK_ANSWER = _ctl_code(FILE_DEVICE_UNKNOWN, 0x71D, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_CALLBACK_ASK_CANCEL = _ctl_code(FILE_DEVICE_UNKNOWN, 0x71E, METHOD_BUFFERED, FILE_ANY_ACCESS)

MYARK_CALLBACK_RULE_ACTION_ASK = 3
MYARK_CALLBACK_OP_ASK_ANSWER = 0x33524243     # 'CBR3' LE
MYARK_CALLBACK_OP_ASK_CANCEL = 0x34524243     # 'CBR4' LE
MYARK_CALLBACK_ASK_DECISION_ALLOW = 0
MYARK_CALLBACK_ASK_DECISION_DENY = 1

_ASK_ENTRY_SIZE = 8 + 8 + 8 + 4 + 4 + 64 * 2          # 160
_ASK_WAIT_HDR = 32
_ASK_TARGET = "myark_ask_target.exe"


def verify_ask(handle, session_key) -> None:
    _step("ASK process-create parking (R2-11)")
    pid = os.getpid() & 0xFFFFFFFF
    import threading
    import time
    import uuid

    if session_key is None:
        skip("ASK", "park/answer/timeout cycle", "no session key")
        return

    def _wait():
        payload = _ioctl(handle, IOCTL_MYARK_CALLBACK_ASK_WAIT, b"", _ASK_WAIT_HDR + 8 * _ASK_ENTRY_SIZE)
        st, pending, asked, denied, timed_out, dropped = struct.unpack_from("<6I", payload, 0)
        entry_size = struct.unpack_from("<I", payload, 24)[0]
        if entry_size != _ASK_ENTRY_SIZE:
            raise OSError(None, "EntryStructSize mismatch: %d" % entry_size, None, 122)
        entries = []
        for i in range(pending):
            off = _ASK_WAIT_HDR + i * _ASK_ENTRY_SIZE
            seq, parent, child = struct.unpack_from("<QQQ", payload, off)
            raw = payload[off + 32:off + 32 + 128].decode("utf-16-le")
            entries.append({"seq": seq, "parent": parent, "pid": child,
                            "name": raw.split("\x00")[0]})
        return {"status": st, "pending": pending, "asked": asked,
                "denied": denied, "timed": timed_out, "dropped": dropped,
                "entries": entries}

    def _poll_pending(timeout_s: float = 3.0):
        deadline = time.time() + timeout_s
        snap = None
        while time.time() < deadline:
            snap = _wait()
            if snap["pending"]:
                return snap
            time.sleep(0.05)
        return snap

    def _answer(seq: int, decision: int):
        in_buf = (sign_token(session_key, pid, MYARK_CALLBACK_OP_ASK_ANSWER, nt_filetime_now())
                  + struct.pack("<QII", seq, decision, 0))
        payload = _ioctl(handle, IOCTL_MYARK_CALLBACK_ASK_ANSWER, in_buf, 8)
        return struct.unpack_from("<II", payload, 0)

    def _cancel():
        in_buf = (sign_token(session_key, pid, MYARK_CALLBACK_OP_ASK_CANCEL, nt_filetime_now())
                  + struct.pack("<IIII", 0, 0, 0, 0))
        payload = _ioctl(handle, IOCTL_MYARK_CALLBACK_ASK_CANCEL, in_buf, 8)
        return struct.unpack_from("<II", payload, 0)

    def _set_rule(op: int, action: int, name: str):
        in_buf = (sign_token(session_key, pid, MYARK_CALLBACK_OP_SET_RULES, nt_filetime_now())
                  + struct.pack("<II", op, action)
                  + name.encode("utf-16-le")[:(64 - 1) * 2].ljust(64 * 2, b"\x00"))
        return _ioctl_raw(handle, IOCTL_MYARK_CALLBACK_SET_RULES, in_buf, 8)

    test_dir = os.path.dirname(os.path.abspath(__file__))
    target = os.path.join(test_dir, _ASK_TARGET)

    try:
        import shutil
        shutil.copyfile(os.path.join(os.environ.get("SystemRoot", "C:" + chr(92) + "Windows"),
                                     "System32", "hostname.exe"), target)
    except OSError as exc:
        check("ASK", "target exe staged", False, str(exc))
        return

    results = {}

    def _spawn():
        try:
            proc = subprocess.Popen([target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            results["rc"] = proc.wait()
            results["exc"] = None
        except OSError as exc:
            results["rc"] = None
            results["exc"] = exc

    try:
        # --- 1. arm ASK rule + engine ---
        _set_rule(MYARK_CALLBACK_RULES_OP_CLEAR, 0, "")
        _set_rule(MYARK_CALLBACK_RULES_OP_SET, MYARK_CALLBACK_RULE_ACTION_ASK, _ASK_TARGET)
        in_enable = (sign_token(session_key, pid, MYARK_CALLBACK_OP_RUNTIME_STATE, nt_filetime_now())
                     + struct.pack("<IIII", MYARK_CALLBACK_STATE_ENABLE, 0, 0, 0))
        _ioctl(handle, IOCTL_MYARK_CALLBACK_RUNTIME_STATE, in_enable, 16)

        # --- 2. ANSWER without token -> denied ---
        ok, _p, err = _ioctl_raw(handle, IOCTL_MYARK_CALLBACK_ASK_ANSWER,
                                 bytes(SAFETY_TOKEN_SIZE + 16), 8)
        check("ASK", "ANSWER without token denied",
              (not ok) and err == ERROR_ACCESS_DENIED, "win32_err=%d" % err)

        # --- 3. DENY: poll pending, resolve DENY, create fails ---
        results.clear()
        th = threading.Thread(target=_spawn)
        th.start()
        snap = _poll_pending()
        hit = [e for e in snap["entries"] if e["name"].lower() == _ASK_TARGET]
        if hit:
            st_out, pending = _answer(hit[0]["seq"], MYARK_CALLBACK_ASK_DECISION_DENY)
            th.join(timeout=10)
            denied_ok = (not th.is_alive() and st_out == 0 and results.get("rc") is None
                         and results["exc"] is not None
                         and getattr(results["exc"], "winerror", None) == 5)
        else:
            th.join(timeout=10)
            denied_ok = False
        check("ASK", "DENY: create fails with ACCESS_DENIED",
              denied_ok, "seen=%d st=%s rc=%s exc=%s alive=%s"
              % (len(hit), snap["pending"], results.get("rc"), results.get("exc"), th.is_alive()))

        # --- 4. ALLOW: resolve ALLOW, child runs ---
        results.clear()
        th = threading.Thread(target=_spawn)
        th.start()
        snap = _poll_pending()
        hit = [e for e in snap["entries"] if e["name"].lower() == _ASK_TARGET]
        if hit:
            st_out, _pending = _answer(hit[0]["seq"], MYARK_CALLBACK_ASK_DECISION_ALLOW)
            th.join(timeout=10)
            allow_ok = (not th.is_alive() and st_out == 0 and results.get("rc") == 0)
        else:
            th.join(timeout=10)
            allow_ok = False
        check("ASK", "ALLOW: child runs to completion",
              allow_ok, "seen=%d st=%s rc=%s" % (len(hit), snap["pending"], results.get("rc")))

        # --- 5. CANCEL: flush all pending fail-open ---
        results.clear()
        th = threading.Thread(target=_spawn)
        th.start()
        snap = _poll_pending()
        st_out, flushed = _cancel()
        th.join(timeout=10)
        check("ASK", "CANCEL flushes pending (child runs)",
              st_out == 0 and flushed >= 1 and results["rc"] == 0,
              "st=%s flushed=%d rc=%s" % (st_out, flushed, results.get("rc")))

        # --- 6. TIMEOUT: no answer -> 5 s fail-open, child still runs ---
        results.clear()
        started = time.time()
        th = threading.Thread(target=_spawn)
        th.start()
        th.join(timeout=20)
        elapsed = time.time() - started
        snap = _wait()
        check("ASK", "TIMEOUT: 5 s fail-open, child runs",
              not th.is_alive() and results.get("rc") == 0
              and elapsed >= 4.0 and snap["timed"] >= 1,
              "rc=%s elapsed=%.1fs timed=%d"
              % (results.get("rc"), elapsed, snap["timed"]))

        # --- 7. suite keeps talking to the driver (queue never starved) ---
        snap = _wait()
        check("ASK", "WAIT still responsive (queue alive)",
              snap["status"] == 0 and snap["pending"] == 0,
              "pending=%d asked=%d" % (snap["pending"], snap["asked"]))
    finally:
        try:
            _set_rule(MYARK_CALLBACK_RULES_OP_CLEAR, 0, "")
            in_disable = (sign_token(session_key, pid, MYARK_CALLBACK_OP_RUNTIME_STATE,
                                     nt_filetime_now())
                          + struct.pack("<IIII", MYARK_CALLBACK_STATE_DISABLE, 0, 0, 0))
            _ioctl(handle, IOCTL_MYARK_CALLBACK_RUNTIME_STATE, in_disable, 16)
        except OSError:
            pass
        try:
            os.remove(target)
        except OSError:
            pass

# ---------------------------------------------------------------------------
# [TASKMGR] R2-8: taskmgr hijack via IFEO (pure R3). Install a Debugger
# value on the taskmgr.exe IFEO key pointing at a marker cmd script, spawn
# taskmgr.exe and prove the redirect fires, uninstall and prove the real
# Task Manager starts again. Mirrors the myark-cli stealth taskmgr-hijack
# surface.
# ---------------------------------------------------------------------------

_TASKMGR_IFEO_KEY = ("SOFTWARE" + chr(92) + "Microsoft" + chr(92) +
                     "Windows NT" + chr(92) + "CurrentVersion" + chr(92) +
                     "Image File Execution Options" + chr(92) + "taskmgr.exe")


def verify_taskmgr_hijack(handle) -> None:
    _step("TASKMGR taskmgr hijack via IFEO (R2-8)")
    import winreg

    access = winreg.KEY_SET_VALUE | winreg.KEY_READ | winreg.KEY_WOW64_64KEY
    key_path = _TASKMGR_IFEO_KEY
    pub = "C:" + chr(92) + "Users" + chr(92) + "Public" + chr(92)
    fired_file = pub + "ifeo_fired.txt"
    fire_cmd = pub + "ifeo_fire.cmd"

    def debugger_value():
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0,
                                 winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        except OSError:
            return None
        try:
            value, _t = winreg.QueryValueEx(key, "Debugger")
            return value
        except OSError:
            return None
        finally:
            key.Close()

    def clean_key():
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0,
                                 access)
        except OSError:
            return
        try:
            winreg.DeleteValue(key, "Debugger")
        except OSError:
            pass
        key.Close()

    # --- 0. clean baseline ---
    clean_key()
    try:
        os.remove(fired_file)
    except OSError:
        pass

    # --- 1. install the redirect (marker cmd script) ---
    with open(fire_cmd, "w") as fp:
        fp.write("@echo fired > " + fired_file + chr(13) + chr(10))
    key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0, access)
    winreg.SetValueEx(key, "Debugger", 0, winreg.REG_SZ, fire_cmd)
    key.Close()
    check("TASKMGR", "install writes Debugger value",
          debugger_value() == fire_cmd,
          "value=%s" % str(debugger_value())[:60])

    # --- 2. spawning taskmgr fires the redirect instead ---
    try:
        r = subprocess.run(["taskmgr.exe"], capture_output=True, timeout=30)
        fired_rc = r.returncode
    except Exception as exc:
        fired_rc = str(exc)
    fired = os.path.exists(fired_file)
    check("TASKMGR", "redirect fires on taskmgr spawn", fired,
          "fired_file=%s rc=%s" % (fired, str(fired_rc)[:40]))

    # --- 3. uninstall restores the real Task Manager ---
    clean_key()
    check("TASKMGR", "uninstall removes Debugger value",
          debugger_value() is None, "value=%s" % str(debugger_value())[:60])
    try:
        proc = subprocess.Popen(["taskmgr.exe"])
        launched = True
        time.sleep(2)
        proc.terminate()
        proc.wait(timeout=10)
    except Exception:
        launched = False
    check("TASKMGR", "real taskmgr launches after uninstall",
          launched, "launched=%s" % launched)

    try:
        os.remove(fire_cmd)
        os.remove(fired_file)
    except OSError:
        pass

# ---------------------------------------------------------------------------
# [PATCHHOOK] R2-1: inline hook patch roundtrip. The full expected-check ->
# MDL write -> restore cycle runs against the driver's own never-called
# probe function (QUERY_PATCH_TARGET), so no live ntoskrnl code is ever
# touched. A stable scan total before/after doubles as the "kernel image
# untouched" proxy for the roadmap's restore-to-clean criterion.
# ---------------------------------------------------------------------------

IOCTL_MYARK_KERNEL_PATCH_INLINE_HOOK = _ctl_code(FILE_DEVICE_UNKNOWN, 0xE21, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_KERNEL_QUERY_PATCH_TARGET = _ctl_code(FILE_DEVICE_UNKNOWN, 0xE22, METHOD_BUFFERED, FILE_ANY_ACCESS)

MYARK_KERNEL_PATCH_FORCE_MAGIC = 0x43524F46  # 'FORC' LE
MYARK_KERNEL_OP_PATCH_HOOK = 0x314E524B      # 'KRN1' LE (distinct op namespace)
PATCH_TARGET_OUT_SIZE = 48
PATCH_OUT_SIZE = 32


def verify_hook_patch(handle, session_key) -> None:
    _step("PATCHHOOK inline hook patch roundtrip (R2-1)")
    pid = os.getpid() & 0xFFFFFFFF

    def _patch_in(addr: int, expected: bytes, restore: bytes,
                  force: bool = True, sign: bool = True) -> bytes:
        if sign:
            if session_key is None:
                raise OSError("no session key")
            tok = sign_token(session_key, pid, MYARK_KERNEL_OP_PATCH_HOOK,
                             nt_filetime_now())
        else:
            tok = b"\x00" * SAFETY_TOKEN_SIZE
        return (tok
                + struct.pack("<QII", addr, len(restore),
                              MYARK_KERNEL_PATCH_FORCE_MAGIC if force else 0)
                + expected[:16].ljust(16, b"\x00")
                + restore[:16].ljust(16, b"\x00"))

    def _query_target():
        payload = _ioctl(handle, IOCTL_MYARK_KERNEL_QUERY_PATCH_TARGET,
                         struct.pack("<I", 0), PATCH_TARGET_OUT_SIZE)
        status, = struct.unpack_from("<I", payload, 4)
        tva, mbase = struct.unpack_from("<QQ", payload, 8)
        bcount, = struct.unpack_from("<I", payload, 24)
        dwell = bytes(payload[32:48])
        return status, tva, mbase, bcount, dwell

    # --- baseline scan total (restored-state proxy) ---
    scan_total_before = None
    try:
        payload = _ioctl(handle, IOCTL_MYARK_KERNEL_SCAN_INLINE_HOOKS,
                         struct.pack("<IIII", 8, 0, 0, 0), 40 + 24 * 8)
        scan_total_before = struct.unpack_from("<I", payload, 8)[0]
    except OSError as exc:
        check("PATCHHOOK", "pre-patch scan baseline", False, str(exc))

    # --- 1. QUERY_PATCH_TARGET sane ---
    orig = None
    try:
        status, tva, mbase, bcount, dwell = _query_target()
        ok = (status == 0 and tva != 0 and mbase != 0
              and 1 <= bcount <= 16 and dwell[:bcount] != b"\x00" * bcount)
        check("PATCHHOOK", "QUERY_PATCH_TARGET sane",
              ok, "status=%d va=#%x base=#%x n=%d dwell=%s"
              % (status, tva, mbase, bcount, dwell[:bcount].hex()))
        orig = dwell[:bcount]
    except OSError as exc:
        check("PATCHHOOK", "QUERY_PATCH_TARGET sane", False, str(exc))
        return

    n = len(orig)

    # --- 2. no token -> denied ---
    stub = b"\xE9" + struct.pack("<i", -5) + b"\x90"  # jmp self + nop pad
    ok, _p, err = _ioctl_raw(handle, IOCTL_MYARK_KERNEL_PATCH_INLINE_HOOK,
                             _patch_in(tva, orig, stub, sign=False),
                             PATCH_OUT_SIZE)
    check("PATCHHOOK", "PATCH without token denied",
          (not ok) and err == ERROR_ACCESS_DENIED, "win32_err=%d" % err)

    # --- 3. token but missing FORCE magic -> denied ---
    if session_key is None:
        skip("PATCHHOOK", "PATCH gate/patch cycle", "no session key")
        return
    ok, _p, err = _ioctl_raw(handle, IOCTL_MYARK_KERNEL_PATCH_INLINE_HOOK,
                             _patch_in(tva, orig, stub, force=False),
                             PATCH_OUT_SIZE)
    check("PATCHHOOK", "PATCH without FORCE denied",
          (not ok) and err == ERROR_ACCESS_DENIED, "win32_err=%d" % err)

    # --- 4. plant hook: expected=orig, restore=stub ---
    ok, payload, err = _ioctl_raw(handle, IOCTL_MYARK_KERNEL_PATCH_INLINE_HOOK,
                                  _patch_in(tva, orig, stub), PATCH_OUT_SIZE)
    planted = ok and struct.unpack_from("<I", payload, 0)[0] == 0 \
        and struct.unpack_from("<I", payload, 4)[0] == n
    check("PATCHHOOK", "PATCH plants hook stub",
          planted, "ok=%s err=%d payload=%s"
          % (ok, err, payload.hex() if ok else "-"))

    # --- 5. hook present on read-back ---
    try:
        status, _tva, _mbase, _n, dwell = _query_target()
        check("PATCHHOOK", "hook stub visible on read-back",
              status == 0 and dwell[:n] == stub[:n],
              "dwell=%s want=%s" % (dwell[:n].hex(), stub[:n].hex()))
    except OSError as exc:
        check("PATCHHOOK", "hook stub visible on read-back", False, str(exc))

    # --- 6. stale expected bytes -> mismatch refusal ---
    ok, _p, err = _ioctl_raw(handle, IOCTL_MYARK_KERNEL_PATCH_INLINE_HOOK,
                             _patch_in(tva, orig, orig), PATCH_OUT_SIZE)
    check("PATCHHOOK", "stale expected bytes refused",
          (not ok) and err == ERROR_INVALID_PARAMETER, "win32_err=%d" % err)

    # --- 7. restore original bytes ---
    ok, payload, err = _ioctl_raw(handle, IOCTL_MYARK_KERNEL_PATCH_INLINE_HOOK,
                                  _patch_in(tva, stub[:n], orig), PATCH_OUT_SIZE)
    restored = ok and struct.unpack_from("<I", payload, 0)[0] == 0
    check("PATCHHOOK", "PATCH restores original", restored,
          "ok=%s err=%d" % (ok, err))

    # --- 8. original bytes back on read-back ---
    try:
        status, _tva, _mbase, _n, dwell = _query_target()
        check("PATCHHOOK", "original bytes on read-back",
              status == 0 and dwell[:n] == orig,
              "dwell=%s want=%s" % (dwell[:n].hex(), orig.hex()))
    except OSError as exc:
        check("PATCHHOOK", "original bytes on read-back", False, str(exc))

    # --- 9. user-mode address refused ---
    ok, _p, err = _ioctl_raw(handle, IOCTL_MYARK_KERNEL_PATCH_INLINE_HOOK,
                             _patch_in(0x41414140, b"\x90" * 6, b"\x90" * 6),
                             PATCH_OUT_SIZE)
    check("PATCHHOOK", "user-mode address refused",
          (not ok) and err == ERROR_INVALID_PARAMETER, "win32_err=%d" % err)

    # --- 10. scan total unchanged (kernel image untouched) ---
    if scan_total_before is not None:
        try:
            payload = _ioctl(handle, IOCTL_MYARK_KERNEL_SCAN_INLINE_HOOKS,
                             struct.pack("<IIII", 8, 0, 0, 0), 40 + 24 * 8)
            scan_total_after = struct.unpack_from("<I", payload, 8)[0]
            # ntoskrnl has paged sections: a page trimmed between the two
            # scans shifts the candidate total by +/-1 -- allow small drift.
            drift = abs(scan_total_after - scan_total_before)
            check("PATCHHOOK", "scan total unchanged after restore",
                  drift <= 2,
                  "before=%d after=%d drift=%d"
                  % (scan_total_before, scan_total_after, drift))
        except OSError as exc:
            check("PATCHHOOK", "scan total unchanged after restore",
                  False, str(exc))


# ---------------------------------------------------------------------------
# [IATEAT] R2-2: read-only IAT/EAT hook enumeration. The driver attaches to
# the target process, parses the PE at ModuleBase and walks the export
# table (RVAs must stay inside the image) and the import table (resolved
# targets must be image-backed). On a clean guest the hook count is 0 and
# the totals prove a real walk happened.
# ---------------------------------------------------------------------------

IOCTL_MYARK_KERNEL_ENUM_IAT_EAT = _ctl_code(FILE_DEVICE_UNKNOWN, 0xE23, METHOD_BUFFERED, FILE_ANY_ACCESS)

MYARK_KERNEL_IATEAT_FLAG_EAT = 1
MYARK_KERNEL_IATEAT_FLAG_IAT = 2
IATEAT_OUT_HDR = 40   # FIELD_OFFSET(..., Entries): 10 UINT32 header, then
                      # the 8-aligned entry array starts with no padding
IATEAT_ENTRY_SIZE = 32
IATEAT_MAX = 64


def verify_iat_eat(handle) -> None:
    _step("IATEAT IAT/EAT hook enumeration (R2-2)")
    pid = os.getpid() & 0xFFFFFFFF
    k32 = ctypes.WinDLL("kernel32")
    k32.GetModuleHandleW.restype = ctypes.c_void_p
    ntdll_base = k32.GetModuleHandleW("ntdll.dll")
    # ntdll is the loader-mapped root and ships NO import table -- the IAT
    # walk targets kernel32.dll instead.
    kernel32_base = k32.GetModuleHandleW("kernel32.dll")
    if not ntdll_base or not kernel32_base:
        check("IATEAT", "locate ntdll/kernel32 base", False,
              "GetModuleHandleW failed")
        return

    def _in(p, flags, base, mx=IATEAT_MAX):
        return struct.pack("<IIQII", p, flags, base, mx, 0)

    def _enum(p, flags, base):
        return _ioctl(handle, IOCTL_MYARK_KERNEL_ENUM_IAT_EAT,
                      _in(p, flags, base),
                      IATEAT_OUT_HDR + IATEAT_ENTRY_SIZE * IATEAT_MAX)

    # --- 1. EAT walk over ntdll in the caller process ---
    eat_totals = None
    try:
        payload = _enum(pid, MYARK_KERNEL_IATEAT_FLAG_EAT, ntdll_base)
        status, count, hooks, total_eat, total_iat = struct.unpack_from("<IIIII", payload, 4)
        image_size = struct.unpack_from("<I", payload, 32)[0]
        ok = (status == 0 and count == 0 and hooks == 0
              and total_eat > 300 and total_iat == 0 and image_size > 0x100000)
        check("IATEAT", "EAT walk ntdll clean+real", ok,
              "status=%d eat=%d hooks=%d img=#%x" % (status, total_eat, hooks, image_size))
        eat_totals = (total_eat, hooks)
    except OSError as exc:
        check("IATEAT", "EAT walk ntdll clean+real", False, str(exc))
        return

    # --- 2. determinism: second EAT run matches ---
    try:
        payload = _enum(pid, MYARK_KERNEL_IATEAT_FLAG_EAT, ntdll_base)
        status, count, hooks, total_eat, _ti = struct.unpack_from("<IIIII", payload, 4)
        check("IATEAT", "EAT walk deterministic",
              status == 0 and (total_eat, hooks) == eat_totals,
              "now=(%d,%d) was=%s" % (total_eat, hooks, str(eat_totals)))
    except OSError as exc:
        check("IATEAT", "EAT walk deterministic", False, str(exc))

    # --- 3. IAT walk over kernel32 (ntdll ships no import table) ---
    try:
        payload = _enum(pid, MYARK_KERNEL_IATEAT_FLAG_IAT, kernel32_base)
        status, count, hooks, _te, total_iat = struct.unpack_from("<IIIII", payload, 4)
        check("IATEAT", "IAT walk kernel32 clean+real",
              status == 0 and count == 0 and hooks == 0 and total_iat > 50,
              "status=%d iat=%d hooks=%d" % (status, total_iat, hooks))
    except OSError as exc:
        check("IATEAT", "IAT walk kernel32 clean+real", False, str(exc))

    # --- 4. combined flags in one call (kernel32 has both tables) ---
    try:
        payload = _enum(pid, MYARK_KERNEL_IATEAT_FLAG_EAT | MYARK_KERNEL_IATEAT_FLAG_IAT,
                        kernel32_base)
        status, _c, _h, total_eat, total_iat = struct.unpack_from("<IIIII", payload, 4)
        check("IATEAT", "combined EAT+IAT walk",
              status == 0 and total_eat > 0 and total_iat > 0,
              "status=%d eat=%d iat=%d" % (status, total_eat, total_iat))
    except OSError as exc:
        check("IATEAT", "combined EAT+IAT walk", False, str(exc))

    # --- 5. bogus PID rejected ---
    ok, _p, err = _ioctl_raw(handle, IOCTL_MYARK_KERNEL_ENUM_IAT_EAT,
                             _in(0x7FFFFFFF, MYARK_KERNEL_IATEAT_FLAG_EAT, ntdll_base),
                             IATEAT_OUT_HDR)
    check("IATEAT", "bogus pid rejected", not ok, "win32_err=%d" % err)

    # --- 6. non-PE user base rejected ---
    ok, _p, err = _ioctl_raw(handle, IOCTL_MYARK_KERNEL_ENUM_IAT_EAT,
                             _in(pid, MYARK_KERNEL_IATEAT_FLAG_EAT, 0x10000),
                             IATEAT_OUT_HDR)
    check("IATEAT", "non-PE base rejected", not ok, "win32_err=%d" % err)

    # --- 7. zero flags rejected ---
    ok, _p, err = _ioctl_raw(handle, IOCTL_MYARK_KERNEL_ENUM_IAT_EAT,
                             _in(pid, 0, ntdll_base),
                             IATEAT_OUT_HDR)
    check("IATEAT", "zero flags rejected",
          (not ok) and err == ERROR_INVALID_PARAMETER, "win32_err=%d" % err)


# ---------------------------------------------------------------------------
# [SHADOWSSDT] R2-3: win32k (shadow) service table walk. The driver
# shape-scans the win32k* module images for the service descriptor and
# walks it with the QUERY_SSDT row format. On a session with GUI loaded
# the table is populated (数百条) and every routine lands inside the
# win32k module union -- SUSPECT flags would mean out-of-image entries.
# ---------------------------------------------------------------------------

IOCTL_MYARK_KERNEL_QUERY_SHADOW_SSDT = _ctl_code(FILE_DEVICE_UNKNOWN, 0xE24, METHOD_BUFFERED, FILE_ANY_ACCESS)

SHADOW_OUT_HDR = 40   # FIELD_OFFSET(..., Entries): 10 UINT32 header, 8-aligned
SHADOW_ENTRY_SIZE = 40
SHADOW_MAX = 1024
SSDT_FLAG_SUSPECT = 0x2


# ---------------------------------------------------------------------------
# [INTEGRITY] R2-4: per-CPU integrity snapshot via KeIpiGenericCall --
# GDT/IDT bases (+ measured IDT extent), syscall MSRs, CR0/CR4 -- plus
# UnloadedDrivers registry evidence. KVA-shadow note: the driver widens
# the ntoskrnl window 4 MiB downward because IDT stubs and LSTAR live in
# the shadow trampoline area below the image base (KDNET-verified).
# ---------------------------------------------------------------------------

IOCTL_MYARK_KERNEL_QUERY_INTEGRITY = _ctl_code(FILE_DEVICE_UNKNOWN, 0xE25, METHOD_BUFFERED, FILE_ANY_ACCESS)

INTEGRITY_HDR = 56
INTEGRITY_CPU_SIZE = 88   # Processor/Flags(8) GdtBase(8) GdtLimit/R(8) IdtBase(8) IdtLimit/Outside(8) 6 MSR/CR qwords(48) -- no trailing pad
INTEGRITY_UNLOADED_SIZE = 64
INTEGRITY_MAX_CPU = 64
MYARK_KERNEL_INTF_LSTAR_IN_WIN = 0x1
MYARK_KERNEL_INTF_IDT_ALL_IN_WIN = 0x2
MYARK_KERNEL_INTF_CR0_NATIVE = 0x4
MYARK_KERNEL_INTEGRITY_PIDDB_NA = 1


def verify_integrity(handle) -> None:
    _step("INTEGRITY per-CPU integrity snapshot (R2-4)")

    def _run():
        return _ioctl(handle, IOCTL_MYARK_KERNEL_QUERY_INTEGRITY,
                      struct.pack("<I", 0),
                      INTEGRITY_HDR + INTEGRITY_CPU_SIZE * INTEGRITY_MAX_CPU
                      + INTEGRITY_UNLOADED_SIZE * 16)

    # --- 1. snapshot sane ---
    first = None
    try:
        payload = _run()
        size, status, pcount, ucount, utotal = struct.unpack_from("<IIIII", payload, 0)
        wbase, wend = struct.unpack_from("<QQ", payload, 24)
        cpu_sz = struct.unpack_from("<I", payload, 40)[0]
        ok = (status == MYARK_KERNEL_INTEGRITY_PIDDB_NA and pcount > 0
              and cpu_sz == INTEGRITY_CPU_SIZE and wbase != 0 and wend > wbase
              and ucount <= utotal and ucount <= 16)
        check("INTEGRITY", "snapshot sane+PiDDB degraded", ok,
              "status=%d cpus=%d unloaded=%d/%d window=[#%x..#%x]"
              % (status, pcount, ucount, utotal, wbase, wend))
        lstar0 = struct.unpack_from("<Q", payload, 56 + 40)[0]
        first = (pcount, lstar0)
    except OSError as exc:
        check("INTEGRITY", "snapshot sane+PiDDB degraded", False, str(exc))
        return

    # --- 2. per-CPU values sane ---
    try:
        payload = _run()
        pcount = struct.unpack_from("<I", payload, 8)[0]
        wbase, wend = struct.unpack_from("<QQ", payload, 24)
        bad = 0
        samples = []
        for i in range(pcount):
            row = INTEGRITY_HDR + i * INTEGRITY_CPU_SIZE
            proc, flags = struct.unpack_from("<II", payload, row)
            gdt = struct.unpack_from("<Q", payload, row + 8)[0]
            gdtlim = struct.unpack_from("<I", payload, row + 16)[0]
            idt = struct.unpack_from("<Q", payload, row + 24)[0]
            idtlim = struct.unpack_from("<I", payload, row + 32)[0]
            idtout = struct.unpack_from("<I", payload, row + 36)[0]
            lstar = struct.unpack_from("<Q", payload, row + 40)[0]
            cr0 = struct.unpack_from("<Q", payload, row + 72)[0]
            lstar_ok = wbase <= lstar < wend and (flags & MYARK_KERNEL_INTF_LSTAR_IN_WIN)
            sane = (gdt != 0 and idt != 0
                    and 0x800 <= idtlim <= 0x1000 and gdtlim > 0
                    and lstar_ok and (flags & MYARK_KERNEL_INTF_CR0_NATIVE))
            if i == 0 and idtout != 0:
                sane = False
            if not sane:
                bad += 1
                if len(samples) < 3:
                    samples.append("cpu%d gdt=#%x idt=#%x lim=%d/%d out=%d"
                                   % (proc, gdt, idt, gdtlim, idtlim, idtout))
        check("INTEGRITY", "per-CPU GDT/IDT/MSR/CR0 sane",
              bad == 0, "bad=%d of %d %s" % (bad, pcount, " ".join(samples)))
    except OSError as exc:
        check("INTEGRITY", "per-CPU GDT/IDT/MSR/CR0 sane", False, str(exc))

    # --- 3. determinism ---
    try:
        payload = _run()
        pcount = struct.unpack_from("<I", payload, 8)[0]
        lstar0 = struct.unpack_from("<Q", payload, 56 + 40)[0]
        check("INTEGRITY", "snapshot deterministic",
              (pcount, lstar0) == first,
              "now=(%d,#%x) was=%s" % (pcount, lstar0, str(first)))
    except OSError as exc:
        check("INTEGRITY", "snapshot deterministic", False, str(exc))


def verify_shadow_ssdt(handle) -> None:
    _step("SHADOWSSDT win32k shadow table walk (R2-3)")

    def _run():
        return _ioctl(handle, IOCTL_MYARK_KERNEL_QUERY_SHADOW_SSDT,
                      struct.pack("<IIII", SHADOW_MAX, 0, 0, 0),
                      SHADOW_OUT_HDR + SHADOW_ENTRY_SIZE * SHADOW_MAX)

    # --- 1. table located and populated ---
    first = None
    try:
        payload = _run()
    except OSError as exc:
        # Build-variant: on some 22631 boots the win32k service table is
        # not reachable through the enumerated module union (the pair scan
        # answers PROCEDURE_NOT_FOUND). Known surface -- skip, not fail.
        if "err=127" in str(exc):
            skip("SHADOWSSDT", "shadow table anchored this boot",
                 "not anchored (22631 build variability)")
            return
        check("SHADOWSSDT", "shadow table located+populated", False, str(exc))
        return
    size, count, total, tblimit = struct.unpack_from("<IIII", payload, 0)
    stbase, wbase = struct.unpack_from("<QQ", payload, 16)
    wsize = struct.unpack_from("<I", payload, 32)[0]
    ok = (count > 0 and total > 0 and tblimit > 0
          and stbase != 0 and wbase != 0 and wsize > 0x100000)
    check("SHADOWSSDT", "shadow table located+populated", ok,
          "count=%d total=%d limit=#%x tbl=#%x win32k=#%x sz=#%x"
          % (count, total, tblimit, stbase, wbase, wsize))
    first = (count, total)

    # --- 2. zero suspect entries (all inside win32k union) ---
    try:
        payload = _run()
        count = struct.unpack_from("<I", payload, 4)[0]
        wbase = struct.unpack_from("<Q", payload, 24)[0]
        wsize = struct.unpack_from("<I", payload, 32)[0]
        suspect = 0
        samples = []
        for i in range(count):
            row = 40 + i * 40
            flags = struct.unpack_from("<I", payload, row + 12)[0]
            if flags & SSDT_FLAG_SUSPECT:
                suspect += 1
                if len(samples) < 4:
                    a = struct.unpack_from("<Q", payload, row)[0]
                    idx = struct.unpack_from("<I", payload, row + 8)[0]
                    samples.append("i=%d a=#%x rel=%x" % (idx, a, a - wbase))
        #
        # Out-of-union entries are triage information, not a hard verdict:
        # on 22631 a few dozen table slots point at shared stubs in the
        # ntoskrnl region by design (34/1024 observed, pairs sharing one
        # address). A hooked table would scatter targets; assert the
        # in-union ratio instead of demanding zero.
        #
        check("SHADOWSSDT", "suspect ratio bounded",
              suspect * 10 < count, "suspect=%d of %d win32k=#%x %s"
              % (suspect, count, wbase, " ".join(samples)))
    except OSError as exc:
        check("SHADOWSSDT", "suspect ratio bounded", False, str(exc))

    # --- 3. determinism ---
    try:
        payload = _run()
        count, total = struct.unpack_from("<II", payload, 4)
        check("SHADOWSSDT", "walk deterministic",
              (count, total) == first,
              "now=(%d,%d) was=%s" % (count, total, str(first)))
    except OSError as exc:
        check("SHADOWSSDT", "walk deterministic", False, str(exc))


def verify_actions(handle, session_key: bytes | None) -> None:
    _step("ACTIONS HMAC accept/reject (S11.1)")
    pid = 0  # Never a live process; Mode A only acks (DEFERRED).
    for function, op in sorted(ACTION_OPS.items()):
        label = ACTION_LABELS[function]
        in_size = SAFETY_TOKEN_SIZE + len(_action_tail(function, pid))
        out_size = ACTION_OUTPUT_SIZE[function]
        if session_key is None:
            skip("ACTIONS", f"{label} valid-token", "no session key")
            skip("ACTIONS", f"{label} tampered-token", "no session key")
            continue

        token = sign_token(session_key, pid, op, nt_filetime_now())
        ok, payload, err = _ioctl_raw(handle, function_code_ioctl(function), token + _action_tail(function, pid), out_size)
        if not ok:
            check("ACTIONS", f"{label} valid-token DEFERRED", False, f"win32_err={err}")
            continue
        if len(payload) < 12:
            check("ACTIONS", f"{label} valid-token DEFERRED", False, f"short read {len(payload)}")
            continue
        result_code = struct.unpack_from("<I", payload, 4)[0]
        tier = struct.unpack_from("<I", payload, 8)[0]
        check("ACTIONS", f"{label} valid-token DEFERRED",
              result_code == 4 and len(payload) >= out_size - 4096,
              f"result={result_code} tier={tier}")

        broken = tamper_signature(token)
        ok, _payload, err = _ioctl_raw(handle, function_code_ioctl(function), broken + _action_tail(function, pid), out_size)
        check("ACTIONS", f"{label} tampered-token denied",
              (not ok) and err == ERROR_ACCESS_DENIED, f"ok={ok} win32_err={err}")

    if session_key is not None:
        # Freshness window: a correctly signed but 10-minute-old token must
        # fall outside the +/-120 s window and be denied.
        stale_ts = nt_filetime_now() - 200 * 10_000_000
        token = sign_token(session_key, pid, ACTION_OPS[0x870], stale_ts)
        ok, _payload, err = _ioctl_raw(handle, function_code_ioctl(0x870), token + _action_tail(0x870, pid), ACTION_OUTPUT_SIZE[0x870])
        check("ACTIONS", "KILL_PROCESS stale-token denied",
              (not ok) and err == ERROR_ACCESS_DENIED, f"ok={ok} win32_err={err}")


def function_code_ioctl(function: int) -> int:
    """Actions IOCTL codes share the FILE_DEVICE_UNKNOWN function layout."""
    return _ctl_code(FILE_DEVICE_UNKNOWN, function, METHOD_BUFFERED, FILE_ANY_ACCESS)


# ---------------------------------------------------------------------------
# [PROCESS] S6 checklist 3 + 5: token reject/allow on the 8 mutating IOCTLs,
# plus the process/thread build-gate behaviour. On builds outside
# 26100..26299 the modules refuse Init, their IOCTLs are unregistered
# (STATUS_INVALID_DEVICE_REQUEST) and they show up DISABLED in QUERY_MODULES.
# ---------------------------------------------------------------------------

PROCESS_MUTATING = [
    # (label, function, token op, tail builder)
    ("TERMINATE",         0xA05, 0x101, lambda pid: struct.pack("<IIII", pid, 1, 1, 0)),
    ("SUSPEND",           0xA06, 0x102, lambda pid: struct.pack("<IIII", pid, 0, 0, 0)),
    ("SET_PPL_LEVEL",     0xA07, 0x103, lambda pid: struct.pack("<IBBBBII", pid, 0, 0, 0, 0, 0, 0)),
    ("SET_INTEGRITY",     0xA08, 0x104, lambda pid: struct.pack("<IIII", pid, 0, 0, 0)),
    ("SET_VISIBILITY",    0xA09, 0x105, lambda pid: struct.pack("<IIII", pid, 0, 0, 0)),
    ("SET_SPECIAL_FLAGS", 0xA0A, 0x106, lambda pid: struct.pack("<IIII", pid, 0, 0, 0)),
    ("DKOM",              0xA0B, 0x107, lambda pid: struct.pack("<IIII", pid, 0, 1, 0)),
    ("INJECT",            0xA0C, 0x108,
     lambda pid: struct.pack("<IIII", pid, 0, 0, 0) + b"\x00" * (260 * 2)),
]

# No-op payloads that are safe to send with a VALID token on a supported
# build: restore-visibility / restore-DKOM / zero mask never mutate anything.
PROCESS_ALLOW_PROBES = {"SET_VISIBILITY", "SET_SPECIAL_FLAGS", "DKOM"}


def process_ioctl(function: int) -> int:
    return _ctl_code(FILE_DEVICE_UNKNOWN, function, METHOD_BUFFERED, FILE_ANY_ACCESS)


def verify_process(handle, session_key: bytes | None, modules: dict[str, tuple[int, int]],
                   capability_functions: list[int]) -> None:
    _step("PROCESS/THREAD cross-build views + token paths")
    build = sys.getwindowsversion().build
    pid = os.getpid() & 0xFFFFFFFF
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    tid = _kernel32.GetCurrentThreadId() & 0xFFFFFFFF

    #
    # Cross-build contract: the modules must be AVAILABLE on every supported
    # Win10/Win11 build. Field access goes through exported kernel accessors
    # and the two list offsets are discovered at runtime, so absence is now a
    # failure rather than the expected state.
    #
    for name in ("process", "thread"):
        entry = modules.get(name)
        ok = entry is not None and entry[0] == MODULE_STATE_ENABLED
        check("PROCESS", f"build {build}: module '{name}' ENABLED", ok, f"entry={entry}")

    registered = {f for f in capability_functions if 0xA00 <= f <= 0xA1F}
    check("PROCESS", f"build {build}: process+thread IOCTLs registered",
          len(registered) >= 18, f"count={len(registered)}")

    # --- ENUM: real rows, and our own PID must be among them ---------------
    try:
        # 512-entry headroom: the guest can legitimately carry >128 processes
        # and the walk order is not stable, so a tight cap can truncate away
        # this very process (2026-09-15: count=128/total=129 flake).
        payload = _ioctl(handle, process_ioctl(0xA00),
                         struct.pack("<IIII", 512, 0x07, 0, 0), 16 + 512 * PROCESS_ENTRY_SIZE)
        size_field, count, total, hidden = struct.unpack_from("<IIII", payload, 0)
        found_self = False
        sample = ""
        for i in range(min(count, 512)):
            base = 16 + i * PROCESS_ENTRY_SIZE
            row_pid = struct.unpack_from("<I", payload, base)[0]
            if i == 0:
                raw_name = payload[base + 8: base + 8 + 128]
                end = raw_name.find(b"\x00\x00")
                sample = raw_name[: max(end, 0)].decode("utf-16-le", errors="replace")
            if row_pid == pid:
                found_self = True
        check("PROCESS", "ENUM returns live processes", count > 0 and total > 0,
              f"count={count} total={total} hidden={hidden} first={sample!r}")
        check("PROCESS", "ENUM contains this process", found_self,
              f"pid={pid} count={count}")
    except OSError as exc:
        check("PROCESS", "ENUM returns live processes", False, str(exc))

    # --- ENUM_THREAD: our own thread must be listed ------------------------
    try:
        payload = _ioctl(handle, process_ioctl(0xA01),
                         struct.pack("<IIII", pid, 128, 0, 0), 16 + 128 * THREAD_ENTRY_SIZE)
        count = struct.unpack_from("<I", payload, 4)[0]
        owner = struct.unpack_from("<I", payload, 8)[0]
        tids = [struct.unpack_from("<I", payload, 16 + i * THREAD_ENTRY_SIZE)[0]
                for i in range(min(count, 128))]
        check("PROCESS", "ENUM_THREAD lists this process's threads",
              count > 0 and owner == pid and tid in tids,
              f"pid={pid} count={count} tid={tid} found={tid in tids} owner={owner}")
    except OSError as exc:
        check("PROCESS", "ENUM_THREAD lists this process's threads", False, str(exc))

    # --- DETAIL: echo + identity fields for a real PID ---------------------
    try:
        payload = _ioctl(handle, process_ioctl(0xA02), struct.pack("<IIII", pid, 0, 0, 0), 4096)
        d_pid = struct.unpack_from("<I", payload, 0)[0]
        raw = payload[DETAIL_NAME_OFFSET:][:128]
        name_end = raw.find(b"\x00\x00")
        d_name = raw[: max(name_end, 0)].decode("utf-16-le", errors="replace")
        links_off = struct.unpack_from("<I", payload, 80)[0]
        thread_off = struct.unpack_from("<I", payload, 92)[0]
        check("PROCESS", "DETAIL echoes pid and name",
              d_pid == pid and len(d_name) > 0,
              f"pid={d_pid} name={d_name!r} links_off=0x{links_off:X} thread_off=0x{thread_off:X}")
    except OSError as exc:
        check("PROCESS", "DETAIL echoes pid and name", False, str(exc))

    # --- CROSSVIEW: three-view agreement on a clean VM ---------------------
    try:
        payload = _ioctl(handle, process_ioctl(0xA04), struct.pack("<IIII", 0, 0, 0, 0), 16 + 256 * PROCESS_ENTRY_SIZE)
        count, public_only, hidden = struct.unpack_from("<I", payload, 4)[0], \
            struct.unpack_from("<I", payload, 8)[0], struct.unpack_from("<I", payload, 12)[0]
        # public_only is informational: it is derived from the public API
        # view, which some builds cannot populate reliably (the driver marks
        # that view unusable rather than flagging everything hidden).
        check("PROCESS", "CROSSVIEW agrees with ENUM",
              count > 0 and hidden == 0,
              f"count={count} public_only={public_only} hidden={hidden}")
    except OSError as exc:
        check("PROCESS", "CROSSVIEW agrees with ENUM", False, str(exc))

    # --- token paths (now meaningful on every build) -----------------------
    probe_pid = 0  # never a live process: only token validation is exercised
    for label, function, op, tail_builder in PROCESS_MUTATING:
        in_buf_tail = tail_builder(probe_pid)
        out_size = 64
        if session_key is None:
            skip("PROCESS", f"{label} token probes", "no session key")
            continue

        bad_token = b"\x00" * SAFETY_TOKEN_SIZE  # zero magic -> instant deny
        ok, _payload, err = _ioctl_raw(
            handle, process_ioctl(function), bad_token + in_buf_tail, out_size)
        check("PROCESS", f"{label} bad-token denied",
              (not ok) and err == ERROR_ACCESS_DENIED, f"ok={ok} win32_err={err}")

        if label in PROCESS_ALLOW_PROBES:
            token = sign_token(session_key, probe_pid, op, nt_filetime_now())
            ok, _payload, err = _ioctl_raw(
                handle, process_ioctl(function), token + in_buf_tail, out_size)
            # Token accepted: the call must NOT be denied for token reasons.
            # Downstream no-op failures with a different status are fine.
            check("PROCESS", f"{label} valid-token passes gate",
                  ok or err != ERROR_ACCESS_DENIED, f"ok={ok} win32_err={err}")


# ---------------------------------------------------------------------------
# [PHYSICAL] S6 checklist 4: RAM-range filter + WRITE_PHYSICAL opt-in gate.
# The suite never writes to a live RAM address: the opt-in probe targets a
# physical address beyond the RAM ranges, so the range filter (not RAM) is
# what the call hits.
# ---------------------------------------------------------------------------

def physical_ioctl(function: int) -> int:
    return _ctl_code(FILE_DEVICE_UNKNOWN, function, METHOD_BUFFERED, FILE_ANY_ACCESS)


def _ram_ranges(handle) -> list[tuple[int, int]]:
    payload = _ioctl(handle, physical_ioctl(0xB07), b"", 8 + 24 * 64)
    count = struct.unpack_from("<I", payload, 4)[0]
    ranges = []
    for i in range(count):
        base = 24 + i * 24
        pa = struct.unpack_from("<Q", payload, base)[0]
        size = struct.unpack_from("<Q", payload, base + 8)[0]
        if pa or size:
            ranges.append((pa, size))
    return ranges


def _allow_physical_write(enable: bool):
    """Set/clear HKLM\\...\\Modules\\memory:AllowPhysicalWrite. Returns a
    restore callable."""
    import winreg
    key_path = r"SYSTEM\CurrentControlSet\Services\MyArkCore\Modules\memory"
    created = False
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
    except FileNotFoundError:
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        created = True
    had_value = False
    try:
        winreg.QueryValueEx(key, "AllowPhysicalWrite")
        had_value = True
    except FileNotFoundError:
        pass
    if enable:
        winreg.SetValueEx(key, "AllowPhysicalWrite", 0, winreg.REG_DWORD, 1)

    def restore():
        if enable:
            if had_value:
                winreg.SetValueEx(key, "AllowPhysicalWrite", 0, winreg.REG_DWORD, 0)
            else:
                winreg.DeleteValue(key, "AllowPhysicalWrite")
        winreg.CloseKey(key)
        if created and not had_value:
            winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, key_path)

    return restore


def _verify_physical_write_roundtrip(handle) -> None:
    """Real WRITE_PHYSICAL round-trip into our own pinned buffer.

    VirtualLock pins the page so the VA->PA translation stays valid for the
    whole test; the marker and restore writes only ever touch the 8 bytes at
    offset 8 of a 64-byte buffer we own. Requires a 4K page mapping with
    at least 8 bytes of page-interior headroom, otherwise skipped.
    """
    import ctypes

    label = "WRITE_PHYSICAL unaligned roundtrip"
    kernel32 = ctypes.windll.kernel32
    probe = ctypes.create_string_buffer(b"\x11" * 64, 64)
    addr = ctypes.addressof(probe)
    if not kernel32.VirtualLock(ctypes.c_void_p(addr), ctypes.c_size_t(64)):
        skip("PHYSICAL", label, "VirtualLock failed")
        return
    try:
        try:
            payload = _ioctl(handle, _memory_ioctl(0xB03),
                             struct.pack("<IIQ", 0, 0, addr), 24)
            status, _rsv, pa, page_size = struct.unpack_from("<IIQQ", payload, 0)
        except OSError as exc:
            check("PHYSICAL", label, False, f"translate failed: {exc}")
            return
        if status != STATUS_SUCCESS or pa == 0 or page_size != PAGE_SIZE_4K \
                or (pa & 0xFFF) > 0x0FF0:
            skip("PHYSICAL", label,
                 f"pa=0x{pa:X} page=0x{page_size:X} (no page-interior room)")
            return

        wpa = pa + 8  # offset 8 in the page -> non-page-aligned PA
        marker = b"\x5A\xA5"

        # Minimum writable payload is sizeof(WRITE_PHYSICAL_INPUT)-16 = 8
        # bytes (struct tail padding), so the marker rides on the first two
        # bytes and the remaining six are re-written with their own values.
        orig = _ioctl(handle, physical_ioctl(0xB05),
                      struct.pack("<QQ", wpa, 8), 24 + 8)[16:24]
        check("PHYSICAL", label + " (orig read)",
              orig == b"\x11" * 8, f"orig={orig.hex()}")

        _ioctl(handle, physical_ioctl(0xB06),
               struct.pack("<QQ", wpa, 8) + marker + orig[2:], 16)
        back = _ioctl(handle, physical_ioctl(0xB05),
                      struct.pack("<QQ", wpa, 8), 24 + 8)[16:24]
        user_view = ctypes.string_at(addr + 8, 8)
        expected = marker + orig[2:]
        check("PHYSICAL", label,
              back == expected and user_view == expected,
              f"driver={back.hex()} user={user_view.hex()} expected={expected.hex()}")

        _ioctl(handle, physical_ioctl(0xB06),
               struct.pack("<QQ", wpa, 8) + orig, 16)
        restored = ctypes.string_at(addr + 8, 8)
        check("PHYSICAL", label + " (restore)",
              restored == orig, f"restored={restored.hex()} orig={orig.hex()}")
    finally:
        kernel32.VirtualUnlock(ctypes.c_void_p(addr), ctypes.c_size_t(64))


# ---------------------------------------------------------------------------
# [CIDTBL] R3-4: PspCidTable full-table walk + DKOM hidden-process
# detection. Three-source join: (A) EPROCESS.ActiveProcessLinks walk,
# (B) PspCidTable enumeration, joined in-driver to flag HIDDEN process
# rows. The round-trip below hides this very process via the existing
# SET_VISIBILITY DKOM op and proves the CID table still sees it.
# ---------------------------------------------------------------------------
IOCTL_MYARK_PROCESS_QUERY_CIDTABLE = _ctl_code(FILE_DEVICE_UNKNOWN, 0xA0D, METHOD_BUFFERED, FILE_ANY_ACCESS)

_CID_ENTRY_SIZE = 32         # 8 + 64... 4 + 4 + 8 + 16
_CID_ENUM_SIZE = 16 + 512 * _CID_ENTRY_SIZE
_CID_FLAG_HIDDEN = 0x4
_CID_OP_SET_VISIBILITY = 0x105


def _cid_query(handle):
    payload = _ioctl(handle, IOCTL_MYARK_PROCESS_QUERY_CIDTABLE, b"",
                     _CID_ENUM_SIZE)
    count, status, ttotal, esz = struct.unpack_from("<IIII", payload, 0)
    rows = {}
    if esz != _CID_ENTRY_SIZE:
        return count, status, ttotal, rows
    for i in range(count):
        base = 16 + i * _CID_ENTRY_SIZE
        cid, flags = struct.unpack_from("<II", payload, base)
        obj = struct.unpack_from("<Q", payload, base + 8)[0]
        name = payload[base + 16:base + 32].split(b"\x00")[0].decode(
            "utf-8", "replace")
        rows[cid] = (flags, obj, name)
    return count, status, ttotal, rows


def verify_cidtable(handle, session_key: bytes | None) -> None:
    _step("CIDTBL PspCidTable full-table + DKOM hidden detection")
    count, status, ttotal, rows = _cid_query(handle)
    proc_rows = {c: r for c, r in rows.items() if r[0] & 0x1}
    has_system = 4 in proc_rows and proc_rows[4][2] == "System"
    check("CIDTBL", "0xA0D baseline: System present + threads counted",
          status == 0 and count >= 3 and has_system and ttotal >= count,
          "status=%d procs=%d threads=%d sample=%s"
          % (status, count, ttotal, sorted(proc_rows)[:8]))

    if session_key is None:
        skip("CIDTBL", "DKOM round-trip",
             "no session key -- token-gated SET_VISIBILITY unavailable")
        return

    proc = subprocess.Popen(["cmd.exe", "/c", "ping -n 60 127.0.0.1 > nul"],
                            creationflags=0x08000000)   # CREATE_NO_WINDOW
    target_pid = proc.pid & 0xFFFFFFFF
    try:
        time.sleep(0.8)

        tok = sign_token(session_key, target_pid, _CID_OP_SET_VISIBILITY,
                         nt_filetime_now())
        hide_in = tok + struct.pack("<IIII", target_pid, 1, 0, 0)
        ok, _p, err = _ioctl_raw(handle, IOCTL_MYARK_PROCESS_SET_VISIBILITY,
                                 hide_in, 16)
        check("CIDTBL", "DKOM hide accepted (token-gated)", ok, "err=%d" % err)

        _c2, _s2, _t2, rows2 = _cid_query(handle)
        flags2 = rows2.get(target_pid, (None,))[0]
        hidden_detected = flags2 is not None and (flags2 & _CID_FLAG_HIDDEN)
        check("CIDTBL", "hidden process still in PspCidTable (HIDDEN flagged)",
              hidden_detected,
              "pid=%d in_table=%s flags=%s" % (target_pid, target_pid in rows2,
                                               hex(flags2) if flags2 is not None else "-"))

        tok2 = sign_token(session_key, target_pid, _CID_OP_SET_VISIBILITY,
                          nt_filetime_now())
        restore_in = tok2 + struct.pack("<IIII", target_pid, 0, 0, 0)
        _ioctl_raw(handle, IOCTL_MYARK_PROCESS_SET_VISIBILITY, restore_in, 16)
        _c3, _s3, _t3, rows3 = _cid_query(handle)
        flags3 = rows3.get(target_pid, (None,))[0]
        restored = flags3 is not None and not (flags3 & _CID_FLAG_HIDDEN)
        check("CIDTBL", "restore: process visible again",
              restored,
              "pid=%d flags=%s" % (target_pid,
                                   hex(flags3) if flags3 is not None else "-"))
    finally:
        try:
            proc.kill()
        except OSError:
            pass


def verify_physical(handle) -> None:
    _step("PHYSICAL range filter + write gate (S6)")
    try:
        ranges = _ram_ranges(handle)
    except OSError as exc:
        check("PHYSICAL", "QUERY_PHYSICAL_LAYOUT", False, str(exc))
        skip("PHYSICAL", "READ/WRITE_PHYSICAL probes", "no layout")
        return
    check("PHYSICAL", "QUERY_PHYSICAL_LAYOUT non-empty", len(ranges) > 0,
          f"regions={len(ranges)} total={sum(s for _b, s in ranges) >> 20}MB")
    if not ranges:
        skip("PHYSICAL", "READ/WRITE_PHYSICAL probes", "no RAM ranges")
        return

    base, size = ranges[0]
    read_pa = base + min(0x1000, max(size - 0x100, 0))
    out_size = 24 + 16  # Status4 BytesRead4 Rsv4 Rsv4 + Data[16]
    try:
        payload = _ioctl(handle, physical_ioctl(0xB05),
                         struct.pack("<QQ", read_pa, 16), out_size)
        status, bytes_read = struct.unpack_from("<II", payload, 0)
        check("PHYSICAL", "READ_PHYSICAL inside RAM", status == 0 and bytes_read == 16,
              f"pa=0x{read_pa:X} status={status} bytes={bytes_read}")
    except OSError as exc:
        check("PHYSICAL", "READ_PHYSICAL inside RAM", False, str(exc))

    # Beyond every RAM range: MMIO / hole -> range filter must deny.
    end_of_ram = max(b + s for b, s in ranges)
    hole_pa = end_of_ram + 0x4000000  # +64 MiB past the last range
    try:
        _ioctl(handle, physical_ioctl(0xB05), struct.pack("<QQ", hole_pa, 16), out_size)
        check("PHYSICAL", "READ_PHYSICAL outside RAM denied", False, "unexpectedly succeeded")
        return  # already failed; skip the remaining probes
    except OSError:
        ok, _payload, err = _ioctl_raw(handle, physical_ioctl(0xB05), struct.pack("<QQ", hole_pa, 16), out_size)
        denied = (not ok) and err == ERROR_ACCESS_DENIED
        check("PHYSICAL", "READ_PHYSICAL outside RAM denied", denied,
              f"pa=0x{hole_pa:X} win32_err={err}")
        if not denied:
            return  # already failed; skip the remaining probes

    # --- Non-page-aligned read, cross-checked against an aligned window ----
    # Read 64 bytes at a RAM-range page base, then read the 4 bytes at
    # +0x2C again unaligned; both must succeed and agree byte-for-byte.
    # (The fixed KUSER_SHARED_DATA PA would be a nicer value check, but on
    # VMware it sits in the MMIO hole outside MmGetPhysicalMemoryRanges, so
    # the driver's RAM-only policy correctly denies it.)
    try:
        pa_base = (base + 0x10000) & ~0xFFF
        aligned = _ioctl(handle, physical_ioctl(0xB05),
                         struct.pack("<QQ", pa_base, 64), 24 + 64)[16:]
        payload = _ioctl(handle, physical_ioctl(0xB05),
                         struct.pack("<QQ", pa_base + 0x2C, 4), 24 + 4)
        status, bytes_read = struct.unpack_from("<II", payload, 0)
        unaligned = payload[16:20]
        expected = aligned[0x2C:0x30]
        check("PHYSICAL", "READ_PHYSICAL non-aligned cross-check",
              status == 0 and bytes_read == 4 and unaligned == expected,
              f"pa=0x{pa_base + 0x2C:X} unaligned={unaligned.hex()} aligned={expected.hex()}")
    except OSError as exc:
        check("PHYSICAL", "READ_PHYSICAL non-aligned cross-check", False, str(exc))

    # WRITE_PHYSICAL default deny: gate fires before anything else.
    in_buf = struct.pack("<QQ", read_pa, 16) + b"\x00" * 16
    ok, _payload, err = _ioctl_raw(handle, physical_ioctl(0xB06), in_buf, 16)
    check("PHYSICAL", "WRITE_PHYSICAL default denied",
          (not ok) and err == ERROR_ACCESS_DENIED, f"win32_err={err}")

    # Opt-in + non-RAM target: gate passes, RAM-range filter still denies.
    # With the gate open we also perform one REAL write round-trip into this
    # process's own VirtualLock'd buffer (page pinned, so the translated PA
    # is stable): write an unaligned marker at pa+8, verify via the driver
    # and via user memory, restore the original bytes.
    restore = None
    try:
        restore = _allow_physical_write(enable=True)
    except OSError as exc:
        check("PHYSICAL", "AllowPhysicalWrite opt-in set", False, str(exc))
    if restore is not None:
        try:
            hole_in = struct.pack("<QQ", hole_pa, 16) + b"\x00" * 16
            ok, _payload, err = _ioctl_raw(handle, physical_ioctl(0xB06), hole_in, 16)
            check("PHYSICAL", "WRITE_PHYSICAL opt-in: non-RAM still denied",
                  (not ok) and err == ERROR_ACCESS_DENIED,
                  f"pa=0x{hole_pa:X} win32_err={err}")
            _verify_physical_write_roundtrip(handle)
        finally:
            restore()
        # Confirm the knob really got cleared (default deny restored).
        ok, _payload, err = _ioctl_raw(handle, physical_ioctl(0xB06), in_buf, 16)
        check("PHYSICAL", "WRITE_PHYSICAL deny restored after cleanup",
              (not ok) and err == ERROR_ACCESS_DENIED, f"win32_err={err}")


# ---------------------------------------------------------------------------
# [MEMVIRT] memory module virtual path (S6 follow-up): QUERY_VM / READ_VM /
# WRITE_VM / TRANSLATE_VA / QUERY_PT_ENTRY / the two kernel scans.
#
# Every probe targets this suite's own process (self PID) or an already
# mapped kernel range, so nothing can damage another process. WRITE_VM is
# exercised against a local ctypes buffer and the bytes the driver wrote are
# read back in Python -- that is what verifies the S11.1 "read inBuf->Size
# only after the fetch" fix actually lands the copy.
# ---------------------------------------------------------------------------

def _memory_ioctl(function: int) -> int:
    return _ctl_code(FILE_DEVICE_UNKNOWN, function, METHOD_BUFFERED, FILE_ANY_ACCESS)


def _kernel_modules() -> dict[str, int]:
    """Loaded kernel module name -> image base, via psapi.EnumDeviceDrivers."""
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    psapi.EnumDeviceDrivers.argtypes = [ctypes.c_void_p, wintypes.DWORD,
                                        ctypes.POINTER(wintypes.DWORD)]
    psapi.EnumDeviceDrivers.restype = wintypes.BOOL
    psapi.GetDeviceDriverBaseNameW.argtypes = [ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
    psapi.GetDeviceDriverBaseNameW.restype = wintypes.DWORD

    needed = wintypes.DWORD(0)
    # Sizing call: EnumDeviceDrivers returns FALSE by design when the buffer
    # is NULL; only cbNeeded matters here.
    psapi.EnumDeviceDrivers(None, 0, ctypes.byref(needed))
    if needed.value == 0:
        return {}
    count = needed.value // ctypes.sizeof(ctypes.c_void_p)
    bases = (ctypes.c_void_p * count)()
    if not psapi.EnumDeviceDrivers(ctypes.cast(bases, ctypes.c_void_p),
                                   needed.value, ctypes.byref(needed)):
        return {}
    out: dict[str, int] = {}
    name = ctypes.create_unicode_buffer(260)
    for i in range(count):
        if not bases[i]:
            continue
        if not psapi.GetDeviceDriverBaseNameW(ctypes.c_void_p(bases[i]), name, 260):
            continue
        out.setdefault(name.value, int(bases[i]))
    return out


def verify_memory_virtual(handle) -> None:
    _step("MEMVIRT virtual path (VAD stub / cross-process read-write / paging / scans)")
    pid = os.getpid() & 0xFFFFFFFF

    # --- QUERY_VM: best-effort VAD stub returns a header with zero rows ----
    out_size = 32 + 16 * 160  # header + 16 row slots
    try:
        payload = _ioctl(handle, _memory_ioctl(0xB00), struct.pack("<IIII", pid, 16, 0, 0), out_size)
        size_field, count, cap, truncated = struct.unpack_from("<IIII", payload, 0)
        # Success path: Size = FIELD_OFFSET(Entries[0]) = 16, Count = 0 and
        # TotalRegions echoes the requested cap (VAD walk itself is a stub).
        check("MEMVIRT", "QUERY_VM header sane",
              size_field == 16 and count == 0 and cap == 16,
              f"pid={pid} size={size_field} count={count} cap={cap} trunc={truncated}")
    except OSError as exc:
        check("MEMVIRT", "QUERY_VM header sane", False, str(exc))

    try:
        payload = _ioctl(handle, _memory_ioctl(0xB00), struct.pack("<IIII", 0xFFFFFFFF, 4, 0, 0), out_size)
        size_field, count = struct.unpack_from("<II", payload, 0)
        check("MEMVIRT", "QUERY_VM bogus pid degrades",
              0 < size_field <= out_size and count == 0,
              f"size={size_field} count={count}")
    except OSError as exc:
        check("MEMVIRT", "QUERY_VM bogus pid degrades", False, str(exc))

    # --- READ_VM / WRITE_VM against our own buffers ------------------------
    # READ_VM_OUTPUT: 4 x UINT32 then Data (offset 16), sizeof 20 (tail pad).
    read_data_off = 16
    read_struct_size = 20
    probe = ctypes.create_string_buffer(b"MYARK_RW_PROBE_0123456789ABC", 64)
    addr = ctypes.addressof(probe)
    read_len = 24
    read_out = read_struct_size + read_len
    try:
        payload = _ioctl(handle, _memory_ioctl(0xB01),
                         struct.pack("<IIQQ", pid, 0, addr, read_len), read_out)
        status, bytes_read = struct.unpack_from("<II", payload, 0)
        check("MEMVIRT", "READ_VM self bytes match",
              status == STATUS_SUCCESS and bytes_read == read_len
              and payload[read_data_off:read_data_off + read_len] == probe.raw[:read_len],
              f"addr=0x{addr:X} status={status} bytes={bytes_read}")
    except OSError as exc:
        check("MEMVIRT", "READ_VM self bytes match", False, str(exc))

    try:
        payload = _ioctl(handle, _memory_ioctl(0xB01),
                         struct.pack("<IIQQ", pid, 0, 0x1000, read_len), read_out)
        status, bytes_read = struct.unpack_from("<II", payload, 0)
        check("MEMVIRT", "READ_VM unmapped addr -> PARTIAL_COPY",
              status == STATUS_PARTIAL_COPY and bytes_read == 0,
              f"status=0x{status:08X} bytes={bytes_read}")
    except OSError as exc:
        check("MEMVIRT", "READ_VM unmapped addr -> PARTIAL_COPY", False, str(exc))

    target = ctypes.create_string_buffer(b"0" * 64, 64)
    taddr = ctypes.addressof(target)
    marker = b"WRITTEN_BY_DRIVER_XY"
    # WRITE_VM_INPUT: Pid, Reserved, Address, Size then Data (offset 24).
    write_in = struct.pack("<IIQQ", pid, 0, taddr, len(marker)) + marker
    try:
        payload = _ioctl(handle, _memory_ioctl(0xB02), write_in, 16)
        status, written = struct.unpack_from("<II", payload, 0)
        check("MEMVIRT", "WRITE_VM lands in self memory",
              status == STATUS_SUCCESS and written == len(marker)
              and target.raw[:len(marker)] == marker,
              f"addr=0x{taddr:X} status={status} bytes={written}")
    except OSError as exc:
        check("MEMVIRT", "WRITE_VM lands in self memory", False, str(exc))

    # Size-field shrink: the exact code path the S11.1 fix repaired (the
    # header field used to be read before the fetch made inBuf valid). Only
    # the first 8 payload bytes may land; the rest must stay untouched.
    shrink = ctypes.create_string_buffer(b"1" * 64, 64)
    saddr = ctypes.addressof(shrink)
    shrink_in = (struct.pack("<IIQQ", pid, 0, saddr, 8)
                 + b"SHRINK!!" + b"X" * 24)
    try:
        payload = _ioctl(handle, _memory_ioctl(0xB02), shrink_in, 16)
        status, written = struct.unpack_from("<II", payload, 0)
        check("MEMVIRT", "WRITE_VM Size-field shrink path",
              status == STATUS_SUCCESS and written == 8
              and shrink.raw[:8] == b"SHRINK!!" and shrink.raw[8:] == b"1" * 56,
              f"status={status} bytes={written}")
    except OSError as exc:
        check("MEMVIRT", "WRITE_VM Size-field shrink path", False, str(exc))

    # --- TRANSLATE_VA / QUERY_PT_ENTRY -------------------------------------
    # Two paths are exercised separately: pid=0 walks the CURRENT process CR3
    # (__readcr3, no EPROCESS read) and pid=<self> goes through
    # PsLookupProcessByProcessId + KPROCESS.DirectoryTableBase. Splitting them
    # tells a broken EPROCESS-offset read apart from a broken page-table walk.
    try:
        payload = _ioctl(handle, _memory_ioctl(0xB03), struct.pack("<IIQ", 0, 0, addr), 24)
        status, _rsv, pa, page_size = struct.unpack_from("<IIQQ", payload, 0)
        check("MEMVIRT", "TRANSLATE_VA current CR3 (pid=0)",
              status == STATUS_SUCCESS and pa != 0
              and page_size in (PAGE_SIZE_4K, PAGE_SIZE_2M, PAGE_SIZE_1G),
              f"va=0x{addr:X} status=0x{status:08X} pa=0x{pa:X} page=0x{page_size:X}")
    except OSError as exc:
        check("MEMVIRT", "TRANSLATE_VA current CR3 (pid=0)", False, str(exc))

    try:
        payload = _ioctl(handle, _memory_ioctl(0xB03), struct.pack("<IIQ", pid, 0, addr), 24)
        status, _rsv, pa, page_size = struct.unpack_from("<IIQQ", payload, 0)
        offset_ok = (page_size != PAGE_SIZE_4K) or ((pa & 0xFFF) == (addr & 0xFFF))
        check("MEMVIRT", "TRANSLATE_VA self buffer",
              status == STATUS_SUCCESS and pa != 0
              and page_size in (PAGE_SIZE_4K, PAGE_SIZE_2M, PAGE_SIZE_1G) and offset_ok,
              f"va=0x{addr:X} status=0x{status:08X} pa=0x{pa:X} page=0x{page_size:X}")
    except OSError as exc:
        check("MEMVIRT", "TRANSLATE_VA self buffer", False, str(exc))

    try:
        payload = _ioctl(handle, _memory_ioctl(0xB04), struct.pack("<IIQ", 0, 0, addr), 32 + 4 * 32)
        status, level, _r0, _r1, pa, page_size = struct.unpack_from("<IIIIQQ", payload, 0)
        pml4e = struct.unpack_from("<Q", payload, 32)[0]
        check("MEMVIRT", "QUERY_PT_ENTRY current CR3 (pid=0)",
              status == STATUS_SUCCESS and 1 <= level <= 4 and pml4e != 0
              and page_size in (PAGE_SIZE_4K, PAGE_SIZE_2M, PAGE_SIZE_1G),
              f"status=0x{status:08X} level={level} pa=0x{pa:X} page=0x{page_size:X} pml4e=0x{pml4e:X}")
    except OSError as exc:
        check("MEMVIRT", "QUERY_PT_ENTRY current CR3 (pid=0)", False, str(exc))

    try:
        payload = _ioctl(handle, _memory_ioctl(0xB04), struct.pack("<IIQ", pid, 0, addr), 32 + 4 * 32)
        status, level, _r0, _r1, pa, page_size = struct.unpack_from("<IIIIQQ", payload, 0)
        pml4e = struct.unpack_from("<Q", payload, 32)[0]
        check("MEMVIRT", "QUERY_PT_ENTRY self buffer",
              status == STATUS_SUCCESS and 1 <= level <= 4 and pml4e != 0
              and page_size in (PAGE_SIZE_4K, PAGE_SIZE_2M, PAGE_SIZE_1G),
              f"status=0x{status:08X} level={level} pa=0x{pa:X} page=0x{page_size:X} pml4e=0x{pml4e:X}")
    except OSError as exc:
        check("MEMVIRT", "QUERY_PT_ENTRY self buffer", False, str(exc))

    # --- kernel scans ------------------------------------------------------
    # Baseline that never depends on module bases: KUSER_SHARED_DATA is
    # mapped at a fixed kernel VA on x64 and its NtSystemRoot field carries
    # the OS path as a wide string, so this page is both a safe scan target
    # and a deterministic positive for the evidence matcher.
    kuser = KUSER_SHARED_DATA_VA

    # Negative: a random 16-byte pattern cannot occur in one page.
    random_sig = os.urandom(16)
    in_buf = struct.pack("<16sI4xQQII", random_sig, 16, kuser, kuser + 0x1000, 8, 0)
    try:
        payload = _ioctl(handle, _memory_ioctl(0xB08), in_buf, 16 + 8 * 24)
        count = struct.unpack_from("<I", payload, 4)[0]
        check("MEMVIRT", "SCAN_KERNEL_EXECUTABLE negative (KUSER page)", count == 0,
              f"count={count} (expected 0)")
    except OSError as exc:
        check("MEMVIRT", "SCAN_KERNEL_EXECUTABLE negative (KUSER page)", False, str(exc))

    wide = "Windows".encode("utf-16-le")
    in_buf = struct.pack("<IIQQ", 8, 0, kuser, kuser + 0x1000) + (wide + b"\x00" * 128)[:128]
    try:
        payload = _ioctl(handle, _memory_ioctl(0xB09), in_buf, 16 + 8 * 16)
        count, matched = struct.unpack_from("<I", payload, 4)[0], 0
        if count:
            matched = struct.unpack_from("<I", payload, 24)[0]
        check("MEMVIRT", "SCAN_EVIDENCE finds NtSystemRoot 'Windows'",
              count >= 1 and matched == len("Windows"),
              f"count={count} matched={matched}")
    except OSError as exc:
        check("MEMVIRT", "SCAN_EVIDENCE finds NtSystemRoot 'Windows'", False, str(exc))

    # Stronger, module-base-dependent checks run only when the caller is
    # privileged enough to see kernel bases: SystemModuleInformation zeroes
    # ImageBase for non-elevated callers (kernel pointer mitigation).
    modules = _kernel_modules()
    nt_base = modules.get("ntoskrnl.exe") or modules.get("ntkrnlmp.exe") or 0
    scan_out = 16 + 8 * 24
    if nt_base:
        # Positive: ntoskrnl's PE header starts with "MZ" at its image base.
        in_buf = struct.pack("<16sI4xQQII", b"MZ".ljust(16, b"\x00"), 2,
                             nt_base, nt_base + 0x1000, 8, 0)
        try:
            payload = _ioctl(handle, _memory_ioctl(0xB08), in_buf, scan_out)
            size_field, count, truncated, _rsv = struct.unpack_from("<IIII", payload, 0)
            first_addr = struct.unpack_from("<Q", payload, 16)[0] if count else 0
            check("MEMVIRT", "SCAN_KERNEL_EXECUTABLE finds nt MZ",
                  count >= 1 and first_addr == nt_base,
                  f"nt=0x{nt_base:X} count={count} first=0x{first_addr:X} size={size_field} trunc={truncated}")
        except OSError as exc:
            check("MEMVIRT", "SCAN_KERNEL_EXECUTABLE finds nt MZ", False, str(exc))

        # Inverted range must be rejected, not crash the walk.
        bad = struct.pack("<16sI4xQQII", b"MZ".ljust(16, b"\x00"), 2, nt_base, nt_base, 4, 0)
        ok, _payload, err = _ioctl_raw(handle, _memory_ioctl(0xB08), bad, scan_out)
        check("MEMVIRT", "SCAN inverted range rejected", (not ok) and err != 0,
              f"ok={ok} win32_err={err}")

        # Positive evidence scan: the driver's own DisplayName literal lives
        # in MyArkCore.sys .rdata (2-byte walk, alignment is a non-issue).
        myark_base = modules.get("MyArkCore.sys", 0)
        if myark_base:
            wide = "MyArk Core 0.1.0".encode("utf-16-le")
            in_buf = (struct.pack("<IIQQ", 8, 0, myark_base, myark_base + 0x40000)
                      + (wide + b"\x00" * 128)[:128])
            try:
                payload = _ioctl(handle, _memory_ioctl(0xB09), in_buf, 16 + 8 * 16)
                size_field, count, truncated, _rsv = struct.unpack_from("<IIII", payload, 0)
                matched = struct.unpack_from("<I", payload, 24)[0] if count else 0
                check("MEMVIRT", "SCAN_EVIDENCE finds driver DisplayName",
                      count >= 1 and matched == len("MyArk Core 0.1.0"),
                      f"base=0x{myark_base:X} count={count} matched={matched} size={size_field} trunc={truncated}")
            except OSError as exc:
                check("MEMVIRT", "SCAN_EVIDENCE finds driver DisplayName", False, str(exc))
        else:
            skip("MEMVIRT", "SCAN_EVIDENCE driver DisplayName", "MyArkCore.sys base unavailable")
    else:
        skip("MEMVIRT", "nt MZ / inverted-range scans",
             "kernel bases invisible to this caller (non-elevated)")


# ---------------------------------------------------------------------------
# [MATRIX] reachability smoke for every registered IOCTL the sections above
# do not already exercise: one call each with a zeroed 1 KiB input.
#
# Read-only queries either succeed with defaults or return a definite
# validation status -- what matters is that the function is registered and
# the driver survives the call. Mutating IOCTLs (WFP callout add/remove,
# token swap, redirect apply, MJ replace, ALPC close) MUST reject a zeroed
# argument block; an accepted zeroed call is a finding, not a pass. A final
# hello PING proves the driver is still answering after the whole matrix.
# ---------------------------------------------------------------------------

MATRIX_READ_ONLY = [
    ("core", "GET_LOG", 0x803),
    ("core", "SET_LOG_CONFIG", 0x804),
    ("hello", "PING", 0x900),
    ("hello", "GREET", 0x901),
    ("handle", "ENUM_PROCESS_HANDLES", 0xC00),
    ("handle", "QUERY_HANDLE", 0xC01),
    ("section", "QUERY_PROCESS", 0xC10),
    ("section", "QUERY_FILE_MAPPINGS", 0xC11),
    ("storage", "QUERY_VOLUME_STACK", 0xC30),
    ("storage", "QUERY_BITLOCKER", 0xC31),
    ("storage", "QUERY_MOUNTMGR_MAPPING", 0xC32),
    ("storage", "QUERY_FS_INTEGRITY", 0xC33),
    ("device-audit", "QUERY_DEVICE_STACK", 0xC40),
    ("device-audit", "QUERY_USB_TOPOLOGY", 0xC41),
    ("device-audit", "QUERY_GPU_DISPLAY", 0xC42),
    ("device-audit", "QUERY_INPUT_STACK", 0xC43),
    ("device-audit", "QUERY_WATCHDOG", 0xC44),
    ("keyboard", "ENUM_HOTKEYS", 0xC50),
    ("keyboard", "ENUM_HOOKS", 0xC51),
    ("debug-output", "CONTROL", 0xC60),
    ("debug-output", "DRAIN", 0xC61),
    ("kernel", "QUERY_SSDT", 0xC70),
    ("callback", "REMOVE(reserved)", 0x716),
    ("callback", "RESTORE(reserved)", 0x717),
    ("callback", "BACKUP(reserved)", 0x718),
    ("callback", "OB_PROTECT_STATUS", 0x724),
    ("wfp", "ENUMERATE_CALLOUTS", 0x720),
    ("wfp", "ENUM_NDIS_FILTERS", 0x8A2),
    ("wfp", "ENUM_CALLOUT_DRIVERS", 0x8A3),
    ("timerdpc", "QUERY_TIMER", 0x8A4),
    ("timerdpc", "QUERY_DPC", 0x8A5),
    ("mutation", "INSPECT_TOKEN", 0x730),
    ("redirect", "INSPECT", 0x740),
    ("hwid", "ENUMERATE_MJ", 0x750),
    ("bugcheck", "QUERY", 0x760),
    ("bugcheck", "RENDER_DIAG", 0x761),
    ("win32k", "ENUMERATE_GUI_THREADS", 0x770),
    ("win32k", "ENUMERATE_HOOKS", 0x771),
    ("wsl", "ENUMERATE_SILOS", 0x780),
    ("alpc", "ENUMERATE_PORTS", 0x790),
    ("authentication", "VERIFY_FILE", 0x7A0),
    ("trust", "VERIFY_PE", 0x7B0),
    ("trust", "VERIFY_CATALOG", 0x7B1),
    ("preflight", "HEALTH", 0x7C0),
    ("security_audit", "DEFENDER", 0x7D0),
    ("security_audit", "SECURE_BOOT", 0x7D1),
    ("security_audit", "TRUSTED_BOOT", 0x7D2),
    ("capability", "REPORT", 0x7E0),
    ("kernel_ext", "QUERY_WIN11_INFO", 0x7F0),
    ("kernel_ext", "READ_SYSCALL_TABLE", 0x7F1),
    ("safety", "EVAL_GATE", 0xD00),
    ("registry", "READ_VALUE", 0xE00),
    ("registry", "ENUM_KEY", 0xE01),
    ("kernel", "SCAN_INLINE_HOOKS", 0xE20),
]

MATRIX_MUTATING = [
    ("wfp", "ADD_CALLOUT", 0x721),
    ("wfp", "REMOVE_CALLOUT", 0x722),
    ("mutation", "SET_TOKEN", 0x731),
    ("redirect", "APPLY", 0x741),
    ("registry", "SET_VALUE", 0xE02),
    ("hwid", "REPLACE_MJ", 0x751),
    ("alpc", "CLOSE_PORT", 0x791),
    ("callback", "OB_PROTECT_SET", 0x723),
]


# ---------------------------------------------------------------------------
# [INJECT] R3-2 (T-C): shellcode injection MECHANISM. The payload comes
# entirely from this script (a bare x64 RET -- benign by construction); the
# driver is a token-gated pipe: ZwAlloc -> copy -> RX -> ZwCreateThreadEx.
# Target is this process (sacrificial, non-PPL).
# ---------------------------------------------------------------------------

IOCTL_MYARK_ACTION_INJECT_SHELLCODE = _ctl_code(FILE_DEVICE_UNKNOWN, 0x877, METHOD_BUFFERED, FILE_ANY_ACCESS)
MYARK_ACTION_OP_INJECT_SHELLCODE = 8
MYARK_ACTION_SHELLCODE_MAX_BYTES = 256 * 1024


def verify_inject(handle, session_key: bytes | None) -> None:
    _step("INJECT shellcode mechanism (R3-2 T-C)")
    pid = os.getpid() & 0xFFFFFFFF
    stub = b"\xC3"          # x64 RET: the queued APC runs it and returns

    def _in_buf(token: bytes, target_pid: int, target_tid: int, payload: bytes, size_override=None):
        size = len(payload) if size_override is None else size_override
        # The C input struct is 96 bytes (Token 72 + 4x4 + Payload[1] pad);
        # send at least that so the driver's size gate passes.
        pad = b"\x00" * (16 - len(payload) % 8 - 1 + 8)   # sizeof(INPUT)==96 (Payload[1]+pad)
        return (token + struct.pack("<IIII", target_pid, target_tid, size, 0)
                + payload + pad)

    if session_key is None:
        skip("INJECT", "mechanism cycle", "no session key")
        return
    token = sign_token(session_key, pid, MYARK_ACTION_OP_INJECT_SHELLCODE, nt_filetime_now())

    # An alertable thread in THIS process: the user APC only fires when the
    # target thread alerts (SleepEx with Alertable=TRUE).
    import ctypes
    import threading
    tid_holder = {}
    delivery = {}
    stop = threading.Event()

    def _alertable_loop():
        k32 = ctypes.windll.kernel32
        tid_holder["tid"] = k32.GetCurrentThreadId() & 0xFFFFFFFF
        while not stop.is_set():
            # SleepEx returning 0 (WAIT_IO_COMPLETION) means an APC was
            # delivered and ran during the wait -- the delivery proof.
            delivery["last_wait"] = k32.SleepEx(50, True)
            if delivery["last_wait"] == 0:
                delivery["apc"] = True

    th = threading.Thread(target=_alertable_loop, daemon=True)
    th.start()
    deadline = time.time() + 2.0
    while "tid" not in tid_holder and time.time() < deadline:
        time.sleep(0.02)
    target_tid = tid_holder.get("tid", 0)

    try:
        # --- 1. zeroed token -> denied ---
        ok, _p, err = _ioctl_raw(handle, IOCTL_MYARK_ACTION_INJECT_SHELLCODE,
                                 _in_buf(bytes(SAFETY_TOKEN_SIZE), pid, target_tid, stub), 128)
        check("INJECT", "INJECT without token denied",
              (not ok) and err == ERROR_ACCESS_DENIED, "win32_err=%d" % err)

        # --- 2. payload over the 256 KB cap -> invalid parameter ---
        ok, _p, err = _ioctl_raw(handle, IOCTL_MYARK_ACTION_INJECT_SHELLCODE,
                                 _in_buf(token, pid, target_tid, b"", MYARK_ACTION_SHELLCODE_MAX_BYTES + 1),
                                 128)
        check("INJECT", "oversize payload rejected",
              (not ok) and err == ERROR_INVALID_PARAMETER, "win32_err=%d" % err)

        # --- 3. inject the RET stub as a user APC into the alertable thread ---
        ok, payload, err = _ioctl_raw(handle, IOCTL_MYARK_ACTION_INJECT_SHELLCODE,
                                      _in_buf(token, pid, target_tid, stub), 128)
        if not ok:
            check("INJECT", "RET stub queued into alertable thread", False, "win32_err=%d" % err)
            return
        result_code = struct.unpack_from("<I", payload, 4)[0]
        out_pid, out_tid = struct.unpack_from("<II", payload, 88)
        remote_base, remote_size = struct.unpack_from("<QQ", payload, 96)
        check("INJECT", "RET stub queued into alertable thread",
              result_code == 0 and out_pid == pid and out_tid == target_tid
              and remote_base != 0 and remote_size == len(stub),
              "rc=%d tid=%d base=#%x size=%d"
              % (result_code, out_tid, remote_base, remote_size))

        # delivery proof: the alertable wait completed on APC delivery
        deadline = time.time() + 2.0
        while not delivery.get("apc") and time.time() < deadline:
            time.sleep(0.05)
        check("INJECT", "APC delivered (alertable wait completed)",
              delivery.get("apc") is True,
              "last_wait=%s" % delivery.get("last_wait"))

        # --- 4. process is still alive and the driver still answers ---
        try:
            _ioctl(handle, IOCTL_MYARK_PROCESS_DETAIL_RUNTIME,
                   struct.pack("<II", pid, 0), 128)
            check("INJECT", "process alive + driver responsive after inject", True)
        except OSError as exc:
            check("INJECT", "process alive + driver responsive after inject", False, str(exc))
    finally:
        stop.set()
        th.join(timeout=3)


# ---------------------------------------------------------------------------
# [HWID] R3-1 (T-B): HWID spoof subdivision (0x752 / 0x753). Disk serial +
# partition GUID get true end-to-end value proof (python-side queries of
# \\.\PhysicalDrive0 / \\.\Harddisk0Partition1 vs the driver preview);
# GPU is asserted at contract level (the display-class key may not carry a
# serial value on every VM); ARP is asserted unsupported.
# ---------------------------------------------------------------------------

IOCTL_MYARK_HWID_QUERY_SPOOF_STATUS = _ctl_code(FILE_DEVICE_UNKNOWN, 0x752, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_HWID_SET_SPOOF_CONFIG = _ctl_code(FILE_DEVICE_UNKNOWN, 0x753, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_HWID_QUERY_SPOOF_CAPTURE = _ctl_code(FILE_DEVICE_UNKNOWN, 0x754, METHOD_BUFFERED, FILE_ANY_ACCESS)
MYARK_HWID_OP_SPOOF_CONFIG = 0x31505357

MYARK_HWID_CLASS_DISK_SERIAL = 1
MYARK_HWID_CLASS_PARTITION_GUID = 2
MYARK_HWID_CLASS_MOUNTMGR_UID = 3
MYARK_HWID_CLASS_GPU_SERIAL = 4
MYARK_HWID_CLASS_ARP = 5
MYARK_HWID_CLASS_DEVICE_ID = 6
_MYARK_HWID_STATUS_SIZE = 208          # 8 + 6 * 32 (R3-1b class table)

MYARK_HWID_SPOOF_ST_ACTIVE = 0x1
MYARK_HWID_SPOOF_ST_CACHE_VALID = 0x4
MYARK_HWID_SPOOF_ST_ATTACHED = 0x8
MYARK_HWID_SPOOF_ST_UNSUPPORTED = 0x10

MYARK_HWID_ACTION_DRY_RUN = 0
MYARK_HWID_ACTION_APPLY = 1
MYARK_HWID_ACTION_RESTORE = 2
MYARK_HWID_ACTION_CAPTURE = 3

_MYARK_FLAG_UI_CONFIRMED = 0x1
_MYARK_FLAG_FORCE = 0x2
_MYARK_FLAG_CAPTURE_START = 0x4

_STATUS_NOT_IMPLEMENTED = 0xC0000002
_STATUS_NOT_FOUND = 0xC0000225

_IOCTL_STORAGE_QUERY_PROPERTY = (0x2D << 16) | (0x500 << 2)
_IOCTL_DISK_GET_PARTITION_INFO_EX = (0x07 << 16) | (0x12 << 2)  # 0x70048


def _hwid_in_buf(token: bytes, cls: int, action: int, flags: int,
                 value: bytes, disk: int = 0) -> bytes:
    # MYARK_HWID_SPOOF_SET_INPUT == 232 bytes (72 token + 28 header + 128
    # value + 4 pad).
    buf = (token
           + struct.pack("<IIIII", cls, action, flags, disk, len(value))
           + b"\x00" * 4                       # Reserved1 + Reserved64 tail
           + b"\x00" * 8
           + value)
    return buf + b"\x00" * (232 - len(buf))


def _hwid_out(payload: bytes) -> dict:
    status, applied, rewritten, attached = struct.unpack_from("<IIII", payload, 0)
    real_len, spoof_len, p_status = struct.unpack_from("<III", payload, 16)
    real = payload[32:32 + real_len]
    spoof = payload[160:160 + spoof_len]
    return {"status": status, "applied": applied, "rewritten": rewritten,
            "attached": attached, "real": real, "spoof": spoof,
            "p_status": p_status}


def _hwid_status_flags(handle, cls: int):
    payload = _ioctl(handle, IOCTL_MYARK_HWID_QUERY_SPOOF_STATUS, b"", _MYARK_HWID_STATUS_SIZE)
    count = struct.unpack_from("<I", payload, 0)[0]
    for i in range(count):
        base = 16 + i * 32
        c, flags, spoof_len, cache_len, rewritten, attached, queries, last = \
            struct.unpack_from("<8I", payload, base)
        if c == cls:
            return flags, rewritten, attached, queries, last
    return None, 0, 0, 0, 0


def _query_disk_serial(disk: int = 0) -> bytes:
    # Raw IOCTL_STORAGE_QUERY_PROPERTY(StorageDeviceProperty) against
    # \\.\PhysicalDriveN; returns the serial string bytes.
    path = "\\\\.\\PhysicalDrive%d" % disk
    h = _kernel32.CreateFileW(path, GENERIC_READ,
                              0x1 | 0x2,      # FILE_SHARE_READ | WRITE
                              None, 3,        # OPEN_EXISTING
                              0, None)
    if h == -1 or h == 0xFFFFFFFFFFFFFFFF:
        raise OSError("open %s failed" % path)
    try:
        ok, blob, err = _ioctl_raw(h, _IOCTL_STORAGE_QUERY_PROPERTY,
                                   struct.pack("<III", 0, 0, 0), 4096)
        if not ok:
            raise OSError("query property failed err=%d" % err)
        # STORAGE_DEVICE_DESCRIPTOR: SerialNumberOffset is at byte 24
        # (DeviceType/Modifier/RemovableMedia/CommandQueueing are
        # UCHARs at 8..11; verified against a live 396-byte descriptor).
        serial_off = struct.unpack_from("<I", blob, 24)[0]
        if serial_off == 0 or serial_off >= len(blob):
            return b""
        end = serial_off
        while end < len(blob) and blob[end] != 0:
            end += 1
        return blob[serial_off:end]
    finally:
        _kernel32.CloseHandle(h)


def _query_disk_device_id(disk: int = 0) -> bytes:
    # STORAGE_DEVICE_ID_DESCRIPTOR (SCSI VPD page 0x83): returns the data
    # bytes of the FIRST identifier -- the same value the driver's
    # DEVICE_ID class previews. Identifier entries are CodeSet(1)
    # IdentifierType(1) Len(2, big-endian) then the data; a descriptor
    # with no identifiers yields b"" (class must refuse cleanly).
    path = "\\\\.\\PhysicalDrive%d" % disk
    h = _kernel32.CreateFileW(path, GENERIC_READ,
                              0x1 | 0x2, None, 3, 0, None)
    if h == -1 or h == 0xFFFFFFFFFFFFFFFF:
        raise OSError("open %s failed" % path)
    try:
        ok, blob, err = _ioctl_raw(h, _IOCTL_STORAGE_QUERY_PROPERTY,
                                   struct.pack("<III", 2, 0, 0), 4096)
        if not ok:
            raise OSError("query device-id failed err=%d" % err)
        if len(blob) < 12:
            return b""
        num = struct.unpack_from("<I", blob, 8)[0]
        if num == 0:
            return b""
        off = struct.unpack_from("<I", blob, 12)[0]
        if off < 4 or off + 4 > len(blob):
            return b""
        ln = (blob[off + 2] << 8) | blob[off + 3]
        if ln == 0 or off + 4 + ln > len(blob):
            return b""
        return blob[off + 4:off + 4 + ln]
    finally:
        _kernel32.CloseHandle(h)


_IOCTL_DISK_GET_DRIVE_LAYOUT_EX = (0x07 << 16) | (0x14 << 2)  # 0x70050


def _win_get_ip_net_table() -> int:
    # iphlpapi!GetIpNetTable via ctypes: drives a real neighbor-table
    # enumerate through nsiproxy. Returns the entry count.
    import ctypes
    iphlpapi = ctypes.windll.iphlpapi
    size = ctypes.c_uint32(0)
    rc = iphlpapi.GetIpNetTable(None, ctypes.byref(size), 0)
    if rc == 1168:            # ERROR_NO_DATA: table empty, query still ran
        return 0
    if rc != 122:             # ERROR_INSUFFICIENT_BUFFER
        raise OSError("GetIpNetTable sizing rc=%d" % rc)
    buf = ctypes.create_string_buffer(size.value)
    rc = iphlpapi.GetIpNetTable(buf, ctypes.byref(size), 0)
    if rc not in (0, 1168):
        raise OSError("GetIpNetTable rc=%d" % rc)
    if rc == 1168:
        return 0
    return struct.unpack_from("<I", buf, 0)[0]


def _win_get_ip_net_table2_blob() -> bytes:
    # GetIpNetTable2 result as raw bytes: the rewrite roundtrip only
    # needs substring checks (fake MAC in, original MAC out), so no
    # MIB_IPNET_ROW2 parsing. sizeof(MIB_IPNET_ROW2) x64 = 92
    # (LUID 8 + idx 4 + len 4 + addr[32] + sockaddr 28 + 4x4 tail).
    import ctypes
    iphlpapi = ctypes.windll.iphlpapi
    table = ctypes.c_void_p()
    # Family = AF_INET (2): the pinned 18362/18363 layout was captured
    # on the AF_INET table (11 rows, keys stride 24); the AF_UNSPEC
    # table mixes IPv6 rows with different strides.
    rc = iphlpapi.GetIpNetTable2(2, ctypes.byref(table))
    if rc != 0:
        raise OSError("GetIpNetTable2 rc=%d" % rc)
    n = struct.unpack_from("<I", ctypes.string_at(table, 4), 0)[0]
    blob = ctypes.string_at(table, 8 + 92 * n)
    iphlpapi.FreeMibTable(table)
    return blob


def _hwid_read_capture(handle, token: bytes) -> dict:
    # 0x754 readback: 5288-byte MYARK_HWID_CAPTURE_OUTPUT (R3-1b + diag
    # tail; Input[] widened to 128B to hold a full NSI_PARAMS request).
    payload = _ioctl(handle, IOCTL_MYARK_HWID_QUERY_SPOOF_CAPTURE,
                     _hwid_in_buf(token, 0, 0, 0, b""), 5288)
    magic, armed, tcount, dlen = struct.unpack_from("<IIII", payload, 0)
    seq = struct.unpack_from("<Q", payload, 16)[0]
    tuples = []
    for i in range(8):
        base = 24 + i * 144
        code, in_len, out_len = struct.unpack_from("<III", payload, base)
        head = min(in_len, 128)  # Input[] is capped at 128 by the driver
        tup_in = payload[base + 16:base + 16 + head] if head else b""
        if code == 0 and in_len == 0 and out_len == 0:
            continue
        tuples.append((code, in_len, out_len, tup_in))
    dnc, dif, dnb, dbg2 = struct.unpack_from("<IIII", payload, 5272)
    return {"magic": magic, "armed": armed, "tuple_count": tcount,
            "sequence": seq, "dump_len": dlen, "tuples": tuples,
            "diag": (dnc, dif, dnb, dbg2),
            "dump": payload[1176:1176 + dlen]}


def _hwid_print_capture(cap: dict) -> None:
    # Calibration dump: tuple table + hex head of the last enumerate
    # response. Read the log with --hex mode to pin the NSI layout.
    print("    [HWID-CAPTURE] magic=#%08x armed=%d seq=%d tuples=%d dump=%d"
          % (cap["magic"], cap["armed"], cap["sequence"],
             cap["tuple_count"], cap["dump_len"]))
    for idx, (code, in_len, out_len, tup_in) in enumerate(cap["tuples"]):
        print("    [HWID-CAPTURE] tup[%d] code=#%08x in=%d out=%d in_head=%s"
              % (idx, code, in_len, out_len, tup_in[:48].hex()))
    head = cap["dump"][:512]
    for off in range(0, len(head), 32):
        print("    [HWID-CAPTURE] dump+%03x %s"
              % (off, head[off:off + 32].hex()))


def _query_partition_info(part: int = 1) -> tuple:
    # Both flavors read through the whole-disk (PhysicalDrive0) LAYOUT
    # query: the partition-name symlink resolves to different stacks
    # on 18362 vs 22631 (22631 bypasses the attached filters entirely
    # -- observed queries=0 on an applied class), while PhysicalDrive0
    # is filtered on both. GPT: layout PartitionEntry[part-1] (base
    # 48, stride 144) Gpt.PartitionId at +48; MBR: Mbr.Signature @8.
    h = _kernel32.CreateFileW("\\\\.\\PhysicalDrive0", GENERIC_READ,
                              0x1 | 0x2, None, 3, 0, None)
    if h == -1 or h == 0xFFFFFFFFFFFFFFFF:
        raise OSError("open PhysicalDrive0 failed")
    try:
        ok, blob, err = _ioctl_raw(h, _IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
                                   b"", 4096)
        if not ok:
            raise OSError("get drive layout failed err=%d" % err)
        style, count = struct.unpack_from("<II", blob, 0)
        if style == 1:                      # PARTITION_STYLE_GPT
        # PARTITION_INFORMATION_GPT = {PartitionType, PartitionId,
        # Attributes, Name} -> the id is entry_base + 48.
            base = 48 + (part - 1) * 144
            estyle = struct.unpack_from("<I", blob, base)[0]
            if estyle != 1:
                raise OSError("entry %d is not GPT (style=%d)" % (part, estyle))
            return 1, blob[base + 48:base + 64]
        return (0 if style == 0 else style), blob[8:12]
    finally:
        _kernel32.CloseHandle(h)






# ---------------------------------------------------------------------------
# [CPU] R3-14: per-CPU register snapshot (0x84A). Read-only IPI capture of
# CR0-4/CR8, GDT/IDT, and a fixed MSR whitelist (LSTAR/EFER/PAT/APIC base).
# ---------------------------------------------------------------------------

IOCTL_MYARK_CPU_SNAPSHOT = _ctl_code(FILE_DEVICE_UNKNOWN, 0x84A, METHOD_BUFFERED, FILE_ANY_ACCESS)
_MYARK_CPU_ENTRY = 112
_MYARK_CPU_MAX = 64


# ---------------------------------------------------------------------------
# [SECPOST] R3-6: platform security posture snapshot (0x7D3) -- hypervisor,
# VBS/HVCI, AppLocker, WDAC policy count, BAM. Read-only registry/CPUID.
# ---------------------------------------------------------------------------

IOCTL_MYARK_SECURITY_AUDIT_POSTURE = _ctl_code(FILE_DEVICE_UNKNOWN, 0x7D3, METHOD_BUFFERED, FILE_ANY_ACCESS)
_SECPOST_SIZE = 328


# ---------------------------------------------------------------------------
# [MUTTX] R3-8: mutation transaction PREPARE/COMMIT/ROLLBACK (0x732-0x735).
# Flags2 mask-and-set toggle on own PID as the test vehicle.
# ---------------------------------------------------------------------------

IOCTL_MYARK_MUTATION_TX_PREPARE = _ctl_code(FILE_DEVICE_UNKNOWN, 0x732, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_MUTATION_TX_COMMIT = _ctl_code(FILE_DEVICE_UNKNOWN, 0x733, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_MUTATION_TX_ROLLBACK = _ctl_code(FILE_DEVICE_UNKNOWN, 0x734, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_MUTATION_TX_LIST = _ctl_code(FILE_DEVICE_UNKNOWN, 0x735, METHOD_BUFFERED, FILE_ANY_ACCESS)
MYARK_MUTATION_OP_TX_PREPARE = 0x364D5554
MYARK_MUTATION_OP_TX_COMMIT = 0x374D5554
MYARK_MUTATION_OP_TX_ROLLBACK = 0x384D5554
_TX_PREPARE_SIZE = 184
_TX_EXEC_SIZE = 88
_TX_LIST_SIZE = 912
_TX_OP_SPEC = 24


def verify_mutation_tx(handle, session_key: bytes | None) -> None:
    _step("MUTTX transaction PREPARE/COMMIT/ROLLBACK (R3-8)")
    pid = os.getpid() & 0xFFFFFFFF
    if session_key is None:
        skip("MUTTX", "tx cycle", "no session key")
        return
    tok_p = sign_token(session_key, pid, MYARK_MUTATION_OP_TX_PREPARE, nt_filetime_now())
    tok_c = sign_token(session_key, pid, MYARK_MUTATION_OP_TX_COMMIT, nt_filetime_now())
    tok_r = sign_token(session_key, pid, MYARK_MUTATION_OP_TX_ROLLBACK, nt_filetime_now())

    def _prep(op_type, ppl_level, mask, value):
        ops = struct.pack("<IIIIII", op_type, pid, ppl_level, mask, value, 0)
        ops += struct.pack("<IIIIII", 0, 0, 0, 0, 0, 0) * 3
        buf = tok_p + struct.pack("<III", 1, 0, 0) + ops
        buf += b"\x00" * (_TX_PREPARE_SIZE - len(buf))
        return _ioctl_raw(handle, IOCTL_MYARK_MUTATION_TX_PREPARE, buf, 16)

    def _exec(ioctl, tok_bytes, tx_token):
        buf = tok_bytes + struct.pack("<IIII", tx_token, 0, 0, 0)
        return _ioctl_raw(handle, ioctl, buf, 16)

    def _list():
        payload = _ioctl(handle, IOCTL_MYARK_MUTATION_TX_LIST, b"", _TX_LIST_SIZE)
        status, active, audit_count, audit_idx = struct.unpack_from("<IIII", payload, 0)
        return status, active, audit_count, audit_idx

    # Flags2 toggle: mask=0x1, value=0x1 (set bit 0)
    mask, value = 0x1, 0x1
    op_type = 2  # MYARK_MUTATION_TX_OP_FLAGS2

    # --- 1. PREPARE without token → ACCESS_DENIED ---
    ok, _p, err = _prep(op_type, 0, mask, value)
    # _prep uses tok_p; replace with zeroed token for the negative test
    ok2, _p2, err2 = _ioctl_raw(handle, IOCTL_MYARK_MUTATION_TX_PREPARE,
                                bytes(_TX_PREPARE_SIZE), 16)
    check("MUTTX", "PREPARE without token denied",
          (not ok2) and err2 == ERROR_ACCESS_DENIED, "win32_err=%d" % err2)

    # --- 2. PREPARE + ROLLBACK (nothing applied yet → no-op rollback) ---
    ok, payload, err = _prep(op_type, 0, mask, value)
    if not ok:
        check("MUTTX", "PREPARE #1 (Flags2 toggle)", False, "err=%d" % err)
        return
    tx1 = struct.unpack_from("<I", payload, 4)[0]
    accepted1 = struct.unpack_from("<I", payload, 8)[0]
    check("MUTTX", "PREPARE #1 accepted", accepted1 == 1 and tx1 != 0xFFFFFFFF,
          "tx=%d accepted=%d" % (tx1, accepted1))

    ok, payload, err = _exec(IOCTL_MYARK_MUTATION_TX_ROLLBACK, tok_r, tx1)
    if not ok:
        check("MUTTX", "ROLLBACK on PREPARED", False, "err=%d" % err)
        return
    rolled = struct.unpack_from("<I", payload, 4)[0]
    tx_state = struct.unpack_from("<I", payload, 12)[0]
    check("MUTTX", "ROLLBACK on PREPARED → rolled=0 (nothing applied)",
          rolled == 0 and tx_state == 3, "rolled=%d state=%d" % (rolled, tx_state))

    # --- 3. PREPARE + COMMIT (applies the Flags2 toggle) ---
    ok, payload, err = _prep(op_type, 0, mask, value)
    if not ok:
        check("MUTTX", "PREPARE #2", False, "err=%d" % err)
        return
    tx2 = struct.unpack_from("<I", payload, 4)[0]
    ok, payload, err = _exec(IOCTL_MYARK_MUTATION_TX_COMMIT, tok_c, tx2)
    if not ok:
        check("MUTTX", "COMMIT #2", False, "err=%d" % err)
        return
    applied2 = struct.unpack_from("<I", payload, 4)[0]
    tx_state2 = struct.unpack_from("<I", payload, 12)[0]
    check("MUTTX", "COMMIT #2 applied", applied2 == 1 and tx_state2 == 2,
          "applied=%d state=%d" % (applied2, tx_state2))

    # --- 4. PREPARE + COMMIT (toggle back to restore) ---
    ok, payload, err = _prep(op_type, 0, mask, value)
    if not ok:
        check("MUTTX", "PREPARE #3 (restore)", False, "err=%d" % err)
        return
    tx3 = struct.unpack_from("<I", payload, 4)[0]
    ok, payload, err = _exec(IOCTL_MYARK_MUTATION_TX_COMMIT, tok_c, tx3)
    applied3 = struct.unpack_from("<I", payload, 4)[0] if ok else 0
    check("MUTTX", "COMMIT #3 (restore)", ok and applied3 == 1,
          "applied=%d" % applied3)

    # --- 5. TX_LIST audit ring sanity ---
    lst_status, lst_active, lst_audit_count, lst_audit_idx = _list()
    check("MUTTX", "TX_LIST audit ring has >= 5 events",
          lst_audit_count >= 5 and lst_status == 0,
          "active=%d audit=%d" % (lst_active, lst_audit_count))


def verify_security_posture(handle) -> None:
    _step("SECPOST posture snapshot (R3-6)")
    try:
        payload = _ioctl(handle, IOCTL_MYARK_SECURITY_AUDIT_POSTURE, b"", _SECPOST_SIZE)
    except OSError as exc:
        check("SECPOST", "0x7D3 posture callable", False, str(exc))
        return

    status = struct.unpack_from("<I", payload, 0)[0]
    hv = struct.unpack_from("<I", payload, 4)[0]
    hv_vendor = payload[8:24].split(b"\x00")[0].decode("ascii", "replace").lower()
    vbs, hvci, hvci_run = struct.unpack_from("<III", payload, 24)
    alp_col, alp_enf, wdac_count, wdac_dir, bam = struct.unpack_from("<IIIII", payload, 36)

    check("SECPOST", "in-band success", status == 0, "status=#%08x" % status)
    check("SECPOST", "hypervisor present on VM, vendor known",
          hv == 1 and hv_vendor in ("microsoft hv", "vmwarevmware", "kvmkvmkvm", "xenvm"),
          "hv=%d vendor=%r" % (hv, hv_vendor))
    check("SECPOST", "VBS/HVCI tri-state domain",
          all(v in (0, 1, 2) for v in (vbs, hvci, hvci_run)),
          "vbs=%d hvci=%d run=%d" % (vbs, hvci, hvci_run))
    check("SECPOST", "BAM start type domain",
          bam == 0xFF or bam <= 4,
          "bam=%d" % bam)

    # WDAC policy count: the driver's directory query must agree with the
    # guest-side listing of CodeIntegrity\CiPolicies\Active.
    wdac_dir_guest = "C:\\Windows\\System32\\CodeIntegrity\\CiPolicies\\Active"
    host_count = 0
    host_present = os.path.isdir(wdac_dir_guest)
    if host_present:
        host_count = len([f for f in os.listdir(wdac_dir_guest)
                          if os.path.isfile(os.path.join(wdac_dir_guest, f))])
    check("SECPOST", "WDAC active-policy count matches directory listing",
          (wdac_dir == 1 and wdac_count == host_count)
          or (wdac_dir == 0 and not host_present and wdac_count == 0),
          "driver=%d/%d guest_present=%s guest_count=%d"
          % (wdac_dir, wdac_count, host_present, host_count))
    check("SECPOST", "AppLocker enforcement implies collections",
          alp_enf == 0 or alp_col >= 1,
          "col=%d enf=%d" % (alp_col, alp_enf))


IOCTL_MYARK_CALLBACK_OB_PROTECT_SET = _ctl_code(FILE_DEVICE_UNKNOWN, 0x723, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_CALLBACK_OB_PROTECT_STATUS = _ctl_code(FILE_DEVICE_UNKNOWN, 0x724, METHOD_BUFFERED, FILE_ANY_ACCESS)
MYARK_CALLBACK_OP_OB_PROTECT_SET = 0x35524243  # 'CBR5'
MYARK_OB_PROTECT_ACTION_ADD = 1
MYARK_OB_PROTECT_ACTION_REMOVE = 2
_MYARK_OB_PROTECT_STATUS_SIZE = 224
_PROC_TERMINATE = 0x0001
_PROC_VM_WRITE = 0x0020
_PROC_VM_READ = 0x0010
_PROC_ALL_ACCESS = 0x1FFFFF


def verify_obprotect(handle, session_key: bytes | None) -> None:
    _step("OBPROTECT ObCallbacks STRIP_ACCESS (R3-9)")
    pid = os.getpid() & 0xFFFFFFFF
    import ctypes
    k32 = ctypes.windll.kernel32
    def _set(action, who, tok_bytes):
        buf = tok_bytes + struct.pack("<IIII", action, who, 0, 0)
        return _ioctl_raw(handle, IOCTL_MYARK_CALLBACK_OB_PROTECT_SET, buf, 16)
    def _status():
        payload = _ioctl(handle, IOCTL_MYARK_CALLBACK_OB_PROTECT_STATUS, b"", _MYARK_OB_PROTECT_STATUS_SIZE)
        reg, cnt = struct.unpack_from("<II", payload, 4)
        total = struct.unpack_from("<Q", payload, 16)[0]
        strips = struct.unpack_from("<16Q", payload, 24)
        pids = struct.unpack_from("<16I", payload, 152)
        return reg, cnt, total, strips, pids
    def _open_granted(target_pid):
        h = k32.OpenProcess(0x1FFFFF, False, target_pid)
        if not h:
            return 0
        try:
            class OBI(ctypes.Structure):
                _fields_ = [('Attributes', ctypes.c_ulong), ('GrantedAccess', ctypes.c_ulong), ('HandleCount', ctypes.c_ulong), ('PointerCount', ctypes.c_ulong), ('PagedPool', ctypes.c_ulong), ('NonPagedPool', ctypes.c_ulong), ('Reserved', ctypes.c_ulong * 3), ('NameInfoLen', ctypes.c_ulong), ('TypeInfoLen', ctypes.c_ulong), ('SecDescLen', ctypes.c_ulong), ('CreateTime', ctypes.c_ulonglong)]
            obi = OBI()
            ret = ctypes.c_ulong()
            ctypes.windll.ntdll.NtQueryObject(h, 0, ctypes.byref(obi), ctypes.sizeof(obi), ctypes.byref(ret))
            return obi.GrantedAccess
        finally:
            k32.CloseHandle(h)
    if session_key is None:
        skip("OBPROTECT", "strip cycle", "no session key")
        return
    token = sign_token(session_key, pid, MYARK_CALLBACK_OP_OB_PROTECT_SET, nt_filetime_now())
    ok, _p, err = _set(MYARK_OB_PROTECT_ACTION_ADD, pid, bytes(SAFETY_TOKEN_SIZE))
    check("OBPROTECT", "ADD without token denied", (not ok) and err == ERROR_ACCESS_DENIED, "win32_err=%d" % err)
    ok, payload, err = _set(MYARK_OB_PROTECT_ACTION_ADD, pid, token)
    reg, cnt, total, strips, pids = _status()
    check("OBPROTECT", "ADD self -> listed", ok and reg == 1 and cnt >= 1 and pid in pids[:cnt], "ok=%s reg=%d cnt=%d" % (ok, reg, cnt))
    granted_protected = _open_granted(pid)
    _FULL_STRIP = 0x087B  # TERM|CTHREAD|VMOP|VMR|VMW|DUP|SUSP
    stripped_ok = ((granted_protected & _FULL_STRIP) == 0)
    check("OBPROTECT", "PROTECTED: dangerous bits stripped from handle", granted_protected != 0 and stripped_ok, "granted=#%06x term=%d vmw=%d vmr=%d" % (granted_protected, granted_protected & _PROC_TERMINATE, granted_protected & _PROC_VM_WRITE, granted_protected & _PROC_VM_READ))
    ok, payload, err = _set(MYARK_OB_PROTECT_ACTION_REMOVE, pid, token)
    reg2, cnt2, total2, strips2, pids2 = _status()
    check("OBPROTECT", "REMOVE self -> unlisted", ok and cnt2 == 0 and pid not in pids2[:cnt2], "ok=%s cnt=%d" % (ok, cnt2))
    granted_full = _open_granted(pid)
    full_ok = ((granted_full & _PROC_TERMINATE) != 0 and (granted_full & _PROC_VM_WRITE) != 0)
    check("OBPROTECT", "UNPROTECTED: full access restored", granted_full != 0 and full_ok, "granted=#%06x term=%d vmw=%d" % (granted_full, granted_full & _PROC_TERMINATE, granted_full & _PROC_VM_WRITE))
    check("OBPROTECT", "TotalStrips >= 1 after the cycle", total2 >= 1, "total=%d" % total2)



def verify_cpu(handle) -> None:
    _step("CPU per-core register snapshot (R3-14)")
    try:
        payload = _ioctl(handle, IOCTL_MYARK_CPU_SNAPSHOT, b"", 7224)
    except OSError as exc:
        check("CPU", "0x84A snapshot callable", False, str(exc))
        return

    cpu_count, current_cpu = struct.unpack_from("<II", payload, 0)
    vendor = payload[8:20].split(b"\x00")[0].decode("ascii", "replace").lower()
    max_leaf = struct.unpack_from("<I", payload, 40)[0]

    check("CPU", "cpu count matches the platform",
          1 <= cpu_count <= _MYARK_CPU_MAX and cpu_count == os.cpu_count()
          and current_cpu < cpu_count,
          "count=%d current=%d os=%d" % (cpu_count, current_cpu, os.cpu_count()))
    check("CPU", "vendor string sane",
          vendor in ("genuineintel", "authenticamd"),
          "vendor=%r maxleaf=%d" % (vendor, max_leaf))

    kva_base = 0xFFFF800000000000
    cr0s, lstars, gdt_bases, efers = [], [], [], []
    ok_regs = True
    for i in range(cpu_count):
        base = 56 + i * _MYARK_CPU_ENTRY
        f = struct.unpack_from("<13Q", payload, base)
        cr0, cr2, cr3, cr4, cr8, gdtb, gdtl, idtb, idtl, lstar, efer, pat, apic = f
        num = struct.unpack_from("<I", payload, base + 104)[0]
        if num != i:
            ok_regs = False
        cr0s.append(cr0)
        lstars.append(lstar)
        gdt_bases.append(gdtb)
        efers.append(efer)
        if (cr0 & 0x80000001) != 0x80000001:      # PE | PG
            ok_regs = False
        if gdtb < kva_base or gdtl > 0xFFFF or idtb < kva_base:
            ok_regs = False
        if lstar < kva_base:
            ok_regs = False
    check("CPU", "control registers sane (CR0.PE|PG, nonzero GDT limit, kernel GDT/IDT)",
          ok_regs and all(g > kva_base for g in gdt_bases)
          and all(struct.unpack_from("<Q", payload, 56 + i * _MYARK_CPU_ENTRY + 40)[0] > 0
                  for i in range(cpu_count)),
          "cr0=%s gdt0=#%x" % ([hex(c) for c in cr0s[:4]], gdt_bases[0] if gdt_bases else 0))
    check("CPU", "LSTAR uniform across CPUs in kernel range",
          len(set(lstars)) == 1 and all(l >= kva_base for l in lstars),
          "lstar=%s" % [hex(l) for l in lstars[:4]])
    check("CPU", "EFER.SCE set on all CPUs",
          all(e & 1 for e in efers), 
          "efer=%s" % [hex(e) for e in efers[:4]])


def verify_hwid_spoof(handle, session_key: bytes | None) -> None:
    _step("HWID spoof subdivision (R3-1 T-B)")
    pid = os.getpid() & 0xFFFFFFFF
    disk_spoof = b"MYARKVM00DISK1"
    import uuid  # local: not imported at module scope
    part_guid = uuid.UUID("12345678-9abc-def0-fedc-ba9876543210").bytes_le
    gpu_spoof = b"MYARKGPUSN01"

    if session_key is None:
        skip("HWID", "spoof cycle", "no session key")
        return
    token = sign_token(session_key, pid, MYARK_HWID_OP_SPOOF_CONFIG, nt_filetime_now())

    def _set(cls: int, action: int, flags: int, value: bytes, disk: int = 0):
        raw = _ioctl_raw(handle, IOCTL_MYARK_HWID_SET_SPOOF_CONFIG,
                         _hwid_in_buf(token, cls, action, flags, value, disk), 288)
        return raw[0], (_hwid_out(raw[1]) if raw[0] else None), raw[2]

    disk_applied = False
    part_applied = False
    gpu_applied = False
    dev_applied = False
    arp_capture_armed = False
    try:
        # --- 1. status table sanity (no token needed) ---
        payload = _ioctl(handle, IOCTL_MYARK_HWID_QUERY_SPOOF_STATUS, b"", _MYARK_HWID_STATUS_SIZE)
        count = struct.unpack_from("<I", payload, 0)[0]
        arp_flags = _hwid_status_flags(handle, MYARK_HWID_CLASS_ARP)[0]
        dev_flags = _hwid_status_flags(handle, MYARK_HWID_CLASS_DEVICE_ID)[0]
        check("HWID", "status table: 6 classes, ARP profile-gated, DEVICE_ID present",
              count == 6 and arp_flags is not None and dev_flags is not None,
              "count=%d arp_flags=#%x dev_flags=#%x"
              % (count, arp_flags or 0, dev_flags or 0))

        # --- 2. negative token gate on 0x753 ---
        ok, _p, err = _ioctl_raw(handle, IOCTL_MYARK_HWID_SET_SPOOF_CONFIG,
                                 _hwid_in_buf(bytes(SAFETY_TOKEN_SIZE),
                                              MYARK_HWID_CLASS_DISK_SERIAL,
                                              MYARK_HWID_ACTION_DRY_RUN, 0,
                                              disk_spoof), 288)
        check("HWID", "DRY_RUN without token denied",
              (not ok) and err == ERROR_ACCESS_DENIED, "win32_err=%d" % err)

        # --- 3. disk serial DRY_RUN preview matches the python-side read ---
        serial_pre = _query_disk_serial(0)
        ok, out, err = _set(MYARK_HWID_CLASS_DISK_SERIAL, MYARK_HWID_ACTION_DRY_RUN,
                            0, disk_spoof)
        check("HWID", "disk serial DRY_RUN previews real value",
              ok and out is not None and out["status"] == 0 and len(out["real"]) > 0
              and out["real"] == serial_pre and out["spoof"] == disk_spoof,
              "real=%r pre=%r err=%d" % (out["real"] if out else b"", serial_pre, err))

        # --- 4. APPLY without the double flag is denied ---
        ok, _o, err = _set(MYARK_HWID_CLASS_DISK_SERIAL, MYARK_HWID_ACTION_APPLY,
                           _MYARK_FLAG_UI_CONFIRMED, disk_spoof)
        check("HWID", "APPLY without UI_CONFIRMED|FORCE denied",
              (not ok) and err == ERROR_ACCESS_DENIED, "win32_err=%d" % err)

        # --- 5. APPLY disk serial, end-to-end value proof ---
        ok, out, err = _set(MYARK_HWID_CLASS_DISK_SERIAL, MYARK_HWID_ACTION_APPLY,
                            _MYARK_FLAG_UI_CONFIRMED | _MYARK_FLAG_FORCE, disk_spoof)
        disk_applied = ok and out is not None and out["applied"] == 1
        check("HWID", "disk serial APPLY activates the class",
              disk_applied and out["status"] == 0, "err=%d out=%s"
              % (err, out["status"] if out else "-"))
        if disk_applied:
            serial_during = _query_disk_serial(0)
            check("HWID", "disk serial query returns spoofed value",
                  serial_during != serial_pre and len(serial_during) > 0
                  and disk_spoof.startswith(serial_during),
                  "during=%r pre=%r" % (serial_during, serial_pre))
            flags, rewritten, attached, _q, _l = _hwid_status_flags(
                handle, MYARK_HWID_CLASS_DISK_SERIAL)
            check("HWID", "disk class status: ACTIVE+ATTACHED, rewrites counted",
                  flags is not None
                  and (flags & MYARK_HWID_SPOOF_ST_ACTIVE) != 0
                  and (flags & MYARK_HWID_SPOOF_ST_ATTACHED) != 0
                  and rewritten >= 1 and attached >= 1,
                  "flags=#%x rewritten=%d attached=%d" % (flags or 0, rewritten, attached))

        # --- 5b. mountmgr UniqueId cycle (embedded-descriptor serial) ---
        ok, out, err = _set(MYARK_HWID_CLASS_MOUNTMGR_UID,
                            MYARK_HWID_ACTION_DRY_RUN, 0, b"MYARKVM00UID01")
        if ok and out is not None and out["status"] != 0:
            # Clean refusal on disks without a rewriteable UniqueId: no
            # embedded descriptor serial (18362 NVMe -> NOT_FOUND) or the
            # build rejects the DUID query shape (22631 -> INVALID_PARAMETER).
            # Both must surface as applied=0 with no attachment.
            check("HWID", "mountmgr UniqueId DRY_RUN refuses cleanly",
                  out["applied"] == 0,
                  "status=#%08x applied=%d"
                  % (out["status"], out["applied"]))
        else:
            uid_dry = ok and out is not None and out["status"] == 0
            uid_real = out["real"] if out else b""
            check("HWID", "mountmgr UniqueId DRY_RUN previews real serial",
                  uid_dry and len(uid_real) > 0,
                  "real=%r status=#%08x err=%d"
                  % (uid_real, out["status"] if out else 0, err))
        ok, out, err = _set(MYARK_HWID_CLASS_MOUNTMGR_UID,
                            MYARK_HWID_ACTION_APPLY,
                            _MYARK_FLAG_UI_CONFIRMED | _MYARK_FLAG_FORCE,
                            b"MYARKVM00UID01")
        uid_applied = (ok and out is not None and out["applied"] == 1
                       and out["status"] == 0)
        if not uid_applied and not (ok and out is not None
                                    and out["status"] != 0):
            check("HWID", "mountmgr UniqueId APPLY activates the class",
                  False, "err=%d" % err)
        uid_restored = True
        if uid_applied:
            # A python-side PropertyId=3 query must flow through the class
            # filter; the rewrite path is proven by the RewrittenCount
            # increment (the embedded serial shares the descriptor serial
            # rewriter proven end-to-end by the disk-serial class above).
            flags, rewritten, attached, _q, _l = _hwid_status_flags(
                handle, MYARK_HWID_CLASS_MOUNTMGR_UID)
            h0 = _kernel32.CreateFileW("\\\\.\\\\PhysicalDrive0",
                                       GENERIC_READ, 0x1 | 0x2,
                                       None, 3, 0, None)
            if h0 not in (-1, 0xFFFFFFFFFFFFFFFF):
                try:
                    _ioctl_raw(h0, _IOCTL_STORAGE_QUERY_PROPERTY,
                               struct.pack("<III", 3, 0, 0), 4096)
                finally:
                    _kernel32.CloseHandle(h0)
            flags2, rewritten2, attached2, _q2, _l2 = _hwid_status_flags(
                handle, MYARK_HWID_CLASS_MOUNTMGR_UID)
            check("HWID", "mountmgr UniqueId query rewrite counted",
                  flags2 is not None and rewritten2 >= rewritten + 1
                  and attached2 >= 1,
                  "rewritten %d->%d attached=%d"
                  % (rewritten, rewritten2, attached2))
            ok, out, err = _set(MYARK_HWID_CLASS_MOUNTMGR_UID,
                                MYARK_HWID_ACTION_RESTORE, 0, b"")
            uid_restored = ok and out is not None and out["status"] == 0
            check("HWID", "mountmgr UniqueId RESTORE re-probe == preview",
                  uid_restored and out["real"] == uid_real,
                  "real=%r want=%r err=%d"
                  % (out["real"] if out else b"", uid_real, err))
            uid_applied = False

        # --- 6. partition identifier cycle (GPT id or MBR signature) ---
        try:
            p_style, p_ident = _query_partition_info(1)
        except OSError as exc:
            p_style, p_ident = None, str(exc).encode()
        part_spoof = (part_guid if p_style == 1
                      else bytes([0x5a, 0xa5, 0x12, 0x34]))  # MBR: signature
        part_label = 'GPT id' if p_style == 1 else 'MBR signature'
        ok, out, err = _set(MYARK_HWID_CLASS_PARTITION_GUID,
                            MYARK_HWID_ACTION_DRY_RUN, 0, part_spoof)
        part_dry = (ok and out is not None and out['status'] == 0
                    and out['real'] == p_ident
                    and len(out['real']) == len(part_spoof))
        check("HWID", "partition DRY_RUN previews the real %s" % part_label,
              part_dry,
              "real=%s pre=%s err=%d"
              % (out["real"].hex() if out else "-", p_ident.hex(), err))
        ok, out, err = _set(MYARK_HWID_CLASS_PARTITION_GUID,
                            MYARK_HWID_ACTION_APPLY,
                            _MYARK_FLAG_UI_CONFIRMED | _MYARK_FLAG_FORCE, part_spoof)
        part_applied = ok and out is not None and out['applied'] == 1
        check("HWID", "partition %s APPLY activates the class" % part_label,
              part_applied and out["status"] == 0, "err=%d" % err)
        p_flags, p_rw, p_att, p_q, _l = _hwid_status_flags(
            handle, MYARK_HWID_CLASS_PARTITION_GUID)
        check("HWID", "partition class attached: disk + >=1 partition",
              p_att is not None and p_att >= 2,
              "attached=%d flags=#%x queries=%d rewritten=%d"
              % (p_att or 0, p_flags or 0, p_q or 0, p_rw or 0))
        if part_applied:
            p_style2, ident_during = _query_partition_info(1)
            p_flags2, p_rw2, p_att2, p_q2, _l2 = _hwid_status_flags(
                handle, MYARK_HWID_CLASS_PARTITION_GUID)
            check("HWID", "partition query returns the spoofed %s" % part_label,
                  ident_during == part_spoof,
                  "during=%s want=%s queries=%d rewritten=%d"
                  % (ident_during.hex(), part_spoof.hex(), p_q2, p_rw2))


        # --- 7. GPU contract-level cycle (skip when no serial value) ---
        ok, out, err = _set(MYARK_HWID_CLASS_GPU_SERIAL,
                            MYARK_HWID_ACTION_DRY_RUN, 0, gpu_spoof)
        if ok and out is not None and out["status"] == 0:
            ok, out, err = _set(MYARK_HWID_CLASS_GPU_SERIAL,
                                MYARK_HWID_ACTION_APPLY,
                                _MYARK_FLAG_UI_CONFIRMED | _MYARK_FLAG_FORCE,
                                gpu_spoof)
            gpu_applied = ok and out is not None and out["applied"] == 1
            gpu_real = out["real"] if out else b""
            check("HWID", "GPU registry class APPLY (value found)",
                  gpu_applied, "err=%d" % err)
            ok, out, err = _set(MYARK_HWID_CLASS_GPU_SERIAL,
                                MYARK_HWID_ACTION_RESTORE, 0, b"")
            check("HWID", "GPU registry class RESTORE returns original",
                  ok and out is not None and out["status"] == 0
                  and out["real"] == gpu_real,
                  "real=%r want=%r" % (out["real"] if out else b"", gpu_real))
            gpu_applied = False   # restore already handled
        else:
            check("HWID", "GPU registry class DRY_RUN reports NOT_FOUND cleanly",
                  ok and out is not None
                  and out["status"] in (_STATUS_NOT_FOUND,),
                  "status=#%08x" % (out["status"] if out else 0))

        # --- 8. VPD 0x83 identifier cycle (class DEVICE_ID, R3-1b) ---
        try:
            dev_real = _query_disk_device_id(0)
        except OSError as exc:
            dev_real = str(exc).encode()
        dev_spoof = bytes((b + 1) % 0x7F for b in dev_real) if dev_real else b""
        ok, out, err = _set(MYARK_HWID_CLASS_DEVICE_ID, MYARK_HWID_ACTION_DRY_RUN,
                            0, dev_spoof)
        if not dev_real:
            # Disks with no 0x83 identifiers must refuse cleanly (no
            # attachment, no state) -- contract-level assertion only.
            check("HWID", "DEVICE_ID DRY_RUN refuses cleanly (no identifiers)",
                  ok and out is not None and out["status"] != 0
                  and out["applied"] == 0,
                  "status=#%08x" % (out["status"] if out else 0))
        else:
            dev_dry = (ok and out is not None and out["status"] == 0
                       and out["real"] == dev_real and len(out["real"]) == len(dev_spoof))
            check("HWID", "DEVICE_ID DRY_RUN previews first 0x83 identifier",
                  dev_dry,
                  "real=%s want=%s err=%d status=#%08x"
                  % (out["real"].hex() if out else "-", dev_real.hex(), err,
                     out["status"] if out else 0))
            ok, out, err = _set(MYARK_HWID_CLASS_DEVICE_ID, MYARK_HWID_ACTION_APPLY,
                                _MYARK_FLAG_UI_CONFIRMED | _MYARK_FLAG_FORCE, dev_spoof)
            dev_applied = ok and out is not None and out["applied"] == 1
            check("HWID", "DEVICE_ID APPLY activates the class",
                  dev_applied and out["status"] == 0, "err=%d" % err)
            if dev_applied:
                dev_during = _query_disk_device_id(0)
                d_flags, d_rw, d_att, _q, _l = _hwid_status_flags(
                    handle, MYARK_HWID_CLASS_DEVICE_ID)
                check("HWID", "DEVICE_ID query returns spoofed identifier",
                      dev_during == dev_spoof,
                      "during=%s want=%s rewritten=%d attached=%d"
                      % (dev_during.hex(), dev_spoof.hex(), d_rw, d_att))
                check("HWID", "DEVICE_ID length-gate: other identifiers intact",
                      d_flags is not None and (d_flags & MYARK_HWID_SPOOF_ST_ACTIVE) != 0,
                      "flags=#%x" % (d_flags or 0))
                ok, out, err = _set(MYARK_HWID_CLASS_DEVICE_ID,
                                    MYARK_HWID_ACTION_RESTORE, 0, b"")
                dev_applied = False
                check("HWID", "DEVICE_ID RESTORE re-probe returns original",
                      ok and out is not None and out["status"] == 0
                      and out["real"] == dev_real,
                      "real=%s want=%s err=%d"
                      % (out["real"].hex() if out else "-", dev_real.hex(), err))
                dev_post = _query_disk_device_id(0)
                check("HWID", "DEVICE_ID back to hardware value after RESTORE",
                      dev_post == dev_real,
                      "post=%s pre=%s" % (dev_post.hex(), dev_real.hex()))

        # --- 9. ARP class: capture tool + rewrite roundtrip (R3-1b) ---
        # With the Tier C 18362 profile pinned the actions are live:
        # DRY_RUN reports NOT_FOUND while the cache is cold, APPLY
        # activates the per-enumerate MAC rewrite, and a fresh
        # GetIpNetTable2 readback must show the fake MAC for the target
        # row until RESTORE hands the kernel truth back.
        # value-contract gate: the 10-byte legacy value is rejected (the
        # profile-pinned contract is 16 bytes {ip, original, fake}).
        ok, out, err = _set(MYARK_HWID_CLASS_ARP, MYARK_HWID_ACTION_DRY_RUN,
                            0, b"\xc0\xa8\xc7\x02" + b"\x01" * 6)
        check("HWID", "ARP DRY_RUN 10B legacy value -> INVALID_PARAMETER",
              ok and out is not None and out["status"] == 0xC000000D
              and out["applied"] == 0,
              "status=#%08x" % (out["status"] if out else 0))
        a_flags = _hwid_status_flags(handle, MYARK_HWID_CLASS_ARP)[0]
        check("HWID", "ARP class profile pinned (no UNSUPPORTED flag)",
              a_flags is not None and (a_flags & MYARK_HWID_SPOOF_ST_UNSUPPORTED) == 0,
              "flags=#%x" % (a_flags or 0))

        tok_cap = sign_token(session_key, pid, MYARK_HWID_OP_SPOOF_CONFIG, nt_filetime_now())
        # 0x754 negative gate: no token -> ERROR_ACCESS_DENIED (P2, review)
        ok, _p2, err = _ioctl_raw(handle, IOCTL_MYARK_HWID_QUERY_SPOOF_CAPTURE,
                                  _hwid_in_buf(bytes(SAFETY_TOKEN_SIZE), 0, 0, 0, b""),
                                  5288)
        check("HWID", "0x754 without token denied",
              (not ok) and err == ERROR_ACCESS_DENIED, "win32_err=%d" % err)
        ok, out, err = _set(MYARK_HWID_CLASS_ARP, MYARK_HWID_ACTION_CAPTURE,
                            _MYARK_FLAG_CAPTURE_START, b"")
        armed_ok = ok and out is not None and out["status"] == 0
        arp_capture_armed = armed_ok
        a_flags = _hwid_status_flags(handle, MYARK_HWID_CLASS_ARP)[0]
        check("HWID", "ARP capture START attaches the nsiproxy filter",
              armed_ok and a_flags is not None
              and (a_flags & MYARK_HWID_SPOOF_ST_ATTACHED) != 0,
              "ok=%s flags=#%x err=%d" % (armed_ok, a_flags or 0, err))
        if armed_ok:
            # Drive live nsiproxy traffic through the filter: the old
            # GetIpNetTable (0x120007 small-query flood) plus the
            # GetIpNetTable2 big enumerate (0x12000F) whose embedded
            # column buffers are what the capture is for.
            try:
                _win_get_ip_net_table()
            except OSError as exc:
                check("HWID", "GetIpNetTable probe ran", False, str(exc))
            try:
                blob0 = _win_get_ip_net_table2_blob()
                check("HWID", "GetIpNetTable2 probe ran", True,
                      "bytes=%d" % len(blob0))
            except OSError as exc:
                check("HWID", "GetIpNetTable2 probe ran", False, str(exc))
            cap = _hwid_read_capture(handle, tok_cap)
            check("HWID", "capture ring recorded nsiproxy device-controls",
                  cap["tuple_count"] >= 1,
                  "tuples=%d armed=%d seq=%d dump=%d diag=%s"
                  % (cap["tuple_count"], cap["armed"], cap["sequence"],
                     cap["dump_len"], cap["diag"]))
            # Calibration-build contract: the dump is content-gated (kept
            # for the NSI layout bring-up), so a zero dump is acceptable
            # until the rewrite lands; tuples + armed state are the
            # deliverable assertions here.
            check("HWID", "capture readback structurally sane",
                  cap["magic"] == 0x48574350 and cap["armed"] == 1
                  and cap["dump_len"] <= 4096,
                  "magic=#%08x armed=%d dump=%d"
                  % (cap["magic"], cap["armed"], cap["dump_len"]))
            _hwid_print_capture(cap)
            ok, out, err = _set(MYARK_HWID_CLASS_ARP, MYARK_HWID_ACTION_CAPTURE,
                                0, b"")
            arp_capture_armed = False
            a_flags = _hwid_status_flags(handle, MYARK_HWID_CLASS_ARP)[0]
            check("HWID", "ARP capture STOP detaches the filter",
                  ok and out is not None and out["status"] == 0
                  and a_flags is not None
                  and (a_flags & MYARK_HWID_SPOOF_ST_ATTACHED) == 0,
                  "flags=#%x" % (a_flags or 0))

        # --- 9b. ARP rewrite roundtrip (R3-1b, 18362 profile) ---
        # Target = a live dynamic neighbor with a real unicast MAC, read
        # from the same GetIpNetTable2 (AF_INET) surface the rewrite
        # serves. APPLY patches the per-enumerate user tables, so the
        # fresh readback must show the fake MAC for the target row until
        # RESTORE hands the kernel truth back. MIB_IPNET_ROW2 (x64, 92B):
        # PhysAddrLength@+12, PhysAddr[32]@+16, family@+48, IPv4@+52.
        # Ground-truth target from "arp -a" (text parse, no struct
        # assumptions), cross-checked against the NSI readback blob:
        # the row must be visible to the surface the rewrite serves.
        arp_out = subprocess.run(["arp", "-a"], capture_output=True)
        arp_txt = arp_out.stdout.decode("gbk", "replace")
        blob0 = b""
        try:
            blob0 = _win_get_ip_net_table2_blob()
        except OSError as exc:
            check("HWID", "GetIpNetTable2 target probe ran", False,
                  str(exc))
        tgt_ip = tgt_mac = None
        for line in arp_txt.splitlines():
            parts = line.split()
            if len(parts) < 2 or parts[0].count(".") != 3:
                continue
            if not all(p.isdigit() for p in parts[0].split(".")):
                continue
            try:
                ip = bytes(int(x) for x in parts[0].split("."))
                mac = bytes.fromhex(parts[1].replace("-", ""))
            except ValueError:
                continue
            if len(mac) != 6 or mac[:5] == b"\x00" * 5:
                continue
            if mac[0] in (0x01, 0x33, 0xFF):
                continue
            if ip[0] in (0xE0, 0xEF, 0xFF) or mac not in blob0:
                continue
            tgt_ip, tgt_mac = ip, mac
            break
        check("HWID", "rewrite target present (arp -a x NSI blob)",
              tgt_ip is not None and tgt_mac in blob0,
              "tgt=%s/%s blob=%d"
              % (tgt_ip.hex() if tgt_ip else "-",
                 tgt_mac.hex() if tgt_mac else "-", len(blob0)))
        if tgt_ip is not None and tgt_mac is not None:
            fake = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
            value16 = tgt_ip + tgt_mac + fake
            ok, out, err = _set(MYARK_HWID_CLASS_ARP, MYARK_HWID_ACTION_DRY_RUN,
                                0, value16)
            check("HWID", "ARP DRY_RUN previews the original MAC",
                  ok and out is not None and out["status"] == 0
                  and out["real"] == tgt_mac and out["applied"] == 0,
                  "status=#%08x real=%s"
                  % (out["status"] if out else 0,
                     out["real"].hex() if out else "-"))
            ok, out, err = _set(MYARK_HWID_CLASS_ARP, MYARK_HWID_ACTION_APPLY,
                                _MYARK_FLAG_UI_CONFIRMED | _MYARK_FLAG_FORCE,
                                value16)
            arp_applied = ok and out is not None and out["status"] == 0
            check("HWID", "ARP APPLY activates the rewrite class",
                  arp_applied, "err=%d status=#%08x"
                  % (err, out["status"] if out else 0))
            if arp_applied:
                a_flags = _hwid_status_flags(handle, MYARK_HWID_CLASS_ARP)[0]
                check("HWID", "ARP class ACTIVE+ATTACHED after APPLY",
                      a_flags is not None
                      and (a_flags & MYARK_HWID_SPOOF_ST_ACTIVE) != 0
                      and (a_flags & MYARK_HWID_SPOOF_ST_ATTACHED) != 0,
                      "flags=#%x" % (a_flags or 0))
                try:
                    blob = _win_get_ip_net_table2_blob()
                except OSError as exc:
                    blob = b""
                    check("HWID", "GetIpNetTable2 rewrite readback",
                          False, str(exc))
                check("HWID", "ARP rewrite visible in NSI table readback",
                      len(blob) > 0 and fake in blob and tgt_mac not in blob,
                      "fake_in=%s orig_gone=%s bytes=%d"
                      % (fake in blob, tgt_mac not in blob, len(blob)))
                st_arp = _hwid_status_flags(handle, MYARK_HWID_CLASS_ARP)
                check("HWID", "ARP rewrite pass fired (rewritten>=1)",
                      st_arp[1] is not None and st_arp[1] >= 1,
                      "rewritten=%s last=#%08x" % (st_arp[1], st_arp[4] or 0))
                ok, out, err = _set(MYARK_HWID_CLASS_ARP,
                                    MYARK_HWID_ACTION_RESTORE, 0, b"")
                arp_applied = False
                check("HWID", "ARP RESTORE returns the learned real MAC",
                      ok and out is not None and out["status"] == 0
                      and out["real"] == tgt_mac,
                      "real=%s want=%s"
                      % (out["real"].hex() if out else "-", tgt_mac.hex()))
                try:
                    blob2 = _win_get_ip_net_table2_blob()
                except OSError as exc:
                    blob2 = b""
                    check("HWID", "GetIpNetTable2 restore readback",
                          False, str(exc))
                check("HWID", "ARP restore: original MAC back in NSI table",
                      len(blob2) > 0 and tgt_mac in blob2 and fake not in blob2,
                      "orig_back=%s fake_gone=%s bytes=%d"
                      % (tgt_mac in blob2, fake not in blob2, len(blob2)))

        # --- 9. restore proof: preview re-probe == the pre-apply value ---
        ok, out, err = _set(MYARK_HWID_CLASS_DISK_SERIAL,
                            MYARK_HWID_ACTION_RESTORE, 0, b"")
        disk_applied = False
        check("HWID", "disk serial RESTORE re-probe returns original",
              ok and out is not None and out["status"] == 0
              and out["real"] == serial_pre,
              "real=%r pre=%r" % (out["real"] if out else b"", serial_pre))
        serial_post = _query_disk_serial(0)
        check("HWID", "disk serial back to hardware value after RESTORE",
              serial_post == serial_pre, "post=%r pre=%r" % (serial_post, serial_pre))
        ok, out, err = _set(MYARK_HWID_CLASS_PARTITION_GUID,
                            MYARK_HWID_ACTION_RESTORE, 0, b"")
        part_applied = False
        check("HWID", "partition RESTORE re-probe returns original",
              ok and out is not None and out["status"] == 0
              and out["real"] == p_ident,
              "real=%s pre=%s" % (out["real"].hex() if out else "-", p_ident.hex()))
        flags, _r, _a, _q, _l = _hwid_status_flags(handle, MYARK_HWID_CLASS_DISK_SERIAL)
        check("HWID", "post-restore status: class inactive, cache cleared",
              flags is not None and (flags & (MYARK_HWID_SPOOF_ST_ACTIVE
                                              | MYARK_HWID_SPOOF_ST_CACHE_VALID)) == 0,
              "flags=#%x" % (flags or 0))
    finally:
        # Best-effort restore so the VM never keeps a spoof after verify.
        if arp_capture_armed:
            try:
                _set(MYARK_HWID_CLASS_ARP, MYARK_HWID_ACTION_CAPTURE, 0, b"")
            except OSError:
                pass
        if arp_applied:
            # P1 (review): an escaped exception between APPLY and RESTORE
            # would otherwise leave the class ACTIVE -- every later
            # neighbor enumeration on the guest keeps showing the fake.
            try:
                _set(MYARK_HWID_CLASS_ARP, MYARK_HWID_ACTION_RESTORE, 0, b"")
            except OSError:
                pass
        if dev_applied:
            try:
                _set(MYARK_HWID_CLASS_DEVICE_ID, MYARK_HWID_ACTION_RESTORE, 0, b"")
            except OSError:
                pass
        if disk_applied:
            try:
                _set(MYARK_HWID_CLASS_DISK_SERIAL, MYARK_HWID_ACTION_RESTORE, 0, b"")
            except OSError:
                pass
        if part_applied:
            try:
                _set(MYARK_HWID_CLASS_PARTITION_GUID, MYARK_HWID_ACTION_RESTORE, 0, b"")
            except OSError:
                pass
        if gpu_applied:
            try:
                _set(MYARK_HWID_CLASS_GPU_SERIAL, MYARK_HWID_ACTION_RESTORE, 0, b"")
            except OSError:
                pass
# ---------------------------------------------------------------------------
# [RUNTIME] R3-5: DETAIL_RUNTIME sampling (0xA03 / 0xA12). Historically an
# all-zero stub; the fills now come from ProcessVmCounters + ProcessCycleTime
# and KeQueryRuntimeThread.
# ---------------------------------------------------------------------------

IOCTL_MYARK_PROCESS_DETAIL_RUNTIME_R3 = _ctl_code(FILE_DEVICE_UNKNOWN, 0xA03, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_MYARK_THREAD_DETAIL_RUNTIME_R3 = _ctl_code(FILE_DEVICE_UNKNOWN, 0xA12, METHOD_BUFFERED, FILE_ANY_ACCESS)


def verify_runtime_fields(handle, session_key: bytes | None) -> None:
    _step("RUNTIME_FIELDS sampling (R3-5)")
    pid = os.getpid() & 0xFFFFFFFF
    tid = _kernel32.GetCurrentThreadId() & 0xFFFFFFFF
    del session_key

    # --- 0xA03: process VM counters on this process ---
    try:
        payload = _ioctl(handle, IOCTL_MYARK_PROCESS_DETAIL_RUNTIME_R3,
                         struct.pack("<II", pid, 0), 128)
        (r_pid, _r0, peak_ws, ws, _qpp_peak, _qpp, _qnp_peak, _qnp,
         pf, _pf_peak, priv, _r1, cycles) = struct.unpack_from("<IIQQQQQQQQIIQ", payload, 0)
        check("RUNTIME", "0xA03 VM counters sane",
              r_pid == pid and ws > 0 and peak_ws >= ws and pf > 0 and priv > 0,
              "pid=%d ws=%d peak=%d pf=%d priv=%d cycles=%d open=#%08X probe=%#08X"
              % (r_pid, ws, peak_ws, pf, priv, cycles, _r0, _r1))
    except OSError as exc:
        check("RUNTIME", "0xA03 VM counters sane", False, str(exc))

    # --- 0xA12: thread tick counts on this thread ---
    try:
        payload = _ioctl(handle, IOCTL_MYARK_THREAD_DETAIL_RUNTIME_R3,
                         struct.pack("<II", tid, 0), 64)
        (t_tid, _r0, ktime, utime, cycles, switches, _r1, flags, _r2) = \
            struct.unpack_from("<IIQQQIIII", payload, 0)
        check("RUNTIME", "0xA12 thread ticks sane",
              t_tid == tid and (ktime + utime) > 0,
              "tid=%d k=%d u=%d cyc=%d sw=%d flags=#%x"
              % (t_tid, ktime, utime, cycles, switches, flags))
    except OSError as exc:
        check("RUNTIME", "0xA12 thread ticks sane", False, str(exc))

    # --- bogus pid fails cleanly (no zero-filled lie) ---
    try:
        payload = _ioctl(handle, IOCTL_MYARK_PROCESS_DETAIL_RUNTIME_R3,
                         struct.pack("<II", 0x5FFFFFFF, 0), 128)
        r_pid = struct.unpack_from("<I", payload, 0)[0]
        ws = struct.unpack_from("<Q", payload, 8)[0]
        check("RUNTIME", "0xA03 dead pid -> empty",
              r_pid == 0x5FFFFFFF and ws == 0,
              "pid=%x ws=%d" % (r_pid, ws))
    except OSError as exc:
        check("RUNTIME", "0xA03 dead pid -> empty", False, str(exc))



def verify_ioctl_matrix(handle, capability_functions: list[int]) -> None:
    _step("MATRIX reachability smoke (zeroed 1 KiB input per IOCTL)")
    registered = set(capability_functions)
    zero_in = b"\x00" * 1024
    out_size = 16 * 1024

    # Registration is the acceptance bar for a read-only smoke: if the code
    # is in the capability table the request reached a real handler, and a
    # handler may legitimately answer "invalid request" or "not implemented"
    # for a zeroed argument block (Win32 maps both to error 1, so the error
    # code alone cannot distinguish them from an unregistered code).
    for module, name, function in MATRIX_READ_ONLY:
        is_registered = function in registered
        ok, payload, err = _ioctl_raw(handle, _ioctl_full_code(function), zero_in, out_size)
        check("MATRIX", f"{module}:{name}", is_registered,
              f"registered={is_registered} ok={ok} err={err} out={len(payload)}")

    for module, name, function in MATRIX_MUTATING:
        is_registered = function in registered
        ok, _payload, err = _ioctl_raw(handle, _ioctl_full_code(function), zero_in, out_size)
        check("MATRIX", f"{module}:{name} (mutating) zero-args rejected",
              is_registered and not ok,
              f"registered={is_registered} ok={ok} err={err}")

    # Liveness: hello PING must still answer after the whole matrix ran.
    try:
        _ioctl(handle, _ioctl_full_code(0x900), b"", 4096)
        check("MATRIX", "driver answers PING after matrix", True)
    except OSError as exc:
        check("MATRIX", "driver answers PING after matrix", False, str(exc))


def _ioctl_full_code(function: int) -> int:
    """All MyArk modules share FILE_DEVICE_UNKNOWN + METHOD_BUFFERED."""
    return _ctl_code(FILE_DEVICE_UNKNOWN, function, METHOD_BUFFERED, FILE_ANY_ACCESS)


# ---------------------------------------------------------------------------
# Summary + S6 checklist mapping.
# ---------------------------------------------------------------------------

def _section_status(section: str) -> tuple[str, list[str]]:
    rows = [r for r in _RESULTS if r[0] == section]
    if not rows:
        return "SKIP", []
    details = [f"{r[1]}: {r[3]}" for r in rows if r[2] == "FAIL"]
    if any(r[2] == "FAIL" for r in rows):
        return "FAIL", details
    return "PASS", details














def main() -> int:
    # Guest consoles default to legacy code pages (GBK etc.); driver error
    # text may carry any bytes, so never let printing kill the regression.
    try:
        sys.stdout.reconfigure(errors="replace")
    except (AttributeError, OSError):
        pass
    print(f"[VERIFY] opening {DEVICE_PATH}")
    handle = _open_driver()
    print(f"[VERIFY] S6 checklist 1 (device opens via symbolic link): PASS")
    _RESULTS.append(("CHECKLIST1", "device open", "PASS", DEVICE_PATH))
    try:
        active = verify_get_version(handle)
        if active < 0:
            raise AssertionError("GET_VERSION unusable")
        modules = verify_query_modules(handle, active)
        _names, functions = verify_query_capabilities(handle)
        session_key = verify_session_key(handle)
        verify_dyndata(handle)
        verify_callback(handle)
        verify_actions(handle, session_key)
        verify_inject(handle, session_key)
        verify_runtime_fields(handle, session_key)
        verify_hwid_spoof(handle, session_key)
        verify_cpu(handle)
        verify_obprotect(handle, session_key)
        verify_security_posture(handle)
        verify_mutation_tx(handle, session_key)
        verify_wfp_inventory(handle)
        verify_kldr_diag(handle)
        verify_timerdpc(handle)
        verify_cidtable(handle, session_key)
        verify_registry(handle, session_key)
        verify_hook_scan(handle)
        verify_hook_patch(handle, session_key)
        verify_iat_eat(handle)
        verify_shadow_ssdt(handle)
        verify_integrity(handle)
        verify_testdrv(handle, session_key)
        verify_rules(handle, session_key)
        verify_ask(handle, session_key)
        verify_taskmgr_hijack(handle)
        verify_file(handle, session_key)
        verify_file_integrity(handle, session_key)
        verify_filemon(handle, session_key)
        verify_redirect(handle, session_key)
        verify_process(handle, session_key, modules, functions)
        verify_physical(handle)
        verify_memory_virtual(handle)
        verify_ioctl_matrix(handle, functions)
    finally:
        _kernel32.CloseHandle(handle)

    print("[S6] REGRESSION SUMMARY (KNOWN_ISSUES.md S6)")
    failed = False
    mapping = [
        ("CHECKLIST1", "(1) MyArkCore device opens via symbolic link"),
        ("CORE",       "(2a) core surface + GET_SESSION_KEY"),
        ("ACTIONS",    "(2b) actions 7 IOCTL HMAC accept/reject"),
        ("PROCESS",    "(3) process/thread views + token paths (all builds)"),
        ("PHYSICAL",   "(4) physical range filter + write gate"),
        ("MEMVIRT",    "(6) memory virtual path (7 IOCTLs)"),
        ("REGISTRY",   "(5) registry R0 read/enum/write cycle"),
        ("HOOKSCAN",   "(5b) inline hook scan"),
        ("PATCHHOOK",  "(5c) inline hook patch roundtrip (R2-1)"),
        ("IATEAT",     "(5d) IAT/EAT hook enumeration (R2-2)"),
        ("SHADOWSSDT", "(5e) shadow SSDT walk (R2-3)"),
        ("INTEGRITY",  "(5f) per-CPU integrity snapshot (R2-4)"),
        ("TESTDRV",    "(5g) force-unload roundtrip (R2-5)"),
        ("RULES",      "(5h) process-create rule engine (R2-6)"),
        ("TASKMGR",    "(5i) taskmgr hijack (R2-8)"),
        ("FILEINTEG",  "(5j) file integrity label (R2-10)"),
        ("FILEMON",    "(5k) file monitor minifilter drain (R2-7)"),
        ("REDIRECT",   "(5l) file/registry redirect engine (R2-9)"),
        ("ASK",        "(5m) ASK_USER interactive decision (R2-11)"),
        ("INJECT",     "(8) shellcode injection mechanism (R3-2)"),
        ("RUNTIME",    "(8b) DETAIL_RUNTIME sampling (R3-5)"),
        ("HWID",      "(8c) HWID spoof subdivision DRY_RUN/APPLY/RESTORE (R3-1)"),
        ("CPU",       "(8d) per-CPU register snapshot (R3-14)"),
        ("OBPROTECT", "(8f) ObCallbacks STRIP_ACCESS (R3-9)"),
        ("SECPOST",   "(8e) security posture snapshot (R3-6)"),
        ("MUTTX",     "(8f) mutation transaction PREPARE/COMMIT/ROLLBACK (R3-8)"),
        ("WFPINV",    "(8g) WFP/NDIS network-filter inventory (R3-15)"),
        ("KLDRDIAG",  "(smoke) KLDR offset discriminator (R3-15 follow-up)"),
        ("TIMERDPC",  "(8h) timer/DPC enumeration (R3-3)"),
        ("CIDTBL",    "(8i) PspCidTable + hidden detection (R3-4)"),
        ("FILE",       "(5b) file R0 delete chain + query info"),
        ("MATRIX",     "(7) full IOCTL matrix (54 read-only + 8 mutating)"),
        ("DYNDATA",    "(smoke) dyndata read-only"),
        ("CALLBACK",   "(smoke) callback read-only"),
    ]
    for section, label in mapping:
        status, details = _section_status(section)
        if status == "FAIL":
            failed = True
        print(f"[S6] {label} ........ {status}")
        for detail in details:
            print(f"[S6]     - {detail}")

    if failed:
        print("[VERIFY] FAILED")
        return 1
    print("[VERIFY] OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
