"""
actions R3 - parser / IOCTL helpers + R3 fallback.

The actions module is the Stage-5 "mixed" module: 7 destructive IOCTLs
that the driver only honours with a valid safety token (see
``actions_internal.c``). The default code path is:

  1. Try ``ArkClient.ioctl`` against the loaded driver -- R0 validates
     the token, runs the action (or returns DEFERRED in Mode A), and
     reports back via the per-action *_OUTPUT struct.
  2. When the driver is missing AND the action is in
     :data:`P.ACTIONS_R0_FALLBACK_AVAILABLE`, fall back to a host-only
     R3 implementation that calls the Win32 API (TerminateProcess,
     TerminateThread, CreateRemoteThread, ReadProcessMemory, ...).
  3. For the R0-only actions (set_token, hide_process, protect_process)
     there is no R3 fallback -- :class:`R3FallbackUnavailable` is raised
     so the CLI can surface a friendly error rather than a stack trace.

The 7 public helpers are: ``kill_process``, ``terminate_thread``,
``inject_dll``, ``dump_memory``, ``set_token``, ``hide_process``,
``protect_process``. They all share the same shape:

    fn(client_or_none, *, pid, ...) -> ActionResult
"""

from __future__ import annotations

import ctypes
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

from myark.client.ark_client import ArkClient, DriverError
from myark.client.safety_token import compute_signature, fetch_session_key, nt_filetime_now

from . import protocol as P


# ---------------------------------------------------------------------------
# Errors + result containers.
# ---------------------------------------------------------------------------

class ActionsError(RuntimeError):
    """Base class for any actions module failure."""


class SafetyTokenRequired(ActionsError):
    """Raised when the caller did not supply a :class:`SafetyToken`."""


class R3FallbackUnavailable(ActionsError):
    """Raised when the driver is missing AND the action has no R3 path."""

    def __init__(self, action_name: str) -> None:
        super().__init__(
            f"action {action_name!r} is R0-only; My ArkCore driver must be installed"
        )
        self.action_name = action_name


@dataclass
class SafetyToken:
    """Caller-side mirror of the R0 ``MYARK_SAFETY_TOKEN`` struct.

    The hardened kernel validator checks ``Signature`` as HMAC-SHA256 of
    (Magic, Pid, Operation, Timestamp) keyed with the per-boot session key
    fetched from ``IOCTL_MYARK_CORE_GET_SESSION_KEY`` -- pass it via
    ``session_key`` (see :func:`_session_key_for`). Timestamps use the
    kernel's FILETIME scale (100-ns since 1601) so the +/-120 s freshness
    window lines up with ``KeQuerySystemTime``.

    When neither ``signature`` nor ``session_key`` is supplied, ``build()``
    emits the legacy deterministic placeholder: only useful for offline
    unit tests, always rejected by the hardened driver.
    """

    magic: int = P.MYARK_SAFETY_TOKEN_MAGIC
    pid: int = 0
    operation: int = 0
    timestamp: int = 0
    signature: bytes = b""
    session_key: bytes = b""

    def __post_init__(self) -> None:
        if self.timestamp == 0:
            self.timestamp = nt_filetime_now()

    def build(self, session_key: bytes = b"") -> P.MYARK_SAFETY_TOKEN:
        """Materialise a ctypes token ready to embed in an action input.

        With ``session_key`` the Signature is a real HMAC-SHA256 over the
        token fields (what the hardened kernel validator demands). Without
        it the legacy deterministic placeholder is emitted -- only useful
        for offline unit tests, always rejected by the hardened driver.
        """
        token = P.MYARK_SAFETY_TOKEN()
        token.Magic = self.magic
        token.Pid = self.pid
        token.Operation = self.operation
        token.Timestamp = self.timestamp
        sig = self.signature
        if not sig:
            if session_key:
                sig = compute_signature(
                    session_key,
                    self.pid,
                    self.operation,
                    self.timestamp,
                    magic=self.magic,
                )
            else:
                sig = self._default_signature()
        for i in range(P.MYARK_SAFETY_TOKEN_SIGNATURE_SIZE):
            token.Signature[i] = sig[i % len(sig)]
        return token

    def _default_signature(self) -> bytes:
        # Deterministic 32-byte payload derived from (pid, op, timestamp).
        seed = f"{self.pid}:{self.operation}:{self.timestamp}".encode("utf-8")
        sig = bytearray(P.MYARK_SAFETY_TOKEN_SIGNATURE_SIZE)
        for i, b in enumerate(seed):
            sig[i % P.MYARK_SAFETY_TOKEN_SIGNATURE_SIZE] ^= b
        # Avoid all-zero: stamp byte 0 with a non-zero sentinel.
        sig[0] |= 0x01
        return bytes(sig)


@dataclass
class ActionResult:
    """Common shape returned by every action helper.

    ``result_code`` and ``executed_tier`` mirror the kernel
    ``MYARK_ACTION_OUTPUT`` fields. ``source`` distinguishes the R0
    path (``"r0"``) from the host R3 fallback (``"r3-fallback"``) so
    callers can render the source in CLI / UI logs.
    """

    action: str = ""
    pid: int = 0
    result_code: int = P.MYARK_ACTION_RESULT_R3_FALLBACK
    result_name: str = ""
    executed_tier: int = P.MYARK_ACTION_TIER_R3
    tier_name: str = ""
    audit_message: str = ""
    source: str = "r3-fallback"
    error: str = ""

    def __post_init__(self) -> None:
        # Auto-resolve human-readable names from the numeric codes.
        if not self.result_name:
            self.result_name = P.ACTIONS_RESULT_NAMES.get(
                self.result_code, f"unknown(0x{self.result_code:X})"
            )
        if not self.tier_name:
            self.tier_name = P.ACTIONS_TIER_NAMES.get(
                self.executed_tier, f"unknown(0x{self.executed_tier:X})"
            )


# ---------------------------------------------------------------------------
# Low-level IOCTL helpers.
# ---------------------------------------------------------------------------

def _send_ioctl(
    client: ArkClient,
    ioctl_code: int,
    in_struct: ctypes.Structure,
    out_struct_type: type,
) -> object:
    """Round-trip one action IOCTL via the supplied (already-opened) client."""
    out_size = ctypes.sizeof(out_struct_type)
    out_buf = (ctypes.c_ubyte * out_size)()
    in_bytes = bytes(in_struct)
    returned = client.ioctl(ioctl_code, in_bytes, out_buf)
    if returned < out_size:
        raise DriverError(f"ioctl 0x{ioctl_code:X}: short read returned={returned} < {out_size}")
    return out_struct_type.from_buffer_copy(bytes(out_buf[:out_size]))


def _session_key_for(client: Optional[ArkClient]) -> bytes:
    """Per-boot session key for HMAC signing; ``b""`` when unavailable.

    Offline paths (no driver / non-elevated caller / older build) return
    ``b""`` so the deterministic placeholder gets embedded; the kernel
    validator rejects it, which is the correct fail-closed behaviour.
    """
    if client is None:
        return b""
    try:
        return fetch_session_key(client)
    except (DriverError, OSError):
        return b""


def _make_token(action_name: str, pid: int, token: Optional[SafetyToken]) -> SafetyToken:
    """Resolve the safety token -- ``None`` => :class:`SafetyTokenRequired`."""
    op = P.ACTIONS_NAME_TO_OP.get(action_name)
    if op is None:
        raise ActionsError(f"unknown action name: {action_name!r}")
    if token is None:
        raise SafetyTokenRequired(
            f"action {action_name!r}: safety token required "
            "(construct SafetyToken(pid=PID, operation=OP) and pass token=...)"
        )
    # Stamp the token with the right pid/op so the driver side matches
    # even if the caller forgot to set them.
    if token.pid == 0:
        token.pid = pid
    if token.operation == 0:
        token.operation = op
    if token.pid != pid:
        raise ActionsError(
            f"action {action_name!r}: token.pid={token.pid} does not match pid={pid}"
        )
    if token.operation != op:
        raise ActionsError(
            f"action {action_name!r}: token.operation={token.operation} "
            f"does not match {op}"
        )
    return token


def _populate_header(result: ActionResult, header: P.MYARK_ACTION_OUTPUT) -> None:
    """Pull the per-action header back into the dataclass."""
    result.result_code = header.ResultCode
    result.executed_tier = header.ExecutedTier
    result.result_name = P.ACTIONS_RESULT_NAMES.get(header.ResultCode, "unknown")
    result.tier_name = P.ACTIONS_TIER_NAMES.get(header.ExecutedTier, "unknown")
    raw = bytes(header.AuditMessage)
    nul = raw.find(b"\x00")
    result.audit_message = raw[: nul if nul >= 0 else len(raw)].decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# R0 dispatch helper. Tries the driver first; if the driver is missing
# AND the action has an R3 fallback, runs the host-only implementation.
# ---------------------------------------------------------------------------

def _execute(
    action_name: str,
    client: Optional[ArkClient],
    in_struct: ctypes.Structure,
    out_struct_type: type,
    ioctl_code: int,
    *,
    r3_fallback,
    pid: int,
    token: Optional[SafetyToken],
) -> ActionResult:
    """Shared core: try R0 then fall back to the supplied R3 callable."""
    _make_token(action_name, pid, token)
    result = ActionResult(action=action_name, pid=pid)

    if client is not None:
        try:
            out = _send_ioctl(client, ioctl_code, in_struct, out_struct_type)
            _populate_header(result, out.Header)
            result.source = "r0"
            return result
        except (DriverError, OSError) as exc:
            # Driver call failed: degrade to R3 if the action has a fallback.
            result.error = str(exc)

    if action_name not in P.ACTIONS_R0_FALLBACK_AVAILABLE:
        raise R3FallbackUnavailable(action_name)

    # R3 fallback path.
    fb = r3_fallback()
    if isinstance(fb, ActionResult):
        fb.action = action_name
        fb.pid = pid
        return fb
    # Backward-compat: the fallback returns a raw value; wrap as success.
    result.result_code = P.MYARK_ACTION_RESULT_R3_FALLBACK
    result.executed_tier = P.MYARK_ACTION_TIER_R3
    result.source = "r3-fallback"
    result.audit_message = str(fb)
    return result


# ---------------------------------------------------------------------------
# R3 fallbacks. The Win32 calls live here so the parser module stays
# the only place that imports kernel32 / ntdll.
# ---------------------------------------------------------------------------

def _r3_kill_process(pid: int, exit_code: int, reason: str) -> ActionResult:
    """Win32 TerminateProcess fallback (PROCESS_TERMINATE = 0x0001)."""
    if sys.platform != "win32":
        return ActionResult(
            action="kill_process",
            pid=pid,
            audit_message="r3-fallback not available on non-win32",
            error="non-win32 platform",
        )
    import ctypes.wintypes as w
    kernel32 = ctypes.windll.kernel32
    kernel32.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    kernel32.OpenProcess.restype = w.HANDLE
    kernel32.TerminateProcess.argtypes = [w.HANDLE, w.UINT]
    kernel32.TerminateProcess.restype = w.BOOL
    kernel32.CloseHandle.argtypes = [w.HANDLE]
    kernel32.CloseHandle.restype = w.BOOL
    kernel32.GetLastError.argtypes = []
    kernel32.GetLastError.restype = w.DWORD

    handle = kernel32.OpenProcess(0x0001, False, pid)
    if not handle:
        err = kernel32.GetLastError()
        return ActionResult(
            action="kill_process",
            pid=pid,
            audit_message=f"r3: OpenProcess failed err={err}",
            error=f"err={err}",
        )
    try:
        ok = kernel32.TerminateProcess(handle, exit_code)
        if not ok:
            err = kernel32.GetLastError()
            return ActionResult(
                action="kill_process",
                pid=pid,
                audit_message=f"r3: TerminateProcess failed err={err}",
                error=f"err={err}",
            )
        return ActionResult(
            action="kill_process",
            pid=pid,
            audit_message=f"r3: terminated pid={pid} reason={reason!r}",
        )
    finally:
        kernel32.CloseHandle(handle)


def _r3_terminate_thread(pid: int, tid: int, exit_code: int) -> ActionResult:
    """Win32 TerminateThread fallback (THREAD_TERMINATE = 0x0001)."""
    if sys.platform != "win32":
        return ActionResult(
            action="terminate_thread",
            pid=pid,
            audit_message="r3-fallback not available on non-win32",
            error="non-win32 platform",
        )
    import ctypes.wintypes as w
    kernel32 = ctypes.windll.kernel32
    kernel32.OpenThread.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    kernel32.OpenThread.restype = w.HANDLE
    kernel32.TerminateThread.argtypes = [w.HANDLE, w.DWORD]
    kernel32.TerminateThread.restype = w.BOOL
    kernel32.CloseHandle.argtypes = [w.HANDLE]
    kernel32.CloseHandle.restype = w.BOOL
    kernel32.GetLastError.argtypes = []
    kernel32.GetLastError.restype = w.DWORD

    handle = kernel32.OpenThread(0x0001, False, tid)
    if not handle:
        err = kernel32.GetLastError()
        return ActionResult(
            action="terminate_thread",
            pid=pid,
            audit_message=f"r3: OpenThread(tid={tid}) failed err={err}",
            error=f"err={err}",
        )
    try:
        ok = kernel32.TerminateThread(handle, exit_code)
        if not ok:
            err = kernel32.GetLastError()
            return ActionResult(
                action="terminate_thread",
                pid=pid,
                audit_message=f"r3: TerminateThread failed err={err}",
                error=f"err={err}",
            )
        return ActionResult(
            action="terminate_thread",
            pid=pid,
            audit_message=f"r3: terminated thread pid={pid} tid={tid}",
        )
    finally:
        kernel32.CloseHandle(handle)


def _r3_inject_dll(pid: int, dll_path: str) -> ActionResult:
    """Win32 CreateRemoteThread fallback -- requires PROCESS_ALL_ACCESS."""
    if sys.platform != "win32":
        return ActionResult(
            action="inject_dll",
            pid=pid,
            audit_message="r3-fallback not available on non-win32",
            error="non-win32 platform",
        )
    import ctypes.wintypes as w
    kernel32 = ctypes.windll.kernel32
    PROCESS_ALL_ACCESS = 0x001F0FFF
    MEM_COMMIT = MEM_RESERVE = 0x1000 | 0x2000
    PAGE_READWRITE = 0x04
    kernel32.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    kernel32.OpenProcess.restype = w.HANDLE
    kernel32.VirtualAllocEx.argtypes = [w.HANDLE, w.LPVOID, ctypes.c_size_t, w.DWORD, w.DWORD]
    kernel32.VirtualAllocEx.restype = w.LPVOID
    kernel32.WriteProcessMemory.argtypes = [w.HANDLE, w.LPVOID, w.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    kernel32.WriteProcessMemory.restype = w.BOOL
    kernel32.GetModuleHandleW.argtypes = [w.LPCWSTR]
    kernel32.GetModuleHandleW.restype = w.HANDLE
    kernel32.GetProcAddress.argtypes = [w.HANDLE, w.LPCSTR]
    kernel32.GetProcAddress.restype = w.LPVOID
    kernel32.CreateRemoteThread.argtypes = [w.HANDLE, w.LPVOID, ctypes.c_size_t, w.LPVOID, w.LPVOID, w.DWORD, w.LPDWORD]
    kernel32.CreateRemoteThread.restype = w.HANDLE
    kernel32.CloseHandle.argtypes = [w.HANDLE]
    kernel32.CloseHandle.restype = w.BOOL
    kernel32.GetLastError.argtypes = []
    kernel32.GetLastError.restype = w.DWORD

    proc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not proc:
        err = kernel32.GetLastError()
        return ActionResult(
            action="inject_dll",
            pid=pid,
            audit_message=f"r3: OpenProcess(PROCESS_ALL_ACCESS) failed err={err}",
            error=f"err={err}",
        )
    try:
        path_bytes = (dll_path + "\x00").encode("utf-16-le")
        remote_mem = kernel32.VirtualAllocEx(proc, None, len(path_bytes), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not remote_mem:
            err = kernel32.GetLastError()
            return ActionResult(
                action="inject_dll",
                pid=pid,
                audit_message=f"r3: VirtualAllocEx failed err={err}",
                error=f"err={err}",
            )
        written = ctypes.c_size_t(0)
        ok = kernel32.WriteProcessMemory(proc, remote_mem, path_bytes, len(path_bytes), ctypes.byref(written))
        if not ok:
            err = kernel32.GetLastError()
            return ActionResult(
                action="inject_dll",
                pid=pid,
                audit_message=f"r3: WriteProcessMemory failed err={err}",
                error=f"err={err}",
            )
        h_kernel32 = kernel32.GetModuleHandleW("kernel32.dll")
        loadlib = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryW")
        if not loadlib:
            err = kernel32.GetLastError()
            return ActionResult(
                action="inject_dll",
                pid=pid,
                audit_message=f"r3: GetProcAddress(LoadLibraryW) failed err={err}",
                error=f"err={err}",
            )
        h_thread = kernel32.CreateRemoteThread(proc, None, 0, loadlib, remote_mem, 0, None)
        if not h_thread:
            err = kernel32.GetLastError()
            return ActionResult(
                action="inject_dll",
                pid=pid,
                audit_message=f"r3: CreateRemoteThread failed err={err}",
                error=f"err={err}",
            )
        kernel32.CloseHandle(h_thread)
        return ActionResult(
            action="inject_dll",
            pid=pid,
            audit_message=f"r3: injected {dll_path!r} into pid={pid}",
        )
    finally:
        kernel32.CloseHandle(proc)


def _r3_dump_memory(pid: int, address: int, size: int) -> ActionResult:
    """Win32 ReadProcessMemory fallback (PROCESS_VM_READ = 0x0010)."""
    if sys.platform != "win32":
        return ActionResult(
            action="dump_memory",
            pid=pid,
            audit_message="r3-fallback not available on non-win32",
            error="non-win32 platform",
        )
    if size <= 0 or size > P.MYARK_ACTION_DUMP_MAX_BYTES:
        size = min(max(size, 0), P.MYARK_ACTION_DUMP_MAX_BYTES)

    import ctypes.wintypes as w
    kernel32 = ctypes.windll.kernel32
    kernel32.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    kernel32.OpenProcess.restype = w.HANDLE
    kernel32.ReadProcessMemory.argtypes = [w.HANDLE, w.LPCVOID, w.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    kernel32.ReadProcessMemory.restype = w.BOOL
    kernel32.CloseHandle.argtypes = [w.HANDLE]
    kernel32.CloseHandle.restype = w.BOOL
    kernel32.GetLastError.argtypes = []
    kernel32.GetLastError.restype = w.DWORD

    proc = kernel32.OpenProcess(0x0010, False, pid)
    if not proc:
        err = kernel32.GetLastError()
        return ActionResult(
            action="dump_memory",
            pid=pid,
            audit_message=f"r3: OpenProcess(PROCESS_VM_READ) failed err={err}",
            error=f"err={err}",
        )
    try:
        buf = (ctypes.c_ubyte * size)()
        got = ctypes.c_size_t(0)
        ok = kernel32.ReadProcessMemory(proc, address, buf, size, ctypes.byref(got))
        if not ok:
            err = kernel32.GetLastError()
            return ActionResult(
                action="dump_memory",
                pid=pid,
                audit_message=f"r3: ReadProcessMemory failed err={err}",
                error=f"err={err}",
            )
        return ActionResult(
            action="dump_memory",
            pid=pid,
            audit_message=f"r3: dumped {got.value} bytes from pid={pid} @ 0x{address:X}",
        )
    finally:
        kernel32.CloseHandle(proc)


# ---------------------------------------------------------------------------
# Public action helpers (the seven ``myark-cli actions <verb> ...``).
# ---------------------------------------------------------------------------

def kill_process(
    client: Optional[ArkClient],
    *,
    pid: int,
    exit_code: int = 1,
    reason: str = "",
    token: Optional[SafetyToken] = None,
) -> ActionResult:
    in_buf = P.MYARK_ACTION_KILL_INPUT()
    if token is not None:
        in_buf.Token = token.build(_session_key_for(client))
    in_buf.Pid = pid
    in_buf.ExitCode = exit_code
    in_buf.Reason = reason

    def _fb() -> ActionResult:
        return _r3_kill_process(pid, exit_code, reason)

    return _execute(
        "kill_process", client, in_buf,
        P.MYARK_ACTION_KILL_OUTPUT,
        P.IOCTL_MYARK_ACTION_KILL_PROCESS,
        r3_fallback=_fb,
        pid=pid, token=token,
    )


def terminate_thread(
    client: Optional[ArkClient],
    *,
    pid: int,
    tid: int,
    exit_code: int = 1,
    token: Optional[SafetyToken] = None,
) -> ActionResult:
    in_buf = P.MYARK_ACTION_TERMINATE_THREAD_INPUT()
    if token is not None:
        in_buf.Token = token.build(_session_key_for(client))
    in_buf.Pid = pid
    in_buf.Tid = tid
    in_buf.ExitCode = exit_code

    def _fb() -> ActionResult:
        return _r3_terminate_thread(pid, tid, exit_code)

    return _execute(
        "terminate_thread", client, in_buf,
        P.MYARK_ACTION_TERMINATE_THREAD_OUTPUT,
        P.IOCTL_MYARK_ACTION_TERMINATE_THREAD,
        r3_fallback=_fb,
        pid=pid, token=token,
    )


def inject_dll(
    client: Optional[ArkClient],
    *,
    pid: int,
    dll_path: str,
    token: Optional[SafetyToken] = None,
) -> ActionResult:
    in_buf = P.MYARK_ACTION_INJECT_DLL_INPUT()
    if token is not None:
        in_buf.Token = token.build(_session_key_for(client))
    in_buf.Pid = pid
    in_buf.DllPath = dll_path

    def _fb() -> ActionResult:
        return _r3_inject_dll(pid, dll_path)

    return _execute(
        "inject_dll", client, in_buf,
        P.MYARK_ACTION_INJECT_DLL_OUTPUT,
        P.IOCTL_MYARK_ACTION_INJECT_DLL,
        r3_fallback=_fb,
        pid=pid, token=token,
    )


def dump_memory(
    client: Optional[ArkClient],
    *,
    pid: int,
    address: int,
    size: int = 4096,
    token: Optional[SafetyToken] = None,
) -> ActionResult:
    in_buf = P.MYARK_ACTION_DUMP_MEMORY_INPUT()
    if token is not None:
        in_buf.Token = token.build(_session_key_for(client))
    in_buf.Pid = pid
    in_buf.Address = address
    in_buf.Size = size

    def _fb() -> ActionResult:
        return _r3_dump_memory(pid, address, size)

    return _execute(
        "dump_memory", client, in_buf,
        P.MYARK_ACTION_DUMP_MEMORY_OUTPUT,
        P.IOCTL_MYARK_ACTION_DUMP_MEMORY,
        r3_fallback=_fb,
        pid=pid, token=token,
    )


def set_token(
    client: Optional[ArkClient],
    *,
    pid: int,
    token_type: int = P.MYARK_ACTION_TOKEN_TYPE_PRIMARY,
    token: Optional[SafetyToken] = None,
) -> ActionResult:
    in_buf = P.MYARK_ACTION_SET_TOKEN_INPUT()
    if token is not None:
        in_buf.Token = token.build(_session_key_for(client))
    in_buf.Pid = pid
    in_buf.TokenType = token_type

    def _fb() -> ActionResult:
        raise R3FallbackUnavailable("set_token")

    return _execute(
        "set_token", client, in_buf,
        P.MYARK_ACTION_SET_TOKEN_OUTPUT,
        P.IOCTL_MYARK_ACTION_SET_TOKEN,
        r3_fallback=_fb,
        pid=pid, token=token,
    )


def hide_process(
    client: Optional[ArkClient],
    *,
    pid: int,
    token: Optional[SafetyToken] = None,
) -> ActionResult:
    in_buf = P.MYARK_ACTION_HIDE_PROCESS_INPUT()
    if token is not None:
        in_buf.Token = token.build(_session_key_for(client))
    in_buf.Pid = pid

    def _fb() -> ActionResult:
        raise R3FallbackUnavailable("hide_process")

    return _execute(
        "hide_process", client, in_buf,
        P.MYARK_ACTION_HIDE_PROCESS_OUTPUT,
        P.IOCTL_MYARK_ACTION_HIDE_PROCESS,
        r3_fallback=_fb,
        pid=pid, token=token,
    )


def protect_process(
    client: Optional[ArkClient],
    *,
    pid: int,
    flags: int = P.MYARK_ACTION_PROTECT_FLAG_SIGNED,
    token: Optional[SafetyToken] = None,
) -> ActionResult:
    in_buf = P.MYARK_ACTION_PROTECT_PROCESS_INPUT()
    if token is not None:
        in_buf.Token = token.build(_session_key_for(client))
    in_buf.Pid = pid
    in_buf.Flags = flags

    def _fb() -> ActionResult:
        raise R3FallbackUnavailable("protect_process")

    return _execute(
        "protect_process", client, in_buf,
        P.MYARK_ACTION_PROTECT_PROCESS_OUTPUT,
        P.IOCTL_MYARK_ACTION_PROTECT_PROCESS,
        r3_fallback=_fb,
        pid=pid, token=token,
    )


# ---------------------------------------------------------------------------
# Convenience: open the driver on demand.
# ---------------------------------------------------------------------------

def try_action(action_fn, *args, **kwargs) -> Optional[ActionResult]:
    """Open the driver on demand, run ``action_fn``, close it.

    Returns ``None`` when the driver is not installed so callers can
    render the empty / "driver not installed" branch.
    """
    client = ArkClient.open_or_null()
    if client is None:
        return None
    try:
        return action_fn(client, *args, **kwargs)
    finally:
        try:
            client.close()
        except Exception:
            pass


__all__ = [
    "ActionsError",
    "SafetyTokenRequired",
    "R3FallbackUnavailable",
    "SafetyToken",
    "ActionResult",
    "kill_process",
    "terminate_thread",
    "inject_dll",
    "dump_memory",
    "set_token",
    "hide_process",
    "protect_process",
    "try_action",
]