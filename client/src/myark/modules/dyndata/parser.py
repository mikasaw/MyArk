"""
dyndata R3 - parser / IOCTL helpers.

The dyndata module is R0-only: every query turns into one DeviceIoControl
call against \\.\\MyArkCore. The helpers below allocate a sufficiently
large variable-length buffer, hand it to the driver, and return the parsed
header + entries slice. Callers (cli / ui / tests) are expected to wrap
each call in ``ArkClient.open_or_null()`` so a missing driver surfaces as
the friendly "driver not installed" message rather than a hard fault.

Buffer sizing policy:
    Default per-query entries = 1024 (process / module), 2048 (thread /
    handle / file), 64 (object). All values are within the corresponding
    HARD_CAP in MyArkDyndataIoctl.h.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass, field
from typing import List, Optional

from myark.client.ark_client import ArkClient
from myark.client.ark_client import DriverError

from . import protocol as P


# ---------------------------------------------------------------------------
# Default buffer sizes per query type.
# ---------------------------------------------------------------------------

_DEFAULT_PROCESS_ENTRIES = 1024
_DEFAULT_THREAD_ENTRIES = 2048
_DEFAULT_MODULE_ENTRIES = 1024
_DEFAULT_HANDLE_ENTRIES = 2048
_DEFAULT_FILE_ENTRIES = 1024
_DEFAULT_SYSCALL_ENTRIES = 1024
_DEFAULT_OBJECT_ENTRIES = 64
_DEFAULT_TOKEN_ENTRIES = 1


# ---------------------------------------------------------------------------
# Helper result wrappers (dataclass; row data is in ctypes entries list).
# ---------------------------------------------------------------------------

@dataclass
class DynDataResult:
    """Common header fields emitted by every dyndata query."""
    count: int = 0
    total_seen: int = 0
    entry_struct_size: int = 0
    extra: dict = field(default_factory=dict)


def _alloc_buffer(header_size: int, entry_struct_size: int, entry_count: int) -> ctypes.Array:
    total = header_size + entry_count * entry_struct_size
    return (ctypes.c_ubyte * total)()


def _send_query(
    client: ArkClient,
    ioctl_code: int,
    in_buf: Optional[ctypes.Structure],
    out_buf: ctypes.Array,
) -> bytes:
    """Send one IOCTL and return the raw bytes the driver wrote.

    Raises ``DriverError`` when the kernel call fails; the caller decides
    how to surface that (CLI prints a stderr message, UI shows a status
    label, tests propagate the exception).
    """
    returned = client.ioctl(ioctl_code, in_buf, out_buf)
    if returned > len(out_buf):
        returned = len(out_buf)
    return bytes(out_buf[:returned])


def _parse_header(out_struct: ctypes.Structure) -> DynDataResult:
    return DynDataResult(
        count=out_struct.Count,
        total_seen=getattr(out_struct, "TotalSeen", 0),
        entry_struct_size=getattr(out_struct, "EntryStructSize", 0),
    )


# ---------------------------------------------------------------------------
# Public IOCTL helpers.
# ---------------------------------------------------------------------------

def query_process(
    client: ArkClient,
    *,
    max_entries: int = _DEFAULT_PROCESS_ENTRIES,
    pid_filter: int = 0,
) -> DynDataResult:
    in_buf = P.MYARK_DYNDATA_QUERY_PROCESS_INPUT()
    in_buf.MaxEntries = max_entries
    in_buf.PidFilter = pid_filter
    out_buf = _alloc_buffer(P.HEADER_SIZE_PROCESS,
                            ctypes.sizeof(P.MYARK_DYNDATA_PROCESS_ENTRY),
                            max_entries)
    raw = _send_query(client, P.IOCTL_MYARK_DYNDATA_QUERY_PROCESS, in_buf, out_buf)
    out = P.MYARK_DYNDATA_QUERY_PROCESS_OUTPUT.from_buffer_copy(raw)
    result = _parse_header(out)
    result.extra["PsActiveProcessHead"] = out.PsActiveProcessHead
    return result


def query_thread(
    client: ArkClient,
    *,
    max_entries: int = _DEFAULT_THREAD_ENTRIES,
    pid_filter: int = 0,
) -> DynDataResult:
    in_buf = P.MYARK_DYNDATA_QUERY_THREAD_INPUT()
    in_buf.MaxEntries = max_entries
    in_buf.PidFilter = pid_filter
    out_buf = _alloc_buffer(P.HEADER_SIZE_THREAD,
                            ctypes.sizeof(P.MYARK_DYNDATA_THREAD_ENTRY),
                            max_entries)
    raw = _send_query(client, P.IOCTL_MYARK_DYNDATA_QUERY_THREAD, in_buf, out_buf)
    out = P.MYARK_DYNDATA_QUERY_THREAD_OUTPUT.from_buffer_copy(raw)
    result = _parse_header(out)
    result.extra["PsActiveThreadHead"] = out.PsActiveThreadHead
    return result


def query_module(
    client: ArkClient,
    *,
    max_entries: int = _DEFAULT_MODULE_ENTRIES,
) -> DynDataResult:
    in_buf = P.MYARK_DYNDATA_QUERY_MODULE_INPUT()
    in_buf.MaxEntries = max_entries
    out_buf = _alloc_buffer(P.HEADER_SIZE_MODULE,
                            ctypes.sizeof(P.MYARK_DYNDATA_MODULE_ENTRY),
                            max_entries)
    raw = _send_query(client, P.IOCTL_MYARK_DYNDATA_QUERY_MODULE, in_buf, out_buf)
    out = P.MYARK_DYNDATA_QUERY_MODULE_OUTPUT.from_buffer_copy(raw)
    result = _parse_header(out)
    result.extra["PsLoadedModuleList"] = out.PsLoadedModuleList
    return result


def query_handle(
    client: ArkClient,
    *,
    max_entries: int = _DEFAULT_HANDLE_ENTRIES,
    pid_filter: int = 0,
    type_index_filter: int = 0xFFFFFFFF,
) -> DynDataResult:
    in_buf = P.MYARK_DYNDATA_QUERY_HANDLE_INPUT()
    in_buf.MaxEntries = max_entries
    in_buf.PidFilter = pid_filter
    in_buf.TypeIndexFilter = type_index_filter
    out_buf = _alloc_buffer(P.HEADER_SIZE_HANDLE,
                            ctypes.sizeof(P.MYARK_DYNDATA_HANDLE_ENTRY),
                            max_entries)
    raw = _send_query(client, P.IOCTL_MYARK_DYNDATA_QUERY_HANDLE, in_buf, out_buf)
    out = P.MYARK_DYNDATA_QUERY_HANDLE_OUTPUT.from_buffer_copy(raw)
    result = _parse_header(out)
    result.extra["PspCidTable"] = out.PspCidTable
    return result


def query_file(
    client: ArkClient,
    *,
    max_entries: int = _DEFAULT_FILE_ENTRIES,
    pid_filter: int = 0,
) -> DynDataResult:
    in_buf = P.MYARK_DYNDATA_QUERY_FILE_INPUT()
    in_buf.MaxEntries = max_entries
    in_buf.PidFilter = pid_filter
    out_buf = _alloc_buffer(P.HEADER_SIZE_FILE,
                            ctypes.sizeof(P.MYARK_DYNDATA_FILE_ENTRY),
                            max_entries)
    raw = _send_query(client, P.IOCTL_MYARK_DYNDATA_QUERY_FILE, in_buf, out_buf)
    out = P.MYARK_DYNDATA_QUERY_FILE_OUTPUT.from_buffer_copy(raw)
    result = _parse_header(out)
    result.extra["ObTypeIndexList"] = out.ObTypeIndexList
    return result


def query_syscall(
    client: ArkClient,
    *,
    max_entries: int = _DEFAULT_SYSCALL_ENTRIES,
    table_mask: int = 0,    # 0 = both NTOS and WIN32K
) -> DynDataResult:
    in_buf = P.MYARK_DYNDATA_QUERY_SYSCALL_INPUT()
    in_buf.MaxEntries = max_entries
    in_buf.TableMask = table_mask
    out_buf = _alloc_buffer(P.HEADER_SIZE_SYSCALL,
                            ctypes.sizeof(P.MYARK_DYNDATA_SYSCALL_ENTRY),
                            max_entries)
    raw = _send_query(client, P.IOCTL_MYARK_DYNDATA_QUERY_SYSCALL, in_buf, out_buf)
    out = P.MYARK_DYNDATA_QUERY_SYSCALL_OUTPUT.from_buffer_copy(raw)
    result = _parse_header(out)
    result.extra["KeServiceDescriptorTable"] = out.KeServiceDescriptorTable
    result.extra["W32pServiceTable"] = out.W32pServiceTable
    result.extra["NtoskrnlTextBase"] = out.NtoskrnlTextBase
    result.extra["NtoskrnlTextEnd"] = out.NtoskrnlTextEnd
    return result


def query_token(
    client: ArkClient,
    pid: int,
) -> DynDataResult:
    in_buf = P.MYARK_DYNDATA_QUERY_TOKEN_INPUT()
    in_buf.Pid = pid
    out_buf = _alloc_buffer(P.HEADER_SIZE_TOKEN,
                            ctypes.sizeof(P.MYARK_DYNDATA_TOKEN_ENTRY),
                            _DEFAULT_TOKEN_ENTRIES)
    raw = _send_query(client, P.IOCTL_MYARK_DYNDATA_QUERY_TOKEN, in_buf, out_buf)
    out = P.MYARK_DYNDATA_QUERY_TOKEN_OUTPUT.from_buffer_copy(raw)
    result = _parse_header(out)
    return result


def query_object(
    client: ArkClient,
    *,
    max_entries: int = _DEFAULT_OBJECT_ENTRIES,
) -> DynDataResult:
    in_buf = P.MYARK_DYNDATA_QUERY_OBJECT_INPUT()
    in_buf.MaxEntries = max_entries
    out_buf = _alloc_buffer(P.HEADER_SIZE_OBJECT,
                            ctypes.sizeof(P.MYARK_DYNDATA_OBJECT_ENTRY),
                            max_entries)
    raw = _send_query(client, P.IOCTL_MYARK_DYNDATA_QUERY_OBJECT, in_buf, out_buf)
    out = P.MYARK_DYNDATA_QUERY_OBJECT_OUTPUT.from_buffer_copy(raw)
    result = _parse_header(out)
    result.extra["ObTypeObjectType"] = out.ObTypeObjectType
    return result


def query_ssdt(
    client: ArkClient,
    *,
    max_entries: int = _DEFAULT_SYSCALL_ENTRIES,
) -> DynDataResult:
    in_buf = P.MYARK_DYNDATA_QUERY_SSDT_INPUT()
    in_buf.MaxEntries = max_entries
    out_buf = _alloc_buffer(P.HEADER_SIZE_SSDT,
                            ctypes.sizeof(P.MYARK_DYNDATA_SSDT_ENTRY),
                            max_entries)
    raw = _send_query(client, P.IOCTL_MYARK_DYNDATA_QUERY_SSDT, in_buf, out_buf)
    out = P.MYARK_DYNDATA_QUERY_SSDT_OUTPUT.from_buffer_copy(raw)
    result = _parse_header(out)
    result.extra["KeServiceDescriptorTableShadow"] = out.KeServiceDescriptorTableShadow
    result.extra["W32pServiceTable"] = out.W32pServiceTable
    result.extra["Win32kTextBase"] = out.Win32kTextBase
    result.extra["Win32kTextEnd"] = out.Win32kTextEnd
    return result


# ---------------------------------------------------------------------------
# Driver-installed convenience: open the driver if present and run a query.
# ---------------------------------------------------------------------------

def try_query(query_fn, *args, **kwargs):
    """Open the driver on demand, run ``query_fn``, close it.

    Returns ``None`` when the driver is not installed so callers can
    render the empty / "driver not installed" branch.
    """
    client: Optional[ArkClient] = ArkClient.open_or_null()
    if client is None:
        return None
    try:
        return query_fn(client, *args, **kwargs)
    except DriverError:
        return None
    finally:
        try:
            client.close()
        except Exception:
            pass


__all__ = [
    "DynDataResult",
    "query_process",
    "query_thread",
    "query_module",
    "query_handle",
    "query_file",
    "query_syscall",
    "query_token",
    "query_object",
    "query_ssdt",
    "try_query",
]
