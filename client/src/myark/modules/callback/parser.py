"""
callback R3 - parser / IOCTL helpers.

The callback module is R0-only: every query turns into one DeviceIoControl
call against ``\\\\.\\MyArkCore``. The helpers below allocate a sufficiently
large variable-length buffer, hand it to the driver, and return the parsed
header + entries slice. Callers (cli / ui / tests) are expected to wrap
each call in ``ArkClient.open_or_null()`` so a missing driver surfaces as
the friendly "driver not installed" message rather than a hard fault.

Buffer sizing policy:
    Default per-query entries = 64 (matches every HARD_CAP in
    MyArkCallbackIoctl.h). STATS uses a fixed-size output (no entries).
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass, field
from typing import Optional

from myark.client.ark_client import ArkClient
from myark.client.ark_client import DriverError

from . import protocol as P


# ---------------------------------------------------------------------------
# Default buffer sizes per query type.
# ---------------------------------------------------------------------------

_DEFAULT_PS_ENTRIES = 64
_DEFAULT_CM_ENTRIES = 64
_DEFAULT_OB_ENTRIES = 64
_DEFAULT_IMAGE_ENTRIES = 64
_DEFAULT_DBG_ENTRIES = 32
_DEFAULT_ENUM_ENTRIES = 256
_DEFAULT_BACKUP_ENTRIES = 64


# ---------------------------------------------------------------------------
# Helper result wrappers (dataclass; row data is in ctypes entries list).
# ---------------------------------------------------------------------------

@dataclass
class CallbackResult:
    """Common header fields emitted by every callback query."""
    count: int = 0
    total_seen: int = 0
    entry_struct_size: int = 0
    extra: dict = field(default_factory=dict)


@dataclass
class CallbackStats:
    """Per-category totals returned by IOCTL_MYARK_CALLBACK_STATS."""
    ps_count: int = 0
    cm_count: int = 0
    ob_count: int = 0
    image_count: int = 0
    dbg_count: int = 0
    total_count: int = 0


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


def _parse_header(out_struct: ctypes.Structure) -> CallbackResult:
    return CallbackResult(
        count=out_struct.Count,
        total_seen=getattr(out_struct, "TotalSeen", 0),
        entry_struct_size=getattr(out_struct, "EntryStructSize", 0),
    )


# ---------------------------------------------------------------------------
# Public IOCTL helpers.
# ---------------------------------------------------------------------------

def query_ps(
    client: ArkClient,
    *,
    max_entries: int = _DEFAULT_PS_ENTRIES,
    subtype_mask: int = 0,
) -> CallbackResult:
    in_buf = P.MYARK_CALLBACK_QUERY_PS_INPUT()
    in_buf.MaxEntries = max_entries
    in_buf.SubTypeMask = subtype_mask
    out_buf = _alloc_buffer(P.HEADER_SIZE_PS,
                            ctypes.sizeof(P.MYARK_CALLBACK_PS_ENTRY),
                            max_entries)
    raw = _send_query(client, P.IOCTL_MYARK_CALLBACK_QUERY_PS, in_buf, out_buf)
    out = P.MYARK_CALLBACK_QUERY_PS_OUTPUT.from_buffer_copy(raw)
    result = _parse_header(out)
    result.extra["PspCreateProcessNotifyRoutine"] = out.PspCreateProcessNotifyRoutine
    result.extra["PspCreateThreadNotifyRoutine"] = out.PspCreateThreadNotifyRoutine
    result.extra["PspLoadImageNotifyRoutine"] = out.PspLoadImageNotifyRoutine
    return result


def query_cm(
    client: ArkClient,
    *,
    max_entries: int = _DEFAULT_CM_ENTRIES,
) -> CallbackResult:
    in_buf = P.MYARK_CALLBACK_QUERY_CM_INPUT()
    in_buf.MaxEntries = max_entries
    out_buf = _alloc_buffer(P.HEADER_SIZE_CM,
                            ctypes.sizeof(P.MYARK_CALLBACK_CM_ENTRY),
                            max_entries)
    raw = _send_query(client, P.IOCTL_MYARK_CALLBACK_QUERY_CM, in_buf, out_buf)
    out = P.MYARK_CALLBACK_QUERY_CM_OUTPUT.from_buffer_copy(raw)
    result = _parse_header(out)
    result.extra["CmpCallbackListHead"] = out.CmpCallbackListHead
    return result


def query_ob(
    client: ArkClient,
    *,
    max_entries: int = _DEFAULT_OB_ENTRIES,
    operation_mask: int = 0,
) -> CallbackResult:
    in_buf = P.MYARK_CALLBACK_QUERY_OB_INPUT()
    in_buf.MaxEntries = max_entries
    in_buf.OperationMask = operation_mask
    out_buf = _alloc_buffer(P.HEADER_SIZE_OB,
                            ctypes.sizeof(P.MYARK_CALLBACK_OB_ENTRY),
                            max_entries)
    raw = _send_query(client, P.IOCTL_MYARK_CALLBACK_QUERY_OB, in_buf, out_buf)
    out = P.MYARK_CALLBACK_QUERY_OB_OUTPUT.from_buffer_copy(raw)
    result = _parse_header(out)
    result.extra["ObCallbackListHead"] = out.ObCallbackListHead
    return result


def query_image(
    client: ArkClient,
    *,
    max_entries: int = _DEFAULT_IMAGE_ENTRIES,
) -> CallbackResult:
    in_buf = P.MYARK_CALLBACK_QUERY_IMAGE_INPUT()
    in_buf.MaxEntries = max_entries
    out_buf = _alloc_buffer(P.HEADER_SIZE_IMAGE,
                            ctypes.sizeof(P.MYARK_CALLBACK_IMAGE_ENTRY),
                            max_entries)
    raw = _send_query(client, P.IOCTL_MYARK_CALLBACK_QUERY_IMAGE, in_buf, out_buf)
    out = P.MYARK_CALLBACK_QUERY_IMAGE_OUTPUT.from_buffer_copy(raw)
    result = _parse_header(out)
    result.extra["PspLoadImageNotifyRoutine"] = out.PspLoadImageNotifyRoutine
    return result


def query_dbg(
    client: ArkClient,
    *,
    max_entries: int = _DEFAULT_DBG_ENTRIES,
    subtype_mask: int = 0,
) -> CallbackResult:
    in_buf = P.MYARK_CALLBACK_QUERY_DBG_INPUT()
    in_buf.MaxEntries = max_entries
    in_buf.SubTypeMask = subtype_mask
    out_buf = _alloc_buffer(P.HEADER_SIZE_DBG,
                            ctypes.sizeof(P.MYARK_CALLBACK_DBG_ENTRY),
                            max_entries)
    raw = _send_query(client, P.IOCTL_MYARK_CALLBACK_QUERY_DBG, in_buf, out_buf)
    out = P.MYARK_CALLBACK_QUERY_DBG_OUTPUT.from_buffer_copy(raw)
    result = _parse_header(out)
    result.extra["DbgkDebugObjectType"] = out.DbgkDebugObjectType
    return result


def enumerate(
    client: ArkClient,
    *,
    max_entries: int = _DEFAULT_ENUM_ENTRIES,
    category_mask: int = 0,
) -> CallbackResult:
    in_buf = P.MYARK_CALLBACK_ENUMERATE_INPUT()
    in_buf.MaxEntries = max_entries
    in_buf.CategoryMask = category_mask
    out_buf = _alloc_buffer(P.HEADER_SIZE_ENUM,
                            ctypes.sizeof(P.MYARK_CALLBACK_ENUM_ENTRY),
                            max_entries)
    raw = _send_query(client, P.IOCTL_MYARK_CALLBACK_ENUMERATE, in_buf, out_buf)
    out = P.MYARK_CALLBACK_ENUMERATE_OUTPUT.from_buffer_copy(raw)
    result = _parse_header(out)
    result.extra["PsCount"] = out.PsCount
    result.extra["CmCount"] = out.CmCount
    result.extra["ObCount"] = out.ObCount
    result.extra["ImageCount"] = out.ImageCount
    result.extra["DbgCount"] = out.DbgCount
    return result


def stats(client: ArkClient) -> CallbackStats:
    """Issue IOCTL_MYARK_CALLBACK_STATS and return the fixed-size totals."""
    out_buf = (ctypes.c_ubyte * ctypes.sizeof(P.MYARK_CALLBACK_STATS_OUTPUT))()
    raw = _send_query(client, P.IOCTL_MYARK_CALLBACK_STATS, None, out_buf)
    out_struct = P.MYARK_CALLBACK_STATS_OUTPUT.from_buffer_copy(raw)
    return CallbackStats(
        ps_count=out_struct.PsCount,
        cm_count=out_struct.CmCount,
        ob_count=out_struct.ObCount,
        image_count=out_struct.ImageCount,
        dbg_count=out_struct.DbgCount,
        total_count=out_struct.TotalCount,
    )


def remove(client: ArkClient, category: int, index: int) -> int:
    """Issue IOCTL_MYARK_CALLBACK_REMOVE (S7.2-fix reserve).

    Returns the Status field the driver wrote; for S7.2 the driver always
    answers STATUS_NOT_IMPLEMENTED so callers see that propagated up.
    """
    in_buf = P.MYARK_CALLBACK_REMOVE_INPUT()
    in_buf.Category = category
    in_buf.Index = index
    out_buf = (ctypes.c_ubyte * ctypes.sizeof(P.MYARK_CALLBACK_REMOVE_OUTPUT))()
    raw = _send_query(client, P.IOCTL_MYARK_CALLBACK_REMOVE, in_buf, out_buf)
    out_struct = P.MYARK_CALLBACK_REMOVE_OUTPUT.from_buffer_copy(raw)
    return out_struct.Status


def restore(client: ArkClient, category: int, index: int) -> int:
    """Issue IOCTL_MYARK_CALLBACK_RESTORE (S7.2-fix reserve)."""
    in_buf = P.MYARK_CALLBACK_RESTORE_INPUT()
    in_buf.Category = category
    in_buf.Index = index
    out_buf = (ctypes.c_ubyte * ctypes.sizeof(P.MYARK_CALLBACK_RESTORE_OUTPUT))()
    raw = _send_query(client, P.IOCTL_MYARK_CALLBACK_RESTORE, in_buf, out_buf)
    out_struct = P.MYARK_CALLBACK_RESTORE_OUTPUT.from_buffer_copy(raw)
    return out_struct.Status


def backup(client: ArkClient, *, max_entries: int = _DEFAULT_BACKUP_ENTRIES) -> CallbackResult:
    """Issue IOCTL_MYARK_CALLBACK_BACKUP (S7.2-fix reserve)."""
    in_buf = P.MYARK_CALLBACK_BACKUP_INPUT()
    in_buf.MaxEntries = max_entries
    out_buf = _alloc_buffer(P.HEADER_SIZE_BACKUP,
                            ctypes.sizeof(P.MYARK_CALLBACK_ENUM_ENTRY),
                            max_entries)
    raw = _send_query(client, P.IOCTL_MYARK_CALLBACK_BACKUP, in_buf, out_buf)
    out = P.MYARK_CALLBACK_BACKUP_OUTPUT.from_buffer_copy(raw)
    result = _parse_header(out)
    result.extra["BackupBlob"] = out.BackupBlob
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
    "CallbackResult",
    "CallbackStats",
    "query_ps",
    "query_cm",
    "query_ob",
    "query_image",
    "query_dbg",
    "enumerate",
    "stats",
    "remove",
    "restore",
    "backup",
    "try_query",
]