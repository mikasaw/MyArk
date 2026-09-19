"""
kernel_object R3 - parser (R0 send + dataclasses).
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass, field
from typing import Optional

from myark.client.ark_client import ArkClient

from . import protocol as P


@dataclass
class ObjectEntry:
    name: str = ""
    type_name: str = ""


@dataclass
class DirectoryReport:
    count: int = 0
    flags: int = 0
    open_status: int = 0
    walk_status: int = 0
    entries: list = field(default_factory=list)
    source: str = "r0"


@dataclass
class IpcSummaryReport:
    pipes: list = field(default_factory=list)
    mailslots: list = field(default_factory=list)
    pipe_flags: int = 0
    pipe_open_status: int = 0
    pipe_walk_status: int = 0
    mailslot_flags: int = 0
    mailslot_open_status: int = 0
    mailslot_walk_status: int = 0
    source: str = "r0"


def _rows(entries, count: int) -> list:
    out = []
    for i in range(min(count, len(entries))):
        e = entries[i]
        out.append(ObjectEntry(name=e.Name, type_name=e.TypeName))
    return out


def _validate_path(path: str) -> Optional[str]:
    if not path or not path.startswith("\\"):
        return "object paths are absolute (must start with '\\')"
    if len(path) + 1 > P.KOBJ_PATH_MAX:
        return f"path longer than {P.KOBJ_PATH_MAX - 1} chars"
    if "*" in path or "?" in path:
        return "wildcards are not valid in object-directory queries"
    return None


def query_directory(client: Optional[ArkClient], path: str) -> DirectoryReport:
    err = _validate_path(path)
    if err:
        raise ValueError(err)
    if client is None:
        raise ConnectionError("driver not available")

    in_buf = P.MYARK_KOBJ_DIRECTORY_INPUT()
    in_buf.PathLength = len(path) + 1
    in_buf.DirectoryPath = path

    out_buf = P.MYARK_KOBJ_DIRECTORY_OUTPUT()
    client.ioctl(P.IOCTL_MYARK_KOBJ_ENUM_DIRECTORY, in_buf, out_buf)
    return DirectoryReport(
        count=out_buf.Count,
        flags=out_buf.Flags,
        open_status=out_buf.OpenStatus,
        walk_status=out_buf.WalkStatus,
        entries=_rows(out_buf.Entries, out_buf.Count),
    )


def ipc_summary(client: Optional[ArkClient]) -> IpcSummaryReport:
    if client is None:
        raise ConnectionError("driver not available")

    out_buf = P.MYARK_KOBJ_IPC_SUMMARY_OUTPUT()
    client.ioctl(P.IOCTL_MYARK_KOBJ_IPC_SUMMARY,
                 (ctypes.c_ubyte * 0)(), out_buf)
    return IpcSummaryReport(
        pipes=_rows(out_buf.Pipes, out_buf.PipeCount),
        mailslots=_rows(out_buf.Mailslots, out_buf.MailslotCount),
        pipe_flags=out_buf.PipeFlags,
        pipe_open_status=out_buf.PipeOpenStatus,
        pipe_walk_status=out_buf.PipeWalkStatus,
        mailslot_flags=out_buf.MailslotFlags,
        mailslot_open_status=out_buf.MailslotOpenStatus,
        mailslot_walk_status=out_buf.MailslotWalkStatus,
    )


__all__ = [
    "ObjectEntry",
    "DirectoryReport",
    "IpcSummaryReport",
    "query_directory",
    "ipc_summary",
]
