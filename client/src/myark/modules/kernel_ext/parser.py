"""
kernel_ext R3 - parser + R3 fallback (NtQuerySystemInformation on the R3 side).
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Optional

from myark.client.ark_client import ArkClient, DriverError

from . import protocol as P


@dataclass
class Win11InfoBlob:
    info_class: int = 0
    status: int = 0
    bytes_returned: int = 0
    source: str = ""  # "r0" or "r3-fallback"


@dataclass
class SyscallEntry:
    index: int = 0
    address: int = 0


@dataclass
class SyscallTable:
    entries: list
    source: str = ""


def _r3_fallback_query(info_class: int) -> Win11InfoBlob:
    """R3 fallback: report unsupported in S7.3. The full NtQuery path is in DynData."""
    return Win11InfoBlob(
        info_class=info_class,
        status=0xC0000002,  # STATUS_NOT_IMPLEMENTED
        bytes_returned=0,
        source="r3-fallback",
    )


def _r3_fallback_table() -> SyscallTable:
    return SyscallTable(entries=[], source="r3-fallback")


def _send_query(client: Optional[ArkClient], info_class: int) -> Optional[Win11InfoBlob]:
    if client is None:
        return None

    in_size = ctypes.sizeof(P.MYARK_KERNEL_EXT_QUERY_INPUT)
    in_buf = (ctypes.c_ubyte * in_size)()
    in_struct = ctypes.cast(in_buf, ctypes.POINTER(P.MYARK_KERNEL_EXT_QUERY_INPUT)).contents
    in_struct.SystemInformationClass = info_class

    out_size = ctypes.sizeof(P.MYARK_KERNEL_EXT_QUERY_OUTPUT)
    out_buf = (ctypes.c_ubyte * out_size)()

    try:
        bytes_returned = client.ioctl(
            P.IOCTL_MYARK_KERNEL_EXT_QUERY_WIN11_INFO, in_buf, out_buf
        )
    except (DriverError, OSError):
        return None
    if bytes_returned < out_size:
        return None

    out = ctypes.cast(out_buf, ctypes.POINTER(P.MYARK_KERNEL_EXT_QUERY_OUTPUT)).contents
    return Win11InfoBlob(
        info_class=info_class,
        status=out.Status,
        bytes_returned=out.BytesReturned,
        source="r0",
    )


def _send_table(client: Optional[ArkClient]) -> Optional[SyscallTable]:
    if client is None:
        return None

    out_size = ctypes.sizeof(P.MYARK_KERNEL_EXT_SYSCALL_TABLE_OUTPUT)
    out_buf = (ctypes.c_ubyte * out_size)()

    try:
        bytes_returned = client.ioctl(
            P.IOCTL_MYARK_KERNEL_EXT_READ_SYSCALL_TABLE, in_buf := (ctypes.c_ubyte * 0)(),
            out_buf,
        )
    except (DriverError, OSError):
        return None
    if bytes_returned < out_size:
        return None

    out = ctypes.cast(out_buf, ctypes.POINTER(P.MYARK_KERNEL_EXT_SYSCALL_TABLE_OUTPUT)).contents
    return SyscallTable(entries=[], source="r0")


def query_win11_info(client: Optional[ArkClient], info_class: int) -> Win11InfoBlob:
    r3 = _r3_fallback_query(info_class)
    r0 = _send_query(client, info_class)
    return r0 if r0 is not None else r3


def read_syscall_table(client: Optional[ArkClient]) -> SyscallTable:
    r3 = _r3_fallback_table()
    r0 = _send_table(client)
    return r0 if r0 is not None else r3


__all__ = [
    "Win11InfoBlob",
    "SyscallEntry",
    "SyscallTable",
    "query_win11_info",
    "read_syscall_table",
]