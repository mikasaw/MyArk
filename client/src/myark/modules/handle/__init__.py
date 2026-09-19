"""Handle module -- EPROCESS.ObjectTable walker (2 IOCTLs).

Mirrors ``driver/src/modules/20_handle/`` + ``shared/driver/MyArkHandleIoctl.h``.
"""

from __future__ import annotations

import argparse
import ctypes
import sys
import tkinter as tk
from tkinter import ttk
from typing import Any, Optional

from myark.client.ark_client import (
    ArkClient,
    DriverCallError,
    DriverError,
)
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration
from myark.protocol.core import _ctl_code


IOCTL_MYARK_HANDLE_ENUM_PROCESS_HANDLES = _ctl_code(0xC00)
IOCTL_MYARK_HANDLE_QUERY_HANDLE = _ctl_code(0xC01)


class MYARK_HANDLE_ENTRY(ctypes.Structure):
    _fields_ = [
        ("HandleValue", ctypes.c_uint64),
        ("PointerCount", ctypes.c_uint32),
        ("HandleCount", ctypes.c_uint32),
        ("TypeIndex", ctypes.c_uint32),
        ("HandleAttributes", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("TypeName", ctypes.c_wchar * 64),
        ("Name", ctypes.c_wchar * 260),
    ]


class MYARK_HANDLE_ENUM_INPUT(ctypes.Structure):
    _fields_ = [
        ("Pid", ctypes.c_uint32),
        ("MaxEntries", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
    ]


class MYARK_HANDLE_ENUM_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("TotalSeen", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Entries", MYARK_HANDLE_ENTRY * 1),
    ]


class MYARK_HANDLE_QUERY_INPUT(ctypes.Structure):
    _fields_ = [
        ("Pid", ctypes.c_uint32),
        ("HandleValue", ctypes.c_uint64),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
    ]


class MYARK_HANDLE_QUERY_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Status", ctypes.c_uint32),
        ("GrantedAccess", ctypes.c_uint32),
        ("PointerCount", ctypes.c_uint32),
        ("HandleCount", ctypes.c_uint32),
        ("TypeIndex", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("TypeName", ctypes.c_wchar * 64),
        ("Name", ctypes.c_wchar * 260),
    ]


def _enum_handles(client: ArkClient, pid: int, max_entries: int) -> MYARK_HANDLE_ENUM_OUTPUT:
    in_buf = MYARK_HANDLE_ENUM_INPUT()
    in_buf.Pid = pid
    in_buf.MaxEntries = max_entries
    out_size = ctypes.sizeof(MYARK_HANDLE_ENUM_OUTPUT) + 4096 * ctypes.sizeof(MYARK_HANDLE_ENTRY)
    out_buf = (ctypes.c_ubyte * out_size)()
    client.ioctl(IOCTL_MYARK_HANDLE_ENUM_PROCESS_HANDLES, in_buf, out_buf)
    return ctypes.cast(out_buf, POINTER(MYARK_HANDLE_ENUM_OUTPUT)).contents


from ctypes import POINTER


def register(
    client: Optional[ArkClient],
    capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    return ModuleRegistration(
        name="handle",
        register_fn=register,
        ui_factory=_build_ui,
        cli_setup=_setup_cli,
        description="Handle module - EPROCESS.ObjectTable walker",
    )


def _build_ui(parent: Any, client: Optional[ArkClient]) -> ttk.Frame:
    status_var = tk.StringVar(value="(not yet queried)")
    pid_var = tk.StringVar(value="0")
    frame = ttk.Frame(parent, padding=12)
    ttk.Label(frame, text="Pid:").grid(row=0, column=0, sticky=tk.W)
    ttk.Entry(frame, textvariable=pid_var, width=10).grid(row=0, column=1, sticky=tk.W)

    def _on_query() -> None:
        if client is None:
            status_var.set("driver not installed")
            return
        try:
            out = _enum_handles(client, int(pid_var.get() or "0"), 64)
            status_var.set(f"OK: count={out.Count} total_seen={out.TotalSeen}")
        except (DriverCallError, DriverError, OSError) as exc:
            status_var.set(f"err: {exc}")

    ttk.Button(frame, text="Query handles", command=_on_query).grid(row=1, column=0, columnspan=2, pady=4)
    ttk.Label(frame, textvariable=status_var, wraplength=480, justify=tk.LEFT).grid(row=2, column=0, columnspan=2, sticky=tk.W)
    return frame


def _setup_cli(subparsers: Any, _client: Optional[ArkClient]) -> None:
    p = subparsers.add_parser("handle", help="handle module commands")
    sub = p.add_subparsers(dest="handle_subcommand")
    pe = sub.add_parser("enum", help="enum process handles")
    pe.add_argument("--pid", type=int, default=0)
    pe.add_argument("--max-entries", type=int, default=64)
    pe.set_defaults(_handler=_cmd_handle_enum)


def _cmd_handle_enum(args: argparse.Namespace) -> int:
    client = ArkClient.open_or_null()
    if client is None:
        print("driver not installed", file=sys.stderr)
        return 2
    try:
        out = _enum_handles(client, args.pid, args.max_entries)
        print(f"count={out.Count} total_seen={out.TotalSeen}")
        return 0
    except (DriverCallError, DriverError) as exc:
        print(f"err: {exc}", file=sys.stderr)
        return 3
    finally:
        try:
            client.close()
        except Exception:
            pass


__all__ = ["register"]