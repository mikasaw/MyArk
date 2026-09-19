"""Section module -- MmControlAreaListHead walker (2 IOCTLs)."""

from __future__ import annotations

import argparse
import ctypes
import sys
import tkinter as tk
from tkinter import ttk
from typing import Any, Optional

from myark.client.ark_client import ArkClient, DriverCallError, DriverError
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration
from myark.protocol.core import _ctl_code

IOCTL_MYARK_SECTION_QUERY_PROCESS = _ctl_code(0xC10)
IOCTL_MYARK_SECTION_QUERY_FILE_MAPPINGS = _ctl_code(0xC11)


class MYARK_SECTION_ENTRY(ctypes.Structure):
    _fields_ = [
        ("ControlAreaAddress", ctypes.c_uint64),
        ("FileObjectAddress", ctypes.c_uint64),
        ("SizeInBytes", ctypes.c_uint64),
        ("Flags", ctypes.c_uint32),
        ("Protection", ctypes.c_uint32),
        ("Pid", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Name", ctypes.c_wchar * 260),
    ]


class MYARK_SECTION_QUERY_PROCESS_INPUT(ctypes.Structure):
    _fields_ = [
        ("Pid", ctypes.c_uint32),
        ("MaxEntries", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
    ]


class MYARK_SECTION_QUERY_PROCESS_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("TotalSeen", ctypes.c_uint32),
        ("RemoteUnsupportedCount", ctypes.c_uint32),
        ("Entries", MYARK_SECTION_ENTRY * 1),
    ]


def _query_process(client: ArkClient, pid: int, max_entries: int) -> MYARK_SECTION_QUERY_PROCESS_OUTPUT:
    in_buf = MYARK_SECTION_QUERY_PROCESS_INPUT()
    in_buf.Pid = pid
    in_buf.MaxEntries = max_entries
    out_size = ctypes.sizeof(MYARK_SECTION_QUERY_PROCESS_OUTPUT) + 4096 * ctypes.sizeof(MYARK_SECTION_ENTRY)
    out_buf = (ctypes.c_ubyte * out_size)()
    client.ioctl(IOCTL_MYARK_SECTION_QUERY_PROCESS, in_buf, out_buf)
    return ctypes.cast(out_buf, ctypes.POINTER(MYARK_SECTION_QUERY_PROCESS_OUTPUT)).contents


def register(client: Optional[ArkClient], capabilities: list[CapabilityInfo]) -> ModuleRegistration:
    return ModuleRegistration(name="section", register_fn=register,
                              ui_factory=_build_ui, cli_setup=_setup_cli,
                              description="Section module - MmControlAreaListHead walker")


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
            out = _query_process(client, int(pid_var.get() or "0"), 64)
            status_var.set(f"OK: count={out.Count} total_seen={out.TotalSeen}")
        except (DriverCallError, DriverError, OSError) as exc:
            status_var.set(f"err: {exc}")

    ttk.Button(frame, text="Query sections", command=_on_query).grid(row=1, column=0, columnspan=2, pady=4)
    ttk.Label(frame, textvariable=status_var, wraplength=480, justify=tk.LEFT).grid(row=2, column=0, columnspan=2, sticky=tk.W)
    return frame


def _setup_cli(subparsers: Any, _client: Optional[ArkClient]) -> None:
    p = subparsers.add_parser("section", help="section module commands")
    sub = p.add_subparsers(dest="section_subcommand")
    pe = sub.add_parser("query", help="query sections for a pid")
    pe.add_argument("--pid", type=int, default=0)
    pe.add_argument("--max-entries", type=int, default=64)
    pe.set_defaults(_handler=_cmd_section_query)


def _cmd_section_query(args: argparse.Namespace) -> int:
    client = ArkClient.open_or_null()
    if client is None:
        print("driver not installed", file=sys.stderr)
        return 2
    try:
        out = _query_process(client, args.pid, args.max_entries)
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