"""Kernel module -- KeServiceDescriptorTable SSDT walker (1 IOCTL)."""

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

IOCTL_MYARK_KERNEL_QUERY_SSDT = _ctl_code(0xC70)


class MYARK_KERNEL_SSDT_ENTRY(ctypes.Structure):
    _fields_ = [
        ("ServiceAddress", ctypes.c_uint64),
        ("ServiceIndex", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("DwellBytesSize", ctypes.c_uint32),
        ("DwellBytes", ctypes.c_ubyte * 8),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
    ]


class MYARK_KERNEL_QUERY_SSDT_INPUT(ctypes.Structure):
    _fields_ = [
        ("MaxEntries", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint32),
    ]


class MYARK_KERNEL_QUERY_SSDT_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("TotalSeen", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("KeServiceDescriptorTable", ctypes.c_uint64),
        ("NtoskrnlTextBase", ctypes.c_uint64),
        ("NtoskrnlTextEnd", ctypes.c_uint64),
        ("EntryStructSize", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Entries", MYARK_KERNEL_SSDT_ENTRY * 1),
    ]


def _query_ssdt(client: ArkClient, max_entries: int) -> MYARK_KERNEL_QUERY_SSDT_OUTPUT:
    in_buf = MYARK_KERNEL_QUERY_SSDT_INPUT()
    in_buf.MaxEntries = max_entries
    out_size = ctypes.sizeof(MYARK_KERNEL_QUERY_SSDT_OUTPUT) + 4096 * ctypes.sizeof(MYARK_KERNEL_SSDT_ENTRY)
    out_buf = (ctypes.c_ubyte * out_size)()
    client.ioctl(IOCTL_MYARK_KERNEL_QUERY_SSDT, in_buf, out_buf)
    return ctypes.cast(out_buf, ctypes.POINTER(MYARK_KERNEL_QUERY_SSDT_OUTPUT)).contents


def register(client: Optional[ArkClient], capabilities: list[CapabilityInfo]) -> ModuleRegistration:
    return ModuleRegistration(name="kernel", register_fn=register,
                              ui_factory=_build_ui, cli_setup=_setup_cli,
                              description="Kernel module - KeServiceDescriptorTable walker")


def _build_ui(parent: Any, client: Optional[ArkClient]) -> ttk.Frame:
    status_var = tk.StringVar(value="(not yet queried)")
    frame = ttk.Frame(parent, padding=12)

    def _on_query() -> None:
        if client is None:
            status_var.set("driver not installed")
            return
        try:
            out = _query_ssdt(client, 256)
            suspect_count = sum(
                1 for i in range(out.Count)
                if out.Entries[i].Flags & 0x2
            )
            status_var.set(
                f"OK: count={out.Count} total_seen={out.TotalSeen} "
                f"suspect={suspect_count} table=0x{out.KeServiceDescriptorTable:x}"
            )
        except (DriverCallError, DriverError, OSError) as exc:
            status_var.set(f"err: {exc}")

    ttk.Button(frame, text="Query SSDT", command=_on_query).grid(row=0, column=0, pady=4)
    ttk.Label(frame, textvariable=status_var, wraplength=480, justify=tk.LEFT).grid(row=1, column=0, sticky=tk.W)
    return frame


def _setup_cli(subparsers: Any, _client: Optional[ArkClient]) -> None:
    p = subparsers.add_parser("kernel", help="kernel module commands")
    sub = p.add_subparsers(dest="kernel_subcommand")
    pe = sub.add_parser("query-ssdt", help="list SSDT entries")
    pe.add_argument("--max-entries", type=int, default=256)
    pe.set_defaults(_handler=_cmd_kernel_query_ssdt)


def _cmd_kernel_query_ssdt(args: argparse.Namespace) -> int:
    client = ArkClient.open_or_null()
    if client is None:
        print("driver not installed", file=sys.stderr)
        return 2
    try:
        out = _query_ssdt(client, args.max_entries)
        suspect_count = sum(
            1 for i in range(out.Count)
            if out.Entries[i].Flags & 0x2
        )
        print(f"count={out.Count} total_seen={out.TotalSeen} suspect={suspect_count}")
        for i in range(min(out.Count, 16)):
            entry = out.Entries[i]
            flags_str = []
            if entry.Flags & 0x1:
                flags_str.append("populated")
            if entry.Flags & 0x2:
                flags_str.append("SUSPECT")
            if entry.Flags & 0x4:
                flags_str.append("HOOK")
            flag_str = ",".join(flags_str) or "none"
            print(f"  [{entry.ServiceIndex:04x}] addr=0x{entry.ServiceAddress:016x} flags={flag_str}")
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
