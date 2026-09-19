"""Kmod module -- IoDriverListHead driver object walker (2 IOCTLs)."""

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

IOCTL_MYARK_KMODULE_QUERY_DRIVER_OBJECT = _ctl_code(0xC20)
IOCTL_MYARK_KMODULE_QUERY_IOCTL_REGISTRY = _ctl_code(0xC21)


class MYARK_KMODULE_ENTRY(ctypes.Structure):
    _fields_ = [
        ("DriverObjectAddress", ctypes.c_uint64),
        ("DriverStartAddress", ctypes.c_uint64),
        ("DriverSize", ctypes.c_uint32),
        ("MajorFunctionCount", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("DriverName", ctypes.c_wchar * 64),
        ("DriverPath", ctypes.c_wchar * 260),
    ]


class MYARK_IOCTL_REG_ENTRY(ctypes.Structure):
    _fields_ = [
        ("DriverObjectAddress", ctypes.c_uint64),
        ("DispatchAddress", ctypes.c_uint64),
        ("Flags", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("DriverName", ctypes.c_wchar * 64),
    ]


class MYARK_MODULE_QUERY_DRIVER_OBJECT_INPUT(ctypes.Structure):
    _fields_ = [
        ("MaxEntries", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint32),
    ]


class MYARK_MODULE_QUERY_DRIVER_OBJECT_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("TotalSeen", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Entries", MYARK_KMODULE_ENTRY * 1),
    ]


def _query_drivers(client: ArkClient, max_entries: int) -> MYARK_MODULE_QUERY_DRIVER_OBJECT_OUTPUT:
    in_buf = MYARK_MODULE_QUERY_DRIVER_OBJECT_INPUT()
    in_buf.MaxEntries = max_entries
    out_size = ctypes.sizeof(MYARK_MODULE_QUERY_DRIVER_OBJECT_OUTPUT) + 4096 * ctypes.sizeof(MYARK_KMODULE_ENTRY)
    out_buf = (ctypes.c_ubyte * out_size)()
    client.ioctl(IOCTL_MYARK_KMODULE_QUERY_DRIVER_OBJECT, in_buf, out_buf)
    return ctypes.cast(out_buf, ctypes.POINTER(MYARK_MODULE_QUERY_DRIVER_OBJECT_OUTPUT)).contents


def register(client: Optional[ArkClient], capabilities: list[CapabilityInfo]) -> ModuleRegistration:
    return ModuleRegistration(name="kmod", register_fn=register,
                              ui_factory=_build_ui, cli_setup=_setup_cli,
                              description="Kmod module - IoDriverListHead walker")


def _build_ui(parent: Any, client: Optional[ArkClient]) -> ttk.Frame:
    status_var = tk.StringVar(value="(not yet queried)")
    frame = ttk.Frame(parent, padding=12)

    def _on_query() -> None:
        if client is None:
            status_var.set("driver not installed")
            return
        try:
            out = _query_drivers(client, 256)
            status_var.set(f"OK: count={out.Count} total_seen={out.TotalSeen}")
        except (DriverCallError, DriverError, OSError) as exc:
            status_var.set(f"err: {exc}")

    ttk.Button(frame, text="Query drivers", command=_on_query).grid(row=0, column=0, pady=4)
    ttk.Label(frame, textvariable=status_var, wraplength=480, justify=tk.LEFT).grid(row=1, column=0, sticky=tk.W)
    return frame


def _setup_cli(subparsers: Any, _client: Optional[ArkClient]) -> None:
    p = subparsers.add_parser("kmod", help="kernel module walker commands")
    sub = p.add_subparsers(dest="kmod_subcommand")
    pe = sub.add_parser("drivers", help="list driver objects")
    pe.add_argument("--max-entries", type=int, default=256)
    pe.set_defaults(_handler=_cmd_kmod_drivers)


def _cmd_kmod_drivers(args: argparse.Namespace) -> int:
    client = ArkClient.open_or_null()
    if client is None:
        print("driver not installed", file=sys.stderr)
        return 2
    try:
        out = _query_drivers(client, args.max_entries)
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