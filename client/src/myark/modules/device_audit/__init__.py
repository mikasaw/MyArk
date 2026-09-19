"""Device-audit module -- device stacks + USB + GPU + input + watchdog (5 IOCTLs)."""

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

IOCTL_MYARK_DEVICE_AUDIT_QUERY_DEVICE_STACK = _ctl_code(0xC40)
IOCTL_MYARK_DEVICE_AUDIT_QUERY_USB_TOPOLOGY = _ctl_code(0xC41)
IOCTL_MYARK_DEVICE_AUDIT_QUERY_GPU_DISPLAY = _ctl_code(0xC42)
IOCTL_MYARK_DEVICE_AUDIT_QUERY_INPUT_STACK = _ctl_code(0xC43)
IOCTL_MYARK_DEVICE_AUDIT_QUERY_WATCHDOG = _ctl_code(0xC44)


class MYARK_DEVAUDIT_INPUT(ctypes.Structure):
    _fields_ = [
        ("MaxEntries", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint32),
    ]


class MYARK_DEVICE_ENTRY(ctypes.Structure):
    _fields_ = [
        ("DeviceObjectAddress", ctypes.c_uint64),
        ("AttachedToAddress", ctypes.c_uint64),
        ("Flags", ctypes.c_uint32),
        ("StackDepth", ctypes.c_uint32),
        ("DriverName", ctypes.c_wchar * 64),
        ("DeviceName", ctypes.c_wchar * 260),
    ]


class MYARK_DEVAUDIT_DEVICE_STACK_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("TotalSeen", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Entries", MYARK_DEVICE_ENTRY * 1),
    ]


def _query_device_stack(client: ArkClient, max_entries: int) -> MYARK_DEVAUDIT_DEVICE_STACK_OUTPUT:
    in_buf = MYARK_DEVAUDIT_INPUT()
    in_buf.MaxEntries = max_entries
    out_size = ctypes.sizeof(MYARK_DEVAUDIT_DEVICE_STACK_OUTPUT) + 4096 * ctypes.sizeof(MYARK_DEVICE_ENTRY)
    out_buf = (ctypes.c_ubyte * out_size)()
    client.ioctl(IOCTL_MYARK_DEVICE_AUDIT_QUERY_DEVICE_STACK, in_buf, out_buf)
    return ctypes.cast(out_buf, ctypes.POINTER(MYARK_DEVAUDIT_DEVICE_STACK_OUTPUT)).contents


def register(client: Optional[ArkClient], capabilities: list[CapabilityInfo]) -> ModuleRegistration:
    return ModuleRegistration(name="device-audit", register_fn=register,
                              ui_factory=_build_ui, cli_setup=_setup_cli,
                              description="Device audit module - device stacks + USB + GPU + input + watchdog")


def _build_ui(parent: Any, client: Optional[ArkClient]) -> ttk.Frame:
    status_var = tk.StringVar(value="(not yet queried)")
    frame = ttk.Frame(parent, padding=12)

    def _on_query() -> None:
        if client is None:
            status_var.set("driver not installed")
            return
        try:
            out = _query_device_stack(client, 256)
            status_var.set(f"OK: count={out.Count} total_seen={out.TotalSeen}")
        except (DriverCallError, DriverError, OSError) as exc:
            status_var.set(f"err: {exc}")

    ttk.Button(frame, text="Query device stack", command=_on_query).grid(row=0, column=0, pady=4)
    ttk.Label(frame, textvariable=status_var, wraplength=480, justify=tk.LEFT).grid(row=1, column=0, sticky=tk.W)
    return frame


def _setup_cli(subparsers: Any, _client: Optional[ArkClient]) -> None:
    p = subparsers.add_parser("device-audit", help="device audit commands")
    sub = p.add_subparsers(dest="device_audit_subcommand")
    pd = sub.add_parser("device-stack", help="list device objects")
    pd.add_argument("--max-entries", type=int, default=256)
    pd.set_defaults(_handler=_cmd_devaudit_stack)


def _cmd_devaudit_stack(args: argparse.Namespace) -> int:
    client = ArkClient.open_or_null()
    if client is None:
        print("driver not installed", file=sys.stderr)
        return 2
    try:
        out = _query_device_stack(client, args.max_entries)
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