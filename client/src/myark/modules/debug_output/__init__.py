"""Debug-output module -- DbgPrint ring buffer (2 IOCTLs)."""

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

IOCTL_MYARK_DEBUG_OUTPUT_CONTROL = _ctl_code(0xC60)
IOCTL_MYARK_DEBUG_OUTPUT_DRAIN = _ctl_code(0xC61)


class MYARK_DEBUG_OUTPUT_CONTROL_INPUT(ctypes.Structure):
    _fields_ = [
        ("Control", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint32),
    ]


class MYARK_DEBUG_OUTPUT_CONTROL_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("CurrentState", ctypes.c_uint32),
        ("PreviousState", ctypes.c_uint32),
        ("OwnerRefCount", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("OwnerModuleName", ctypes.c_wchar * 64),
    ]


def _control(client: ArkClient, ctrl: int) -> MYARK_DEBUG_OUTPUT_CONTROL_OUTPUT:
    in_buf = MYARK_DEBUG_OUTPUT_CONTROL_INPUT()
    in_buf.Control = ctrl
    out_buf = MYARK_DEBUG_OUTPUT_CONTROL_OUTPUT()
    client.ioctl(IOCTL_MYARK_DEBUG_OUTPUT_CONTROL, in_buf, out_buf)
    return out_buf


def register(client: Optional[ArkClient], capabilities: list[CapabilityInfo]) -> ModuleRegistration:
    return ModuleRegistration(name="debug-output", register_fn=register,
                              ui_factory=_build_ui, cli_setup=_setup_cli,
                              description="Debug output module - DbgPrint ring buffer")


def _build_ui(parent: Any, client: Optional[ArkClient]) -> ttk.Frame:
    status_var = tk.StringVar(value="(idle)")
    frame = ttk.Frame(parent, padding=12)

    def _on_start() -> None:
        if client is None:
            status_var.set("driver not installed")
            return
        try:
            out = _control(client, 1)
            status_var.set(f"started, refcount={out.OwnerRefCount}")
        except (DriverCallError, DriverError, OSError) as exc:
            status_var.set(f"err: {exc}")

    def _on_stop() -> None:
        if client is None:
            status_var.set("driver not installed")
            return
        try:
            out = _control(client, 0)
            status_var.set(f"stopped, prev={out.PreviousState}")
        except (DriverCallError, DriverError, OSError) as exc:
            status_var.set(f"err: {exc}")

    ttk.Button(frame, text="Start capture", command=_on_start).grid(row=0, column=0, pady=4)
    ttk.Button(frame, text="Stop capture", command=_on_stop).grid(row=0, column=1, pady=4)
    ttk.Label(frame, textvariable=status_var, wraplength=480, justify=tk.LEFT).grid(row=1, column=0, columnspan=2, sticky=tk.W)
    return frame


def _setup_cli(subparsers: Any, _client: Optional[ArkClient]) -> None:
    p = subparsers.add_parser("debug-output", help="debug output module commands")
    sub = p.add_subparsers(dest="dbg_subcommand")
    ps = sub.add_parser("start", help="start DbgPrint capture")
    ps.set_defaults(_handler=_cmd_dbg_start)
    pt = sub.add_parser("stop", help="stop DbgPrint capture")
    pt.set_defaults(_handler=_cmd_dbg_stop)


def _cmd_dbg_start(_args: argparse.Namespace) -> int:
    client = ArkClient.open_or_null()
    if client is None:
        print("driver not installed", file=sys.stderr)
        return 2
    try:
        out = _control(client, 1)
        print(f"started, refcount={out.OwnerRefCount}")
        return 0
    except (DriverCallError, DriverError) as exc:
        print(f"err: {exc}", file=sys.stderr)
        return 3
    finally:
        try:
            client.close()
        except Exception:
            pass


def _cmd_dbg_stop(_args: argparse.Namespace) -> int:
    client = ArkClient.open_or_null()
    if client is None:
        print("driver not installed", file=sys.stderr)
        return 2
    try:
        out = _control(client, 0)
        print(f"stopped, prev={out.PreviousState}")
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