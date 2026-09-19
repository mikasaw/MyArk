"""Keyboard module -- win32k tagTHREADINFO + tagHOOK walker (2 IOCTLs)."""

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

IOCTL_MYARK_KEYBOARD_ENUM_HOTKEYS = _ctl_code(0xC50)
IOCTL_MYARK_KEYBOARD_ENUM_HOOKS = _ctl_code(0xC51)


class MYARK_HOTKEY_ENTRY(ctypes.Structure):
    _fields_ = [
        ("Tid", ctypes.c_uint32),
        ("Pid", ctypes.c_uint32),
        ("HotkeyId", ctypes.c_uint32),
        ("VirtualKey", ctypes.c_uint32),
        ("Modifiers", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Description", ctypes.c_wchar * 64),
    ]


class MYARK_KEYBOARD_ENUM_HOTKEYS_INPUT(ctypes.Structure):
    _fields_ = [
        ("MaxEntries", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint32),
    ]


class MYARK_KEYBOARD_ENUM_HOTKEYS_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("TotalSeen", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Entries", MYARK_HOTKEY_ENTRY * 1),
    ]


class MYARK_HOOK_ENTRY(ctypes.Structure):
    _fields_ = [
        ("HookObjectAddress", ctypes.c_uint64),
        ("FunctionAddress", ctypes.c_uint64),
        ("HookType", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("OwningTid", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("ModuleName", ctypes.c_wchar * 64),
    ]


class MYARK_KEYBOARD_ENUM_HOOKS_INPUT(ctypes.Structure):
    _fields_ = [
        ("MaxEntries", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint32),
    ]


class MYARK_KEYBOARD_ENUM_HOOKS_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("ChainDepthMax", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Entries", MYARK_HOOK_ENTRY * 1),
    ]


def _enum_hooks(client: ArkClient, max_entries: int) -> MYARK_KEYBOARD_ENUM_HOOKS_OUTPUT:
    in_buf = MYARK_KEYBOARD_ENUM_HOOKS_INPUT()
    in_buf.MaxEntries = max_entries
    out_size = ctypes.sizeof(MYARK_KEYBOARD_ENUM_HOOKS_OUTPUT) + 4096 * ctypes.sizeof(MYARK_HOOK_ENTRY)
    out_buf = (ctypes.c_ubyte * out_size)()
    client.ioctl(IOCTL_MYARK_KEYBOARD_ENUM_HOOKS, in_buf, out_buf)
    return ctypes.cast(out_buf, ctypes.POINTER(MYARK_KEYBOARD_ENUM_HOOKS_OUTPUT)).contents


def register(client: Optional[ArkClient], capabilities: list[CapabilityInfo]) -> ModuleRegistration:
    return ModuleRegistration(name="keyboard", register_fn=register,
                              ui_factory=_build_ui, cli_setup=_setup_cli,
                              description="Keyboard module - win32k tagTHREADINFO+tagHOOK walker")


def _build_ui(parent: Any, client: Optional[ArkClient]) -> ttk.Frame:
    status_var = tk.StringVar(value="(not yet queried)")
    frame = ttk.Frame(parent, padding=12)

    def _on_query() -> None:
        if client is None:
            status_var.set("driver not installed")
            return
        try:
            out = _enum_hooks(client, 256)
            status_var.set(f"OK: count={out.Count} chain_depth_max={out.ChainDepthMax}")
        except (DriverCallError, DriverError, OSError) as exc:
            status_var.set(f"err: {exc}")

    ttk.Button(frame, text="Enum hooks", command=_on_query).grid(row=0, column=0, pady=4)
    ttk.Label(frame, textvariable=status_var, wraplength=480, justify=tk.LEFT).grid(row=1, column=0, sticky=tk.W)
    return frame


def _setup_cli(subparsers: Any, _client: Optional[ArkClient]) -> None:
    p = subparsers.add_parser("keyboard", help="keyboard module commands")
    sub = p.add_subparsers(dest="keyboard_subcommand")
    pe = sub.add_parser("enum-hooks", help="enum keyboard hooks")
    pe.add_argument("--max-entries", type=int, default=256)
    pe.set_defaults(_handler=_cmd_keyboard_enum)


def _cmd_keyboard_enum(args: argparse.Namespace) -> int:
    client = ArkClient.open_or_null()
    if client is None:
        print("driver not installed", file=sys.stderr)
        return 2
    try:
        out = _enum_hooks(client, args.max_entries)
        print(f"count={out.Count} chain_depth_max={out.ChainDepthMax}")
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