"""Storage module -- filter stack + bitlocker + mountmgr + USN (4 IOCTLs)."""

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

IOCTL_MYARK_STORAGE_QUERY_VOLUME_STACK = _ctl_code(0xC30)
IOCTL_MYARK_STORAGE_QUERY_BITLOCKER = _ctl_code(0xC31)
IOCTL_MYARK_STORAGE_QUERY_MOUNTMGR_MAPPING = _ctl_code(0xC32)
IOCTL_MYARK_STORAGE_QUERY_FS_INTEGRITY = _ctl_code(0xC33)


class MYARK_VOLUME_STACK_ENTRY(ctypes.Structure):
    _fields_ = [
        ("DeviceObjectAddress", ctypes.c_uint64),
        ("Layer", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("StackDepth", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("DriverName", ctypes.c_wchar * 64),
        ("DeviceName", ctypes.c_wchar * 260),
    ]


class MYARK_STORAGE_VOLUME_STACK_INPUT(ctypes.Structure):
    _fields_ = [
        ("VolumeOrDevice", ctypes.c_wchar * 260),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
    ]


class MYARK_STORAGE_VOLUME_STACK_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Entries", MYARK_VOLUME_STACK_ENTRY * 1),
    ]


class MYARK_BITLOCKER_ENTRY(ctypes.Structure):
    _fields_ = [
        ("VolumeDeviceAddress", ctypes.c_uint64),
        ("Encrypted", ctypes.c_uint32),
        ("Protection", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("VolumeName", ctypes.c_wchar * 260),
    ]


class MYARK_STORAGE_BITLOCKER_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Entries", MYARK_BITLOCKER_ENTRY * 1),
    ]


def _query_bitlocker(client: ArkClient) -> MYARK_STORAGE_BITLOCKER_OUTPUT:
    out_size = ctypes.sizeof(MYARK_STORAGE_BITLOCKER_OUTPUT) + 4096 * ctypes.sizeof(MYARK_BITLOCKER_ENTRY)
    out_buf = (ctypes.c_ubyte * out_size)()
    client.ioctl(IOCTL_MYARK_STORAGE_QUERY_BITLOCKER, None, out_buf)
    return ctypes.cast(out_buf, ctypes.POINTER(MYARK_STORAGE_BITLOCKER_OUTPUT)).contents


def register(client: Optional[ArkClient], capabilities: list[CapabilityInfo]) -> ModuleRegistration:
    return ModuleRegistration(name="storage", register_fn=register,
                              ui_factory=_build_ui, cli_setup=_setup_cli,
                              description="Storage module - filter stack + bitlocker + mountmgr + USN")


def _build_ui(parent: Any, client: Optional[ArkClient]) -> ttk.Frame:
    status_var = tk.StringVar(value="(not yet queried)")
    frame = ttk.Frame(parent, padding=12)

    def _on_query() -> None:
        if client is None:
            status_var.set("driver not installed")
            return
        try:
            out = _query_bitlocker(client)
            status_var.set(f"OK: count={out.Count}")
        except (DriverCallError, DriverError, OSError) as exc:
            status_var.set(f"err: {exc}")

    ttk.Button(frame, text="Query BitLocker", command=_on_query).grid(row=0, column=0, pady=4)
    ttk.Label(frame, textvariable=status_var, wraplength=480, justify=tk.LEFT).grid(row=1, column=0, sticky=tk.W)
    return frame


def _setup_cli(subparsers: Any, _client: Optional[ArkClient]) -> None:
    p = subparsers.add_parser("storage", help="storage module commands")
    sub = p.add_subparsers(dest="storage_subcommand")
    pb = sub.add_parser("bitlocker", help="query bitlocker volumes")
    pb.set_defaults(_handler=_cmd_storage_bitlocker)


def _cmd_storage_bitlocker(_args: argparse.Namespace) -> int:
    client = ArkClient.open_or_null()
    if client is None:
        print("driver not installed", file=sys.stderr)
        return 2
    try:
        out = _query_bitlocker(client)
        print(f"count={out.Count}")
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