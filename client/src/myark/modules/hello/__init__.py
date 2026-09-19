"""Hello module -- minimum-viable client for IOCTL_MYARK_HELLO_PING.

The matching driver code lives in
``driver/src/modules/00_hello/``; the shared protocol is in
``shared/driver/MyArkHelloIoctl.h``. This module exists purely to verify
that the module-mechanism plumbing works end-to-end:

- Driver side  -- ``MYARK_MODULE_HELLO`` profile macro gates the IOCTL
  entry from being linked into the ``.sys`` at all.
- Registry side -- ``HKLM\\...\\MyArkCore\\Modules\\hello = 0`` flips the
  runtime mask; ``Init()`` is skipped at ``sc start`` time.
- Client side  -- the UI shows a "hello" tab and the CLI gains a
  ``hello ping`` subcommand, both routed through the global IOCTL table.

A round-trip ``hello ping --name test`` that returns ``Hello, test! ...``
proves the full stack is wired.
"""

from __future__ import annotations

import argparse
import ctypes
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


# Mirrors IOCTL_MYARK_HELLO_PING = CTL_CODE(0x22, 0x900, 0, 0).
IOCTL_MYARK_HELLO_PING = (0x22 << 16) | (0x900 << 2)
IOCTL_MYARK_HELLO_GREET = (0x22 << 16) | (0x901 << 2)


class MYARK_HELLO_PING_INPUT(ctypes.Structure):
    _fields_ = [("Name", ctypes.c_char * 64)]


class MYARK_HELLO_PING_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Greeting", ctypes.c_char * 128),
        ("BuildNumber", ctypes.c_uint32),
        ("ModuleId", ctypes.c_uint32),
        ("TickCount", ctypes.c_uint32),
    ]


class MYARK_HELLO_GREET_INPUT(ctypes.Structure):
    _fields_ = [("Name", ctypes.c_wchar * 64)]


class MYARK_HELLO_GREET_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Greeting", ctypes.c_wchar * 128),
        ("BuildNumber", ctypes.c_uint32),
        ("ModuleId", ctypes.c_uint32),
        ("Timestamp", ctypes.c_uint64),
    ]


REQUIRED_NAME_MAX = 64


def _ping_via_client(client: ArkClient, name: str) -> MYARK_HELLO_PING_OUTPUT:
    """Drive IOCTL_MYARK_HELLO_PING through the shared client handle.

    Re-uses :class:`ArkClient`'s raw device I/O plumbing rather than
    poking ``DeviceIoControl`` directly, so we exercise the same buffer
    marshalling the rest of the tool uses. The output struct is filled
    in place and returned for the caller to inspect.
    """
    encoded = name.encode("ascii", errors="replace")[: REQUIRED_NAME_MAX - 1]
    in_buf = MYARK_HELLO_PING_INPUT(Name=encoded.ljust(REQUIRED_NAME_MAX, b"\x00"))

    out = MYARK_HELLO_PING_OUTPUT()

    # Walk the client transport to keep IOCTL handling uniform across the
    # codebase: ArkClient.ioctl packs the input struct and fills the output
    # struct in place.
    client.ioctl(IOCTL_MYARK_HELLO_PING, in_buf, out)
    return out


def _greet_via_client(client: ArkClient, name: str) -> MYARK_HELLO_GREET_OUTPUT:
    """Drive IOCTL_MYARK_HELLO_GREET (WCHAR variant) through the client handle.

    Mirrors :func:`_ping_via_client` but on the WCHAR wire path; the
    Timestamp field lets callers measure driver-side dispatch latency.
    """
    in_buf = MYARK_HELLO_GREET_INPUT(Name=name[: REQUIRED_NAME_MAX - 1].ljust(REQUIRED_NAME_MAX, "\x00"))

    out = MYARK_HELLO_GREET_OUTPUT()

    client.ioctl(IOCTL_MYARK_HELLO_GREET, in_buf, out)
    return out


def register(
    client: Optional[ArkClient],
    capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    """Entry point for the myark.modules plugin group."""
    return ModuleRegistration(
        name="hello",
        register_fn=register,
        ui_factory=_build_ui,
        cli_setup=_setup_cli,
        description="Hello module - mechanism verification probe",
    )


# ----------------------------------------------------------------- UI


def _build_ui(parent: Any, client: Optional[ArkClient]) -> ttk.Frame:
    """One-tab Tkinter widget: a name field + a ping button + a status line."""

    status_var = tk.StringVar(value="(not yet pinged)")
    name_var = tk.StringVar(value="world")

    frame = ttk.Frame(parent, padding=12)

    ttk.Label(
        frame,
        text="Hello module",
        font=("Segoe UI", 12, "bold"),
    ).grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 6))

    ttk.Label(
        frame,
        text=(
            "Mechanism verification -- confirms compile-time macro gate + "
            "runtime registry mask are wired end-to-end."
        ),
        wraplength=480,
        justify=tk.LEFT,
    ).grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=(0, 8))

    ttk.Label(frame, text="Name:").grid(row=2, column=0, sticky=tk.W, pady=2)
    name_entry = ttk.Entry(frame, textvariable=name_var, width=32)
    name_entry.grid(row=2, column=1, sticky=tk.W, pady=2)

    def _on_ping() -> None:
        if client is None:
            status_var.set("driver not installed -- cannot ping")
            return
        try:
            out = _ping_via_client(client, name_var.get())
            greeting = out.Greeting.split(b"\x00", 1)[0].decode("ascii", errors="replace")
            status_var.set(
                f"OK: {greeting} (build={out.BuildNumber}, mod=0x{out.ModuleId:08X}, "
                f"ticks={out.TickCount})"
            )
        except DriverCallError as exc:
            status_var.set(f"IOCTL failed: Win32 error 0x{exc.errno & 0xFFFFFFFF:08X}")
        except DriverError as exc:
            status_var.set(f"driver error: {exc}")
        except OSError as exc:
            status_var.set(f"OSError: errno={exc.errno}")

    ttk.Button(frame, text="Ping driver", command=_on_ping).grid(
        row=3, column=0, columnspan=2, sticky=tk.W, pady=4
    )

    ttk.Label(frame, textvariable=status_var, wraplength=480, justify=tk.LEFT).grid(
        row=4, column=0, columnspan=2, sticky=tk.W, pady=(4, 0)
    )

    frame.columnconfigure(1, weight=1)
    return frame


# ----------------------------------------------------------------- CLI


def _setup_cli(subparsers: Any, _client: Optional[ArkClient]) -> None:
    """Wire a ``myark-cli hello ping`` subcommand into the CLI parser."""
    hello_p = subparsers.add_parser(
        "hello",
        help="hello module commands (mechanism verification)",
    )
    hello_subs = hello_p.add_subparsers(dest="hello_subcommand")

    p_ping = hello_subs.add_parser("ping", help="send a ping to the driver")
    p_ping.add_argument(
        "--name",
        default="world",
        help="name to greet (default: world)",
    )
    p_ping.set_defaults(_handler=_cmd_hello_ping)


def _cmd_hello_ping(args: argparse.Namespace) -> int:
    """``myark-cli hello ping --name X`` handler."""
    client = ArkClient.open_or_null()
    if client is None:
        print("driver not installed -- cannot ping", file=__import__("sys").stderr)
        return 2
    try:
        out = _ping_via_client(client, args.name)
    except DriverCallError as exc:
        print(f"IOCTL failed: Win32 error 0x{exc.errno & 0xFFFFFFFF:08X}", file=__import__("sys").stderr)
        client.close()
        return 3
    except DriverError as exc:
        print(f"driver error: {exc}", file=__import__("sys").stderr)
        client.close()
        return 3
    finally:
        try:
            client.close()
        except Exception:
            pass

    greeting = out.Greeting.split(b"\x00", 1)[0].decode("ascii", errors="replace")
    print(greeting)
    print(f"build={out.BuildNumber} module_id=0x{out.ModuleId:08X} tick={out.TickCount}")
    return 0


__all__ = ["register", "IOCTL_MYARK_HELLO_PING", "IOCTL_MYARK_HELLO_GREET",
           "_ping_via_client", "_greet_via_client"]