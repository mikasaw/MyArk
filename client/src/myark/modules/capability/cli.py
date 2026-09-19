"""
capability R3 - CLI subcommands.

The capability module is R0-only: every ``myark-cli capability report``
call turns into one DeviceIoControl against ``\\\\.\\MyArkCore``. When
the driver is not installed the CLI prints a friendly "driver not
installed" message and exits 2.

Usage:
    myark-cli capability report
    myark-cli capability report --max-entries 32
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional

from myark.client.ark_client import ArkClient, DriverError

from . import parser as P


def _open_or_complain() -> Optional[ArkClient]:
    """Open the driver or print a stderr message and return None."""
    client = ArkClient.open_or_null()
    if client is None:
        print(
            "!! capability: MyArkCore driver not installed (run inside Hyper-V VM with testsigning on)",
            file=sys.stderr,
        )
        return None
    return client


def _cmd_report(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    if client is None:
        return 2
    try:
        report = P.query_report(client, max_entries=args.max_entries)
        print(
            f"# capability: driver={report.version_major}.{report.version_minor}"
            f".{report.version_build} modules={report.total_modules}"
            f" ioctls={report.total_ioctls}"
        )
        for entry in report.entries:
            flags = []
            if entry.flags & P.CAPABILITY_FLAG_R0:
                flags.append("R0")
            if entry.flags & P.CAPABILITY_FLAG_R3:
                flags.append("R3")
            if entry.flags & P.CAPABILITY_FLAG_ENABLED:
                flags.append("ENABLED")
            flag_str = "|".join(flags) if flags else "-"
            print(
                f"  module={entry.module_name:<24} id=0x{entry.module_id:08X}"
                f" ioctls={entry.ioctl_count:<3} flags={flag_str}"
            )
        return 0
    except (DriverError, OSError, RuntimeError) as exc:
        print(f"!! capability: DeviceIoControl failed: {exc}", file=sys.stderr)
        return 3
    finally:
        try:
            client.close()
        except Exception:
            pass


def _setup_cli(subparsers, _client=None) -> None:
    """Wire the ``myark-cli capability report`` subtree."""
    p_root = subparsers.add_parser(
        "capability",
        help="capability module commands (R0 driver self-report)",
    )
    p_root.set_defaults(_handler=_cmd_root)

    p_subs = p_root.add_subparsers(dest="capability_subcommand", required=True)

    p_report = p_subs.add_parser(
        "report",
        help="query the driver for its capability table",
    )
    p_report.add_argument(
        "--max-entries",
        type=int,
        default=64,
        help="max module entries to request (default 64, capped by driver HARD_CAP)",
    )
    p_report.set_defaults(_handler=_cmd_report)


def _cmd_root(args: argparse.Namespace) -> int:
    print("!! capability: missing subcommand (try `myark-cli capability report`)", file=sys.stderr)
    return 2


__all__ = ["_setup_cli"]