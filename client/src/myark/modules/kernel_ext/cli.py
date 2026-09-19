"""
kernel_ext R3 - CLI subcommands.

Usage:
    myark-cli kernel_ext query-win11 <class>
    myark-cli kernel_ext read-syscall-table
"""

from __future__ import annotations

import argparse
import sys

from myark.client.ark_client import ArkClient

from . import parser as P
from . import protocol as PP


def _open_or_complain() -> "ArkClient | None":
    return ArkClient.open_or_null()


def _cmd_query(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    try:
        info_class = args.info_class if args.info_class is not None else PP.KERNEL_EXT_WIN11_INFO_BASE
        blob = P.query_win11_info(client, info_class)
        print(
            f"# kernel_ext query-win11: source={blob.source}"
            f" class={blob.info_class:#x}"
            f" status={blob.status:#x}"
            f" bytes={blob.bytes_returned}"
        )
        return 0
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _cmd_table(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    try:
        table = P.read_syscall_table(client)
        print(f"# kernel_ext read-syscall-table: source={table.source} count={len(table.entries)}")
        return 0
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _setup_cli(subparsers, _client=None) -> None:
    p_root = subparsers.add_parser(
        "kernel_ext",
        help="kernel_ext module (extends DynData with Win11 25H2 info classes)",
    )
    p_root.set_defaults(_handler=_cmd_root)

    p_subs = p_root.add_subparsers(dest="kernel_ext_subcommand", required=True)

    p1 = p_subs.add_parser("query-win11", help="query a Win11 25H2 info class")
    p1.add_argument("--class", dest="info_class", type=lambda s: int(s, 0),
                    default=PP.KERNEL_EXT_WIN11_INFO_BASE,
                    help="SystemInformationClass (default 0xAD)")
    p1.set_defaults(_handler=_cmd_query)

    p2 = p_subs.add_parser("read-syscall-table", help="read the syscall table (R0 walk)")
    p2.set_defaults(_handler=_cmd_table)


def _cmd_root(_args: argparse.Namespace) -> int:
    print("!! kernel_ext: missing subcommand (try `myark-cli kernel_ext query-win11`)", file=sys.stderr)
    return 2


__all__ = ["_setup_cli"]
