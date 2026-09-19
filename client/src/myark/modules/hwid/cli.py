"""
hwid R3 - CLI subcommands.

Usage:
    myark-cli hwid enumerate-mj
"""

from __future__ import annotations

import argparse
import sys

from myark.client.ark_client import ArkClient

from . import parser as P


def _open_or_complain() -> "ArkClient | None":
    return ArkClient.open_or_null()


def _cmd_enumerate(_args: argparse.Namespace) -> int:
    client = _open_or_complain()
    try:
        report = P.enumerate_mj(client)
        print(f"# hwid enumerate-mj: source={report.source} count={report.count}")
        return 0
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _setup_cli(subparsers, _client=None) -> None:
    p_root = subparsers.add_parser(
        "hwid",
        help="hwid module (MajorFunction inspection; ENUMERATE_MJ stub for S7.3)",
    )
    p_root.set_defaults(_handler=_cmd_root)

    p_subs = p_root.add_subparsers(dest="hwid_subcommand", required=True)

    p1 = p_subs.add_parser("enumerate-mj", help="enumerate driver MajorFunction tables")
    p1.set_defaults(_handler=_cmd_enumerate)


def _cmd_root(_args: argparse.Namespace) -> int:
    print("!! hwid: missing subcommand (try `myark-cli hwid enumerate-mj`)", file=sys.stderr)
    return 2


__all__ = ["_setup_cli"]
