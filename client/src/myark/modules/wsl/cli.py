"""
wsl R3 - CLI subcommands.

Usage:
    myark-cli wsl enumerate-silos
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
        report = P.enumerate_silos(client)
        print(f"# wsl enumerate-silos: source={report.source} count={report.count}")
        return 0
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _setup_cli(subparsers, _client=None) -> None:
    p_root = subparsers.add_parser(
        "wsl",
        help="wsl module (WSL silo enumeration; stub for S7.3)",
    )
    p_root.set_defaults(_handler=_cmd_root)

    p_subs = p_root.add_subparsers(dest="wsl_subcommand", required=True)

    p1 = p_subs.add_parser("enumerate-silos", help="enumerate WSL silos")
    p1.set_defaults(_handler=_cmd_enumerate)


def _cmd_root(_args: argparse.Namespace) -> int:
    print("!! wsl: missing subcommand (try `myark-cli wsl enumerate-silos`)", file=sys.stderr)
    return 2


__all__ = ["_setup_cli"]
