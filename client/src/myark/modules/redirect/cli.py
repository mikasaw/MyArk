"""
redirect R3 - CLI subcommands.

Usage:
    myark-cli redirect inspect
"""

from __future__ import annotations

import argparse
import sys

from myark.client.ark_client import ArkClient

from . import parser as P


def _open_or_complain() -> "ArkClient | None":
    return ArkClient.open_or_null()


def _cmd_inspect(_args: argparse.Namespace) -> int:
    client = _open_or_complain()
    try:
        r = P.inspect_redirects(client)
        print(f"# redirect inspect: source={r.source} count={r.count}")
        return 0
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _setup_cli(subparsers, _client=None) -> None:
    p_root = subparsers.add_parser(
        "redirect",
        help="redirect module (IoCallDriver / CmCallback inspection; stub for S7.3)",
    )
    p_root.set_defaults(_handler=_cmd_root)

    p_subs = p_root.add_subparsers(dest="redirect_subcommand", required=True)

    p1 = p_subs.add_parser("inspect", help="inspect IoCallDriver / CmCallback redirect chains")
    p1.set_defaults(_handler=_cmd_inspect)


def _cmd_root(_args: argparse.Namespace) -> int:
    print("!! redirect: missing subcommand", file=sys.stderr)
    return 2


__all__ = ["_setup_cli"]
