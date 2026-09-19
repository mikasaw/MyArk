"""
mutation R3 - CLI subcommands.

Usage:
    myark-cli mutation inspect-token <pid>
"""

from __future__ import annotations

import argparse
import sys

from myark.client.ark_client import ArkClient

from . import parser as P


def _open_or_complain() -> "ArkClient | None":
    return ArkClient.open_or_null()


def _cmd_inspect(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    try:
        r = P.inspect_token(client, args.pid)
        print(f"# mutation inspect-token: source={r.source} pid={r.process_id} flags={r.token_flags:#x} addr={r.token_address:#x}")
        return 0
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _setup_cli(subparsers, _client=None) -> None:
    p_root = subparsers.add_parser(
        "mutation",
        help="mutation module (EPROCESS Token inspection; stub for S7.3)",
    )
    p_root.set_defaults(_handler=_cmd_root)

    p_subs = p_root.add_subparsers(dest="mutation_subcommand", required=True)

    p1 = p_subs.add_parser("inspect-token", help="inspect a process EPROCESS.Token")
    p1.add_argument("pid", type=int, help="target process id")
    p1.set_defaults(_handler=_cmd_inspect)


def _cmd_root(_args: argparse.Namespace) -> int:
    print("!! mutation: missing subcommand", file=sys.stderr)
    return 2


__all__ = ["_setup_cli"]
