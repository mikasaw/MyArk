"""
authentication R3 - CLI subcommands.

Usage:
    myark-cli authentication verify-file <path>
"""

from __future__ import annotations

import argparse
import sys

from myark.client.ark_client import ArkClient

from . import parser as P


def _open_or_complain() -> "ArkClient | None":
    return ArkClient.open_or_null()


def _cmd_verify(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    try:
        r = P.verify_file(client, args.path)
        print(f"# authentication verify-file: source={r.source} path={args.path} status={r.status_name}")
        return 0
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _setup_cli(subparsers, _client=None) -> None:
    p_root = subparsers.add_parser(
        "authentication",
        help="authentication module (Authenticode stub; R3 WinVerifyTrust is primary)",
    )
    p_root.set_defaults(_handler=_cmd_root)

    p_subs = p_root.add_subparsers(dest="authentication_subcommand", required=True)

    p1 = p_subs.add_parser("verify-file", help="verify a PE / catalog signature")
    p1.add_argument("path", help="path to file")
    p1.set_defaults(_handler=_cmd_verify)


def _cmd_root(_args: argparse.Namespace) -> int:
    print("!! authentication: missing subcommand", file=sys.stderr)
    return 2


__all__ = ["_setup_cli"]
