"""
trust R3 - CLI subcommands.

Usage:
    myark-cli trust verify-pe C:\Windows\System32\notepad.exe
    myark-cli trust verify-catalog C:\path\to\file

The row builder below is shared with the module's UI panel
(``myark.modules.trust.ui``): the CLI prints it and the UI tables it,
so both surfaces always show the same field values.
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional

from myark.client.ark_client import ArkClient

from . import parser as P
from . import protocol as PP


def _open_or_complain() -> Optional[ArkClient]:
    return ArkClient.open_or_null()


# ---- shared row builder (CLI print + UI table) -------------------------

_TRUST_KNOWN_FLAGS = (
    PP.TRUST_FLAG_CATALOG,
    PP.TRUST_FLAG_EMBEDDED,
    PP.TRUST_FLAG_TIMESTAMP,
)
_TRUST_FLAG_NAMES = {
    PP.TRUST_FLAG_CATALOG: "catalog",
    PP.TRUST_FLAG_EMBEDDED: "embedded",
    PP.TRUST_FLAG_TIMESTAMP: "timestamp",
}


def _flags_text(flags: int) -> str:
    """Human-readable flag decomposition, e.g. ``embedded|timestamp``."""
    parts = [
        _TRUST_FLAG_NAMES[bit]
        for bit in _TRUST_KNOWN_FLAGS
        if flags & bit
    ]
    unknown = flags
    for bit in _TRUST_KNOWN_FLAGS:
        unknown &= ~bit
    if unknown:
        parts.append(f"0x{unknown:08X}")
    return "|".join(parts)


def verify_pe_row(client: Optional[ArkClient], path: str) -> dict:
    """`trust verify-pe` row data (shared by CLI + UI)."""
    result = P.verify_pe(client, path)
    return {
        "path": path,
        "status": result.status_name,
        "source": result.source,
        "subject": result.subject,
        "issuer": result.issuer,
        "flags": _flags_text(result.flags),
    }


# ---- CLI subcommands ---------------------------------------------------


def _cmd_verify_pe(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    try:
        row = verify_pe_row(client, args.path)
        print(
            f"# trust verify-pe: source={row['source']}"
            f" path={row['path']}"
            f" status={row['status']}"
        )
        if row["subject"] or row["issuer"]:
            print(f"  subject={row['subject']}")
            print(f"  issuer={row['issuer']}")
        return 0
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _cmd_verify_catalog(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    try:
        result = P.verify_catalog(client, args.path)
        print(
            f"# trust verify-catalog: source={result.source}"
            f" path={args.path}"
            f" status={result.status_name}"
        )
        return 0
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _setup_cli(subparsers, _client=None) -> None:
    p_root = subparsers.add_parser(
        "trust",
        help="trust module commands (PE / catalog signature verification)",
    )
    p_root.set_defaults(_handler=_cmd_root)

    p_subs = p_root.add_subparsers(dest="trust_subcommand", required=True)

    p1 = p_subs.add_parser("verify-pe", help="verify a PE signature (R3 primary, R0 fallback)")
    p1.add_argument("path", help="path to PE file")
    p1.set_defaults(_handler=_cmd_verify_pe)

    p2 = p_subs.add_parser("verify-catalog", help="verify a catalog signature")
    p2.add_argument("path", help="path to file")
    p2.set_defaults(_handler=_cmd_verify_catalog)


def _cmd_root(args: argparse.Namespace) -> int:
    print("!! trust: missing subcommand (try `myark-cli trust verify-pe <path>`)", file=sys.stderr)
    return 2


__all__ = ["_setup_cli"]
