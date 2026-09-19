"""
security-audit R3 - CLI subcommands.

Usage:
    myark-cli security_audit defender
    myark-cli security_audit secure-boot
    myark-cli security_audit trusted-boot

The row builders below are shared with the module's UI tab
(``myark.modules.security_audit.ui``): the CLI prints them and the UI
tables them, so both surfaces always show the same field values.
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional

from myark.client.ark_client import ArkClient

from . import parser as P


def _open_or_complain() -> Optional[ArkClient]:
    return ArkClient.open_or_null()


# ---- shared row builders (CLI print + UI table) -----------------------


def defender_row(client: Optional[ArkClient]) -> dict:
    """`security_audit defender` row data (shared by CLI + UI)."""
    report = P.query_defender(client)
    return {
        "item": "defender",
        "source": report.source,
        "status_kv": (
            f"installed={report.is_installed}"
            f" running={report.is_running}"
            f" realtime={report.is_realtime_enabled}"
        ),
        "note": report.note,
    }


def secure_boot_row(client: Optional[ArkClient]) -> dict:
    """`security_audit secure-boot` row data (shared by CLI + UI)."""
    report = P.query_secure_boot(client)
    return {
        "item": "secure-boot",
        "source": report.source,
        "status_kv": f"enabled={report.is_enabled}",
        "note": report.note,
    }


def trusted_boot_row(client: Optional[ArkClient]) -> dict:
    """`security_audit trusted-boot` row data (shared by CLI + UI)."""
    report = P.query_trusted_boot(client)
    return {
        "item": "trusted-boot",
        "source": report.source,
        "status_kv": (
            f"measured_boot={report.is_measured_boot_enabled}"
            f" event_log={report.is_event_log_present}"
        ),
        "note": report.note,
    }


def audit_rows(client: Optional[ArkClient]) -> list[dict]:
    """All three audit rows in tab order (used by the security_audit UI)."""
    return [defender_row(client), secure_boot_row(client), trusted_boot_row(client)]


# ---- CLI subcommands ---------------------------------------------------


def _cmd_defender(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    try:
        row = defender_row(client)
        print(f"# security_audit defender: source={row['source']} {row['status_kv']}")
        if row["note"]:
            print(f"  note: {row['note']}")
        return 0
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _cmd_secure_boot(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    try:
        row = secure_boot_row(client)
        print(f"# security_audit secure-boot: source={row['source']} {row['status_kv']}")
        if row["note"]:
            print(f"  note: {row['note']}")
        return 0
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _cmd_trusted_boot(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    try:
        row = trusted_boot_row(client)
        print(f"# security_audit trusted-boot: source={row['source']} {row['status_kv']}")
        if row["note"]:
            print(f"  note: {row['note']}")
        return 0
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _setup_cli(subparsers, _client=None) -> None:
    p_root = subparsers.add_parser(
        "security_audit",
        help="security-audit module commands (Defender / Secure Boot / Trusted Boot)",
    )
    p_root.set_defaults(_handler=_cmd_root)

    p_subs = p_root.add_subparsers(dest="secaudit_subcommand", required=True)

    p1 = p_subs.add_parser("defender", help="query Defender activity state")
    p1.set_defaults(_handler=_cmd_defender)

    p2 = p_subs.add_parser("secure-boot", help="query Secure Boot status")
    p2.set_defaults(_handler=_cmd_secure_boot)

    p3 = p_subs.add_parser("trusted-boot", help="query Trusted Boot (measured boot) status")
    p3.set_defaults(_handler=_cmd_trusted_boot)


def _cmd_root(args: argparse.Namespace) -> int:
    print("!! security_audit: missing subcommand (try `myark-cli security_audit defender`)", file=sys.stderr)
    return 2


__all__ = [
    "_setup_cli",
    "defender_row",
    "secure_boot_row",
    "trusted_boot_row",
    "audit_rows",
]
