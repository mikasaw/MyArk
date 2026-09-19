"""
preflight R3 - CLI subcommands.

The preflight module is R3-primary: ``myark-cli preflight health`` returns
a best-effort environment health snapshot even when the driver is not
installed. When the driver IS installed the R3 client overlays the R0
reply with bcdedit / Secure Boot / Defender state.

Usage:
    myark-cli preflight health
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional

from myark.client.ark_client import ArkClient

from . import parser as P


def _open_or_complain() -> Optional[ArkClient]:
    """Open the driver or return None (parser will fall back to R3-only)."""
    return ArkClient.open_or_null()


def health_rows(report: P.HealthReport) -> list[tuple[str, object]]:
    """The 6 key/value rows the CLI one-liner and the S10.10 UI tab render.

    Single source of truth so the two surfaces cannot drift: values keep
    their natural types (str / int) and each consumer picks the textual
    form -- the CLI prints booleans as 0/1, the UI as True/False. Row
    order is the UI's; the CLI re-orders ``source`` to the front of its
    one-liner.
    """
    return [
        ("os", f"{report.major_version}.{report.minor_version}.{report.build_number}"),
        ("testsigning", report.is_test_signing),
        ("secure_boot", report.is_secure_boot),
        ("driver_signed", report.is_driver_signed),
        ("flags", report.flags),
        ("source", report.source),
    ]


def _cmd_health(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    try:
        report = P.query_health(client)
        values = dict(health_rows(report))
        print(
            f"# preflight: source={values['source']}"
            f" os={values['os']}"
            f" testsigning={values['testsigning']}"
            f" secure_boot={values['secure_boot']}"
            f" driver_signed={values['driver_signed']}"
            f" flags=0x{values['flags']:X}"
        )
        if report.kernel_base:
            print(
                f"  kernel=0x{report.kernel_base:X} size=0x{report.kernel_size:X}"
            )
        if report.note:
            print(f"  note: {report.note}")
        return 0
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _setup_cli(subparsers, _client=None) -> None:
    """Wire the ``myark-cli preflight health`` subtree."""
    p_root = subparsers.add_parser(
        "preflight",
        help="preflight module commands (environment health check)",
    )
    p_root.set_defaults(_handler=_cmd_root)

    p_subs = p_root.add_subparsers(dest="preflight_subcommand", required=True)

    p_health = p_subs.add_parser(
        "health",
        help="query the environment health snapshot",
    )
    p_health.set_defaults(_handler=_cmd_health)


def _cmd_root(args: argparse.Namespace) -> int:
    print("!! preflight: missing subcommand (try `myark-cli preflight health`)", file=sys.stderr)
    return 2


__all__ = ["_setup_cli", "health_rows"]