"""
kernel_object R3 - CLI subcommands.

Usage:
    myark-cli object dir <path>     walk one object directory
    myark-cli object types          list object types (\\ObjectTypes)
    myark-cli object ipc            named pipes + mailslots summary
"""

from __future__ import annotations

import argparse
import sys

from myark.client.ark_client import ArkClient

from . import parser as P


def _open_or_complain() -> "ArkClient | None":
    return ArkClient.open_or_null()


def _cmd_dir(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    try:
        report = P.query_directory(client, args.path)
        status = f" open_status=0x{report.open_status:08X}" if report.open_status else ""
        print(f"# object dir {args.path}: count={report.count}{status}")
        for e in report.entries:
            print(f"  {e.name}  ({e.type_name})")
        return 0
    except (ValueError, ConnectionError) as exc:
        print(f"!! object dir: {exc}", file=sys.stderr)
        return 2
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _cmd_types(_args: argparse.Namespace) -> int:
    client = _open_or_complain()
    try:
        report = P.query_directory(client, "\\ObjectTypes")
        print(f"# object types: count={report.count}")
        names = sorted(e.name for e in report.entries)
        for n in names:
            print(f"  {n}")
        return 0
    except (ValueError, ConnectionError) as exc:
        print(f"!! object types: {exc}", file=sys.stderr)
        return 2
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _cmd_ipc(_args: argparse.Namespace) -> int:
    client = _open_or_complain()
    try:
        report = P.ipc_summary(client)
        print(f"# ipc summary: pipes={len(report.pipes)} mailslots={len(report.mailslots)}")
        print("  [named pipes]")
        for e in report.pipes:
            print(f"    {e.name}")
        print("  [mailslots]")
        for e in report.mailslots:
            print(f"    {e.name}")
        return 0
    except (ValueError, ConnectionError) as exc:
        print(f"!! object ipc: {exc}", file=sys.stderr)
        return 2
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _cmd_root(_args: argparse.Namespace) -> int:
    print("!! object: missing subcommand "
          "(try `myark-cli object dir \\Device`)", file=sys.stderr)
    return 2


def _setup_cli(subparsers, _client=None) -> None:
    p_root = subparsers.add_parser(
        "object",
        help="kernel object namespace + IPC summary (R0; read-only)",
    )
    p_root.set_defaults(_handler=_cmd_root)

    p_subs = p_root.add_subparsers(dest="object_subcommand", required=True)

    p1 = p_subs.add_parser("dir", help="walk one object directory")
    p1.add_argument("path", help="object-manager path, e.g. \\Device")
    p1.set_defaults(_handler=_cmd_dir)

    p2 = p_subs.add_parser("types", help="list object types (\\ObjectTypes)")
    p2.set_defaults(_handler=_cmd_types)

    p3 = p_subs.add_parser("ipc", help="named pipes + mailslots summary")
    p3.set_defaults(_handler=_cmd_ipc)


__all__ = ["_setup_cli"]
