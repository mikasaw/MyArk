"""
win32k R3 - CLI subcommands.

Usage:
    myark-cli win32k enumerate-gui-threads
    myark-cli win32k enumerate-hooks
    myark-cli win32k handles [--type N]
    myark-cli win32k timers
"""

from __future__ import annotations

import argparse
import sys

from myark.client.ark_client import ArkClient

from . import parser as P


def _open_or_complain() -> "ArkClient | None":
    return ArkClient.open_or_null()


def _cmd_threads(_args: argparse.Namespace) -> int:
    client = _open_or_complain()
    try:
        r = P.enumerate_gui_threads(client)
        print(f"# win32k enumerate-gui-threads: source={r.source} count={r.count}")
        return 0
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _cmd_hooks(_args: argparse.Namespace) -> int:
    client = _open_or_complain()
    try:
        r = P.enumerate_hooks(client)
        print(f"# win32k enumerate-hooks: source={r.source} count={r.count}")
        return 0
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _cmd_handles(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    try:
        r = P.enum_user_handles(client)
        diag = f" diag=0x{r.diag_status:08X}" if r.diag_status else ""
        print(f"# win32k handles: source={r.source} count={r.count}"
              f" shared_info=0x{r.shared_info:X} ahe_list=0x{r.ahe_list:X}"
              f" he_entry_size={r.he_entry_size} scanned={r.scanned_slots}{diag}")
        for e in r.entries:
            if args.type is None or e.type == args.type:
                print(f"  [{e.index:6d}] {e.type_name:<12} obj=0x{e.kernel_object:016X}"
                      f" user=0x{e.user_pointer:016X} flags={e.flags:#x}")
        return 0
    except (ValueError, ConnectionError, OSError) as exc:
        print(f"!! win32k handles: {exc}", file=sys.stderr)
        return 2
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _cmd_timers(_args: argparse.Namespace) -> int:
    client = _open_or_complain()
    try:
        r = P.enum_timers(client)
        diag = f" diag=0x{r.diag_status:08X}" if r.diag_status else ""
        print(f"# win32k timers: source={r.source} count={r.count}"
              f" hash_table=0x{r.timer_hash_table:X} session_base=0x{r.session_base:X}"
              f" buckets={r.bucket_count} node_size=0x{r.node_size:X}"
              f" scanned={r.scanned_buckets}{diag}")
        for e in r.entries:
            proc = f" proc=0x{e.timer_proc:X}" if e.timer_proc else ""
            print(f"  [{e.index:3d}] id={e.timer_id:#06x} {e.kind:<7}"
                  f" elapse={e.elapse_ms:6d}ms wnd=0x{e.window:012X}"
                  f" pti=0x{e.pti:012X}{proc}")
        return 0
    except (ValueError, ConnectionError, OSError) as exc:
        print(f"!! win32k timers: {exc}", file=sys.stderr)
        return 2
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _setup_cli(subparsers, _client=None) -> None:
    p_root = subparsers.add_parser(
        "win32k",
        help="win32k module (GUI threads / hooks / USER handle table)",
    )
    p_root.set_defaults(_handler=_cmd_root)

    p_subs = p_root.add_subparsers(dest="win32k_subcommand", required=True)

    p1 = p_subs.add_parser("enumerate-gui-threads", help="enumerate GUI threads")
    p1.set_defaults(_handler=_cmd_threads)

    p2 = p_subs.add_parser("enumerate-hooks", help="enumerate win32k hooks")
    p2.set_defaults(_handler=_cmd_hooks)

    p3 = p_subs.add_parser(
        "handles",
        help="walk the USER handle table (windows/hooks/menus, R3-10a)",
    )
    p3.add_argument("--type", type=int, default=None,
                    help="filter by raw TYPE_* id (e.g. 1=Window, 5=Hook)")
    p3.set_defaults(_handler=_cmd_handles)

    p4 = p_subs.add_parser(
        "timers",
        help="walk the session timer hash table (window/thread timers, R3-10b-iii)",
    )
    p4.set_defaults(_handler=_cmd_timers)


def _cmd_root(_args: argparse.Namespace) -> int:
    print("!! win32k: missing subcommand", file=sys.stderr)
    return 2


__all__ = ["_setup_cli"]
