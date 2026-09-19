"""
callback R3 - CLI subcommands.

The callback module is R0-only: every ``myark-cli callback <command>``
call turns into one DeviceIoControl against ``\\\\.\\MyArkCore``. When the
driver is not installed the CLI prints a friendly "driver not installed"
message and exits 2 -- no crash, no stack trace.

Usage examples:
    myark-cli callback query ps
    myark-cli callback query cm
    myark-cli callback query ob
    myark-cli callback query image
    myark-cli callback query dbg
    myark-cli callback enumerate
    myark-cli callback stats
    myark-cli callback remove --category ps --index 0   # reserved (S7.2-fix)
    myark-cli callback restore --category ps --index 0  # reserved (S7.2-fix)
    myark-cli callback backup                            # reserved (S7.2-fix)
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional

from myark.client.ark_client import ArkClient, DriverError

from . import parser as P


QUERY_NAMES = (
    "ps",
    "cm",
    "ob",
    "image",
    "dbg",
)


def _open_or_complain() -> Optional[ArkClient]:
    """Open the driver or print a stderr message and return None."""
    client = ArkClient.open_or_null()
    if client is None:
        print(
            "!! callback: MyArkCore driver not installed (run inside Hyper-V VM with testsigning on)",
            file=sys.stderr,
        )
        return None
    return client


def _format_extra(result: P.CallbackResult) -> str:
    """Render the extra diagnostics as a single line (key=value pairs)."""
    if not result.extra:
        return ""
    return " ".join(f"{k}={v:x}" if isinstance(v, int) else f"{k}={v}"
                    for k, v in result.extra.items())


# ---------------------------------------------------------------------------
# Per-query handlers (single-arg signature, matching memory/process modules).
# Each handler opens the driver lazily, runs one IOCTL, prints one summary
# line, and returns 0 / 2 / 3.
# ---------------------------------------------------------------------------

def _cmd_query_ps(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    if client is None:
        return 2
    try:
        result = P.query_ps(client, max_entries=args.max_entries)
        line = f"# method=r0 query=ps count={result.count} total_seen={result.total_seen}"
        extra = _format_extra(result)
        if extra:
            line = f"{line} {extra}"
        print(line)
        return 0
    except (DriverError, OSError, RuntimeError) as exc:
        print(f"!! callback: DeviceIoControl failed: {exc}", file=sys.stderr)
        return 3
    finally:
        try:
            client.close()
        except Exception:
            pass


def _cmd_query_cm(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    if client is None:
        return 2
    try:
        result = P.query_cm(client, max_entries=args.max_entries)
        line = f"# method=r0 query=cm count={result.count} total_seen={result.total_seen}"
        extra = _format_extra(result)
        if extra:
            line = f"{line} {extra}"
        print(line)
        return 0
    except (DriverError, OSError, RuntimeError) as exc:
        print(f"!! callback: DeviceIoControl failed: {exc}", file=sys.stderr)
        return 3
    finally:
        try:
            client.close()
        except Exception:
            pass


def _cmd_query_ob(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    if client is None:
        return 2
    try:
        result = P.query_ob(client, max_entries=args.max_entries)
        line = f"# method=r0 query=ob count={result.count} total_seen={result.total_seen}"
        extra = _format_extra(result)
        if extra:
            line = f"{line} {extra}"
        print(line)
        return 0
    except (DriverError, OSError, RuntimeError) as exc:
        print(f"!! callback: DeviceIoControl failed: {exc}", file=sys.stderr)
        return 3
    finally:
        try:
            client.close()
        except Exception:
            pass


def _cmd_query_image(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    if client is None:
        return 2
    try:
        result = P.query_image(client, max_entries=args.max_entries)
        line = f"# method=r0 query=image count={result.count} total_seen={result.total_seen}"
        extra = _format_extra(result)
        if extra:
            line = f"{line} {extra}"
        print(line)
        return 0
    except (DriverError, OSError, RuntimeError) as exc:
        print(f"!! callback: DeviceIoControl failed: {exc}", file=sys.stderr)
        return 3
    finally:
        try:
            client.close()
        except Exception:
            pass


def _cmd_query_dbg(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    if client is None:
        return 2
    try:
        result = P.query_dbg(client, max_entries=args.max_entries)
        line = f"# method=r0 query=dbg count={result.count} total_seen={result.total_seen}"
        extra = _format_extra(result)
        if extra:
            line = f"{line} {extra}"
        print(line)
        return 0
    except (DriverError, OSError, RuntimeError) as exc:
        print(f"!! callback: DeviceIoControl failed: {exc}", file=sys.stderr)
        return 3
    finally:
        try:
            client.close()
        except Exception:
            pass


def _cmd_enumerate(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    if client is None:
        return 2
    try:
        result = P.enumerate(client,
                             max_entries=args.max_entries,
                             category_mask=args.category_mask)
        line = f"# method=r0 query=enumerate count={result.count} total_seen={result.total_seen}"
        extra = _format_extra(result)
        if extra:
            line = f"{line} {extra}"
        print(line)
        return 0
    except (DriverError, OSError, RuntimeError) as exc:
        print(f"!! callback: DeviceIoControl failed: {exc}", file=sys.stderr)
        return 3
    finally:
        try:
            client.close()
        except Exception:
            pass


def _cmd_stats(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    if client is None:
        return 2
    try:
        stats = P.stats(client)
        print(
            f"# method=r0 query=stats "
            f"ps={stats.ps_count} cm={stats.cm_count} ob={stats.ob_count}"
            f" image={stats.image_count} dbg={stats.dbg_count}"
            f" total={stats.total_count}"
        )
        return 0
    except (DriverError, OSError, RuntimeError) as exc:
        print(f"!! callback: DeviceIoControl failed: {exc}", file=sys.stderr)
        return 3
    finally:
        try:
            client.close()
        except Exception:
            pass


def _cmd_remove(args: argparse.Namespace) -> int:
    """S7.2-fix reserve: handler always returns 3 (NOT_IMPLEMENTED)."""
    print("!! callback: remove is reserved for S7.2-fix; not implemented", file=sys.stderr)
    return 3


def _cmd_restore(args: argparse.Namespace) -> int:
    """S7.2-fix reserve: handler always returns 3 (NOT_IMPLEMENTED)."""
    print("!! callback: restore is reserved for S7.2-fix; not implemented", file=sys.stderr)
    return 3


def _cmd_backup(args: argparse.Namespace) -> int:
    """S7.2-fix reserve: handler always returns 3 (NOT_IMPLEMENTED)."""
    print("!! callback: backup is reserved for S7.2-fix; not implemented", file=sys.stderr)
    return 3


# ---------------------------------------------------------------------------
# Argument wiring.
# ---------------------------------------------------------------------------

def _add_common_filter_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-entries", type=int, default=64,
                        help="max entries to request (default 64, capped by driver HARD_CAP)")


def _setup_cli(subparsers, _client=None) -> None:
    """Wire the ``myark-cli callback {query,enumerate,...}`` subtree.

    Structure is ``callback -> query -> {ps,cm,ob,image,dbg}`` so the
    spec path ``myark-cli callback query ps`` works alongside the
    short-form fallback registered by ``main()``. The intermediate
    ``query`` parser is required so S7.1's ``TypeError`` regression
    (handlers expected ``(client, args)`` but the dispatcher only passed
    ``args``) cannot recur on the S7.2 surface.
    """
    p_root = subparsers.add_parser(
        "callback",
        help="callback module commands (R0 inspection of Ps/Cm/Ob/Image/Dbg callbacks)",
    )
    p_root.set_defaults(_handler=_cmd_callback_root)

    p_root_subs = p_root.add_subparsers(dest="callback_subcommand", required=True)

    #
    # Intermediate "query" so dispatcher wires each leaf through a
    # query_kind-specific handler with a single (args) signature.
    #
    p_query = p_root_subs.add_parser(
        "query",
        help="send a single callback IOCTL (ps/cm/ob/image/dbg)",
    )
    p_query_subs = p_query.add_subparsers(dest="query_kind", required=True)

    p_ps = p_query_subs.add_parser("ps", help="walk Psp*NotifyRoutine arrays")
    _add_common_filter_args(p_ps)
    p_ps.set_defaults(_handler=_cmd_query_ps)

    p_cm = p_query_subs.add_parser("cm", help="walk CmRegisterCallback list")
    _add_common_filter_args(p_cm)
    p_cm.set_defaults(_handler=_cmd_query_cm)

    p_ob = p_query_subs.add_parser("ob", help="walk ObRegisterCallbacks list")
    _add_common_filter_args(p_ob)
    p_ob.set_defaults(_handler=_cmd_query_ob)

    p_image = p_query_subs.add_parser("image", help="walk PspLoadImageNotifyRoutine")
    _add_common_filter_args(p_image)
    p_image.set_defaults(_handler=_cmd_query_image)

    p_dbg = p_query_subs.add_parser("dbg", help="enumerate kernel debugger objects")
    _add_common_filter_args(p_dbg)
    p_dbg.set_defaults(_handler=_cmd_query_dbg)

    #
    # Other top-level subcommands.
    #
    p_enum = p_root_subs.add_parser(
        "enumerate",
        help="enumerate every category as a flat list",
    )
    p_enum.add_argument("--max-entries", type=int, default=256)
    p_enum.add_argument("--category-mask", type=int, default=0,
                        help="bit0=PS, bit1=CM, bit2=OB, bit3=IMAGE, bit4=DBG (0=all)")
    p_enum.set_defaults(_handler=_cmd_enumerate)

    p_stats = p_root_subs.add_parser(
        "stats",
        help="per-category totals (PS/CM/OB/IMAGE/DBG)",
    )
    p_stats.set_defaults(_handler=_cmd_stats)

    p_remove = p_root_subs.add_parser(
        "remove",
        help="reserved for S7.2-fix (currently NOT_IMPLEMENTED)",
    )
    p_remove.add_argument("--category", type=int, default=0,
                          help="MYARK_CALLBACK_CATEGORY_* value")
    p_remove.add_argument("--index", type=int, default=0)
    p_remove.set_defaults(_handler=_cmd_remove)

    p_restore = p_root_subs.add_parser(
        "restore",
        help="reserved for S7.2-fix (currently NOT_IMPLEMENTED)",
    )
    p_restore.add_argument("--category", type=int, default=0)
    p_restore.add_argument("--index", type=int, default=0)
    p_restore.set_defaults(_handler=_cmd_restore)

    p_backup = p_root_subs.add_parser(
        "backup",
        help="reserved for S7.2-fix (currently NOT_IMPLEMENTED)",
    )
    p_backup.add_argument("--max-entries", type=int, default=64)
    p_backup.set_defaults(_handler=_cmd_backup)


def _cmd_callback_root(args: argparse.Namespace) -> int:
    """Fallback when the user types ``myark-cli callback`` with no subcommand.

    The argparse ``required=True`` on ``callback_subcommand`` should reject
    this with a usage error and SystemExit(2) before we ever get here, but
    we keep a friendly fallback in case the parser changes.
    """
    print("!! callback: missing subcommand (try `myark-cli callback query <kind>`)", file=sys.stderr)
    return 2


__all__ = ["_setup_cli", "QUERY_NAMES"]