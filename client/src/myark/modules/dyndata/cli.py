"""
dyndata R3 - CLI subcommands.

The dyndata module is R0-only: every ``myark-cli dyndata query <kind>``
call turns into one DeviceIoControl against ``\\\\.\\MyArkCore``. When the
driver is not installed the CLI prints a friendly "driver not installed"
message and exits 2 -- no crash, no stack trace.

Usage examples:
    myark-cli dyndata query process
    myark-cli dyndata query thread --pid 1234
    myark-cli dyndata query module
    myark-cli dyndata query handle --pid 1234
    myark-cli dyndata query file --pid 1234
    myark-cli dyndata query syscall
    myark-cli dyndata query token --pid 1234
    myark-cli dyndata query object
    myark-cli dyndata query ssdt
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional

from myark.client.ark_client import ArkClient, DriverError

from . import parser as P


QUERY_NAMES = (
    "process",
    "thread",
    "module",
    "handle",
    "file",
    "syscall",
    "token",
    "object",
    "ssdt",
)


def _open_or_complain() -> Optional[ArkClient]:
    """Open the driver or print a stderr message and return None."""
    client = ArkClient.open_or_null()
    if client is None:
        print(
            "!! dyndata: MyArkCore driver not installed (run inside Hyper-V VM with testsigning on)",
            file=sys.stderr,
        )
        return None
    return client


def _format_extra(result: P.DynDataResult) -> str:
    """Render the extra diagnostics as a single line (key=value pairs)."""
    if not result.extra:
        return ""
    return " ".join(f"{k}=0x{v:x}" if isinstance(v, int) else f"{k}={v}"
                    for k, v in result.extra.items())


# ---------------------------------------------------------------------------
# Per-query handlers (single-arg signature, matching memory/process modules).
# Each handler opens the driver lazily, runs one IOCTL, prints one summary
# line, and returns 0 / 2 / 3.
# ---------------------------------------------------------------------------

def _cmd_query_process(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    if client is None:
        return 2
    try:
        result = P.query_process(client, pid_filter=args.pid, max_entries=args.max_entries)
        line = f"# method=r0 query=process count={result.count} total_seen={result.total_seen}"
        extra = _format_extra(result)
        if extra:
            line = f"{line} {extra}"
        print(line)
        return 0
    except (DriverError, OSError, RuntimeError) as exc:
        print(f"!! dyndata: DeviceIoControl failed: {exc}", file=sys.stderr)
        return 3
    finally:
        try:
            client.close()
        except Exception:
            pass


def _cmd_query_thread(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    if client is None:
        return 2
    try:
        result = P.query_thread(client, pid_filter=args.pid, max_entries=args.max_entries)
        line = f"# method=r0 query=thread count={result.count} total_seen={result.total_seen}"
        extra = _format_extra(result)
        if extra:
            line = f"{line} {extra}"
        print(line)
        return 0
    except (DriverError, OSError, RuntimeError) as exc:
        print(f"!! dyndata: DeviceIoControl failed: {exc}", file=sys.stderr)
        return 3
    finally:
        try:
            client.close()
        except Exception:
            pass


def _cmd_query_module(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    if client is None:
        return 2
    try:
        result = P.query_module(client, max_entries=args.max_entries)
        line = f"# method=r0 query=module count={result.count} total_seen={result.total_seen}"
        extra = _format_extra(result)
        if extra:
            line = f"{line} {extra}"
        print(line)
        return 0
    except (DriverError, OSError, RuntimeError) as exc:
        print(f"!! dyndata: DeviceIoControl failed: {exc}", file=sys.stderr)
        return 3
    finally:
        try:
            client.close()
        except Exception:
            pass


def _cmd_query_handle(args: argparse.Namespace) -> int:
    type_filter = 0xFFFFFFFF
    if args.type_index is not None:
        type_filter = args.type_index
    client = _open_or_complain()
    if client is None:
        return 2
    try:
        result = P.query_handle(client,
                                pid_filter=args.pid,
                                type_index_filter=type_filter,
                                max_entries=args.max_entries)
        line = f"# method=r0 query=handle count={result.count} total_seen={result.total_seen}"
        extra = _format_extra(result)
        if extra:
            line = f"{line} {extra}"
        print(line)
        return 0
    except (DriverError, OSError, RuntimeError) as exc:
        print(f"!! dyndata: DeviceIoControl failed: {exc}", file=sys.stderr)
        return 3
    finally:
        try:
            client.close()
        except Exception:
            pass


def _cmd_query_file(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    if client is None:
        return 2
    try:
        result = P.query_file(client, pid_filter=args.pid, max_entries=args.max_entries)
        line = f"# method=r0 query=file count={result.count} total_seen={result.total_seen}"
        extra = _format_extra(result)
        if extra:
            line = f"{line} {extra}"
        print(line)
        return 0
    except (DriverError, OSError, RuntimeError) as exc:
        print(f"!! dyndata: DeviceIoControl failed: {exc}", file=sys.stderr)
        return 3
    finally:
        try:
            client.close()
        except Exception:
            pass


def _cmd_query_syscall(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    if client is None:
        return 2
    try:
        result = P.query_syscall(client,
                                 table_mask=args.table_mask,
                                 max_entries=args.max_entries)
        line = f"# method=r0 query=syscall count={result.count} total_seen={result.total_seen}"
        extra = _format_extra(result)
        if extra:
            line = f"{line} {extra}"
        print(line)
        return 0
    except (DriverError, OSError, RuntimeError) as exc:
        print(f"!! dyndata: DeviceIoControl failed: {exc}", file=sys.stderr)
        return 3
    finally:
        try:
            client.close()
        except Exception:
            pass


def _cmd_query_token(args: argparse.Namespace) -> int:
    if args.pid is None:
        print("!! dyndata query token: --pid is required", file=sys.stderr)
        return 2
    client = _open_or_complain()
    if client is None:
        return 2
    try:
        result = P.query_token(client, args.pid)
        line = f"# method=r0 query=token pid={args.pid} count={result.count}"
        extra = _format_extra(result)
        if extra:
            line = f"{line} {extra}"
        print(line)
        return 0
    except (DriverError, OSError, RuntimeError) as exc:
        print(f"!! dyndata: DeviceIoControl failed: {exc}", file=sys.stderr)
        return 3
    finally:
        try:
            client.close()
        except Exception:
            pass


def _cmd_query_object(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    if client is None:
        return 2
    try:
        result = P.query_object(client, max_entries=args.max_entries)
        line = f"# method=r0 query=object count={result.count} total_seen={result.total_seen}"
        extra = _format_extra(result)
        if extra:
            line = f"{line} {extra}"
        print(line)
        return 0
    except (DriverError, OSError, RuntimeError) as exc:
        print(f"!! dyndata: DeviceIoControl failed: {exc}", file=sys.stderr)
        return 3
    finally:
        try:
            client.close()
        except Exception:
            pass


def _cmd_query_ssdt(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    if client is None:
        return 2
    try:
        result = P.query_ssdt(client, max_entries=args.max_entries)
        line = f"# method=r0 query=ssdt count={result.count} total_seen={result.total_seen}"
        extra = _format_extra(result)
        if extra:
            line = f"{line} {extra}"
        print(line)
        return 0
    except (DriverError, OSError, RuntimeError) as exc:
        print(f"!! dyndata: DeviceIoControl failed: {exc}", file=sys.stderr)
        return 3
    finally:
        try:
            client.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Argument wiring.
# ---------------------------------------------------------------------------

def _add_common_filter_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-entries", type=int, default=1024,
                        help="max entries to request (default 1024, capped by driver HARD_CAP)")
    parser.add_argument("--pid", type=int, default=0,
                        help="filter to a single PID where applicable (0 = all)")


def _setup_cli(subparsers, _client=None) -> None:
    """Wire the ``myark-cli dyndata query <kind> ...`` subtree.

    Structure is ``dyndata -> query -> {process,thread,...,ssdt}`` so the
    spec path ``myark-cli dyndata query process`` works alongside the
    short-form fallback registered by ``main()``.
    """
    p_root = subparsers.add_parser(
        "dyndata",
        help="dyndata module commands (R0 NtQuerySystemInformation-style)",
    )
    p_root.set_defaults(_handler=_cmd_dyndata_root)

    p_root_subs = p_root.add_subparsers(dest="dyndata_subcommand", required=True)

    p_query = p_root_subs.add_parser(
        "query",
        help="send a single dyndata IOCTL (process/thread/module/...)",
    )
    p_query_subs = p_query.add_subparsers(dest="query_kind", required=True)

    p_process = p_query_subs.add_parser("process", help="walk EPROCESS.ActiveProcessLinks")
    _add_common_filter_args(p_process)
    p_process.set_defaults(_handler=_cmd_query_process)

    p_thread = p_query_subs.add_parser("thread", help="walk ETHREAD via PsActiveThreadHead")
    _add_common_filter_args(p_thread)
    p_thread.set_defaults(_handler=_cmd_query_thread)

    p_module = p_query_subs.add_parser("module", help="walk KLDR_DATA_TABLE_ENTRY via PsLoadedModuleList")
    p_module.add_argument("--max-entries", type=int, default=1024)
    p_module.set_defaults(_handler=_cmd_query_module)

    p_handle = p_query_subs.add_parser("handle", help="snapshot handle table (PspCidTable level-0)")
    _add_common_filter_args(p_handle)
    p_handle.add_argument("--type-index", type=int, default=None,
                          help="filter to a single ObTypeIndex (default: all)")
    p_handle.set_defaults(_handler=_cmd_query_handle)

    p_file = p_query_subs.add_parser("file", help="snapshot open file objects per process")
    _add_common_filter_args(p_file)
    p_file.set_defaults(_handler=_cmd_query_file)

    p_syscall = p_query_subs.add_parser("syscall", help="walk NTOS + win32k syscall tables")
    p_syscall.add_argument("--max-entries", type=int, default=1024)
    p_syscall.add_argument("--table-mask", type=int, default=0,
                           help="bit0=NTOS, bit1=WIN32K (0=both)")
    p_syscall.set_defaults(_handler=_cmd_query_syscall)

    p_token = p_query_subs.add_parser("token", help="token snapshot for a single PID")
    p_token.add_argument("--pid", type=int, required=True, help="target PID")
    p_token.set_defaults(_handler=_cmd_query_token)

    p_object = p_query_subs.add_parser("object", help="enumerate object-type entries")
    p_object.add_argument("--max-entries", type=int, default=64)
    p_object.set_defaults(_handler=_cmd_query_object)

    p_ssdt = p_query_subs.add_parser("ssdt", help="walk the shadow SSDT (W32pServiceTable)")
    p_ssdt.add_argument("--max-entries", type=int, default=1024)
    p_ssdt.set_defaults(_handler=_cmd_query_ssdt)


def _cmd_dyndata_root(args: argparse.Namespace) -> int:
    """Fallback when the user types ``myark-cli dyndata`` with no subcommand.

    The argparse ``required=True`` on ``dyndata_subcommand`` should reject
    this with a usage error and SystemExit(2) before we ever get here, but
    we keep a friendly fallback in case the parser changes.
    """
    print("!! dyndata: missing subcommand (try `myark-cli dyndata query <kind>`)", file=sys.stderr)
    return 2


__all__ = ["_setup_cli", "QUERY_NAMES"]