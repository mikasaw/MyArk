"""MyArk thread module: CLI subcommands.

Adds ``myark-cli thread {enum, detail, detail-runtime, crossview, terminate}``
to the parent argparse parser. R3 is the default -- the driver is
optional and only needed for ``crossview``.

Each subcommand opens its own ArkClient for the R0 path (handle is
closed in a finally), so the CLI works without an already-open driver
handle.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, Optional

from myark.client.ark_client import ArkClient


def _require_client() -> Optional[ArkClient]:
    return ArkClient.open_or_null()


def _safe_close(client: Optional[ArkClient]) -> None:
    if client is None:
        return
    try:
        client.close()
    except Exception:
        pass


def _print_row(row) -> None:
    """Format one ThreadRow for CLI output."""
    anomaly = ""
    if row.anomaly:
        anomaly = f" ANOMALY=0x{row.anomaly:02X}"
    print(
        f"tid={row.tid:>6} pid={row.pid:>6} state={row.state_name:<14} "
        f"prio={row.priority:>3} wait={row.wait_name:<20} "
        f"start=0x{row.start_address:016X} module={row.module!r}{anomaly}"
    )


def _setup_cli(subparsers: Any, _client: Optional[ArkClient]) -> None:
    """Wire the ``myark-cli thread ...`` subtree."""
    p_root = subparsers.add_parser(
        "thread",
        help="thread module commands (enum / detail / actions)",
    )
    subs = p_root.add_subparsers(dest="thread_subcommand", required=True)

    # ---------- enum
    p_enum = subs.add_parser(
        "enum", help="list threads of a process (R3 default; --method r0 uses driver)",
    )
    p_enum.add_argument("--pid", type=int, required=True, help="target process id")
    p_enum.add_argument("--max", type=int, default=256, help="max rows (default 256)")
    p_enum.add_argument(
        "--method",
        choices=["r0", "r3"],
        default="r3",
        help="r3 = pure user-mode via Toolhelp32 (default). r0 = driver IOCTL.",
    )
    p_enum.set_defaults(_handler=_cmd_enum)

    # ---------- detail
    p_det = subs.add_parser("detail", help="per-thread detail (R3 OpenThread + GetThreadTimes)")
    p_det.add_argument("--tid", type=int, required=True, help="target thread id")
    p_det.add_argument(
        "--method",
        choices=["r0", "r3"],
        default="r3",
        help="r3 = pure user-mode (default). r0 = driver IOCTL.",
    )
    p_det.set_defaults(_handler=_cmd_detail)

    # ---------- detail-runtime
    p_drt = subs.add_parser(
        "detail-runtime", help="runtime stats for one thread (R3 GetThreadContext)",
    )
    p_drt.add_argument("--tid", type=int, required=True)
    p_drt.add_argument(
        "--method",
        choices=["r0", "r3"],
        default="r3",
        help="r3 = pure user-mode (default). r0 = driver IOCTL.",
    )
    p_drt.set_defaults(_handler=_cmd_detail_runtime)

    # ---------- crossview (R0-only)
    p_cv = subs.add_parser(
        "crossview",
        help="R0-only (cross-view: kernel + ThreadListHead + PspCidTable)",
    )
    p_cv.add_argument("--pid", type=int, required=True, help="target process id")
    p_cv.add_argument("--tid", type=int, default=0, help="optional tid filter")
    p_cv.set_defaults(_handler=_cmd_crossview)

    # ---------- terminate
    p_t = subs.add_parser(
        "terminate",
        help="terminate a thread (R3 OpenThread + TerminateThread by default)",
    )
    p_t.add_argument("--tid", type=int, required=True)
    p_t.add_argument("--exit-code", type=int, default=0)
    p_t.add_argument("--force", action="store_true")
    p_t.set_defaults(_handler=_cmd_terminate)


def _cmd_enum(args: argparse.Namespace) -> int:
    if args.method == "r0":
        from myark.modules.thread.protocol import enum_threads
        client = _require_client()
        if client is None:
            print(
                "driver not installed -- cannot enumerate via R0 (use --method r3)",
                file=sys.stderr,
            )
            return 2
        try:
            result = enum_threads(client, pid=args.pid, max_entries=args.max)
        except Exception as exc:
            print(f"enum failed: {exc}", file=sys.stderr)
            return 3
        finally:
            _safe_close(client)

        for r in result.rows:
            _print_row(r)
        print(
            f"# method=r0 owner_pid={result.owner_pid} count={len(result.rows)} "
            f"anomaly={result.anomaly_count} bytes={result.bytes_used}"
        )
        return 0

    # --method r3 (default)
    from myark.modules.thread.parser import enum_threads_r3
    try:
        stats = enum_threads_r3(args.pid)
    except OSError as exc:
        print(f"enum failed: {exc}", file=sys.stderr)
        return 3

    for r in stats.rows:
        _print_row(r)
    print(f"# method=r3 total_tids={stats.total_tids} rows={len(stats.rows)}")
    return 0


def _cmd_detail(args: argparse.Namespace) -> int:
    if args.method == "r0":
        from myark.modules.thread.protocol import detail
        client = _require_client()
        if client is None:
            print(
                "driver not installed -- cannot detail via R0 (use --method r3)",
                file=sys.stderr,
            )
            return 2
        try:
            d = detail(client, args.tid)
        except Exception as exc:
            print(f"detail failed: {exc}", file=sys.stderr)
            return 3
        finally:
            _safe_close(client)

        print(f"tid={d.Tid} owner_pid={d.OwnerPid}")
        print(f"state={int(d.State)} priority={d.Priority} base_priority={d.BasePriority}")
        print(f"wait_reason={int(d.WaitReason)} anomaly=0x{int(d.Anomaly):08X}")
        print(f"create_time=0x{d.CreateTime:016X}")
        print(f"start_address=0x{d.StartAddress:016X}")
        print(f"win32_start_address=0x{d.Win32StartAddress:016X}")
        print(f"ethread_addr=0x{d.EThreadKernelAddress:016X}")
        print(f"eprocess_addr=0x{d.EProcessKernelAddress:016X}")
        print(f"module={d.Module!r}")
        print(f"start_path={d.StartAddressModulePath!r}")
        print(
            f"offsets: tid=0x{d.UniqueThreadIdOffset:X} state=0x{d.StateOffset:X} "
            f"prio=0x{d.PriorityOffset:X} start=0x{d.StartAddressOffset:X}"
        )
        return 0

    # --method r3 (default)
    from myark.modules.thread.parser import thread_detail_r3
    try:
        d = thread_detail_r3(args.tid)
    except OSError as exc:
        print(f"detail failed: {exc}", file=sys.stderr)
        return 3

    print(f"# method=r3")
    print(f"tid={d['tid']} priority={d['priority']}")
    print(f"create_time=0x{d['create_time']:016X}")
    print(f"exit_time=0x{d['exit_time']:016X}")
    print(f"kernel_time=0x{d['kernel_time']:016X}")
    print(f"user_time=0x{d['user_time']:016X}")
    print(
        f"# R3 detail cannot resolve StartAddress / ETHREAD / wait reason; "
        f"those need --method r0 with .sys loaded"
    )
    return 0


def _cmd_detail_runtime(args: argparse.Namespace) -> int:
    if args.method == "r0":
        from myark.modules.thread.protocol import detail_runtime
        client = _require_client()
        if client is None:
            print(
                "driver not installed -- cannot detail-runtime via R0 (use --method r3)",
                file=sys.stderr,
            )
            return 2
        try:
            rt = detail_runtime(client, args.tid)
        except Exception as exc:
            print(f"detail-runtime failed: {exc}", file=sys.stderr)
            return 3
        finally:
            _safe_close(client)

        print(f"tid={rt.Tid}")
        print(f"kernel_time={rt.KernelTime} user_time={rt.UserTime}")
        print(f"cycle_time=0x{rt.CycleTime:016X}")
        print(f"context_switches={rt.ContextSwitches} state_flags=0x{rt.StateFlags:08X}")
        return 0

    # --method r3 (default)
    from myark.modules.thread.parser import thread_detail_runtime_r3
    try:
        ctx = thread_detail_runtime_r3(args.tid)
    except OSError as exc:
        print(f"detail-runtime failed: {exc}", file=sys.stderr)
        return 3

    print(f"# method=r3")
    print(f"tid={ctx['tid']}")
    print(f"rip=0x{ctx['rip']:016X} rsp=0x{ctx['rsp']:016X}")
    print(f"rbp=0x{ctx['rbp']:016X} rax=0x{ctx['rax']:016X}")
    print(f"rbx=0x{ctx['rbx']:016X} eflags=0x{ctx['eflags']:08X}")
    return 0


def _cmd_crossview(args: argparse.Namespace) -> int:
    from myark.modules.thread.protocol import crossview
    client = _require_client()
    if client is None:
        print(
            "!! crossview: R0-only (requires .sys driver loaded, not available in R3)",
            file=sys.stderr,
        )
        print("   Use VM with .sys loaded to access this command.", file=sys.stderr)
        return 2
    try:
        result = crossview(client, pid=args.pid, tid_filter=args.tid)
    except Exception as exc:
        print(f"crossview failed: {exc}", file=sys.stderr)
        return 3
    finally:
        _safe_close(client)

    for r in result.rows:
        _print_row(r)
    print(
        f"# pid={args.pid} hidden={result.hidden_count} "
        f"public_only={result.public_only} bytes={result.bytes_used}"
    )
    return 0


def _cmd_terminate(args: argparse.Namespace) -> int:
    # Try R3 first (TerminateThread); fall back to R0 only if R3 fails
    # AND the user explicitly asked for --force OR the driver is loaded.
    from myark.modules.thread.parser import terminate_thread_r3
    try:
        status = terminate_thread_r3(args.tid, args.exit_code)
        if status == 0:
            print(
                f"tid={args.tid} status=0x{status:08X} method=r3 (TerminateThread)"
            )
            return 0
        # R3 failed -- check errno and decide whether to fall back.
        print(
            f"tid={args.tid} R3 TerminateThread failed: Win32 error {status:#x}",
            file=sys.stderr,
        )
        if not args.force:
            return 5
    except OSError as exc:
        print(f"tid={args.tid} R3 terminate raised: {exc}", file=sys.stderr)
        if not args.force:
            return 3

    # Fall through to driver-side IOCTL (R0).
    from myark.modules.thread.protocol import terminate
    client = _require_client()
    if client is None:
        print("driver not installed -- cannot R0 terminate (R3 failed)", file=sys.stderr)
        return 2
    try:
        out = terminate(client, args.tid, exit_code=args.exit_code, force=args.force)
    except Exception as exc:
        print(f"terminate failed: {exc}", file=sys.stderr)
        return 3
    finally:
        _safe_close(client)

    print(
        f"tid={args.tid} status=0x{out.Status:08X} r0_fallback={out.UsedR0Fallback}"
    )
    return 0


__all__ = ["_setup_cli"]