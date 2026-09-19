"""
process R3 - cli commands (try/except AccessDenied/ProcessError on every entry)

R3 implementation, no .sys required. Skip crossview / set-ppl /
set-visibility / dkom / set-flags (R0 only). Every handler that opens
another process wraps its call in try/except so AccessDenied surfaces
as a friendly stderr message + nonzero exit code instead of a stack
trace.
"""
import argparse
import sys

from .parser import (
    enum_processes, enum_threads, process_detail, read_process_memory,
    terminate_process, suspend_thread, resume_thread,
    set_integrity_level, inject_dll,
)
from .protocol import (
    INTEGRITY_LEVEL_LOW, INTEGRITY_LEVEL_MEDIUM,
    INTEGRITY_LEVEL_HIGH, INTEGRITY_LEVEL_SYSTEM,
    ProcessError, AccessDeniedError,
)

INTEGRITY_MAP = {
    "low": INTEGRITY_LEVEL_LOW,
    "medium": INTEGRITY_LEVEL_MEDIUM,
    "high": INTEGRITY_LEVEL_HIGH,
    "system": INTEGRITY_LEVEL_SYSTEM,
}


def _setup_cli(subparsers, _client=None):
    """Called by plugin.register() to add ``process <subcommand>``."""
    p_proc = subparsers.add_parser(
        "process",
        help="process module (R3: enum/threads/detail/terminate/suspend/inject; R0 skipped)",
    )
    proc_subs = p_proc.add_subparsers(dest="process_command", required=True)

    # ===== enum =====
    p_enum = proc_subs.add_parser("enum", help="list all processes (R3 CreateToolhelp32Snapshot)")
    p_enum.set_defaults(_handler=_cmd_enum)

    # ===== enum-by-name =====
    p_ebn = proc_subs.add_parser(
        "enum-by-name",
        help="filter processes by name (case-insensitive substring)",
    )
    p_ebn.add_argument("name", help="substring to match against process name")
    p_ebn.set_defaults(_handler=_cmd_enum_by_name)

    # ===== threads =====
    p_threads = proc_subs.add_parser("threads", help="list threads of a process")
    p_threads.add_argument("pid", type=int, help="PID to query")
    p_threads.set_defaults(_handler=_cmd_threads)

    # ===== detail =====
    p_detail = proc_subs.add_parser("detail", help="show process details (R3 OpenProcess)")
    p_detail.add_argument("pid", type=int, help="PID to query")
    p_detail.set_defaults(_handler=_cmd_detail)

    # ===== detail-runtime =====
    p_drt = proc_subs.add_parser(
        "detail-runtime",
        help="read process PEB/memory (R3 ReadProcessMemory)",
    )
    p_drt.add_argument("pid", type=int, help="PID to query")
    p_drt.add_argument("--size", type=int, default=256, help="bytes to read (default 256)")
    p_drt.set_defaults(_handler=_cmd_detail_runtime)

    # ===== terminate =====
    p_term = proc_subs.add_parser("terminate", help="terminate process (R3 TerminateProcess)")
    p_term.add_argument("pid", type=int, help="PID to terminate")
    p_term.add_argument("--exit-code", type=int, default=1, help="exit code (default 1)")
    p_term.set_defaults(_handler=_cmd_terminate)

    # ===== suspend =====
    p_susp = proc_subs.add_parser("suspend", help="suspend thread (R3 SuspendThread)")
    p_susp.add_argument("tid", type=int, help="TID to suspend")
    p_susp.set_defaults(_handler=_cmd_suspend)

    # ===== resume =====
    p_res = proc_subs.add_parser("resume", help="resume thread (R3 ResumeThread)")
    p_res.add_argument("tid", type=int, help="TID to resume")
    p_res.set_defaults(_handler=_cmd_resume)

    # ===== set-integrity =====
    p_int = proc_subs.add_parser("set-integrity", help="set integrity level (R3 SetTokenInformation)")
    p_int.add_argument("pid", type=int, help="PID")
    p_int.add_argument("level", choices=list(INTEGRITY_MAP.keys()), help="low/medium/high/system")
    p_int.set_defaults(_handler=_cmd_set_integrity)

    # ===== inject =====
    p_inj = proc_subs.add_parser(
        "inject",
        help="inject DLL into process (R3 CreateRemoteThread + LoadLibraryW)",
    )
    p_inj.add_argument("pid", type=int, help="PID to inject")
    p_inj.add_argument("dll_path", help="full path to DLL")
    p_inj.set_defaults(_handler=_cmd_inject)

    # ===== R0-only placeholders =====
    for name in ["crossview", "set-ppl", "set-visibility", "dkom", "set-flags"]:
        p_ro = proc_subs.add_parser(name, help=f"R0-only ({name} requires .sys driver loaded)")
        p_ro.add_argument("args", nargs="*")
        p_ro.set_defaults(_handler=_cmd_r0_only, r0_name=name)


# ===== Handlers =====

def filter_processes_by_name(rows, name: str):
    """Case-insensitive substring filter on ProcessRow.name.

    Pure function, no Win32 calls -- testable without kernel32 / psapi.
    Empty / whitespace-only ``name`` returns the rows unchanged (matches
    ``enum`` behaviour for an empty pattern).
    """
    if not name or not name.strip():
        return list(rows)
    needle = name.strip().lower()
    return [r for r in rows if needle in r.name.lower()]


def _print_enum_rows(rows) -> None:
    """Render a list of ProcessRow in the canonical enum format."""
    print(f"{'PID':<8} {'PPID':<8} {'NAME':<30} {'THREADS':<10} {'PATH'}")
    print("-" * 100)
    for r in rows:
        path = r.path or "(unknown)"
        print(f"{r.pid:<8} {r.ppid:<8} {r.name:<30} {r.thread_count:<10} {path[:60]}")
    print(f"\nTotal: {len(rows)} processes")


def _cmd_enum(args):
    rows = enum_processes()
    _print_enum_rows(rows)
    return 0


def _cmd_enum_by_name(args):
    rows = enum_processes()
    matched = filter_processes_by_name(rows, args.name)
    _print_enum_rows(matched)
    return 0


def _cmd_threads(args):
    rows = enum_threads(args.pid)
    print(f"{'TID':<10} {'OWNER_PID':<12} {'BASE_PRIORITY':<14}")
    print("-" * 40)
    for r in rows:
        print(f"{r.tid:<10} {r.owner_pid:<12} {r.base_priority:<14}")
    print(f"\nTotal: {len(rows)} threads for PID {args.pid}")
    return 0


def _cmd_detail(args):
    try:
        d = process_detail(args.pid)
    except AccessDeniedError as exc:
        print(f"!! process detail {args.pid}: AccessDenied (Win32 error 5) - 需要 admin 权限运行 myark-cli", file=sys.stderr)
        print(f"   {exc}", file=sys.stderr)
        return 5
    except ProcessError as exc:
        print(f"!! process detail {args.pid}: {exc}", file=sys.stderr)
        return 3

    print(f"pid:           {d.pid}")
    print(f"name:          {d.name}")
    print(f"path:          {d.path}")
    print(f"session_id:    {d.session_id}")
    print(f"exit_code:     {d.exit_code} (0x{d.exit_code:08X})")
    print(f"priority:      0x{d.priority_class:08X}")
    print(f"thread_count:  {d.thread_count}")
    return 0


def _cmd_detail_runtime(args):
    try:
        data = read_process_memory(args.pid, 0, args.size)
    except AccessDeniedError as exc:
        print(f"!! process detail-runtime {args.pid}: AccessDenied (Win32 error 5) - 需要 admin 权限", file=sys.stderr)
        print(f"   {exc}", file=sys.stderr)
        return 5
    except ProcessError as exc:
        print(f"!! process detail-runtime {args.pid}: {exc}", file=sys.stderr)
        return 3

    print(f"Read {len(data)} bytes from PID {args.pid} (PEB start):")
    print()
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"{offset:08X}  {hex_part:<47}  {ascii_part}")
    return 0


def _cmd_terminate(args):
    try:
        terminate_process(args.pid, args.exit_code)
    except AccessDeniedError as exc:
        print(f"!! process terminate {args.pid}: AccessDenied (Win32 error 5) - 需要 admin 权限", file=sys.stderr)
        print(f"   {exc}", file=sys.stderr)
        return 5
    except ProcessError as exc:
        print(f"!! process terminate {args.pid}: {exc}", file=sys.stderr)
        return 3

    print(f"Process {args.pid} termination requested (exit code {args.exit_code})")
    return 0


def _cmd_suspend(args):
    try:
        prev = suspend_thread(args.tid)
    except AccessDeniedError as exc:
        print(f"!! process suspend {args.tid}: AccessDenied (Win32 error 5) - 需要 admin 权限", file=sys.stderr)
        print(f"   {exc}", file=sys.stderr)
        return 5
    except ProcessError as exc:
        print(f"!! process suspend {args.tid}: {exc}", file=sys.stderr)
        return 3
    print(f"Thread {args.tid} suspended (previous suspend count: {prev})")
    return 0


def _cmd_resume(args):
    try:
        prev = resume_thread(args.tid)
    except AccessDeniedError as exc:
        print(f"!! process resume {args.tid}: AccessDenied (Win32 error 5) - 需要 admin 权限", file=sys.stderr)
        print(f"   {exc}", file=sys.stderr)
        return 5
    except ProcessError as exc:
        print(f"!! process resume {args.tid}: {exc}", file=sys.stderr)
        return 3
    print(f"Thread {args.tid} resumed (previous suspend count: {prev})")
    return 0


def _cmd_set_integrity(args):
    level = INTEGRITY_MAP[args.level]
    try:
        set_integrity_level(args.pid, level)
    except AccessDeniedError as exc:
        print(f"!! process set-integrity {args.pid}: AccessDenied (Win32 error 5) - 需要 admin 权限 (token 调整需要 SeTcbPrivilege 或 admin)", file=sys.stderr)
        print(f"   {exc}", file=sys.stderr)
        return 5
    except ProcessError as exc:
        print(f"!! process set-integrity {args.pid}: {exc}", file=sys.stderr)
        return 3
    print(f"PID {args.pid} integrity level set to {args.level} (0x{level:X})")
    return 0


def _cmd_inject(args):
    try:
        tid = inject_dll(args.pid, args.dll_path)
    except AccessDeniedError as exc:
        print(f"!! process inject {args.pid}: AccessDenied (Win32 error 5) - 需要 admin 权限", file=sys.stderr)
        print(f"   {exc}", file=sys.stderr)
        return 5
    except ProcessError as exc:
        print(f"!! process inject {args.pid}: {exc}", file=sys.stderr)
        return 3
    print(f"DLL injection requested: PID {args.pid}, tid {tid}, dll={args.dll_path}")
    return 0


def _cmd_r0_only(args):
    print(f"!! {args.r0_name}: R0-only (requires .sys driver loaded, not available in R3)", file=sys.stderr)
    print("   Use VM with .sys loaded to access this command.", file=sys.stderr)
    return 2


__all__ = ["_setup_cli", "filter_processes_by_name"]