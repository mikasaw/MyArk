"""
actions R3 - CLI subcommands (7 mixed actions).

Usage:
    myark-cli actions kill         --pid 1234 [--exit-code 1] [--reason "..."]
    myark-cli actions terminate-thread --pid 1234 --tid 5678 [--exit-code 1]
    myark-cli actions inject-dll   --pid 1234 --dll-path C:\\my.dll
    myark-cli actions dump-memory  --pid 1234 --address 0x7FF... --size 256
    myark-cli actions set-token    --pid 1234 [--type primary|impersonation]
    myark-cli actions hide-process --pid 1234
    myark-cli actions protect-process --pid 1234 [--flags signed|lsa|wintcb]
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional

from myark.client.ark_client import ArkClient
from myark.history import record as _history_record

from . import parser as P
from . import protocol as PP


def _log_history(action: str, target: str, result: str, detail: str = "") -> None:
    """Append one entry to ``~/.myark/history.log`` (best-effort)."""
    try:
        _history_record(action, target, result, detail)
    except Exception:
        pass


def _open_or_complain() -> Optional[ArkClient]:
    """Open the driver or print a stderr message and return None."""
    client = ArkClient.open_or_null()
    if client is None:
        print(
            "!! actions: MyArkCore driver not installed; "
            "R0-only actions (set-token/hide-process/protect-process) "
            "and the destructive R0 path are unavailable "
            "(run inside Hyper-V VM with testsigning on)",
            file=sys.stderr,
        )
    return client


def _format_result(result: P.ActionResult) -> str:
    return (
        f"# actions: action={result.action} pid={result.pid} "
        f"source={result.source} tier={result.tier_name} "
        f"result={result.result_name} audit={result.audit_message!r}"
    )


def _make_token(args: argparse.Namespace, action_name: str) -> Optional[P.SafetyToken]:
    """Build a SafetyToken from CLI flags, or ``None`` if --no-token.

    In Mode A the driver validates Magic / Pid / Op / Timestamp /
    signature-non-zero only -- the cryptographic check is wired up
    during VM verification. Here we just stamp a deterministic
    pseudo-signature.
    """
    if getattr(args, "no_token", False):
        return None
    op = PP.ACTIONS_NAME_TO_OP[action_name]
    return P.SafetyToken(pid=args.pid, operation=op)


# ---------------------------------------------------------------------------
# Per-action handlers (single-arg signature, matching the dyndata /
# callback style). Each opens the driver lazily, runs one IOCTL (or
# R3 fallback), prints one summary line, and returns 0/2/3.
# ---------------------------------------------------------------------------

def _cmd_kill(args: argparse.Namespace) -> int:
    token = _make_token(args, "kill_process")
    try:
        result = P.try_action(
            P.kill_process,
            pid=args.pid,
            exit_code=args.exit_code,
            reason=args.reason,
            token=token,
        )
        if result is None:
            # Driver missing but R3 fallback available: still try R3 directly.
            result = P.kill_process(
                None, pid=args.pid, exit_code=args.exit_code,
                reason=args.reason, token=token,
            )
    except P.SafetyTokenRequired as exc:
        print(f"!! actions: {exc}", file=sys.stderr)
        return 2
    print(_format_result(result))
    _log_history("kill", f"pid={args.pid}", result.result_name,
                 detail=f"reason={args.reason}")
    return 0


def _cmd_terminate_thread(args: argparse.Namespace) -> int:
    token = _make_token(args, "terminate_thread")
    try:
        result = P.try_action(
            P.terminate_thread,
            pid=args.pid, tid=args.tid,
            exit_code=args.exit_code, token=token,
        )
        if result is None:
            result = P.terminate_thread(
                None, pid=args.pid, tid=args.tid,
                exit_code=args.exit_code, token=token,
            )
    except P.SafetyTokenRequired as exc:
        print(f"!! actions: {exc}", file=sys.stderr)
        return 2
    print(_format_result(result))
    _log_history("terminate_thread", f"pid={args.pid} tid={args.tid}",
                 result.result_name)
    return 0


def _cmd_inject_dll(args: argparse.Namespace) -> int:
    token = _make_token(args, "inject_dll")
    try:
        result = P.try_action(
            P.inject_dll,
            pid=args.pid, dll_path=args.dll_path, token=token,
        )
        if result is None:
            result = P.inject_dll(
                None, pid=args.pid, dll_path=args.dll_path, token=token,
            )
    except P.SafetyTokenRequired as exc:
        print(f"!! actions: {exc}", file=sys.stderr)
        return 2
    print(_format_result(result))
    _log_history("inject_dll", f"pid={args.pid}", result.result_name,
                 detail=f"dll={args.dll_path}")
    return 0


def _cmd_dump_memory(args: argparse.Namespace) -> int:
    token = _make_token(args, "dump_memory")
    try:
        result = P.try_action(
            P.dump_memory,
            pid=args.pid, address=args.address, size=args.size,
            token=token,
        )
        if result is None:
            result = P.dump_memory(
                None, pid=args.pid, address=args.address, size=args.size,
                token=token,
            )
    except P.SafetyTokenRequired as exc:
        print(f"!! actions: {exc}", file=sys.stderr)
        return 2
    print(_format_result(result))
    _log_history("dump_memory", f"pid={args.pid}", result.result_name,
                 detail=f"addr=0x{args.address:x} size={args.size}")
    return 0


def _cmd_set_token(args: argparse.Namespace) -> int:
    token = _make_token(args, "set_token")
    try:
        result = P.try_action(
            P.set_token,
            pid=args.pid, token_type=args.type, token=token,
        )
    except P.SafetyTokenRequired as exc:
        print(f"!! actions: {exc}", file=sys.stderr)
        return 2
    except P.R3FallbackUnavailable as exc:
        print(f"!! actions: {exc}", file=sys.stderr)
        return 3
    if result is None:
        print("!! actions: set_token is R0-only; driver must be installed", file=sys.stderr)
        return 3
    print(_format_result(result))
    _log_history("set_token", f"pid={args.pid}", result.result_name,
                 detail=f"type={args.type}")
    return 0


def _cmd_hide_process(args: argparse.Namespace) -> int:
    token = _make_token(args, "hide_process")
    try:
        result = P.try_action(
            P.hide_process,
            pid=args.pid, token=token,
        )
    except P.SafetyTokenRequired as exc:
        print(f"!! actions: {exc}", file=sys.stderr)
        return 2
    except P.R3FallbackUnavailable as exc:
        print(f"!! actions: {exc}", file=sys.stderr)
        return 3
    if result is None:
        print("!! actions: hide_process is R0-only; driver must be installed", file=sys.stderr)
        return 3
    print(_format_result(result))
    _log_history("hide_process", f"pid={args.pid}", result.result_name)
    return 0


def _cmd_protect_process(args: argparse.Namespace) -> int:
    token = _make_token(args, "protect_process")
    try:
        result = P.try_action(
            P.protect_process,
            pid=args.pid, flags=args.flags, token=token,
        )
    except P.SafetyTokenRequired as exc:
        print(f"!! actions: {exc}", file=sys.stderr)
        return 2
    except P.R3FallbackUnavailable as exc:
        print(f"!! actions: {exc}", file=sys.stderr)
        return 3
    if result is None:
        print("!! actions: protect_process is R0-only; driver must be installed", file=sys.stderr)
        return 3
    print(_format_result(result))
    _log_history("protect_process", f"pid={args.pid}", result.result_name,
                 detail=f"flags={args.flags}")
    return 0


def _setup_cli(subparsers, _client=None) -> None:
    """Wire ``myark-cli actions <verb> ...``."""
    p_root = subparsers.add_parser(
        "actions",
        help="actions module commands (7 mixed R0+R3 actions; "
             "kill/terminate/inject/dump have R3 fallbacks, "
             "set-token/hide-process/protect-process are R0-only)",
    )
    p_root.set_defaults(_handler=_cmd_actions_root)

    p_subs = p_root.add_subparsers(dest="actions_subcommand", required=True)

    # Common safety-token flag -- supplied to every action.
    def _add_token_flag(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--no-token",
            action="store_true",
            help="omit the safety token (driver returns DENIED_NO_TOKEN)",
        )

    # kill
    p_kill = p_subs.add_parser("kill", help="kill process by PID (R3 fallback: TerminateProcess)")
    p_kill.add_argument("--pid", type=int, required=True, help="target PID")
    p_kill.add_argument("--exit-code", type=int, default=1, help="Win32 exit code (default 1)")
    p_kill.add_argument("--reason", default="", help="free-form reason for audit log")
    _add_token_flag(p_kill)
    p_kill.set_defaults(_handler=_cmd_kill)

    # terminate-thread
    p_tt = p_subs.add_parser(
        "terminate-thread",
        help="kill one thread inside a process (R3 fallback: TerminateThread)",
    )
    p_tt.add_argument("--pid", type=int, required=True, help="target PID")
    p_tt.add_argument("--tid", type=int, required=True, help="target thread ID")
    p_tt.add_argument("--exit-code", type=int, default=1, help="Win32 exit code (default 1)")
    _add_token_flag(p_tt)
    p_tt.set_defaults(_handler=_cmd_terminate_thread)

    # inject-dll
    p_inj = p_subs.add_parser(
        "inject-dll",
        help="load a DLL into a remote process (R3 fallback: CreateRemoteThread)",
    )
    p_inj.add_argument("--pid", type=int, required=True, help="target PID")
    p_inj.add_argument("--dll-path", required=True, help="DLL path on the target filesystem")
    _add_token_flag(p_inj)
    p_inj.set_defaults(_handler=_cmd_inject_dll)

    # dump-memory
    p_dump = p_subs.add_parser(
        "dump-memory",
        help="read (address, size) bytes from a remote process "
             "(R3 fallback: ReadProcessMemory)",
    )
    p_dump.add_argument("--pid", type=int, required=True, help="target PID")
    p_dump.add_argument("--address", type=lambda v: int(v, 0), required=True,
                        help="start address (hex like 0x7FF...)")
    p_dump.add_argument("--size", type=int, default=4096,
                        help="bytes to read (default 4096, capped at MYARK_ACTION_DUMP_MAX_BYTES)")
    _add_token_flag(p_dump)
    p_dump.set_defaults(_handler=_cmd_dump_memory)

    # set-token (R0-only)
    p_set = p_subs.add_parser(
        "set-token",
        help="assign primary/impersonation token to a process (R0-only)",
    )
    p_set.add_argument("--pid", type=int, required=True, help="target PID")
    p_set.add_argument("--type", type=int, default=PP.MYARK_ACTION_TOKEN_TYPE_PRIMARY,
                       choices=[PP.MYARK_ACTION_TOKEN_TYPE_PRIMARY,
                                PP.MYARK_ACTION_TOKEN_TYPE_IMPERSONATION],
                       help="0=primary, 1=impersonation (default primary)")
    _add_token_flag(p_set)
    p_set.set_defaults(_handler=_cmd_set_token)

    # hide-process (R0-only)
    p_hide = p_subs.add_parser(
        "hide-process",
        help="DKOM-unlink a process from ActiveProcessLinks (R0-only)",
    )
    p_hide.add_argument("--pid", type=int, required=True, help="target PID")
    _add_token_flag(p_hide)
    p_hide.set_defaults(_handler=_cmd_hide_process)

    # protect-process (R0-only)
    p_prot = p_subs.add_parser(
        "protect-process",
        help="mark a process so TerminateProcess from R3 is denied (R0-only)",
    )
    p_prot.add_argument("--pid", type=int, required=True, help="target PID")
    p_prot.add_argument("--flags", type=int, default=PP.MYARK_ACTION_PROTECT_FLAG_SIGNED,
                        help="PS_PROTECTION flag bits (default SIGNED)")
    _add_token_flag(p_prot)
    p_prot.set_defaults(_handler=_cmd_protect_process)


def _cmd_actions_root(args: argparse.Namespace) -> int:
    print(
        "!! actions: missing subcommand "
        "(try `myark-cli actions {kill,terminate-thread,inject-dll,"
        "dump-memory,set-token,hide-process,protect-process} ...`)",
        file=sys.stderr,
    )
    return 2


__all__ = ["_setup_cli"]