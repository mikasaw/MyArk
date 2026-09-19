"""
safety R3 - CLI subcommands.

Usage:
    myark-cli safety eval --op kill_process --steps 0x1F
    myark-cli safety ops     # list operations + their required steps
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


def _cmd_eval(args: argparse.Namespace) -> int:
    client = _open_or_complain()
    try:
        result = P.evaluate_gate(client, args.op, args.steps)
        line = f"# safety: op={PP.SAFETY_OP_NAMES.get(args.op, args.op)} decision={result.decision_name}"
        if result.failed_step:
            line += f" failed_step={result.failed_step}({result.failed_step_name})"
        print(line)
        return 0 if result.decision == PP.SAFETY_DECISION_APPROVE else 1
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _cmd_ops(args: argparse.Namespace) -> int:
    for op_code, name in PP.SAFETY_OP_NAMES.items():
        required = P._required_steps_r3(op_code)
        bits = []
        for i in range(6):
            if required & (1 << i):
                bits.append(PP.SAFETY_STEP_NAMES[i])
        print(f"  op={name} required=[{','.join(bits)}]")
    return 0


def _setup_cli(subparsers, _client=None) -> None:
    p_root = subparsers.add_parser(
        "safety",
        help="safety module commands (6-step gate evaluator)",
    )
    p_root.set_defaults(_handler=_cmd_root)

    p_subs = p_root.add_subparsers(dest="safety_subcommand", required=True)

    p_eval = p_subs.add_parser(
        "eval",
        help="evaluate the gate for an operation",
    )
    p_eval.add_argument(
        "--op",
        type=int,
        required=True,
        choices=list(PP.SAFETY_OP_NAMES.keys()),
        help="operation code (1=kill_process, 2=terminate_thread, ...)",
    )
    p_eval.add_argument(
        "--steps",
        type=lambda v: int(v, 0),
        default=0,
        help="bitfield of completed steps (hex like 0x1F)",
    )
    p_eval.set_defaults(_handler=_cmd_eval)

    p_ops = p_subs.add_parser(
        "ops",
        help="list operations and required steps",
    )
    p_ops.set_defaults(_handler=_cmd_ops)


def _cmd_root(args: argparse.Namespace) -> int:
    print("!! safety: missing subcommand (try `myark-cli safety eval --op N --steps X`)", file=sys.stderr)
    return 2


__all__ = ["_setup_cli"]