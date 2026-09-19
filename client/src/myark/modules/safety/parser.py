"""
safety R3 - parser / IOCTL helpers (gate evaluator + R3 policy engine).
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass, field
from typing import Optional

from myark.client.ark_client import ArkClient, DriverError

from . import protocol as P


@dataclass
class GateResult:
    decision: int = 0          # APPROVE / DENY / REQUIRE_TOKEN
    decision_name: str = ""
    failed_step: int = 0       # 1-based index when DENY
    failed_step_name: str = ""


def _required_steps_r3(op_code: int) -> int:
    """R3-side mirror of the driver's per-operation policy."""
    base = (P.SAFETY_STEP_AUTHENTICATED
            | P.SAFETY_STEP_CONFIRM_DIALOG
            | P.SAFETY_STEP_TOKEN_PRESENTED
            | P.SAFETY_STEP_TARGET_RESOLVED
            | P.SAFETY_STEP_AUDIT_LOGGED)
    if op_code in (P.SAFETY_OP_KILL_PROCESS,
                   P.SAFETY_OP_TERMINATE_THREAD,
                   P.SAFETY_OP_INJECT_DLL,
                   P.SAFETY_OP_DELETE_FILE,
                   P.SAFETY_OP_CLEAR_CALLBACK,
                   P.SAFETY_OP_MUTATE_TOKEN):
        return base
    return P.SAFETY_STEP_AUTHENTICATED | P.SAFETY_STEP_CONFIRM_DIALOG | P.SAFETY_STEP_REVIEW_TIMEOUT


def evaluate_local(op_code: int, step_flags: int) -> GateResult:
    """R3-only evaluation (when the driver is not available)."""
    required = _required_steps_r3(op_code)
    for i in range(6):
        bit = 1 << i
        if (required & bit) and not (step_flags & bit):
            return GateResult(
                decision=P.SAFETY_DECISION_DENY,
                decision_name="deny",
                failed_step=i + 1,
                failed_step_name=P.SAFETY_STEP_NAMES[i],
            )
    return GateResult(decision=P.SAFETY_DECISION_APPROVE, decision_name="approve")


def evaluate_gate(client: Optional[ArkClient],
                   op_code: int,
                   step_flags: int) -> GateResult:
    """Send IOCTL_MYARK_SAFETY_EVAL_GATE; fall back to R3 evaluation if driver missing."""
    if client is None:
        return evaluate_local(op_code, step_flags)

    in_buf = (ctypes.c_ubyte * ctypes.sizeof(P.MYARK_SAFETY_EVAL_INPUT))()
    in_struct = ctypes.cast(in_buf, ctypes.POINTER(P.MYARK_SAFETY_EVAL_INPUT)).contents
    in_struct.OperationCode = op_code
    in_struct.StepFlags = step_flags

    out_size = ctypes.sizeof(P.MYARK_SAFETY_EVAL_OUTPUT)
    out_buf = (ctypes.c_ubyte * out_size)()

    try:
        bytes_returned = client.ioctl(P.IOCTL_MYARK_SAFETY_EVAL_GATE, in_buf, out_buf)
    except (DriverError, OSError):
        return evaluate_local(op_code, step_flags)

    if bytes_returned < out_size:
        return evaluate_local(op_code, step_flags)

    out = ctypes.cast(out_buf, ctypes.POINTER(P.MYARK_SAFETY_EVAL_OUTPUT)).contents
    decision = out.Decision
    failed = out.FailedStep
    decision_name = {
        P.SAFETY_DECISION_APPROVE: "approve",
        P.SAFETY_DECISION_DENY: "deny",
        P.SAFETY_DECISION_REQUIRE_TOKEN: "require_token",
    }.get(decision, "unknown")
    failed_name = ""
    if failed >= 1 and failed <= 6:
        failed_name = P.SAFETY_STEP_NAMES[failed - 1]
    return GateResult(
        decision=decision,
        decision_name=decision_name,
        failed_step=failed,
        failed_step_name=failed_name,
    )


__all__ = ["GateResult", "evaluate_gate", "evaluate_local"]