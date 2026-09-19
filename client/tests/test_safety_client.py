"""
Tests for the safety module's R3 client (gate evaluator + policy engine).
"""

from __future__ import annotations

import ctypes

import pytest

from myark.modules.safety import parser as P
from myark.modules.safety import protocol as PP


def test_gate_result_defaults():
    r = P.GateResult()
    assert r.decision == 0
    assert r.decision_name == ""
    assert r.failed_step == 0
    assert r.failed_step_name == ""


def test_required_steps_r3_for_known_ops():
    """All 6 known operations require the 5-step base mask (no REVIEW_TIMEOUT)."""
    base = (PP.SAFETY_STEP_AUTHENTICATED
            | PP.SAFETY_STEP_CONFIRM_DIALOG
            | PP.SAFETY_STEP_TOKEN_PRESENTED
            | PP.SAFETY_STEP_TARGET_RESOLVED
            | PP.SAFETY_STEP_AUDIT_LOGGED)
    for op_code in [PP.SAFETY_OP_KILL_PROCESS,
                    PP.SAFETY_OP_TERMINATE_THREAD,
                    PP.SAFETY_OP_INJECT_DLL,
                    PP.SAFETY_OP_DELETE_FILE,
                    PP.SAFETY_OP_CLEAR_CALLBACK,
                    PP.SAFETY_OP_MUTATE_TOKEN]:
        assert P._required_steps_r3(op_code) == base


def test_evaluate_local_full_steps_approves():
    """When all required steps are set, local evaluation approves."""
    full = (PP.SAFETY_STEP_AUTHENTICATED
            | PP.SAFETY_STEP_CONFIRM_DIALOG
            | PP.SAFETY_STEP_TOKEN_PRESENTED
            | PP.SAFETY_STEP_TARGET_RESOLVED
            | PP.SAFETY_STEP_AUDIT_LOGGED)
    result = P.evaluate_local(PP.SAFETY_OP_KILL_PROCESS, full)
    assert result.decision == PP.SAFETY_DECISION_APPROVE
    assert result.failed_step == 0


def test_evaluate_local_missing_step_denies():
    """When a required step is missing, evaluation denies with the first failed step."""
    partial = PP.SAFETY_STEP_AUTHENTICATED  # only step 1
    result = P.evaluate_local(PP.SAFETY_OP_KILL_PROCESS, partial)
    assert result.decision == PP.SAFETY_DECISION_DENY
    assert result.failed_step == 2  # first missing required is CONFIRM_DIALOG
    assert result.failed_step_name == "confirm_dialog"


def test_evaluate_gate_falls_back_when_client_is_none():
    """When client is None, evaluate_gate mirrors evaluate_local."""
    full = (PP.SAFETY_STEP_AUTHENTICATED
            | PP.SAFETY_STEP_CONFIRM_DIALOG
            | PP.SAFETY_STEP_TOKEN_PRESENTED
            | PP.SAFETY_STEP_TARGET_RESOLVED
            | PP.SAFETY_STEP_AUDIT_LOGGED)
    result = P.evaluate_gate(None, PP.SAFETY_OP_MUTATE_TOKEN, full)
    assert result.decision == PP.SAFETY_DECISION_APPROVE
    assert result.decision_name == "approve"


def test_evaluate_gate_local_denies_with_correct_step():
    """evaluate_gate without driver reports the first missing required step."""
    partial = PP.SAFETY_STEP_AUTHENTICATED
    result = P.evaluate_gate(None, PP.SAFETY_OP_INJECT_DLL, partial)
    assert result.decision_name == "deny"
    assert result.failed_step == 2
    assert result.failed_step_name == "confirm_dialog"


def test_eval_input_field_order():
    fields = [f[0] for f in PP.MYARK_SAFETY_EVAL_INPUT._fields_]
    expected = [
        "OperationCode",
        "Reserved1",
        "StepFlags",
        "Reserved2",
        "TargetId",
        "Reserved3",
    ]
    assert fields == expected


def test_eval_output_field_order():
    fields = [f[0] for f in PP.MYARK_SAFETY_EVAL_OUTPUT._fields_]
    assert fields == ["Decision", "FailedStep", "Reserved1", "Reserved2"]