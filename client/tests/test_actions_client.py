"""
Tests for the actions module's R3 client (parser / dataclasses / tiered
degradation / CLI subprocess dispatch).
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from myark.modules.actions import parser as P
from myark.modules.actions import protocol as PP


# ---------------------------------------------------------------------------
# SafetyToken dataclass.
# ---------------------------------------------------------------------------

def test_safety_token_defaults():
    t = P.SafetyToken()
    assert t.magic == PP.MYARK_SAFETY_TOKEN_MAGIC
    assert t.pid == 0
    assert t.operation == 0
    assert t.timestamp != 0  # __post_init__ stamped time.time_ns()
    assert t.signature == b""


def test_safety_token_default_signature_is_nonzero():
    t = P.SafetyToken(pid=1234, operation=1)
    sig = t._default_signature()
    assert len(sig) == PP.MYARK_SAFETY_TOKEN_SIGNATURE_SIZE
    assert any(b != 0 for b in sig)


def test_safety_token_build_populates_struct():
    t = P.SafetyToken(pid=42, operation=3)
    struct = t.build()
    assert struct.Magic == PP.MYARK_SAFETY_TOKEN_MAGIC
    assert struct.Pid == 42
    assert struct.Operation == 3
    assert struct.Timestamp == t.timestamp
    assert any(b != 0 for b in struct.Signature)


def test_safety_token_build_stamps_signature_in_struct():
    t = P.SafetyToken(pid=999, operation=7, signature=b"X" * 32)
    struct = t.build()
    for i in range(PP.MYARK_SAFETY_TOKEN_SIGNATURE_SIZE):
        assert struct.Signature[i] == ord("X")


def test_safety_token_different_pid_op_produce_different_sigs():
    a = P.SafetyToken(pid=1, operation=1)._default_signature()
    b = P.SafetyToken(pid=2, operation=1)._default_signature()
    assert a != b
    c = P.SafetyToken(pid=1, operation=2)._default_signature()
    assert a != c


# ---------------------------------------------------------------------------
# ActionResult dataclass.
# ---------------------------------------------------------------------------

def test_action_result_defaults():
    r = P.ActionResult()
    assert r.action == ""
    assert r.pid == 0
    assert r.result_code == PP.MYARK_ACTION_RESULT_R3_FALLBACK
    assert r.executed_tier == PP.MYARK_ACTION_TIER_R3
    assert r.source == "r3-fallback"


def test_action_result_tier_and_result_names_resolve():
    r = P.ActionResult(
        result_code=PP.MYARK_ACTION_RESULT_DEFERRED,
        executed_tier=PP.MYARK_ACTION_TIER_DEFERRED,
    )
    assert r.result_name == "deferred"
    assert r.tier_name == "deferred"


# ---------------------------------------------------------------------------
# Errors.
# ---------------------------------------------------------------------------

def test_r3_fallback_unavailable_carries_action_name():
    exc = P.R3FallbackUnavailable("hide_process")
    assert exc.action_name == "hide_process"
    assert "R0-only" in str(exc)


def test_safety_token_required_message_helpful():
    exc = P.SafetyTokenRequired("action 'kill_process': safety token required")
    assert "kill_process" in str(exc)
    assert "safety token" in str(exc)


# ---------------------------------------------------------------------------
# Token validation in _execute helper.
# ---------------------------------------------------------------------------

def test_make_token_rejects_when_none():
    with pytest.raises(P.SafetyTokenRequired):
        P._make_token("kill_process", 1234, None)


def test_make_token_rejects_pid_mismatch():
    t = P.SafetyToken(pid=1234, operation=PP.MYARK_ACTION_OP_KILL_PROCESS)
    with pytest.raises(P.ActionsError, match="pid"):
        P._make_token("kill_process", 5678, t)


def test_make_token_rejects_op_mismatch():
    t = P.SafetyToken(pid=1234, operation=PP.MYARK_ACTION_OP_KILL_PROCESS)
    with pytest.raises(P.ActionsError, match="operation"):
        P._make_token("terminate_thread", 1234, t)


def test_make_token_stamps_defaults_when_zero():
    t = P.SafetyToken()  # pid=0, op=0
    out = P._make_token("kill_process", 1234, t)
    assert out.pid == 1234
    assert out.operation == PP.MYARK_ACTION_OP_KILL_PROCESS


def test_make_token_raises_for_unknown_action():
    t = P.SafetyToken(pid=1, operation=99)
    with pytest.raises(P.ActionsError, match="unknown action"):
        P._make_token("nope", 1, t)


# ---------------------------------------------------------------------------
# Tiered degradation: R0-only actions must raise when driver missing.
# ---------------------------------------------------------------------------

def test_r0_only_actions_have_no_r3_fallback():
    for name in ("set_token", "hide_process", "protect_process"):
        assert name not in PP.ACTIONS_R0_FALLBACK_AVAILABLE


def test_r3_only_actions_are_in_fallback_set():
    for name in ("kill_process", "terminate_thread", "inject_dll", "dump_memory"):
        assert name in PP.ACTIONS_R0_FALLBACK_AVAILABLE


def test_hide_process_raises_r3_fallback_unavailable():
    """hide_process is R0-only; without a driver we must error rather than call win32."""
    with pytest.raises(P.R3FallbackUnavailable):
        P.hide_process(None, pid=1234, token=P.SafetyToken(pid=1234, operation=PP.MYARK_ACTION_OP_HIDE_PROCESS))


def test_protect_process_raises_r3_fallback_unavailable():
    with pytest.raises(P.R3FallbackUnavailable):
        P.protect_process(None, pid=1234, token=P.SafetyToken(pid=1234, operation=PP.MYARK_ACTION_OP_PROTECT_PROCESS))


def test_set_token_raises_r3_fallback_unavailable():
    with pytest.raises(P.R3FallbackUnavailable):
        P.set_token(None, pid=1234, token=P.SafetyToken(pid=1234, operation=PP.MYARK_ACTION_OP_SET_TOKEN))


# ---------------------------------------------------------------------------
# CLI subprocess dispatch (mirrors the S7.1 e2e pattern).
# ---------------------------------------------------------------------------

def _run_cli(*args: str) -> subprocess.CompletedProcess:
    """Invoke ``python -m myark.cli.main actions ...`` and return the result."""
    return subprocess.run(
        [sys.executable, "-m", "myark.cli.main", *args],
        capture_output=True,
        text=True,
        timeout=20,
    )


def test_cli_actions_help_lists_7_subcommands():
    result = _run_cli("actions", "--help")
    # argparse may emit to stdout or stderr; both should mention the subcommands.
    out = result.stdout + result.stderr
    for sub in ("kill", "terminate-thread", "inject-dll", "dump-memory",
                "set-token", "hide-process", "protect-process"):
        assert sub in out, f"missing subcommand {sub!r} in CLI help:\n{out}"


def test_cli_actions_kill_no_token_friendly_error():
    """``--no-token`` should make the CLI surface 'safety token required'."""
    result = _run_cli("actions", "kill", "--pid", "1234", "--no-token")
    # Exit code 2 is reserved for "safety token required" (matches dyndata pattern).
    assert result.returncode == 2
    out = result.stdout + result.stderr
    assert "safety token" in out.lower() or "kill" in out.lower()


def test_cli_actions_set_token_no_driver_is_clean_error():
    """set_token is R0-only; without a driver it should error (no stack trace)."""
    result = _run_cli("actions", "set-token", "--pid", "1234")
    # Either the driver is installed (exit 0 with a result line) OR the
    # CLI surfaces a friendly "R0-only" / "driver not installed" message
    # with exit 3. A Python traceback is never acceptable.
    out = result.stdout + result.stderr
    assert "Traceback" not in out, f"CLI leaked a traceback:\n{out}"
    if result.returncode != 0:
        assert "R0-only" in out or "driver" in out.lower()


def test_cli_actions_root_without_subcommand():
    """`myark-cli actions` alone should be rejected with usage / exit 2."""
    result = _run_cli("actions")
    assert result.returncode == 2


# ---------------------------------------------------------------------------
# Module registration smoke test (mirrors S7.2 pattern).
# ---------------------------------------------------------------------------

def test_module_registration_imports_cleanly():
    from myark.modules.actions import register
    from myark.plugin_loader import ModuleRegistration
    reg = register(None, [])
    assert isinstance(reg, ModuleRegistration)
    assert reg.name == "actions"
    assert reg.cli_setup is not None


def test_module_appears_in_builtin_list():
    from myark._builtin_modules import _BUILTIN_MODULE_NAMES
    assert "actions" in _BUILTIN_MODULE_NAMES


def test_module_pyproject_entry_point():
    """[project.entry-points.myark_modules] should list the actions module."""
    import tomllib
    from pathlib import Path

    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    with pyproject.open("rb") as fh:
        data = tomllib.load(fh)
    eps = data["project"]["entry-points"]["myark_modules"]
    assert "actions" in eps
    assert eps["actions"] == "myark.modules.actions:register"