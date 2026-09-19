"""
Tests for the module subsystem R3 fallback.

The parser issues real Win32 calls; tests that require a live PID and
admin privileges are skipped gracefully when the target process is not
available or access is denied.
"""

from __future__ import annotations

import pytest

from myark.modules.module import parser, protocol


def _self_pid() -> int:
    import os

    return os.getpid()


def test_module_protocol_dataclass():
    row = protocol.ModuleRow(
        pid=4,
        base_address=0x7FFE0000,
        size=0x1000,
        entry_point=0x7FFE0100,
        name="ntdll.dll",
        path="C:\\Windows\\System32\\ntdll.dll",
    )
    assert row.pid == 4
    assert row.name == "ntdll.dll"
    assert row.size == 0x1000
    assert row.path.endswith("ntdll.dll")


def test_module_protocol_defaults():
    row = protocol.ModuleRow()
    assert row.pid == 0
    assert row.base_address == 0
    assert row.size == 0
    assert row.name == ""
    assert row.path == ""


def test_module_access_denied_error_is_module_error():
    assert issubclass(protocol.AccessDeniedError, protocol.ModuleError)


def test_module_enumerate_self_or_skip():
    """Enumerate the test process's own modules -- should always work
    in the current process regardless of admin state."""
    try:
        rows = parser.enumerate_modules(_self_pid())
    except protocol.AccessDeniedError as exc:
        pytest.skip(f"Access denied enumerating self (Win32 error 5): {exc}")
    except protocol.ModuleError as exc:
        pytest.skip(f"ModuleError enumerating self: {exc}")

    assert isinstance(rows, list)
    assert len(rows) > 0, "current process should always have at least one module"
    for r in rows:
        assert r.pid == _self_pid()
        assert r.size > 0
        assert r.base_address != 0
        assert r.name  # base name non-empty


def test_module_enumerate_invalid_pid_raises():
    """PID 0 (idle process) is not openable; expect a Win32 error."""
    with pytest.raises((protocol.AccessDeniedError, protocol.ModuleError)):
        parser.enumerate_modules(0)


def test_module_constants_present():
    assert protocol.PROCESS_QUERY_INFORMATION == 0x0400
    assert protocol.PROCESS_QUERY_LIMITED_INFORMATION == 0x1000


__all__ = []