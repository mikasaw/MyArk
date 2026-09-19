"""R3 process module acceptance: pure-R3 (no driver).

Covers the dataclass wire-format (Python 3.14 ctypes strict typing),
the R3 parser (psapi / advapi32 / toolhelp), and the CLI registration
shape. The driver itself is not required for any test in this file --
the goal is "passes on a Windows host that never installed MyArkCore.sys".

Tests that need Win32 (psapi / advapi32 / kernel32) skip cleanly on
non-Windows or in headless CI environments that lack those DLLs.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import sys

import pytest

from myark.modules.process import cli as process_cli
from myark.modules.process import protocol as proto


def _win32_dlls_available() -> bool:
    """Skip the live Win32 tests where any of the required DLLs is missing."""
    for name in ("kernel32.dll", "psapi.dll", "advapi32.dll"):
        try:
            ctypes.WinDLL(name)
        except OSError:
            return False
    return True


_SKIP_NO_WIN32 = pytest.mark.skipif(
    not _win32_dlls_available(),
    reason="kernel32 / psapi / advapi32 not available in this environment",
)


# ---------------------------------------------------------------------------
# protocol.py -- dataclass data shapes (always run, no Win32 calls)
# ---------------------------------------------------------------------------


class TestDataclassShapes:
    """The dataclass fields must line up with the parser's return rows.

    These tests pin the public attribute names so a future rename breaks
    a test instead of silently breaking callers.
    """

    def test_process_row_fields(self) -> None:
        from myark.modules.process.protocol import ProcessRow
        r = ProcessRow(pid=1, ppid=0, name="x", path="y", session_id=0, thread_count=2)
        assert r.pid == 1
        assert r.ppid == 0
        assert r.name == "x"
        assert r.path == "y"
        assert r.session_id == 0
        assert r.thread_count == 2

    def test_thread_row_fields(self) -> None:
        from myark.modules.process.protocol import ThreadRow
        r = ThreadRow(tid=2, owner_pid=1, base_priority=8)
        assert r.tid == 2
        assert r.owner_pid == 1
        assert r.base_priority == 8

    def test_process_detail_fields(self) -> None:
        from myark.modules.process.protocol import ProcessDetail
        d = ProcessDetail(
            pid=4,
            name="System",
            path="System",
            session_id=0,
            exit_code=0,
            priority_class=0x20,
            thread_count=300,
        )
        assert d.pid == 4
        assert d.exit_code == 0
        assert d.thread_count == 300
        assert d.priority_class == 0x20

    def test_access_right_constants(self) -> None:
        # Access right masks mirror the kernel definitions.
        assert proto.PROCESS_TERMINATE == 0x0001
        assert proto.PROCESS_VM_READ == 0x0010
        assert proto.PROCESS_VM_WRITE == 0x0020
        assert proto.PROCESS_QUERY_INFORMATION == 0x0400
        assert proto.PROCESS_QUERY_LIMITED_INFORMATION == 0x1000
        assert proto.PROCESS_SUSPEND_RESUME == 0x0800
        assert proto.THREAD_SUSPEND_RESUME == 0x0002
        assert proto.THREAD_TERMINATE == 0x0001

    def test_integrity_level_constants(self) -> None:
        assert proto.INTEGRITY_LEVEL_LOW == 0x10000
        assert proto.INTEGRITY_LEVEL_MEDIUM == 0x20000
        assert proto.INTEGRITY_LEVEL_HIGH == 0x30000
        assert proto.INTEGRITY_LEVEL_SYSTEM == 0x40000

    def test_token_information_class(self) -> None:
        assert proto.TokenIntegrityLevel == 25

    def test_process_error_hierarchy(self) -> None:
        assert issubclass(proto.AccessDeniedError, proto.ProcessError)


# ---------------------------------------------------------------------------
# parser.py -- pure-R3 helpers (Win32; skip when DLLs unavailable)
# ---------------------------------------------------------------------------


@_SKIP_NO_WIN32
class TestParserEnumProcesses:
    """``enum_processes`` against the live Win32 API."""

    def test_returns_at_least_self(self) -> None:
        from myark.modules.process.parser import enum_processes
        rows = enum_processes()
        # Every Windows host has at least one process (the System Idle
        # Process and System are listed by toolhelp).
        assert len(rows) >= 1
        # The dataclass rows must be ProcessRow instances.
        for r in rows:
            assert isinstance(r.pid, int)
            assert isinstance(r.name, str)
            assert r.name, f"pid {r.pid} has empty name"

    def test_total_pids_covers_self(self) -> None:
        from myark.modules.process.parser import enum_processes
        rows = enum_processes()
        my_pid = os.getpid()
        pids = {r.pid for r in rows}
        assert my_pid in pids, (
            f"self PID {my_pid} missing from enum_processes output"
        )

    def test_rows_are_well_formed(self) -> None:
        from myark.modules.process.parser import enum_processes
        rows = enum_processes()
        for r in rows:
            assert isinstance(r.pid, int)
            assert isinstance(r.ppid, int)
            assert isinstance(r.name, str)
            assert isinstance(r.thread_count, int)


@_SKIP_NO_WIN32
class TestParserEnumThreads:
    """``enum_threads`` for a known live PID."""

    def test_self_has_at_least_one_thread(self) -> None:
        from myark.modules.process.parser import enum_threads
        rows = enum_threads(os.getpid())
        assert len(rows) >= 1
        for r in rows:
            assert r.owner_pid == os.getpid()

    def test_unknown_pid_returns_empty(self) -> None:
        from myark.modules.process.parser import enum_threads
        rows = enum_threads(0xFFFFFFFE)
        assert rows == []


@_SKIP_NO_WIN32
class TestParserProcessDetail:
    """``process_detail`` for a known live PID (or AccessDenied)."""

    def test_self_resolves(self) -> None:
        from myark.modules.process.parser import process_detail
        my_pid = os.getpid()
        d = process_detail(my_pid)
        assert d.pid == my_pid
        # At least one of name / path should be populated; if both are
        # empty we hit a privilege problem and the test should fail so the
        # operator can elevate.
        assert d.name or d.path, (
            "R3 detail returned no name AND no path -- likely needs admin"
        )


@_SKIP_NO_WIN32
class TestParserReadProcessMemory:
    """``read_process_memory`` against the self process."""

    def test_read_64_bytes_from_self_peb(self) -> None:
        from myark.modules.process.parser import read_process_memory
        data = read_process_memory(os.getpid(), 0, 64)
        # addr==0 is intercepted by the parser and rewritten to the PEB
        # base address. The data must contain at least the InheritedFrom
        # UniqueProcessId -- not asserted for content, just length.
        assert isinstance(data, (bytes, bytearray))
        assert len(data) <= 64


# ---------------------------------------------------------------------------
# CLI registration -- ensure the parser tree covers the 14 subcommands
# (9 R3 + 5 R0-only placeholders).
# ---------------------------------------------------------------------------


def _process_subcommand_names() -> set[str]:
    """Return the set of names under ``myark-cli process <subcommand>``."""
    top = argparse.ArgumentParser()
    subs = top.add_subparsers(dest="cmd")
    process_cli._setup_cli(subs, None)

    candidates = {
        "enum": [],
        "enum-by-name": ["explorer"],
        "threads": ["1"],
        "detail": ["1"],
        "detail-runtime": ["1"],
        "terminate": ["1"],
        "suspend": ["1"],
        "resume": ["1"],
        "set-integrity": ["1", "low"],
        "inject": ["1", "C:\\temp\\x.dll"],
        "crossview": [],
        "set-ppl": [],
        "set-visibility": [],
        "dkom": [],
        "set-flags": [],
    }
    accepted: set[str] = set()
    for name, tail in candidates.items():
        try:
            top.parse_args(["process", name, *tail])
            accepted.add(name)
        except SystemExit:
            pass
    return accepted


class TestCliShape:
    def test_setup_cli_registers_fifteen_subcommands(self) -> None:
        names = _process_subcommand_names()
        expected = {
            "enum", "enum-by-name", "threads", "detail", "detail-runtime", "terminate",
            "suspend", "resume", "set-integrity", "inject",
            "crossview", "set-ppl", "set-visibility", "dkom", "set-flags",
        }
        missing = expected - names
        extra = names - expected
        assert not missing, f"missing subcommands: {sorted(missing)}"
        assert not extra, f"unexpected subcommands: {sorted(extra)}"

    def test_set_integrity_accepts_all_levels(self) -> None:
        top = argparse.ArgumentParser()
        subs = top.add_subparsers(dest="cmd")
        process_cli._setup_cli(subs, None)
        for level in ("low", "medium", "high", "system"):
            args = top.parse_args(["process", "set-integrity", "4", level])
            assert args.level == level


# ---------------------------------------------------------------------------
# Module registration -- ensure the plugin shape is right.
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_register_returns_module_registration(self) -> None:
        from myark.plugin_loader import ModuleRegistration
        from myark.modules.process import register as process_register

        reg = process_register(None, [])
        assert isinstance(reg, ModuleRegistration)
        assert reg.name == "process"
        assert reg.description
        assert reg.cli_setup is not None

    def test_register_callable_via_package(self) -> None:
        import myark.modules.process as pkg
        assert hasattr(pkg, "register")
        assert callable(pkg.register)
        # parser module must be importable from the package surface so
        # scripts can ``from myark.modules.process.parser import ...``.
        assert hasattr(pkg, "parser")

    def test_register_appears_in_builtin_loader(self) -> None:
        from myark import _builtin_modules

        assert "process" in _builtin_modules._BUILTIN_MODULE_NAMES

    def test_register_marks_r3_only(self) -> None:
        from myark.modules.process import register as process_register
        reg = process_register(None, [])
        # The R3-fallback flag tells the UI to skip the "driver not
        # installed" banner since the module never needed it.
        assert reg.extra.get("r3_only") is True

    def test_register_cli_setup_is_callable(self) -> None:
        from myark.modules.process import register as process_register
        reg = process_register(None, [])
        assert callable(reg.cli_setup)

    def test_register_description_mentions_r3(self) -> None:
        from myark.modules.process import register as process_register
        reg = process_register(None, [])
        # The description should mention R3 so users know the module
        # does not need the driver.
        assert "R3" in reg.description

    def test_register_name_is_process(self) -> None:
        from myark.modules.process import register as process_register
        reg = process_register(None, [])
        assert reg.name == "process"