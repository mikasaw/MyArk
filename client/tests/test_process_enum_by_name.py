"""process enum-by-name: case-insensitive substring filter.

Pure-Python tests (no Win32 dependency). The filter helper lives in
``myark.modules.process.cli`` and the CLI registration is exercised via
argparse shape checks.
"""

from __future__ import annotations

import argparse

import pytest

from myark.modules.process import cli as process_cli
from myark.modules.process.protocol import ProcessRow


def _row(pid: int, name: str, path: str = "") -> ProcessRow:
    return ProcessRow(pid=pid, ppid=0, name=name, path=path, session_id=0, thread_count=1)


class TestFilterProcessesByName:
    """The pure-Python filter behind ``enum-by-name``."""

    def test_empty_name_returns_all(self) -> None:
        rows = [_row(1, "explorer.exe"), _row(2, "svchost.exe")]
        assert process_cli.filter_processes_by_name(rows, "") == rows

    def test_whitespace_only_returns_all(self) -> None:
        rows = [_row(1, "explorer.exe"), _row(2, "svchost.exe")]
        assert process_cli.filter_processes_by_name(rows, "   ") == rows

    def test_exact_match_returns_match(self) -> None:
        rows = [_row(1, "explorer.exe"), _row(2, "svchost.exe")]
        out = process_cli.filter_processes_by_name(rows, "explorer.exe")
        assert [r.pid for r in out] == [1]

    def test_case_insensitive(self) -> None:
        rows = [_row(1, "Explorer.EXE"), _row(2, "svchost.exe")]
        assert process_cli.filter_processes_by_name(rows, "explorer") == [rows[0]]
        assert process_cli.filter_processes_by_name(rows, "EXPLORER") == [rows[0]]
        assert process_cli.filter_processes_by_name(rows, "Explorer") == [rows[0]]

    def test_substring_match(self) -> None:
        rows = [
            _row(1, "explorer.exe"),
            _row(2, "svchost.exe"),
            _row(3, "RuntimeBroker.exe"),
        ]
        # 'host' is a substring of svchost but not of the other two
        out = process_cli.filter_processes_by_name(rows, "host")
        assert [r.pid for r in out] == [2]

    def test_no_match_returns_empty(self) -> None:
        rows = [_row(1, "explorer.exe"), _row(2, "svchost.exe")]
        out = process_cli.filter_processes_by_name(rows, "nonexistent")
        assert out == []

    def test_surrounding_whitespace_is_trimmed(self) -> None:
        rows = [_row(1, "explorer.exe")]
        out = process_cli.filter_processes_by_name(rows, "  explorer  ")
        assert [r.pid for r in out] == [1]

    def test_preserves_input_order(self) -> None:
        rows = [_row(1, "alpha.exe"), _row(2, "beta.exe"), _row(3, "alphacore.exe")]
        out = process_cli.filter_processes_by_name(rows, "alpha")
        assert [r.pid for r in out] == [1, 3]


class TestEnumByNameCliShape:
    """The argparse subcommand must be wired up under ``process``."""

    def test_enum_by_name_is_registered(self) -> None:
        top = argparse.ArgumentParser()
        subs = top.add_subparsers(dest="cmd")
        process_cli._setup_cli(subs, None)
        args = top.parse_args(["process", "enum-by-name", "explorer"])
        assert args.process_command == "enum-by-name"
        assert args.name == "explorer"

    def test_enum_by_name_requires_name_arg(self) -> None:
        top = argparse.ArgumentParser()
        subs = top.add_subparsers(dest="cmd")
        process_cli._setup_cli(subs, None)
        with pytest.raises(SystemExit):
            top.parse_args(["process", "enum-by-name"])