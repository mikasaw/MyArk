"""
Tests for the dyndata R3 client (parser.py / cli.py).

These tests mock ``myark.client.ark_client.ArkClient.ioctl`` so they can
exercise the parser / CLI without needing the actual driver. The
behavioural check is: every ``query_*`` helper sends exactly one IOCTL
with the right function code, and renders a sensible empty-result
response when the driver is absent.

The end-to-end TestCliEndToEnd class walks the real ``myark.cli.main``
dispatcher via ``subprocess.run`` -- it would have caught the original
``TypeError: _cmd_query_process() missing 1 required positional argument:
'args'`` regression that the in-process ``TestCliHandlers`` tests
accidentally hid by hand-building the Namespace.
"""

from __future__ import annotations

import argparse
import ctypes
import io
import os
import struct
import subprocess
import sys
from contextlib import redirect_stderr, redirect_stdout
from typing import List
from unittest import mock

import pytest

from myark.client.ark_client import ArkClient
from myark.modules.dyndata import cli, parser
from myark.modules.dyndata import protocol as P


# ---------------------------------------------------------------------------
# Fake ArkClient that captures IOCTL calls and serves a canned empty output.
# ---------------------------------------------------------------------------

class _FakeArkClient:
    """Captures each DeviceIoControl call and returns a synthetic payload."""

    def __init__(self, empty_output: bytes = b"\x00" * 64) -> None:
        self._calls: List[dict] = []
        self._empty_output = empty_output
        self._closed = False

    def ioctl(self, code: int, in_bytes, out_buf) -> int:
        """Mirror the real ``ArkClient.ioctl``: fill ``out_buf``, return bytes."""
        payload = b"" if in_bytes is None else bytes(in_bytes)
        self._calls.append({
            "code": code,
            "in_size": len(payload),
            "out_size": ctypes.sizeof(out_buf),
        })
        n = min(len(self._empty_output), ctypes.sizeof(out_buf))
        out_buf[:n] = self._empty_output[:n]
        return n

    def close(self) -> None:
        self._closed = True

    @property
    def calls(self) -> List[dict]:
        return self._calls

    @property
    def closed(self) -> bool:
        return self._closed


def _make_empty_output(header_size: int, output_struct: type = None) -> bytes:
    """Build a minimal valid empty output (Size header set, Count=0).

    The buffer is sized to the full ctypes.sizeof of the matching output
    struct (when supplied) so ``from_buffer_copy`` doesn't reject a too-
    short payload. The driver writes Size / Count / TotalSeen / Reserved
    into the first 16 bytes; the rest stays zeroed.
    """
    if output_struct is None:
        total = max(header_size, 16)
    else:
        total = max(header_size, ctypes.sizeof(output_struct))
    # Size header (4 bytes) + Count=0 (4 bytes) + TotalSeen=0 (4 bytes) +
    # Reserved0 (4 bytes); the rest stays zero so any other UINT32 / UINT64
    # header fields parse as 0.
    payload = bytearray(total)
    struct.pack_into("<I", payload, 0, header_size)
    struct.pack_into("<I", payload, 4, 0)
    return bytes(payload)


# ---------------------------------------------------------------------------
# parser.py: every query sends exactly one IOCTL with the expected code.
# ---------------------------------------------------------------------------

class TestQueryHelpers:
    def test_query_process_sends_correct_ioctl(self) -> None:
        client = _FakeArkClient(empty_output=_make_empty_output(P.HEADER_SIZE_PROCESS, P.MYARK_DYNDATA_QUERY_PROCESS_OUTPUT))
        result = parser.query_process(client, max_entries=128, pid_filter=0)
        assert len(client.calls) == 1
        assert client.calls[0]["code"] == P.IOCTL_MYARK_DYNDATA_QUERY_PROCESS
        assert client.calls[0]["in_size"] == ctypes.sizeof(P.MYARK_DYNDATA_QUERY_PROCESS_INPUT)
        assert result.count == 0

    def test_query_thread_sends_correct_ioctl(self) -> None:
        client = _FakeArkClient(empty_output=_make_empty_output(P.HEADER_SIZE_THREAD, P.MYARK_DYNDATA_QUERY_THREAD_OUTPUT))
        result = parser.query_thread(client, pid_filter=1234)
        assert len(client.calls) == 1
        assert client.calls[0]["code"] == P.IOCTL_MYARK_DYNDATA_QUERY_THREAD
        assert result.count == 0

    def test_query_module_sends_correct_ioctl(self) -> None:
        client = _FakeArkClient(empty_output=_make_empty_output(P.HEADER_SIZE_MODULE, P.MYARK_DYNDATA_QUERY_MODULE_OUTPUT))
        result = parser.query_module(client, max_entries=256)
        assert len(client.calls) == 1
        assert client.calls[0]["code"] == P.IOCTL_MYARK_DYNDATA_QUERY_MODULE
        assert result.count == 0

    def test_query_handle_sends_correct_ioctl(self) -> None:
        client = _FakeArkClient(empty_output=_make_empty_output(P.HEADER_SIZE_HANDLE, P.MYARK_DYNDATA_QUERY_HANDLE_OUTPUT))
        result = parser.query_handle(client, pid_filter=4, type_index_filter=0xFFFFFFFF)
        assert len(client.calls) == 1
        assert client.calls[0]["code"] == P.IOCTL_MYARK_DYNDATA_QUERY_HANDLE
        assert result.count == 0

    def test_query_file_sends_correct_ioctl(self) -> None:
        client = _FakeArkClient(empty_output=_make_empty_output(P.HEADER_SIZE_FILE, P.MYARK_DYNDATA_QUERY_FILE_OUTPUT))
        result = parser.query_file(client, pid_filter=5678)
        assert len(client.calls) == 1
        assert client.calls[0]["code"] == P.IOCTL_MYARK_DYNDATA_QUERY_FILE
        assert result.count == 0

    def test_query_syscall_sends_correct_ioctl(self) -> None:
        client = _FakeArkClient(empty_output=_make_empty_output(P.HEADER_SIZE_SYSCALL, P.MYARK_DYNDATA_QUERY_SYSCALL_OUTPUT))
        result = parser.query_syscall(client, table_mask=0)
        assert len(client.calls) == 1
        assert client.calls[0]["code"] == P.IOCTL_MYARK_DYNDATA_QUERY_SYSCALL
        assert result.count == 0

    def test_query_token_sends_correct_ioctl(self) -> None:
        client = _FakeArkClient(empty_output=_make_empty_output(P.HEADER_SIZE_TOKEN, P.MYARK_DYNDATA_QUERY_TOKEN_OUTPUT))
        result = parser.query_token(client, pid=1234)
        assert len(client.calls) == 1
        assert client.calls[0]["code"] == P.IOCTL_MYARK_DYNDATA_QUERY_TOKEN
        assert result.count == 0

    def test_query_object_sends_correct_ioctl(self) -> None:
        client = _FakeArkClient(empty_output=_make_empty_output(P.HEADER_SIZE_OBJECT, P.MYARK_DYNDATA_QUERY_OBJECT_OUTPUT))
        result = parser.query_object(client, max_entries=32)
        assert len(client.calls) == 1
        assert client.calls[0]["code"] == P.IOCTL_MYARK_DYNDATA_QUERY_OBJECT
        assert result.count == 0

    def test_query_ssdt_sends_correct_ioctl(self) -> None:
        client = _FakeArkClient(empty_output=_make_empty_output(P.HEADER_SIZE_SSDT, P.MYARK_DYNDATA_QUERY_SSDT_OUTPUT))
        result = parser.query_ssdt(client, max_entries=512)
        assert len(client.calls) == 1
        assert client.calls[0]["code"] == P.IOCTL_MYARK_DYNDATA_QUERY_SSDT
        assert result.count == 0


# ---------------------------------------------------------------------------
# cli.py: the CLI handler emits a friendly "driver not installed" line when
# open_or_null returns None, and a "# method=r0" line otherwise.
# ---------------------------------------------------------------------------

class TestCliHandlers:
    def test_driver_not_installed_emits_friendly_message(self) -> None:
        with mock.patch.object(ArkClient, "open_or_null", return_value=None):
            args = argparse.Namespace(pid=0, max_entries=64, type_index=None, table_mask=0)
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = cli._cmd_query_process(args)
            assert rc == 2
            assert "driver not installed" in stderr.getvalue()

    def test_driver_not_installed_handles_all_queries(self) -> None:
        with mock.patch.object(ArkClient, "open_or_null", return_value=None):
            for name in cli.QUERY_NAMES:
                handler = getattr(cli, f"_cmd_query_{name}", None)
                assert handler is not None, f"missing handler for query={name}"
                # token requires a pid; everything else defaults to 0/None.
                args = argparse.Namespace(pid=1234, max_entries=64,
                                          type_index=None, table_mask=0)
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    rc = handler(args)
                assert rc == 2, f"query={name} should exit 2 with no driver"
                assert "driver not installed" in stderr.getvalue()

    def test_successful_query_emits_summary_line(self) -> None:
        client = _FakeArkClient(empty_output=_make_empty_output(P.HEADER_SIZE_PROCESS, P.MYARK_DYNDATA_QUERY_PROCESS_OUTPUT))
        with mock.patch.object(ArkClient, "open_or_null", return_value=client):
            args = argparse.Namespace(pid=0, max_entries=64, type_index=None, table_mask=0)
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                rc = cli._cmd_query_process(args)
            assert rc == 0
            assert client.closed is True
            assert "query=process" in stdout.getvalue()
            assert "count=0" in stdout.getvalue()

    def test_token_query_requires_pid(self) -> None:
        # token handler is special: it rejects --pid=None BEFORE opening
        # the driver so argparse users see a clear error.
        client = _FakeArkClient()
        with mock.patch.object(ArkClient, "open_or_null", return_value=client):
            args = argparse.Namespace(pid=None, max_entries=1, type_index=None, table_mask=0)
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = cli._cmd_query_token(args)
            assert rc == 2
            assert "--pid is required" in stderr.getvalue()
            assert len(client.calls) == 0

    def test_ioctl_failure_surfaces_as_exit_code_3(self) -> None:
        def _boom(*_args, **_kwargs):
            raise RuntimeError("simulated DeviceIoControl failure")

        client = _FakeArkClient()
        client.ioctl = _boom  # type: ignore[assignment]

        with mock.patch.object(ArkClient, "open_or_null", return_value=client):
            args = argparse.Namespace(pid=0, max_entries=64, type_index=None, table_mask=0)
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = cli._cmd_query_process(args)
            assert rc == 3
            assert "DeviceIoControl failed" in stderr.getvalue()


# ---------------------------------------------------------------------------
# cli.py: parser wire-up -- the argparse subparser tree should expose all
# 9 query subcommands under ``dyndata``.
# ---------------------------------------------------------------------------

class TestCliParser:
    def _build_parser(self) -> argparse.ArgumentParser:
        root = argparse.ArgumentParser()
        subs = root.add_subparsers(dest="command")
        cli._setup_cli(subs, _client=None)
        return root

    def test_all_nine_subcommands_registered(self) -> None:
        parser = self._build_parser()
        # Walk three levels: root -> dyndata -> query -> 9 leaves.
        dyndata_action = None
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                dyndata_action = action
                break
        assert dyndata_action is not None
        dyndata_parser = dyndata_action.choices["dyndata"]

        root_sub_action = None
        for action in dyndata_parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                root_sub_action = action
                break
        assert root_sub_action is not None
        query_parser = root_sub_action.choices["query"]

        query_sub_action = None
        for action in query_parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                query_sub_action = action
                break
        assert query_sub_action is not None
        choices = set(query_sub_action.choices.keys())
        expected = {"process", "thread", "module", "handle",
                    "file", "syscall", "token", "object", "ssdt"}
        assert choices == expected, f"got {choices}, expected {expected}"

    def test_token_parser_requires_pid(self) -> None:
        parser = self._build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["dyndata", "query", "token"])

        args = parser.parse_args(["dyndata", "query", "token", "--pid", "1234"])
        assert args.pid == 1234


# ---------------------------------------------------------------------------
# try_query(): open_or_null returning None yields None without raising.
# ---------------------------------------------------------------------------

class TestTryQuery:
    def test_returns_none_when_driver_missing(self) -> None:
        with mock.patch.object(ArkClient, "open_or_null", return_value=None):
            result = parser.try_query(parser.query_process, max_entries=8)
            assert result is None

    def test_propagates_result_when_driver_present(self) -> None:
        client = _FakeArkClient(empty_output=_make_empty_output(P.HEADER_SIZE_PROCESS, P.MYARK_DYNDATA_QUERY_PROCESS_OUTPUT))
        with mock.patch.object(ArkClient, "open_or_null", return_value=client):
            result = parser.try_query(parser.query_process, max_entries=8)
            assert result is not None
            assert result.count == 0
            assert client.closed is True


# ---------------------------------------------------------------------------
# End-to-end CLI dispatch. Walks the real ``myark.cli.main`` argparse
# chain via subprocess.run so a regression in the dispatcher (e.g. the
# original TypeError where handlers expected ``(client, args)`` but the
# dispatcher only passed ``args``) shows up as a failing test rather
# than as a traceback in the user's terminal.
# ---------------------------------------------------------------------------

class TestCliEndToEnd:
    def _run_cli(self, *args: str) -> subprocess.CompletedProcess:
        # Inherit PYTHONPATH from the current interpreter so the subprocess
        # can resolve ``myark.cli.main`` without re-installing the package.
        env = os.environ.copy()
        return subprocess.run(
            [sys.executable, "-m", "myark.cli.main", *args],
            capture_output=True,
            text=True,
            env=env,
            timeout=15,
        )

    def test_dyndata_query_process_does_not_typeerror(self) -> None:
        proc = self._run_cli("dyndata", "query", "process")
        assert proc.returncode == 2, (
            f"expected exit 2 (driver not installed), got {proc.returncode}\n"
            f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
        )
        assert "driver not installed" in proc.stderr
        assert "Traceback" not in proc.stderr
        assert "TypeError" not in proc.stderr

    def test_dyndata_query_token_without_pid_errors(self) -> None:
        proc = self._run_cli("dyndata", "query", "token")
        assert proc.returncode != 0
        # argparse prints its own usage to stderr (SystemExit 2) when
        # --pid is missing.
        assert "--pid" in proc.stderr

    @pytest.mark.parametrize("kind", [
        "process", "thread", "module", "handle", "file",
        "syscall", "object", "ssdt",
    ])
    def test_dyndata_query_all_kinds_no_typeerror(self, kind: str) -> None:
        proc = self._run_cli("dyndata", "query", kind)
        assert "TypeError" not in proc.stderr, (
            f"{kind} raised TypeError; stdout={proc.stdout} stderr={proc.stderr}"
        )
        assert "Traceback" not in proc.stderr
        assert proc.returncode == 2


__all__ = []
