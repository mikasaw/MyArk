"""
Tests for the callback R3 client (parser.py / cli.py).

These tests mock ``myark.client.ark_client.ArkClient.ioctl`` so they can
exercise the parser / CLI without needing the actual driver. The
behavioural check is: every ``query_*`` helper sends exactly one IOCTL
with the right function code, and renders a sensible empty-response
result when the driver is absent.

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
from myark.modules.callback import cli, parser
from myark.modules.callback import protocol as P


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
    """Build a minimal valid empty output (Size header set, Count=0)."""
    if output_struct is None:
        total = max(header_size, 16)
    else:
        total = max(header_size, ctypes.sizeof(output_struct))
    payload = bytearray(total)
    struct.pack_into("<I", payload, 0, header_size)
    struct.pack_into("<I", payload, 4, 0)
    return bytes(payload)


# ---------------------------------------------------------------------------
# parser.py: every query sends exactly one IOCTL with the expected code.
# ---------------------------------------------------------------------------

class TestQueryHelpers:
    def test_query_ps_sends_correct_ioctl(self) -> None:
        client = _FakeArkClient(empty_output=_make_empty_output(P.HEADER_SIZE_PS, P.MYARK_CALLBACK_QUERY_PS_OUTPUT))
        result = parser.query_ps(client, max_entries=32)
        assert len(client.calls) == 1
        assert client.calls[0]["code"] == P.IOCTL_MYARK_CALLBACK_QUERY_PS
        assert client.calls[0]["in_size"] == ctypes.sizeof(P.MYARK_CALLBACK_QUERY_PS_INPUT)
        assert result.count == 0

    def test_query_cm_sends_correct_ioctl(self) -> None:
        client = _FakeArkClient(empty_output=_make_empty_output(P.HEADER_SIZE_CM, P.MYARK_CALLBACK_QUERY_CM_OUTPUT))
        result = parser.query_cm(client, max_entries=32)
        assert len(client.calls) == 1
        assert client.calls[0]["code"] == P.IOCTL_MYARK_CALLBACK_QUERY_CM
        assert result.count == 0

    def test_query_ob_sends_correct_ioctl(self) -> None:
        client = _FakeArkClient(empty_output=_make_empty_output(P.HEADER_SIZE_OB, P.MYARK_CALLBACK_QUERY_OB_OUTPUT))
        result = parser.query_ob(client, max_entries=32)
        assert len(client.calls) == 1
        assert client.calls[0]["code"] == P.IOCTL_MYARK_CALLBACK_QUERY_OB
        assert result.count == 0

    def test_query_image_sends_correct_ioctl(self) -> None:
        client = _FakeArkClient(empty_output=_make_empty_output(P.HEADER_SIZE_IMAGE, P.MYARK_CALLBACK_QUERY_IMAGE_OUTPUT))
        result = parser.query_image(client, max_entries=32)
        assert len(client.calls) == 1
        assert client.calls[0]["code"] == P.IOCTL_MYARK_CALLBACK_QUERY_IMAGE
        assert result.count == 0

    def test_query_dbg_sends_correct_ioctl(self) -> None:
        client = _FakeArkClient(empty_output=_make_empty_output(P.HEADER_SIZE_DBG, P.MYARK_CALLBACK_QUERY_DBG_OUTPUT))
        result = parser.query_dbg(client, max_entries=16)
        assert len(client.calls) == 1
        assert client.calls[0]["code"] == P.IOCTL_MYARK_CALLBACK_QUERY_DBG
        assert result.count == 0

    def test_enumerate_sends_correct_ioctl(self) -> None:
        client = _FakeArkClient(empty_output=_make_empty_output(P.HEADER_SIZE_ENUM, P.MYARK_CALLBACK_ENUMERATE_OUTPUT))
        result = parser.enumerate(client, max_entries=128)
        assert len(client.calls) == 1
        assert client.calls[0]["code"] == P.IOCTL_MYARK_CALLBACK_ENUMERATE
        assert result.count == 0

    def test_stats_sends_correct_ioctl(self) -> None:
        stats_payload = bytearray(ctypes.sizeof(P.MYARK_CALLBACK_STATS_OUTPUT))
        struct.pack_into("<I", stats_payload, 0, ctypes.sizeof(P.MYARK_CALLBACK_STATS_OUTPUT))
        client = _FakeArkClient(empty_output=bytes(stats_payload))
        stats = parser.stats(client)
        assert len(client.calls) == 1
        assert client.calls[0]["code"] == P.IOCTL_MYARK_CALLBACK_STATS
        assert stats.ps_count == 0
        assert stats.total_count == 0


# ---------------------------------------------------------------------------
# cli.py: the CLI handler emits a friendly "driver not installed" line when
# open_or_null returns None, and a "# method=r0" line otherwise.
# ---------------------------------------------------------------------------

class TestCliHandlers:
    def test_driver_not_installed_emits_friendly_message(self) -> None:
        with mock.patch.object(ArkClient, "open_or_null", return_value=None):
            args = argparse.Namespace(max_entries=32, subtype_mask=0,
                                       operation_mask=0, category_mask=0)
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = cli._cmd_query_ps(args)
            assert rc == 2
            assert "driver not installed" in stderr.getvalue()

    def test_driver_not_installed_handles_all_queries(self) -> None:
        with mock.patch.object(ArkClient, "open_or_null", return_value=None):
            for name in cli.QUERY_NAMES:
                handler = getattr(cli, f"_cmd_query_{name}", None)
                assert handler is not None, f"missing handler for query={name}"
                args = argparse.Namespace(max_entries=32, subtype_mask=0,
                                           operation_mask=0, category_mask=0)
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    rc = handler(args)
                assert rc == 2, f"query={name} should exit 2 with no driver"
                assert "driver not installed" in stderr.getvalue()

    def test_successful_query_emits_summary_line(self) -> None:
        client = _FakeArkClient(empty_output=_make_empty_output(P.HEADER_SIZE_PS, P.MYARK_CALLBACK_QUERY_PS_OUTPUT))
        with mock.patch.object(ArkClient, "open_or_null", return_value=client):
            args = argparse.Namespace(max_entries=32, subtype_mask=0,
                                       operation_mask=0, category_mask=0)
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                rc = cli._cmd_query_ps(args)
            assert rc == 0
            assert client.closed is True
            assert "query=ps" in stdout.getvalue()
            assert "count=0" in stdout.getvalue()

    def test_ioctl_failure_surfaces_as_exit_code_3(self) -> None:
        def _boom(*_args, **_kwargs):
            raise RuntimeError("simulated DeviceIoControl failure")

        client = _FakeArkClient()
        client.ioctl = _boom  # type: ignore[assignment]

        with mock.patch.object(ArkClient, "open_or_null", return_value=client):
            args = argparse.Namespace(max_entries=32, subtype_mask=0,
                                       operation_mask=0, category_mask=0)
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = cli._cmd_query_ps(args)
            assert rc == 3
            assert "DeviceIoControl failed" in stderr.getvalue()


# ---------------------------------------------------------------------------
# cli.py: parser wire-up -- the argparse subparser tree should expose the
# 5 query subcommands under ``callback -> query`` AND other top-level
# subcommands (enumerate / stats / remove / restore / backup).
# ---------------------------------------------------------------------------

class TestCliParser:
    def _build_parser(self) -> argparse.ArgumentParser:
        root = argparse.ArgumentParser()
        subs = root.add_subparsers(dest="command")
        cli._setup_cli(subs, _client=None)
        return root

    def test_all_five_query_subcommands_registered(self) -> None:
        parser = self._build_parser()
        # Walk three levels: root -> callback -> query -> 5 leaves.
        callback_action = None
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                callback_action = action
                break
        assert callback_action is not None
        callback_parser = callback_action.choices["callback"]

        root_sub_action = None
        for action in callback_parser._actions:
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
        expected = {"ps", "cm", "ob", "image", "dbg"}
        assert choices == expected, f"got {choices}, expected {expected}"

    def test_top_level_subcommands_registered(self) -> None:
        parser = self._build_parser()
        callback_action = None
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                callback_action = action
                break
        assert callback_action is not None
        callback_parser = callback_action.choices["callback"]

        callback_sub_action = None
        for action in callback_parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                callback_sub_action = action
                break
        assert callback_sub_action is not None
        choices = set(callback_sub_action.choices.keys())
        expected = {"query", "enumerate", "stats", "remove", "restore", "backup"}
        assert choices == expected, f"got {choices}, expected {expected}"


# ---------------------------------------------------------------------------
# try_query(): open_or_null returning None yields None without raising.
# ---------------------------------------------------------------------------

class TestTryQuery:
    def test_returns_none_when_driver_missing(self) -> None:
        with mock.patch.object(ArkClient, "open_or_null", return_value=None):
            result = parser.try_query(parser.query_ps, max_entries=8)
            assert result is None

    def test_propagates_result_when_driver_present(self) -> None:
        client = _FakeArkClient(empty_output=_make_empty_output(P.HEADER_SIZE_PS, P.MYARK_CALLBACK_QUERY_PS_OUTPUT))
        with mock.patch.object(ArkClient, "open_or_null", return_value=client):
            result = parser.try_query(parser.query_ps, max_entries=8)
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
        env = os.environ.copy()
        return subprocess.run(
            [sys.executable, "-m", "myark.cli.main", *args],
            capture_output=True,
            text=True,
            env=env,
            timeout=15,
        )

    def test_callback_query_ps_does_not_typeerror(self) -> None:
        proc = self._run_cli("callback", "query", "ps")
        assert proc.returncode == 2, (
            f"expected exit 2 (driver not installed), got {proc.returncode}\n"
            f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
        )
        assert "driver not installed" in proc.stderr
        assert "Traceback" not in proc.stderr
        assert "TypeError" not in proc.stderr

    @pytest.mark.parametrize("kind", ["ps", "cm", "ob", "image", "dbg"])
    def test_callback_query_all_kinds_no_typeerror(self, kind: str) -> None:
        proc = self._run_cli("callback", "query", kind)
        assert "TypeError" not in proc.stderr, (
            f"{kind} raised TypeError; stdout={proc.stdout} stderr={proc.stderr}"
        )
        assert "Traceback" not in proc.stderr
        assert proc.returncode == 2

    def test_callback_enumerate_does_not_typeerror(self) -> None:
        proc = self._run_cli("callback", "enumerate")
        assert "TypeError" not in proc.stderr
        assert proc.returncode == 2
        assert "driver not installed" in proc.stderr

    def test_callback_stats_does_not_typeerror(self) -> None:
        proc = self._run_cli("callback", "stats")
        assert "TypeError" not in proc.stderr
        assert proc.returncode == 2
        assert "driver not installed" in proc.stderr

    @pytest.mark.parametrize("kind", ["remove", "restore", "backup"])
    def test_callback_reserve_kinds_return_3(self, kind: str) -> None:
        proc = self._run_cli("callback", kind)
        assert "TypeError" not in proc.stderr
        assert "Traceback" not in proc.stderr
        assert proc.returncode == 3, (
            f"{kind} should exit 3 (NOT_IMPLEMENTED), got {proc.returncode}\n"
            f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
        )


__all__ = []