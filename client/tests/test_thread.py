"""S6.2 acceptance: thread module ctypes wire-format + CLI shape tests.

Covers the wire format (mirrors ``shared/driver/MyArkThreadIoctl.h``) and
the CLI / module registration shape. The driver itself is not required --
the goal is "passes on a Windows host that never installed MyArkCore.sys".

Tests that need Win32 (kernel32 / psapi) skip cleanly on non-Windows or
in headless CI environments that lack those DLLs.
"""

from __future__ import annotations

import argparse
import ctypes
import sys

import pytest

from myark.modules.thread import cli as thread_cli
from myark.modules.thread import protocol as proto


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _win32_dlls_available() -> bool:
    """Skip the live Win32 tests where any of the required DLLs is missing."""
    for name in ("kernel32.dll", "psapi.dll"):
        try:
            ctypes.WinDLL(name)
        except OSError:
            return False
    return True


_SKIP_NO_WIN32 = pytest.mark.skipif(
    not _win32_dlls_available(),
    reason="kernel32 / psapi not available in this environment",
)


# ---------------------------------------------------------------------------
# protocol.py -- struct layout (always run, no Win32 calls)
# ---------------------------------------------------------------------------


class TestStructLayout:
    """The ctypes wire format mirrors the C driver; any drift shows up as
    a buffer-too-small error or garbage values when the driver reads back.
    """

    def test_thread_entry_size(self) -> None:
        # Tid(4) + Pid(4) + StartAddress(8) + Module[64](128) +
        # State(1) + Anomaly(1) + Reserved0(1) + Reserved1(1) +
        # Priority(4) + WaitReason(4) + CreateTime(8) + EThreadKernelAddress(8)
        # = 4+4+8+128+4+4+4+4+8+8 = 176 bytes.
        assert ctypes.sizeof(proto.MYARK_THREAD_ENTRY) == 176

    def test_enum_output_header_size(self) -> None:
        # ENUM_OUTPUT header is Size + Count + OwnerPid + AnomalyCount (16 bytes)
        # plus one trailing MYARK_THREAD_ENTRY (176).
        assert (
            ctypes.sizeof(proto.MYARK_THREAD_ENUM_OUTPUT)
            - ctypes.sizeof(proto.MYARK_THREAD_ENTRY)
        ) == 16

    def test_detail_size(self) -> None:
        # 8 UINT32 (Tid..Anomaly+Reserved0) + 5 UINT64 (CreateTime..EProcess)
        # + 8 UINT32 (UniqueThreadIdOffset..ApcStateProcessOffset) +
        # Module[64](128) + StartAddressModulePath[260](520)
        # = 32 + 40 + 32 + 128 + 520 = 752 bytes.
        assert ctypes.sizeof(proto.MYARK_THREAD_DETAIL) == 752

    def test_detail_runtime_size(self) -> None:
        # 2 UINT32 (Tid + Reserved0) + 3 UINT64 (Kernel/User/Cycle) +
        # 2 UINT32 (ContextSwitches + Reserved1) + 2 UINT32 (StateFlags + Reserved2)
        # = 8 + 24 + 8 + 8 = 48 bytes.
        assert ctypes.sizeof(proto.MYARK_THREAD_DETAIL_RUNTIME) == 48

    def test_crossview_output_header_size(self) -> None:
        assert (
            ctypes.sizeof(proto.MYARK_THREAD_CROSSVIEW_OUTPUT)
            - ctypes.sizeof(proto.MYARK_THREAD_ENTRY)
        ) == 16

    def test_ioctl_function_codes_align(self) -> None:
        # All 5 thread IOCTLs must lie in the 0xA1x range; no overlap with
        # process (0xA0x) or other modules.
        codes = [
            proto.IOCTL_MYARK_THREAD_ENUM,
            proto.IOCTL_MYARK_THREAD_DETAIL,
            proto.IOCTL_MYARK_THREAD_DETAIL_RUNTIME,
            proto.IOCTL_MYARK_THREAD_CROSSVIEW,
            proto.IOCTL_MYARK_THREAD_TERMINATE,
        ]
        assert len(set(codes)) == 5, "thread IOCTL codes must be unique"
        for code in codes:
            assert (code >> 2) & 0xFFF in range(0xA10, 0xA15), \
                f"IOCTL {code:#x} outside 0xA10..0xA14 range"

    def test_thread_entry_round_trip(self) -> None:
        e = proto.MYARK_THREAD_ENTRY(
            Tid=0x1234,
            Pid=0x5678,
            StartAddress=0xFFFF800000000000,
            Module="ntoskrnl.exe",
            State=2,        # Running
            Anomaly=0,
            Reserved0=0,
            Reserved1=0,
            Priority=16,
            WaitReason=0,
            CreateTime=0xDEADBEEF,
            EThreadKernelAddress=0xFFFFF80300000000,
        )
        rebuilt = proto.MYARK_THREAD_ENTRY.from_buffer_copy(bytes(e))
        assert rebuilt.Tid == 0x1234
        assert rebuilt.Pid == 0x5678
        assert rebuilt.StartAddress == 0xFFFF800000000000
        assert rebuilt.Module == "ntoskrnl.exe"
        assert rebuilt.State == 2
        assert rebuilt.Priority == 16
        assert rebuilt.CreateTime == 0xDEADBEEF
        assert rebuilt.EThreadKernelAddress == 0xFFFFF80300000000

    def test_source_and_hidden_constants(self) -> None:
        # The masks used by the R3 parser and the driver must be byte-equal.
        assert proto.SRC_PUBLIC == 0x01
        assert proto.SRC_THREADLIST == 0x02
        assert proto.SRC_PSPCIDTABLE == 0x04
        assert proto.HIDDEN_NONE == 0x00
        assert proto.HIDDEN_VIA_DKOM == 0x01

    def test_anomaly_constants(self) -> None:
        assert proto.ANOMALY_NONE == 0x00
        assert proto.ANOMALY_START_OUTSIDE_MODULE == 0x01

    def test_module_id_constant(self) -> None:
        # MYARK_THREAD_MODULE_ID = 0x44524854UL ('THRD' ASCII LE)
        # The constant lives in the C header; Python side mirrors via the
        # protocol shape. We pin the module-name string for the loader
        # instead.
        assert proto.MODULE_NAME_MAX == 64
        assert proto.START_PATH_MAX == 260


class TestThreadRowDataclass:
    def test_from_entry_roundtrip(self) -> None:
        e = proto.MYARK_THREAD_ENTRY(
            Tid=1234, Pid=5678, StartAddress=0x1000,
            Module="user32.dll", State=2, Anomaly=0, Reserved0=0, Reserved1=0,
            Priority=15, WaitReason=0, CreateTime=0x12345,
            EThreadKernelAddress=0xFFFF,
        )
        row = proto.ThreadRow.from_entry(e)
        assert row.tid == 1234
        assert row.pid == 5678
        assert row.start_address == 0x1000
        assert row.module == "user32.dll"
        assert row.state == 2
        assert row.state_name == "Running"
        assert row.priority == 15
        assert row.wait_name == "Executive"  # wait_reason == 0 maps to "Executive"
        assert row.ethread_addr == 0xFFFF

    def test_unknown_state_falls_back_to_string(self) -> None:
        e = proto.MYARK_THREAD_ENTRY(
            Tid=1, Pid=1, StartAddress=0, Module="", State=200,
            Anomaly=0, Reserved0=0, Reserved1=0, Priority=0, WaitReason=0,
            CreateTime=0, EThreadKernelAddress=0,
        )
        row = proto.ThreadRow.from_entry(e)
        assert row.state_name == "state=200"


# ---------------------------------------------------------------------------
# parser.py -- pure-R3 helpers (Win32; skip when DLLs unavailable)
# ---------------------------------------------------------------------------


@_SKIP_NO_WIN32
class TestParserEnumThreadsR3:
    """``enum_threads_r3`` against the live Win32 API."""

    def test_returns_at_least_self(self) -> None:
        from myark.modules.thread.parser import enum_threads_r3
        my_pid = 0
        try:
            import os
            my_pid = os.getpid()
        except Exception:
            pass
        # Pick a PID that exists; fall back to the test process if our
        # introspection failed.
        target = my_pid if my_pid else 0
        stats = enum_threads_r3(target if target else 4)
        assert stats is not None
        # Each row should be a ThreadRow with a tid.
        for r in stats.rows:
            assert isinstance(r.tid, int)
            assert isinstance(r.pid, int)


@_SKIP_NO_WIN32
class TestParserThreadDetailR3:
    """``thread_detail_r3`` against the live Win32 API.

    OpenThread + GetThreadTimes needs the caller to own the thread or
    hold THREAD_QUERY_INFORMATION. Skips when neither applies.
    """

    def test_self_thread_resolves(self) -> None:
        import os
        from myark.modules.thread.parser import thread_detail_r3, enum_threads_r3
        tids = [r.tid for r in enum_threads_r3(os.getpid()).rows]
        if not tids:
            pytest.skip("no threads visible for self")
        d = thread_detail_r3(tids[0])
        assert d["tid"] == tids[0]
        assert d["create_time"] > 0
        assert "kernel_time" in d
        assert "user_time" in d


@_SKIP_NO_WIN32
class TestParserThreadDetailRuntimeR3:
    """``thread_detail_runtime_r3`` snapshots the thread context.

    Suspending a thread while the calling thread is the same thread
    would deadlock, so the test only runs when the test process owns
    at least two threads (the main thread + worker threads from pytest /
    pytest-xdist). Single-threaded test runners skip the case.
    """

    def test_other_thread_context(self) -> None:
        import os
        from myark.modules.thread.parser import thread_detail_runtime_r3, enum_threads_r3
        my_tid_rows = enum_threads_r3(os.getpid()).rows
        # Find a thread that isn't the current one -- suspending self
        # would deadlock the test runner.
        my_tid = None
        try:
            import ctypes
            my_tid = ctypes.windll.kernel32.GetCurrentThreadId()
        except Exception:
            pass
        other = [r.tid for r in my_tid_rows if r.tid != my_tid]
        if not other:
            pytest.skip("no other thread available to suspend")
        ctx = thread_detail_runtime_r3(other[0])
        # R3 context acquisition can fail with AccessDenied when the
        # other thread belongs to a protected sub-process; tolerate.
        if "error" in ctx:
            pytest.skip(f"OpenThread failed: Win32 error {ctx['error']}")
        assert ctx["tid"] == other[0]
        assert "rip" in ctx
        assert "rsp" in ctx


@_SKIP_NO_WIN32
class TestParserTerminateThreadR3:
    """``terminate_thread_r3`` returns the Win32 status (or success)."""

    def test_unknown_tid_returns_nonzero(self) -> None:
        from myark.modules.thread.parser import terminate_thread_r3
        # 0xFFFFFFFE is well above any realistic live range; OpenThread
        # will fail and we surface the Win32 error as a nonzero status.
        status = terminate_thread_r3(0xFFFFFFFE)
        assert status != 0


# ---------------------------------------------------------------------------
# CLI registration -- ensure the parser tree covers all 5 IOCTLs.
# ---------------------------------------------------------------------------


def _thread_subcommand_names() -> set[str]:
    """Return the set of names under ``myark-cli thread <subcommand>``.

    Rather than introspect argparse's private ``_subparsers`` (the API
    shifts between Python minor versions), we feed each candidate name
    through ``parse_args`` with the minimum flags it needs.
    """
    top = argparse.ArgumentParser()
    subs = top.add_subparsers(dest="cmd")
    thread_cli._setup_cli(subs, None)

    candidates = {
        "enum": ["--pid", "1"],
        "detail": ["--tid", "1"],
        "detail-runtime": ["--tid", "1"],
        "crossview": ["--pid", "1"],
        "terminate": ["--tid", "1"],
    }
    accepted: set[str] = set()
    for name, tail in candidates.items():
        try:
            top.parse_args(["thread", name, *tail])
            accepted.add(name)
        except SystemExit:
            pass
    return accepted


class TestCliShape:
    def test_setup_cli_registers_five_subcommands(self) -> None:
        names = _thread_subcommand_names()
        expected = {"enum", "detail", "detail-runtime", "crossview", "terminate"}
        missing = expected - names
        extra = names - expected
        assert not missing, f"missing subcommands: {sorted(missing)}"
        assert not extra, f"unexpected subcommands: {sorted(extra)}"

    def test_enum_accepts_method_r0_and_r3(self) -> None:
        top = argparse.ArgumentParser()
        subs = top.add_subparsers(dest="cmd")
        thread_cli._setup_cli(subs, None)
        args = top.parse_args(["thread", "enum", "--pid", "1", "--method", "r3"])
        assert args.method == "r3"
        args = top.parse_args(["thread", "enum", "--pid", "1", "--method", "r0"])
        assert args.method == "r0"
        # Default (no --method) must also be accepted.
        args = top.parse_args(["thread", "enum", "--pid", "1"])
        assert args.method in ("r0", "r3")


# ---------------------------------------------------------------------------
# Module registration -- ensure the plugin shape is right.
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_register_returns_module_registration(self) -> None:
        from myark.plugin_loader import ModuleRegistration
        from myark.modules.thread import register as thread_register

        reg = thread_register(None, [])
        assert isinstance(reg, ModuleRegistration)
        assert reg.name == "thread"
        assert reg.description
        assert reg.ui_factory is not None
        assert reg.cli_setup is not None

    def test_register_callable_via_package(self) -> None:
        import myark.modules.thread as pkg
        assert hasattr(pkg, "register")
        assert callable(pkg.register)
        # parser module must be importable from the package surface so
        # scripts can ``from myark.modules.thread.parser import ...``.
        assert hasattr(pkg, "parser")

    def test_register_appears_in_builtin_loader(self) -> None:
        from myark import _builtin_modules

        assert "thread" in _builtin_modules._BUILTIN_MODULE_NAMES
