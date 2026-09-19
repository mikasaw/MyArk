"""S5.2 acceptance: pure-R3 network module round-trips.

These tests exercise the public API exposed by
``myark.modules.network`` -- they do not need the driver installed and
they do not need admin. The acceptance tests hit the live IP Helper
API (``GetTcpTable2`` / ``GetUdpTable``) -- any normal Windows host has
at least one LISTENING socket (``svchost`` RPC, WSL, etc.) so the
"returns at least one row" assertions are stable across test runners.

Buffer-level parser tests use a hand-crafted byte buffer to cover edge
cases (empty, truncated, big-endian field layout) without depending on
the host's network state.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import socket
import struct

import pytest

from myark.modules.network import cli as net_cli
from myark.modules.network import parser as net_parser
from myark.modules.network.protocol import TCP_STATE_NAMES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iphlpapi_available() -> bool:
    """Skip the live-API tests on a host where ``iphlpapi.dll`` is missing.

    Should never happen on Windows, but keeps the suite runnable in CI
    containers that lack a full Win32 stack (e.g. the build agent used
    for cross-platform type-checking).
    """
    try:
        ctypes.WinDLL("iphlpapi.dll")
    except OSError:
        return False
    return True


_SKIP_NO_IPHLPAPI = pytest.mark.skipif(
    not _iphlpapi_available(),
    reason="iphlpapi.dll not available in this test environment",
)


def _build_tcp_buffer(rows: list[tuple[int, int, int, int, int, int]]) -> bytes:
    """Build a synthetic ``GetExtendedTcpTable``-shaped byte buffer.

    Each row is ``(state, local_addr, local_port, remote_addr, remote_port, pid)``
    given in *host* byte order. The helper applies the network-byte-order
    swap that the real API would have done -- ``socket.htonl``/``htons``
    before packing as little-endian DWORDs -- so the parser, which calls
    ``socket.ntohl``/``ntohs``, sees the exact layout ``iphlpapi.dll``
    would emit. Each row is exactly 24 bytes (no trailing pad).
    """
    parts = bytearray()
    parts.extend(struct.pack("<I", len(rows)))
    for state, local_addr, local_port, remote_addr, remote_port, pid in rows:
        parts.extend(
            struct.pack(
                "<6I",
                state,
                socket.htonl(local_addr),
                socket.htons(local_port),
                socket.htonl(remote_addr),
                socket.htons(remote_port),
                pid,
            )
        )
    return bytes(parts)


def _build_udp_buffer(rows: list[tuple[int, int, int]]) -> bytes:
    """Build a synthetic ``GetExtendedUdpTable``-shaped byte buffer.

    Each row is ``(local_addr, local_port, pid)`` in host byte order;
    the helper applies the same network-byte-order swap as the TCP
    helper. UDP rows are exactly 12 bytes (no trailing pad).
    """
    parts = bytearray()
    parts.extend(struct.pack("<I", len(rows)))
    for local_addr, local_port, pid in rows:
        parts.extend(
            struct.pack(
                "<3I",
                socket.htonl(local_addr),
                socket.htons(local_port),
                pid,
            )
        )
    return bytes(parts)


# ---------------------------------------------------------------------------
# parser.py -- structural checks (always run; no IP Helper call)
# ---------------------------------------------------------------------------


class TestStructLayout:
    def test_tcp_row_size(self) -> None:
        # dwState + dwLocalAddr + dwLocalPort + dwRemoteAddr +
        # dwRemotePort + dwOwningPid = 6 * 4 = 24.
        assert ctypes.sizeof(net_parser.MIB_TCPROW_OWNER_PID) == 24
        assert net_parser.TCP_ROW_SIZE == 24

    def test_udp_row_size(self) -> None:
        # dwLocalAddr + dwLocalPort + dwOwningPid = 3 * 4 = 12.
        assert ctypes.sizeof(net_parser.MIB_UDPROW_OWNER_PID) == 12
        assert net_parser.UDP_ROW_SIZE == 12

    def test_field_order_tcp(self) -> None:
        # Guard against accidental field reordering -- the wire layout
        # depends on the C declaration order.
        names = [f[0] for f in net_parser.MIB_TCPROW_OWNER_PID._fields_]
        assert names == [
            "dwState",
            "dwLocalAddr",
            "dwLocalPort",
            "dwRemoteAddr",
            "dwRemotePort",
            "dwOwningPid",
        ]

    def test_field_order_udp(self) -> None:
        names = [f[0] for f in net_parser.MIB_UDPROW_OWNER_PID._fields_]
        assert names == ["dwLocalAddr", "dwLocalPort", "dwOwningPid"]


class TestParseBuffers:
    def test_parse_empty_tcp_buffer(self) -> None:
        # No-row buffer: leading DWORD = 0, no trailing bytes.
        assert net_parser.parse_tcp_table(_build_tcp_buffer([])) == []
        # Bare empty bytes are also legal -- the parser treats it as "no
        # rows" without raising.
        assert net_parser.parse_tcp_table(b"") == []

    def test_parse_single_tcp_listening_row(self) -> None:
        # Local = 127.0.0.1:135 (RPC endpoint mapper -- a fixture every
        # Windows host exposes). Remote = 0.0.0.0:0 (LISTENING semantics).
        buf = _build_tcp_buffer(
            [(2, 0x7F000001, 135, 0, 0, 1234)],
        )
        rows = net_parser.parse_tcp_table(buf)
        assert len(rows) == 1
        r = rows[0]
        assert r["protocol"] == "TCP"
        assert r["state"] == 2
        assert r["state_name"] == "LISTENING"
        assert r["local_addr"] == "127.0.0.1"
        assert r["local_port"] == 135
        assert r["remote_addr"] == "0.0.0.0"
        assert r["remote_port"] == 0
        assert r["pid"] == 1234

    def test_parse_multiple_tcp_rows(self) -> None:
        buf = _build_tcp_buffer(
            [
                (2, 0x7F000001, 80,  0,       0,  10),  # LISTENING
                (5, 0xC0A80164, 49152, 0x08080808, 443, 11),  # ESTABLISHED
            ],
        )
        rows = net_parser.parse_tcp_table(buf)
        assert [r["state_name"] for r in rows] == ["LISTENING", "ESTABLISHED"]
        assert rows[0]["pid"] == 10
        assert rows[1]["remote_addr"] == "8.8.8.8"
        assert rows[1]["remote_port"] == 443
        assert rows[1]["pid"] == 11

    def test_parse_partial_buffer_returns_fitting_rows(self) -> None:
        # Leading count says 2 rows but only one fits in the buffer.
        # ``GetExtendedTcpTable`` can return this shape when the
        # kernel grew the table between probe and fetch -- the parser
        # must clamp to the rows that actually fit, not raise.
        buf = _build_tcp_buffer(
            [(2, 0x7F000001, 135, 0, 0, 1234)],
        )
        # Forge a buffer with count=2 by overwriting the leading DWORD.
        forged = struct.pack("<I", 2) + buf[4:]
        rows = net_parser.parse_tcp_table(forged)
        assert len(rows) == 1
        assert rows[0]["pid"] == 1234
        assert rows[0]["local_port"] == 135

    def test_parse_udp_buffer(self) -> None:
        buf = _build_udp_buffer(
            [
                (0x7F000001, 53,   99),  # DNS-style
                (0x00000000, 5353,  0),  # mDNS, kernel-owned (pid=0)
            ],
        )
        rows = net_parser.parse_udp_table(buf)
        assert len(rows) == 2
        assert rows[0]["protocol"] == "UDP"
        assert rows[0]["local_addr"] == "127.0.0.1"
        assert rows[0]["local_port"] == 53
        assert rows[0]["pid"] == 99
        # UDP row has no state/remote fields at all -- not present-with-None.
        assert "state" not in rows[0]
        assert "remote_addr" not in rows[0]
        # Kernel-owned UDP listener surfaces as pid=0 -- documented case.
        assert rows[1]["pid"] == 0


class TestFilterByPid:
    def test_filter_matches_only_target_pid(self) -> None:
        buf = _build_tcp_buffer(
            [
                (5, 0x7F000001, 49152, 0x08080808, 443, 10),
                (5, 0x7F000001, 49153, 0x08080808, 443, 11),
                (5, 0x7F000001, 49154, 0x08080808, 443, 10),
            ],
        )
        rows = net_parser.parse_tcp_table(buf)
        assert net_parser.filter_by_pid(rows, 10) == [rows[0], rows[2]]
        assert net_parser.filter_by_pid(rows, 11) == [rows[1]]
        assert net_parser.filter_by_pid(rows, 999) == []

    def test_filter_rejects_invalid_pid(self) -> None:
        with pytest.raises(ValueError):
            net_parser.filter_by_pid([], 0)
        with pytest.raises(ValueError):
            net_parser.filter_by_pid([], -5)


class TestTcpStateTable:
    def test_state_table_covers_known_codes(self) -> None:
        # The table in protocol.py must cover the canonical states from
        # ``iprtrmib.h`` -- a future addition by Microsoft should be
        # added there, not buried in the parser.
        assert TCP_STATE_NAMES[2] == "LISTENING"
        assert TCP_STATE_NAMES[5] == "ESTABLISHED"
        assert TCP_STATE_NAMES[12] == "DELETE_TCB"

    def test_unknown_state_falls_back_to_label(self) -> None:
        buf = _build_tcp_buffer([(99, 0, 0, 0, 0, 1)])
        rows = net_parser.parse_tcp_table(buf)
        assert rows[0]["state_name"] == "STATE_99"


# ---------------------------------------------------------------------------
# Live IP Helper API -- acceptance tests from the S5.2 spec.
# ---------------------------------------------------------------------------


@_SKIP_NO_IPHLPAPI
class TestLiveTcpList:
    """``network tcp-list`` against the live IP Helper API."""

    def test_tcp_list_returns_at_least_one(self) -> None:
        # Acceptance test from the S5.2 issue spec: any Windows host has
        # at least one LISTENING or ESTABLISHED TCP endpoint.
        rows = net_cli.get_tcp_rows()
        assert isinstance(rows, list)
        assert len(rows) >= 1

        # Every row must carry the keys the UI / CLI rely on.
        for row in rows:
            assert row["protocol"] == "TCP"
            assert isinstance(row["state"], int)
            assert isinstance(row["state_name"], str)
            assert row["local_addr"] and row["remote_addr"]
            assert isinstance(row["local_port"], int)
            assert isinstance(row["remote_port"], int)
            assert isinstance(row["pid"], int)


@_SKIP_NO_IPHLPAPI
class TestLiveUdpList:
    """``network udp-list`` against the live IP Helper API."""

    def test_udp_list_returns_at_least_one(self) -> None:
        # Acceptance test from the S5.2 spec.
        rows = net_cli.get_udp_rows()
        assert isinstance(rows, list)
        assert len(rows) >= 1

        for row in rows:
            assert row["protocol"] == "UDP"
            assert isinstance(row["local_addr"], str)
            assert isinstance(row["local_port"], int)
            assert isinstance(row["pid"], int)
            # UDP rows must NOT carry TCP-only fields.
            assert "state" not in row
            assert "remote_addr" not in row
            assert "remote_port" not in row


@_SKIP_NO_IPHLPAPI
class TestLiveFilterByPid:
    """``network tcp-by-pid`` against the live IP Helper API."""

    def test_filter_by_pid_works(self) -> None:
        # Pick a PID we know is present: an OS PID that owns at least
        # one TCP endpoint in practice is rare on a CI host, so we use
        # ``os.getpid()`` (the test runner itself) -- any socket the
        # test runner opened will surface; if it opened none, the
        # filter must still return an empty list (not error).
        test_pid = os.getpid()
        rows = net_cli.get_tcp_rows_for_pid(test_pid)
        assert isinstance(rows, list)
        # Every row that comes back must match the requested PID.
        for row in rows:
            assert row["pid"] == test_pid

        # Negative control: a PID well above any plausible live process
        # (the kernel caps PIDs at 2^22 = ~4M on Windows; 4_000_000 is
        # therefore always unused).
        rows = net_cli.get_tcp_rows_for_pid(4_000_000)
        assert rows == []

        # Invalid PID -- the helper must reject, not silently match
        # nothing.
        with pytest.raises(ValueError):
            net_cli.get_tcp_rows_for_pid(0)


# ---------------------------------------------------------------------------
# ``network active`` -- combined non-LISTENING TCP + all UDP filter.
#
# The filter is pure Python over the parser output, so we drive it with
# hand-crafted dicts (built from the same parser the live-API path uses)
# instead of mocking the IP Helper API. ``monkeypatch`` rewires
# ``net_cli.get_tcp_rows`` / ``net_cli.get_udp_rows`` to return our
# canned dicts without touching the parser or the live fetchers.
# ---------------------------------------------------------------------------


class TestActiveFilter:
    def test_excludes_listening_tcp_rows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # A LISTENING row (state=2) must be dropped; every other state
        # (ESTABLISHED, SYN_SENT, ...) must be kept.
        tcp_rows = [
            {
                "protocol": "TCP", "state": 2, "state_name": "LISTENING",
                "local_addr": "0.0.0.0", "local_port": 80,
                "remote_addr": "0.0.0.0", "remote_port": 0,
                "pid": 10,
            },
            {
                "protocol": "TCP", "state": 5, "state_name": "ESTABLISHED",
                "local_addr": "192.168.1.100", "local_port": 49152,
                "remote_addr": "8.8.8.8", "remote_port": 443,
                "pid": 11,
            },
        ]
        monkeypatch.setattr(net_cli, "get_tcp_rows", lambda: list(tcp_rows))
        monkeypatch.setattr(net_cli, "get_udp_rows", lambda: [])

        active = net_cli.get_active_rows()
        assert [r["pid"] for r in active] == [11]
        assert active[0]["state_name"] == "ESTABLISHED"

    def test_includes_all_udp_rows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(net_cli, "get_tcp_rows", lambda: [])
        monkeypatch.setattr(
            net_cli, "get_udp_rows",
            lambda: [
                {
                    "protocol": "UDP",
                    "local_addr": "127.0.0.1", "local_port": 53,
                    "pid": 99,
                },
                {
                    "protocol": "UDP",
                    "local_addr": "0.0.0.0", "local_port": 5353,
                    "pid": 0,  # kernel-owned listener
                },
            ],
        )

        active = net_cli.get_active_rows()
        # UDP rows must be passed through unchanged, kernel pid=0 included.
        assert [r["local_port"] for r in active] == [53, 5353]
        assert [r["pid"] for r in active] == [99, 0]

    def test_combines_tcp_and_udp(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            net_cli, "get_tcp_rows",
            lambda: [
                {
                    "protocol": "TCP", "state": 2, "state_name": "LISTENING",
                    "local_addr": "0.0.0.0", "local_port": 135,
                    "remote_addr": "0.0.0.0", "remote_port": 0,
                    "pid": 1,
                },
                {
                    "protocol": "TCP", "state": 5, "state_name": "ESTABLISHED",
                    "local_addr": "10.0.0.1", "local_port": 50000,
                    "remote_addr": "1.1.1.1", "remote_port": 443,
                    "pid": 2,
                },
            ],
        )
        monkeypatch.setattr(
            net_cli, "get_udp_rows",
            lambda: [
                {
                    "protocol": "UDP",
                    "local_addr": "127.0.0.1", "local_port": 53,
                    "pid": 3,
                },
            ],
        )

        active = net_cli.get_active_rows()
        # 1 active TCP + 1 UDP; LISTENING TCP filtered out.
        assert len(active) == 2
        protocols = [r["protocol"] for r in active]
        assert protocols.count("TCP") == 1
        assert protocols.count("UDP") == 1
        # TCP first, UDP last -- matches the ``active`` CLI handler order.
        assert active[0]["protocol"] == "TCP"
        assert active[1]["protocol"] == "UDP"

    def test_empty_inputs_return_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(net_cli, "get_tcp_rows", lambda: [])
        monkeypatch.setattr(net_cli, "get_udp_rows", lambda: [])
        assert net_cli.get_active_rows() == []

    def test_cli_subcommand_is_wired(self) -> None:
        # The dispatcher path the user actually runs:
        # ``myark-cli network active``. Build the same argparse tree the
        # CLI uses and check ``_handler`` resolves to :func:`_cmd_active`.
        from myark.modules.network import cli as network_cli

        top = argparse.ArgumentParser()
        sub = top.add_subparsers(dest="command")
        network_cli._setup_cli(sub, None)
        args = top.parse_args(["network", "active"])
        assert getattr(args, "_handler", None) is network_cli._cmd_active


# ---------------------------------------------------------------------------
# Module registration -- ensure the plugin shape is right.
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_register_returns_module_registration(self) -> None:
        from myark.plugin_loader import ModuleRegistration
        from myark.modules.network.plugin import register as net_register

        reg = net_register(None, [])
        assert isinstance(reg, ModuleRegistration)
        assert reg.name == "network"
        assert reg.description
        # The factories must be present so the loader wires CLI + UI.
        assert reg.ui_factory is not None
        assert reg.cli_setup is not None

    def test_register_callable_via_package(self) -> None:
        """``myark.modules.network`` must expose ``register`` at package level."""
        import myark.modules.network as pkg
        assert hasattr(pkg, "register")
        assert callable(pkg.register)

    def test_register_appears_in_builtin_loader(self) -> None:
        """The in-tree module loader must include ``network`` in S5.2."""
        from myark import _builtin_modules

        assert "network" in _builtin_modules._BUILTIN_MODULE_NAMES