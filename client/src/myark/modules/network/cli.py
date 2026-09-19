"""MyArk Network module: CLI subcommands.

Adds ``myark-cli network {tcp-list, udp-list, tcp-by-pid}`` to the
parent argparse parser. Each subcommand invokes the IP Helper API via
:mod:`ctypes` -- no driver handle is required, so the parent CLI's
"driver not installed" fallback never fires for this subtree.

The IP Helper API surfaces the relevant functions:

* ``GetExtendedTcpTable`` with ``TCP_TABLE_OWNER_PID`` and
  ``AF_INET`` -- returns ``MIB_TCPROW_OWNER_PID`` rows. We use this
  rather than ``GetTcpTable2`` because ``GetTcpTable2`` writes an
  undocumented 28 bytes per row (24-byte struct + 4-byte trailing pad)
  on Windows 10 / 11, while ``GetExtendedTcpTable`` writes the
  doc-stated 24 bytes per row and we avoid having to model the pad.
* ``GetExtendedUdpTable`` with ``UDP_TABLE_OWNER_PID`` and
  ``AF_INET`` -- returns ``MIB_UDPROW_OWNER_PID`` rows. The plain
  ``GetUdpTable`` returns ``MIB_UDPROW`` (no owning PID!) despite its
  older documentation claiming otherwise, so we cannot use it for the
  S5.2 spec which requires the PID.

Both functions follow the standard "probe size, then fetch" protocol:
the first call passes ``NULL`` and the function writes the required
buffer size into ``pcbSize``; we then allocate that many bytes and
call again. ``ERROR_INSUFFICIENT_BUFFER`` from the second call (the
table grew between probe and fetch) triggers one retry with the larger
size.

Subcommand surface (matches the S5.2 issue spec):

* ``network tcp-list``           -- list every IPv4 TCP endpoint.
* ``network udp-list``           -- list every IPv4 UDP endpoint.
* ``network tcp-by-pid <pid>``   -- list only TCP rows owned by ``<pid>``.
* ``network active``             -- list every non-LISTENING TCP row plus
  every UDP row, in the same per-row format as ``tcp-list``.
"""

from __future__ import annotations

import argparse
import ctypes
import sys
from typing import Any, Optional

from myark.client.ark_client import ArkClient
from myark.modules.network import parser as net_parser


# ---------------------------------------------------------------------------
# IP Helper API binding.
#
# We bind only the two functions we actually need. Loading the full
# ``iphlpapi.dll`` would also resolve the IPv6 helpers
# (``GetExtendedTcpTable`` with ``AF_INET6``, ``GetTcp6Table2`` etc.),
# which we do not want to accidentally call -- the S5.2 spec keeps IPv6
# out of scope and a future contributor reaching for an IPv6 helper
# should add it explicitly with the matching struct, not piggy-back on
# this module.
# ---------------------------------------------------------------------------


_iphlpapi = ctypes.WinDLL("iphlpapi.dll")

# DWORD GetExtendedTcpTable(PVOID pTcpTable, PDWORD pdwSize, BOOL bOrder,
#                           ULONG ulFamily, TCP_TABLE_CLASS TableClass, ULONG Reserved);
_GetExtendedTcpTable = _iphlpapi.GetExtendedTcpTable
_GetExtendedTcpTable.restype = ctypes.c_uint32
_GetExtendedTcpTable.argtypes = [
    ctypes.c_void_p,                          # PVOID
    ctypes.POINTER(ctypes.c_ulong),            # PDWORD
    ctypes.c_int,                             # BOOL
    ctypes.c_uint32,                          # ULONG (ulFamily)
    ctypes.c_uint32,                          # TCP_TABLE_CLASS (TableClass)
    ctypes.c_uint32,                          # ULONG (Reserved)
]

# DWORD GetExtendedUdpTable(PVOID pUdpTable, PDWORD pdwSize, BOOL bOrder,
#                           ULONG ulFamily, UDP_TABLE_CLASS TableClass, ULONG Reserved);
_GetExtendedUdpTable = _iphlpapi.GetExtendedUdpTable
_GetExtendedUdpTable.restype = ctypes.c_uint32
_GetExtendedUdpTable.argtypes = [
    ctypes.c_void_p,                          # PVOID
    ctypes.POINTER(ctypes.c_ulong),            # PDWORD
    ctypes.c_int,                             # BOOL
    ctypes.c_uint32,                          # ULONG (ulFamily)
    ctypes.c_uint32,                          # UDP_TABLE_CLASS (TableClass)
    ctypes.c_uint32,                          # ULONG (Reserved)
]


# TCP_TABLE_OWNER_PID and UDP_TABLE_OWNER_PID are defined in ``iprtrmib.h``
# / ``udpmib.h``. Defined locally to avoid pulling in the full table for
# two constants.
_TCP_TABLE_OWNER_PID = 3
_UDP_TABLE_OWNER_PID = 1

# Win32 error codes we care about. Defined locally to avoid pulling in
# the entire ``ctypes.wintypes`` table for two constants.
_ERROR_SUCCESS = 0
_ERROR_INSUFFICIENT_BUFFER = 122

# Address family. ``AF_INET`` = IPv4 only; IPv6 is intentionally out of
# scope per the S5.2 spec.
_AF_INET = 2

# MIB_TCP_STATE_LISTENING from ``iprtrmib.h``. Local copy so the
# ``active`` filter does not have to import the full TCP_STATE_NAMES
# table just to compare against one constant.
_TCP_STATE_LISTENING = 2


# ---------------------------------------------------------------------------
# Native buffer fetches.
# ---------------------------------------------------------------------------


def _fetch_tcp_table() -> bytes:
    """Call ``GetExtendedTcpTable`` (TCP_TABLE_OWNER_PID, AF_INET) and
    return the populated byte buffer.

    Implements the standard "probe size, then fetch" dance: first call
    passes ``NULL`` so the API writes only the required size into
    ``pcbSize``, then we allocate that many bytes and call again. A
    second-pass ``ERROR_INSUFFICIENT_BUFFER`` (possible on busy hosts
    where rows were added between the probe and the fetch) triggers a
    further retry with the now-larger size -- the cost is one extra
    allocation, well below the millisecond.
    """
    size = ctypes.c_ulong(0)
    rc = _GetExtendedTcpTable(
        None,
        ctypes.byref(size),
        0,
        _AF_INET,
        _TCP_TABLE_OWNER_PID,
        0,
    )
    if rc not in (_ERROR_SUCCESS, _ERROR_INSUFFICIENT_BUFFER):
        raise OSError(f"GetExtendedTcpTable probe failed: error {rc}")

    buf = ctypes.create_string_buffer(size.value)
    rc = _GetExtendedTcpTable(
        ctypes.byref(buf),
        ctypes.byref(size),
        0,
        _AF_INET,
        _TCP_TABLE_OWNER_PID,
        0,
    )
    if rc == _ERROR_INSUFFICIENT_BUFFER:
        # The kernel grew the table between our probe and our fetch.
        # ``size`` now holds the *required* size -- reallocate and retry.
        buf = ctypes.create_string_buffer(size.value)
        rc = _GetExtendedTcpTable(
            ctypes.byref(buf),
            ctypes.byref(size),
            0,
            _AF_INET,
            _TCP_TABLE_OWNER_PID,
            0,
        )
    if rc != _ERROR_SUCCESS:
        raise OSError(
            f"GetExtendedTcpTable fetch failed: error {rc} (size={size.value})"
        )

    # ``create_string_buffer`` returns one extra trailing NUL byte that
    # the API did not write; trim it so ``len(buf)`` matches what the
    # IP Helper returned, and so the row parser sees the exact buffer
    # the kernel produced.
    return bytes(buf[: size.value])


def _fetch_udp_table() -> bytes:
    """Call ``GetExtendedUdpTable`` (UDP_TABLE_OWNER_PID, AF_INET) and
    return the populated byte buffer.

    Same probe-and-fetch dance as :func:`_fetch_tcp_table`. UDP
    endpoints are especially prone to the buffer-growing race because
    mDNS / SSDP listeners open short-lived sockets during a probe, so
    the retry path is the rule rather than the exception.
    """
    size = ctypes.c_ulong(0)
    rc = _GetExtendedUdpTable(
        None,
        ctypes.byref(size),
        0,
        _AF_INET,
        _UDP_TABLE_OWNER_PID,
        0,
    )
    if rc not in (_ERROR_SUCCESS, _ERROR_INSUFFICIENT_BUFFER):
        raise OSError(f"GetExtendedUdpTable probe failed: error {rc}")

    buf = ctypes.create_string_buffer(size.value)
    rc = _GetExtendedUdpTable(
        ctypes.byref(buf),
        ctypes.byref(size),
        0,
        _AF_INET,
        _UDP_TABLE_OWNER_PID,
        0,
    )
    if rc == _ERROR_INSUFFICIENT_BUFFER:
        buf = ctypes.create_string_buffer(size.value)
        rc = _GetExtendedUdpTable(
            ctypes.byref(buf),
            ctypes.byref(size),
            0,
            _AF_INET,
            _UDP_TABLE_OWNER_PID,
            0,
        )
    if rc != _ERROR_SUCCESS:
        raise OSError(
            f"GetExtendedUdpTable fetch failed: error {rc} (size={size.value})"
        )

    return bytes(buf[: size.value])


# ---------------------------------------------------------------------------
# High-level entry points.
#
# These wrap the native fetch + parser pair and are reused by both the
# CLI handlers and the test suite. Tests inject a pre-built byte buffer
# via ``parse_*_table`` to keep the IP Helper call out of the test path.
# ---------------------------------------------------------------------------


def get_tcp_rows() -> list[dict[str, Any]]:
    """Return every IPv4 TCP endpoint as a list of dicts."""
    return net_parser.parse_tcp_table(_fetch_tcp_table())


def get_udp_rows() -> list[dict[str, Any]]:
    """Return every IPv4 UDP endpoint as a list of dicts."""
    return net_parser.parse_udp_table(_fetch_udp_table())


def get_tcp_rows_for_pid(pid: int) -> list[dict[str, Any]]:
    """Return only the TCP endpoints whose owning PID equals ``pid``."""
    return net_parser.filter_by_pid(get_tcp_rows(), pid)


def get_active_rows() -> list[dict[str, Any]]:
    """Return every "active" TCP and UDP endpoint as a single list.

    "Active" here means *not* passively listening for an incoming
    connection: every TCP row whose state is anything other than
    ``LISTENING`` (state code 2), plus every UDP row (UDP is
    connectionless, so every row is an actively-bound endpoint). The
    list preserves the dict shape that :func:`get_tcp_rows` /
    :func:`get_udp_rows` emit, so callers that switch on
    ``row["protocol"]`` keep working unchanged.

    Reuses the same IP Helper fetchers as ``tcp-list`` / ``udp-list`` --
    no extra ``GetExtended*`` call, no extra allocation beyond the
    ``[r for r in rows if ...]`` filter.
    """
    rows: list[dict[str, Any]] = [
        row for row in get_tcp_rows() if int(row.get("state", 0)) != _TCP_STATE_LISTENING
    ]
    rows.extend(get_udp_rows())
    return rows


# ---------------------------------------------------------------------------
# CLI wiring.
# ---------------------------------------------------------------------------


def _setup_cli(subparsers: Any, _client: Optional[ArkClient]) -> None:
    """Wire the ``myark-cli network ...`` subtree."""
    p_root = subparsers.add_parser(
        "network",
        help="network module commands (pure-R3 IP Helper API)",
    )
    subs = p_root.add_subparsers(dest="network_subcommand")

    # ---- tcp-list
    p_tcp = subs.add_parser(
        "tcp-list",
        help="list every IPv4 TCP endpoint (state, local, remote, pid)",
    )
    p_tcp.set_defaults(_handler=_cmd_tcp_list)

    # ---- udp-list
    p_udp = subs.add_parser(
        "udp-list",
        help="list every IPv4 UDP endpoint (local, pid)",
    )
    p_udp.set_defaults(_handler=_cmd_udp_list)

    # ---- tcp-by-pid
    p_pid = subs.add_parser(
        "tcp-by-pid",
        help="list IPv4 TCP endpoints owned by <pid>",
    )
    p_pid.add_argument("pid", type=int, help="owning PID to filter by")
    p_pid.set_defaults(_handler=_cmd_tcp_by_pid)

    # ---- active
    p_active = subs.add_parser(
        "active",
        help="list every active TCP/UDP endpoint (no LISTENING TCP)",
    )
    p_active.set_defaults(_handler=_cmd_active)


# ---------------------------------------------------------------------------
# Handlers.
# ---------------------------------------------------------------------------


def _err(msg: str) -> int:
    print(msg, file=sys.stderr)
    return 3


def _format_endpoint(addr: str, port: int) -> str:
    """``"a.b.c.d:12345"`` for non-listening rows, ``"a.b.c.d:0"`` otherwise."""
    return f"{addr}:{port}"


def _print_tcp_row(row: dict[str, Any]) -> None:
    state_name = row.get("state_name") or "STATE_?"
    print(
        "  "
        f"[{state_name:<11}] "
        f"{_format_endpoint(row['local_addr'], row['local_port']):<22} "
        f"-> {_format_endpoint(row['remote_addr'], row['remote_port']):<22} "
        f"pid={row['pid']}"
    )


def _print_udp_row(row: dict[str, Any]) -> None:
    print(
        "  "
        f"UDP {_format_endpoint(row['local_addr'], row['local_port']):<22} "
        f"pid={row['pid']}"
    )


def _cmd_tcp_list(args: argparse.Namespace) -> int:
    try:
        rows = get_tcp_rows()
    except OSError as exc:
        return _err(f"GetTcpTable2 failed: {exc}")
    except ValueError as exc:
        return _err(f"parse failed: {exc}")

    for row in rows:
        _print_tcp_row(row)
    print(f"({len(rows)} TCP endpoints)")
    return 0


def _cmd_udp_list(args: argparse.Namespace) -> int:
    try:
        rows = get_udp_rows()
    except OSError as exc:
        return _err(f"GetUdpTable failed: {exc}")
    except ValueError as exc:
        return _err(f"parse failed: {exc}")

    for row in rows:
        _print_udp_row(row)
    print(f"({len(rows)} UDP endpoints)")
    return 0


def _cmd_tcp_by_pid(args: argparse.Namespace) -> int:
    pid = int(args.pid)
    if pid <= 0:
        return _err(f"pid must be a positive integer, got {pid}")

    try:
        rows = get_tcp_rows_for_pid(pid)
    except OSError as exc:
        return _err(f"GetTcpTable2 failed: {exc}")
    except ValueError as exc:
        return _err(f"parse failed: {exc}")

    if not rows:
        # Not an error -- a "no endpoints for this PID" result is a
        # legitimate answer to the user's question. Print a single
        # informative line and exit 0 so shell scripts can rely on the
        # exit code alone.
        print(f"no TCP endpoints found for pid {pid}")
        return 0

    for row in rows:
        _print_tcp_row(row)
    print(f"({len(rows)} TCP endpoints for pid {pid})")
    return 0


def _cmd_active(args: argparse.Namespace) -> int:
    try:
        rows = get_active_rows()
    except OSError as exc:
        return _err(f"GetExtendedTable failed: {exc}")
    except ValueError as exc:
        return _err(f"parse failed: {exc}")

    # Same per-row rendering as ``tcp-list`` / ``udp-list`` so the user
    # sees a single uniform column layout across all three commands.
    # The dict shape is identical (each row carries ``protocol``), so
    # we just branch on it instead of building a parallel formatter.
    tcp_rows = [r for r in rows if r.get("protocol") == "TCP"]
    udp_rows = [r for r in rows if r.get("protocol") == "UDP"]

    for row in tcp_rows:
        _print_tcp_row(row)
    for row in udp_rows:
        _print_udp_row(row)
    print(f"({len(tcp_rows)} active TCP + {len(udp_rows)} UDP endpoints)")
    return 0


__all__ = [
    "_setup_cli",
    "get_tcp_rows",
    "get_udp_rows",
    "get_tcp_rows_for_pid",
    "get_active_rows",
]