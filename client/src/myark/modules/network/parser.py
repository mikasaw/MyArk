"""MyArk Network module: ctypes struct mirrors + byte-array parsers.

The IP Helper API (see ``iphlpapi.dll``) returns connection data as a
flat byte array with a leading ``DWORD`` row count followed by that many
fixed-size row records. The relevant C structs are:

* ``MIB_TCPROW_OWNER_PID`` -- one IPv4 TCP endpoint + owning PID.
  Layout (per ``iprtrmib.h``)::

      DWORD  dwState;       // MIB_TCP_STATE_*
      DWORD  dwLocalAddr;   // network byte order (big-endian)
      DWORD  dwLocalPort;   // network byte order
      DWORD  dwRemoteAddr;  // network byte order
      DWORD  dwRemotePort;  // network byte order
      DWORD  dwOwningPid;   // host order

  Total size: 24 bytes.

* ``MIB_UDPROW_OWNER_PID`` -- one IPv4 UDP endpoint + owning PID.
  Layout::

      DWORD  dwLocalAddr;   // network byte order
      DWORD  dwLocalPort;   // network byte order
      DWORD  dwOwningPid;   // host order

  Total size: 12 bytes. UDP has no ``dwState`` (UDP is connectionless)
  and no remote endpoint.

``MIB_TCPROW_OWNER_PID`` and ``MIB_UDPROW_OWNER_PID`` are returned by
``GetExtendedTcpTable`` (with ``TCP_TABLE_OWNER_PID`` /
``UDP_TABLE_OWNER_PID`` and ``AF_INET``). They are *not* the
connection-only ``MIB_TCPROW`` / ``MIB_UDPROW`` types -- the
``_OWNER_PID`` suffix is load-bearing and a common copy-paste trap.

.. note::

    We deliberately use ``GetExtendedTcpTable`` / ``GetExtendedUdpTable``
    rather than the older ``GetTcpTable2`` / ``GetUdpTable``. The
    older ``GetTcpTable2`` writes an undocumented 28 bytes per row
    (24 doc-stated + 4-byte trailing pad) on Windows 10 / 11, and the
    older ``GetUdpTable`` returns ``MIB_UDPROW`` rows without the
    owning PID at all -- both behaviours surprise callers who follow
    the Microsoft docs. The ``*Extended`` variants honour the doc-
    stated row sizes (24 and 12) and always include the PID.

The IPv6 variants (``MIB_TCP6ROW_OWNER_PID`` etc.) are intentionally
*not* implemented here -- the S5.2 spec places them out of scope.

Everything in this file is pure ctypes + struct unpacking. No driver
handle, no IOCTL, no shared memory.
"""

from __future__ import annotations

import ctypes
import socket
import struct
from typing import Any, Optional

from myark.modules.network.protocol import TCP_STATE_NAMES


# ---------------------------------------------------------------------------
# ctypes struct mirrors.
# ---------------------------------------------------------------------------


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    """ctypes mirror of iprtrmib.h's ``MIB_TCPROW_OWNER_PID``.

    Field order MUST match the C declaration -- ``GetExtendedTcpTable``
    writes the rows contiguously with no padding beyond the natural
    alignment a ``DWORD`` already provides, so a single shared 24-byte
    layout works on every Windows architecture.
    """

    _fields_ = [
        ("dwState",       ctypes.c_uint32),
        ("dwLocalAddr",   ctypes.c_uint32),
        ("dwLocalPort",   ctypes.c_uint32),
        ("dwRemoteAddr",  ctypes.c_uint32),
        ("dwRemotePort",  ctypes.c_uint32),
        ("dwOwningPid",   ctypes.c_uint32),
    ]


class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    """ctypes mirror of udpmib.h's ``MIB_UDPROW_OWNER_PID``."""

    _fields_ = [
        ("dwLocalAddr",  ctypes.c_uint32),
        ("dwLocalPort",  ctypes.c_uint32),
        ("dwOwningPid",  ctypes.c_uint32),
    ]


# Public type aliases. Callers can use these as the row type for type hints
# without depending on ctypes' loose typing.
TcpRow = MIB_TCPROW_OWNER_PID
UdpRow = MIB_UDPROW_OWNER_PID


# Doc-stated struct sizes. ``GetExtendedTcpTable`` /
# ``GetExtendedUdpTable`` honour these on every supported Windows build.
TCP_ROW_SIZE: int = ctypes.sizeof(MIB_TCPROW_OWNER_PID)   # 24
UDP_ROW_SIZE: int = ctypes.sizeof(MIB_UDPROW_OWNER_PID)   # 12


# ---------------------------------------------------------------------------
# Byte-order helpers.
#
# The IP Helper API stores the IPv4 address and port fields in network
# byte order (big-endian). The owning PID is in host byte order. Python's
# :func:`struct.unpack` would work but ctypes' :class:`BigEndianStructure`
# would force us to split the row type, so we just swap the bytes
# ourselves with :func:`socket.ntohl` / :func:`socket.ntohs`.
# ---------------------------------------------------------------------------


def _addr_to_str(network_order_int: int) -> str:
    """Convert a network-byte-order ``DWORD`` into ``"a.b.c.d"``."""
    host = socket.ntohl(network_order_int) & 0xFFFFFFFF
    return socket.inet_ntoa(struct.pack("!I", host))


def _port_to_int(network_order_int: int) -> int:
    """Convert a network-byte-order ``WORD`` (zero-extended into a DWORD) to an int."""
    # The IP Helper API actually exposes the port as a full DWORD with
    # the high 16 bits zero, but applying ``ntohs`` to the low half is
    # robust to either layout.
    return socket.ntohs(network_order_int & 0xFFFF)


def _state_name(state_code: int) -> str:
    """Render a ``MIB_TCP_STATE_*`` integer as a human string."""
    return TCP_STATE_NAMES.get(int(state_code), f"STATE_{int(state_code)}")


# ---------------------------------------------------------------------------
# Row → dict conversion.
# ---------------------------------------------------------------------------


def tcp_row_to_dict(
    row: MIB_TCPROW_OWNER_PID,
    *,
    include_state_name: bool = True,
) -> dict[str, Any]:
    """Render a single ``MIB_TCPROW_OWNER_PID`` as a JSON-friendly dict.

    The dict keys are stable -- the CLI prints them, the UI columns use
    them, and the test suite asserts on them -- so renaming a key here
    counts as a breaking change to the module's public surface.

    Fields:

    * ``protocol``    -- always ``"TCP"`` for rows from this parser.
    * ``state``       -- the integer ``dwState`` (raw enum value).
    * ``state_name``  -- human label from :data:`TCP_STATE_NAMES`. Set to
      ``None`` when ``include_state_name`` is ``False`` (the caller is
      going to render the label itself).
    * ``local_addr``  / ``local_port`` -- local endpoint, host order.
    * ``remote_addr`` / ``remote_port`` -- remote endpoint, host order.
      ``"0.0.0.0"`` / ``0`` for LISTENING rows where the remote is unset.
    * ``pid``         -- owning PID as an ``int``.
    """
    state_name = _state_name(row.dwState) if include_state_name else None
    return {
        "protocol":    "TCP",
        "state":       int(row.dwState),
        "state_name":  state_name,
        "local_addr":  _addr_to_str(row.dwLocalAddr),
        "local_port":  _port_to_int(row.dwLocalPort),
        "remote_addr": _addr_to_str(row.dwRemoteAddr),
        "remote_port": _port_to_int(row.dwRemotePort),
        "pid":         int(row.dwOwningPid),
    }


def udp_row_to_dict(row: MIB_UDPROW_OWNER_PID) -> dict[str, Any]:
    """Render a single ``MIB_UDPROW_OWNER_PID`` as a JSON-friendly dict.

    UDP has no state and no remote endpoint -- those keys are deliberately
    absent rather than present-with-``None`` so callers iterating dict
    keys won't accidentally render ``"None"`` in the UI.

    ``pid`` may be ``0`` -- the IP Helper API legitimately returns zero
    for some kernel-owned listeners and for orphaned rows whose owning
    process has since exited. Callers that want to highlight "missing"
    should test ``pid == 0``, not truthiness.
    """
    return {
        "protocol":   "UDP",
        "local_addr": _addr_to_str(row.dwLocalAddr),
        "local_port": _port_to_int(row.dwLocalPort),
        "pid":        int(row.dwOwningPid),
    }


# ---------------------------------------------------------------------------
# Buffer parsers.
#
# The IP Helper API returns a contiguous byte buffer:
#     DWORD dwNumEntries;
#     MIB_<T>ROW_OWNER_PID table[ANYSIZE_ARRAY];
# The leading DWORD is in host byte order and is the *exact* row count
# -- if the buffer was too small for all rows, the function sets the
# caller-supplied size and returns ``ERROR_INSUFFICIENT_BUFFER``; we
# retry with the larger size. The buffer returned on success always has
# the trailing rows.
# ---------------------------------------------------------------------------


def parse_tcp_table(buffer: bytes) -> list[dict[str, Any]]:
    """Parse a ``GetExtendedTcpTable`` byte buffer into a list of dicts.

    The buffer layout is ``DWORD count`` followed by ``count`` packed
    ``MIB_TCPROW_OWNER_PID`` records (each 24 bytes). The function
    trusts the embedded count -- it does not re-derive it from
    ``len(buffer)`` because the API may pass a buffer larger than
    ``4 + 24*count`` (some Win32 versions round up). All extra
    trailing bytes are ignored.

    The count is *clamped* to the rows that actually fit: on busy hosts
    the UDP/TCP table can grow between the probe-size call and the
    fetch-data call. When that happens, the API may return a still-
    SUCCESS status with the larger count but a buffer that holds only
    the rows from the probe snapshot. We drop the unreachable rows
    rather than raising -- partial snapshots are still useful, and
    "the kernel grew its endpoint table mid-fetch" is not the user's
    fault.

    Returns an empty list when ``count == 0`` rather than raising -- a
    "no TCP endpoints at all" return from the kernel is possible on a
    freshly-booted VM with the firewall service disabled.
    """
    if not buffer:
        return []
    if len(buffer) < 4:
        raise ValueError(
            f"tcp table buffer too short: {len(buffer)} bytes (need >= 4)"
        )
    (count,) = struct.unpack_from("<I", buffer, 0)
    available = (len(buffer) - 4) // TCP_ROW_SIZE
    count = min(count, available)
    rows: list[dict[str, Any]] = []
    offset = 4
    for _ in range(count):
        chunk = buffer[offset:offset + TCP_ROW_SIZE]
        if len(chunk) < TCP_ROW_SIZE:
            raise ValueError(
                f"tcp table row truncated at offset {offset}: "
                f"{len(chunk)} bytes (need {TCP_ROW_SIZE})"
            )
        rows.append(tcp_row_to_dict(MIB_TCPROW_OWNER_PID.from_buffer_copy(chunk)))
        offset += TCP_ROW_SIZE
    return rows


def parse_udp_table(buffer: bytes) -> list[dict[str, Any]]:
    """Parse a ``GetExtendedUdpTable`` byte buffer into a list of dicts.

    Mirrors :func:`parse_tcp_table` for the smaller UDP record size.
    The count-clamping is especially important for UDP: a typical
    Windows host has 60-80 mDNS / SSDP / NetBIOS listeners that open
    and close constantly, so the race between probe and fetch fires
    far more often than for TCP.
    """
    if not buffer:
        return []
    if len(buffer) < 4:
        raise ValueError(
            f"udp table buffer too short: {len(buffer)} bytes (need >= 4)"
        )
    (count,) = struct.unpack_from("<I", buffer, 0)
    available = (len(buffer) - 4) // UDP_ROW_SIZE
    count = min(count, available)
    rows: list[dict[str, Any]] = []
    offset = 4
    for _ in range(count):
        chunk = buffer[offset:offset + UDP_ROW_SIZE]
        if len(chunk) < UDP_ROW_SIZE:
            raise ValueError(
                f"udp table row truncated at offset {offset}: "
                f"{len(chunk)} bytes (need {UDP_ROW_SIZE})"
            )
        rows.append(udp_row_to_dict(MIB_UDPROW_OWNER_PID.from_buffer_copy(chunk)))
        offset += UDP_ROW_SIZE
    return rows


# ---------------------------------------------------------------------------
# Caller-side filters.
# ---------------------------------------------------------------------------


def filter_by_pid(rows: list[dict[str, Any]], pid: int) -> list[dict[str, Any]]:
    """Return only the rows whose ``pid`` matches ``pid``.

    A ``pid <= 0`` is rejected -- the IP Helper API never returns a
    negative PID and we want to catch a typo on the CLI (e.g.
    ``network tcp-by-pid -4``) before it silently matches nothing.
    """
    if pid <= 0:
        raise ValueError(f"pid must be a positive integer, got {pid}")
    return [row for row in rows if int(row.get("pid", 0)) == int(pid)]


__all__ = [
    "MIB_TCPROW_OWNER_PID",
    "MIB_UDPROW_OWNER_PID",
    "TcpRow",
    "UdpRow",
    "TCP_ROW_SIZE",
    "UDP_ROW_SIZE",
    "tcp_row_to_dict",
    "udp_row_to_dict",
    "parse_tcp_table",
    "parse_udp_table",
    "filter_by_pid",
]