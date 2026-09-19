"""MyArk Network module: protocol constants (no IOCTL codes).

Quadrant ① modules carry no driver protocol -- every operation is a direct
call into a Win32 / standard-library API. This file documents that
deliberate non-presence: there are no ``IOCTL_MYARK_NETWORK_*`` codes, no
ctypes mirrors of driver structs, no shared memory. Anything that needs
driver-side state (raw socket enumeration, PID-process mapping for
protected processes, etc.) belongs to a different quadrant.

What lives here instead is the small Network-specific state table that
both the CLI and the UI consult when rendering ``MIB_TCPROW_OWNER_PID``
and ``MIB_UDPROW_OWNER_PID`` rows:

* :data:`TCP_STATE_NAMES` -- the canonical human label for the ``dwState``
  integer (``MIB_TCP_STATE_*`` from ``iprtrmib.h``).
* :data:`NO_IOCTL`        -- sentinel that guards against a future
  contributor reaching for a ctypes / IOCTL pattern by accident.

The driver path never receives a packet from this module -- the call chain
is purely ``myark-cli network tcp-list`` -> ``parser.parse_tcp_table()`` ->
``iphlpapi.GetTcpTable2`` -> stdout.
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Sentinel for "this module has no IOCTL surface" -- guards against future
# contributors reaching for a ctypes / IOCTL pattern by accident.
# ---------------------------------------------------------------------------

NO_IOCTL: str = "network module is pure R3; no IOCTL codes apply."


# ---------------------------------------------------------------------------
# TCP state table.
#
# ``MIB_TCPROW_OWNER_PID.dwState`` carries an integer from ``iprtrmib.h``.
# Microsoft has been slowly extending the table (the kernel headers list
# ``MIB_TCP_STATE_DELETE_TCB`` = 12 alongside the original ten values), so
# we keep our own list rather than hard-coding a single literal in the
# CLI / UI. Codes outside the table render as ``"STATE_<n>"`` so a future
# Windows build does not silently mislabel a row.
# ---------------------------------------------------------------------------

TCP_STATE_NAMES: dict[int, str] = {
    1:  "CLOSED",
    2:  "LISTENING",
    3:  "SYN_SENT",
    4:  "SYN_RCVD",
    5:  "ESTABLISHED",
    6:  "FIN_WAIT1",
    7:  "FIN_WAIT2",
    8:  "CLOSE_WAIT",
    9:  "CLOSING",
    10: "LAST_ACK",
    11: "TIME_WAIT",
    12: "DELETE_TCB",
}


# ---------------------------------------------------------------------------
# Reserved column width hints for the UI Treeview.
#
# These are advisory -- the Tkinter tab still lets the user resize any
# column -- but they keep the initial layout readable on a 1080p display
# without manual adjustment. Centralising them avoids drift between the
# Tk treeview, the CLI table, and any future HTML export.
# ---------------------------------------------------------------------------

COLUMN_WIDTHS: dict[str, int] = {
    "protocol":  80,
    "local":    160,
    "remote":   160,
    "state":    120,
    "pid":       80,
}


__all__ = [
    "NO_IOCTL",
    "TCP_STATE_NAMES",
    "COLUMN_WIDTHS",
]