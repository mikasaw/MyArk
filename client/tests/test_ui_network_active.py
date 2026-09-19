"""Tests for the network tab's Active only view (S10.12).

The checkbox mirrors ``myark-cli network active``: checking it switches
the data source to ``cli.get_active_rows()`` (non-LISTENING TCP merged
with all UDP), keeps the tree on the fixed TCP column layout with UDP
rows marked in the state column, reports ``active: N TCP + M UDP`` in
the status line, and greys the protocol chooser out while in force.
Clearing the box restores the plain TCP/UDP two-source behavior.

All row fetchers are patched so no test touches the live IP Helper
API -- the mixed rows use the exact dict shapes the parser emits.

Tk-root sharing
---------------
All Tk-using tests share a single ``tk.Tk()`` root via the conftest
shared helper (see ``test_ui_detail_window`` for the rationale).
"""

from __future__ import annotations

import os
import tkinter as tk
import unittest
from tkinter import ttk
from unittest.mock import patch

from myark.modules.network import cli as net_cli
from myark.modules.network.ui import PID_ALL, TCP_COLUMNS, _build_ui, _refresh


HARNESS_HAS_TK = os.name == "nt" or os.environ.get("DISPLAY")


# Synthetic rows in the exact dict shape the parser emits (one TCP
# LISTENING row for the restore path, plus the mixed active-view
# input). ``get_active_rows`` itself filters LISTENING out -- that is
# covered in test_r3_network; here the mock replaces the whole fetcher.
TCP_LISTENING = {
    "protocol": "TCP",
    "state": 2,
    "state_name": "LISTENING",
    "local_addr": "0.0.0.0",
    "local_port": 445,
    "remote_addr": "0.0.0.0",
    "remote_port": 0,
    "pid": 4242,
}
TCP_ESTABLISHED = {
    "protocol": "TCP",
    "state": 5,
    "state_name": "ESTABLISHED",
    "local_addr": "10.0.0.2",
    "local_port": 52341,
    "remote_addr": "93.184.216.34",
    "remote_port": 443,
    "pid": 4242,
}
TCP_TIME_WAIT = {
    "protocol": "TCP",
    "state": 11,
    "state_name": "TIME_WAIT",
    "local_addr": "10.0.0.2",
    "local_port": 52342,
    "remote_addr": "93.184.216.34",
    "remote_port": 80,
    "pid": 4242,
}
UDP_A = {"protocol": "UDP", "local_addr": "0.0.0.0", "local_port": 5353, "pid": 9110}
UDP_B = {"protocol": "UDP", "local_addr": "127.0.0.1", "local_port": 1900, "pid": 1234}

MIXED_ROWS = [TCP_ESTABLISHED, UDP_A, TCP_TIME_WAIT, UDP_B]


# ---------------------------------------------------------------------------
# Widget helpers.
# ---------------------------------------------------------------------------


def _shared_root() -> tk.Tk:
    from tests import conftest
    return conftest.shared_tk_root()


def _walk(widget: tk.Widget):
    yield widget
    for child in widget.winfo_children():
        yield from _walk(child)


def _sole_of(frame: ttk.Frame, cls: type, what: str):
    found = [w for w in _walk(frame) if isinstance(w, cls)]
    assert len(found) == 1, f"expected exactly one {what}, got {len(found)}"
    return found[0]


def _status_text(root: tk.Tk, frame: ttk.Frame) -> str:
    """Read the status label's text through its textvariable."""
    for w in _walk(frame):
        if isinstance(w, ttk.Label) and w.cget("textvariable"):
            return str(root.getvar(str(w.cget("textvariable"))))
    raise AssertionError("status label not found")


@unittest.skipUnless(HARNESS_HAS_TK, "no Tk display available")
class TestNetworkActiveOnlyView(unittest.TestCase):
    def setUp(self) -> None:
        self.root = _shared_root()
        self.holder = tk.Toplevel(self.root)
        self.holder.withdraw()
        # Patch every row fetcher: neither the initial after(50) load nor
        # any test-driven refresh may reach the live IP Helper API.
        patcher = patch.multiple(
            net_cli,
            get_tcp_rows=lambda: [TCP_LISTENING],
            get_udp_rows=lambda: [UDP_A, UDP_B],
            get_active_rows=lambda: list(MIXED_ROWS),
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self) -> None:
        try:
            self.holder.destroy()
        except tk.TclError:
            pass

    # ---- structure

    def test_checkbutton_present(self):
        frame = _build_ui(self.holder, None)
        check = _sole_of(frame, ttk.Checkbutton, "Checkbutton")
        self.assertEqual(str(check.cget("text")), "Active only")

    def test_checking_greys_out_protocol_chooser(self):
        frame = _build_ui(self.holder, None)
        combo = _sole_of(frame, ttk.Combobox, "Combobox")
        check = _sole_of(frame, ttk.Checkbutton, "Checkbutton")

        self.assertEqual(str(combo.cget("state")), "readonly")
        check.invoke()
        self.assertEqual(str(combo.cget("state")), "disabled")
        check.invoke()
        self.assertEqual(str(combo.cget("state")), "readonly")

    # ---- data (active view)

    def test_checking_renders_mixed_rows_in_fixed_tcp_columns(self):
        frame = _build_ui(self.holder, None)
        tree = _sole_of(frame, ttk.Treeview, "Treeview")
        check = _sole_of(frame, ttk.Checkbutton, "Checkbutton")

        check.invoke()

        children = tree.get_children()
        self.assertEqual(len(children), 4)
        rows = [tuple(tree.item(c, "values")) for c in children]
        self.assertEqual(
            rows,
            [
                ("ESTABLISHED", "10.0.0.2:52341", "93.184.216.34:443", "4242"),
                ("UDP", "0.0.0.0:5353", "", "9110"),
                ("TIME_WAIT", "10.0.0.2:52342", "93.184.216.34:80", "4242"),
                ("UDP", "127.0.0.1:1900", "", "1234"),
            ],
        )

    def test_udp_rows_carry_udp_state_marker(self):
        frame = _build_ui(self.holder, None)
        tree = _sole_of(frame, ttk.Treeview, "Treeview")
        check = _sole_of(frame, ttk.Checkbutton, "Checkbutton")
        check.invoke()

        rows = [tuple(tree.item(c, "values")) for c in tree.get_children()]
        udp_rows = [r for r in rows if r[0] == "UDP"]
        self.assertEqual(len(udp_rows), 2, rows)
        # State column shows the marker, remote column stays blank.
        self.assertTrue(all(r[2] == "" for r in udp_rows), rows)

    def test_columns_stay_fixed_to_tcp_layout_while_active(self):
        frame = _build_ui(self.holder, None)
        tree = _sole_of(frame, ttk.Treeview, "Treeview")
        check = _sole_of(frame, ttk.Checkbutton, "Checkbutton")
        check.invoke()
        self.assertEqual(tuple(tree["columns"]), TCP_COLUMNS)

        # The view is protocol-agnostic: even a UDP protocol context
        # must not flip the columns back while Active only is checked.
        _refresh(tree, "UDP", PID_ALL, tk.StringVar(), active_only=True)
        self.assertEqual(tuple(tree["columns"]), TCP_COLUMNS)
        self.assertEqual(len(tree.get_children()), 4)

    def test_status_line_matches_cli_active_tail(self):
        frame = _build_ui(self.holder, None)
        check = _sole_of(frame, ttk.Checkbutton, "Checkbutton")
        check.invoke()

        # Same TCP/UDP split the CLI's
        # "({n} active TCP + {m} UDP endpoints)" tail line reports.
        n_tcp = sum(1 for r in MIXED_ROWS if r.get("protocol") == "TCP")
        self.assertEqual(
            _status_text(self.root, frame),
            f"active: {n_tcp} TCP + {len(MIXED_ROWS) - n_tcp} UDP",
        )

    # ---- restore path

    def test_unchecking_restores_protocol_view(self):
        frame = _build_ui(self.holder, None)
        tree = _sole_of(frame, ttk.Treeview, "Treeview")
        check = _sole_of(frame, ttk.Checkbutton, "Checkbutton")

        check.invoke()
        check.invoke()

        rows = [tuple(tree.item(c, "values")) for c in tree.get_children()]
        self.assertEqual(
            rows, [("LISTENING", "0.0.0.0:445", "0.0.0.0:0", "4242")]
        )
        self.assertEqual(_status_text(self.root, frame), "TCP: 1 endpoints")

    def test_refresh_button_keeps_active_source_while_checked(self):
        frame = _build_ui(self.holder, None)
        tree = _sole_of(frame, ttk.Treeview, "Treeview")
        check = _sole_of(frame, ttk.Checkbutton, "Checkbutton")
        button = _sole_of(frame, ttk.Button, "Button")

        check.invoke()
        # A later snapshot must re-enter the active view, not fall back
        # to the plain TCP source.
        button.invoke()

        self.assertEqual(len(tree.get_children()), 4)
        self.assertEqual(
            _status_text(self.root, frame), "active: 2 TCP + 2 UDP"
        )

    def test_pid_filter_still_applies_in_active_view(self):
        frame = _build_ui(self.holder, None)
        tree = _sole_of(frame, ttk.Treeview, "Treeview")
        # ttk.Combobox subclasses ttk.Entry -- pick the PID entry only.
        entries = [
            w
            for w in _walk(frame)
            if isinstance(w, ttk.Entry) and not isinstance(w, ttk.Combobox)
        ]
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        check = _sole_of(frame, ttk.Checkbutton, "Checkbutton")
        button = _sole_of(frame, ttk.Button, "Button")

        check.invoke()
        entry.delete(0, "end")
        entry.insert(0, "9110")
        button.invoke()

        rows = [tuple(tree.item(c, "values")) for c in tree.get_children()]
        self.assertEqual(rows, [("UDP", "0.0.0.0:5353", "", "9110")])
        self.assertEqual(
            _status_text(self.root, frame), "active: 0 TCP + 1 UDP, pid=9110"
        )


if __name__ == "__main__":
    unittest.main()
