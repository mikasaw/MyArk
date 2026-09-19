"""Tests for :mod:`myark.modules.security_audit.ui` (S10.9).

The security_audit tab is the first data-bearing R3 fallback panel for
the audit modules: three rows (defender / secure-boot / trusted-boot)
built by the same ``cli.audit_rows`` builders the CLI prints, so the
tab can never disagree with ``myark-cli security_audit ...``.

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

from myark.modules.security_audit import cli
from myark.modules.security_audit.ui import AUDIT_COLUMNS, _build_ui


HARNESS_HAS_TK = os.name == "nt" or os.environ.get("DISPLAY")


def _shared_root() -> tk.Tk:
    from tests import conftest
    return conftest.shared_tk_root()


class _OfflineClient:
    """Non-None client stand-in whose IOCTLs fail like a missing driver.

    Exercises the ``client is not None`` UI path (extra note label)
    while every query still degrades to the parser's R3 fallback.
    """

    def ioctl(self, *args, **kwargs):
        raise OSError("driver unavailable")


@unittest.skipUnless(HARNESS_HAS_TK, "no Tk display available")
class TestSecurityAuditUI(unittest.TestCase):
    def setUp(self) -> None:
        self.root = _shared_root()
        self.holder = tk.Toplevel(self.root)
        self.holder.withdraw()

    def tearDown(self) -> None:
        try:
            self.holder.destroy()
        except tk.TclError:
            pass

    @staticmethod
    def _widgets_of(frame):
        return list(frame.winfo_children())

    @staticmethod
    def _tree_of(frame) -> ttk.Treeview:
        trees = [w for w in frame.winfo_children() if isinstance(w, ttk.Treeview)]
        assert len(trees) == 1, f"expected exactly one Treeview, got {len(trees)}"
        return trees[0]

    def _refresh_button_of(self, frame) -> ttk.Button:
        buttons = [w for w in frame.winfo_children() if isinstance(w, ttk.Button)]
        self.assertEqual(len(buttons), 1, "expected exactly one Refresh button")
        return buttons[0]

    # ---- structure

    def test_build_ui_returns_frame(self):
        frame = _build_ui(self.holder, None)
        self.assertIsInstance(frame, ttk.Frame)

    def test_columns_are_item_source_status_kv(self):
        frame = _build_ui(self.holder, None)
        tree = self._tree_of(frame)
        self.assertEqual(tuple(tree["columns"]), AUDIT_COLUMNS)
        self.assertEqual(AUDIT_COLUMNS, ("item", "source", "status_kv"))

    def test_refresh_button_present(self):
        frame = _build_ui(self.holder, None)
        button = self._refresh_button_of(frame)
        self.assertIn("Refresh", str(button.cget("text")))

    def test_title_reports_r3_fallback(self):
        frame = _build_ui(self.holder, None)
        labels = [w for w in self._widgets_of(frame) if isinstance(w, ttk.Label)]
        texts = [str(l.cget("text")) for l in labels]
        self.assertTrue(
            any("R3 fallback - no driver required" in t for t in texts),
            f"title missing: {texts}",
        )

    def test_online_note_only_when_client_present(self):
        offline = _build_ui(self.holder, None)
        offline_texts = [
            str(w.cget("text"))
            for w in self._widgets_of(offline)
            if isinstance(w, ttk.Label)
        ]
        self.assertFalse(any("driver online" in t for t in offline_texts))

        online = _build_ui(self.holder, _OfflineClient())
        online_texts = [
            str(w.cget("text"))
            for w in self._widgets_of(online)
            if isinstance(w, ttk.Label)
        ]
        self.assertTrue(
            any("driver online" in t for t in online_texts),
            f"note missing: {online_texts}",
        )

    # ---- data (R3 fallback rows)

    def test_refresh_fills_three_r3_fallback_rows(self):
        frame = _build_ui(self.holder, None)
        self._refresh_button_of(frame).invoke()

        tree = self._tree_of(frame)
        children = tree.get_children()
        self.assertEqual(len(children), 3)

        rows = [tree.item(c, "values") for c in children]
        self.assertEqual([r[0] for r in rows], ["defender", "secure-boot", "trusted-boot"])
        self.assertTrue(all(r[1] == "r3-fallback" for r in rows), rows)
        self.assertEqual(rows[0][2], "installed=0 running=0 realtime=0")
        self.assertEqual(rows[1][2], "enabled=0")
        self.assertEqual(rows[2][2], "measured_boot=0 event_log=0")

    def test_refresh_degrades_gracefully_with_failing_client(self):
        # Non-None client whose IOCTLs raise: the tab must still show
        # the R3 fallback rows, not an error state.
        frame = _build_ui(self.holder, _OfflineClient())
        self._refresh_button_of(frame).invoke()

        tree = self._tree_of(frame)
        rows = [tree.item(c, "values") for c in tree.get_children()]
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(r[1] == "r3-fallback" for r in rows), rows)

    def test_rows_match_cli_row_builders(self):
        # The whole point of the shared builders: the UI table and the
        # CLI must report the same field values.
        frame = _build_ui(self.holder, None)
        self._refresh_button_of(frame).invoke()

        tree = self._tree_of(frame)
        ui_rows = [tuple(tree.item(c, "values")) for c in tree.get_children()]
        cli_rows = [
            (r["item"], r["source"], r["status_kv"]) for r in cli.audit_rows(None)
        ]
        self.assertEqual(ui_rows, cli_rows)

    def test_status_line_reports_row_count(self):
        frame = _build_ui(self.holder, None)
        self._refresh_button_of(frame).invoke()
        status_labels = [
            str(w.cget("text"))
            for w in self._widgets_of(frame)
            if isinstance(w, ttk.Label) and "audit items" in str(w.cget("text"))
        ]
        self.assertEqual(len(status_labels), 1, status_labels)
        self.assertIn("loaded 3 audit items (r3-fallback)", status_labels[0])


@unittest.skipUnless(HARNESS_HAS_TK, "no Tk display available")
class TestSecurityAuditTabInMainWindow(unittest.TestCase):
    """security_audit must now host its own panel, not R3ModulePanel."""

    def setUp(self) -> None:
        if not HARNESS_HAS_TK:
            self.skipTest("no Tk display available")
        from myark.ui.main_window import MainWindow
        self.win = MainWindow()

    def tearDown(self) -> None:
        try:
            for child in list(self.win.winfo_children()):
                try:
                    child.destroy()
                except tk.TclError:
                    pass
            self.win.destroy()
        except tk.TclError:
            pass

    def _tab_widget(self, name):
        for tab_id in self.win._notebook.tabs():
            if self.win._notebook.tab(tab_id, "text") == name:
                return self.win.nametowidget(tab_id)
        return None

    def test_tab_hosts_data_panel_not_r3_module_panel(self):
        from myark.ui.widgets.r3_module_panel import R3ModulePanel

        widget = self._tab_widget("security_audit")
        self.assertIsNotNone(widget, "security_audit tab missing")
        self.assertNotIsInstance(widget, R3ModulePanel)
        self.assertIsInstance(widget, ttk.Frame)

        labels = [c for c in widget.winfo_children() if isinstance(c, ttk.Label)]
        texts = [str(l.cget("text")) for l in labels]
        self.assertTrue(
            any("R3 fallback - no driver required" in t for t in texts), texts
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
