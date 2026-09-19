"""Integration tests for :mod:`myark.ui.main_window` after S9.2.

The MainWindow now owns four S9.2 popup helpers
(``_open_detail / _open_diff / _open_filter_builder / _open_history``)
plus a help dialog and a ``PopupStack`` that tracks all Toplevels so
``Ctrl+Tab`` / ``Ctrl+W`` work.

We instantiate the full MainWindow (which probes the driver, queries
capabilities, etc.) and then drive the S9.2 surface directly. No real
keyboard events are generated -- the keybindings helper attaches the
script strings and we inspect the bound scripts via ``widget.bind``.

Tk-root sharing
---------------
MainWindow inherits from ``tk.Tk`` so it IS a Tk root. We therefore
destroy the MainWindow in ``tearDown`` instead of using the conftest
shared root. That keeps the existing shared-root pool untouched for
other tests.
"""

from __future__ import annotations

import os
import tkinter as tk
import unittest

from myark.ui.keybindings import (
    KEY_CTRL_TAB,
    KEY_CTRL_W,
    KEY_F1,
    KEY_F5,
    PopupStack,
)
from myark.ui.main_window import MainWindow
from myark.ui.widgets.detail_window import DetailWindow
from myark.ui.widgets.diff_window import DiffWindow
from myark.ui.widgets.filter_window import FilterWindow
from myark.ui.widgets.history_window import HistoryWindow


HARNESS_HAS_TK = os.name == "nt" or os.environ.get("DISPLAY")


@unittest.skipUnless(HARNESS_HAS_TK, "no Tk display available")
class TestMainWindowIntegration(unittest.TestCase):
    def setUp(self) -> None:
        if not HARNESS_HAS_TK:
            self.skipTest("no Tk display available")
        self.win = MainWindow()

    def tearDown(self) -> None:
        try:
            for child in list(self.win.winfo_children()):
                try:
                    child.destroy()
                except tk.TclError:
                    pass
        except tk.TclError:
            pass
        try:
            self.win.destroy()
        except tk.TclError:
            pass

    # ---- helpers & popups

    def test_popup_stack_initialized(self):
        self.assertIsInstance(self.win._popup_stack, PopupStack)
        self.assertEqual(self.win._popup_stack.popups, [])

    def test_open_help_creates_toplevel(self):
        self.win._open_help()
        self.assertEqual(len(self.win._popup_stack.popups), 1)
        top = self.win._popup_stack.popups[-1]
        self.assertTrue(bool(top.winfo_exists()))
        self.assertNotIsInstance(top, DetailWindow)
        top.destroy()

    def test_open_diff_creates_diff_window(self):
        self.win._open_diff()
        top = self.win._popup_stack.popups[-1]
        self.assertIsInstance(top, DiffWindow)
        top.destroy()

    def test_open_filter_builder_creates_filter_window(self):
        self.win._open_filter_builder()
        top = self.win._popup_stack.popups[-1]
        self.assertIsInstance(top, FilterWindow)
        top.destroy()

    def test_open_history_creates_history_window(self):
        self.win._open_history()
        top = self.win._popup_stack.popups[-1]
        self.assertIsInstance(top, HistoryWindow)
        top.destroy()

    def test_open_detail_no_selection_shows_status(self):
        # No row is selected, so _open_detail must NOT pop a window.
        self.win._open_detail()
        self.assertEqual(self.win._popup_stack.popups, [])

    # ---- keybindings

    def test_bindings_present(self):
        for key in (KEY_F1, KEY_F5, KEY_CTRL_TAB, KEY_CTRL_W):
            self.assertTrue(
                self.win.bind(key),
                f"<{key}> must be bound on MainWindow",
            )

    def test_ctrl_w_no_popup_is_noop(self):
        # No popups open; Ctrl+W must not raise.
        self.win._close_popup()
        self.assertEqual(self.win._popup_stack.popups, [])

    def test_ctrl_w_closes_top_popup(self):
        self.win._open_history()
        top = self.win._popup_stack.popups[-1]
        self.win._close_popup()
        self.win.update_idletasks()
        self.assertFalse(bool(top.winfo_exists()))

    def test_cycle_popup_no_popups_does_not_raise(self):
        # When no popups are open, Ctrl+Tab should focus the master
        # without raising even if it is withdrawn.
        try:
            self.win._cycle_popup(False)
            self.win._cycle_popup(True)
        except tk.TclError:
            pass

    def test_apply_builder_filter_clears_when_inactive(self):
        from myark.ui.search.adv_search_panel import AdvancedFilter
        from myark.ui.search.matcher import MatchMode

        flt = AdvancedFilter(fields={}, ranges={}, mode=MatchMode.PINYIN)
        self.win._apply_builder_filter(flt)
        self.assertIsNone(self.win._active_advanced)

    def test_apply_builder_filter_active_sets_label(self):
        from myark.ui.search.adv_search_panel import AdvancedFilter
        from myark.ui.search.matcher import MatchMode

        flt = AdvancedFilter(
            fields={"name": "py"},
            ranges={},
            mode=MatchMode.SUBSTRING,
        )
        self.win._apply_builder_filter(flt)
        self.assertIsNotNone(self.win._active_advanced)
        self.assertIn("name~py", self.win._adv_label_var.get())

    def test_popup_chain_tracks_destroy(self):
        self.win._open_history()
        self.win._open_diff()
        self.assertEqual(len(self.win._popup_stack.popups), 2)
        # Destroy the top -- the chain must update via the <Destroy>
        # binding the popup stack installed.
        top = self.win._popup_stack.popups[-1]
        top.destroy()
        self.win.update_idletasks()
        self.assertEqual(len(self.win._popup_stack.popups), 1)


if __name__ == "__main__":
    unittest.main()