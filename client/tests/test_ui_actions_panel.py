"""Tests for :mod:`myark.ui.widgets.actions_panel` (S10.5).

The panel lists the actions module's IOCTL surface: one row per
``QUERY_CAPABILITIES`` entry with ``module_id == 'ACTN'``, or the static
protocol mirror when no driver-derived entry survives that filter.

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

from myark.client.module_query import CapabilityInfo
from myark.modules.actions.protocol import (
    ACTIONS_IOCTL_FUNCTIONS,
    IOCTL_MYARK_ACTION_DUMP_MEMORY,
    IOCTL_MYARK_ACTION_KILL_PROCESS,
    IOCTL_MYARK_ACTION_PROTECT_PROCESS,
    MYARK_ACTIONS_MODULE_ID,
)
from myark.ui.widgets.actions_panel import ActionsPanel, _BUILTIN_ACTIONS


HARNESS_HAS_TK = os.name == "nt" or os.environ.get("DISPLAY")


def _shared_root() -> tk.Tk:
    from tests import conftest
    return conftest.shared_tk_root()


def _make_actions_caps():
    """The 7 actions entries exactly as QUERY_CAPABILITIES reports them."""
    return [
        CapabilityInfo(ioctl_code=code, name=name, module_id=MYARK_ACTIONS_MODULE_ID)
        for name, code in _BUILTIN_ACTIONS
    ]


class TestActionsPanel(unittest.TestCase):
    def setUp(self) -> None:
        if not HARNESS_HAS_TK:
            self.skipTest("no Tk display available")
        self.root = _shared_root()
        self.panel_holder = tk.Toplevel(self.root)
        self.panel_holder.withdraw()
        self._widgets = []

    def tearDown(self) -> None:
        for w in self._widgets:
            try:
                w.destroy()
            except tk.TclError:
                pass
        try:
            self.panel_holder.destroy()
        except tk.TclError:
            pass

    def _make_panel(self) -> ActionsPanel:
        panel = ActionsPanel(self.panel_holder)
        self._widgets.append(panel)
        return panel

    # ---- driver-present path

    def test_driver_rows_listed_with_source_column(self):
        panel = self._make_panel()
        caps = _make_actions_caps()
        # Inject one foreign-module entry to prove the module_id filter.
        caps.insert(0, CapabilityInfo(ioctl_code=0x2A0000, name="process_enum",
                                      module_id=0x50424944))
        panel.set_capabilities(caps)

        rows = panel._table._all_rows
        self.assertEqual(len(rows), len(ACTIONS_IOCTL_FUNCTIONS))
        self.assertEqual({r[1] for r in rows}, set(ACTIONS_IOCTL_FUNCTIONS))
        self.assertTrue(all(r[2] == "driver" for r in rows))

    def test_ioctl_codes_formatted_hex(self):
        panel = self._make_panel()
        panel.set_capabilities(
            [CapabilityInfo(ioctl_code=IOCTL_MYARK_ACTION_DUMP_MEMORY,
                            name="dump_memory",
                            module_id=MYARK_ACTIONS_MODULE_ID)]
        )
        row = panel._table._all_rows[0]
        self.assertEqual(row[0], f"0x{IOCTL_MYARK_ACTION_DUMP_MEMORY:08X}")
        self.assertEqual(row[1], "dump_memory")

    def test_rows_sorted_in_function_code_order(self):
        panel = self._make_panel()
        caps = list(reversed(_make_actions_caps()))
        panel.set_capabilities(caps)
        names = [r[1] for r in panel._table._all_rows]
        self.assertEqual(names[0], "kill_process")
        self.assertEqual(names[-1], "protect_process")

    # ---- driver-offline fallback

    def test_empty_capabilities_fall_back_to_builtin_mirror(self):
        panel = self._make_panel()
        panel.set_capabilities([])

        rows = panel._table._all_rows
        self.assertEqual(len(rows), len(_BUILTIN_ACTIONS))
        self.assertTrue(all(r[2] == "builtin" for r in rows))
        self.assertIn("kill_process", {r[1] for r in rows})
        codes = {int(r[0], 16) for r in rows}
        self.assertIn(IOCTL_MYARK_ACTION_KILL_PROCESS, codes)
        self.assertIn(IOCTL_MYARK_ACTION_PROTECT_PROCESS, codes)

    def test_only_foreign_modules_also_fall_back(self):
        panel = self._make_panel()
        panel.set_capabilities(
            [CapabilityInfo(ioctl_code=0x2A0001, name="reg_key_query",
                            module_id=0x52454745)]
        )
        rows = panel._table._all_rows
        self.assertTrue(rows)
        self.assertTrue(all(r[2] == "builtin" for r in rows))

    def test_builtin_mirror_matches_protocol_constants(self):
        # Keep the static mirror honest against the ctypes protocol module.
        by_name = dict(_BUILTIN_ACTIONS)
        self.assertEqual(by_name["kill_process"], IOCTL_MYARK_ACTION_KILL_PROCESS)
        self.assertEqual(by_name["dump_memory"], IOCTL_MYARK_ACTION_DUMP_MEMORY)
        self.assertEqual(set(by_name), set(ACTIONS_IOCTL_FUNCTIONS))


class TestActionsPanelClipboard(unittest.TestCase):
    def setUp(self) -> None:
        if not HARNESS_HAS_TK:
            self.skipTest("no Tk display available")
        self.root = _shared_root()

    def tearDown(self) -> None:
        try:
            self.root.clipboard_clear()
        except tk.TclError:
            pass

    def test_copy_text_sets_clipboard(self):
        holder = tk.Toplevel(self.root)
        holder.withdraw()
        try:
            panel = ActionsPanel(holder)
            panel.copy_text("test-ioctl-code")
            self.assertEqual(panel.clipboard_get(), "test-ioctl-code")
        finally:
            try:
                holder.destroy()
            except tk.TclError:
                pass


@unittest.skipUnless(HARNESS_HAS_TK, "no Tk display available")
class TestActionsTabInMainWindow(unittest.TestCase):
    """The actions notebook tab must host the panel, not the placeholder.

    MainWindow inherits from ``tk.Tk`` so it IS a Tk root; destroy it in
    tearDown instead of using the conftest shared root (same pattern as
    ``test_ui_main_window_s92``).
    """

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
        except tk.TclError:
            pass
        try:
            self.win.destroy()
        except tk.TclError:
            pass

    def _actions_tab_widget(self):
        for tab_id in self.win._notebook.tabs():
            if self.win._notebook.tab(tab_id, "text") == "actions":
                return self.win.nametowidget(tab_id)
        return None

    def test_actions_tab_hosts_panel(self):
        widget = self._actions_tab_widget()
        self.assertIsInstance(widget, ActionsPanel)

    def test_actions_tab_lists_full_ioctl_set_without_driver(self):
        # This harness has no driver: the tab must show the builtin
        # mirror rather than an empty table (with a driver loaded, the
        # row count is whatever QUERY_CAPABILITIES reports).
        widget = self._actions_tab_widget()
        self.assertIsNotNone(widget)
        rows = widget._table._all_rows
        if self.win._client is None:
            self.assertEqual(len(rows), len(ACTIONS_IOCTL_FUNCTIONS))
            self.assertTrue(all(r[2] == "builtin" for r in rows))
        else:
            self.assertGreaterEqual(len(rows), 1)

    def test_placeholder_text_gone_for_actions(self):
        texts = []
        for tab_id in self.win._notebook.tabs():
            widget = self.win.nametowidget(tab_id)
            labels = [c for c in widget.winfo_children()
                      if isinstance(c, ttk.Label)]
            texts.extend(str(l.cget("text")) for l in labels)
        self.assertNotIn("actions: no UI shipped yet", texts)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
