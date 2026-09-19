"""Tests for :mod:`myark.ui.widgets.r3_module_panel` (S10.6).

The generic panel gives every UI-less module a tab listing its IOCTL
surface: one row per ``QUERY_CAPABILITIES`` entry belonging to the module
once the driver is loaded, or the module's protocol-mirror fallback while
it is offline. ``callback`` (10 IOCTLs, 'CBLK') doubles as the concrete
fixture throughout.

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
from myark.modules.callback.protocol import (
    IOCTL_MYARK_CALLBACK_BACKUP,
    IOCTL_MYARK_CALLBACK_ENUMERATE,
    IOCTL_MYARK_CALLBACK_QUERY_CM,
    IOCTL_MYARK_CALLBACK_QUERY_DBG,
    IOCTL_MYARK_CALLBACK_QUERY_IMAGE,
    IOCTL_MYARK_CALLBACK_QUERY_OB,
    IOCTL_MYARK_CALLBACK_QUERY_PS,
    IOCTL_MYARK_CALLBACK_REMOVE,
    IOCTL_MYARK_CALLBACK_RESTORE,
    IOCTL_MYARK_CALLBACK_STATS,
)
from myark.ui.widgets.actions_panel import ActionsPanel
from myark.ui.widgets.r3_module_panel import (
    R3ModulePanel,
    protocol_mirror_ioctls,
)


HARNESS_HAS_TK = os.name == "nt" or os.environ.get("DISPLAY")

# Mirror of MYARK_CALLBACK_MODULE_ID in MyArkCallbackIoctl.h ('CBLK'); the
# R3 protocol mirror does not (yet) carry module ids, so the tests pin the
# value the driver reports in QUERY_MODULES / QUERY_CAPABILITIES.
MYARK_CALLBACK_MODULE_ID = 0x43424C4B

_ALL_CALLBACK_IOCTLS = {
    IOCTL_MYARK_CALLBACK_QUERY_PS,
    IOCTL_MYARK_CALLBACK_QUERY_CM,
    IOCTL_MYARK_CALLBACK_QUERY_OB,
    IOCTL_MYARK_CALLBACK_QUERY_IMAGE,
    IOCTL_MYARK_CALLBACK_QUERY_DBG,
    IOCTL_MYARK_CALLBACK_ENUMERATE,
    IOCTL_MYARK_CALLBACK_REMOVE,
    IOCTL_MYARK_CALLBACK_RESTORE,
    IOCTL_MYARK_CALLBACK_BACKUP,
    IOCTL_MYARK_CALLBACK_STATS,
}


# The 14 UI-less modules that now host the generic panel (actions,
# security_audit, preflight and trust keep their dedicated tabs).
UI_LESS_MODULES = (
    "alpc", "authentication", "bugcheck", "callback", "capability",
    "dyndata", "hwid", "kernel_ext", "mutation", "redirect",
    "safety", "wfp", "win32k", "wsl",
)


def _shared_root() -> tk.Tk:
    from tests import conftest
    return conftest.shared_tk_root()


class TestProtocolMirrorIntrospection(unittest.TestCase):
    """The builtin fallback derives straight from the protocol mirror."""

    def test_callback_mirror_lists_all_ten_ioctls(self):
        mirror = protocol_mirror_ioctls("callback")
        self.assertEqual(len(mirror), 10)
        self.assertEqual({code for code, _ in mirror}, _ALL_CALLBACK_IOCTLS)
        self.assertIn("IOCTL_MYARK_CALLBACK_QUERY_PS", {name for _, name in mirror})

    def test_mirror_sorted_by_function_code(self):
        codes = [code for code, _ in protocol_mirror_ioctls("callback")]
        self.assertEqual(codes, sorted(codes))
        self.assertEqual(codes[0], IOCTL_MYARK_CALLBACK_QUERY_PS)

    def test_mirror_names_are_protocol_constant_names(self):
        by_code = dict(protocol_mirror_ioctls("callback"))
        self.assertEqual(by_code[IOCTL_MYARK_CALLBACK_STATS],
                         "IOCTL_MYARK_CALLBACK_STATS")

    def test_unknown_module_yields_empty_mirror(self):
        self.assertEqual(protocol_mirror_ioctls("no_such_module"), ())

    def test_module_without_mirror_yields_empty(self):
        # 'debug-output' registers under a hyphenated name and ships no
        # protocol.py; the lookup must degrade to an empty mirror.
        self.assertEqual(protocol_mirror_ioctls("debug-output"), ())


@unittest.skipUnless(HARNESS_HAS_TK, "no Tk display available")
class TestR3ModulePanel(unittest.TestCase):
    def setUp(self) -> None:
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

    def _make_panel(self, module_id=None) -> R3ModulePanel:
        panel = R3ModulePanel(self.panel_holder, "callback", module_id=module_id)
        self._widgets.append(panel)
        return panel

    @staticmethod
    def _callback_caps(module_id):
        return [
            CapabilityInfo(ioctl_code=code, name=name, module_id=module_id)
            for code, name in protocol_mirror_ioctls("callback")
        ]

    # ---- driver-present path

    def test_driver_rows_listed_with_source_column(self):
        panel = self._make_panel(module_id=MYARK_CALLBACK_MODULE_ID)
        caps = self._callback_caps(MYARK_CALLBACK_MODULE_ID)
        # Inject one foreign-module entry to prove the module_id filter.
        caps.insert(0, CapabilityInfo(ioctl_code=0x2A0000, name="process_enum",
                                      module_id=0x50424944))
        panel.set_capabilities(caps)

        rows = panel._table._all_rows
        self.assertEqual(len(rows), 10)
        self.assertEqual({int(r[0], 16) for r in rows}, _ALL_CALLBACK_IOCTLS)
        self.assertTrue(all(r[2] == "driver" for r in rows))

    def test_ioctl_codes_formatted_hex(self):
        panel = self._make_panel(module_id=MYARK_CALLBACK_MODULE_ID)
        panel.set_capabilities(
            [CapabilityInfo(ioctl_code=IOCTL_MYARK_CALLBACK_STATS,
                            name="IOCTL_MYARK_CALLBACK_STATS",
                            module_id=MYARK_CALLBACK_MODULE_ID)]
        )
        row = panel._table._all_rows[0]
        self.assertEqual(row[0], f"0x{IOCTL_MYARK_CALLBACK_STATS:08X}")
        self.assertEqual(row[1], "IOCTL_MYARK_CALLBACK_STATS")

    def test_rows_sorted_in_function_code_order(self):
        panel = self._make_panel(module_id=MYARK_CALLBACK_MODULE_ID)
        panel.set_capabilities(list(reversed(
            self._callback_caps(MYARK_CALLBACK_MODULE_ID))))
        names = [r[1] for r in panel._table._all_rows]
        self.assertEqual(names[0], "IOCTL_MYARK_CALLBACK_QUERY_PS")
        self.assertEqual(names[-1], "IOCTL_MYARK_CALLBACK_STATS")

    def test_module_id_mismatch_rescued_by_code_membership(self):
        # A driver whose QUERY_MODULES name->id mapping is missing must
        # not lose the module's rows: IOCTL codes are globally unique,
        # so membership in the mirror identifies the module too.
        panel = self._make_panel(module_id=None)
        panel.set_capabilities(self._callback_caps(0xDEADBEEF))
        rows = panel._table._all_rows
        self.assertEqual(len(rows), 10)
        self.assertTrue(all(r[2] == "driver" for r in rows))

    # ---- driver-offline fallback

    def test_empty_capabilities_fall_back_to_builtin_mirror(self):
        panel = self._make_panel()
        panel.set_capabilities([])

        rows = panel._table._all_rows
        self.assertEqual(len(rows), 10)
        self.assertTrue(all(r[2] == "builtin" for r in rows))
        self.assertIn("IOCTL_MYARK_CALLBACK_QUERY_PS", {r[1] for r in rows})
        self.assertEqual({int(r[0], 16) for r in rows}, _ALL_CALLBACK_IOCTLS)

    def test_only_foreign_modules_also_fall_back(self):
        panel = self._make_panel(module_id=MYARK_CALLBACK_MODULE_ID)
        panel.set_capabilities(
            [CapabilityInfo(ioctl_code=0x2A0001, name="reg_key_query",
                            module_id=0x52454745)]
        )
        rows = panel._table._all_rows
        self.assertEqual(len(rows), 10)
        self.assertTrue(all(r[2] == "builtin" for r in rows))

    def test_builtin_rows_render_like_driver_rows(self):
        # Names come from the protocol-header constants -- the same
        # strings QUERY_CAPABILITIES reports -- so the two sources are
        # indistinguishable apart from the source column.
        offline = self._make_panel()
        offline.set_capabilities([])
        online = self._make_panel(module_id=MYARK_CALLBACK_MODULE_ID)
        online.set_capabilities(self._callback_caps(MYARK_CALLBACK_MODULE_ID))

        offline_rows = [(int(r[0], 16), r[1]) for r in offline._table._all_rows]
        online_rows = [(int(r[0], 16), r[1]) for r in online._table._all_rows]
        self.assertEqual(offline_rows, online_rows)

    # ---- S10.13 offline note

    def test_builtin_fallback_shows_offline_note(self):
        # With no driver rows the table shows the static protocol
        # mirror; the gray note above it must say so (S10.13).
        panel = self._make_panel()
        panel.set_capabilities([])
        self.assertEqual(panel._offline_note.winfo_manager(), "pack")

    def test_driver_rows_hide_offline_note(self):
        # Once real driver rows render, the note would wrongly claim
        # the list is static -- it must be gone.
        panel = self._make_panel(module_id=MYARK_CALLBACK_MODULE_ID)
        panel.set_capabilities(self._callback_caps(MYARK_CALLBACK_MODULE_ID))
        self.assertEqual(panel._offline_note.winfo_manager(), "")

    def test_mirror_note_reports_ioctl_count(self):
        panel = self._make_panel()
        self.assertEqual(panel._mirror_var.get(), "protocol mirror: 10 IOCTLs")

    def test_unknown_module_panel_renders_empty(self):
        panel = R3ModulePanel(self.panel_holder, "no_such_module")
        self._widgets.append(panel)
        self.assertEqual(panel._mirror_var.get(), "protocol mirror: unavailable")
        panel.set_capabilities([])
        self.assertEqual(panel._table._all_rows, [])


@unittest.skipUnless(HARNESS_HAS_TK, "no Tk display available")
class TestR3ModulePanelClipboard(unittest.TestCase):
    def setUp(self) -> None:
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
            panel = R3ModulePanel(holder, "callback")
            panel.copy_text("test-ioctl-code")
            self.assertEqual(panel.clipboard_get(), "test-ioctl-code")
        finally:
            try:
                holder.destroy()
            except tk.TclError:
                pass


@unittest.skipUnless(HARNESS_HAS_TK, "no Tk display available")
class TestR3ModuleTabsInMainWindow(unittest.TestCase):
    """Every UI-less module tab must host R3ModulePanel, not a placeholder.

    MainWindow inherits from ``tk.Tk`` so it IS a Tk root; destroy it in
    tearDown instead of using the conftest shared root (same pattern as
    ``test_ui_actions_panel``).
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
            self.win.destroy()
        except tk.TclError:
            pass

    def _tab_widget(self, name):
        for tab_id in self.win._notebook.tabs():
            if self.win._notebook.tab(tab_id, "text") == name:
                return self.win.nametowidget(tab_id)
        return None

    def test_ui_less_module_tabs_all_host_r3_module_panel(self):
        for name in UI_LESS_MODULES:
            widget = self._tab_widget(name)
            self.assertIsNotNone(widget, f"{name}: tab missing")
            self.assertIsInstance(widget, R3ModulePanel, name)

    def test_ui_less_tabs_show_builtin_mirror_without_driver(self):
        # This harness has no driver: the tabs must show the builtin
        # protocol mirror rather than empty tables (with a driver
        # loaded, the rows are whatever QUERY_CAPABILITIES reports).
        for name in ("callback", "dyndata", "wsl"):
            widget = self._tab_widget(name)
            if self.win._client is None:
                rows = widget._table._all_rows
                self.assertTrue(rows, name)
                self.assertTrue(all(r[2] == "builtin" for r in rows), name)

    def test_placeholder_text_gone_for_ui_less_modules(self):
        texts = []
        for tab_id in self.win._notebook.tabs():
            widget = self.win.nametowidget(tab_id)
            labels = [c for c in widget.winfo_children()
                      if isinstance(c, ttk.Label)]
            texts.extend(str(l.cget("text")) for l in labels)
        for name in UI_LESS_MODULES:
            self.assertNotIn(f"{name}: no UI shipped yet", texts)

    def test_actions_tab_still_hosts_actions_panel(self):
        # S10.5 behaviour is preserved: actions keeps its dedicated
        # panel (special display source) instead of the generic one.
        widget = self._tab_widget("actions")
        self.assertIsInstance(widget, ActionsPanel)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
