"""Tests for :mod:`myark.modules.trust.ui` (S10.11).

The trust tab is a single verify-pe panel: path entry + Browse + Verify
PE, a key-value result area, and a status line. It calls the same
``verify_pe_row`` data function the CLI prints, so UI and CLI always
report the same status. Tests drive the panel through the named handles
``_build_ui`` attaches to the returned frame; the data function is
pinned against the CLI's observed notepad.exe sample
(``source=r3-fallback status=not_signed`` while the driver is offline).

Tk-root sharing: see tests/conftest (one shared tk.Tk() per session).
"""

from __future__ import annotations

import os
import tkinter as tk
import unittest
from tkinter import ttk

from myark.modules.trust import cli, ui
from myark.modules.trust import parser as P
from myark.modules.trust import protocol as PP

HARNESS_HAS_TK = os.name == "nt" or os.environ.get("DISPLAY")

NOTEPAD = "C:/Windows/System32/notepad.exe"
# Deliberate typo of kernel32.dll: exercises a re-verify of a missing file
# (the r3 fallback reports the same not_signed either way, like the CLI).
KERNEL32_TYPO = "C:/Windows/System32/kerneL32.dll"


def _shared_root() -> tk.Tk:
    from tests import conftest
    return conftest.shared_tk_root()


class TestVerifyPeRow(unittest.TestCase):
    """The shared data function consumed by both CLI and UI."""

    def test_notepad_row_matches_cli_sample(self):
        self.assertEqual(
            cli.verify_pe_row(None, NOTEPAD),
            {
                "path": NOTEPAD,
                "status": "not_signed",
                "source": "r3-fallback",
                "subject": "",
                "issuer": "",
                "flags": "",
            },
        )

    def test_row_agrees_with_parser(self):
        for path in (NOTEPAD, KERNEL32_TYPO):
            row = cli.verify_pe_row(None, path)
            result = P.verify_pe(None, path)
            self.assertEqual(row["status"], result.status_name)
            self.assertEqual(row["source"], result.source)

    def test_flags_text_decomposition(self):
        self.assertEqual(cli._flags_text(0), "")
        self.assertEqual(cli._flags_text(PP.TRUST_FLAG_EMBEDDED), "embedded")
        self.assertEqual(
            cli._flags_text(PP.TRUST_FLAG_CATALOG | PP.TRUST_FLAG_TIMESTAMP),
            "catalog|timestamp",
        )
        self.assertEqual(cli._flags_text(0x80000000), "0x80000000")


class TestTrustPluginWiring(unittest.TestCase):
    def test_register_sets_ui_factory(self):
        from myark.modules.trust import plugin
        reg = plugin.register(None, [])
        self.assertIs(reg.ui_factory, ui._build_ui)
        self.assertTrue(reg.extra.get("r3_primary"))

    def test_make_ui_returns_panel(self):
        if not HARNESS_HAS_TK:
            self.skipTest("no Tk display available")
        from myark.modules.trust import plugin
        holder = tk.Toplevel(_shared_root())
        holder.withdraw()
        self.addCleanup(holder.destroy)
        panel = plugin.register(None, []).make_ui(holder, None)
        self.assertIsInstance(panel, ttk.Frame)


@unittest.skipUnless(HARNESS_HAS_TK, "no Tk display available")
class TestTrustPanelStructure(unittest.TestCase):
    def setUp(self):
        self.holder = tk.Toplevel(_shared_root())
        self.holder.withdraw()
        self.panel = ui._build_ui(self.holder, None)

    def tearDown(self):
        try:
            self.holder.destroy()
        except tk.TclError:
            pass

    def test_toolbar_widgets_exist(self):
        self.assertIsInstance(self.panel._path_entry, ttk.Entry)
        self.assertEqual(self.panel._browse_btn.cget("text"), "Browse...")
        self.assertEqual(self.panel._verify_btn.cget("text"), "Verify PE")

    def test_result_rows_exist(self):
        self.assertEqual(
            tuple(self.panel._result_vars.keys()),
            ("path", "status", "source", "subject", "issuer", "flags"),
        )

    def test_catalog_note_present(self):
        self.assertEqual(
            self.panel._catalog_note.cget("text"),
            "catalog verify 需驱动 (VM)",
        )


@unittest.skipUnless(HARNESS_HAS_TK, "no Tk display available")
class TestTrustPanelBehavior(unittest.TestCase):
    def setUp(self):
        self.holder = tk.Toplevel(_shared_root())
        self.holder.withdraw()
        self.panel = ui._build_ui(self.holder, None)

    def tearDown(self):
        try:
            self.holder.destroy()
        except tk.TclError:
            pass

    def test_verify_notepad_shows_cli_status(self):
        self.panel._path_var.set(NOTEPAD)
        self.panel._verify_btn.invoke()
        self.assertEqual(self.panel._result_vars["path"].get(), NOTEPAD)
        self.assertEqual(self.panel._result_vars["status"].get(), "not_signed")
        self.assertEqual(self.panel._result_vars["source"].get(), "r3-fallback")
        self.assertIn("status=not_signed", self.panel._status_var.get())

    def test_empty_path_hint_keeps_result_area(self):
        self.panel._path_var.set(NOTEPAD)
        self.panel._verify_btn.invoke()
        self.panel._path_var.set("   ")
        self.panel._verify_btn.invoke()
        self.assertEqual(self.panel._status_var.get(), "enter a PE path first")
        # the result area still shows the previous verification
        self.assertEqual(self.panel._result_vars["path"].get(), NOTEPAD)
        self.assertEqual(self.panel._result_vars["status"].get(), "not_signed")

    def test_second_verify_replaces_result(self):
        self.panel._path_var.set(NOTEPAD)
        self.panel._verify_btn.invoke()
        self.panel._path_var.set(KERNEL32_TYPO)
        self.panel._verify_btn.invoke()
        self.assertEqual(self.panel._result_vars["path"].get(), KERNEL32_TYPO)
        self.assertEqual(self.panel._result_vars["status"].get(), "not_signed")
        self.assertIn(KERNEL32_TYPO, self.panel._status_var.get())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
