"""Tests for :mod:`myark.ui.widgets.detail_window`.

The detail popup is pure UI: no driver IOCTLs, no Python package state.
We exercise the surface (constructor, item swap, format rules, Esc
binding, geometry placement) with ``tk.Toplevel`` widgets created and
destroyed inside each test so we never leave a window alive between
runs.

Tk-root sharing
---------------
All Tk-using tests in this module share a single ``tk.Tk()`` root
created at import time. This matches the convention used by the
project's existing smoke tests (``test_ui_search``), where each test
body creates a fresh ``tk.Tk()`` and tears it down. Sharing across
``unittest`` cases keeps the Tk interpreter count low enough that the
tests stay green in the full 600+ test suite -- creating a new root
for every test exhausts Tcl resources after a few hundred cases.
"""

from __future__ import annotations

import os
import sys
import tkinter as tk
import unittest

from myark.ui.widgets.detail_window import DEFAULT_TITLE, DetailWindow


HARNESS_HAS_TK = os.name == "nt" or os.environ.get("DISPLAY")


_SHARED_ROOT: tk.Tk | None = None


def _shared_root() -> tk.Tk:
    from tests import conftest
    return conftest.shared_tk_root()


def _purge_children(root: tk.Tk) -> None:
    try:
        for child in list(root.winfo_children()):
            try:
                child.destroy()
            except tk.TclError:
                pass
    except tk.TclError:
        pass


@unittest.skipUnless(HARNESS_HAS_TK, "no Tk display available")
class TestDetailWindow(unittest.TestCase):
    def setUp(self) -> None:
        if not HARNESS_HAS_TK:
            self.skipTest("no Tk display available")
        self.root = _shared_root()
        _purge_children(self.root)

    def tearDown(self) -> None:
        _purge_children(self.root)

    # ----- lifecycle / shape

    def test_open_and_close(self):
        win = DetailWindow(self.root, item={"pid": 1234})
        self.assertIsInstance(win, tk.Toplevel)
        self.assertTrue(bool(win.winfo_exists()))
        win.destroy()
        self.assertFalse(bool(win.winfo_exists()))

    def test_default_title_fallback(self):
        win = DetailWindow(self.root, item={"k": "v"})
        self.assertEqual(win.title(), DEFAULT_TITLE)

    def test_custom_title(self):
        win = DetailWindow(self.root, item={"pid": 1}, title="Process 1")
        self.assertEqual(win.title(), "Process 1")

    # ----- rendering

    def test_display_dict_in_insertion_order(self):
        data = {"pid": 1234, "name": "lsass.exe", "path": "C:\\Windows\\System32"}
        win = DetailWindow(self.root, item=data)
        rows = [win._tree.item(iid, "values") for iid in win._tree.get_children()]
        keys = [r[0] for r in rows]
        values = [r[1] for r in rows]
        self.assertEqual(keys, ["pid", "name", "path"])
        self.assertEqual(values, ["1234", "lsass.exe", "C:\\Windows\\System32"])

    def test_set_item_replaces_dict(self):
        win = DetailWindow(self.root, item={"a": 1})
        win.set_item({"x": 10, "y": 20})
        keys = [win._tree.item(i, "values")[0] for i in win._tree.get_children()]
        self.assertEqual(keys, ["x", "y"])

    def test_format_bytes_and_list(self):
        win = DetailWindow(
            self.root,
            item={"raw": b"hello\x00world", "tags": [1, 2, 3]},
        )
        values = {
            win._tree.item(i, "values")[0]: win._tree.item(i, "values")[1]
            for i in win._tree.get_children()
        }
        self.assertEqual(values["raw"], "hello")
        self.assertEqual(values["tags"], "1, 2, 3")

    def test_esc_binding_closes_window(self):
        win = DetailWindow(self.root, item={"pid": 1})
        bindings = win.bind("<Escape>")
        self.assertTrue(bindings, "<Escape> must be bound")
        win.destroy()
        self.assertFalse(bool(win.winfo_exists()))

    # ----- geometry

    def test_position_near_pointer(self):
        win = DetailWindow(self.root, item={"pid": 1})
        win.update_idletasks()
        geo = win.geometry()
        self.assertTrue(
            geo.startswith("+") or geo[0].isdigit(),
            f"unexpected geometry: {geo!r}",
        )


if __name__ == "__main__":
    unittest.main()