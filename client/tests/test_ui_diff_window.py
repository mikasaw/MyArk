"""Tests for :mod:`myark.ui.widgets.diff_window`.

Pure-UI comparison popup; we cover the public surface (construction,
diff list, per-kind summary banners, "differences only" toggle, Esc
binding) without doing any real Tk event processing -- the bound
callbacks are inspected via ``widget.bind("<Escape>")`` instead.

Tk-root sharing
---------------
All Tk-using tests share a single ``tk.Tk()`` root via the module-level
``_shared_root`` helper. See ``test_ui_detail_window`` for the rationale
(creating a fresh Tk root for every test exhausts Tcl resources in a
600+ test suite).
"""

from __future__ import annotations

import os
import tkinter as tk
import unittest

from myark.ui.widgets.diff_window import DEFAULT_TITLE, DiffWindow


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
class TestDiffWindow(unittest.TestCase):
    def setUp(self) -> None:
        if not HARNESS_HAS_TK:
            self.skipTest("no Tk display available")
        self.root = _shared_root()
        _purge_children(self.root)

    def tearDown(self) -> None:
        _purge_children(self.root)

    # ----- lifecycle

    def test_open_and_close(self):
        win = DiffWindow(
            self.root,
            item_a={"pid": 1},
            item_b={"pid": 2},
        )
        self.assertIsInstance(win, tk.Toplevel)
        win.destroy()
        self.assertFalse(bool(win.winfo_exists()))

    def test_default_title_fallback(self):
        win = DiffWindow(self.root)
        self.assertEqual(win.title(), DEFAULT_TITLE)

    def test_custom_title(self):
        win = DiffWindow(
            self.root,
            item_a={"k": 1}, item_b={"k": 2},
            title="Compare two entries",
        )
        self.assertEqual(win.title(), "Compare two entries")

    # ----- differences detection

    def test_differences_lists_changed_keys(self):
        win = DiffWindow(
            self.root,
            item_a={"pid": 1, "name": "a", "path": "C:\\a"},
            item_b={"pid": 1, "name": "b", "path": "C:\\a"},
        )
        self.assertEqual(win.differences, ["name"])

    def test_differences_empty_when_identical(self):
        win = DiffWindow(
            self.root,
            item_a={"pid": 1, "name": "x"},
            item_b={"pid": 1, "name": "x"},
        )
        self.assertEqual(win.differences, [])
        self.assertIn("identical", win._summary().lower())

    def test_summary_per_kind_registry(self):
        win = DiffWindow(
            self.root,
            item_a={"Value": "1", "Permissions": "DACL-A", "Exists": True},
            item_b={"Value": "2", "Permissions": "DACL-B", "Exists": True},
            kind="registry",
        )
        text = win._summary()
        self.assertIn("value", text.lower())
        self.assertIn("permissions", text.lower())

    def test_summary_per_kind_file(self):
        win = DiffWindow(
            self.root,
            item_a={"size_bytes": 100, "mtime": "2026-01-01"},
            item_b={"size_bytes": 200, "mtime": "2026-01-01"},
            kind="file",
        )
        text = win._summary().lower()
        self.assertIn("size", text)
        self.assertNotIn("timestamp", text)

    def test_set_items_replaces(self):
        win = DiffWindow(
            self.root,
            item_a={"k": 1},
            item_b={"k": 1},
        )
        win.set_items({"pid": 5, "name": "a"}, {"pid": 6, "name": "a"})
        self.assertEqual(win.differences, ["pid"])

    def test_diff_only_toggle_hides_matching_rows(self):
        win = DiffWindow(
            self.root,
            item_a={"pid": 1, "name": "a"},
            item_b={"pid": 2, "name": "a"},
        )
        win._diff_only_var.set(True)
        win._refresh()
        inner = win._tree_a._inner_tree  # type: ignore[attr-defined]
        a_keys = [
            inner.item(i, "values")[0]
            for i in inner.get_children()
        ]
        self.assertEqual(a_keys, ["pid"])

    def test_esc_binding_present(self):
        win = DiffWindow(self.root)
        bindings = win.bind("<Escape>")
        self.assertTrue(bindings, "<Escape> must be bound")
        win.destroy()


if __name__ == "__main__":
    unittest.main()