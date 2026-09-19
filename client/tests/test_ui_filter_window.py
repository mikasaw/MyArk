"""Tests for :mod:`myark.ui.widgets.filter_window`.

The filter builder is a Toplevel popup that emits an
:class:`AdvancedFilter`. We cover the form's data assembly (name regex
toggle, size/date ranges, permission flags) and the lifecycle (Esc to
cancel, Apply to commit) without driving the Tk event loop directly.

Tk-root sharing
---------------
All Tk-using tests share a single ``tk.Tk()`` root via the module-level
``_shared_root`` helper. See ``test_ui_detail_window`` for the rationale.
"""

from __future__ import annotations

import os
import tkinter as tk
import unittest

from myark.ui.search.adv_search_panel import AdvancedFilter
from myark.ui.search.matcher import MatchMode
from myark.ui.widgets.filter_window import DEFAULT_TITLE, FilterWindow


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
class TestFilterWindow(unittest.TestCase):
    def setUp(self) -> None:
        if not HARNESS_HAS_TK:
            self.skipTest("no Tk display available")
        self.root = _shared_root()
        _purge_children(self.root)

    def tearDown(self) -> None:
        _purge_children(self.root)

    # ----- lifecycle

    def test_open_and_close(self):
        win = FilterWindow(self.root)
        self.assertIsInstance(win, tk.Toplevel)
        self.assertTrue(bool(win.winfo_exists()))
        win.destroy()
        self.assertFalse(bool(win.winfo_exists()))

    def test_default_title_fallback(self):
        win = FilterWindow(self.root)
        self.assertEqual(win.title(), DEFAULT_TITLE)

    def test_esc_cancels(self):
        win = FilterWindow(self.root)
        self.assertTrue(bool(win.bind("<Escape>")))
        # Esc cancels and clears result; we test the cancel handler
        # directly because synthetic events are unreliable headless.
        win._cancel()
        self.assertFalse(bool(win.winfo_exists()))
        self.assertIsNone(win.result)

    # ----- form assembly

    def test_build_filter_empty(self):
        win = FilterWindow(self.root)
        flt = win.build_filter()
        self.assertFalse(flt.is_active())

    def test_build_filter_with_name_and_size(self):
        win = FilterWindow(self.root)
        win._name_var.set("python")
        win._size_min_var.set("1024")
        win._size_max_var.set("2048")
        flt = win.build_filter()
        self.assertTrue(flt.is_active())
        self.assertEqual(flt._fields.get("name"), "python")
        self.assertEqual(flt._ranges.get("size"), (1024, 2048))

    def test_build_filter_invalid_size_coerced_to_none(self):
        win = FilterWindow(self.root)
        win._size_min_var.set("not-a-number")
        flt = win.build_filter()
        # Invalid integer input is treated as ``None``; the range is
        # therefore not added to the filter.
        self.assertNotIn("size", flt._ranges)

    def test_build_filter_with_permissions(self):
        win = FilterWindow(self.root)
        win._read_var.set(True)
        win._write_var.set(True)
        flt = win.build_filter()
        self.assertEqual(
            flt._fields.get("permissions"),
            "readable,writable",
        )

    def test_build_filter_with_year_range(self):
        win = FilterWindow(self.root)
        win._date_min_var.set("2020")
        win._date_max_var.set("2025")
        flt = win.build_filter()
        self.assertEqual(flt._ranges.get("year"), (2020, 2025))

    def test_validate_regex_rejects_invalid(self):
        win = FilterWindow(self.root)
        win._regex_var.set(True)
        win._name_var.set("[unclosed")
        self.assertIsNotNone(win.validate_regex())

    def test_validate_regex_accepts_valid(self):
        win = FilterWindow(self.root)
        win._regex_var.set(True)
        win._name_var.set(r"^foo\d+$")
        self.assertIsNone(win.validate_regex())

    def test_populate_from_initial(self):
        initial = AdvancedFilter(
            fields={"name": "py", "permissions": "readable"},
            ranges={"size": (10, 100)},
            mode=MatchMode.SUBSTRING,
        )
        win = FilterWindow(self.root, initial=initial)
        self.assertEqual(win._name_var.get(), "py")
        self.assertTrue(win._read_var.get())
        self.assertFalse(win._write_var.get())
        self.assertEqual(win._size_min_var.get(), "10")
        self.assertEqual(win._size_max_var.get(), "100")

    def test_apply_emits_filter_and_calls_callback(self):
        received: dict = {}
        def _cb(flt):
            received["flt"] = flt
        win = FilterWindow(self.root, on_apply=_cb)
        win._name_var.set("x")
        win._apply()
        self.assertIsInstance(received["flt"], AdvancedFilter)
        self.assertEqual(received["flt"]._fields.get("name"), "x")
        self.assertIsNotNone(win.result)
        self.assertFalse(bool(win.winfo_exists()))


if __name__ == "__main__":
    unittest.main()