"""Unit tests for the MyArk three-layer search package.

The search layer is pure-Python on top of Tkinter + pypinyin. We import
the modules directly and avoid driving the Tk main loop: most tests only
exercise the matcher / filter / index logic, with a single headless
``Toplevel`` smoke at the end to make sure the palette and the
advanced-search panel still instantiate when Tk is available.

Tk is skipped on a non-interactive build (CI without a display) by
guarding the smoke test with the ``HARNESS_HAS_TK`` flag we set inside
``setUp``. Tests that need a display should still pass on Windows.
"""

from __future__ import annotations

import os
import unittest

from myark.ui.search import (
    AdvancedFilter,
    MatchMode,
    SearchEntry,
    build_index,
    match,
    match_any,
    pinyin_key,
)
from myark.ui.search.index_builder import _COLLECTORS
from myark.ui.search.matcher import _PINYIN


HARNESS_HAS_TK = os.name == "nt" or os.environ.get("DISPLAY")


class TestMatcher(unittest.TestCase):
    """Five match modes: exact / prefix / substring / pinyin / regex."""

    def test_empty_query_matches_everything(self):
        self.assertTrue(match("", "anything"))
        self.assertTrue(match("   ", "anything"))

    def test_substring_case_insensitive(self):
        self.assertTrue(match("FOO", "foobar"))
        self.assertTrue(match("oob", "foobar"))
        self.assertFalse(match("baz", "foobar"))

    def test_prefix_mode(self):
        self.assertTrue(match("foo", "foobar", MatchMode.PREFIX))
        self.assertFalse(match("bar", "foobar", MatchMode.PREFIX))

    def test_exact_mode(self):
        # EXACT is case-insensitive for consistency with substring / prefix
        # / pinyin modes -- the user-visible "exact" semantics is "whole
        # string equal after normalisation" (query is stripped of leading
        # / trailing whitespace).
        self.assertTrue(match("Foobar", "Foobar", MatchMode.EXACT))
        self.assertTrue(match("FOOBAR", "Foobar", MatchMode.EXACT))
        self.assertTrue(match("Foobar  ", "Foobar", MatchMode.EXACT))
        self.assertFalse(match("foo", "Foobar", MatchMode.EXACT))
        self.assertFalse(match("FoobarX", "Foobar", MatchMode.EXACT))

    def test_regex_mode(self):
        self.assertTrue(match(r"^foo", "foobar", MatchMode.REGEX))
        self.assertTrue(match(r"\d+", "abc 42", MatchMode.REGEX))
        # Invalid regex -> no match, no raise.
        self.assertFalse(match(r"[unclosed", "foobar", MatchMode.REGEX))

    def test_pinyin_mode_chinese(self):
        # Always works even without pypinyin (falls back to substring).
        self.assertTrue(match("进程", "进程", MatchMode.PINYIN))
        if _PINYIN is not None:
            self.assertTrue(match("jc", "进程", MatchMode.PINYIN))
            self.assertTrue(match("jincheng", "进程", MatchMode.PINYIN))

    def test_pinyin_key_initial_letters(self):
        if _PINYIN is None:
            self.skipTest("pypinyin not installed")
        # '进程' -> full 'jincheng' + initials 'jc'
        key = pinyin_key("进程")
        self.assertIn("jincheng", key)
        self.assertIn("jc", key)

    def test_match_any(self):
        self.assertTrue(
            match_any("xyz", ["alpha", "beta", "xyzz"], MatchMode.SUBSTRING)
        )
        self.assertFalse(
            match_any("xyz", ["alpha", "beta"], MatchMode.SUBSTRING)
        )
        self.assertTrue(match_any("", ["a"], MatchMode.SUBSTRING))


class TestSearchEntry(unittest.TestCase):
    def test_matches_primary(self):
        e = SearchEntry(module="process", kind="row", primary="svchost.exe")
        self.assertTrue(e.matches("svch", MatchMode.PREFIX))
        self.assertFalse(e.matches("cmd", MatchMode.SUBSTRING))

    def test_matches_description(self):
        e = SearchEntry(
            module="process",
            kind="row",
            primary="x",
            description="windows subsystem",
        )
        self.assertTrue(e.matches("subsystem", MatchMode.SUBSTRING))

    def test_matches_field(self):
        e = SearchEntry(
            module="process",
            kind="row",
            primary="x",
            fields=["1024", "560"],
        )
        self.assertTrue(e.matches("1024", MatchMode.SUBSTRING))


class TestIndexBuilder(unittest.TestCase):
    def test_build_index_process_at_least_one_entry(self):
        # R3 enum_processes can return at least the current process.
        idx = build_index(modules=["process"])
        names = {e.module for e in idx}
        self.assertIn("process", names)

    def test_build_index_module_kind_present(self):
        idx = build_index(modules=["process"])
        kinds = {e.kind for e in idx}
        self.assertIn("module", kinds)
        self.assertIn("row", kinds)

    def test_build_index_dedupes(self):
        idx = build_index(modules=["process"])
        seen = {(e.module, e.primary) for e in idx}
        self.assertEqual(len(seen), len(idx))

    def test_build_index_unknown_module_safe(self):
        # Unknown module name should be silently ignored.
        idx = build_index(modules=["this_does_not_exist"])
        self.assertEqual(idx, [])

    def test_collectors_discover_known_modules(self):
        # 7 R3 modules + hello stub should be covered.
        self.assertGreaterEqual(len(_COLLECTORS), 7)


class TestAdvancedFilter(unittest.TestCase):
    def test_is_active_with_text(self):
        f = AdvancedFilter(
            fields={"name": "py", "path": ""},
            ranges={},
            mode=MatchMode.SUBSTRING,
        )
        self.assertTrue(f.is_active())

    def test_is_active_inactive(self):
        f = AdvancedFilter(
            fields={"name": "", "path": ""},
            ranges={},
            mode=MatchMode.SUBSTRING,
        )
        self.assertFalse(f.is_active())

    def test_is_active_with_range(self):
        f = AdvancedFilter(
            fields={},
            ranges={"pid": (100, None)},
            mode=MatchMode.SUBSTRING,
        )
        self.assertTrue(f.is_active())

    def test_matches_dict_text_field(self):
        f = AdvancedFilter(
            fields={"name": "py"},
            ranges={},
            mode=MatchMode.SUBSTRING,
        )
        self.assertTrue(f.matches({"name": "python.exe"}))
        self.assertFalse(f.matches({"name": "cmd.exe"}))

    def test_matches_dict_int_range(self):
        f = AdvancedFilter(
            fields={},
            ranges={"pid": (100, 200)},
            mode=MatchMode.SUBSTRING,
        )
        self.assertTrue(f.matches({"pid": 150}))
        self.assertFalse(f.matches({"pid": 50}))
        self.assertFalse(f.matches({"pid": 250}))
        # Missing key fails the range constraint (we cannot prove the
        # row's pid is in [100, 200]).
        self.assertFalse(f.matches({"other": "x"}))

    def test_matches_dict_invalid_int(self):
        f = AdvancedFilter(
            fields={},
            ranges={"pid": (100, None)},
            mode=MatchMode.SUBSTRING,
        )
        self.assertFalse(f.matches({"pid": "not-a-number"}))

    def test_describe_includes_active_terms(self):
        f = AdvancedFilter(
            fields={"name": "py"},
            ranges={"pid": (100, None)},
            mode=MatchMode.SUBSTRING,
        )
        desc = f.describe()
        self.assertIn("name~py", desc)
        self.assertIn("pid", desc)


class TestToplevelSmoke(unittest.TestCase):
    """Make sure the two Toplevel-based dialogs still instantiate."""

    def setUp(self):
        if not HARNESS_HAS_TK:
            self.skipTest("no Tk display available")
        from tests import conftest
        self.root = conftest.shared_tk_root()
        self._purge_children()
        self.addCleanup(self._purge_children)

    def _purge_children(self):
        try:
            for child in list(self.root.winfo_children()):
                try:
                    child.destroy()
                except tk.TclError:
                    pass
        except tk.TclError:
            pass

    def test_cmd_palette_instantiates(self):
        from myark.ui.search.cmd_palette import open_palette

        palette = open_palette(
            self.root,
            entries=[SearchEntry(module="process", kind="row", primary="x")],
        )
        self.root.update()
        self.assertTrue(palette.winfo_exists())
        palette.destroy()

    def test_adv_panel_instantiates(self):
        from myark.ui.search.adv_search_panel import open_panel

        panel = open_panel(self.root)
        self.root.update()
        self.assertTrue(panel.winfo_exists())
        panel.destroy()


if __name__ == "__main__":
    unittest.main()