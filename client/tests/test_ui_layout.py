"""Unit tests for the MyArk layout persistence layer.

The :mod:`myark.ui.layout` module is intentionally decoupled from
Tkinter so the tests run on every platform (including CI containers
without a display).
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from myark.ui.layout import (
    SCHEMA_VERSION,
    LayoutState,
    default_path,
    load_layout,
    save_layout,
)


class TestLayoutState(unittest.TestCase):
    def test_defaults(self):
        s = LayoutState()
        self.assertEqual(s.geometry, "")
        self.assertEqual(s.sash_positions, [])
        self.assertIsNone(s.active_module)
        self.assertIsNone(s.advanced_filter)


class TestRoundTrip(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = os.path.join(self._tmp.name, "sub", "layout.json")

    def test_full_roundtrip(self):
        s = LayoutState(
            geometry="1280x800+10+20",
            sash_positions=[240, 600],
            active_module="process",
            advanced_filter={
                "fields": {"name": "py"},
                "ranges": {"pid": [100, None]},
                "mode": "pinyin",
            },
        )
        save_layout(s, self.path)
        loaded = load_layout(self.path)
        self.assertEqual(loaded.geometry, s.geometry)
        self.assertEqual(loaded.sash_positions, s.sash_positions)
        self.assertEqual(loaded.active_module, s.active_module)
        self.assertEqual(loaded.advanced_filter, s.advanced_filter)

    def test_atomic_write_does_not_leave_tmp(self):
        save_layout(LayoutState(geometry="100x100"), self.path)
        leftover = [
            f for f in os.listdir(os.path.dirname(self.path))
            if f.startswith(".layout-")
        ]
        self.assertEqual(leftover, [])

    def test_schema_version_present(self):
        save_layout(LayoutState(), self.path)
        with open(self.path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data.get("schema_version"), SCHEMA_VERSION)


class TestFaultTolerance(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def test_missing_file_returns_defaults(self):
        path = os.path.join(self._tmp.name, "missing.json")
        s = load_layout(path)
        self.assertEqual(s.geometry, "")
        self.assertEqual(s.sash_positions, [])

    def test_garbage_file_returns_defaults(self):
        path = os.path.join(self._tmp.name, "bad.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        s = load_layout(path)
        self.assertEqual(s.geometry, "")

    def test_partial_file_partial_state(self):
        path = os.path.join(self._tmp.name, "partial.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"geometry": "800x600"}, fh)
        s = load_layout(path)
        self.assertEqual(s.geometry, "800x600")
        self.assertEqual(s.sash_positions, [])
        self.assertIsNone(s.active_module)


class TestDefaultPath(unittest.TestCase):
    def test_default_path_in_user_home(self):
        path = default_path()
        self.assertTrue(path.endswith("layout.json"))
        # Sanity: the user-home expansion should resolve to an absolute path.
        self.assertTrue(os.path.isabs(os.path.expanduser(path)))


if __name__ == "__main__":
    unittest.main()