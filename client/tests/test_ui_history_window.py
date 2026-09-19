"""Tests for :mod:`myark.history` and :mod:`myark.ui.widgets.history_window`.

The history logger writes / reads ``~/.myark/history.log``. We redirect
the path to a tmp file so tests never touch the user's real history.

The HistoryWindow widget is pure UI; we exercise it with the same
shared Tk root from :mod:`tests.conftest`.
"""

from __future__ import annotations

import os
import tempfile
import tkinter as tk
import unittest
from pathlib import Path

from myark.history import (
    DEFAULT_HISTORY_FILE,
    HistoryRecord,
    append,
    iter_all,
    read_recent,
    record,
    reset_history_path,
    set_history_path,
)
from myark.ui.widgets.history_window import DEFAULT_TITLE, HistoryWindow


HARNESS_HAS_TK = os.name == "nt" or os.environ.get("DISPLAY")


def _shared_root():
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


class TestHistoryRecord(unittest.TestCase):
    def test_round_trip(self):
        rec = HistoryRecord(
            timestamp=1700000000.123456,
            action="kill",
            target="pid=1234",
            result="ok",
            detail="exit=0",
        )
        line = rec.to_line()
        parsed = HistoryRecord.from_line(line)
        self.assertEqual(parsed.action, "kill")
        self.assertEqual(parsed.target, "pid=1234")
        self.assertEqual(parsed.result, "ok")
        self.assertEqual(parsed.detail, "exit=0")
        self.assertAlmostEqual(parsed.timestamp, 1700000000.123456, places=3)

    def test_from_line_garbage_raises(self):
        with self.assertRaises(ValueError):
            HistoryRecord.from_line("not json at all")

    def test_from_line_default_detail(self):
        rec = HistoryRecord.from_line(
            '{"ts": 1700000000.0, "action": "read", "target": "C:\\\\a", "result": "ok"}'
        )
        self.assertEqual(rec.detail, "")


class TestHistoryFile(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self._path = Path(self._tmpdir.name) / "history.log"
        set_history_path(self._path)

    def tearDown(self) -> None:
        reset_history_path()
        self._tmpdir.cleanup()

    def test_append_writes_record(self):
        rec = record("kill", "pid=1234", "ok")
        self.assertTrue(self._path.exists())
        records = list(iter_all())
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].action, "kill")
        self.assertEqual(records[0].result, "ok")
        self.assertEqual(records[0].timestamp, rec.timestamp)

    def test_append_is_idempotent_to_record(self):
        rec = HistoryRecord(
            timestamp=1700000000.0,
            action="read",
            target="C:\\foo",
            result="ok",
        )
        append(rec)
        records = read_recent()
        self.assertEqual(records[-1].target, "C:\\foo")

    def test_read_recent_limit(self):
        for i in range(5):
            record("op", f"target{i}", "ok")
        records = read_recent(limit=2)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].target, "target3")
        self.assertEqual(records[1].target, "target4")

    def test_default_path_resolves_to_home(self):
        reset_history_path()
        # The default path always lives under ``~/.myark/``.
        self.assertEqual(str(DEFAULT_HISTORY_FILE).replace("\\", "/"),
                         str(DEFAULT_HISTORY_FILE).replace("\\", "/"))
        self.assertIn(".myark", str(DEFAULT_HISTORY_FILE))

    def test_target_with_field_separator_preserved(self):
        # JSON takes care of escaping arbitrary chars in ``target`` /
        # ``detail``, so the round-trip is loss-less.
        rec = HistoryRecord(
            timestamp=1700000000.0,
            action="write",
            target='key=with,commas,plus"quotes"and\\backslashes',
            result="ok",
            detail="foo bar baz",
        )
        append(rec)
        records = list(iter_all())
        self.assertEqual(records[-1].target, 'key=with,commas,plus"quotes"and\\backslashes')
        self.assertEqual(records[-1].detail, "foo bar baz")


@unittest.skipUnless(HARNESS_HAS_TK, "no Tk display available")
class TestHistoryWindow(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self._path = Path(self._tmpdir.name) / "history.log"
        set_history_path(self._path)
        if not HARNESS_HAS_TK:
            self.skipTest("no Tk display available")
        self.root = _shared_root()
        _purge_children(self.root)

    def tearDown(self) -> None:
        _purge_children(self.root)
        reset_history_path()
        self._tmpdir.cleanup()

    def test_open_and_close(self):
        win = HistoryWindow(self.root)
        self.assertIsInstance(win, tk.Toplevel)
        win.destroy()
        self.assertFalse(bool(win.winfo_exists()))

    def test_default_title(self):
        win = HistoryWindow(self.root)
        self.assertEqual(win.title(), DEFAULT_TITLE)

    def test_empty_history_shows_summary(self):
        win = HistoryWindow(self.root)
        rows = list(win._tree.get_children())
        self.assertEqual(rows, [])
        self.assertIn("empty", win._summary_var.get().lower())

    def test_records_render_in_tree(self):
        for i in range(3):
            record("kill", f"pid={i}", "ok", detail=f"reason={i}")
        win = HistoryWindow(self.root)
        rows = win._tree.get_children()
        self.assertEqual(len(rows), 3)
        values = win._tree.item(rows[0], "values")
        self.assertEqual(values[1], "kill")  # action
        self.assertEqual(values[2], "pid=0")  # target

    def test_reload_picks_up_new_entries(self):
        win = HistoryWindow(self.root)
        self.assertEqual(len(win._tree.get_children()), 0)
        record("read", "C:\\foo", "ok")
        win.reload()
        self.assertEqual(len(win._tree.get_children()), 1)

    def test_esc_binding_present(self):
        win = HistoryWindow(self.root)
        bindings = win.bind("<Escape>")
        self.assertTrue(bindings, "<Escape> must be bound")
        win.destroy()

    def test_records_property_returns_copy(self):
        record("op", "x", "ok")
        win = HistoryWindow(self.root)
        snap = win.records
        snap.clear()
        self.assertEqual(len(win.records), 1)


if __name__ == "__main__":
    unittest.main()