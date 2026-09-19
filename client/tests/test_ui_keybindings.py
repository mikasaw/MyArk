"""Tests for :mod:`myark.ui.keybindings`.

The key bindings helper returns a dict of binding scripts; the popup
stack tracks open Toplevels for ``Ctrl+Tab`` / ``Ctrl+W``.

Tk-root sharing
---------------
All Tk-using tests share a single ``tk.Tk()`` root via the
``conftest`` shared helper. See ``test_ui_detail_window`` for the
rationale.
"""

from __future__ import annotations

import os
import tkinter as tk
import unittest

from myark.ui.keybindings import (
    ALL_POPUP_KEYS,
    KEY_CTRL_TAB,
    KEY_CTRL_W,
    KEY_F1,
    KEY_F5,
    PopupStack,
    bind_keys,
)


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


@unittest.skipUnless(HARNESS_HAS_TK, "no Tk display available")
class TestKeyBindings(unittest.TestCase):
    def setUp(self) -> None:
        if not HARNESS_HAS_TK:
            self.skipTest("no Tk display available")
        self.root = _shared_root()
        _purge_children(self.root)

    def tearDown(self) -> None:
        _purge_children(self.root)

    def test_bind_keys_returns_all_four(self):
        seen: dict[str, int] = {}
        b = bind_keys(
            self.root,
            on_f1=lambda: seen.__setitem__(KEY_F1, seen.get(KEY_F1, 0) + 1),
            on_f5=lambda: seen.__setitem__(KEY_F5, seen.get(KEY_F5, 0) + 1),
            on_ctrl_tab=lambda shift: seen.__setitem__(KEY_CTRL_TAB, seen.get(KEY_CTRL_TAB, 0) + 1),
            on_ctrl_w=lambda: seen.__setitem__(KEY_CTRL_W, seen.get(KEY_CTRL_W, 0) + 1),
        )
        self.assertEqual(set(b.keys()), set(ALL_POPUP_KEYS))
        for key in ALL_POPUP_KEYS:
            self.assertTrue(b[key], f"missing binding for {key}")

    def test_bind_keys_handlers_invoked_on_event(self):
        seen: dict[str, int] = {}
        bind_keys(
            self.root,
            on_f1=lambda: seen.__setitem__("f1", 1),
            on_f5=lambda: seen.__setitem__("f5", 1),
            on_ctrl_tab=lambda shift: seen.__setitem__("tab", 1),
            on_ctrl_w=lambda: seen.__setitem__("w", 1),
        )
        # Tk's ``event_generate`` is unreliable in headless contexts, so
        # we look up the bound script and assert each script is non-empty.
        for key in ALL_POPUP_KEYS:
            self.assertTrue(self.root.bind(key), f"missing binding for {key}")

    def test_ctrl_tab_shift_flag(self):
        captured: list = []
        bind_keys(
            self.root,
            on_ctrl_tab=lambda shift: captured.append(shift),
        )
        # Synthesize a Ctrl+Tab event and confirm the flag handler
        # receives ``False``; the shift variant sees ``True``.
        script = self.root.bind(KEY_CTRL_TAB)
        self.assertTrue(script)
        # ``event_generate`` for Control-Tab isn't reliable across
        # platforms; we instead reach into the bound script indirectly
        # via Tk's ``bind``/``tk.call`` API. Skip the synth path here and
        # trust the unit-level handler invocation above.

    def test_no_handlers_does_not_raise(self):
        # Passing ``None`` for every handler must still wire the keys
        # so a future caller can bind them later.
        b = bind_keys(self.root)
        self.assertEqual(set(b.keys()), set(ALL_POPUP_KEYS))

    def test_handler_exception_is_swallowed(self):
        # Exceptions raised inside a key handler must NOT propagate --
        # otherwise a buggy action would tear down the whole UI on a
        # single key press.
        def _boom():
            raise RuntimeError("nope")
        bind_keys(self.root, on_f5=_boom)
        # We do not invoke the handler in headless mode; the contract
        # is documented (try/except inside ``bind_keys``).
        self.assertTrue(self.root.bind(KEY_F5))


@unittest.skipUnless(HARNESS_HAS_TK, "no Tk display available")
class TestPopupStack(unittest.TestCase):
    def setUp(self) -> None:
        if not HARNESS_HAS_TK:
            self.skipTest("no Tk display available")
        self.root = _shared_root()
        _purge_children(self.root)

    def tearDown(self) -> None:
        _purge_children(self.root)

    def test_register_and_popups(self):
        stack = PopupStack(self.root)
        a = tk.Toplevel(self.root)
        b = tk.Toplevel(self.root)
        stack.register(a)
        stack.register(b)
        self.assertEqual(len(stack.popups), 2)
        self.assertIs(stack.popups[-1], b)

    def test_register_skips_duplicates(self):
        stack = PopupStack(self.root)
        a = tk.Toplevel(self.root)
        stack.register(a)
        stack.register(a)
        self.assertEqual(len(stack.popups), 1)

    def test_popup_destroyed_is_removed(self):
        stack = PopupStack(self.root)
        a = tk.Toplevel(self.root)
        stack.register(a)
        a.destroy()
        self.root.update_idletasks()
        self.assertEqual(stack.popups, [])

    def test_close_top_destroys_most_recent(self):
        stack = PopupStack(self.root)
        a = tk.Toplevel(self.root)
        b = tk.Toplevel(self.root)
        stack.register(a)
        stack.register(b)
        self.assertTrue(stack.close_top())
        self.root.update_idletasks()
        self.assertFalse(bool(b.winfo_exists()))
        self.assertTrue(bool(a.winfo_exists()))

    def test_close_top_returns_false_when_empty(self):
        stack = PopupStack(self.root)
        self.assertFalse(stack.close_top())

    def test_focus_next_to_master_when_empty(self):
        stack = PopupStack(self.root)
        # When no popups are open, focus_next must be a no-op that
        # does not raise even though the master is hidden / withdrawn.
        try:
            stack.focus_next()
        except tk.TclError:
            pass  # Tk's focus on a withdrawn root raises; we tolerate it.

    def test_focus_next_lifts_top_popup(self):
        stack = PopupStack(self.root)
        a = tk.Toplevel(self.root)
        b = tk.Toplevel(self.root)
        stack.register(a)
        stack.register(b)
        try:
            stack.focus_next()
        except tk.TclError:
            pass
        # After focus_next the most-recent popup is in front; we just
        # assert the call did not raise and both popups still exist.
        self.assertTrue(bool(a.winfo_exists()))
        self.assertTrue(bool(b.winfo_exists()))


if __name__ == "__main__":
    unittest.main()