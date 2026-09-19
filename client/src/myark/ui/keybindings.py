"""Global key bindings for the MyArk main window + popup chain.

S9.2 adds four shortcuts on top of the S9.1 ``Ctrl+P`` / ``Ctrl+Shift+F``
/ ``F5`` bindings:

* ``F1`` -- open the help window (currently a placeholder dialog; the
  full help page is rendered in the dialog's ``Text`` widget);
* ``Ctrl+Tab`` -- cycle focus between the main window and the most
  recent popup. The most-recent popup is tracked on a per-window
  basis through ``register_toplevel`` / ``focus_next``.
* ``Ctrl+W`` -- close the focused popup if one exists; otherwise a
  no-op (the main window ignores ``Ctrl+W`` so users do not lose work
  by accident);
* ``F5`` (already bound by S9.1) is re-bound to call the main window's
  :meth:`refresh` hook.

The :func:`bind_keys` helper takes a main window + an optional help
factory and wires all four shortcuts. The main window registers
itself with ``register_toplevel`` whenever it spawns a popup.
"""

from __future__ import annotations

import tkinter as tk
from typing import Callable, Optional


# Public key constants so tests / callers do not have to hard-code the
# exact Tk binding strings.
KEY_F1 = "F1"
KEY_F5 = "F5"
KEY_CTRL_TAB = "Control-Tab"
KEY_CTRL_SHIFT_TAB = "Control-Shift-Tab"
KEY_CTRL_W = "Control-w"
KEY_CTRL_SHIFT_H = "Control-Shift-H"

ALL_POPUP_KEYS = (KEY_F1, KEY_F5, KEY_CTRL_TAB, KEY_CTRL_W)


def bind_keys(
    master: tk.Misc,
    *,
    on_f1: Optional[Callable[[], None]] = None,
    on_f5: Optional[Callable[[], None]] = None,
    on_ctrl_tab: Optional[Callable[[bool], None]] = None,
    on_ctrl_w: Optional[Callable[[], None]] = None,
) -> dict[str, str]:
    """Wire the four S9.2 shortcuts on ``master``.

    Returns the bindings dict (key -> Tk binding script) so callers
    can inspect / unbind without remembering the literal sequences.
    """
    bindings: dict[str, str] = {}

    def _f1(_event: tk.Event = None) -> str:
        if on_f1 is not None:
            try:
                on_f1()
            except Exception:
                pass
        return "break"

    def _f5(_event: tk.Event = None) -> str:
        if on_f5 is not None:
            try:
                on_f5()
            except Exception:
                pass
        return "break"

    def _ctrl_tab(event: tk.Event = None) -> str:
        shift = bool(event and (event.state & 0x1))
        if on_ctrl_tab is not None:
            try:
                on_ctrl_tab(shift)
            except Exception:
                pass
        return "break"

    def _ctrl_w(_event: tk.Event = None) -> str:
        if on_ctrl_w is not None:
            try:
                on_ctrl_w()
            except Exception:
                pass
        return "break"

    master.bind(KEY_F1, _f1)
    master.bind(KEY_F5, _f5)
    master.bind(KEY_CTRL_TAB, _ctrl_tab)
    master.bind(KEY_CTRL_SHIFT_TAB, _ctrl_tab)
    master.bind(KEY_CTRL_W, _ctrl_w)

    bindings[KEY_F1] = master.bind(KEY_F1)
    bindings[KEY_F5] = master.bind(KEY_F5)
    bindings[KEY_CTRL_TAB] = master.bind(KEY_CTRL_TAB)
    bindings[KEY_CTRL_W] = master.bind(KEY_CTRL_W)
    return bindings


class PopupStack:
    """Track the chain of open popups so ``Ctrl+Tab`` / ``Ctrl+W``
    can cycle focus or close the active one.

    The main window owns one :class:`PopupStack`. Each time it creates
    a :class:`tk.Toplevel` child, it calls :meth:`register` with the
    new window. ``Ctrl+Tab`` moves focus to the most-recently-registered
    popup (or back to the master if no popups are open). ``Ctrl+W``
    destroys the focused popup -- or, if focus is on the master and a
    popup is open, the most-recent one.
    """

    def __init__(self, master: tk.Misc) -> None:
        self._master = master
        self._popups: list[tk.Toplevel] = []

    def register(self, popup: tk.Toplevel) -> None:
        """Add ``popup`` to the focus chain. Duplicates are skipped."""
        if popup in self._popups:
            return
        self._popups.append(popup)
        popup.bind("<Destroy>", lambda _e, p=popup: self._on_destroy(p), add="+")

    def _on_destroy(self, popup: tk.Toplevel) -> None:
        try:
            self._popups.remove(popup)
        except ValueError:
            pass

    @property
    def popups(self) -> list[tk.Toplevel]:
        """Return the current focus chain (most-recent last)."""
        return list(self._popups)

    def focus_next(self, reverse: bool = False) -> None:
        """Move focus to the next popup in the chain.

        If no popups are open, focus returns to the master window.
        ``reverse=True`` walks the chain in the opposite order
        (``Ctrl+Shift+Tab``).
        """
        popups = list(self._popups)
        if reverse:
            popups.reverse()
        # Filter out any destroyed popups that are still on the list.
        popups = [p for p in popups if bool(p.winfo_exists())]
        if not popups:
            try:
                self._master.focus_set()
            except tk.TclError:
                pass
            return
        target = popups[-1]
        try:
            target.focus_force()
            target.lift()
        except tk.TclError:
            pass

    def close_top(self) -> bool:
        """Destroy the most-recent popup. ``False`` if none are open."""
        popups = [p for p in self._popups if bool(p.winfo_exists())]
        if not popups:
            return False
        target = popups[-1]
        try:
            target.destroy()
        except tk.TclError:
            pass
        return True


__all__ = [
    "KEY_F1",
    "KEY_F5",
    "KEY_CTRL_TAB",
    "KEY_CTRL_SHIFT_TAB",
    "KEY_CTRL_W",
    "KEY_CTRL_SHIFT_H",
    "ALL_POPUP_KEYS",
    "bind_keys",
    "PopupStack",
]