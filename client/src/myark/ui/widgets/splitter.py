"""A draggable ``ttk.PanedWindow`` subclass that remembers its sash position.

The main window is split three ways (left / center / right) and we want the
relative sash offsets to survive across restarts. ``MyArkSplitter`` keeps a
config dict and persists every sash move via the ``on_change`` callback so
``MainWindow`` can stash the positions in ``~/.myark/ui-state.json``.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional


class MyArkSplitter(ttk.PanedWindow):
    """Three-pane horizontal splitter with persisted sash positions."""

    def __init__(
        self,
        parent: tk.Misc,
        *,
        orient: str = "horizontal",
        on_change: Optional[Callable[[list[int]], None]] = None,
    ):
        super().__init__(parent, orient=orient)
        self._on_change = on_change
        # ttk.PanedWindow fires a <ButtonRelease-1> on the sash handle; bind
        # on the widget itself since child binding isn't reliable across themes.
        self.bind("<ButtonRelease-1>", self._handle_sash_release, add="+")

    def add_pane(self, child: tk.Widget, *, weight: int = 1) -> None:
        # ``ttk.PanedWindow`` on the Tk version bundled with Python 3.14 only
        # accepts ``weight`` / ``sticky`` / ``padx`` / ``pady`` per pane -- the
        # older ``minsize`` option is not recognised here. The weight is what
        # controls how the panes share leftover space, which is what we want.
        self.add(child, weight=weight)

    def current_sash_positions(self) -> list[int]:
        try:
            return list(self.sashpos(0) if self.orient == "horizontal" else self.sashpos(0))
        except tk.TclError:
            return []

    def restore_sash_positions(self, positions: list[int]) -> None:
        if not positions:
            return
        try:
            self.sashpos(0, int(positions[0]))
        except (tk.TclError, IndexError, ValueError):
            pass

    def _handle_sash_release(self, _event: tk.Event) -> None:
        if self._on_change is None:
            return
        try:
            positions = self.current_sash_positions()
        except tk.TclError:
            return
        if positions:
            self._on_change(positions)


__all__ = ["MyArkSplitter"]