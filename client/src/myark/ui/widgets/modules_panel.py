"""Sidebar widget listing every MyArk module and its enable state.

Two views are exposed:

* :class:`ModulesPanel` -- read-only Treeview listing the registered
  modules with a boolean ``enabled`` column. The model is the
  ``ModuleInfo`` objects returned by :class:`ModuleQuery.query_modules`.

The widget is intentionally lightweight: the driver has to be loaded for
the ``enabled`` bit to be meaningful, so when no driver is present the
column is hidden and every row shows ``(driver not installed)``.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Iterable, Optional

from .tree_table import TreeTable


MODULE_COLUMNS: tuple[str, ...] = ("module", "state")


class ModulesPanel(ttk.LabelFrame):
    """Top-of-window strip listing registered modules + their state."""

    def __init__(self, parent: tk.Misc):
        super().__init__(parent, text="Modules", padding=(4, 2))
        self._table = TreeTable(
            self,
            columns=MODULE_COLUMNS,
            height=8,
        )
        self._table.pack(fill=tk.BOTH, expand=True)

    def set_modules(self, modules: Iterable, *, registered: Optional[Iterable[str]] = None) -> None:
        """Refresh the table from a list of ``ModuleInfo`` rows.

        ``registered`` lets us also show in-tree modules whose driver
        counterpart is missing -- e.g. ``process`` / ``thread`` show
        "R3" even when the .sys is not loaded.
        """
        rows = []
        seen: set[str] = set()
        for m in modules:
            seen.add(m.name)
            rows.append((m.name, m.state))
        if registered is not None:
            for name in registered:
                if name in seen:
                    continue
                rows.append((name, "R3 only"))
        rows.sort()
        self._table.set_rows(rows)


__all__ = ["ModulesPanel", "MODULE_COLUMNS"]