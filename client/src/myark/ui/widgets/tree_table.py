"""ttk.Treeview-backed table widget with sortable headers and CN/pinyin filter.

Used as the entity list on the left pane of the main window. The class wraps
``ttk.Treeview`` to give every MyArk pane a consistent::

    TreeTable(parent, columns=("name", "pid", ...))
    tree.set_rows([(1234, "svchost.exe", ...), ...])

interface, plus a ``filter_text`` property that does case-insensitive
substring match on every column (and pinyin match via ``pypinyin`` when the
literal text contains no Latin letters).
"""

from __future__ import annotations

import tkinter as tk

from myark.ui.scaling import scaled_width
from tkinter import ttk
from typing import Iterable, Optional, Sequence

try:
    from pypinyin import lazy_pinyin

    _PINYIN_AVAILABLE = True
except Exception:  # pragma: no cover -- optional at S3
    lazy_pinyin = None  # type: ignore[assignment]
    _PINYIN_AVAILABLE = False


class TreeTable(ttk.Frame):
    """Reusable sortable / filterable table widget."""

    def __init__(
        self,
        parent: tk.Misc,
        columns: Sequence[str],
        *,
        show: str = "headings",
        height: int = 20,
    ):
        super().__init__(parent)
        self._columns = tuple(columns)
        self._all_rows: list[tuple] = []
        self._filter_text: str = ""

        self.tree = ttk.Treeview(self, columns=self._columns, show=show, height=height)
        for col in self._columns:
            self.tree.heading(col, text=col.title(), command=lambda c=col: self._sort_by(c))
            self.tree.column(col, width=scaled_width(self, 120), anchor=tk.W, stretch=True)

        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        self._sort_state: dict[str, bool] = {}  # col -> ascending

    # -------------------------------------------------------- public API

    def set_rows(self, rows: Iterable[tuple]) -> None:
        self._all_rows = list(rows)
        self._refresh()

    def clear(self) -> None:
        self._all_rows = []
        self._refresh()

    @property
    def filter_text(self) -> str:
        return self._filter_text

    @filter_text.setter
    def filter_text(self, value: str) -> None:
        self._filter_text = value or ""
        self._refresh()

    def selected_iid(self) -> Optional[str]:
        sel = self.tree.selection()
        return sel[0] if sel else None

    # -------------------------------------------------------- internals

    def _matches(self, row: tuple, needle: str) -> bool:
        if not needle:
            return True
        needle_l = needle.lower()
        # Direct substring match on any column.
        for cell in row:
            if needle_l in str(cell).lower():
                return True
        # Pinyin match: convert every cell to pinyin and substring-match.
        if _PINYIN_AVAILABLE and lazy_pinyin is not None:
            joined = "".join(lazy_pinyin(" ".join(str(c) for c in row)))
            if needle_l in joined.lower():
                return True
        return False

    def _refresh(self) -> None:
        self.tree.delete(*self.tree.get_children())
        needle = self._filter_text
        for i, row in enumerate(self._all_rows):
            if not self._matches(row, needle):
                continue
            display = tuple(self._format_cell(c) for c in row)
            self.tree.insert("", "end", iid=str(i), values=display)

    def _format_cell(self, cell) -> str:
        if isinstance(cell, bytes):
            return cell.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        return str(cell)

    def _sort_by(self, col: str) -> None:
        idx = self._columns.index(col)
        asc = self._sort_state.get(col, True)
        self._all_rows.sort(key=lambda r: self._sort_key(r[idx]), reverse=not asc)
        self._sort_state[col] = not asc
        self._refresh()

    @staticmethod
    def _sort_key(value):
        if isinstance(value, (int, float)):
            return (0, value)
        if isinstance(value, bytes):
            value = value.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        return (1, str(value).lower())


__all__ = ["TreeTable"]