"""Sidebar advanced-search dialog.

A modal Toplevel with one entry per searchable field plus optional numeric
ranges. The dialog emits a single :class:`AdvancedFilter` object on
``OK`` that the main window applies to whichever tab is active.

The fields are deliberately coarse -- process / thread / registry /
network / file all share ``name``, ``pid`` / ``tid``, ``path`` --
because the dialog's job is to narrow, not to expose every column. Each
field defaults to ``MatchMode.PINYIN`` so a Chinese query ("进程") still
hits ``process``.

The dialog is pure-R3 -- it does no IOCTLs and never touches the driver.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Optional

from .matcher import MatchMode


# Fields the user can fill in. ``kind`` is "text" (string match) or
# "int" (numeric range). The label is what shows in the dialog; ``key``
# is what the AdvancedFilter exposes for the caller's predicate.
FIELDS: tuple[dict, ...] = (
    {"key": "name",       "label": "Name",       "kind": "text", "default": ""},
    {"key": "pid",        "label": "PID",        "kind": "int",  "default": ""},
    {"key": "tid",        "label": "TID",        "kind": "int",  "default": ""},
    {"key": "path",       "label": "Path",       "kind": "text", "default": ""},
    {"key": "session_id", "label": "Session ID", "kind": "int",  "default": ""},
)


class AdvancedFilter:
    """Filter spec returned by :class:`AdvancedSearchPanel`.

    ``matches(row)`` is the predicate the caller applies to its row
    tuples. Empty fields mean "no constraint on this column".
    """

    def __init__(
        self,
        *,
        fields: dict[str, str],
        ranges: dict[str, tuple[Optional[int], Optional[int]]],
        mode: MatchMode,
    ) -> None:
        self._fields = fields
        self._ranges = ranges
        self._mode = mode

    @property
    def mode(self) -> MatchMode:
        return self._mode

    def is_active(self) -> bool:
        return any(v.strip() for v in self._fields.values()) or any(
            lo is not None or hi is not None for lo, hi in self._ranges.values()
        )

    def matches(self, row) -> bool:
        # Map row keys by index. The caller may pass either a tuple
        # (positional, the common case) or a dict.
        if isinstance(row, dict):
            return self._match_dict(row)
        return self._match_tuple(row)

    def _match_dict(self, row: dict) -> bool:
        from .matcher import match

        for key, value in self._fields.items():
            v = (value or "").strip()
            if not v:
                continue
            if key not in row:
                # The row doesn't carry this column -- it cannot
                # possibly satisfy the constraint, so fail fast.
                return False
            cell = row.get(key, "")
            if not match(v, str(cell), self._mode):
                return False
        for key, (lo, hi) in self._ranges.items():
            if lo is None and hi is None:
                continue
            if key not in row:
                return False
            cell = row.get(key, 0)
            try:
                cell_n = int(cell)
            except (TypeError, ValueError):
                return False
            if lo is not None and cell_n < lo:
                return False
            if hi is not None and cell_n > hi:
                return False
        return True

    def _match_tuple(self, row) -> bool:
        # When called with a positional tuple we just check text fields
        # against a flattened string form -- the caller can be more
        # precise by passing a dict.
        from .matcher import match

        for value in self._fields.values():
            v = (value or "").strip()
            if not v:
                continue
            if not any(match(v, str(cell), self._mode) for cell in row):
                return False
        return True

    def describe(self) -> str:
        bits = []
        for k, v in self._fields.items():
            if v.strip():
                bits.append(f"{k}~{v}")
        for k, (lo, hi) in self._ranges.items():
            if lo is not None or hi is not None:
                bits.append(f"{k}∈[{lo},{hi}]")
        return ",".join(bits) or "(no filter)"


class AdvancedSearchPanel(tk.Toplevel):
    """Modal dialog that produces an :class:`AdvancedFilter` on commit."""

    def __init__(
        self,
        master: tk.Misc,
        *,
        initial: Optional[AdvancedFilter] = None,
    ) -> None:
        super().__init__(master)
        self.title("Advanced Search")
        self.transient(master)
        self.resizable(False, False)

        self._result: Optional[AdvancedFilter] = None
        self._field_vars: dict[str, tk.StringVar] = {}
        self._range_lo_vars: dict[str, tk.StringVar] = {}
        self._range_hi_vars: dict[str, tk.StringVar] = {}
        self._mode_var = tk.StringVar(
            value=str(initial.mode.value) if initial else MatchMode.PINYIN.value
        )

        outer = ttk.Frame(self, padding=12)
        outer.pack(fill=tk.BOTH, expand=True)

        for i, spec in enumerate(FIELDS):
            ttk.Label(outer, text=f"{spec['label']}:", width=12, anchor=tk.W).grid(
                row=i, column=0, sticky=tk.W, pady=2
            )
            var = tk.StringVar(value=spec["default"])
            self._field_vars[spec["key"]] = var

            if spec["kind"] == "int":
                cell = ttk.Frame(outer)
                lo_var = tk.StringVar()
                hi_var = tk.StringVar()
                self._range_lo_vars[spec["key"]] = lo_var
                self._range_hi_vars[spec["key"]] = hi_var
                ttk.Label(cell, text="min:").pack(side=tk.LEFT)
                ttk.Entry(cell, textvariable=lo_var, width=10).pack(side=tk.LEFT, padx=(2, 6))
                ttk.Label(cell, text="max:").pack(side=tk.LEFT)
                ttk.Entry(cell, textvariable=hi_var, width=10).pack(side=tk.LEFT, padx=(2, 0))
                ttk.Label(cell, text="   or contains:").pack(side=tk.LEFT)
                ttk.Entry(cell, textvariable=var, width=14).pack(side=tk.LEFT, padx=(2, 0))
                cell.grid(row=i, column=1, sticky=tk.W + tk.E, pady=2)
            else:
                ttk.Entry(outer, textvariable=var, width=40).grid(
                    row=i, column=1, sticky=tk.W + tk.E, pady=2
                )

        # Mode selector
        mode_row = len(FIELDS) + 1
        ttk.Label(outer, text="Mode:", anchor=tk.W).grid(
            row=mode_row, column=0, sticky=tk.W, pady=(8, 2)
        )
        mode_frame = ttk.Frame(outer)
        mode_frame.grid(row=mode_row, column=1, sticky=tk.W, pady=(8, 2))
        for m in MatchMode:
            ttk.Radiobutton(
                mode_frame,
                text=m.value,
                value=m.value,
                variable=self._mode_var,
            ).pack(side=tk.LEFT, padx=2)

        # Buttons
        btn_row = mode_row + 1
        btns = ttk.Frame(outer)
        btns.grid(row=btn_row, column=0, columnspan=2, sticky=tk.E, pady=(10, 0))
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side=tk.RIGHT, padx=2)
        ttk.Button(btns, text="Apply",  command=self._apply).pack(side=tk.RIGHT, padx=2)
        ttk.Button(btns, text="Clear",  command=self._clear).pack(side=tk.RIGHT, padx=2)

        outer.columnconfigure(1, weight=1)

        self.bind("<Return>", lambda _e: self._apply())
        self.bind("<Escape>", lambda _e: self.destroy())
        self._center_over_master(master)

    # ---------------------------------------------------------- helpers

    def _center_over_master(self, master: tk.Misc) -> None:
        try:
            self.update_idletasks()
            mx = master.winfo_rootx()
            my = master.winfo_rooty()
            mw = master.winfo_width()
            mh = master.winfo_height()
            w = self.winfo_width()
            h = self.winfo_height()
            x = mx + (mw - w) // 2
            y = my + max(40, (mh - h) // 3)
            self.geometry(f"+{x}+{y}")
        except tk.TclError:
            pass

    def _clear(self) -> None:
        for var in self._field_vars.values():
            var.set("")
        for var in self._range_lo_vars.values():
            var.set("")
        for var in self._range_hi_vars.values():
            var.set("")

    def _apply(self) -> None:
        try:
            mode = MatchMode(self._mode_var.get())
        except ValueError:
            mode = MatchMode.SUBSTRING

        fields = {k: v.get() for k, v in self._field_vars.items()}
        ranges: dict[str, tuple[Optional[int], Optional[int]]] = {}
        for key in self._range_lo_vars:
            lo_text = self._range_lo_vars[key].get().strip()
            hi_text = self._range_hi_vars[key].get().strip()
            lo = int(lo_text) if lo_text else None
            hi = int(hi_text) if hi_text else None
            ranges[key] = (lo, hi)

        self._result = AdvancedFilter(fields=fields, ranges=ranges, mode=mode)
        self.destroy()

    @property
    def result(self) -> Optional[AdvancedFilter]:
        return self._result


def open_panel(
    master: tk.Misc,
    *,
    initial: Optional[AdvancedFilter] = None,
) -> AdvancedSearchPanel:
    """Helper that constructs and lifts a fresh panel."""
    panel = AdvancedSearchPanel(master, initial=initial)
    panel.lift()
    panel.attributes("-topmost", True)
    panel.after(50, lambda: panel.attributes("-topmost", False))
    return panel


__all__ = [
    "AdvancedFilter",
    "AdvancedSearchPanel",
    "open_panel",
    "FIELDS",
]