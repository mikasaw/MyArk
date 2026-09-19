"""Filter builder popup window: assemble a multi-criteria filter and apply.

The left-pane substring filter and the right-side ``Advanced Search``
panel each cover one slice of the filtering story. ``FilterWindow``
is the dialog you reach for when neither is enough -- you want a
name regex + size range + date range + permission flag, and you want
to apply it to the main window's current tab without leaving the UI.

Design notes
------------
* Pure R3 / pure UI. The window is a :class:`tk.Toplevel` that builds
  an :class:`~myark.ui.search.adv_search_panel.AdvancedFilter` and
  hands it back to the caller through :attr:`result`.
* ``on_apply`` is the integration hook the main window passes in --
  typically it forwards the filter into the active module tab and
  forces a refresh.
* ``Esc`` cancels without applying (the filter is discarded); the
  Apply button commits and closes the window.
"""

from __future__ import annotations

import re
import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional

from ..search.adv_search_panel import AdvancedFilter
from ..search.matcher import MatchMode


DEFAULT_TITLE = "Filter builder"
DEFAULT_WIDTH = 560
DEFAULT_HEIGHT = 460


class FilterWindow(tk.Toplevel):
    """Multi-criteria filter builder + applier."""

    def __init__(
        self,
        master: tk.Misc,
        *,
        initial: Optional[AdvancedFilter] = None,
        on_apply: Optional[Callable[[AdvancedFilter], None]] = None,
        title: str = DEFAULT_TITLE,
        width: int = DEFAULT_WIDTH,
        height: int = DEFAULT_HEIGHT,
    ) -> None:
        super().__init__(master)
        self.title(title)
        self.transient(master)
        self.resizable(True, True)
        self.minsize(440, 320)

        self._on_apply = on_apply
        self._result: Optional[AdvancedFilter] = None
        self._initial = initial

        outer = ttk.Frame(self, padding=10)
        outer.pack(fill=tk.BOTH, expand=True)

        # ---- name field (regex on/off)
        ttk.Label(outer, text="Name regex (case-insensitive when off):").pack(
            anchor=tk.W
        )
        self._regex_var = tk.BooleanVar(value=False)
        name_row = ttk.Frame(outer)
        name_row.pack(fill=tk.X, pady=(2, 6))
        self._name_var = tk.StringVar()
        ttk.Entry(name_row, textvariable=self._name_var).pack(
            side=tk.LEFT, fill=tk.X, expand=True
        )
        ttk.Checkbutton(
            name_row, text="regex", variable=self._regex_var
        ).pack(side=tk.LEFT, padx=(6, 0))

        # ---- size range
        size_frame = ttk.LabelFrame(outer, text="Size range (bytes)")
        size_frame.pack(fill=tk.X, pady=(0, 6))
        self._size_min_var = tk.StringVar()
        self._size_max_var = tk.StringVar()
        size_row = ttk.Frame(size_frame)
        size_row.pack(fill=tk.X, padx=6, pady=4)
        ttk.Label(size_row, text="min:").pack(side=tk.LEFT)
        ttk.Entry(size_row, textvariable=self._size_min_var, width=12).pack(
            side=tk.LEFT, padx=(2, 12)
        )
        ttk.Label(size_row, text="max:").pack(side=tk.LEFT)
        ttk.Entry(size_row, textvariable=self._size_max_var, width=12).pack(
            side=tk.LEFT, padx=(2, 0)
        )

        # ---- date range (year only -- keeps the dialog simple)
        date_frame = ttk.LabelFrame(outer, text="Date range (year)")
        date_frame.pack(fill=tk.X, pady=(0, 6))
        self._date_min_var = tk.StringVar()
        self._date_max_var = tk.StringVar()
        date_row = ttk.Frame(date_frame)
        date_row.pack(fill=tk.X, padx=6, pady=4)
        ttk.Label(date_row, text="from:").pack(side=tk.LEFT)
        ttk.Entry(date_row, textvariable=self._date_min_var, width=8).pack(
            side=tk.LEFT, padx=(2, 12)
        )
        ttk.Label(date_row, text="to:").pack(side=tk.LEFT)
        ttk.Entry(date_row, textvariable=self._date_max_var, width=8).pack(
            side=tk.LEFT, padx=(2, 0)
        )

        # ---- permission flags
        perm_frame = ttk.LabelFrame(outer, text="Permission flags")
        perm_frame.pack(fill=tk.X, pady=(0, 6))
        self._read_var = tk.BooleanVar()
        self._write_var = tk.BooleanVar()
        self._exec_var = tk.BooleanVar()
        perm_row = ttk.Frame(perm_frame)
        perm_row.pack(fill=tk.X, padx=6, pady=4)
        ttk.Checkbutton(perm_row, text="readable", variable=self._read_var).pack(
            side=tk.LEFT
        )
        ttk.Checkbutton(perm_row, text="writable", variable=self._write_var).pack(
            side=tk.LEFT, padx=(8, 0)
        )
        ttk.Checkbutton(perm_row, text="executable", variable=self._exec_var).pack(
            side=tk.LEFT, padx=(8, 0)
        )

        # ---- match mode
        mode_row = ttk.Frame(outer)
        mode_row.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(mode_row, text="Match mode:").pack(side=tk.LEFT)
        self._mode_var = tk.StringVar(value=MatchMode.SUBSTRING.value)
        ttk.Combobox(
            mode_row,
            textvariable=self._mode_var,
            values=[m.value for m in MatchMode],
            state="readonly",
            width=12,
        ).pack(side=tk.LEFT, padx=(6, 0))

        # ---- preview + buttons
        self._preview_var = tk.StringVar(value="(no filter)")
        ttk.Label(
            outer, textvariable=self._preview_var, foreground="#888",
            wraplength=width - 32, justify=tk.LEFT,
        ).pack(fill=tk.X, pady=(8, 4))

        btns = ttk.Frame(outer)
        btns.pack(fill=tk.X, pady=(4, 0))
        ttk.Button(btns, text="Cancel", command=self._cancel).pack(side=tk.RIGHT)
        ttk.Button(btns, text="Apply", command=self._apply).pack(
            side=tk.RIGHT, padx=(0, 6)
        )
        ttk.Button(btns, text="Preview", command=self._update_preview).pack(
            side=tk.LEFT
        )

        # ---- bindings
        for var in (
            self._name_var,
            self._regex_var,
            self._size_min_var,
            self._size_max_var,
            self._date_min_var,
            self._date_max_var,
            self._read_var,
            self._write_var,
            self._exec_var,
            self._mode_var,
        ):
            try:
                var.trace_add("write", lambda *_: self._update_preview())
            except AttributeError:
                pass

        self.bind("<Escape>", lambda _e: self._cancel())
        self.bind("<Return>", lambda _e: self._apply())
        self.protocol("WM_DELETE_WINDOW", self._cancel)

        if initial is not None:
            self._populate_from(initial)

        self.geometry(f"{width}x{height}")
        self._position(master)
        self._update_preview()

    # ----------------------------------------------------------- public API

    @property
    def result(self) -> Optional[AdvancedFilter]:
        """The filter the user committed, or ``None`` on cancel."""
        return self._result

    def build_filter(self) -> AdvancedFilter:
        """Return the current form values as an AdvancedFilter.

        Exposed for tests; the dialog does not block.
        """
        fields: dict[str, str] = {}
        ranges: dict[str, tuple] = {}
        name = self._name_var.get().strip()
        if name:
            fields["name"] = name
        permissions: list[str] = []
        if self._read_var.get():
            permissions.append("readable")
        if self._write_var.get():
            permissions.append("writable")
        if self._exec_var.get():
            permissions.append("executable")
        if permissions:
            fields["permissions"] = ",".join(permissions)

        try:
            size_min = int(self._size_min_var.get()) if self._size_min_var.get() else None
        except ValueError:
            size_min = None
        try:
            size_max = int(self._size_max_var.get()) if self._size_max_var.get() else None
        except ValueError:
            size_max = None
        if size_min is not None or size_max is not None:
            ranges["size"] = (size_min, size_max)

        try:
            date_min = int(self._date_min_var.get()) if self._date_min_var.get() else None
        except ValueError:
            date_min = None
        try:
            date_max = int(self._date_max_var.get()) if self._date_max_var.get() else None
        except ValueError:
            date_max = None
        if date_min is not None or date_max is not None:
            ranges["year"] = (date_min, date_max)

        try:
            mode = MatchMode(self._mode_var.get())
        except ValueError:
            mode = MatchMode.SUBSTRING

        return AdvancedFilter(fields=fields, ranges=ranges, mode=mode)

    def validate_regex(self) -> Optional[str]:
        """Return an error message if the regex is invalid, else ``None``.

        The user is allowed to leave the name field empty (then ``name``
        is simply not in the filter).
        """
        if not self._regex_var.get():
            return None
        name = self._name_var.get().strip()
        if not name:
            return None
        try:
            re.compile(name)
            return None
        except re.error as exc:
            return f"Invalid regex: {exc}"

    # ------------------------------------------------------------ helpers

    def _populate_from(self, flt: AdvancedFilter) -> None:
        name = flt._fields.get("name", "")
        self._name_var.set(str(name))
        permissions = flt._fields.get("permissions", "")
        perms = {p.strip() for p in permissions.split(",") if p.strip()}
        self._read_var.set("readable" in perms)
        self._write_var.set("writable" in perms)
        self._exec_var.set("executable" in perms)
        if "size" in flt._ranges:
            lo, hi = flt._ranges["size"]
            self._size_min_var.set(str(lo) if lo is not None else "")
            self._size_max_var.set(str(hi) if hi is not None else "")
        if "year" in flt._ranges:
            lo, hi = flt._ranges["year"]
            self._date_min_var.set(str(lo) if lo is not None else "")
            self._date_max_var.set(str(hi) if hi is not None else "")
        self._mode_var.set(flt.mode.value)

    def _update_preview(self) -> None:
        flt = self.build_filter()
        if not flt.is_active():
            self._preview_var.set("(no filter)")
        else:
            self._preview_var.set("filter: " + flt.describe())

    def _apply(self) -> None:
        err = self.validate_regex()
        if err is not None:
            self._preview_var.set(err)
            return
        flt = self.build_filter()
        self._result = flt
        if self._on_apply is not None:
            try:
                self._on_apply(flt)
            except Exception:
                pass
        self.destroy()

    def _cancel(self) -> None:
        self._result = None
        self.destroy()

    def _position(self, master: tk.Misc) -> None:
        try:
            self.update_idletasks()
            try:
                mx, my = master.winfo_pointerxy()
            except tk.TclError:
                mx, my = master.winfo_rootx() + 40, master.winfo_rooty() + 40
            w = self.winfo_width()
            h = self.winfo_height()
            x = max(8, mx - w // 2)
            y = max(8, my - 20)
            self.geometry(f"+{x}+{y}")
        except tk.TclError:
            pass


__all__ = ["FilterWindow"]