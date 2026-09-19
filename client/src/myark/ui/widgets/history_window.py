"""History popup window: tail ``~/.myark/history.log`` for recent actions.

The popup is opened from the ``myark-ui`` main menu (or via
``Ctrl+Shift+H`` once we add the binding in S9.2 task 5) and renders
the last ``limit`` records written by :mod:`myark.history`. Each row
shows ``timestamp / action / target / result / detail``.

Design notes
------------
* Pure R3 / pure UI. The window is a :class:`tk.Toplevel` that reads
  the file once at construction time. There is no auto-refresh -- the
  user clicks "Reload" to see new entries (the file is normally only
  written by action callbacks, so polling is unnecessary).
* Esc and the close button destroy the window.
"""

from __future__ import annotations

import datetime as _dt
import tkinter as tk

from myark.ui.scaling import scaled_width
from tkinter import ttk
from typing import Optional

from ...history import HistoryRecord, history_path, read_recent


DEFAULT_TITLE = "Action history"
DEFAULT_WIDTH = 720
DEFAULT_HEIGHT = 460
DEFAULT_LIMIT = 200


def _format_ts(ts: float) -> str:
    if not ts:
        return "?"
    try:
        return _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return f"{ts:.0f}"


class HistoryWindow(tk.Toplevel):
    """Read-only ``Toplevel`` that renders the history file."""

    def __init__(
        self,
        master: tk.Misc,
        *,
        limit: int = DEFAULT_LIMIT,
        title: str = DEFAULT_TITLE,
        width: int = DEFAULT_WIDTH,
        height: int = DEFAULT_HEIGHT,
        path: Optional[str] = None,
    ) -> None:
        super().__init__(master)
        self.title(title)
        self.transient(master)
        self.resizable(True, True)
        self.minsize(560, 320)

        self._limit = max(1, int(limit))
        self._path_arg = path
        self._records: list[HistoryRecord] = []

        outer = ttk.Frame(self, padding=8)
        outer.pack(fill=tk.BOTH, expand=True)

        header = ttk.Frame(outer)
        header.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(
            header,
            text="Recent actions",
            font=("Segoe UI", 11, "bold"),
            foreground="#204060",
        ).pack(side=tk.LEFT)

        self._path_var = tk.StringVar(value="(no history)")
        ttk.Label(
            header, textvariable=self._path_var, foreground="#888"
        ).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(header, text="Reload", command=self._reload).pack(side=tk.RIGHT)

        body = ttk.Frame(outer)
        body.pack(fill=tk.BOTH, expand=True)

        self._tree = ttk.Treeview(
            body,
            columns=("when", "action", "target", "result", "detail"),
            show="headings",
            height=14,
        )
        self._tree.heading("when", text="When")
        self._tree.heading("action", text="Action")
        self._tree.heading("target", text="Target")
        self._tree.heading("result", text="Result")
        self._tree.heading("detail", text="Detail")
        self._tree.column("when", width=scaled_width(self, 140), anchor=tk.W, stretch=False)
        self._tree.column("action", width=scaled_width(self, 110), anchor=tk.W, stretch=False)
        self._tree.column("target", width=scaled_width(self, 180), anchor=tk.W, stretch=True)
        self._tree.column("result", width=scaled_width(self, 80), anchor=tk.W, stretch=False)
        self._tree.column("detail", width=scaled_width(self, 180), anchor=tk.W, stretch=True)

        vsb = ttk.Scrollbar(body, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)

        self._summary_var = tk.StringVar(value="")
        ttk.Label(
            outer,
            textvariable=self._summary_var,
            foreground="#888",
        ).pack(fill=tk.X, pady=(4, 0))

        btns = ttk.Frame(outer)
        btns.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(btns, text="Close", command=self.destroy).pack(side=tk.RIGHT)

        # Bindings
        self.bind("<Escape>", lambda _e: self.destroy())
        self.bind("<F5>", lambda _e: self._reload())
        self.protocol("WM_DELETE_WINDOW", self.destroy)

        self.geometry(f"{width}x{height}")
        self._position(master)
        self._reload()

    # ----------------------------------------------------------- public API

    @property
    def records(self) -> list[HistoryRecord]:
        """Return a copy of the records currently shown (oldest first)."""
        return list(self._records)

    def reload(self) -> None:
        """Re-read the history file and rebuild the table."""
        self._reload()

    # ------------------------------------------------------------ helpers

    def _reload(self) -> None:
        path = self._path_arg if self._path_arg else str(history_path())
        self._path_var.set(path)
        try:
            records = read_recent(self._limit, path=path) if self._path_arg else read_recent(self._limit)
        except Exception as exc:
            self._summary_var.set(f"read failed: {exc}")
            records = []
        self._records = list(records)
        self._tree.delete(*self._tree.get_children())
        for idx, rec in enumerate(self._records):
            self._tree.insert(
                "",
                "end",
                iid=str(idx),
                values=(
                    _format_ts(rec.timestamp),
                    rec.action,
                    rec.target,
                    rec.result,
                    rec.detail,
                ),
            )
        if self._records:
            self._summary_var.set(
                f"{len(self._records)} record(s) -- newest last"
            )
        else:
            self._summary_var.set("history file is empty")

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


__all__ = ["HistoryWindow"]