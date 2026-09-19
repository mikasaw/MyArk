"""Detail popup window: show a single entity's full key/value map.

When the user clicks an item in a module's tree (process / registry entry /
file / handle / ...), the module UI hands the row dict to
:class:`DetailWindow` and a Toplevel pops up at the pointer position with
a "title + key-value table + close" layout.

Design notes
------------
* Pure R3 / pure UI. No driver IOCTLs.
* Modal-ish via :meth:`tk.Toplevel.transient` + :meth:`grab_set`, but not
  blocking -- the main window stays usable because modules may want to
  cross-reference multiple details at once.
* ``Esc`` and the close button both destroy the window. No callback is
  expected back to the caller -- the dialog is read-only by design.
* The display order is "title first, then the dict keys in their insertion
  order, then a Close button". Rows whose values are bytes are decoded as
  UTF-8 with replacement so the window never blows up on a null-terminated
  C string.
"""

from __future__ import annotations

import tkinter as tk

from myark.ui.scaling import scaled_width
from tkinter import ttk
from typing import Any, Mapping, Optional


DEFAULT_TITLE = "Details"
DEFAULT_WIDTH = 520
DEFAULT_HEIGHT = 480


class DetailWindow(tk.Toplevel):
    """A read-only ``Toplevel`` that renders one entity's dict."""

    def __init__(
        self,
        master: tk.Misc,
        *,
        item: Optional[Mapping[str, Any]] = None,
        title: str = DEFAULT_TITLE,
        width: int = DEFAULT_WIDTH,
        height: int = DEFAULT_HEIGHT,
    ) -> None:
        super().__init__(master)
        self.title(title)
        self.transient(master)
        self.resizable(True, True)
        self.minsize(360, 240)

        self._item: dict = dict(item) if item is not None else {}

        outer = ttk.Frame(self, padding=8)
        outer.pack(fill=tk.BOTH, expand=True)

        # ---- title strip
        title_frame = ttk.Frame(outer)
        title_frame.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(
            title_frame,
            text=self._title_text(title),
            font=("Segoe UI", 11, "bold"),
            foreground="#204060",
        ).pack(side=tk.LEFT)
        count = len(self._item)
        suffix = f"  ({count} field{'s' if count != 1 else ''})"
        ttk.Label(
            title_frame,
            text=suffix,
            foreground="#888",
        ).pack(side=tk.LEFT, padx=(6, 0))

        # ---- key/value table
        body = ttk.Frame(outer)
        body.pack(fill=tk.BOTH, expand=True)

        self._tree = ttk.Treeview(
            body,
            columns=("key", "value"),
            show="headings",
            height=14,
        )
        self._tree.heading("key", text="Field")
        self._tree.heading("value", text="Value")
        self._tree.column("key", width=scaled_width(self, 140), anchor=tk.W, stretch=False)
        self._tree.column("value", width=scaled_width(self, 320), anchor=tk.W, stretch=True)

        vsb = ttk.Scrollbar(body, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)

        self._populate()

        # ---- close button
        btns = ttk.Frame(outer)
        btns.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(btns, text="Close", command=self.destroy).pack(side=tk.RIGHT)

        # Bindings
        self.bind("<Escape>", lambda _e: self.destroy())
        self.protocol("WM_DELETE_WINDOW", self.destroy)

        # Sizing
        self.geometry(f"{width}x{height}")
        self._position_near_pointer(master)

    # ----------------------------------------------------------- public API

    @property
    def item(self) -> dict:
        """Return a shallow copy of the rendered dict (read-only)."""
        return dict(self._item)

    def set_item(self, item: Mapping[str, Any]) -> None:
        """Replace the rendered dict and refresh the table."""
        self._item = dict(item) if item is not None else {}
        self._populate()

    # ------------------------------------------------------------ helpers

    @staticmethod
    def _title_text(base: str) -> str:
        return base if base else DEFAULT_TITLE

    def _populate(self) -> None:
        self._tree.delete(*self._tree.get_children())
        for idx, (k, v) in enumerate(self._item.items()):
            self._tree.insert(
                "",
                "end",
                iid=str(idx),
                values=(str(k), self._format_value(v)),
            )

    @staticmethod
    def _format_value(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            try:
                return value.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            except Exception:
                return repr(value)
        if isinstance(value, (list, tuple)):
            return ", ".join(str(x) for x in value)
        if isinstance(value, dict):
            return "{" + ", ".join(f"{k}={v}" for k, v in value.items()) + "}"
        return str(value)

    def _position_near_pointer(self, master: tk.Misc) -> None:
        """Place the popup near the mouse pointer.

        On Tk the absolute pointer coordinates are obtained from
        ``master.winfo_pointerxy``. We offset so the cursor does not sit
        exactly on the title bar.
        """
        try:
            self.update_idletasks()
            try:
                px, py = master.winfo_pointerxy()
            except tk.TclError:
                px, py = master.winfo_rootx() + 40, master.winfo_rooty() + 40
            w = self.winfo_width()
            h = self.winfo_height()
            x = max(8, px - w // 2)
            y = max(8, py - 20)
            self.geometry(f"+{x}+{y}")
        except tk.TclError:
            pass


__all__ = ["DetailWindow"]