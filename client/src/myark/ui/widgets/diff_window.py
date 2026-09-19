"""Comparison popup window: diff two entities side-by-side.

When the user selects two rows of the same kind (two processes / two
registry entries / two files) and triggers "Compare", the module UI
hands the two dicts to :class:`DiffWindow` and a Toplevel pops up with:

* a left/right key-value table (``item a`` vs ``item b``);
* a "differences only" toggle that hides fields whose values match;
* per-kind summary banners that call out the most semantically
  meaningful delta (registry: ``key missing / value differs / perms
  differ``; file: ``size / time / content``; process: ``pid / path /
  integrity``).

Design notes
------------
* Pure R3 / pure UI. No driver IOCTLs.
* The two items can be of any shape; matching is done by string
  representation so two ``int`` 1234 and ``str`` "1234" still diff.
* The window is read-only -- there is no callback for "apply left to
  right" because destructive merges belong in the action layer, not
  in a popup.
"""

from __future__ import annotations

import tkinter as tk

from myark.ui.scaling import scaled_width
from tkinter import ttk
from typing import Any, Literal, Mapping, Optional


DiffKind = Literal["registry", "process", "file", "generic"]

DEFAULT_TITLE = "Compare"
DEFAULT_WIDTH = 720
DEFAULT_HEIGHT = 520


def _norm(value: Any) -> str:
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


class DiffWindow(tk.Toplevel):
    """Side-by-side diff popup for two entity dicts."""

    def __init__(
        self,
        master: tk.Misc,
        *,
        item_a: Optional[Mapping[str, Any]] = None,
        item_b: Optional[Mapping[str, Any]] = None,
        kind: DiffKind = "generic",
        title: str = DEFAULT_TITLE,
        width: int = DEFAULT_WIDTH,
        height: int = DEFAULT_HEIGHT,
    ) -> None:
        super().__init__(master)
        self.title(title)
        self.transient(master)
        self.resizable(True, True)
        self.minsize(560, 320)

        self._item_a: dict = dict(item_a) if item_a is not None else {}
        self._item_b: dict = dict(item_b) if item_b is not None else {}
        self._kind: DiffKind = kind
        self._diffs_only: bool = False

        outer = ttk.Frame(self, padding=8)
        outer.pack(fill=tk.BOTH, expand=True)

        # ---- header
        header = ttk.Frame(outer)
        header.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(
            header,
            text=f"Compare ({self._kind})",
            font=("Segoe UI", 11, "bold"),
            foreground="#204060",
        ).pack(side=tk.LEFT)

        self._diff_only_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            header,
            text="Differences only",
            variable=self._diff_only_var,
            command=self._refresh,
        ).pack(side=tk.RIGHT)

        # ---- summary banner (per-kind most-meaningful delta)
        self._summary_var = tk.StringVar(value="")
        ttk.Label(
            outer,
            textvariable=self._summary_var,
            foreground="#a00",
            wraplength=width - 32,
            justify=tk.LEFT,
        ).pack(fill=tk.X, pady=(0, 4))

        # ---- side-by-side body
        body = ttk.Frame(outer)
        body.pack(fill=tk.BOTH, expand=True)

        body.columnconfigure(0, weight=1, uniform="col")
        body.columnconfigure(1, weight=1, uniform="col")
        body.rowconfigure(1, weight=1)

        ttk.Label(body, text="Item A", foreground="#204060").grid(
            row=0, column=0, sticky=tk.W, padx=2
        )
        ttk.Label(body, text="Item B", foreground="#204060").grid(
            row=0, column=1, sticky=tk.W, padx=2
        )

        self._tree_a = self._make_tree(body)
        self._tree_a.grid(row=1, column=0, sticky="nsew", padx=(0, 4))
        self._tree_b = self._make_tree(body)
        self._tree_b.grid(row=1, column=1, sticky="nsew", padx=(4, 0))

        # ---- close button
        btns = ttk.Frame(outer)
        btns.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(btns, text="Close", command=self.destroy).pack(side=tk.RIGHT)

        # Bindings
        self.bind("<Escape>", lambda _e: self.destroy())
        self.protocol("WM_DELETE_WINDOW", self.destroy)

        # Sizing
        self.geometry(f"{width}x{height}")
        self._position(master)
        self._refresh()

    # ----------------------------------------------------------- public API

    @property
    def item_a(self) -> dict:
        return dict(self._item_a)

    @property
    def item_b(self) -> dict:
        return dict(self._item_b)

    @property
    def differences(self) -> list[str]:
        """Return the list of keys whose normalized values differ."""
        keys = set(self._item_a) | set(self._item_b)
        out: list[str] = []
        for k in keys:
            if _norm(self._item_a.get(k)) != _norm(self._item_b.get(k)):
                out.append(k)
        return sorted(out)

    def set_items(
        self,
        item_a: Mapping[str, Any],
        item_b: Mapping[str, Any],
        kind: Optional[DiffKind] = None,
    ) -> None:
        self._item_a = dict(item_a) if item_a is not None else {}
        self._item_b = dict(item_b) if item_b is not None else {}
        if kind is not None:
            self._kind = kind
        self._refresh()

    # ------------------------------------------------------------ helpers

    @staticmethod
    def _make_tree(parent: tk.Misc) -> ttk.Treeview:
        wrapper = ttk.Frame(parent)
        tree = ttk.Treeview(
            wrapper,
            columns=("key", "value"),
            show="headings",
            height=14,
        )
        tree.heading("key", text="Field")
        tree.heading("value", text="Value")
        tree.column("key", width=scaled_width(parent, 120), anchor=tk.W, stretch=False)
        tree.column("value", width=scaled_width(parent, 200), anchor=tk.W, stretch=True)

        vsb = ttk.Scrollbar(wrapper, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        # Stash the inner tree so we can find it from outside.
        wrapper._inner_tree = tree  # type: ignore[attr-defined]
        return wrapper

    def _fill_tree(self, wrapper: ttk.Frame, item: dict) -> None:
        tree = wrapper._inner_tree  # type: ignore[attr-defined]
        tree.delete(*tree.get_children())
        keys = sorted(item.keys())
        iid_counter = 0
        for k in keys:
            if not self._should_show(k):
                continue
            tag = "diff" if self._is_diff(k) else ""
            tree.insert(
                "",
                "end",
                iid=str(iid_counter),
                values=(k, _norm(item.get(k))),
                tags=(tag,) if tag else (),
            )
            iid_counter += 1
        # Tag styling: highlight diff rows in both trees.
        try:
            tree.tag_configure("diff", background="#fff3cf")
        except tk.TclError:
            pass

    def _is_diff(self, key: str) -> bool:
        return _norm(self._item_a.get(key)) != _norm(self._item_b.get(key))

    def _should_show(self, key: str) -> bool:
        return not self._diffs_only or self._is_diff(key)

    def _summary(self) -> str:
        diffs = self.differences
        if not diffs:
            return "Items are identical."
        if self._kind == "registry":
            labels = self._registry_summary(diffs)
        elif self._kind == "file":
            labels = self._file_summary(diffs)
        elif self._kind == "process":
            labels = self._process_summary(diffs)
        else:
            labels = diffs
        if not labels:
            labels = diffs
        return f"{len(diffs)} field(s) differ: " + ", ".join(labels)

    def _registry_summary(self, diffs: list[str]) -> list[str]:
        out: list[str] = []
        for k in diffs:
            lk = k.lower()
            if lk in ("exists", "present", "has_key"):
                out.append("key existence")
            elif "perm" in lk:
                out.append("permissions")
            elif lk in ("value", "data"):
                out.append("value")
            else:
                out.append(k)
        return out

    def _file_summary(self, diffs: list[str]) -> list[str]:
        out: list[str] = []
        for k in diffs:
            lk = k.lower()
            if lk in ("size", "size_bytes"):
                out.append("size")
            elif "time" in lk or "date" in lk:
                out.append("timestamp")
            elif "content" in lk or "head" in lk:
                out.append("content (head 1KB)")
            else:
                out.append(k)
        return out

    def _process_summary(self, diffs: list[str]) -> list[str]:
        out: list[str] = []
        for k in diffs:
            lk = k.lower()
            if lk in ("pid", "process_id"):
                out.append("PID")
            elif "path" in lk:
                out.append("image path")
            elif "integrity" in lk:
                out.append("integrity level")
            elif "ppid" in lk:
                out.append("parent PID")
            else:
                out.append(k)
        return out

    def _refresh(self) -> None:
        self._diffs_only = bool(self._diff_only_var.get())
        self._fill_tree(self._tree_a, self._item_a)
        self._fill_tree(self._tree_b, self._item_b)
        self._summary_var.set(self._summary())

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


__all__ = ["DiffWindow", "DiffKind"]