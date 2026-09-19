"""Ctrl+P command palette: a quick-jump launcher for the MyArk main window.

The palette is a small Toplevel with an Entry on top and a Listbox below.
The user types into the Entry; candidates below are filtered live using
:mod:`myark.ui.search.matcher` with a default mode of :class:`MatchMode.PINYIN`
(substring + pinyin initials). ``Up`` / ``Down`` move the highlight,
``Enter`` commits, ``Esc`` closes, and ``Ctrl+P`` toggles.

On commit, the palette invokes a registered ``on_pick`` callback with the
selected :class:`SearchEntry`. The main window supplies the callback to
switch to the right module tab and forward focus into the row.

The palette is pure UI / pure R3 -- no driver IOCTLs.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional

from .index_builder import SearchEntry, build_index
from .matcher import MatchMode


DEFAULT_LIMIT = 80


class CommandPalette(tk.Toplevel):
    """Modal Toplevel that overlays the main window with a fuzzy jump list."""

    def __init__(
        self,
        master: tk.Misc,
        *,
        entries: Optional[list[SearchEntry]] = None,
        on_pick: Optional[Callable[[SearchEntry], None]] = None,
        mode: MatchMode = MatchMode.PINYIN,
        limit: int = DEFAULT_LIMIT,
    ) -> None:
        super().__init__(master)
        self.title("Command Palette (Ctrl+P)")
        self.transient(master)
        self.resizable(True, False)
        self.configure(bg="#1e1e1e")

        self._entries = list(entries) if entries is not None else build_index()
        self._on_pick = on_pick
        self._mode = mode
        self._limit = limit
        self._filtered: list[SearchEntry] = []

        # ----- layout
        outer = ttk.Frame(self, padding=8)
        outer.pack(fill=tk.BOTH, expand=True)

        self._query_var = tk.StringVar()
        self._query_var.trace_add("write", lambda *_: self._refresh())

        entry = ttk.Entry(outer, textvariable=self._query_var, font=("Segoe UI", 12))
        entry.pack(fill=tk.X, pady=(0, 6))
        entry.focus_set()

        self._mode_var = tk.StringVar(value=str(mode.value))
        mode_frame = ttk.Frame(outer)
        mode_frame.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(mode_frame, text="Mode:").pack(side=tk.LEFT)
        for m in MatchMode:
            ttk.Radiobutton(
                mode_frame,
                text=m.value,
                value=m.value,
                variable=self._mode_var,
                command=self._on_mode_change,
            ).pack(side=tk.LEFT, padx=2)

        list_frame = ttk.Frame(outer)
        list_frame.pack(fill=tk.BOTH, expand=True)
        self._listbox = tk.Listbox(
            list_frame,
            height=14,
            activestyle="dotbox",
            font=("Consolas", 10),
            background="#1e1e1e",
            foreground="#d4d4d4",
            selectbackground="#264f78",
            selectforeground="#ffffff",
        )
        vsb = ttk.Scrollbar(list_frame, orient="vertical", command=self._listbox.yview)
        self._listbox.configure(yscrollcommand=vsb.set)
        self._listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self._status_var = tk.StringVar(value=f"{len(self._entries)} entries")
        ttk.Label(outer, textvariable=self._status_var, foreground="#888").pack(
            anchor=tk.W, pady=(4, 0)
        )

        # ----- bindings
        entry.bind("<Down>", lambda _e: self._move(1))
        entry.bind("<Up>", lambda _e: self._move(-1))
        entry.bind("<Return>", self._on_enter)
        self._listbox.bind("<Return>", self._on_enter)
        self._listbox.bind("<Double-Button-1>", self._on_enter)
        self.bind("<Escape>", lambda _e: self.destroy())
        # Toggle mode via Ctrl+1..5.
        for i, m in enumerate(MatchMode):
            self.bind(f"<Control-Key-{i + 1}>", lambda _e, mm=m: self._set_mode(mm))

        # Geometry: overlay top-center, 640px wide.
        self.geometry("640x420")
        self._center_over_master(master)
        self._refresh()

    # ------------------------------------------------------------- helpers

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
            y = my + max(40, (mh - h) // 4)
            self.geometry(f"+{x}+{y}")
        except tk.TclError:
            pass

    def _set_mode(self, mode: MatchMode) -> None:
        self._mode = mode
        self._mode_var.set(str(mode.value))
        self._refresh()

    def _on_mode_change(self) -> None:
        try:
            self._mode = MatchMode(self._mode_var.get())
        except ValueError:
            self._mode = MatchMode.SUBSTRING
        self._refresh()

    def _refresh(self) -> None:
        query = self._query_var.get()
        filtered: list[SearchEntry] = []
        if not query.strip():
            filtered = list(self._entries[: self._limit])
        else:
            for entry in self._entries:
                if entry.matches(query, self._mode):
                    filtered.append(entry)
                    if len(filtered) >= self._limit:
                        break

        self._filtered = filtered
        self._listbox.delete(0, tk.END)
        for e in filtered:
            label = f"[{e.module}] {e.primary}"
            if e.description and e.description != e.primary:
                label += f"   -- {e.description}"
            self._listbox.insert(tk.END, label)
        if filtered:
            self._listbox.selection_set(0)
            self._listbox.activate(0)
        self._status_var.set(
            f"{len(filtered)} match(es) / {len(self._entries)} entries"
        )

    def _move(self, delta: int) -> str:
        if not self._filtered:
            return "break"
        size = self._listbox.size()
        if size == 0:
            return "break"
        sel = self._listbox.curselection()
        cur = sel[0] if sel else 0
        nxt = max(0, min(size - 1, cur + delta))
        self._listbox.selection_clear(0, tk.END)
        self._listbox.selection_set(nxt)
        self._listbox.activate(nxt)
        self._listbox.see(nxt)
        return "break"

    def _on_enter(self, _event: tk.Event = None) -> str:
        sel = self._listbox.curselection()
        if not sel:
            return "break"
        idx = sel[0]
        if idx >= len(self._filtered):
            return "break"
        entry = self._filtered[idx]
        callback = self._on_pick
        self.destroy()
        if callback is not None:
            try:
                callback(entry)
            except Exception as exc:  # pragma: no cover -- UI feedback path
                print(f"[CommandPalette] on_pick failed: {exc}", file=__import__("sys").stderr)
        return "break"


def open_palette(
    master: tk.Misc,
    *,
    entries: Optional[list[SearchEntry]] = None,
    on_pick: Optional[Callable[[SearchEntry], None]] = None,
) -> CommandPalette:
    """Helper that constructs, lifts, and returns a fresh palette."""
    palette = CommandPalette(master, entries=entries, on_pick=on_pick)
    palette.lift()
    palette.attributes("-topmost", True)
    palette.after(50, lambda: palette.attributes("-topmost", False))
    return palette


__all__ = ["CommandPalette", "open_palette"]