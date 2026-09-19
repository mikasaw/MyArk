"""
process R3 - Tkinter UI factory

Mirrors the network/file UI shape: a frame with a Treeview of the
process list and a refresh button. The driver is never opened; every
call goes through ``myark.modules.process.parser``.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Optional, Any

from myark.client.ark_client import ArkClient
from myark.ui.scaling import scaled_width


def _build_ui(parent: Any, _client: Optional[ArkClient]) -> ttk.Frame:
    """Return the process module tab body."""
    from myark.modules.process.parser import enum_processes

    frame = ttk.Frame(parent, padding=8)
    ttk.Label(
        frame,
        text="Process module (R3 fallback - no driver required)",
        font=("Segoe UI", 11, "bold"),
    ).grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 6))

    cols = ("pid", "ppid", "name", "threads", "path")
    tree = ttk.Treeview(frame, columns=cols, show="headings", height=18)
    for c, w in zip(cols, (80, 80, 220, 80, 360)):
        tree.heading(c, text=c.upper())
        tree.column(c, width=scaled_width(tree, w), anchor=tk.W)
    tree.grid(row=1, column=0, columnspan=3, sticky="nsew")

    status = tk.StringVar(value="(not loaded yet)")

    def _refresh() -> None:
        for row in tree.get_children():
            tree.delete(row)
        try:
            rows = enum_processes()
        except Exception as exc:
            status.set(f"enum_processes failed: {exc}")
            return
        for r in rows:
            tree.insert(
                "",
                tk.END,
                values=(r.pid, r.ppid, r.name, r.thread_count, r.path[:60]),
            )
        status.set(f"loaded {len(rows)} processes (R3)")

    ttk.Button(frame, text="Refresh (R3)", command=_refresh).grid(
        row=2, column=0, sticky=tk.W, pady=4
    )
    ttk.Label(frame, textvariable=status).grid(
        row=2, column=1, columnspan=2, sticky=tk.W, padx=8
    )

    frame.columnconfigure(2, weight=1)
    frame.rowconfigure(1, weight=1)
    return frame


__all__ = ["_build_ui"]