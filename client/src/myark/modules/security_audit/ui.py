"""
security-audit R3 - Tkinter UI factory

Mirrors the process/network UI shape: a frame with a title, a refresh
button, a small results table and a status line. Every row comes from
the same builders the CLI prints (``myark.modules.security_audit.cli``)
so the tab and the CLI can never drift apart. When ``client`` is None
(driver offline) each query degrades to the parser's R3 fallback; the
driver is never opened here -- the caller-provided handle is only
forwarded to the row builders.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Optional

from myark.client.ark_client import ArkClient
from myark.ui.scaling import scaled_width


AUDIT_COLUMNS: tuple[str, ...] = ("item", "source", "status_kv")


def _build_ui(parent: Any, client: Optional[ArkClient]) -> ttk.Frame:
    """Return the security_audit module tab body."""
    from myark.modules.security_audit import cli

    frame = ttk.Frame(parent, padding=8)
    ttk.Label(
        frame,
        text="Security audit module (R3 fallback - no driver required)",
        font=("Segoe UI", 11, "bold"),
    ).grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 6))

    row = 1
    if client is not None:
        ttk.Label(
            frame,
            text="driver online - fields may be more complete",
            foreground="#888",
        ).grid(row=row, column=0, columnspan=3, sticky=tk.W, pady=(0, 6))
        row += 1

    status = tk.StringVar(value="(not loaded yet)")

    def _refresh() -> None:
        for r in tree.get_children():
            tree.delete(r)
        try:
            rows = cli.audit_rows(client)
        except Exception as exc:
            status.set(f"security_audit failed: {exc}")
            return
        for r in rows:
            tree.insert("", tk.END, values=(r["item"], r["source"], r["status_kv"]))
        sources = {r["source"] for r in rows}
        src = sources.pop() if len(sources) == 1 else "mixed"
        status.set(f"loaded {len(rows)} audit items ({src})")

    tree = ttk.Treeview(frame, columns=AUDIT_COLUMNS, show="headings", height=5)
    for c, w in zip(AUDIT_COLUMNS, (140, 120, 420)):
        tree.heading(c, text=c.upper())
        tree.column(c, width=scaled_width(tree, w), anchor=tk.W)
    tree.grid(row=row, column=0, columnspan=3, sticky="nsew")
    table_row = row
    row += 1

    ttk.Button(frame, text="Refresh (R3)", command=_refresh).grid(
        row=row, column=0, sticky=tk.W, pady=4
    )
    ttk.Label(frame, textvariable=status).grid(
        row=row, column=1, columnspan=2, sticky=tk.W, padx=8
    )

    frame.columnconfigure(2, weight=1)
    frame.rowconfigure(table_row, weight=1)
    return frame


__all__ = ["_build_ui", "AUDIT_COLUMNS"]
