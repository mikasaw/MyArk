"""MyArk Module subsystem: Tkinter UI for the loaded-module browser.

Pure-R3 (no driver). The user enters a PID, hits Refresh, and the tab
loads the loader-visible modules via ``enumerate_modules``. The columns
are name / base address / size / path -- the four pieces a reverse
engineer wants when triaging a process.

Layout:

* toolbar    -- Pid entry + Refresh button.
* tree       -- 4 columns (name / base / size / path).
* status bar -- row count + last refresh time.

The driver-side ``client`` handle is unused -- this is a pure-R3 module.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.modules.module.parser import enumerate_modules
from myark.ui.scaling import scaled_width


MODULE_COLUMNS: tuple[str, ...] = ("name", "base", "size", "path")


def register(
    client: Optional[ArkClient],
    capabilities: list[CapabilityInfo],
) -> Any:
    """Re-expose the package-level ``register`` from ``plugin``."""
    from myark.modules.module.plugin import register as _register
    return _register(client, capabilities)


def _format_base(addr: int) -> str:
    return f"0x{addr:016X}"


def _format_size(size: int) -> str:
    if size >= 1024 * 1024:
        return f"{size / (1024 * 1024):.2f} MiB"
    if size >= 1024:
        return f"{size / 1024:.2f} KiB"
    return str(size)


def _build_ui(parent: Any, _client: Optional[ArkClient]) -> ttk.Frame:
    pid_var = tk.StringVar(value="")
    status_var = tk.StringVar(value="(enter a PID and click Refresh)")

    frame = ttk.Frame(parent, padding=8)

    ttk.Label(
        frame,
        text="Module subsystem (R3 - EnumProcessModules)",
        font=("Segoe UI", 12, "bold"),
    ).grid(row=0, column=0, columnspan=4, sticky=tk.W, pady=(0, 4))
    ttk.Label(
        frame,
        text=(
            "Pure-R3 module browser over EnumProcessModules + "
            "GetModuleFileNameExW. Loader-visible modules only."
        ),
        wraplength=600,
        justify=tk.LEFT,
    ).grid(row=1, column=0, columnspan=4, sticky=tk.W, pady=(0, 8))

    toolbar = ttk.Frame(frame)
    toolbar.grid(row=2, column=0, columnspan=4, sticky=tk.W + tk.E, pady=(0, 8))

    ttk.Label(toolbar, text="PID:").grid(row=0, column=0, padx=(0, 4))
    pid_entry = ttk.Entry(toolbar, textvariable=pid_var, width=10)
    pid_entry.grid(row=0, column=1, padx=(0, 8))

    tree_frame = ttk.Frame(frame)
    tree_frame.grid(row=3, column=0, columnspan=4, sticky=tk.N + tk.S + tk.W + tk.E)

    tree = ttk.Treeview(
        tree_frame,
        columns=MODULE_COLUMNS,
        show="headings",
        selectmode="browse",
    )
    for col, label, width in [
        ("name", "Name",     220),
        ("base", "Base",     160),
        ("size", "Size",     100),
        ("path", "Path",     360),
    ]:
        tree.heading(col, text=label)
        tree.column(col, width=scaled_width(tree, width), anchor=tk.W)
    vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
    hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
    tree.grid(row=0, column=0, sticky=tk.N + tk.S + tk.W + tk.E)
    vsb.grid(row=0, column=1, sticky=tk.N + tk.S)
    hsb.grid(row=1, column=0, sticky=tk.W + tk.E)

    frame.columnconfigure(0, weight=1)
    frame.rowconfigure(3, weight=1)
    tree_frame.columnconfigure(0, weight=1)
    tree_frame.rowconfigure(0, weight=1)

    status = ttk.Label(frame, textvariable=status_var, anchor=tk.W)
    status.grid(row=4, column=0, columnspan=4, sticky=tk.W + tk.E, pady=(8, 0))

    def _refresh() -> None:
        text = pid_var.get().strip()
        try:
            pid = int(text)
        except ValueError:
            status_var.set("enter a numeric PID")
            return
        try:
            mods = enumerate_modules(pid)
        except Exception as exc:
            status_var.set(f"enumerate_modules failed: {exc}")
            tree.delete(*tree.get_children())
            return
        tree.delete(*tree.get_children())
        for m in mods:
            tree.insert(
                "",
                "end",
                values=(
                    m.name,
                    _format_base(m.base_address),
                    _format_size(m.size),
                    m.path,
                ),
            )
        status_var.set(f"pid={pid}: {len(mods)} module(s) loaded")

    ttk.Button(toolbar, text="Refresh", command=_refresh).grid(
        row=0, column=2, padx=(4, 0)
    )
    pid_entry.bind("<Return>", lambda _e: _refresh())

    return frame


__all__ = ["register", "_build_ui", "MODULE_COLUMNS"]