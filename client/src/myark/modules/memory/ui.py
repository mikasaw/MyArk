"""MyArk Memory module: Tkinter UI for the R3 memory-region browser.

Pure-R3 (no driver). The user enters a PID, hits Refresh, and the tab
loads the loader-visible regions via ``query_memory_regions``. The full
VAD tree needs the driver and is intentionally out of scope at S9.1.

Layout:

* toolbar    -- Pid entry + Refresh button.
* tree       -- 4 columns (base / size / protection / name).
* status bar -- row count + last refresh time.

The driver-side ``client`` handle is unused -- this is a pure-R3 module.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.modules.memory.parser import query_memory_regions
from myark.ui.scaling import scaled_width


REGION_COLUMNS: tuple[str, ...] = ("base", "size", "protection", "name")


def register(
    client: Optional[ArkClient],
    capabilities: list[CapabilityInfo],
) -> Any:
    """Re-expose the package-level ``register`` from ``plugin``.

    Some UI callers prefer to wire the entry-point factory directly
    rather than going through ``myark.plugin_loader``. This alias keeps
    that pattern working without forcing the spec'd ``plugin.py`` to
    double as the UI factory.
    """
    from myark.modules.memory.plugin import register as _register
    return _register(client, capabilities)


def _format_base(addr: int) -> str:
    return f"0x{addr:016X}"


def _format_size(size: int) -> str:
    if size >= 1024 * 1024:
        return f"{size / (1024 * 1024):.2f} MiB"
    if size >= 1024:
        return f"{size / 1024:.2f} KiB"
    return str(size)


def _protection_string(region) -> str:
    # R3 doesn't carry protection bits; we render what we do have.
    bits = []
    if region.path:
        bits.append("path")
    if region.name:
        bits.append("named")
    return ",".join(bits) or "(unnamed)"


def _build_ui(parent: Any, _client: Optional[ArkClient]) -> ttk.Frame:
    pid_var = tk.StringVar(value="")
    status_var = tk.StringVar(value="(enter a PID and click Refresh)")

    frame = ttk.Frame(parent, padding=8)

    ttk.Label(
        frame,
        text="Memory module (R3 - EnumProcessModules based)",
        font=("Segoe UI", 12, "bold"),
    ).grid(row=0, column=0, columnspan=4, sticky=tk.W, pady=(0, 4))
    ttk.Label(
        frame,
        text=(
            "Pure-R3 memory browser over EnumProcessModules. Loader-visible "
            "regions only -- the full VAD tree needs the .sys driver."
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
        columns=REGION_COLUMNS,
        show="headings",
        selectmode="browse",
    )
    for col, label, width in [
        ("base",        "Base address", 160),
        ("size",        "Size",         100),
        ("protection",  "Protection",   160),
        ("name",        "Name",         240),
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
            regions = query_memory_regions(pid)
        except Exception as exc:
            status_var.set(f"query_memory_regions failed: {exc}")
            tree.delete(*tree.get_children())
            return
        tree.delete(*tree.get_children())
        for r in regions:
            tree.insert(
                "",
                "end",
                values=(
                    _format_base(r.base_address),
                    _format_size(r.size),
                    _protection_string(r),
                    r.name or "(unnamed)",
                ),
            )
        status_var.set(f"pid={pid}: {len(regions)} region(s) loaded")

    ttk.Button(toolbar, text="Refresh", command=_refresh).grid(
        row=0, column=2, padx=(4, 0)
    )
    pid_entry.bind("<Return>", lambda _e: _refresh())

    return frame


__all__ = ["register", "_build_ui", "REGION_COLUMNS"]