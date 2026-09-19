"""MyArk trust module: Tkinter UI for R3 PE signature verification.

One panel, no entity tree -- "pick a file, verify its signature" is a
high-frequency ARK operation, and the trust module's R3 primary path
(``trust verify-pe``) needs no driver. The panel calls the same
``verify_pe_row`` data function the CLI prints, so UI and CLI always
report the same ``status``.

``verify-catalog`` gets no button on purpose: catalog verification is
driver-dependent (R0 only), i.e. a VM scenario -- see the note pinned
to the bottom of the panel.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, ttk
from typing import Any, Optional

from myark.client.ark_client import ArkClient
from myark.modules.trust import cli

RESULT_FIELDS = ("path", "status", "source", "subject", "issuer", "flags")


def _build_ui(
    parent: Any,
    client: Optional[ArkClient],
    *,
    safety_authority: Optional[Any] = None,
) -> ttk.Frame:
    """Build the trust module's verify-pe tab.

    ``safety_authority`` is accepted for the standard ui_factory
    signature; trust exposes no destructive action, so it is unused.
    """
    frame = ttk.Frame(parent, padding=8)

    ttk.Label(
        frame,
        text="trust - PE signature verification (R3 primary)",
        font=("Segoe UI", 12, "bold"),
    ).grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 4))

    # -- toolbar: path entry + Browse + Verify PE
    toolbar = ttk.Frame(frame)
    toolbar.grid(row=1, column=0, columnspan=2, sticky=tk.W + tk.E, pady=(0, 8))

    path_var = tk.StringVar(value="")
    ttk.Label(toolbar, text="Path:").grid(row=0, column=0, padx=(0, 4))
    entry = ttk.Entry(toolbar, textvariable=path_var, width=60)
    entry.grid(row=0, column=1, padx=(0, 8))

    # -- result area: one key-value row per verify_pe_row field
    result_frame = ttk.LabelFrame(frame, text="Result")
    result_frame.grid(row=2, column=0, columnspan=2, sticky=tk.N + tk.S + tk.W + tk.E)
    result_vars = {name: tk.StringVar(value="") for name in RESULT_FIELDS}
    for row_idx, name in enumerate(RESULT_FIELDS):
        ttk.Label(
            result_frame, text=name, foreground="#555", width=10, anchor=tk.W
        ).grid(row=row_idx, column=0, sticky=tk.W, padx=(6, 4), pady=1)
        ttk.Label(
            result_frame, textvariable=result_vars[name], anchor=tk.W
        ).grid(row=row_idx, column=1, sticky=tk.W + tk.E, padx=(0, 6), pady=1)
    result_frame.columnconfigure(1, weight=1)

    # -- status line: most recent verification (or hint)
    status_var = tk.StringVar(value="(enter a PE path and press Verify PE)")
    ttk.Label(frame, textvariable=status_var, anchor=tk.W).grid(
        row=3, column=0, columnspan=2, sticky=tk.W + tk.E, pady=(8, 0)
    )

    # -- bottom note: verify-catalog stays CLI-only (R0 / VM)
    note = ttk.Label(frame, text="catalog verify 需驱动 (VM)", foreground="#888")
    note.grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=(4, 0))

    frame.columnconfigure(0, weight=1)
    frame.rowconfigure(2, weight=1)

    def _do_browse() -> None:
        chosen = filedialog.askopenfilename(parent=frame, title="Select a PE file")
        if chosen:
            path_var.set(chosen)

    def _do_verify() -> None:
        path = path_var.get().strip()
        if not path:
            # Hint only: the result area keeps showing the last verify.
            status_var.set("enter a PE path first")
            return
        try:
            row = cli.verify_pe_row(client, path)
        except Exception as exc:
            status_var.set(f"verify failed: {exc}")
            return
        for name, value in row.items():
            result_vars[name].set(str(value))
        status_var.set(
            f"last verify: {row['path']} -> status={row['status']}"
            f" (source={row['source']})"
        )

    browse_btn = ttk.Button(toolbar, text="Browse...", command=_do_browse)
    browse_btn.grid(row=0, column=2, padx=2)
    verify_btn = ttk.Button(toolbar, text="Verify PE", command=_do_verify)
    verify_btn.grid(row=0, column=3, padx=2)

    # Named handles so tests (and future panes) can drive the panel
    # without traversing the widget tree.
    frame._path_var = path_var
    frame._path_entry = entry
    frame._browse_btn = browse_btn
    frame._verify_btn = verify_btn
    frame._result_vars = result_vars
    frame._status_var = status_var
    frame._catalog_note = note

    return frame


__all__ = ["_build_ui"]
