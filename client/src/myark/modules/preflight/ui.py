"""preflight module: Tkinter UI for the S10.10 environment health panel.

Pure-R3 key/value grid over :func:`myark.modules.preflight.cli.health_rows`
-- the exact 6 rows ``myark-cli preflight health`` prints (os / testsigning
/ secure_boot / driver_signed / flags / source), so the tab and the CLI
always agree. The Refresh button re-queries; with the driver offline the
parser's R3 fallback still yields a real snapshot.

Booleans render as True/False, and ``testsigning=False`` carries the
bcdedit hint from VM_SETUP.md. The ``client`` handle may be ``None``
(R3-primary module) -- the panel builds from the fallback snapshot.
"""

from __future__ import annotations

import tkinter as tk
from datetime import datetime
from tkinter import ttk
from typing import Any, Optional

from myark.client.ark_client import ArkClient
from myark.modules.preflight.cli import health_rows
from myark.modules.preflight.parser import query_health


# Row order == health_rows order; the three bool fields render True/False.
ROW_KEYS: tuple[str, ...] = (
    "os", "testsigning", "secure_boot", "driver_signed", "flags", "source",
)
BOOL_KEYS = frozenset({"testsigning", "secure_boot", "driver_signed"})

TESTSIGNING_HINT = (
    "testsigning=False: 物理机需 bcdedit /set testsigning on, 详见 VM_SETUP.md"
)


def _format_value(key: str, value: object) -> str:
    """UI textual form of a health_rows value (booleans as True/False)."""
    if key in BOOL_KEYS:
        return "True" if value else "False"
    if key == "flags":
        return f"0x{value:X}"
    return str(value)


def _build_ui(parent: Any, client: Optional[ArkClient],
              safety_authority: Optional[Any] = None) -> ttk.Frame:
    """Build the preflight tab: a two-column key/value grid + Refresh.

    Read-only panel (no destructive surface), so ``safety_authority`` is
    accepted for the plugin contract and ignored.
    """
    value_vars = {key: tk.StringVar(value="-") for key in ROW_KEYS}
    hint_var = tk.StringVar(value="")
    status_var = tk.StringVar(value="(not refreshed yet)")

    frame = ttk.Frame(parent, padding=8)

    ttk.Label(
        frame,
        text="preflight module (R3 - environment health)",
        font=("Segoe UI", 12, "bold"),
    ).grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 4))
    ttk.Label(
        frame,
        text=(
            "Environment health snapshot -- the same 6 values as "
            "`myark-cli preflight health`. Works without the driver: "
            "the parser falls back to an R3-only probe."
        ),
        wraplength=600,
        justify=tk.LEFT,
    ).grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=(0, 8))

    toolbar = ttk.Frame(frame)
    toolbar.grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=(0, 8))

    # Two-column key/value grid -- same row rendering as
    # MainWindow._build_overview_tab (labels on purpose, no table).
    for row, key in enumerate(ROW_KEYS, start=3):
        ttk.Label(frame, text=f"{key}:", width=18, anchor=tk.W).grid(
            row=row, column=0, sticky=tk.W, pady=1
        )
        ttk.Label(frame, textvariable=value_vars[key], anchor=tk.W).grid(
            row=row, column=1, sticky=tk.W, pady=1
        )

    hint_row = len(ROW_KEYS) + 3
    ttk.Label(frame, textvariable=hint_var, foreground="#B26A00",
              wraplength=600, justify=tk.LEFT).grid(
        row=hint_row, column=0, columnspan=2, sticky=tk.W, pady=(8, 0)
    )
    ttk.Label(frame, textvariable=status_var, foreground="#888",
              anchor=tk.W).grid(
        row=hint_row + 1, column=0, columnspan=2, sticky=tk.W + tk.E,
        pady=(4, 0)
    )

    def _refresh() -> None:
        try:
            report = query_health(client)
        except Exception as exc:
            status_var.set(f"query_health failed: {exc}")
            return
        for key, value in health_rows(report):
            value_vars[key].set(_format_value(key, value))
        # VM_SETUP.md: the physical host must run testsigning ON for the
        # driver to load -- only the R0 overlay can ever report True.
        hint_var.set("" if report.is_test_signing else TESTSIGNING_HINT)
        stamp = datetime.now().strftime("%H:%M:%S")
        note = f" · {report.note}" if report.note else ""
        status_var.set(f"refreshed {stamp}{note}")

    ttk.Button(toolbar, text="Refresh", command=_refresh).pack(side=tk.LEFT)

    # Test/automation hook (R3ModulePanel tests reach into privates too):
    # keep the row vars and the re-query callable reachable without a
    # Tcl widget walk.
    frame._value_vars = value_vars  # type: ignore[attr-defined]
    frame._refresh = _refresh  # type: ignore[attr-defined]

    _refresh()  # populate on build -- the snapshot is cheap and read-only

    return frame


__all__ = ["_build_ui", "BOOL_KEYS", "ROW_KEYS", "TESTSIGNING_HINT"]
