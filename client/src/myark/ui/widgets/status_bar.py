"""Bottom status bar: driver state + module count + row count + log tail."""

from __future__ import annotations

import time
import tkinter as tk
from tkinter import ttk
from typing import Optional


class StatusBar(ttk.Frame):
    """Four-segment status bar pinned to the bottom of the main window.

    Segments left-to-right:

    1. driver state           -- ``driver: ok (...)`` / ``driver: not installed``
    2. module count           -- ``modules: 5/8`` (enabled / total)
    3. row count / selected   -- ``rows: 231 selected: 0``
    4. last refresh timestamp + free-form message

    The free-form message is the only segment that is allowed to overflow
    with arbitrary status text; the others are intentionally short.
    """

    def __init__(self, parent: tk.Misc):
        super().__init__(parent, relief=tk.SUNKEN, padding=(6, 2))
        self._var_driver = tk.StringVar(value="driver: unknown")
        self._var_modules = tk.StringVar(value="modules: 0/0")
        self._var_rows = tk.StringVar(value="rows: 0")
        self._var_message = tk.StringVar(value="")

        ttk.Label(self, textvariable=self._var_driver, width=28, anchor=tk.W).pack(side=tk.LEFT)
        ttk.Separator(self, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=4)
        ttk.Label(self, textvariable=self._var_modules, width=20, anchor=tk.W).pack(side=tk.LEFT)
        ttk.Separator(self, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=4)
        ttk.Label(self, textvariable=self._var_rows, width=24, anchor=tk.W).pack(side=tk.LEFT)
        ttk.Separator(self, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=4)
        ttk.Label(self, textvariable=self._var_message, anchor=tk.W).pack(
            side=tk.LEFT, fill=tk.X, expand=True
        )

    # ------------------------------------------------------ public setters

    def set_driver(self, installed: bool, version: Optional[str] = None) -> None:
        if installed:
            text = f"driver: ok ({version})" if version else "driver: ok"
        else:
            text = "driver: not installed"
        self._var_driver.set(text)

    def set_module_count(self, enabled: int, total: int) -> None:
        self._var_modules.set(f"modules: {enabled}/{total}")

    def set_rows(self, total: int, selected: int = 0) -> None:
        if selected:
            self._var_rows.set(f"rows: {total}  selected: {selected}")
        else:
            self._var_rows.set(f"rows: {total}")

    def set_refresh_time(self, when: Optional[float] = None) -> None:
        ts = time.strftime("%H:%M:%S", time.localtime(when or time.time()))
        # The refresh timestamp rides along with the free-form message so
        # we never overwrite an existing one with a stale display.
        existing = self._var_message.get()
        prefix = f"@ {ts}  "
        if existing.startswith("@ "):
            self._var_message.set(prefix + existing.split("  ", 1)[-1])
        else:
            self._var_message.set(prefix + existing)

    def set_message(self, message: str) -> None:
        self._var_message.set(message)

    def clear_message(self) -> None:
        self._var_message.set("")


__all__ = ["StatusBar"]