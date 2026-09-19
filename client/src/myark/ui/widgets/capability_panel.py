"""Sidebar panel listing every IOCTL the driver currently exposes.

Renders one row per entry from ``IOCTL_MYARK_CORE_QUERY_CAPABILITIES`` so the
user can see which capabilities are active in this driver build (the count
is a function of the build profile).
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Iterable

from ...client.module_query import CapabilityInfo
from .tree_table import TreeTable


class CapabilityPanel(ttk.LabelFrame):
    """Sidebar widget that renders a ``TreeTable`` of capabilities."""

    def __init__(self, parent: tk.Misc):
        super().__init__(parent, text="Capabilities", padding=(4, 2))
        self._table = TreeTable(
            self,
            columns=("ioctl_code", "name", "module_id"),
            height=18,
        )
        self._table.pack(fill=tk.BOTH, expand=True)

    def set_capabilities(self, capabilities: Iterable[CapabilityInfo]) -> None:
        rows = [
            (
                f"0x{c.ioctl_code:08X}",
                c.name,
                c.module_id,
            )
            for c in capabilities
        ]
        self._table.set_rows(rows)


__all__ = ["CapabilityPanel"]