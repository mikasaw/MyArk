"""Generic tab body for R3 modules without a dedicated UI widget.

Most in-tree modules register with ``ui_factory=None`` until their stage
ships a bespoke tab; :class:`R3ModulePanel` gives every one of them a
useful tab instead of the old "no UI shipped yet" placeholder. It lists
the module's IOCTL surface: one row per ``QUERY_CAPABILITIES`` entry
belonging to the module once MyArkCore.sys is loaded, falling back to
the module's ctypes protocol mirror (``myark.modules.<name>.protocol``)
while the driver is offline. The ``source`` column tells the two apart.

Row names come straight from the protocol-header constant names
(``IOCTL_MYARK_CALLBACK_STATS`` &c.) -- the same strings the driver
reports as capability ``Name`` -- so driver and builtin rows render
identically apart from their ``source`` value. While that fallback
list is showing, a gray note above the table spells out that the rows
are IOCTL *definitions*, not live query results (S10.13).
"""

from __future__ import annotations

import importlib
import tkinter as tk
from tkinter import ttk
from typing import Iterable, Optional

from ...client.module_query import CapabilityInfo
from .tree_table import TreeTable


def protocol_mirror_ioctls(module_name: str) -> tuple[tuple[int, str], ...]:
    """Collect ``(ioctl_code, constant_name)`` from a module's protocol mirror.

    ``myark.modules.<name>.protocol`` mirrors the module's shared driver
    header, so its module-level ``IOCTL_MYARK_*`` constants are the
    authoritative offline list. Returns an empty tuple when the module
    ships no mirror. Sorted by IOCTL function-code order.
    """
    pkg = module_name.replace("-", "_")
    try:
        mirror = importlib.import_module(f"myark.modules.{pkg}.protocol")
    except ImportError:
        return ()
    pairs = [
        (int(value), name)
        for name, value in vars(mirror).items()
        if name.startswith("IOCTL_MYARK_") and isinstance(value, int)
    ]
    pairs.sort()
    return tuple(pairs)


class R3ModulePanel(ttk.LabelFrame):
    """Widget that renders a ``TreeTable`` of any module's IOCTL surface."""

    def __init__(self, parent: tk.Misc, module_name: str,
                 module_id: Optional[int] = None):
        super().__init__(parent, text=module_name, padding=(4, 2))
        self._module_name = module_name
        self._module_id = module_id
        self._builtin = protocol_mirror_ioctls(module_name)

        self._table = TreeTable(
            self,
            columns=("ioctl_code", "name", "source"),
            height=14,
        )
        self._table.pack(fill=tk.BOTH, expand=True)
        self._table.tree.bind("<Button-3>", self._on_context_menu)

        # S10.13: shown only while the builtin fallback list renders
        # (packed above the table on demand); hidden once driver rows
        # arrive so the note never claims live data is static.
        self._offline_note = ttk.Label(
            self,
            text="当前为协议 IOCTL 清单 (非实时数据)。"
                 "此模块需 MyArkCore.sys 在线才显示实时结果, 安装见 VM_SETUP.md。",
            foreground="#888",
        )

        count = len(self._builtin)
        mirror_note = f"{count} IOCTLs" if count else "unavailable"
        self._mirror_var = tk.StringVar(value=f"protocol mirror: {mirror_note}")
        ttk.Label(self, textvariable=self._mirror_var, foreground="#888").pack(
            anchor=tk.W
        )

    def set_capabilities(self, capabilities: Iterable[CapabilityInfo]) -> None:
        """Render one row per capability belonging to this module.

        Entries are accepted when their ``module_id`` matches the
        constructor value (the ``QUERY_MODULES``-derived id) or their
        IOCTL code appears in the protocol mirror -- IOCTL codes are
        globally unique, so either test identifies the module. When no
        entry survives (driver offline), fall back to the static mirror
        so the list stays useful, and show the S10.13 offline note above
        the table until real driver rows arrive.
        """
        builtin_codes = {code for code, _ in self._builtin}
        rows = [
            (f"0x{c.ioctl_code:08X}", c.name, "driver")
            for c in capabilities
            if (self._module_id is not None and c.module_id == self._module_id)
            or c.ioctl_code in builtin_codes
        ]
        if not rows:
            rows = [
                (f"0x{code:08X}", name, "builtin")
                for code, name in self._builtin
            ]
            self._offline_note.pack(anchor=tk.W, before=self._table)
        else:
            self._offline_note.pack_forget()
            rows.sort(key=lambda r: int(r[0], 16))
        self._table.set_rows(rows)

    # ----------------------------------------------------------- context menu

    def _on_context_menu(self, event) -> Optional[str]:
        """Right-click on a row: copy its IOCTL code / constant name."""
        item = self._table.tree.identify_row(event.y)
        if not item:
            return None
        self._table.tree.selection_set(item)
        values = tuple(str(v) for v in self._table.tree.item(item, "values"))
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(
            label="Copy IOCTL code",
            command=lambda: self.copy_text(values[0]),
        )
        menu.add_command(
            label="Copy name",
            command=lambda: self.copy_text(values[1]),
        )
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()
        return None

    def copy_text(self, text: str) -> None:
        """Best-effort clipboard write (Tk has no way to report failure)."""
        self.clipboard_clear()
        self.clipboard_append(text)


__all__ = ["R3ModulePanel", "protocol_mirror_ioctls"]
