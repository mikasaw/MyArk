"""Center-tab panel listing the ``actions`` module's IOCTL surface.

One row per actions IOCTL (``MyArkActionsIoctl.h`` / its ctypes mirror in
:mod:`myark.modules.actions.protocol`). Rows come from
``IOCTL_MYARK_CORE_QUERY_CAPABILITIES`` filtered to ``module_id == 'ACTN'``
once MyArkCore.sys is loaded; while the driver is offline the panel falls
back to the static protocol mirror so the tab still documents the full
action set instead of an empty table. The ``source`` column tells the two
apart.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Iterable, Optional

from ...client.module_query import CapabilityInfo
from ...modules.actions.protocol import (
    ACTIONS_IOCTL_FUNCTIONS,
    IOCTL_MYARK_ACTION_DUMP_MEMORY,
    IOCTL_MYARK_ACTION_HIDE_PROCESS,
    IOCTL_MYARK_ACTION_INJECT_DLL,
    IOCTL_MYARK_ACTION_KILL_PROCESS,
    IOCTL_MYARK_ACTION_PROTECT_PROCESS,
    IOCTL_MYARK_ACTION_SET_TOKEN,
    IOCTL_MYARK_ACTION_TERMINATE_THREAD,
    MYARK_ACTIONS_MODULE_ID,
)
from .tree_table import TreeTable

# Static mirror of the driver's actions capability list, keyed in IOCTL
# function-code order (0x870..0x876). Used when QUERY_CAPABILITIES is not
# available or reports no actions entries yet.
_BUILTIN_ACTIONS = (
    ("kill_process", IOCTL_MYARK_ACTION_KILL_PROCESS),
    ("terminate_thread", IOCTL_MYARK_ACTION_TERMINATE_THREAD),
    ("inject_dll", IOCTL_MYARK_ACTION_INJECT_DLL),
    ("dump_memory", IOCTL_MYARK_ACTION_DUMP_MEMORY),
    ("set_token", IOCTL_MYARK_ACTION_SET_TOKEN),
    ("hide_process", IOCTL_MYARK_ACTION_HIDE_PROCESS),
    ("protect_process", IOCTL_MYARK_ACTION_PROTECT_PROCESS),
)

assert len(_BUILTIN_ACTIONS) == len(ACTIONS_IOCTL_FUNCTIONS)


class ActionsPanel(ttk.LabelFrame):
    """Widget that renders a ``TreeTable`` of the actions module's IOCTLs."""

    def __init__(self, parent: tk.Misc):
        super().__init__(parent, text="Actions", padding=(4, 2))
        self._table = TreeTable(
            self,
            columns=("ioctl_code", "name", "source"),
            height=14,
        )
        self._table.pack(fill=tk.BOTH, expand=True)
        self._table.tree.bind("<Button-3>", self._on_context_menu)

    def set_capabilities(self, capabilities: Iterable[CapabilityInfo]) -> None:
        """Render one row per actions capability.

        Entries whose ``module_id`` differs from ``'ACTN'`` are ignored,
        so callers may pass the unfiltered ``QUERY_CAPABILITIES`` result.
        When no actions entry survives the filter (driver offline), fall
        back to the static protocol mirror so the list stays useful.
        """
        rows = [
            (f"0x{c.ioctl_code:08X}", c.name, "driver")
            for c in capabilities
            if c.module_id == MYARK_ACTIONS_MODULE_ID
        ]
        if not rows:
            rows = [
                (f"0x{code:08X}", name, "builtin")
                for name, code in _BUILTIN_ACTIONS
            ]
        else:
            rows.sort(key=lambda r: int(r[0], 16))
        self._table.set_rows(rows)

    # ----------------------------------------------------------- context menu

    def _on_context_menu(self, event) -> Optional[str]:
        """Right-click on a row: copy its IOCTL code / action name."""
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


__all__ = ["ActionsPanel"]
