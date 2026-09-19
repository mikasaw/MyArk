"""Custom Tk widgets used by the main window.

Submodules:

- :mod:`myark.ui.widgets.tree_table`     sortable / filterable ``ttk.Treeview``
- :mod:`myark.ui.widgets.status_bar`     bottom status bar
- :mod:`myark.ui.widgets.capability_panel`  sidebar listing driver capabilities
- :mod:`myark.ui.widgets.actions_panel`  actions module IOCTL list (tab body)
- :mod:`myark.ui.widgets.r3_module_panel` generic protocol-mirror tab body
- :mod:`myark.ui.widgets.modules_panel`  top-of-window strip with module states
- :mod:`myark.ui.widgets.splitter`       ``ttk.PanedWindow`` with sash persistence
"""

from .actions_panel import ActionsPanel
from .capability_panel import CapabilityPanel
from .modules_panel import ModulesPanel
from .r3_module_panel import R3ModulePanel
from .splitter import MyArkSplitter
from .status_bar import StatusBar
from .tree_table import TreeTable

__all__ = [
    "ActionsPanel",
    "CapabilityPanel",
    "ModulesPanel",
    "R3ModulePanel",
    "MyArkSplitter",
    "StatusBar",
    "TreeTable",
]