"""MyArk File module: pure-R3 entry point (S5.3, quadrant ①).

This module exists entirely in R3 -- the driver is never touched. Every
operation maps directly onto Win32 / Security APIs:

* ``myark.modules.file.protocol`` -- constants (FILE_ATTRIBUTE_* names,
  integrity-level names, NO_IOCTL sentinel).
* ``myark.modules.file.parser``   -- ctypes mirrors of
  ``WIN32_FILE_ATTRIBUTE_DATA`` + ACL/SID parsers + high-level entry
  points.
* ``myark.modules.file.cli``      -- ``myark-cli file {info, owner,
  dacl, integrity}``.
* ``myark.modules.file.ui``       -- Tkinter tab with a path entry +
  attribute table + SDDL panel.

``register(client, capabilities)`` returns a :class:`ModuleRegistration`
and is called by ``myark._builtin_modules.iter_builtin_registrations`` at
startup. The driver-side handle (``client``) is unused here -- the file
module never sends an IOCTL -- so we accept it only to satisfy the
shared entry-point contract.
"""

from __future__ import annotations

from typing import Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration

from myark.modules.file import cli, ui


def register(
    _client: Optional[ArkClient],
    _capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    """Entry point for the ``myark.modules`` plugin group.

    The driver-side ``client`` and ``capabilities`` are intentionally
    ignored: the file module is pure R3 and never opens the driver.
    """
    return ModuleRegistration(
        name="file",
        register_fn=register,
        ui_factory=ui._build_ui,
        cli_setup=cli._setup_cli,
        description=(
            "File module - pure-R3 file-attribute browser over "
            "GetFileAttributesEx / GetNamedSecurityInfo / SDDL"
        ),
    )


__all__ = ["register"]