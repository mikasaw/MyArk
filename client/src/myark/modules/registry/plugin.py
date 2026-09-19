"""MyArk Registry module: pure-R3 entry point (S5.1, quadrant ①).

This module exists entirely in R3 -- the driver is never touched. Every
operation maps directly onto the standard-library :mod:`winreg` API:

* ``myark.modules.registry.protocol`` -- constants (hive prefixes, type names).
* ``myark.modules.registry.parser``  -- path / value-name / value-type parsers.
* ``myark.modules.registry.cli``     -- ``myark-cli registry {list, read, ...}``.
* ``myark.modules.registry.ui``      -- Tkinter tab for the registry browser.

``register(client, capabilities)`` returns a :class:`ModuleRegistration`
and is called by ``myark._builtin_modules.iter_builtin_registrations`` at
startup. The driver-side handle (``client``) is unused here -- the
registry module never sends an IOCTL -- so we accept it only to satisfy
the shared entry-point contract.
"""

from __future__ import annotations

from typing import Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration

from myark.modules.registry import cli, ui


def register(
    _client: Optional[ArkClient],
    _capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    """Entry point for the ``myark.modules`` plugin group.

    The driver-side ``client`` and ``capabilities`` are intentionally
    ignored: the registry module is pure R3 and never opens the driver.
    """
    return ModuleRegistration(
        name="registry",
        register_fn=register,
        ui_factory=ui._build_ui,
        cli_setup=cli._setup_cli,
        description=(
            "Registry module - pure-R3 browser over winreg "
            "(list / read / write / delete-value / delete-key)"
        ),
    )


__all__ = ["register"]