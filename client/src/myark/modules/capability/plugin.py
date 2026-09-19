"""
capability module - plugin registration.

The capability module is R0-only: the driver self-reports its feature
list (modules, IOCTL counts, version) so the R3 client can render a
"what does this build support" view without probing each IOCTL code
individually. When the driver is not installed the CLI / UI paths print
a friendly "driver not installed" message and exit / render gracefully.
"""

from __future__ import annotations

from typing import Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration

from myark.modules.capability import cli


def register(
    client: Optional[ArkClient],
    capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    """Entry point for the ``myark.modules`` plugin group."""
    return ModuleRegistration(
        name="capability",
        register_fn=register,
        ui_factory=None,
        cli_setup=cli._setup_cli,
        description=(
            "capability module (R0: driver self-reported capability table -- "
            "version + modules + IOCTL counts)"
        ),
        extra={"r0_only": True},
    )


__all__ = ["register"]