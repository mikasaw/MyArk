"""
redirect module - plugin registration.
"""

from __future__ import annotations

from typing import Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration

from myark.modules.redirect import cli


def register(
    client: Optional[ArkClient],
    capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    return ModuleRegistration(
        name="redirect",
        register_fn=register,
        ui_factory=None,
        cli_setup=cli._setup_cli,
        description=(
            "redirect module (R0 IoCallDriver / CmCallback redirect "
            "inspection; INSPECT stub for S7.3; APPLY reserved; 2 IOCTLs)"
        ),
        extra={"r0_only": True, "mutating_reserved": True},
    )


__all__ = ["register"]
