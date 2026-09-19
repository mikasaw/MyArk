"""
hwid module - plugin registration.
"""

from __future__ import annotations

from typing import Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration

from myark.modules.hwid import cli


def register(
    client: Optional[ArkClient],
    capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    return ModuleRegistration(
        name="hwid",
        register_fn=register,
        ui_factory=None,
        cli_setup=cli._setup_cli,
        description=(
            "hwid module (R0 MajorFunction inspection; ENUMERATE_MJ stub for "
            "S7.3; 2 IOCTLs: ENUMERATE_MJ / REPLACE_MJ)"
        ),
        extra={"r0_only": True, "mutating_reserved": True},
    )


__all__ = ["register"]
