"""
wfp module - plugin registration.
"""

from __future__ import annotations

from typing import Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration

from myark.modules.wfp import cli


def register(
    client: Optional[ArkClient],
    capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    return ModuleRegistration(
        name="wfp",
        register_fn=register,
        ui_factory=None,
        cli_setup=cli._setup_cli,
        description=(
            "wfp module (R0 WFP callout enum; ENUMERATE_CALLOUTS stub for "
            "S7.3; ADD/REMOVE reserved; 3 IOCTLs)"
        ),
        extra={"r0_only": True, "mutating_reserved": True},
    )


__all__ = ["register"]
