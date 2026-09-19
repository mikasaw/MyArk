"""
mutation module - plugin registration.
"""

from __future__ import annotations

from typing import Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration

from myark.modules.mutation import cli


def register(
    client: Optional[ArkClient],
    capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    return ModuleRegistration(
        name="mutation",
        register_fn=register,
        ui_factory=None,
        cli_setup=cli._setup_cli,
        description=(
            "mutation module (R0 EPROCESS Token inspection; INSPECT_TOKEN "
            "stub for S7.3; SET_TOKEN STATUS_NOT_IMPLEMENTED; 2 IOCTLs)"
        ),
        extra={"r0_only": True, "mutating_reserved": True},
    )


__all__ = ["register"]
