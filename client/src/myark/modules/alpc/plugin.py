"""
alpc module - plugin registration.
"""

from __future__ import annotations

from typing import Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration

from myark.modules.alpc import cli


def register(
    client: Optional[ArkClient],
    capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    return ModuleRegistration(
        name="alpc",
        register_fn=register,
        ui_factory=None,
        cli_setup=cli._setup_cli,
        description=(
            "alpc module (R0 ALPC port enumeration; ENUMERATE_PORTS stub "
            "for S7.3; 2 IOCTLs: ENUMERATE_PORTS / CLOSE_PORT)"
        ),
        extra={"r0_only": True, "mutating_reserved": True},
    )


__all__ = ["register"]
