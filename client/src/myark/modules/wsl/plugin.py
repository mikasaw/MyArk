"""
wsl module - plugin registration.
"""

from __future__ import annotations

from typing import Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration

from myark.modules.wsl import cli


def register(
    client: Optional[ArkClient],
    capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    return ModuleRegistration(
        name="wsl",
        register_fn=register,
        ui_factory=None,
        cli_setup=cli._setup_cli,
        description=(
            "wsl module (R0 WSL silo enumeration; stub for S7.3; "
            "1 IOCTL: ENUMERATE_SILOS)"
        ),
        extra={"r0_only": True},
    )


__all__ = ["register"]
