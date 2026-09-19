"""
kernel_object module - plugin registration.
"""

from __future__ import annotations

from typing import Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration

from myark.modules.kernel_object import cli


def register(
    client: Optional[ArkClient],
    capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    return ModuleRegistration(
        name="kernel_object",
        register_fn=register,
        ui_factory=None,
        cli_setup=cli._setup_cli,
        description=(
            "kernel object module (R0 object-directory walk + named pipe / "
            "mailslot IPC summary; R3-4b; 2 IOCTLs: ENUM_DIRECTORY, "
            "IPC_SUMMARY)"
        ),
        extra={"r0_only": True},
    )


__all__ = ["register"]
