"""
kernel_ext module - plugin registration.
"""

from __future__ import annotations

from typing import Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration

from myark.modules.kernel_ext import cli


def register(
    client: Optional[ArkClient],
    capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    return ModuleRegistration(
        name="kernel_ext",
        register_fn=register,
        ui_factory=None,
        cli_setup=cli._setup_cli,
        description=(
            "kernel_ext module (extends DynData; R3 NtQuerySystemInformation "
            "primary + R0 25H2 info class stub; 2 IOCTLs: QUERY_WIN11_INFO / "
            "READ_SYSCALL_TABLE)"
        ),
        extra={"r3_primary": True},
    )


__all__ = ["register"]
