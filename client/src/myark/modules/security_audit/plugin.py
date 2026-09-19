"""
security-audit module - plugin registration.
"""

from __future__ import annotations

from typing import Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration

from myark.modules.security_audit import cli, ui


def register(
    client: Optional[ArkClient],
    capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    return ModuleRegistration(
        name="security_audit",
        register_fn=register,
        ui_factory=ui._build_ui,
        cli_setup=cli._setup_cli,
        description=(
            "security-audit module (R3 WMI/bcdedit/EFI + R0 scaffolding; "
            "3 IOCTLs: DEFENDER / SECURE_BOOT / TRUSTED_BOOT)"
        ),
        extra={"r3_primary": True},
    )


__all__ = ["register"]