"""
trust module - plugin registration.
"""

from __future__ import annotations

from typing import Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration

from myark.modules.trust import cli, ui


def register(
    client: Optional[ArkClient],
    capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    return ModuleRegistration(
        name="trust",
        register_fn=register,
        ui_factory=ui._build_ui,   # S10.11: R3 verify-pe panel
        cli_setup=cli._setup_cli,
        description=(
            "trust module (R3 WinVerifyTrust is primary; R0 fallback returns "
            "not-signed for S7.3; 2 IOCTLs: VERIFY_PE / VERIFY_CATALOG)"
        ),
        extra={"r3_primary": True},
    )


__all__ = ["register"]