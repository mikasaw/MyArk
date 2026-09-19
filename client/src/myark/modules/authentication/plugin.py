"""
authentication module - plugin registration.
"""

from __future__ import annotations

from typing import Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration

from myark.modules.authentication import cli


def register(
    client: Optional[ArkClient],
    capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    return ModuleRegistration(
        name="authentication",
        register_fn=register,
        ui_factory=None,
        cli_setup=cli._setup_cli,
        description=(
            "authentication module (R0 Authenticode stub returns NOT_SIGNED; "
            "R3 WinVerifyTrust is primary path; 1 IOCTL: VERIFY_FILE)"
        ),
        extra={"r3_primary": True},
    )


__all__ = ["register"]
