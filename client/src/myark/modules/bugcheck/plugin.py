"""
bugcheck module - plugin registration.
"""

from __future__ import annotations

from typing import Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration

from myark.modules.bugcheck import cli


def register(
    client: Optional[ArkClient],
    capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    return ModuleRegistration(
        name="bugcheck",
        register_fn=register,
        ui_factory=None,
        cli_setup=cli._setup_cli,
        description=(
            "bugcheck module (R0 last-bugcheck query + SVGA render; "
            "QUERY stub for S7.3; RENDER_DIAG STATUS_NOT_IMPLEMENTED; "
            "2 IOCTLs: QUERY / RENDER_DIAG)"
        ),
        extra={"r0_only": True},
    )


__all__ = ["register"]
