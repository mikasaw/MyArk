"""
actions module - plugin registration.
"""

from __future__ import annotations

from typing import Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration

from myark.modules.actions import cli


def register(
    client: Optional[ArkClient],
    capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    """Entry point for the ``myark.modules`` plugin group."""
    return ModuleRegistration(
        name="actions",
        register_fn=register,
        ui_factory=None,
        cli_setup=cli._setup_cli,
        description=(
            "actions module (Stage-5 mixed: 7 R0 IOCTLs gated by MYARK_SAFETY_TOKEN; "
            "kill/terminate-thread/inject-dll/dump-memory have R3 fallbacks, "
            "set-token/hide-process/protect-process are R0-only)"
        ),
        extra={"r3_primary": False, "tiered_degradation": True},
    )


__all__ = ["register"]