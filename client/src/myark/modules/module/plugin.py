"""
module R3 - plugin entry
"""

from __future__ import annotations

from typing import Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration

from myark.modules.module import cli, ui


def register(
    _client: Optional[ArkClient],
    _capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    """Entry point for the ``myark.modules`` plugin group."""
    return ModuleRegistration(
        name="module",
        register_fn=register,
        ui_factory=ui._build_ui,
        cli_setup=cli._setup_cli,
        description=(
            "module enumeration (R3 EnumProcessModules + GetModuleFileNameExW)"
        ),
        extra={"r3_only": True},
    )


__all__ = ["register"]