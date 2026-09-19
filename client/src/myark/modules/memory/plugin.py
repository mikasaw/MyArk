"""
memory module - R3 implementation (pure user-mode for read/write/query)

Subcommands:
    read / write / query   -- R3 EnumProcessModules + Read/WriteProcessMemory
    translate / scan       -- R0-only placeholders

⚠️  Cross-process Read/WriteProcessMemory need matching token + access
rights; some PPL / protected processes fail with ``AccessDeniedError``
even when myark-cli runs as admin.
"""

from __future__ import annotations

from typing import Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration

from myark.modules.memory import cli, ui


def register(
    _client: Optional[ArkClient],
    _capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    """Entry point for the ``myark.modules`` plugin group."""
    return ModuleRegistration(
        name="memory",
        register_fn=register,
        ui_factory=ui._build_ui,    # R3 Tab: EnumProcessModules regions
        cli_setup=cli._setup_cli,
        description=(
            "memory module (R3: read/write/query; R0-only: translate/scan)"
        ),
        extra={"r3_only": True},
    )


__all__ = ["register"]