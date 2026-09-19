"""
win32k module - plugin registration.
"""

from __future__ import annotations

from typing import Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration

from myark.modules.win32k import cli


def register(
    client: Optional[ArkClient],
    capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    return ModuleRegistration(
        name="win32k",
        register_fn=register,
        ui_factory=None,
        cli_setup=cli._setup_cli,
        description=(
            "win32k module (R0 GUI thread + syscall-table hook enum, both "
            "still S7.3 stubs; R3-10a USER handle table via gSharedInfo: "
            "windows/hooks/menus; 3 IOCTLs: ENUMERATE_GUI_THREADS / "
            "ENUMERATE_HOOKS / ENUM_USER_HANDLES)"
        ),
        extra={"r0_only": True, "read_only": True},
    )


__all__ = ["register"]
