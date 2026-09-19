"""
preflight module - plugin registration.

The preflight module is R3-primary: bcdedit + GetVersionEx + WMI for
driver signing state. The driver reports kernel base + size for R3 to
overlay. When neither is available we surface a "best-effort" R3-only
synthesized snapshot.
"""

from __future__ import annotations

from typing import Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration

from myark.modules.preflight import cli, ui


def register(
    client: Optional[ArkClient],
    capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    """Entry point for the ``myark.modules`` plugin group."""
    return ModuleRegistration(
        name="preflight",
        register_fn=register,
        ui_factory=ui._build_ui,             # S10.10: R3 environment health panel
        cli_setup=cli._setup_cli,
        description=(
            "preflight module (R3 bcdedit / RtlGetVersion + R0 kernel-base; "
            "single HEALTH IOCTL)"
        ),
        extra={"r3_primary": True},
    )


__all__ = ["register"]