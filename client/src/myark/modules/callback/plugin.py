"""
callback module - plugin registration.

The callback module is R0-only: every query turns into one DeviceIoControl
against ``\\\\.\\MyArkCore``. There is no R3 fallback (the kernel callback
arrays are not visible from R3 -- the entire point of Callback is to
surface them). When the driver is not installed the CLI / UI paths print
a friendly "driver not installed" message and exit / render gracefully.
"""

from __future__ import annotations

from typing import Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration

from myark.modules.callback import cli


def register(
    client: Optional[ArkClient],
    capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    """Entry point for the ``myark.modules`` plugin group."""
    return ModuleRegistration(
        name="callback",
        register_fn=register,
        ui_factory=None,                     # Callback module UI lands in a follow-up stage
        cli_setup=cli._setup_cli,
        description=(
            "callback module (R0: Ps/Cm/Ob/Image/Dbg callback enumeration; "
            "remove/restore/backup reserved for S7.2-fix)"
        ),
        extra={"r0_only": True},
    )


__all__ = ["register"]