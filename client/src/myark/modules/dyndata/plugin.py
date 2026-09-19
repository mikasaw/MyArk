"""
dyndata module - plugin registration.

The dyndata module is R0-only: every query turns into one DeviceIoControl
against ``\\\\.\\MyArkCore``. There is no R3 fallback (the entire point
of DynData is to surface build-specific kernel data structures that R3
can't see). When the driver is not installed the CLI / UI paths print a
friendly "driver not installed" message and exit / render gracefully.
"""

from __future__ import annotations

from typing import Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration

from myark.modules.dyndata import cli


def register(
    client: Optional[ArkClient],
    capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    """Entry point for the ``myark.modules`` plugin group."""
    return ModuleRegistration(
        name="dyndata",
        register_fn=register,
        ui_factory=None,                     # DynData feeds other modules; no standalone tab yet
        cli_setup=cli._setup_cli,
        description=(
            "dyndata module (R0: NtQuerySystemInformation-style: process / "
            "thread / module / handle / file / syscall / token / object / ssdt)"
        ),
        extra={"r0_only": True},
    )


__all__ = ["register"]
