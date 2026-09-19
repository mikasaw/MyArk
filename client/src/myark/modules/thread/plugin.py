"""MyArk thread module: plugin entry point.

The driver-side R0 IOCTLs live in ``driver/src/modules/11_thread/`` and
the shared wire protocol in ``shared/driver/MyArkThreadIoctl.h``. The R3
fallback in ``parser`` covers every subcommand except ``crossview``,
which needs the kernel-side ETHREAD walk the driver performs.

``register(client, capabilities)`` returns a :class:`ModuleRegistration`
called by ``myark._builtin_modules.iter_builtin_registrations`` at
startup. The driver-side ``client`` is only used by ``crossview`` and
the explicit ``--method r0`` paths.
"""

from __future__ import annotations

from typing import Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration

from myark.modules.thread import cli, ui


def register(
    _client: Optional[ArkClient],
    _capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    """Entry point for the ``myark.modules`` plugin group."""
    return ModuleRegistration(
        name="thread",
        register_fn=register,
        ui_factory=ui._build_ui,
        cli_setup=cli._setup_cli,
        description=(
            "thread module - ETHREAD enumeration (R3 default) + "
            "crossview + terminate (R0 fallback)"
        ),
    )


__all__ = ["register"]