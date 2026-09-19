"""
process module - R3 implementation (pure user-mode, no .sys)

Subcommands:
    enum / threads / detail / detail-runtime / terminate / suspend / resume /
    set-integrity / inject

R0-only placeholders (require the driver loaded):
    crossview / set-ppl / set-visibility / dkom / set-flags

⚠️  Cross-process operations need matching token + access rights; some
PPL / protected processes fail with ``AccessDeniedError`` even when
myark-cli runs as admin. The CLI handler prints a friendly error and
returns exit code 5 in that case.
"""
from __future__ import annotations

from typing import Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration

from myark.modules.process import cli, ui


def register(
    _client: Optional[ArkClient],
    _capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    """Entry point for the ``myark.modules`` plugin group.

    The driver-side ``client`` is unused: the process module is pure R3
    and never sends an IOCTL.
    """
    return ModuleRegistration(
        name="process",
        register_fn=register,
        ui_factory=ui._build_ui,
        cli_setup=cli._setup_cli,
        description=(
            "process module (R3: enum/threads/detail/terminate/suspend/"
            "resume/set-integrity/inject)"
        ),
        extra={"r3_only": True},
    )


__all__ = ["register"]