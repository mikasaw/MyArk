"""MyArk Network module: pure-R3 entry point (S5.2, quadrant ①).

This module exists entirely in R3 -- the driver is never touched. Every
operation maps directly onto the IP Helper API (iphlpapi.dll):

* ``myark.modules.network.protocol`` -- constants (TCP state names,
  column-width hints, the NO_IOCTL sentinel).
* ``myark.modules.network.parser``   -- ctypes mirrors of
  ``MIB_TCPROW_OWNER_PID`` / ``MIB_UDPROW_OWNER_PID`` plus byte-buffer
  parsers.
* ``myark.modules.network.cli``      -- ``myark-cli network {tcp-list,
  udp-list, tcp-by-pid}``.
* ``myark.modules.network.ui``       -- Tkinter tab for the network
  browser.

``register(client, capabilities)`` returns a :class:`ModuleRegistration`
and is called by ``myark._builtin_modules.iter_builtin_registrations`` at
startup. The driver-side handle (``client``) is unused here -- the
network module never sends an IOCTL -- so we accept it only to satisfy
the shared entry-point contract.
"""

from __future__ import annotations

from typing import Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration

from myark.modules.network import cli, ui


def register(
    _client: Optional[ArkClient],
    _capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    """Entry point for the ``myark.modules`` plugin group.

    The driver-side ``client`` and ``capabilities`` are intentionally
    ignored: the network module is pure R3 and never opens the driver.
    """
    return ModuleRegistration(
        name="network",
        register_fn=register,
        ui_factory=ui._build_ui,
        cli_setup=cli._setup_cli,
        description=(
            "Network module - pure-R3 TCP/UDP endpoint browser over "
            "GetExtendedTcpTable / GetExtendedUdpTable"
        ),
    )


__all__ = ["register"]