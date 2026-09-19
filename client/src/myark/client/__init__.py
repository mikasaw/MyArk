"""User-mode side of the MyArk client.

Submodules:

- :mod:`myark.client.transport`  raw CreateFileW / DeviceIoControl wrappers
- :mod:`myark.client.ark_client` high-level ``ArkClient`` with typed methods
- :mod:`myark.client.driver_check` probe-only helper for the CLI / UI
- :mod:`myark.client.module_query` query-capabilities / query-modules wrappers
  used by :mod:`myark.plugin_loader`
"""

from .ark_client import (
    ArkClient,
    DriverCallError,
    DriverError,
    DriverNotInstalledError,
    open_driver,
    open_driver_or_null,
)
from .driver_check import (
    DriverProbe,
    driver_not_installed_message,
    probe_driver,
)

__all__ = [
    "ArkClient",
    "DriverCallError",
    "DriverError",
    "DriverNotInstalledError",
    "DriverProbe",
    "driver_not_installed_message",
    "open_driver",
    "open_driver_or_null",
    "probe_driver",
]