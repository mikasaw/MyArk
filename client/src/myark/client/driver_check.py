"""Driver-presence probe without taking a hard dependency on ``ArkClient``.

Used by both the CLI (``myark-cli driver check``) and the UI (status bar) to
decide whether to talk to the driver at all. ``probe_driver`` is intentionally
side-effect free: it opens a handle, asks for the version, and closes the
handle, returning a ``DriverProbe`` value object.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Optional

from ..protocol.core import (
    IOCTL_MYARK_CORE_GET_VERSION,
    MYARK_CORE_DEVICE_NAME,
    MYARK_CORE_VERSION_OUTPUT,
)
from . import transport


@dataclass
class DriverProbe:
    installed: bool
    device_path: str = MYARK_CORE_DEVICE_NAME
    error_code: Optional[int] = None
    version_output: Optional[MYARK_CORE_VERSION_OUTPUT] = None


def probe_driver() -> DriverProbe:
    """Try to open the driver and ask for its version.

    Returns a ``DriverProbe`` whose ``installed`` flag tells the caller whether
    to even attempt further IOCTLs. We never raise -- the CLI / UI want a
    structured result, not an exception.
    """
    handle: Optional[int] = None
    try:
        handle = transport.create_file(MYARK_CORE_DEVICE_NAME)
    except OSError as exc:
        return DriverProbe(installed=False, error_code=exc.errno)

    try:
        out = MYARK_CORE_VERSION_OUTPUT()
        _bytes, _ = transport.device_io_control(
            handle,
            IOCTL_MYARK_CORE_GET_VERSION,
            b"",
            ctypes.sizeof(out),
        )
        ctypes.memmove(ctypes.pointer(out), _bytes, ctypes.sizeof(out))
        return DriverProbe(installed=True, version_output=out)
    except OSError as exc:
        return DriverProbe(installed=True, error_code=exc.errno)
    finally:
        if handle is not None:
            transport.close_handle(handle)


def driver_not_installed_message() -> str:
    """The user-facing string the CLI / UI use when the driver is absent."""
    return f"driver not installed (expected device {MYARK_CORE_DEVICE_NAME})"


def is_admin() -> bool:
    """Return True when the current process runs with Administrator privileges.

    Wraps ``shell32.IsUserAnAdmin`` so the CLI can refuse to attempt driver
    load/start and the UI can show a "needs elevation" hint instead of a raw
    ``ERROR_ACCESS_DENIED`` from ``CreateFileW``. Returns False on any ctypes
    failure (DLL not loadable, exotic host) rather than raising -- callers
    only branch on the boolean.
    """
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


__all__ = ["DriverProbe", "probe_driver", "driver_not_installed_message", "is_admin"]