"""
security-audit R3 - parser + IOCTL helpers.

Three IOCTLs: DEFENDER / SECURE_BOOT / TRUSTED_BOOT. When the driver
is not installed the R3 client overlays best-effort scaffolding readings
(bcdedit / WMI / EFI variable probes would be added in a follow-up).
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Optional

from myark.client.ark_client import ArkClient, DriverError

from . import protocol as P


@dataclass
class DefenderReport:
    is_installed: int = 0
    is_running: int = 0
    is_realtime_enabled: int = 0
    note: str = ""
    source: str = ""  # "r0" or "r3-fallback"


@dataclass
class SecureBootReport:
    is_enabled: int = 0
    note: str = ""
    source: str = ""


@dataclass
class TrustedBootReport:
    is_measured_boot_enabled: int = 0
    is_event_log_present: int = 0
    note: str = ""
    source: str = ""


def _send(client: Optional[ArkClient], ioctl_code: int, out_struct_type):
    if client is None:
        return None
    buf_size = ctypes.sizeof(out_struct_type)
    buf = (ctypes.c_ubyte * buf_size)()
    try:
        bytes_returned = client.ioctl(ioctl_code, None, buf)
    except (DriverError, OSError):
        return None
    if bytes_returned < buf_size:
        return None
    return ctypes.cast(buf, ctypes.POINTER(out_struct_type)).contents


def query_defender(client: Optional[ArkClient]) -> DefenderReport:
    out = _send(client, P.IOCTL_MYARK_SECURITY_AUDIT_DEFENDER, P.MYARK_SECURITY_AUDIT_DEFENDER_OUTPUT)
    if out is None:
        return DefenderReport(note="defender: R3 fallback (driver not installed)", source="r3-fallback")
    return DefenderReport(
        is_installed=out.IsInstalled,
        is_running=out.IsRunning,
        is_realtime_enabled=out.IsRealTimeProtectionEnabled,
        note=out.Note,
        source="r0",
    )


def query_secure_boot(client: Optional[ArkClient]) -> SecureBootReport:
    out = _send(client, P.IOCTL_MYARK_SECURITY_AUDIT_SECURE_BOOT, P.MYARK_SECURITY_AUDIT_SECURE_BOOT_OUTPUT)
    if out is None:
        return SecureBootReport(note="secure_boot: R3 fallback (driver not installed)", source="r3-fallback")
    return SecureBootReport(
        is_enabled=out.IsEnabled,
        note=out.Note,
        source="r0",
    )


def query_trusted_boot(client: Optional[ArkClient]) -> TrustedBootReport:
    out = _send(client, P.IOCTL_MYARK_SECURITY_AUDIT_TRUSTED_BOOT, P.MYARK_SECURITY_AUDIT_TRUSTED_BOOT_OUTPUT)
    if out is None:
        return TrustedBootReport(note="trusted_boot: R3 fallback (driver not installed)", source="r3-fallback")
    return TrustedBootReport(
        is_measured_boot_enabled=out.IsMeasuredBootEnabled,
        is_event_log_present=out.IsEventLogPresent,
        note=out.Note,
        source="r0",
    )


__all__ = [
    "DefenderReport",
    "SecureBootReport",
    "TrustedBootReport",
    "query_defender",
    "query_secure_boot",
    "query_trusted_boot",
]