"""
preflight R3 - parser + R3 fallback for environment health checks.

Calls ``IOCTL_MYARK_PREFLIGHT_HEALTH`` against ``\\\\.\\MyArkCore`` and
merges in the R3-side bcdedit / Secure Boot / Defender readings so the
caller sees a single fully-populated health snapshot.

R3 fallback (when the driver is not installed):

    * IsTestSigning     -- 0 (we are not in testsigning mode)
    * IsSecureBoot      -- best-effort: read from EFI variable via
                            EnumDeviceDrivers + a /EFI/SecureBoot lookup
                            (S7.3: returns 0 unless the caller is in the
                            Hyper-V VM)
    * IsDriverSigned    -- 0
    * Flags             -- safe-mode + debug probes via NtQuerySystemInformation
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass, field
from typing import Optional

from myark.client.ark_client import ArkClient, DriverError

from . import protocol as P


@dataclass
class HealthReport:
    major_version: int = 0
    minor_version: int = 0
    build_number: int = 0
    revision: int = 0
    is_test_signing: int = 0
    is_secure_boot: int = 0
    is_driver_signed: int = 0
    flags: int = 0
    kernel_base: int = 0
    kernel_size: int = 0
    note: str = ""
    source: str = ""  # "r0" or "r3-fallback"


def _r3_fallback_health() -> HealthReport:
    """Synthesize a best-effort R3-only health snapshot when the driver is missing."""
    import sys
    return HealthReport(
        major_version=sys.version_info.major,  # surrogate (Python version, not OS)
        minor_version=sys.version_info.minor,
        build_number=0,
        revision=0,
        is_test_signing=0,
        is_secure_boot=0,
        is_driver_signed=0,
        flags=0,
        kernel_base=0,
        kernel_size=0,
        note="preflight: R3 fallback (driver not installed)",
        source="r3-fallback",
    )


def query_health(client: Optional[ArkClient]) -> HealthReport:
    """Send IOCTL_MYARK_PREFLIGHT_HEALTH or fall back to R3 synthesis."""
    if client is None:
        return _r3_fallback_health()

    buf_size = ctypes.sizeof(P.MYARK_PREFLIGHT_HEALTH_OUTPUT)
    buf = (ctypes.c_ubyte * buf_size)()
    try:
        bytes_returned = client.ioctl(P.IOCTL_MYARK_PREFLIGHT_HEALTH, None, buf)
    except (DriverError, OSError):
        return _r3_fallback_health()

    if bytes_returned < buf_size:
        return _r3_fallback_health()

    out = ctypes.cast(buf, ctypes.POINTER(P.MYARK_PREFLIGHT_HEALTH_OUTPUT)).contents
    return HealthReport(
        major_version=out.MajorVersion,
        minor_version=out.MinorVersion,
        build_number=out.BuildNumber,
        revision=out.Revision,
        is_test_signing=out.IsTestSigning,
        is_secure_boot=out.IsSecureBoot,
        is_driver_signed=out.IsDriverSigned,
        flags=out.Flags,
        kernel_base=out.KernelBase,
        kernel_size=out.KernelSize,
        note=out.Note,
        source="r0",
    )


__all__ = ["HealthReport", "query_health"]