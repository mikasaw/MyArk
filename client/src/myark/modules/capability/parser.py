"""
capability R3 - parser / IOCTL helpers.

Calls ``IOCTL_MYARK_CAPABILITY_REPORT`` against ``\\\\.\\MyArkCore`` and
parses the variable-length header + entries into a Python dataclass.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass, field
from typing import List

from myark.client.ark_client import ArkClient, DriverError

from . import protocol as P


_DEFAULT_CAPABILITY_ENTRIES = 64


@dataclass
class CapabilityEntry:
    module_id: int = 0
    ioctl_count: int = 0
    flags: int = 0
    module_name: str = ""


@dataclass
class CapabilityReport:
    version_major: int = 0
    version_minor: int = 0
    version_build: int = 0
    total_modules: int = 0
    total_ioctls: int = 0
    entries: List[CapabilityEntry] = field(default_factory=list)


def query_report(client: ArkClient, max_entries: int = _DEFAULT_CAPABILITY_ENTRIES) -> CapabilityReport:
    """Send IOCTL_MYARK_CAPABILITY_REPORT and return the parsed report."""
    if max_entries <= 0:
        max_entries = _DEFAULT_CAPABILITY_ENTRIES

    buf_size = P.capability_report_buffer_size(max_entries)
    buf = (ctypes.c_ubyte * buf_size)()
    bytes_returned = client.ioctl(P.IOCTL_MYARK_CAPABILITY_REPORT, None, buf)

    out = ctypes.cast(buf, ctypes.POINTER(P.MYARK_CAPABILITY_REPORT_OUTPUT)).contents
    entries_size = bytes_returned - P.HEADER_SIZE_CAPABILITY_REPORT
    if entries_size < 0:
        raise DriverError(f"capability: malformed reply ({bytes_returned} bytes)")

    entry_size = ctypes.sizeof(P.MYARK_CAPABILITY_MODULE_ENTRY)
    count = entries_size // entry_size
    if count > max_entries:
        count = max_entries

    report = CapabilityReport(
        version_major=out.DriverVersionMajor,
        version_minor=out.DriverVersionMinor,
        version_build=out.DriverVersionBuild,
        total_modules=out.TotalModules,
        total_ioctls=out.TotalIoctls,
        entries=[],
    )

    raw_entries = ctypes.cast(
        ctypes.addressof(out) + P.HEADER_SIZE_CAPABILITY_REPORT,
        ctypes.POINTER(P.MYARK_CAPABILITY_MODULE_ENTRY * count),
    ).contents

    for i in range(count):
        e = raw_entries[i]
        report.entries.append(
            CapabilityEntry(
                module_id=e.ModuleId,
                ioctl_count=e.IoctlCount,
                flags=e.Flags,
                module_name=e.ModuleName,
            )
        )

    return report


__all__ = ["CapabilityEntry", "CapabilityReport", "query_report"]