"""
wfp R3 - parser + R3 fallback.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Optional

from myark.client.ark_client import ArkClient, DriverError

from . import protocol as P


@dataclass
class CalloutEntry:
    callout_key: bytes = b"\x00" * 16
    applicable_layer: bytes = b"\x00" * 16
    flags: int = 0
    callout_name: str = ""


@dataclass
class WfpReport:
    count: int = 0
    callouts: list = None
    source: str = ""

    def __post_init__(self):
        if self.callouts is None:
            self.callouts = []


def _r3_fallback() -> WfpReport:
    return WfpReport(count=0, callouts=[], source="r3-fallback")


def _send_enumerate(client: Optional[ArkClient]) -> Optional[WfpReport]:
    if client is None:
        return None
    out_size = ctypes.sizeof(P.MYARK_WFP_ENUMERATE_CALLOUTS_OUTPUT)
    out_buf = (ctypes.c_ubyte * out_size)()
    try:
        bytes_returned = client.ioctl(
            P.IOCTL_MYARK_WFP_ENUMERATE_CALLOUTS, (ctypes.c_ubyte * 0)(), out_buf
        )
    except (DriverError, OSError):
        return None
    if bytes_returned < out_size:
        return None
    out = ctypes.cast(out_buf, ctypes.POINTER(P.MYARK_WFP_ENUMERATE_CALLOUTS_OUTPUT)).contents
    return WfpReport(count=out.Count, callouts=[], source="r0")


def enumerate_callouts(client: Optional[ArkClient]) -> WfpReport:
    r3 = _r3_fallback()
    r0 = _send_enumerate(client)
    return r0 if r0 is not None else r3


def add_callout(client: Optional[ArkClient], callout_key: bytes,
                layer_guid: bytes, flags: int) -> bool:
    """Mutating IOCTL: reserved for S7.3-fix. Returns False for S7.3."""
    return False


def remove_callout(client: Optional[ArkClient], callout_key: bytes) -> bool:
    """Mutating IOCTL: reserved for S7.3-fix. Returns False for S7.3."""
    return False


__all__ = [
    "CalloutEntry", "WfpReport",
    "enumerate_callouts", "add_callout", "remove_callout",
]


# ---------------------------------------------------------------------------
# R3-15: network-filter inventory (0x8A2 NDIS chain, 0x8A3 callout drivers).
# ---------------------------------------------------------------------------

@dataclass
class NdisFilterEntry:
    service_name: str = ""
    instance_guid: str = ""
    friendly_name: str = ""


@dataclass
class NdisFilterReport:
    count: int = 0
    filters: list = None

    def __post_init__(self):
        if self.filters is None:
            self.filters = []


@dataclass
class CalloutDriverEntry:
    image_base: int = 0
    image_size: int = 0
    flags: int = 0
    name: str = ""

    @property
    def wfp_capable(self) -> bool:
        return bool(self.flags & P.WFP_CDRIVER_FLAG_WFP_CAPABLE)

    @property
    def ndis_capable(self) -> bool:
        return bool(self.flags & P.WFP_CDRIVER_FLAG_NDIS_CAPABLE)


@dataclass
class CalloutDriverReport:
    count: int = 0
    total_seen: int = 0
    drivers: list = None

    def __post_init__(self):
        if self.drivers is None:
            self.drivers = []


def _decode(buf) -> str:
    return bytes(buf).split(b"\x00")[0].decode("utf-8", "replace")


def enum_ndis_filters(client: Optional[ArkClient]) -> NdisFilterReport:
    """0x8A2: every NDIS filter instance installed (NetService class)."""
    if client is None:
        return NdisFilterReport()
    out_size = ctypes.sizeof(P.MYARK_WFP_ENUM_NDIS_FILTERS_OUTPUT) \
        + (P.WFP_NDIS_HARD_CAP - 1) * ctypes.sizeof(P.MYARK_WFP_NDIS_FILTER_ENTRY)
    out_buf = (ctypes.c_ubyte * out_size)()
    try:
        bytes_returned = client.ioctl(
            P.IOCTL_MYARK_WFP_ENUM_NDIS_FILTERS, (ctypes.c_ubyte * 0)(), out_buf
        )
    except (DriverError, OSError):
        return NdisFilterReport()
    head = ctypes.sizeof(P.MYARK_WFP_ENUM_NDIS_FILTERS_OUTPUT)
    entry = ctypes.sizeof(P.MYARK_WFP_NDIS_FILTER_ENTRY)
    if bytes_returned < head:
        return NdisFilterReport()
    out = ctypes.cast(out_buf, ctypes.POINTER(P.MYARK_WFP_ENUM_NDIS_FILTERS_OUTPUT)).contents
    report = NdisFilterReport(count=out.Count)
    for i in range(min(out.Count, P.WFP_NDIS_HARD_CAP)):
        row = ctypes.cast(
            ctypes.addressof(out.Entries[0]) + i * entry,
            ctypes.POINTER(P.MYARK_WFP_NDIS_FILTER_ENTRY),
        ).contents
        report.filters.append(NdisFilterEntry(
            service_name=_decode(row.ServiceName),
            instance_guid=_decode(row.InstanceGuid),
            friendly_name=_decode(row.FriendlyName),
        ))
    return report


def enum_callout_drivers(client: Optional[ArkClient]) -> CalloutDriverReport:
    """0x8A3: loaded drivers whose PE imports reference fwpkclnt/ndis."""
    if client is None:
        return CalloutDriverReport()
    out_size = ctypes.sizeof(P.MYARK_WFP_ENUM_CALLOUT_DRIVERS_OUTPUT) \
        + (P.WFP_CDRIVER_HARD_CAP - 1) * ctypes.sizeof(P.MYARK_WFP_CALLOUT_DRIVER_ENTRY)
    out_buf = (ctypes.c_ubyte * out_size)()
    try:
        bytes_returned = client.ioctl(
            P.IOCTL_MYARK_WFP_ENUM_CALLOUT_DRIVERS, (ctypes.c_ubyte * 0)(), out_buf
        )
    except (DriverError, OSError):
        return CalloutDriverReport()
    head = ctypes.sizeof(P.MYARK_WFP_ENUM_CALLOUT_DRIVERS_OUTPUT)
    entry = ctypes.sizeof(P.MYARK_WFP_CALLOUT_DRIVER_ENTRY)
    if bytes_returned < head:
        return CalloutDriverReport()
    out = ctypes.cast(out_buf, ctypes.POINTER(P.MYARK_WFP_ENUM_CALLOUT_DRIVERS_OUTPUT)).contents
    report = CalloutDriverReport(count=out.Count, total_seen=out.TotalSeen)
    for i in range(min(out.Count, P.WFP_CDRIVER_HARD_CAP)):
        row = ctypes.cast(
            ctypes.addressof(out.Entries[0]) + i * entry,
            ctypes.POINTER(P.MYARK_WFP_CALLOUT_DRIVER_ENTRY),
        ).contents
        report.drivers.append(CalloutDriverEntry(
            image_base=row.ImageBase, image_size=row.ImageSize,
            flags=row.Flags, name=_decode(row.Name),
        ))
    return report


__all__ = [
    "CalloutEntry", "WfpReport",
    "enumerate_callouts", "add_callout", "remove_callout",
    "NdisFilterEntry", "NdisFilterReport", "CalloutDriverEntry",
    "CalloutDriverReport", "enum_ndis_filters", "enum_callout_drivers",
]
