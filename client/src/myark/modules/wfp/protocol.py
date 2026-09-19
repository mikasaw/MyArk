"""
wfp R3 - protocol data structures.
"""

from __future__ import annotations

import ctypes

from myark.protocol.core import _ctl_code


IOCTL_MYARK_WFP_ENUMERATE_CALLOUTS = _ctl_code(0x720)
IOCTL_MYARK_WFP_ADD_CALLOUT = _ctl_code(0x721)
IOCTL_MYARK_WFP_REMOVE_CALLOUT = _ctl_code(0x722)


WFP_NAME_MAX = 64
WFP_LAYER_GUID_MAX = 40
WFP_CALLOUT_HARD_CAP = 128


class MYARK_WFP_CALLOUT_ENTRY(ctypes.Structure):
    _fields_ = [
        ("CalloutKey", ctypes.c_ubyte * 16),
        ("ApplicableLayer", ctypes.c_ubyte * 16),
        ("Flags", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("CalloutName", ctypes.c_wchar * WFP_NAME_MAX),
    ]


class MYARK_WFP_ENUMERATE_CALLOUTS_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Count", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Entries", MYARK_WFP_CALLOUT_ENTRY * 1),
    ]


class MYARK_WFP_CALLOUT_OP_INPUT(ctypes.Structure):
    _fields_ = [
        ("CalloutKey", ctypes.c_ubyte * 16),
        ("ApplicableLayer", ctypes.c_ubyte * 16),
        ("Flags", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
    ]


# ---------------------------------------------------------------------------
# R3-15 (2026-09-16): system network-filter inventory, read-only.
# Mirror of shared/driver/MyArkWfpIoctl.h 0x8A2/0x8A3.
# ---------------------------------------------------------------------------

IOCTL_MYARK_WFP_ENUM_NDIS_FILTERS = _ctl_code(0x8A2)
IOCTL_MYARK_WFP_ENUM_CALLOUT_DRIVERS = _ctl_code(0x8A3)

WFP_NDIS_NAME_MAX = 64
WFP_NDIS_GUID_MAX = 40
WFP_NDIS_HARD_CAP = 128
WFP_CDRIVER_NAME_MAX = 64
WFP_CDRIVER_HARD_CAP = 256

WFP_CDRIVER_FLAG_WFP_CAPABLE = 0x00000001
WFP_CDRIVER_FLAG_NDIS_CAPABLE = 0x00000002
WFP_CDRIVER_FLAG_PARSE_FAILED = 0x00000004


class MYARK_WFP_NDIS_FILTER_ENTRY(ctypes.Structure):
    _fields_ = [
        ("ServiceName", ctypes.c_char * WFP_NDIS_NAME_MAX),
        ("InstanceGuid", ctypes.c_char * WFP_NDIS_GUID_MAX),
        ("FriendlyName", ctypes.c_char * WFP_NDIS_NAME_MAX),
    ]


class MYARK_WFP_ENUM_NDIS_FILTERS_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Count", ctypes.c_uint32),
        ("EntryStructSize", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint32),
        ("Entries", MYARK_WFP_NDIS_FILTER_ENTRY * 1),
    ]


class MYARK_WFP_CALLOUT_DRIVER_ENTRY(ctypes.Structure):
    _fields_ = [
        ("ImageBase", ctypes.c_uint64),
        ("ImageSize", ctypes.c_uint64),
        ("Flags", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Name", ctypes.c_char * WFP_CDRIVER_NAME_MAX),
    ]


class MYARK_WFP_ENUM_CALLOUT_DRIVERS_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Count", ctypes.c_uint32),
        ("TotalSeen", ctypes.c_uint32),
        ("EntryStructSize", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("PsLoadedModuleList", ctypes.c_uint64),
        ("Entries", MYARK_WFP_CALLOUT_DRIVER_ENTRY * 1),
    ]


assert ctypes.sizeof(MYARK_WFP_NDIS_FILTER_ENTRY) == 168
assert ctypes.sizeof(MYARK_WFP_CALLOUT_DRIVER_ENTRY) == 88
assert ctypes.sizeof(MYARK_WFP_ENUM_NDIS_FILTERS_OUTPUT) == 184
assert ctypes.sizeof(MYARK_WFP_ENUM_CALLOUT_DRIVERS_OUTPUT) == 112
