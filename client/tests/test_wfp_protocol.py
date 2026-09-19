"""
wfp protocol ctypes layout tests.
"""

from __future__ import annotations

import ctypes

import pytest

from myark.modules.wfp import protocol as P


def test_ioctl_codes_match_kt():
    raw_e = 0x720
    raw_a = 0x721
    raw_r = 0x722
    expected_e = ((0x22 << 16) | (raw_e << 2) | 0) & 0xFFFFFFFF
    expected_a = ((0x22 << 16) | (raw_a << 2) | 0) & 0xFFFFFFFF
    expected_r = ((0x22 << 16) | (raw_r << 2) | 0) & 0xFFFFFFFF
    assert P.IOCTL_MYARK_WFP_ENUMERATE_CALLOUTS == expected_e
    assert P.IOCTL_MYARK_WFP_ADD_CALLOUT == expected_a
    assert P.IOCTL_MYARK_WFP_REMOVE_CALLOUT == expected_r


def test_constants():
    assert P.WFP_NAME_MAX == 64
    assert P.WFP_LAYER_GUID_MAX == 40
    assert P.WFP_CALLOUT_HARD_CAP == 128


def test_callout_entry_layout():
    e_size = ctypes.sizeof(P.MYARK_WFP_CALLOUT_ENTRY)
    # 16 + 16 + 4 + 4 + 64*2 = 168
    assert e_size == 168


def test_enumerate_callouts_output_layout():
    out_size = ctypes.sizeof(P.MYARK_WFP_ENUMERATE_CALLOUTS_OUTPUT)
    # 4 + 4 + 1 entry of 168 = 176
    assert out_size == 176


def test_op_input_layout():
    in_size = ctypes.sizeof(P.MYARK_WFP_CALLOUT_OP_INPUT)
    # 16 + 16 + 4 + 4 = 40
    assert in_size == 40


def test_struct_can_be_instantiated():
    e = P.MYARK_WFP_CALLOUT_ENTRY()
    e.CalloutKey = (ctypes.c_ubyte * 16)(*range(16))
    e.ApplicableLayer = (ctypes.c_ubyte * 16)(*range(16, 32))
    e.Flags = 0x4
    e.CalloutName = "FwpsCallout0"
    assert e.CalloutKey[0] == 0
    assert e.CalloutName == "FwpsCallout0"


def test_op_input_can_be_instantiated():
    i = P.MYARK_WFP_CALLOUT_OP_INPUT()
    i.CalloutKey = (ctypes.c_ubyte * 16)(*range(16))
    i.Flags = 0x1
    assert i.Flags == 0x1


def test_guid_sizes():
    e = P.MYARK_WFP_CALLOUT_ENTRY()
    assert len(e.CalloutKey) == 16
    assert len(e.ApplicableLayer) == 16


# ---------------------------------------------------------------------------
# R3-15: network-filter inventory (0x8A2 NDIS chain / 0x8A3 callout drivers).
# ---------------------------------------------------------------------------

def test_inventory_ioctl_codes():
    expected_a2 = ((0x22 << 16) | (0x8A2 << 2) | 0) & 0xFFFFFFFF
    expected_a3 = ((0x22 << 16) | (0x8A3 << 2) | 0) & 0xFFFFFFFF
    assert P.IOCTL_MYARK_WFP_ENUM_NDIS_FILTERS == expected_a2
    assert P.IOCTL_MYARK_WFP_ENUM_CALLOUT_DRIVERS == expected_a3


def test_inventory_struct_layouts():
    # Mirror of the C_ASSERTs in MyArkWfpIoctl.h.
    assert ctypes.sizeof(P.MYARK_WFP_NDIS_FILTER_ENTRY) == 168
    assert ctypes.sizeof(P.MYARK_WFP_CALLOUT_DRIVER_ENTRY) == 88
    assert ctypes.sizeof(P.MYARK_WFP_ENUM_NDIS_FILTERS_OUTPUT) == 184
    assert ctypes.sizeof(P.MYARK_WFP_ENUM_CALLOUT_DRIVERS_OUTPUT) == 112


def _fake_client(payload: bytes):
    """ArkClient stand-in returning *payload* from any ioctl()."""

    class _Fake:
        def ioctl(self, _code, _in_buf, out_buf):
            n = min(len(payload), len(out_buf))
            out_buf[:n] = payload[:n]
            return n

    return _Fake()


def test_enum_ndis_filters_parses_rows():
    from myark.modules.wfp import parser as W
    entry = P.MYARK_WFP_NDIS_FILTER_ENTRY()
    entry.ServiceName = b"wfplwfs"
    entry.InstanceGuid = b"{5F3CFA4C-8A1F-4DE3-9C5A-1234567890AB}"
    entry.FriendlyName = b"WFP 802.3"
    head = P.MYARK_WFP_ENUM_NDIS_FILTERS_OUTPUT()
    head.Count = 1
    head.EntryStructSize = 168
    head.Entries[0] = entry
    raw = bytes(head) + bytes(entry)
    report = W.enum_ndis_filters(_fake_client(raw))
    assert report.count == 1
    assert report.filters[0].service_name == "wfplwfs"
    assert report.filters[0].friendly_name == "WFP 802.3"
    assert report.filters[0].instance_guid.startswith("{")


def test_enum_callout_drivers_flags():
    from myark.modules.wfp import parser as W
    row = P.MYARK_WFP_CALLOUT_DRIVER_ENTRY()
    row.ImageBase = 0xFFFFF80000000000
    row.ImageSize = 0x40000
    row.Flags = P.WFP_CDRIVER_FLAG_WFP_CAPABLE | P.WFP_CDRIVER_FLAG_NDIS_CAPABLE
    row.Name = b"tcpip.sys"
    head = P.MYARK_WFP_ENUM_CALLOUT_DRIVERS_OUTPUT()
    head.Count = 1
    head.TotalSeen = 1
    head.EntryStructSize = 88
    head.PsLoadedModuleList = 0xFFFFF800000000
    head.Entries[0] = row
    raw = bytes(head) + bytes(row)
    report = W.enum_callout_drivers(_fake_client(raw))
    assert report.count == 1 and report.total_seen == 1
    assert report.drivers[0].name == "tcpip.sys"
    assert report.drivers[0].wfp_capable and report.drivers[0].ndis_capable


def test_inventory_error_paths_return_empty():
    from myark.modules.wfp import parser as W

    class _Boom:
        def ioctl(self, *_a):
            raise OSError("driver offline")

    assert W.enum_ndis_filters(_Boom()).count == 0
    assert W.enum_callout_drivers(_Boom()).count == 0
    assert W.enum_ndis_filters(None).count == 0
