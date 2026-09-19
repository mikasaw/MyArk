"""
hwid protocol ctypes layout tests.
"""

from __future__ import annotations

import ctypes

import pytest

from myark.modules.hwid import protocol as P


def test_ioctl_codes_match_kt():
    raw_e = 0x750
    raw_r = 0x751
    expected_e = ((0x22 << 16) | (raw_e << 2) | 0) & 0xFFFFFFFF
    expected_r = ((0x22 << 16) | (raw_r << 2) | 0) & 0xFFFFFFFF
    assert P.IOCTL_MYARK_HWID_ENUMERATE_MJ == expected_e
    assert P.IOCTL_MYARK_HWID_REPLACE_MJ == expected_r


def test_constants():
    assert P.HWID_NAME_MAX == 64
    assert P.HWID_MJ_COUNT == 28
    assert P.HWID_HARD_CAP == 64


def test_input_struct_layout():
    in_size = ctypes.sizeof(P.MYARK_HWID_ENUMERATE_MJ_INPUT)
    assert in_size == 16  # 4 + 4 + 8


def test_mj_entry_struct_layout():
    e_size = ctypes.sizeof(P.MYARK_HWID_MJ_ENTRY)
    # 64*2 (DriverName) + 28*8 (MajorFunction) = 128 + 224 = 352
    assert e_size == 352


def test_enumerate_mj_output_layout():
    out_size = ctypes.sizeof(P.MYARK_HWID_ENUMERATE_MJ_OUTPUT)
    # 4+4 + 1 entry of 352 = 360
    assert out_size == 360


def test_replace_mj_input_layout():
    in_size = ctypes.sizeof(P.MYARK_HWID_REPLACE_MJ_INPUT)
    # 64*2 (DriverName) + 4 (MajorFunctionCode) + 8 (NewAddress) = 144
    assert in_size == 144


def test_struct_can_be_instantiated():
    e = P.MYARK_HWID_ENUMERATE_MJ_INPUT()
    e.DriverIndexHint = 0
    assert e.DriverIndexHint == 0

    r = P.MYARK_HWID_REPLACE_MJ_INPUT()
    r.DriverName = "\\Driver\\MyArkCore"
    r.MajorFunctionCode = 14  # IRP_MJ_DEVICE_CONTROL
    r.NewAddress = 0xFFFFF80001234000
    assert r.MajorFunctionCode == 14
    assert r.NewAddress == 0xFFFFF80001234000


def test_mj_entry_has_28_function_slots():
    e = P.MYARK_HWID_MJ_ENTRY()
    assert len(e.MajorFunction) == 28
