"""
redirect protocol ctypes layout tests.
"""

from __future__ import annotations

import ctypes

import pytest

from myark.modules.redirect import protocol as P


def test_ioctl_codes_match_kt():
    raw_i = 0x740
    raw_a = 0x741
    expected_i = ((0x22 << 16) | (raw_i << 2) | 0) & 0xFFFFFFFF
    expected_a = ((0x22 << 16) | (raw_a << 2) | 0) & 0xFFFFFFFF
    assert P.IOCTL_MYARK_REDIRECT_INSPECT == expected_i
    assert P.IOCTL_MYARK_REDIRECT_APPLY == expected_a


def test_constants():
    assert P.REDIRECT_NAME_MAX == 64
    assert P.REDIRECT_HARD_CAP == 64


def test_type_constants():
    assert P.REDIRECT_TYPE_NONE == 0
    assert P.REDIRECT_TYPE_IRP == 1
    assert P.REDIRECT_TYPE_CM == 2
    assert P.REDIRECT_TYPE_OB == 3


def test_inspect_input_layout():
    in_size = ctypes.sizeof(P.MYARK_REDIRECT_INSPECT_INPUT)
    assert in_size == 16


def test_redirect_entry_layout():
    e_size = ctypes.sizeof(P.MYARK_REDIRECT_ENTRY)
    # 8 + 8 + 4 + 4 + 64*2 = 152
    assert e_size == 152


def test_inspect_output_layout():
    out_size = ctypes.sizeof(P.MYARK_REDIRECT_INSPECT_OUTPUT)
    # 4 + 4 + 1 entry of 152 = 160
    assert out_size == 160


def test_apply_input_layout():
    in_size = ctypes.sizeof(P.MYARK_REDIRECT_APPLY_INPUT)
    # 8 + 8 + 4 + 4 = 24
    assert in_size == 24


def test_struct_can_be_instantiated():
    e = P.MYARK_REDIRECT_ENTRY()
    e.OriginalAddress = 0xFFFFF80000001000
    e.RedirectAddress = 0xFFFFF80012345000
    e.RedirectType = P.REDIRECT_TYPE_IRP
    e.DriverName = "\\Driver\\Evil"
    assert e.RedirectType == 1
    assert e.DriverName == "\\Driver\\Evil"
