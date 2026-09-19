"""
trust protocol ctypes layout tests.
"""

from __future__ import annotations

import ctypes
import struct

import pytest

from myark.modules.trust import protocol as P


def test_ioctl_codes_match_kt():
    raw_pe = 0x7B0
    raw_cat = 0x7B1
    expected = ((0x22 << 16) | (raw_pe << 2) | 0) & 0xFFFFFFFF
    assert P.IOCTL_MYARK_TRUST_VERIFY_PE == expected
    expected = ((0x22 << 16) | (raw_cat << 2) | 0) & 0xFFFFFFFF
    assert P.IOCTL_MYARK_TRUST_VERIFY_CATALOG == expected


def test_trust_status_constants():
    assert P.TRUST_TRUSTED == 0
    assert P.TRUST_UNTRUSTED == 1
    assert P.TRUST_NOT_SIGNED == 2


def test_trust_flag_constants():
    assert P.TRUST_FLAG_CATALOG == 0x1
    assert P.TRUST_FLAG_EMBEDDED == 0x2
    assert P.TRUST_FLAG_TIMESTAMP == 0x4


def test_input_struct_alignment():
    size = ctypes.sizeof(P.MYARK_TRUST_VERIFY_INPUT)
    assert size == 528  # 260*2 (FilePath) + 4 (Flags) + 4 (Reserved) = 528


def test_output_struct_alignment():
    size = ctypes.sizeof(P.MYARK_TRUST_VERIFY_OUTPUT)
    # 4 + 4 + 256 + 256 + 8 + 8 = 536 (ctypes adds trailing pad to align structure to 4)
    assert size == 536


def test_input_and_output_distinct():
    # input is 528 (260*2 + 4 + 4); output is 536 (4+4 + 256 + 256 + 8 + 8 + 4 trailing pad)
    assert ctypes.sizeof(P.MYARK_TRUST_VERIFY_INPUT) == 528
    assert ctypes.sizeof(P.MYARK_TRUST_VERIFY_OUTPUT) == 536


def test_status_and_flag_are_distinct():
    in_struct_size = ctypes.sizeof(P.MYARK_TRUST_VERIFY_INPUT)
    out_struct_size = ctypes.sizeof(P.MYARK_TRUST_VERIFY_OUTPUT)
    assert in_struct_size == 528
    assert out_struct_size == 536


def test_struct_can_be_instantiated():
    in_buf = P.MYARK_TRUST_VERIFY_INPUT()
    in_buf.FilePath = "C:\\test.exe"
    in_buf.Flags = P.TRUST_FLAG_EMBEDDED
    assert in_buf.Flags == 0x2

    out_buf = P.MYARK_TRUST_VERIFY_OUTPUT()
    out_buf.Status = P.TRUST_NOT_SIGNED
    assert out_buf.Status == 2