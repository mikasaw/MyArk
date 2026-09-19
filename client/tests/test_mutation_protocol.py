"""
mutation protocol ctypes layout tests.
"""

from __future__ import annotations

import ctypes

import pytest

from myark.modules.mutation import protocol as P


def test_ioctl_codes_match_kt():
    raw_i = 0x730
    raw_s = 0x731
    expected_i = ((0x22 << 16) | (raw_i << 2) | 0) & 0xFFFFFFFF
    expected_s = ((0x22 << 16) | (raw_s << 2) | 0) & 0xFFFFFFFF
    assert P.IOCTL_MYARK_MUTATION_INSPECT_TOKEN == expected_i
    assert P.IOCTL_MYARK_MUTATION_SET_TOKEN == expected_s


def test_token_flag_constants():
    assert P.MUTATION_TOKEN_FLAG_VALID == 0x1
    assert P.MUTATION_TOKEN_FLAG_ADMIN == 0x2
    assert P.MUTATION_TOKEN_FLAG_SYSTEM == 0x4


def test_input_struct_layout():
    in_size = ctypes.sizeof(P.MYARK_MUTATION_INSPECT_TOKEN_INPUT)
    # 4 + 4 + 8 = 16
    assert in_size == 16


def test_output_struct_layout():
    out_size = ctypes.sizeof(P.MYARK_MUTATION_INSPECT_TOKEN_OUTPUT)
    # 4 + 4 + 4 + 4 + 8 + 8 = 32
    assert out_size == 32


def test_set_token_input_layout():
    in_size = ctypes.sizeof(P.MYARK_MUTATION_SET_TOKEN_INPUT)
    # 4 + 4 + 8 + 8 = 24
    assert in_size == 24


def test_struct_can_be_instantiated():
    in_buf = P.MYARK_MUTATION_INSPECT_TOKEN_INPUT()
    in_buf.ProcessId = 1234
    assert in_buf.ProcessId == 1234

    out_buf = P.MYARK_MUTATION_INSPECT_TOKEN_OUTPUT()
    out_buf.TokenFlags = P.MUTATION_TOKEN_FLAG_ADMIN
    out_buf.IsElevated = 1
    out_buf.TokenAddress = 0xFFFFF80012345000
    assert out_buf.TokenFlags == 0x2
    assert out_buf.IsElevated == 1


def test_set_token_input_can_be_instantiated():
    in_buf = P.MYARK_MUTATION_SET_TOKEN_INPUT()
    in_buf.ProcessId = 1234
    in_buf.TokenHandle = 0xFFFFE00100001234
    assert in_buf.TokenHandle == 0xFFFFE00100001234
