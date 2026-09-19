"""
kernel_ext protocol ctypes layout tests.
"""

from __future__ import annotations

import ctypes

import pytest

from myark.modules.kernel_ext import protocol as P


def test_ioctl_codes_match_kt():
    raw_q = 0x7F0
    raw_t = 0x7F1
    expected_q = ((0x22 << 16) | (raw_q << 2) | 0) & 0xFFFFFFFF
    expected_t = ((0x22 << 16) | (raw_t << 2) | 0) & 0xFFFFFFFF
    assert P.IOCTL_MYARK_KERNEL_EXT_QUERY_WIN11_INFO == expected_q
    assert P.IOCTL_MYARK_KERNEL_EXT_READ_SYSCALL_TABLE == expected_t


def test_win11_info_base_constant():
    assert P.KERNEL_EXT_WIN11_INFO_BASE == 0xAD


def test_input_struct_layout():
    in_size = ctypes.sizeof(P.MYARK_KERNEL_EXT_QUERY_INPUT)
    assert in_size == 16  # 4 + 4 + 8


def test_output_struct_layout():
    out_size = ctypes.sizeof(P.MYARK_KERNEL_EXT_QUERY_OUTPUT)
    assert out_size == 24  # 4 + 4 + 8 + 1 + 7 trailing pad


def test_syscall_entry_layout():
    e_size = ctypes.sizeof(P.MYARK_KERNEL_EXT_SYSCALL_ENTRY)
    assert e_size == 16  # 4 + 4 + 8


def test_syscall_table_output_layout():
    t_size = ctypes.sizeof(P.MYARK_KERNEL_EXT_SYSCALL_TABLE_OUTPUT)
    assert t_size == 8 + 16  # 4+4 + 1 entry of 16 = 24


def test_input_and_output_distinct():
    assert ctypes.sizeof(P.MYARK_KERNEL_EXT_QUERY_INPUT) == 16
    assert ctypes.sizeof(P.MYARK_KERNEL_EXT_QUERY_OUTPUT) == 24


def test_struct_can_be_instantiated():
    in_buf = P.MYARK_KERNEL_EXT_QUERY_INPUT()
    in_buf.SystemInformationClass = 0xAD
    assert in_buf.SystemInformationClass == 0xAD

    out_buf = P.MYARK_KERNEL_EXT_QUERY_OUTPUT()
    out_buf.Status = 0xC0000002
    assert out_buf.Status == 0xC0000002
