"""
alpc protocol ctypes layout tests.
"""

from __future__ import annotations

import ctypes

import pytest

from myark.modules.alpc import protocol as P


def test_ioctl_codes_match_kt():
    raw_e = 0x790
    raw_c = 0x791
    expected_e = ((0x22 << 16) | (raw_e << 2) | 0) & 0xFFFFFFFF
    expected_c = ((0x22 << 16) | (raw_c << 2) | 0) & 0xFFFFFFFF
    assert P.IOCTL_MYARK_ALPC_ENUMERATE_PORTS == expected_e
    assert P.IOCTL_MYARK_ALPC_CLOSE_PORT == expected_c


def test_constants():
    assert P.ALPC_NAME_MAX == 64
    assert P.ALPC_HARD_CAP == 128


def test_flag_constants():
    assert P.ALPC_FLAG_CONNECTED == 0x1
    assert P.ALPC_FLAG_SERVER == 0x2


def test_port_entry_struct_layout():
    e_size = ctypes.sizeof(P.MYARK_ALPC_PORT_ENTRY)
    # 8 + 4 + 4 + 4 + 4 + 64*2 = 152
    assert e_size == 152


def test_ports_output_layout():
    out_size = ctypes.sizeof(P.MYARK_ALPC_PORTS_OUTPUT)
    # 4 + 4 + 1 entry of 152 = 160
    assert out_size == 160


def test_close_input_layout():
    in_size = ctypes.sizeof(P.MYARK_ALPC_CLOSE_INPUT)
    # 4 + 4 + 8 = 16
    assert in_size == 16


def test_struct_can_be_instantiated():
    e = P.MYARK_ALPC_PORT_ENTRY()
    e.PortAddress = 0xFFFFF80012345000
    e.PortId = 42
    e.OwnerProcessId = 1234
    e.Flags = P.ALPC_FLAG_CONNECTED | P.ALPC_FLAG_SERVER
    e.PortName = "\\RPC Control\\lsass"
    assert e.PortId == 42
    assert e.Flags == 0x3
    assert e.PortName == "\\RPC Control\\lsass"


def test_close_input_can_be_instantiated():
    in_buf = P.MYARK_ALPC_CLOSE_INPUT()
    in_buf.PortId = 99
    assert in_buf.PortId == 99
