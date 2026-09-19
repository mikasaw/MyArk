"""
wsl protocol ctypes layout tests.
"""

from __future__ import annotations

import ctypes

import pytest

from myark.modules.wsl import protocol as P


def test_ioctl_code_matches_kt():
    raw = 0x780
    expected = ((0x22 << 16) | (raw << 2) | 0) & 0xFFFFFFFF
    assert P.IOCTL_MYARK_WSL_ENUMERATE_SILOS == expected


def test_constants():
    assert P.WSL_DISTRO_NAME_MAX == 64
    assert P.WSL_HARD_CAP == 16


def test_flag_constants():
    assert P.WSL_FLAG_ACTIVE == 0x1
    assert P.WSL_FLAG_DEFAULT == 0x2


def test_silo_entry_struct_layout():
    e_size = ctypes.sizeof(P.MYARK_WSL_SILO_ENTRY)
    # 8 + 4 + 4 + 4 + 4 + 64*2 = 152
    assert e_size == 152


def test_silos_output_layout():
    out_size = ctypes.sizeof(P.MYARK_WSL_SILOS_OUTPUT)
    # 4 + 4 + 1 entry of 152 = 160
    assert out_size == 160


def test_struct_can_be_instantiated():
    e = P.MYARK_WSL_SILO_ENTRY()
    e.SiloAddress = 0xFFFFF80012345000
    e.SiloId = 7
    e.Flags = P.WSL_FLAG_ACTIVE | P.WSL_FLAG_DEFAULT
    e.DistroCount = 1
    e.DistroName = "Ubuntu-22.04"
    assert e.SiloId == 7
    assert e.Flags == 0x3
    assert e.DistroName == "Ubuntu-22.04"
