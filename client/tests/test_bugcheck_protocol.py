"""
bugcheck protocol ctypes layout tests.
"""

from __future__ import annotations

import ctypes

import pytest

from myark.modules.bugcheck import protocol as P


def test_ioctl_codes_match_kt():
    raw_q = 0x760
    raw_r = 0x761
    expected_q = ((0x22 << 16) | (raw_q << 2) | 0) & 0xFFFFFFFF
    expected_r = ((0x22 << 16) | (raw_r << 2) | 0) & 0xFFFFFFFF
    assert P.IOCTL_MYARK_BUGCHECK_QUERY == expected_q
    assert P.IOCTL_MYARK_BUGCHECK_RENDER_DIAG == expected_r


def test_constants():
    assert P.BUGCHECK_TEXT_MAX == 256


def test_record_struct_layout():
    e_size = ctypes.sizeof(P.MYARK_BUGCHECK_RECORD)
    # 4 + 4 + 8 + 8 + 8 + 8 + 8 = 48
    assert e_size == 48


def test_query_output_layout():
    out_size = ctypes.sizeof(P.MYARK_BUGCHECK_QUERY_OUTPUT)
    # 4 + 4 + 48 = 56
    assert out_size == 56


def test_render_input_layout():
    in_size = ctypes.sizeof(P.MYARK_BUGCHECK_RENDER_INPUT)
    # 4 + 4 + 4 + 4 + 256*2 = 528
    assert in_size == 528


def test_struct_can_be_instantiated():
    rec = P.MYARK_BUGCHECK_RECORD()
    rec.BugCheckCode = 0xEF
    rec.Parameter1 = 0xDEADBEEF
    assert rec.BugCheckCode == 0xEF
    assert rec.Parameter1 == 0xDEADBEEF


def test_query_output_can_be_instantiated():
    o = P.MYARK_BUGCHECK_QUERY_OUTPUT()
    o.HasRecord = 1
    o.Record.BugCheckCode = 0x7E
    assert o.HasRecord == 1
    assert o.Record.BugCheckCode == 0x7E


def test_render_input_can_be_instantiated():
    r = P.MYARK_BUGCHECK_RENDER_INPUT()
    r.ForegroundColor = 0xFFFFFF
    r.BackgroundColor = 0
    r.X = 100
    r.Y = 200
    r.Text = "MyArk"
    assert r.X == 100
    assert r.Text == "MyArk"
