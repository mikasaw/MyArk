"""
authentication protocol ctypes layout tests.
"""

from __future__ import annotations

import ctypes

import pytest

from myark.modules.authentication import protocol as P


def test_ioctl_code_matches_kt():
    raw = 0x7A0
    expected = ((0x22 << 16) | (raw << 2) | 0) & 0xFFFFFFFF
    assert P.IOCTL_MYARK_AUTHENTICATION_VERIFY_FILE == expected


def test_constants():
    assert P.AUTHENTICATION_PATH_MAX == 260
    assert P.AUTHENTICATION_SUBJECT_MAX == 128
    assert P.AUTHENTICATION_ISSUER_MAX == 128


def test_status_constants():
    assert P.AUTHENTICATION_TRUSTED == 0
    assert P.AUTHENTICATION_UNTRUSTED == 1
    assert P.AUTHENTICATION_NOT_SIGNED == 2


def test_flag_constants():
    assert P.AUTHENTICATION_FLAG_CATALOG == 0x1
    assert P.AUTHENTICATION_FLAG_EMBEDDED == 0x2


def test_input_struct_layout():
    in_size = ctypes.sizeof(P.MYARK_AUTHENTICATION_VERIFY_INPUT)
    # 260*2 = 520
    assert in_size == 520


def test_output_struct_layout():
    out_size = ctypes.sizeof(P.MYARK_AUTHENTICATION_VERIFY_OUTPUT)
    # 4+4 + 128*2 + 128*2 + 8 + 8 = 536
    assert out_size == 536


def test_input_and_output_distinct():
    assert ctypes.sizeof(P.MYARK_AUTHENTICATION_VERIFY_INPUT) == 520
    assert ctypes.sizeof(P.MYARK_AUTHENTICATION_VERIFY_OUTPUT) == 536


def test_struct_can_be_instantiated():
    in_buf = P.MYARK_AUTHENTICATION_VERIFY_INPUT()
    in_buf.FilePath = "C:\\test.exe"
    assert in_buf.FilePath == "C:\\test.exe"

    out_buf = P.MYARK_AUTHENTICATION_VERIFY_OUTPUT()
    out_buf.Status = P.AUTHENTICATION_NOT_SIGNED
    out_buf.Flags = P.AUTHENTICATION_FLAG_EMBEDDED
    out_buf.Subject = "CN=Microsoft"
    assert out_buf.Status == 2
    assert out_buf.Flags == 0x2
