"""
Tests for the preflight module's R3 client (parser / dataclasses / fallback).
"""

from __future__ import annotations

import ctypes

import pytest

from myark.modules.preflight import parser as P
from myark.modules.preflight import protocol as PP


def test_health_report_defaults():
    r = P.HealthReport()
    assert r.major_version == 0
    assert r.minor_version == 0
    assert r.build_number == 0
    assert r.revision == 0
    assert r.is_test_signing == 0
    assert r.is_secure_boot == 0
    assert r.is_driver_signed == 0
    assert r.flags == 0
    assert r.kernel_base == 0
    assert r.kernel_size == 0
    assert r.note == ""
    assert r.source == ""


def test_r3_fallback_health_returns_synthesized_report():
    """When client is None, query_health returns a synthetic R3 fallback report."""
    report = P.query_health(None)
    assert report.source == "r3-fallback"
    assert "R3 fallback" in report.note
    # No real driver data, so all boolean fields should be 0.
    assert report.is_test_signing == 0
    assert report.is_secure_boot == 0
    assert report.is_driver_signed == 0


def test_health_output_size_matches_kernel_struct():
    assert ctypes.sizeof(PP.MYARK_PREFLIGHT_HEALTH_OUTPUT) == 304


def test_health_output_is_fixed_size():
    """Preflight HEALTH has no variable-length entries; size is exact."""
    assert PP.MYARK_PREFLIGHT_HEALTH_OUTPUT().Note == ""


def test_health_output_population():
    """Build a synthetic reply and confirm fields round-trip."""
    out = PP.MYARK_PREFLIGHT_HEALTH_OUTPUT()
    out.MajorVersion = 10
    out.MinorVersion = 0
    out.BuildNumber = 26100
    out.Revision = 4652
    out.IsTestSigning = 1
    out.IsSecureBoot = 0
    out.IsDriverSigned = 1
    out.Flags = PP.PREFLIGHT_FLAG_DEBUG
    out.KernelBase = 0xFFFFF80012345678
    out.KernelSize = 0x1000000
    out.Note = "test"
    assert out.MajorVersion == 10
    assert out.KernelBase == 0xFFFFF80012345678
    assert out.Flags & PP.PREFLIGHT_FLAG_DEBUG