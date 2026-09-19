"""
wsl client (parser) tests.
"""

from __future__ import annotations

from myark.modules.wsl import parser as P
from myark.modules.wsl import protocol as PP


def test_wsl_report_defaults():
    r = P.WslReport()
    assert r.count == 0
    assert r.silos == []
    assert r.source == ""


def test_silo_entry_defaults():
    e = P.SiloEntry()
    assert e.silo_address == 0
    assert e.silo_id == 0
    assert e.flags == 0
    assert e.distro_count == 0
    assert e.distro_name == ""


def test_enumerate_silos_r3_fallback_when_no_driver():
    r = P.enumerate_silos(None)
    assert r.source == "r3-fallback"
    assert r.count == 0
    assert r.silos == []


def test_r3_fallback_fields():
    r = P._r3_fallback()
    assert r.count == 0
    assert r.silos == []
    assert r.source == "r3-fallback"


def test_silo_entry_can_be_constructed():
    e = P.SiloEntry(
        silo_address=0xFFFFF80012345000,
        silo_id=7,
        flags=PP.WSL_FLAG_ACTIVE,
        distro_count=1,
        distro_name="Ubuntu-22.04",
    )
    assert e.silo_id == 7
    assert e.flags == 0x1
    assert e.distro_name == "Ubuntu-22.04"


def test_constants_match_protocol():
    assert PP.WSL_DISTRO_NAME_MAX == 64
    assert PP.WSL_HARD_CAP == 16
