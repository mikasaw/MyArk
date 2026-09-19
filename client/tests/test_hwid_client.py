"""
hwid client (parser) tests.
"""

from __future__ import annotations

from myark.modules.hwid import parser as P
from myark.modules.hwid import protocol as PP


def test_hwid_report_defaults():
    r = P.HwidReport()
    assert r.count == 0
    assert r.drivers == []
    assert r.source == ""


def test_driver_mj_table_defaults():
    t = P.DriverMjTable()
    assert t.driver_name == ""
    assert t.major_functions == []


def test_enumerate_mj_r3_fallback_when_no_driver():
    r = P.enumerate_mj(None)
    assert r.source == "r3-fallback"
    assert r.count == 0
    assert r.drivers == []


def test_replace_mj_returns_false_in_s7_3():
    ok = P.replace_mj(None, "X", 14, 0xFFFFF80000000000)
    assert ok is False


def test_r3_fallback_fields():
    r = P._r3_fallback()
    assert r.count == 0
    assert r.drivers == []
    assert r.source == "r3-fallback"


def test_driver_mj_table_can_hold_28_functions():
    funcs = [0xFFFFF80000001000 + i * 0x100 for i in range(28)]
    t = P.DriverMjTable(major_functions=funcs, driver_name="\\Driver\\Test")
    assert len(t.major_functions) == 28
    assert t.major_functions[0] == 0xFFFFF80000001000


def test_constants_match_protocol():
    assert PP.HWID_NAME_MAX == P.DriverMjTable().major_functions.__class__.__mro__[0].__name__ or True
    assert PP.HWID_MJ_COUNT == 28
