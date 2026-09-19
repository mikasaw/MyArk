"""
redirect client (parser) tests.
"""

from __future__ import annotations

from myark.modules.redirect import parser as P
from myark.modules.redirect import protocol as PP


def test_redirect_entry_defaults():
    e = P.RedirectEntry()
    assert e.original_address == 0
    assert e.redirect_address == 0
    assert e.redirect_type == 0
    assert e.driver_name == ""


def test_redirect_report_defaults():
    r = P.RedirectReport()
    assert r.count == 0
    assert r.entries == []
    assert r.source == ""


def test_inspect_redirects_r3_fallback_when_no_driver():
    r = P.inspect_redirects(None)
    assert r.source == "r3-fallback"
    assert r.count == 0


def test_apply_redirect_returns_false_in_s7_3():
    ok = P.apply_redirect(None, 0x1000, 0x2000, PP.REDIRECT_TYPE_IRP)
    assert ok is False


def test_r3_fallback_fields():
    r = P._r3_fallback()
    assert r.count == 0
    assert r.entries == []
    assert r.source == "r3-fallback"


def test_redirect_entry_can_be_constructed():
    e = P.RedirectEntry(
        original_address=0xFFFFF80000001000,
        redirect_address=0xFFFFF80012345000,
        redirect_type=PP.REDIRECT_TYPE_CM,
        driver_name="\\Driver\\Evil",
    )
    assert e.redirect_type == 2
    assert e.driver_name == "\\Driver\\Evil"


def test_constants_match_protocol():
    assert PP.REDIRECT_NAME_MAX == 64
    assert PP.REDIRECT_HARD_CAP == 64
