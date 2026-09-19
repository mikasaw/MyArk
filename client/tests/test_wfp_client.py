"""
wfp client (parser) tests.
"""

from __future__ import annotations

from myark.modules.wfp import parser as P
from myark.modules.wfp import protocol as PP


def test_callout_entry_defaults():
    e = P.CalloutEntry()
    assert e.callout_key == b"\x00" * 16
    assert e.applicable_layer == b"\x00" * 16
    assert e.flags == 0
    assert e.callout_name == ""


def test_wfp_report_defaults():
    r = P.WfpReport()
    assert r.count == 0
    assert r.callouts == []
    assert r.source == ""


def test_enumerate_callouts_r3_fallback_when_no_driver():
    r = P.enumerate_callouts(None)
    assert r.source == "r3-fallback"
    assert r.count == 0


def test_add_callout_returns_false_in_s7_3():
    ok = P.add_callout(None, b"\x00" * 16, b"\x00" * 16, 0)
    assert ok is False


def test_remove_callout_returns_false_in_s7_3():
    ok = P.remove_callout(None, b"\x00" * 16)
    assert ok is False


def test_r3_fallback_fields():
    r = P._r3_fallback()
    assert r.count == 0
    assert r.callouts == []
    assert r.source == "r3-fallback"


def test_callout_entry_can_be_constructed():
    e = P.CalloutEntry(
        callout_key=b"\x01" + b"\x00" * 15,
        applicable_layer=b"\x02" + b"\x00" * 15,
        flags=0x4,
        callout_name="TestCallout",
    )
    assert e.callout_key[0] == 0x01
    assert e.callout_name == "TestCallout"


def test_constants_match_protocol():
    assert PP.WFP_NAME_MAX == 64
    assert PP.WFP_CALLOUT_HARD_CAP == 128
