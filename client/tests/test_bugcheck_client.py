"""
bugcheck client (parser) tests.
"""

from __future__ import annotations

from myark.modules.bugcheck import parser as P


def test_bugcheck_record_defaults():
    r = P.BugcheckRecord()
    assert r.bug_check_code == 0
    assert r.parameter1 == 0
    assert r.timestamp == 0


def test_query_report_defaults():
    r = P.BugcheckQueryReport()
    assert r.has_record is False
    assert r.record.bug_check_code == 0
    assert r.source == ""


def test_query_r3_fallback_when_no_driver():
    r = P.query_last_bugcheck(None)
    assert r.source == "r3-fallback"
    assert r.has_record is False
    assert r.record.bug_check_code == 0


def test_render_diagnostic_returns_false():
    ok = P.render_diagnostic(None, "test", x=10, y=20)
    assert ok is False


def test_r3_fallback_fields():
    r = P._r3_fallback_query()
    assert r.has_record is False
    assert r.source == "r3-fallback"


def test_record_can_be_constructed():
    r = P.BugcheckRecord(
        bug_check_code=0xEF,
        parameter1=0xDEADBEEF,
        timestamp=0x12345678,
    )
    assert r.bug_check_code == 0xEF
    assert r.timestamp == 0x12345678


def test_report_can_be_constructed():
    r = P.BugcheckQueryReport(
        has_record=True,
        record=P.BugcheckRecord(bug_check_code=0x7E),
        source="r0",
    )
    assert r.has_record is True
    assert r.record.bug_check_code == 0x7E
    assert r.source == "r0"
