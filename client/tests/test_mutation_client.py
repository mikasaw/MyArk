"""
mutation client (parser) tests.
"""

from __future__ import annotations

from myark.modules.mutation import parser as P
from myark.modules.mutation import protocol as PP


def test_token_report_defaults():
    r = P.TokenReport()
    assert r.process_id == 0
    assert r.token_flags == 0
    assert r.integrity_level == 0
    assert r.is_elevated is False
    assert r.is_uac_restricted is False
    assert r.token_address == 0
    assert r.source == ""


def test_inspect_token_r3_fallback_when_no_driver():
    r = P.inspect_token(None, 1234)
    assert r.source == "r3-fallback"
    assert r.process_id == 1234
    assert r.token_flags == 0


def test_set_token_returns_false_in_s7_3():
    ok = P.set_token(None, 1234, 0xFFFFE00100001234)
    assert ok is False


def test_r3_fallback_fields():
    r = P._r3_fallback(5678)
    assert r.process_id == 5678
    assert r.source == "r3-fallback"


def test_token_report_can_be_constructed():
    r = P.TokenReport(
        process_id=1234,
        token_flags=PP.MUTATION_TOKEN_FLAG_ADMIN,
        integrity_level=2,
        is_elevated=True,
        is_uac_restricted=False,
        token_address=0xFFFFF80012345000,
        source="r0",
    )
    assert r.token_flags == 0x2
    assert r.is_elevated is True
    assert r.token_address == 0xFFFFF80012345000


def test_constants_match_protocol():
    assert PP.MUTATION_TOKEN_FLAG_VALID == 0x1
    assert PP.MUTATION_TOKEN_FLAG_ADMIN == 0x2


def test_zero_pid_still_falls_back():
    r = P.inspect_token(None, 0)
    assert r.source == "r3-fallback"
    assert r.process_id == 0
