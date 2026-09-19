"""
trust client (parser) tests.
"""

from __future__ import annotations

from myark.modules.trust import parser as P
from myark.modules.trust import protocol as PP


def test_verify_result_dataclass_defaults():
    r = P.VerifyResult()
    assert r.status == 0
    assert r.status_name == ""
    assert r.flags == 0
    assert r.subject == ""
    assert r.issuer == ""
    assert r.source == ""


def test_verify_pe_r3_fallback_when_no_driver():
    r = P.verify_pe(None, "C:\\test.exe")
    assert r.source == "r3-fallback"
    assert r.status == PP.TRUST_NOT_SIGNED
    assert r.status_name == "not_signed"


def test_verify_catalog_r3_fallback_when_no_driver():
    r = P.verify_catalog(None, "C:\\some.dll")
    assert r.source == "r3-fallback"
    assert r.status == PP.TRUST_NOT_SIGNED


def test_status_name_mapping():
    assert P._status_name(0) == "trusted"
    assert P._status_name(1) == "untrusted"
    assert P._status_name(2) == "not_signed"
    assert P._status_name(99) == "unknown"


def test_r3_fallback_fields():
    r = P._r3_fallback("C:\\test.exe")
    assert r.status == PP.TRUST_NOT_SIGNED
    assert r.subject == ""
    assert r.issuer == ""
    assert r.source == "r3-fallback"


def test_verify_pe_empty_path_still_fallback():
    r = P.verify_pe(None, "")
    assert r.source == "r3-fallback"
    assert r.status == PP.TRUST_NOT_SIGNED


def test_verify_result_can_be_set():
    r = P.VerifyResult(
        status=PP.TRUST_TRUSTED,
        status_name="trusted",
        flags=PP.TRUST_FLAG_EMBEDDED,
        subject="CN=Microsoft",
        issuer="CN=MS Root",
        source="r0",
    )
    assert r.subject == "CN=Microsoft"
    assert r.issuer == "CN=MS Root"
    assert r.flags == 0x2