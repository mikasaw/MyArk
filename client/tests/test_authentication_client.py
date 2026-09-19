"""
authentication client (parser) tests.
"""

from __future__ import annotations

from myark.modules.authentication import parser as P
from myark.modules.authentication import protocol as PP


def test_verify_result_defaults():
    r = P.VerifyResult()
    assert r.status == 0
    assert r.status_name == ""
    assert r.flags == 0
    assert r.subject == ""
    assert r.issuer == ""
    assert r.source == ""


def test_verify_file_r3_fallback_when_no_driver():
    r = P.verify_file(None, "C:\\test.exe")
    assert r.source == "r3-fallback"
    assert r.status == PP.AUTHENTICATION_NOT_SIGNED
    assert r.status_name == "not_signed"


def test_status_name_mapping():
    assert P._status_name(0) == "trusted"
    assert P._status_name(1) == "untrusted"
    assert P._status_name(2) == "not_signed"
    assert P._status_name(99) == "unknown"


def test_r3_fallback_fields():
    r = P._r3_fallback("C:\\test.exe")
    assert r.status == PP.AUTHENTICATION_NOT_SIGNED
    assert r.subject == ""
    assert r.issuer == ""
    assert r.source == "r3-fallback"


def test_empty_path_still_falls_back():
    r = P.verify_file(None, "")
    assert r.source == "r3-fallback"
    assert r.status == PP.AUTHENTICATION_NOT_SIGNED


def test_verify_result_can_be_set():
    r = P.VerifyResult(
        status=PP.AUTHENTICATION_TRUSTED,
        status_name="trusted",
        flags=PP.AUTHENTICATION_FLAG_EMBEDDED,
        subject="CN=Microsoft",
        issuer="CN=MS Root",
        source="r0",
    )
    assert r.subject == "CN=Microsoft"
    assert r.flags == 0x2
