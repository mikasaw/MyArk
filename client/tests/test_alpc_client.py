"""
alpc client (parser) tests.
"""

from __future__ import annotations

from myark.modules.alpc import parser as P
from myark.modules.alpc import protocol as PP


def test_alpc_report_defaults():
    r = P.AlpcReport()
    assert r.count == 0
    assert r.ports == []
    assert r.source == ""


def test_port_entry_defaults():
    e = P.PortEntry()
    assert e.port_address == 0
    assert e.port_id == 0
    assert e.owner_process_id == 0
    assert e.flags == 0
    assert e.port_name == ""


def test_enumerate_ports_r3_fallback_when_no_driver():
    r = P.enumerate_ports(None)
    assert r.source == "r3-fallback"
    assert r.count == 0
    assert r.ports == []


def test_close_port_returns_false_in_s7_3():
    ok = P.close_port(None, port_id=42)
    assert ok is False


def test_r3_fallback_fields():
    r = P._r3_fallback()
    assert r.count == 0
    assert r.ports == []
    assert r.source == "r3-fallback"


def test_port_entry_can_be_constructed():
    e = P.PortEntry(
        port_address=0xFFFFF80012345000,
        port_id=42,
        owner_process_id=1234,
        flags=PP.ALPC_FLAG_CONNECTED,
        port_name="\\RPC Control\\lsass",
    )
    assert e.port_id == 42
    assert e.flags == 0x1
    assert e.port_name == "\\RPC Control\\lsass"


def test_constants_match_protocol():
    assert PP.ALPC_NAME_MAX == 64
    assert PP.ALPC_HARD_CAP == 128
