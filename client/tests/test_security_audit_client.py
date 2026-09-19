"""
Tests for the security-audit module's R3 client (parser dataclasses + R3 fallback).
"""

from __future__ import annotations

import ctypes

import pytest

from myark.modules.security_audit import parser as P
from myark.modules.security_audit import protocol as PP


def test_defender_report_defaults():
    r = P.DefenderReport()
    assert r.is_installed == 0
    assert r.is_running == 0
    assert r.is_realtime_enabled == 0
    assert r.note == ""
    assert r.source == ""


def test_secure_boot_report_defaults():
    r = P.SecureBootReport()
    assert r.is_enabled == 0
    assert r.note == ""


def test_trusted_boot_report_defaults():
    r = P.TrustedBootReport()
    assert r.is_measured_boot_enabled == 0
    assert r.is_event_log_present == 0


def test_query_defender_r3_fallback():
    report = P.query_defender(None)
    assert report.source == "r3-fallback"
    assert "driver not installed" in report.note
    assert report.is_installed == 0


def test_query_secure_boot_r3_fallback():
    report = P.query_secure_boot(None)
    assert report.source == "r3-fallback"
    assert "driver not installed" in report.note


def test_query_trusted_boot_r3_fallback():
    report = P.query_trusted_boot(None)
    assert report.source == "r3-fallback"
    assert "driver not installed" in report.note


def test_defender_output_round_trip():
    out = PP.MYARK_SECURITY_AUDIT_DEFENDER_OUTPUT()
    out.IsInstalled = 1
    out.IsRunning = 1
    out.IsRealTimeProtectionEnabled = 1
    out.Note = "ok"
    assert out.IsInstalled == 1
    assert out.Note == "ok"


def test_secure_boot_output_round_trip():
    out = PP.MYARK_SECURITY_AUDIT_SECURE_BOOT_OUTPUT()
    out.IsEnabled = 1
    out.Note = "ok"
    assert out.IsEnabled == 1
    assert out.Note == "ok"


def test_trusted_boot_output_round_trip():
    out = PP.MYARK_SECURITY_AUDIT_TRUSTED_BOOT_OUTPUT()
    out.IsMeasuredBootEnabled = 1
    out.IsEventLogPresent = 0
    assert out.IsMeasuredBootEnabled == 1


# ---- S10.9: shared row builders (CLI print + UI table) -----------------


def test_cli_row_builders_r3_fallback():
    from myark.modules.security_audit import cli

    rows = cli.audit_rows(None)
    assert [r["item"] for r in rows] == ["defender", "secure-boot", "trusted-boot"]
    assert all(r["source"] == "r3-fallback" for r in rows)
    assert rows[0]["status_kv"] == "installed=0 running=0 realtime=0"
    assert rows[1]["status_kv"] == "enabled=0"
    assert rows[2]["status_kv"] == "measured_boot=0 event_log=0"


def test_cli_print_output_locked(capsys, monkeypatch):
    # Byte-level lock: the S10.9 row-builder refactor must not change
    # what the CLI prints (driver forced offline for determinism).
    import argparse

    from myark.modules.security_audit import cli

    monkeypatch.setattr(cli, "_open_or_complain", lambda: None)
    assert cli._cmd_defender(argparse.Namespace()) == 0
    assert cli._cmd_secure_boot(argparse.Namespace()) == 0
    assert cli._cmd_trusted_boot(argparse.Namespace()) == 0
    assert capsys.readouterr().out == (
        "# security_audit defender: source=r3-fallback installed=0 running=0 realtime=0\n"
        "  note: defender: R3 fallback (driver not installed)\n"
        "# security_audit secure-boot: source=r3-fallback enabled=0\n"
        "  note: secure_boot: R3 fallback (driver not installed)\n"
        "# security_audit trusted-boot: source=r3-fallback measured_boot=0 event_log=0\n"
        "  note: trusted_boot: R3 fallback (driver not installed)\n"
    )