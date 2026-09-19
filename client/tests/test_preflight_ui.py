"""Tests for :mod:`myark.modules.preflight.ui` (S10.10).

The tab renders the same 6 rows ``myark-cli preflight health`` prints,
sourced from ``cli.health_rows``. All tests run with ``client=None``:
the parser's R3 fallback is deterministic (no driver probe, Python
version as the os surrogate), so the expected values hold on any
machine.

Tk-root sharing
---------------
All Tk-using tests share a single ``tk.Tk()`` root via the conftest
shared helper (see ``test_ui_detail_window`` for the rationale).
"""

from __future__ import annotations

import os
import re
import tkinter as tk
from tkinter import ttk

import pytest

from myark.modules.preflight import cli, parser
from myark.modules.preflight.plugin import register
from myark.modules.preflight.ui import ROW_KEYS, TESTSIGNING_HINT, _build_ui


HARNESS_HAS_TK = os.name == "nt" or os.environ.get("DISPLAY")


@pytest.fixture()
def holder():
    if not HARNESS_HAS_TK:
        pytest.skip("no Tk display available")
    from tests import conftest
    root = conftest.shared_tk_root()
    win = tk.Toplevel(root)
    win.withdraw()
    yield win
    try:
        win.destroy()
    except tk.TclError:
        pass


def _label_texts(widget) -> list[str]:
    texts = []
    for child in widget.winfo_children():
        if isinstance(child, ttk.Label):
            texts.append(str(child.cget("text")))
        texts.extend(_label_texts(child))
    return texts


def _fallback_os_string() -> str:
    r = parser.query_health(None)
    return f"{r.major_version}.{r.minor_version}.{r.build_number}"


# ---- data layer (no Tk required)

def test_health_rows_order_and_raw_types():
    report = parser.HealthReport(
        major_version=10, minor_version=0, build_number=26100,
        is_test_signing=1, is_secure_boot=0, is_driver_signed=1,
        flags=2, source="r0",
    )
    rows = cli.health_rows(report)
    assert [key for key, _ in rows] == list(ROW_KEYS)
    # Raw values keep the CLI's 0/1 ints -- each surface does its own
    # boolean rendering (CLI prints 0/1, the UI prints True/False).
    assert rows[1] == ("testsigning", 1)
    assert rows[4] == ("flags", 2)


def test_cli_one_liner_format_unchanged(capsys, monkeypatch):
    """S10.10 routes the CLI print through health_rows; the output line
    must stay exactly as before (byte-for-byte regression guard)."""
    monkeypatch.setattr(cli, "_open_or_complain", lambda: None)
    rc = cli._cmd_health(type("Args", (), {})())
    out = capsys.readouterr().out
    assert rc == 0
    pattern = (
        r"^# preflight: source=(?P<source>\S+)"
        r" os=(?P<os>\d+\.\d+\.\d+)"
        r" testsigning=(?P<ts>[01])"
        r" secure_boot=(?P<sb>[01])"
        r" driver_signed=(?P<ds>[01])"
        r" flags=0x(?P<flags>[0-9A-F]+)\r?\n"
    )
    m = re.match(pattern, out)
    assert m, out
    report = parser.query_health(None)
    assert m.group("source") == report.source
    assert m.group("os") == (
        f"{report.major_version}.{report.minor_version}.{report.build_number}"
    )
    assert m.group("ts") == str(report.is_test_signing)
    assert m.group("flags") == f"{report.flags:X}"
    assert "note: preflight: R3 fallback (driver not installed)" in out


# ---- the panel

def test_build_ui_returns_frame_with_row_keys(holder):
    frame = _build_ui(holder, None)
    assert isinstance(frame, ttk.Frame)
    joined = "\n".join(_label_texts(frame))
    assert "os" in joined
    assert "testsigning" in joined
    for key in ROW_KEYS:
        assert f"{key}:" in joined


def test_ui_values_match_cli_rows(holder):
    frame = _build_ui(holder, None)
    rows = dict(cli.health_rows(parser.query_health(None)))
    assert frame._value_vars["os"].get() == rows["os"]
    assert frame._value_vars["os"].get() == _fallback_os_string()
    assert frame._value_vars["source"].get() == rows["source"]
    assert frame._value_vars["flags"].get() == f"0x{rows['flags']:X}"
    for key in ("testsigning", "secure_boot", "driver_signed"):
        assert frame._value_vars[key].get() == ("True" if rows[key] else "False")


def test_testsigning_hint_shown_when_false(holder):
    # The R3 fallback always reports testsigning=0, so the panel shows
    # the VM_SETUP.md hint (only the R0 overlay can ever report True).
    frame = _build_ui(holder, None)
    assert frame._value_vars["testsigning"].get() == "False"
    assert "bcdedit /set testsigning on" in "\n".join(_label_texts(frame))
    assert "VM_SETUP.md" in TESTSIGNING_HINT


def test_refresh_button_rereads_values(holder):
    frame = _build_ui(holder, None)
    for var in frame._value_vars.values():
        var.set("stale")
    frame._refresh()
    assert frame._value_vars["os"].get() == _fallback_os_string()
    assert frame._value_vars["source"].get() == "r3-fallback"


def test_plugin_wires_ui_factory(holder):
    reg = register(None, [])
    assert reg.ui_factory is not None
    widget = reg.make_ui(holder, None)
    assert isinstance(widget, ttk.Frame)
    assert "os" in "\n".join(_label_texts(widget))
