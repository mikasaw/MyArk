"""B3 acceptance: column widths scale with the display DPI.

``scaled_width`` multiplies a designer-intended 96-DPI pixel width by
``dpi_factor`` (real ppi / 96, clamped). The math helper is pure and
tested directly; the widget-level behaviour is exercised through a stub
widget whose ``winfo_fpixels`` answer is controlled per test.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from myark.ui import scaling


class _FakeWidget:
    """Just the one method ``dpi_factor`` uses."""

    def __init__(self, ppi):
        self._ppi = ppi

    def winfo_fpixels(self, spec):
        assert spec == "1i"
        return self._ppi


class TestDpiFactor:
    def test_baseline_96_is_one(self):
        assert scaling.dpi_factor(_FakeWidget(96.0)) == pytest.approx(1.0)

    def test_200pct_display_doubles(self):
        assert scaling.dpi_factor(_FakeWidget(192.0)) == pytest.approx(2.0)

    def test_175pct_display(self):
        assert scaling.dpi_factor(_FakeWidget(168.0)) == pytest.approx(1.75)

    def test_bogus_zero_falls_back_to_one(self):
        assert scaling.dpi_factor(_FakeWidget(0)) == 1.0

    def test_negative_falls_back_to_one(self):
        assert scaling.dpi_factor(_FakeWidget(-5)) == 1.0

    def test_tcl_error_falls_back_to_one(self):
        class Broken:
            def winfo_fpixels(self, spec):
                import tkinter
                raise tkinter.TclError("no display")

        assert scaling.dpi_factor(Broken()) == 1.0

    def test_factor_clamped(self):
        # 8x is the documented ceiling; beyond that the factor stops.
        assert scaling.dpi_factor(_FakeWidget(96.0 * 100)) == pytest.approx(8.0)
        assert scaling.dpi_factor(_FakeWidget(96.0 * 0.01)) == pytest.approx(0.5)


class TestScaledWidth:
    def test_unchanged_at_baseline(self):
        assert scaling.scaled_width(_FakeWidget(96.0), 120) == 120

    def test_doubles_at_200pct(self):
        assert scaling.scaled_width(_FakeWidget(192.0), 120) == 240

    def test_never_returns_zero_or_negative(self):
        assert scaling.scaled_width(_FakeWidget(96.0 * 0.01), 2) >= 1


class TestModulePanelsIntegrated:
    """R3-12 acceptance: every ``modules/*/ui.py`` self-built Treeview
    column width goes through ``scaled_width``.

    A source-level guard (no display needed): each ``.column(...)`` call
    must wrap its pixel width, except the intentional ``width=0``
    auto-size resets in the network module. Without this test a new
    module panel silently reintroduces fixed widths that truncate CJK
    text on >100% DPI displays (the original B3 symptom).
    """

    MODULES_DIR = pathlib.Path(scaling.__file__).parent.parent / "modules"

    # Canary: the guard is vacuous if the scan comes up empty (directory
    # moved / package layout changed), so pin the expected module set.
    EXPECTED_MODULES = frozenset(
        {"file", "memory", "module", "network", "process",
         "registry", "security_audit", "thread"}
    )

    def _module_ui_paths(self):
        paths = sorted(self.MODULES_DIR.glob("*/ui.py"))
        found = {p.parent.name for p in paths}
        assert self.EXPECTED_MODULES <= found, (
            f"guard scan lost modules: {sorted(self.EXPECTED_MODULES - found)}"
        )
        return paths

    def test_every_module_ui_imports_scaled_width(self):
        for path in self._module_ui_paths():
            if ".column(" not in path.read_text(encoding="utf-8"):
                continue
            assert "scaled_width" in path.read_text(encoding="utf-8"), (
                f"{path.parent.name}/ui.py: builds a Treeview but never "
                "imports scaled_width"
            )

    def test_every_column_width_is_wrapped(self):
        unwrapped = []
        for path in self._module_ui_paths():
            for lineno, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if ".column(" not in line:
                    continue
                # \b keeps "minwidth=0" from passing as an auto-size reset.
                if "scaled_width(" in line or re.search(r"\bwidth=0\b", line):
                    continue
                unwrapped.append(f"{path.relative_to(self.MODULES_DIR)}:{lineno}: {line.strip()}")
        assert unwrapped == [], (
            "Treeview column widths must go through scaled_width "
            f"(B3/R3-12):\n" + "\n".join(unwrapped)
        )

