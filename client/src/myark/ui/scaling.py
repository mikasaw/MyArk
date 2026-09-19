"""DPI scaling helpers for the UI (KNOWN_ISSUES B3).

With process DPI awareness opted in (:func:`myark.ui.main_window.
_enable_dpi_awareness`), Tk scales fonts but *not* the literal pixel
widths handed to ``Treeview.column(...)``. On a >175% display the
hard-coded widths truncate CJK text, so every fixed width goes through
:func:`scaled_width`, which multiplies by the display's actual
pixels-per-inch over the 96-DPI baseline.
"""

from __future__ import annotations

import tkinter as tk
from typing import Any

# 96 DPI is the Windows 100% baseline; ``winfo_fpixels("1i")`` returns
# the real value (96 on a 100% display, 192 on 200%, ...).
_BASE_DPI: float = 96.0

# Floor so a bogus winfo answer (0 / negative / huge) can never collapse
# a column to nothing. 0.5 keeps half-size layouts usable, 8.0 covers
# any realistic multi-monitor mix.
_MIN_FACTOR: float = 0.5
_MAX_FACTOR: float = 8.0


def dpi_factor(widget: tk.Misc) -> float:
    """Return the widget's display DPI over the 96-DPI baseline.

    Falls back to ``1.0`` when the measurement is unavailable (no
    window manager yet, headless test environment).
    """
    try:
        ppi = float(widget.winfo_fpixels("1i"))
    except (tk.TclError, ValueError, TypeError):
        return 1.0
    if ppi <= 0:
        return 1.0
    factor = ppi / _BASE_DPI
    return max(_MIN_FACTOR, min(_MAX_FACTOR, factor))


def scaled_width(widget: Any, width_px: int) -> int:
    """Scale a designer-intended 96-DPI pixel width for this display."""
    return max(1, round(width_px * dpi_factor(widget)))
