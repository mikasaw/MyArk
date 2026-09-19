"""Shared test fixtures.

``tk_root``
-----------
Tk-using tests in this repo (search smoke tests + the S9.2 multi-window
popups) all need at least one ``tk.Tk()`` instance. Creating a fresh
root for every test method works in isolation but exhausts Tcl
resources once the full 600+ test suite runs -- the Windows Tcl
interpreter keeps state across Tk() instances and starts failing with
"couldn't read init.tcl" after a few dozen.

The session-scoped root below is created in ``pytest_configure`` (when
the test session boots) and torn down in ``pytest_unconfigure``. Tests
that need it should import :data:`tests.conftest._tk_root` directly
(or call the :func:`shared_tk_root` helper) rather than relying on a
pytest fixture, because unittest.TestCase classes do not pick up
plain pytest fixtures unless they opt in via ``@pytest.mark.usefixtures``
or accept the fixture in their signature.

Tk-using tests should:

* obtain the shared root in ``setUp``;
* create ``tk.Toplevel`` children against the shared root;
* destroy those children in ``tearDown`` (via ``_purge_children`` in
  each test module) so the next test starts clean.
"""

from __future__ import annotations

import os
from typing import Optional


HARNESS_HAS_TK = os.name == "nt" or os.environ.get("DISPLAY")


_tk_root = None  # type: Optional["tk.Tk"]


def pytest_configure(config):
    """Create the shared Tk root when the session starts (if Tk is available)."""
    global _tk_root
    if not HARNESS_HAS_TK:
        return
    if _tk_root is not None:
        return
    import tkinter as tk
    _tk_root = tk.Tk()
    _tk_root.withdraw()


def pytest_unconfigure(config):
    """Tear the shared Tk root down when pytest exits."""
    global _tk_root
    if _tk_root is not None:
        try:
            _tk_root.destroy()
        except Exception:
            pass
        _tk_root = None


def shared_tk_root():
    """Return the shared Tk root, or skip the calling test if Tk is unavailable."""
    import pytest
    if not HARNESS_HAS_TK:
        pytest.skip("no Tk display available")
    assert _tk_root is not None, "shared Tk root not initialized"
    return _tk_root