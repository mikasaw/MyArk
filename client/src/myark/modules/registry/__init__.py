"""MyArk Registry module -- pure R3 (no driver IOCTLs).

S5 belongs to quadrant ①: every operation in this module is a plain call
into the standard-library :mod:`winreg` API. The driver is never opened.
This module is the first demonstration of that pattern and serves as a
template for future read-only / Win32-API-only modules (Event Log, ETW,
Services, ...).

The layout mirrors the rest of the modules:

* ``protocol`` -- pure-R3 constants and helpers (no IOCTL codes).
* ``parser``  -- path / value-name / value-type parsers.
* ``cli``     -- ``myark-cli registry {list,keys,read,write,delete-value,delete-key}``.
* ``ui``      -- Tkinter tab with a path entry + Treeview of (key, value).
* ``plugin``  -- the entry point ``register(client, capabilities)`` that the
  ``myark.modules`` plugin group discovers.

Note: the spec for this module (``S5.1``) lists the entry point file as
``plugin.py``. ``myark._builtin_modules`` discovers the registration by
``importlib.import_module("myark.modules.registry")`` then looks up
``register`` on that package, so ``__init__.py`` re-exports the symbol
defined in ``plugin.py``. Both names work for third-party consumers.
"""

from __future__ import annotations

from myark.modules.registry.plugin import register

__all__ = ["register"]