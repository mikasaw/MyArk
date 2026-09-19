"""MyArk File module -- pure R3 (no driver IOCTLs).

S5.3 belongs to quadrant ①: every operation in this module is a plain
call into Win32 (``kernel32``, ``advapi32``, ``sddl``) via :mod:`ctypes`.
The driver is never opened. This module is the third demonstration of
the quadrant-① pattern (after S5.1's registry module and S5.2's network
module) and serves as a template for future read-only / Win32-API-only
modules (Event Log, ETW, Services, ...).

The layout mirrors the rest of the modules:

* ``protocol`` -- pure-R3 constants (file attribute names, integrity
  level names, NO_IOCTL sentinel).
* ``parser``   -- ctypes struct mirrors + ACL/SID parsers + high-level
  entry points.
* ``cli``      -- ``myark-cli file {info, owner, dacl, integrity}``.
* ``ui``       -- Tkinter tab with a path entry + attribute tree + SDDL
  panel.
* ``plugin``   -- the entry point ``register(client, capabilities)``
  that the ``myark.modules`` plugin group discovers.

Note: the spec for this module (``S5.3``) lists the entry point file as
``plugin.py``. ``myark._builtin_modules`` discovers the registration
by ``importlib.import_module("myark.modules.file")`` then looks up
``register`` on that package, so ``__init__.py`` re-exports the symbol
defined in ``plugin.py``. Both names work for third-party consumers.
"""

from __future__ import annotations

from myark.modules.file.plugin import register

__all__ = ["register"]