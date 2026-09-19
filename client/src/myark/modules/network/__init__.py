"""MyArk Network module -- pure R3 (no driver IOCTLs).

S5.2 belongs to quadrant ①: every operation in this module is a plain
call into the IP Helper API via :mod:`ctypes`. The driver is never
opened. This module is the second demonstration of the quadrant-①
pattern (after S5.1's registry module) and serves as a template for
future read-only / Win32-API-only modules (Event Log, ETW, Services,
...).

The layout mirrors the rest of the modules:

* ``protocol`` -- pure-R3 constants (TCP state names, NO_IOCTL).
* ``parser``   -- ctypes struct mirrors + byte-buffer parsers.
* ``cli``      -- ``myark-cli network {tcp-list, udp-list, tcp-by-pid}``.
* ``ui``       -- Tkinter tab with a protocol picker + Treeview.
* ``plugin``   -- the entry point ``register(client, capabilities)`` that
  the ``myark.modules`` plugin group discovers.

Note: the spec for this module (``S5.2``) lists the entry point file as
``plugin.py``. ``myark._builtin_modules`` discovers the registration by
``importlib.import_module("myark.modules.network")`` then looks up
``register`` on that package, so ``__init__.py`` re-exports the symbol
defined in ``plugin.py``. Both names work for third-party consumers.
"""

from __future__ import annotations

from myark.modules.network.plugin import register

__all__ = ["register"]