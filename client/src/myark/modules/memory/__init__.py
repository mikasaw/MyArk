"""
memory R3 - plugin entry (re-export ``register`` from ``plugin.py``)

Driver-side wire format (MYARK_MEMORY_* IOCTLs) and the legacy
``query_vm / read_vm / write_vm / translate_va / scan_kernel_executable``
functions remain importable from this package for backwards compat, but
the CLI default for read / write / query now goes through the R3
helpers in ``parser.py``.
"""

from myark.modules.memory.plugin import register

__all__ = ["register"]