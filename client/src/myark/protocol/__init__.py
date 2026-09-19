"""Protocol package -- re-exports IOCTL / wire-format definitions.

The core IOCTLs and ctypes structures live in ``core``; module-specific
protocols (process, hello, ...) live in their own submodules and are
re-exported here for ``myark.protocol.<NAME>`` shorthand.
"""

from .core import *  # noqa: F401,F403
from .core import __all__ as _CORE_ALL
from . import process as _process

__all__ = list(_CORE_ALL) + list(_process.__all__)