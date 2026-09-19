"""MyArk R3 client package.

This package is the user-mode counterpart to MyArkCore.sys. Subpackages:

- ``myark.client``     low-level device I/O (CreateFileW + DeviceIoControl)
- ``myark.protocol``   ctypes definitions matching ``driver/src/.../MyArkCoreIoctl.h``
- ``myark.plugin_loader`` entry_points-based module discovery
- ``myark.cli``        argparse-based ``myark-cli`` console entry point
- ``myark.ui``         Tkinter-based ``myark-ui`` graphical entry point

Stage S3 lands the core plumbing only -- no functional ARK modules yet.
Stage S4 onward attaches real modules via the ``myark.modules`` entry point group.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]