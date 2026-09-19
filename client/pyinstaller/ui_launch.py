"""Standalone-exe launcher for ``myark-ui`` (PyInstaller entry script).

See :mod:`cli_launch` for why this exists: PyInstaller runs its entry script
as a top-level module, so the UI must be started through an absolute import
of ``myark.ui.main_window`` for the package's relative imports to work.

Used by ``scripts/build_exe.bat``; never imported by library code.
"""

import sys

from myark.ui.main_window import main

if __name__ == "__main__":
    sys.exit(main())
