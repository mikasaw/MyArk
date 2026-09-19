"""Standalone-exe launcher for ``myark-cli`` (PyInstaller entry script).

PyInstaller executes its entry script as a *top-level* module (``__main__``
named after the file), so pointing it at ``myark/cli/main.py`` directly makes
every package-relative import there fail with::

    ImportError: attempted relative import with no known parent package

This launcher is the fix: as a top-level script it only uses *absolute*
imports, and importing ``myark.cli.main`` through the normal package
machinery lets the relative imports inside the package resolve correctly.

Used by ``scripts/build_exe.bat``; never imported by library code.
"""

import sys

from myark.cli.main import main

if __name__ == "__main__":
    sys.exit(main())
