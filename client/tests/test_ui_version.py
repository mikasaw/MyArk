"""Structural test: UI version metadata is single-sourced (S10.8).

``myark.ui.main_window`` must not hardcode a version string; it imports
``myark.__version__`` as ``APP_VERSION`` so the window title, About and
help dialogs always match the installed package (and ``pyproject.toml``).
"""

from __future__ import annotations

import unittest

import myark
from myark.ui import APP_VERSION as UI_PACKAGE_APP_VERSION
from myark.ui import main_window


class TestAppVersionSingleSource(unittest.TestCase):
    def test_main_window_app_version_matches_package_version(self):
        self.assertEqual(main_window.APP_VERSION, myark.__version__)
        # The ``myark.ui`` re-export must forward the same value.
        self.assertEqual(UI_PACKAGE_APP_VERSION, myark.__version__)


if __name__ == "__main__":
    unittest.main()
