"""Tkinter UI package.

The ``myark-ui`` console script is defined in ``myark.ui.main_window:main``.
Stage S3 ships a three-pane skeleton (entity list / detail tabs / sidebar)
plus module-aware tabs populated via ``myark.plugin_loader``.
"""

from .main_window import APP_TITLE, APP_VERSION, MainWindow, main

__all__ = ["APP_TITLE", "APP_VERSION", "MainWindow", "main"]