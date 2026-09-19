"""
dyndata R3 - plugin entry (re-export ``register`` from ``plugin.py``).

The plugin-loader contract looks up ``register`` on ``myark.modules.dyndata``;
that symbol lives in ``plugin.py`` and is re-exported here so third-party
consumers can do either ``from myark.modules.dyndata import register`` or
``from myark.modules.dyndata.plugin import register``.
"""

from myark.modules.dyndata.plugin import register

__all__ = ["register"]
