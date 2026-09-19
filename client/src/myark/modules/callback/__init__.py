"""
callback R3 - plugin entry (re-export ``register`` from ``plugin.py``).

The plugin-loader contract looks up ``register`` on ``myark.modules.callback``;
that symbol lives in ``plugin.py`` and is re-exported here so third-party
consumers can do either ``from myark.modules.callback import register`` or
``from myark.modules.callback.plugin import register``.
"""

from myark.modules.callback.plugin import register

__all__ = ["register"]