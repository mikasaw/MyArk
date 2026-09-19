"""
actions R3 - plugin entry (re-export ``register`` from ``plugin.py``).
"""

from myark.modules.actions.plugin import register

__all__ = ["register"]