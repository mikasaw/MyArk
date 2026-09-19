"""
capability R3 - plugin entry (re-export ``register`` from ``plugin.py``).
"""

from myark.modules.capability.plugin import register

__all__ = ["register"]