"""
preflight R3 - plugin entry (re-export ``register`` from ``plugin.py``).
"""

from myark.modules.preflight.plugin import register

__all__ = ["register"]