"""
security-audit R3 - plugin entry (re-export ``register`` from ``plugin.py``).
"""

from myark.modules.security_audit.plugin import register

__all__ = ["register"]