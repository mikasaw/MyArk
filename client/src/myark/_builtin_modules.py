"""In-tree module discovery for ``myark.modules``.

The myark distribution also ships modules directly under ``myark.modules``
(e.g. ``myark.modules.hello``). These are *always* importable as a normal
package, so we can enumerate them by ``pkgutil.iter_modules`` rather than
relying on the entry-point path -- which is the way third-party plugins
ship their own modules but does not always survive setuptools 84's
editable-install metadata rewrite for the distribution that owns the
group itself.

``iter_builtin_registrations`` calls each module's ``register(client,
capabilities)`` function and returns a ``name -> ModuleRegistration`` dict.
A module that lacks a top-level ``register`` callable is silently skipped,
so third-party modules with a different shape can still coexist.

Importing this module triggers no side effects; ``register`` runs only
when :func:`iter_builtin_registrations` is called.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import TYPE_CHECKING, Optional

from .plugin_loader import ModuleRegistration

if TYPE_CHECKING:
    from .client.ark_client import ArkClient
    from .client.module_query import CapabilityInfo


_BUILTIN_MODULE_NAMES = (
    "hello",
    "dyndata",
    "callback",
    "capability",
    "preflight",
    "safety",
    "security_audit",
    "trust",
    "kernel_ext",
    "hwid",
    "alpc",
    "wsl",
    "win32k",
    "authentication",
    "bugcheck",
    "wfp",
    "mutation",
    "redirect",
    "actions",
    "memory",
    "module",
    "network",
    "process",
    "thread",
    "registry",
    "file",
    # The S7.3 generation below used to be reachable only through the
    # pyproject entry-points path, so editable installs (where setuptools
    # drops the dist's own entry-point group) silently lost them. Keep the
    # pkgutil fallback list in sync with [project.entry-points.myark_modules].
    "handle",
    "section",
    "kmod",
    "kernel",
    "storage",
    "keyboard",
    "debug_output",
    "device_audit",
    "kernel_object",
)


def iter_builtin_registrations(
    client: Optional["ArkClient"],
    capabilities: list["CapabilityInfo"],
) -> dict[str, ModuleRegistration]:
    """Walk ``myark.modules`` and call each submodule's ``register()``.

    Returns a dict keyed by module name. Modules that fail to import or
    whose ``register`` raises are logged to stderr and skipped.
    """
    registered: dict[str, ModuleRegistration] = {}

    import sys

    package = importlib.import_module("myark.modules")
    package_path = getattr(package, "__path__", None)
    if package_path is None:
        return registered

    for info in pkgutil.iter_modules(package_path):
        if info.name not in _BUILTIN_MODULE_NAMES:
            continue
        full_name = f"myark.modules.{info.name}"
        try:
            mod = importlib.import_module(full_name)
        except Exception as exc:
            print(f"[builtin_modules] import {full_name} failed: {exc}", file=sys.stderr)
            continue

        register_fn = getattr(mod, "register", None)
        if register_fn is None:
            continue

        try:
            reg = register_fn(client, capabilities)
        except Exception as exc:
            print(f"[builtin_modules] {full_name}.register() failed: {exc}", file=sys.stderr)
            continue

        if not isinstance(reg, ModuleRegistration):
            print(
                f"[builtin_modules] {full_name}.register() returned {type(reg).__name__}",
                file=sys.stderr,
            )
            continue

        registered[reg.name] = reg

    return registered


__all__ = ["iter_builtin_registrations"]