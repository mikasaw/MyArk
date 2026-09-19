"""Entry-points based loader for the ``myark.modules`` plugin group.

A module is any distribution that registers an entry point in the
``myark.modules`` group. The entry point's load() callable must follow the
``register(client, capabilities)`` contract described below.

The loader is intentionally permissive: a failing module is logged to stderr
and skipped, never raised -- a broken third-party plugin must not take down
the whole UI / CLI. ``registered`` is a dict of ``name -> registration record``
that downstream UI / CLI code uses to inject tabs / subcommands.
"""

from __future__ import annotations

import importlib.metadata
import sys
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Optional

if TYPE_CHECKING:
    from .client.ark_client import ArkClient
    from .client.module_query import CapabilityInfo, ModuleInfo


# ---------------------------------------------------------------------------
# Registration record.
#
# Modules return a ``ModuleRegistration`` from their ``register(client, caps)``
# function so the loader / UI / CLI can wire them up without each module
# needing to know about Tkinter or argparse.
# ---------------------------------------------------------------------------


@dataclass
class ModuleRegistration:
    name: str
    register_fn: Callable[..., "ModuleRegistration"]
    ui_factory: Optional[Callable[..., Any]] = None
    cli_setup: Optional[Callable[..., None]] = None
    description: str = ""
    extra: dict = field(default_factory=dict)

    def make_ui(
        self,
        parent: Any,
        client: Optional["ArkClient"],
        *,
        safety_authority: Optional[Any] = None,
    ):
        """Build the module's tab widget.

        ``safety_authority`` is an optional :class:`SafetyTokenAuthority`
        passed in by the main window; modules that expose destructive
        actions (terminate / inject / set-integrity / ...) should use it
        to gate those actions through :func:`myark.ui.safety_dialog.confirm`.
        Modules that have no destructive surface can safely ignore it.
        """
        if self.ui_factory is None:
            return None
        try:
            return self.ui_factory(parent, client, safety_authority=safety_authority)
        except TypeError:
            # Backwards-compat: ui factories written before the safety hook
            # landed only accept ``(parent, client)``; retry without the
            # extra kwarg so older module UIs keep working.
            return self.ui_factory(parent, client)

    def setup_cli(self, subparsers: Any, client: Optional["ArkClient"]) -> None:
        if self.cli_setup is None:
            return
        self.cli_setup(subparsers, client)


# Type alias for the register() signature expected from entry points.
ModuleRegisterFn = Callable[[Optional["ArkClient"], list["CapabilityInfo"]], "ModuleRegistration"]


# ---------------------------------------------------------------------------
# Loader entry points.
# ---------------------------------------------------------------------------


def load_modules(
    client: Optional["ArkClient"],
    capabilities: Optional[list["CapabilityInfo"]] = None,
    *,
    group: str = "myark.modules",
) -> dict[str, ModuleRegistration]:
    """Discover entry points in ``group`` and call ``register(client, caps)``.

    Returns a ``name -> ModuleRegistration`` dict. Module load failures are
    logged but never raised so a broken plugin can't crash the UI.

    Discovery walks ``importlib.metadata.distributions()`` because some
    setuptools / pip combinations silently drop custom entry-point groups
    from the editable-install dist-info even though they appear in the
    package's ``PKG-INFO`` / wheel metadata. Iterating distributions and
    asking each one for its ``entry_points`` is more reliable than
    ``entry_points(group=...)`` for plugins shipped inside the same package.
    """
    if capabilities is None:
        capabilities = []

    registered: dict[str, ModuleRegistration] = {}

    try:
        discovered = _discover_group(group)
    except Exception as exc:
        print(f"[plugin_loader] failed to enumerate {group}: {exc}", file=sys.stderr)
        discovered = []

    for ep in discovered:
        try:
            register_fn = ep.load()
        except Exception as exc:
            print(f"[plugin_loader] failed to load entry point {ep.name}: {exc}", file=sys.stderr)
            continue

        try:
            reg = register_fn(client, capabilities)
        except Exception as exc:
            print(
                f"[plugin_loader] module {ep.name} register() failed: {exc}",
                file=sys.stderr,
            )
            continue

        if not isinstance(reg, ModuleRegistration):
            print(
                f"[plugin_loader] module {ep.name} returned {type(reg).__name__}, "
                "expected ModuleRegistration",
                file=sys.stderr,
            )
            continue

        registered[ep.name] = reg

    #
    # Fallback: in-tree modules under ``myark.modules.<name>`` are always
    # importable. The package's own ``__init__`` exposes
    # ``register_builtin_modules`` which iterates them. This sidesteps a
    # known setuptools 84 quirk where custom entry-point groups on the
    # myark distribution itself are not always copied into the editable-
    # install dist-info. Third-party plugins continue to come in through
    # the entry-point path above.
    #
    try:
        from . import _builtin_modules

        for name, reg in _builtin_modules.iter_builtin_registrations(client, capabilities).items():
            registered.setdefault(name, reg)
    except Exception as exc:
        print(f"[plugin_loader] builtin registration failed: {exc}", file=sys.stderr)

    return registered


def _discover_group(group: str) -> list:
    """Return all entry points in ``group`` across every distribution.

    Tries ``entry_points(group=...)`` first (the documented API), and falls
    back to iterating ``distributions()`` for toolchains that omit the group
    from the fast-path lookup but still expose it via each distribution's
    own ``entry_points`` view.
    """
    import importlib.metadata

    try:
        eps = importlib.metadata.entry_points(group=group)
        if eps:
            return list(eps)
    except Exception:
        pass

    seen: dict[tuple[str, str], object] = {}
    for dist in importlib.metadata.distributions():
        try:
            for ep in dist.entry_points:
                if ep.group == group and (ep.group, ep.name) not in seen:
                    seen[(ep.group, ep.name)] = ep
        except Exception:
            continue
    return list(seen.values())


def registered_names(registered: dict[str, ModuleRegistration]) -> list[str]:
    """Convenience for CLI listings."""
    return sorted(registered.keys())


__all__ = [
    "ModuleRegistration",
    "ModuleRegisterFn",
    "load_modules",
    "registered_names",
]