"""Cross-module search index used by the Ctrl+P palette and the
sidebar advanced-search dialog.

Each ``SearchEntry`` carries enough context for the palette to jump to a
specific module + row when the user picks a candidate:

- ``module``         -- registered module name (process / thread / ...).
- ``kind``           -- coarse row kind ("row" / "module" / "ioctl").
- ``primary``        -- the row's headline string (process name, TID,
                        registry value, network endpoint, etc.).
- ``fields``         -- everything searchable; pinyin index is computed
                        lazily on first ``.pinyin`` access.
- ``description``    -- free-form blurb shown next to the candidate.
- ``target``         -- opaque call-back invoked by the palette.

Index construction is R3-only: it never opens the driver. Each module
provides a small ``collect_rows()`` callable that returns plain tuples.
That keeps the loader happy (a failing module is logged and skipped) and
keeps the unit tests off any Win32 / driver path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from .matcher import pinyin_key


@dataclass
class SearchEntry:
    module: str
    kind: str
    primary: str
    fields: list[str] = field(default_factory=list)
    description: str = ""
    target: Optional[Callable[[], Any]] = None
    _pinyin_cache: Optional[str] = None

    def matches(self, query: str, mode) -> bool:
        """Single-entry ``match`` shortcut used by ``cmd_palette``."""
        from .matcher import match

        if match(query, self.primary, mode):
            return True
        if self.description and match(query, self.description, mode):
            return True
        for f in self.fields:
            if match(query, str(f), mode):
                return True
        return False

    @property
    def pinyin(self) -> str:
        if self._pinyin_cache is None:
            joined = " ".join([self.primary, self.description, *self.fields])
            self._pinyin_cache = pinyin_key(joined)
        return self._pinyin_cache


# ---------------------------------------------------------------------------
# Module row collectors -- each returns a list of (primary, fields, desc).
# The collectors are R3-only; they import the lightweight parser layer
# that runs without the driver loaded.
# ---------------------------------------------------------------------------


def _collect_process() -> Iterable[tuple[str, list[str], str]]:
    try:
        from myark.modules.process.parser import enum_processes
    except Exception:
        return
    try:
        for row in enum_processes():
            yield (
                row.name,
                [str(row.pid), str(row.ppid), row.path, str(row.session_id)],
                f"pid={row.pid} ppid={row.ppid}",
            )
    except Exception:
        return


def _collect_thread() -> Iterable[tuple[str, list[str], str]]:
    try:
        from myark.modules.process.parser import enum_processes
    except Exception:
        return
    try:
        from myark.modules.thread.parser import enum_threads
    except Exception:
        return

    seen: set[tuple[int, int]] = set()
    try:
        procs = enum_processes()
    except Exception:
        return

    for p in procs:
        try:
            res = enum_threads(p.pid)
        except Exception:
            continue
        for r in res.rows:
            key = (r.tid, r.pid)
            if key in seen:
                continue
            seen.add(key)
            yield (
                f"{r.tid} ({p.name})",
                [str(r.tid), str(r.pid), str(r.priority), r.wait_name, r.module],
                f"tid={r.tid} pid={r.pid} state={r.state_name}",
            )


def _collect_memory() -> Iterable[tuple[str, list[str], str]]:
    try:
        from myark.modules.process.parser import enum_processes
        from myark.modules.memory.parser import query_memory_regions
    except Exception:
        return
    try:
        procs = enum_processes()
    except Exception:
        return
    for p in procs:
        try:
            regions = query_memory_regions(p.pid)
        except Exception:
            continue
        for r in regions:
            yield (
                f"{p.name}@{r.base_address:#x}",
                [str(p.pid), f"{r.base_address:#x}", str(r.size), r.name],
                f"pid={p.pid} base={r.base_address:#x} size={r.size}",
            )


def _collect_module() -> Iterable[tuple[str, list[str], str]]:
    try:
        from myark.modules.process.parser import enum_processes
        from myark.modules.module.parser import enumerate_modules
    except Exception:
        return
    try:
        procs = enum_processes()
    except Exception:
        return
    for p in procs:
        try:
            mods = enumerate_modules(p.pid)
        except Exception:
            continue
        for m in mods:
            yield (
                m.name,
                [str(p.pid), f"{m.base_address:#x}", str(m.size), m.path],
                f"pid={p.pid} base={m.base_address:#x}",
            )


def _collect_registry() -> Iterable[tuple[str, list[str], str]]:
    try:
        from myark.modules.registry.parser import parse_path
        import winreg
    except Exception:
        return
    roots = [
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        r"HKLM\SYSTEM\CurrentControlSet\Services",
        r"HKCU\SOFTWARE",
    ]
    for path in roots:
        try:
            hive, sub = parse_path(path)
            key = winreg.OpenKey(hive, sub, 0, winreg.KEY_READ)
        except Exception:
            continue
        try:
            i = 0
            while True:
                try:
                    name, raw, kind = winreg.EnumValue(key, i)
                except OSError:
                    break
                yield (
                    name or "(Default)",
                    [path, str(kind), str(raw)],
                    f"reg {path}\\{name}",
                )
                i += 1
        finally:
            try:
                key.Close()
            except Exception:
                pass


def _collect_network() -> Iterable[tuple[str, list[str], str]]:
    try:
        from myark.modules.network.cli import get_tcp_rows, get_udp_rows
    except Exception:
        return
    try:
        rows = list(get_tcp_rows()) + list(get_udp_rows())
    except Exception:
        return
    for r in rows:
        proto = "UDP" if "local_port" in r and "remote_port" not in r else "TCP"
        local = f"{r.get('local_addr', '?')}:{r.get('local_port', '?')}"
        if proto == "TCP":
            remote = f"{r.get('remote_addr', '?')}:{r.get('remote_port', '?')}"
            primary = f"{local} -> {remote}"
        else:
            primary = local
        yield (
            primary,
            [str(r.get("pid", "")), r.get("state_name", "") or f"STATE_{r.get('state', '')}"],
            f"{proto} pid={r.get('pid', '')}",
        )


def _collect_file() -> Iterable[tuple[str, list[str], str]]:
    # The file module is a single-file inspector; no flat row list.
    # Index its known starting point so Ctrl+P can jump to it.
    try:
        from myark.modules.file.ui import DEFAULT_PATH as FP
    except Exception:
        FP = r"C:\Windows\notepad.exe"
    yield (
        FP,
        [FP],
        "file inspector default",
    )


_COLLECTORS: dict[str, Callable[[], Iterable[tuple[str, list[str], str]]]] = {
    "process": _collect_process,
    "thread": _collect_thread,
    "memory": _collect_memory,
    "module": _collect_module,
    "registry": _collect_registry,
    "network": _collect_network,
    "file": _collect_file,
}


def _registered_modules(client: Optional[Any], capabilities: list) -> dict[str, Any]:
    """Load the builtin module registry (best-effort)."""
    try:
        from myark._builtin_modules import iter_builtin_registrations
    except Exception:
        return {}
    try:
        return iter_builtin_registrations(client, capabilities or [])
    except Exception:
        return {}


def build_index(
    client: Optional[Any] = None,
    capabilities: Optional[list] = None,
    *,
    modules: Optional[Iterable[str]] = None,
) -> list[SearchEntry]:
    """Walk the registered modules and produce a flat search index.

    Parameters
    ----------
    client:
        Optional driver handle (unused for R3 collectors).
    capabilities:
        Driver capability list (unused for R3 collectors).
    modules:
        Restrict the index to these module names. ``None`` means "every
        collector we have a row source for".
    """
    capabilities = capabilities or []
    names = list(modules) if modules is not None else list(_COLLECTORS.keys())

    entries: list[SearchEntry] = []
    seen: set[tuple[str, str]] = set()

    # First, a "module" entry per registered module -- Ctrl+P jumps to
    # the module tab when the user picks one.
    registered = _registered_modules(client, capabilities)
    for name in sorted(registered.keys()):
        if modules is not None and name not in modules:
            continue
        primary = name
        key = ("module", primary)
        if key in seen:
            continue
        seen.add(key)
        entries.append(
            SearchEntry(
                module=name,
                kind="module",
                primary=primary,
                fields=[name],
                description=registered[name].description or "",
            )
        )

    # Then the row entries per collector.
    for name in names:
        if name not in _COLLECTORS:
            continue
        try:
            for primary, fields, desc in _COLLECTORS[name]():
                key = (name, primary)
                if key in seen:
                    continue
                seen.add(key)
                entries.append(
                    SearchEntry(
                        module=name,
                        kind="row",
                        primary=primary,
                        fields=fields,
                        description=desc,
                    )
                )
        except Exception:
            continue

    return entries


__all__ = [
    "SearchEntry",
    "build_index",
]