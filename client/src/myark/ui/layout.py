"""Persist MyArk UI layout (window geometry + splitter sash positions).

The store is a tiny JSON file at ``~/.myark/layout.json``. The schema is
flat -- adding a new field is safe because :func:`save_layout` always
writes the full dict and :func:`load_layout` returns a default for
missing keys.

The serializer is deliberately tolerant of partial / older files: a
user who upgraded to S9.1 from S3 should still get a sensible window
without the script crashing on a missing ``splitter`` key.

The module is pure Python -- no Tkinter, no driver, no IOCTL. It is
importable by tests without an active display.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from typing import Optional


DEFAULT_DIR = os.path.join("~", ".myark")
DEFAULT_FILE = os.path.join(DEFAULT_DIR, "layout.json")
SCHEMA_VERSION = 1


@dataclass
class LayoutState:
    """Serialisable snapshot of the main-window state.

    Attributes
    ----------
    geometry:
        Tk geometry string like ``"1280x800+100+100"``. Empty means
        "let Tk pick".
    sash_positions:
        List of pixel offsets along the horizontal splitter. Tk only
        lets us set the *first* sash on a horizontal PanedWindow
        (between left and center), so the list is typically one entry.
    active_module:
        Name of the module tab the user last viewed. ``None`` means
        "no preference -- let the loader pick".
    advanced_filter:
        Optional dict form of an :class:`AdvancedFilter` (text + ranges
        + mode). ``None`` if the user never opened the dialog.
    """

    geometry: str = ""
    sash_positions: list[int] = field(default_factory=list)
    active_module: Optional[str] = None
    advanced_filter: Optional[dict] = None


def default_path() -> str:
    """Return the canonical layout.json path (``~/.myark/layout.json``)."""
    return os.path.expanduser(DEFAULT_FILE)


def _ensure_dir(path: str) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)


def load_layout(path: Optional[str] = None) -> LayoutState:
    """Load a :class:`LayoutState` from disk; return defaults on failure."""
    target = path or default_path()
    try:
        with open(target, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return LayoutState()

    state = LayoutState()
    state.geometry = str(data.get("geometry") or "")
    raw_sash = data.get("sash_positions")
    if isinstance(raw_sash, list):
        state.sash_positions = [int(x) for x in raw_sash if isinstance(x, int)]
    state.active_module = data.get("active_module")
    state.advanced_filter = data.get("advanced_filter")
    return state


def save_layout(state: LayoutState, path: Optional[str] = None) -> None:
    """Write ``state`` to disk as JSON.

    Uses an atomic temp-file + rename so a crash mid-write does not
    leave the user with a half-written file that crashes the next
    start.
    """
    target = path or default_path()
    _ensure_dir(target)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "geometry": state.geometry,
        "sash_positions": list(state.sash_positions),
        "active_module": state.active_module,
        "advanced_filter": state.advanced_filter,
    }
    directory = os.path.dirname(target) or "."
    fd, tmp = tempfile.mkstemp(prefix=".layout-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        os.replace(tmp, target)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


__all__ = [
    "LayoutState",
    "SCHEMA_VERSION",
    "default_path",
    "load_layout",
    "save_layout",
]