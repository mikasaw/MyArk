"""Per-session action history: ``~/.myark/history.log`` append-only log.

When the user fires a destructive action through the ``actions`` module
(``kill / terminate / read / write / ...``), the CLI / UI callback asks
this module to append a single line to ``~/.myark/history.log``. The
:class:`~myark.ui.widgets.history_window.HistoryWindow` popup reads the
same file and renders the recent lines in a table.

Design notes
------------
* Pure Python, no driver IOCTLs, no Tk. This module is importable
  from the R3 CLI just as easily as from the UI.
* Each record is a single JSON line (``{"ts": ..., "action": ...}``)
  so a record never collides with itself when a target path contains
  arbitrary text -- JSON takes care of escaping.
* ``HOME`` is honoured via ``Path.home()``. A custom path can be
  injected for tests via :func:`set_history_path`; the change is
  process-global and is reset by :func:`reset_history_path`.
* Encryption (S5, v1.1.0): the log carries sensitive targets, so every
  line may instead be DPAPI-protected (``crypt32 CryptProtectData``,
  current-user scope) and stored as ``ENC1:<base64>``. The knob is
  :func:`set_encryption_enabled` / the ``MYARK_HISTORY_ENCRYPT``
  environment variable (default: off, matching the historical format).
  The reader accepts both line shapes, so enabling encryption never
  orphans existing plaintext records; :func:`migrate_to_encrypted`
  rewrites an existing plaintext file in place when the user opts in.
  DPAPI's threat model is "other user accounts / other machines" --
  same-user processes can still decrypt, which is documented, not a
  bug.
"""

from __future__ import annotations

import base64
import json
import os
import time
import ctypes
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional


DEFAULT_HISTORY_DIR = Path.home() / ".myark"
DEFAULT_HISTORY_FILE = DEFAULT_HISTORY_DIR / "history.log"

# Lines starting with this marker hold a base64 DPAPI blob instead of
# plain JSON. The ``1`` is a format version for future migrations.
_ENC_LINE_PREFIX = "ENC1:"

_history_path: Path = DEFAULT_HISTORY_FILE
_encryption_enabled: Optional[bool] = None


def history_path() -> Path:
    """Return the current history file path (process-global)."""
    return _history_path


def set_history_path(path: Path) -> None:
    """Override the history file path (used by tests)."""
    global _history_path
    _history_path = Path(path)


def reset_history_path() -> None:
    """Restore the default history file path (``~/.myark/history.log``)."""
    global _history_path
    _history_path = DEFAULT_HISTORY_FILE


def set_encryption_enabled(enabled: bool) -> None:
    """Force encryption on/off for this process (used by tests + UI).

    ``None`` restores the default behaviour: honour the
    ``MYARK_HISTORY_ENCRYPT`` environment variable (``1``/``true``/
    ``on``/``yes``, case-insensitive), otherwise off.
    """
    global _encryption_enabled
    _encryption_enabled = None if enabled is None else bool(enabled)


def reset_encryption_enabled() -> None:
    """Alias of ``set_encryption_enabled(None)`` (back to env default)."""
    set_encryption_enabled(None)


def encryption_enabled() -> bool:
    """Whether new records are written DPAPI-encrypted."""
    if _encryption_enabled is not None:
        return _encryption_enabled
    return os.environ.get("MYARK_HISTORY_ENCRYPT", "").strip().lower() in (
        "1", "true", "on", "yes",
    )


# ---------------------------------------------------------------------------
# DPAPI (crypt32) bindings.
# ---------------------------------------------------------------------------


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.c_uint32),
        ("pbData", ctypes.c_void_p),
    ]


_crypt32 = ctypes.WinDLL("crypt32.dll")
_CryptProtectData = _crypt32.CryptProtectData
_CryptProtectData.restype = ctypes.c_int
_CryptProtectData.argtypes = [
    ctypes.POINTER(_DATA_BLOB),        # pDataIn
    ctypes.c_wchar_p,                  # szDataDescr
    ctypes.c_void_p,                   # pOptionalEntropy
    ctypes.c_void_p,                   # pvReserved
    ctypes.c_void_p,                   # pPromptStruct
    ctypes.c_uint32,                   # dwFlags
    ctypes.POINTER(_DATA_BLOB),        # pDataOut
]
_CryptUnprotectData = _crypt32.CryptUnprotectData
_CryptUnprotectData.restype = ctypes.c_int
_CryptUnprotectData.argtypes = [
    ctypes.POINTER(_DATA_BLOB),        # pDataIn
    ctypes.POINTER(ctypes.c_wchar_p),  # ppszDataDescr
    ctypes.c_void_p,                   # pOptionalEntropy
    ctypes.c_void_p,                   # pvReserved
    ctypes.c_void_p,                   # pPromptStruct
    ctypes.c_uint32,                   # dwFlags
    ctypes.POINTER(_DATA_BLOB),        # pDataOut
]
_localfree = ctypes.windll.ole32.CoTaskMemFree


def _dpapi_protect(plaintext: str) -> str:
    """DPAPI-protect ``plaintext`` (current-user scope) -> ``ENC1:<b64>``."""
    raw = plaintext.encode("utf-8")
    in_blob = _DATA_BLOB(len(raw), ctypes.cast(
        ctypes.create_string_buffer(raw, len(raw)), ctypes.c_void_p,
    ))
    out_blob = _DATA_BLOB()
    if not _CryptProtectData(
        ctypes.byref(in_blob), "MyArk action history", None, None, None, 0,
        ctypes.byref(out_blob),
    ):
        raise OSError("CryptProtectData failed")
    try:
        blob = ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        _localfree(ctypes.c_void_p(out_blob.pbData))
    return _ENC_LINE_PREFIX + base64.b64encode(blob).decode("ascii")


def _dpapi_unprotect(stored: str) -> str:
    """Inverse of :func:`_dpapi_protect`; raises ``OSError`` on failure."""
    blob = base64.b64decode(stored[len(_ENC_LINE_PREFIX):])
    in_blob = _DATA_BLOB(len(blob), ctypes.cast(
        ctypes.create_string_buffer(blob, len(blob)), ctypes.c_void_p,
    ))
    # ppszDataDescr stays None: the out-string is a LocalAlloc'd copy we
    # would have to free (review found ~42 B leaked per decrypt); we do
    # not need the description.
    out_blob = _DATA_BLOB()
    if not _CryptUnprotectData(
        ctypes.byref(in_blob), None, None, None, None, 0,
        ctypes.byref(out_blob),
    ):
        raise OSError("CryptUnprotectData failed")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData).decode("utf-8")
    finally:
        _localfree(ctypes.c_void_p(out_blob.pbData))


@dataclass
class HistoryRecord:
    """One entry in the per-session action history."""

    timestamp: float
    action: str
    target: str
    result: str
    detail: str = ""

    @classmethod
    def from_line(cls, line: str) -> "HistoryRecord":
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"malformed history record: {line!r}") from exc
        try:
            return cls(
                timestamp=float(data.get("ts", 0.0)),
                action=str(data.get("action", "")),
                target=str(data.get("target", "")),
                result=str(data.get("result", "")),
                detail=str(data.get("detail", "")),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid history record fields: {line!r}") from exc

    def to_line(self) -> str:
        return json.dumps(
            {
                "ts": float(self.timestamp),
                "action": self.action,
                "target": self.target,
                "result": self.result,
                "detail": self.detail,
            },
            ensure_ascii=False,
        )


def _record_from_stored_line(line: str) -> Optional[HistoryRecord]:
    """Decode one stored line (plaintext or ``ENC1:``) into a record.

    Returns ``None`` for lines that cannot be decoded -- a DPAPI blob
    from another user account, a truncated write, or garbage must never
    take down the reader.
    """
    try:
        if line.startswith(_ENC_LINE_PREFIX):
            return HistoryRecord.from_line(_dpapi_unprotect(line))
        return HistoryRecord.from_line(line)
    except (ValueError, OSError):
        return None


def _stored_line_for(record: HistoryRecord) -> str:
    """Encode one record according to :func:`encryption_enabled`."""
    line = record.to_line()
    if encryption_enabled():
        return _dpapi_protect(line)
    return line


def _ensure_parent(path: Path) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass


def append(record: HistoryRecord, *, path: Optional[Path] = None) -> None:
    """Append a single record to the history file (best-effort)."""
    target = Path(path) if path is not None else history_path()
    _ensure_parent(target)
    try:
        with target.open("a", encoding="utf-8") as fp:
            fp.write(_stored_line_for(record))
            fp.write("\n")
    except OSError:
        pass


def record(action: str, target: str, result: str, detail: str = "") -> HistoryRecord:
    """Build a record for ``time.time()``, append it, and return it."""
    rec = HistoryRecord(
        timestamp=time.time(),
        action=action,
        target=target,
        result=result,
        detail=detail,
    )
    append(rec)
    return rec


def read_recent(limit: int = 200, *, path: Optional[Path] = None) -> list[HistoryRecord]:
    """Return up to ``limit`` most-recent history records (newest last)."""
    target = Path(path) if path is not None else history_path()
    if not target.exists():
        return []
    try:
        with target.open("r", encoding="utf-8") as fp:
            data = fp.read()
    except OSError:
        return []
    records: list[HistoryRecord] = []
    for line in data.splitlines():
        if not line:
            continue
        rec = _record_from_stored_line(line)
        if rec is not None:
            records.append(rec)
    if limit and len(records) > limit:
        records = records[-limit:]
    return records


def iter_all(*, path: Optional[Path] = None) -> Iterable[HistoryRecord]:
    """Yield all records in the file (oldest first)."""
    target = Path(path) if path is not None else history_path()
    if not target.exists():
        return
    try:
        with target.open("r", encoding="utf-8") as fp:
            for line in fp:
                if not line.strip():
                    continue
                rec = _record_from_stored_line(line.rstrip("\n"))
                if rec is not None:
                    yield rec
    except OSError:
        return


def migrate_to_encrypted(*, path: Optional[Path] = None) -> tuple[int, int]:
    """Rewrite an existing plaintext history file into ``ENC1:`` lines.

    Runs regardless of the current :func:`encryption_enabled` state --
    the caller decides when to convert. Already-encrypted lines and
    undecodable lines are preserved byte-for-byte. Returns
    ``(converted, left_unchanged)``.
    """
    target = Path(path) if path is not None else history_path()
    if not target.exists():
        return (0, 0)
    try:
        raw_lines = target.read_text(encoding="utf-8").splitlines()
    except OSError:
        return (0, 0)

    converted = 0
    untouched = 0
    out_lines: list[str] = []
    for line in raw_lines:
        if not line.strip():
            continue
        if line.startswith(_ENC_LINE_PREFIX):
            out_lines.append(line)
            untouched += 1
            continue
        try:
            HistoryRecord.from_line(line)  # validate before rewriting
        except ValueError:
            out_lines.append(line)
            untouched += 1
            continue
        out_lines.append(_dpapi_protect(line))
        converted += 1

    try:
        target.write_text("\n".join(out_lines) + ("\n" if out_lines else ""),
                          encoding="utf-8")
    except OSError:
        return (0, untouched)
    return (converted, untouched)


__all__ = [
    "DEFAULT_HISTORY_DIR",
    "DEFAULT_HISTORY_FILE",
    "HistoryRecord",
    "history_path",
    "set_history_path",
    "reset_history_path",
    "set_encryption_enabled",
    "reset_encryption_enabled",
    "encryption_enabled",
    "append",
    "record",
    "read_recent",
    "iter_all",
    "migrate_to_encrypted",
]