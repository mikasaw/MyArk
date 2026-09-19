"""Five-mode matcher for the MyArk three-layer search.

Each registered module exposes a set of rows; the search layer needs a
single ``match(query, text, mode=...)`` entry point so the left-pane filter,
the Ctrl+P palette and the sidebar advanced-search dialog all share one
semantics tree.

Modes:

- ``EXACT``     -- case-insensitive whole-string equality (after strip).
- ``PREFIX``    -- case-insensitive prefix.
- ``SUBSTRING`` -- case-insensitive substring on the literal text.
- ``PINYIN``    -- lowercase substring on the pypinyin-flattened form;
                  also matches initial letters (e.g. "jc" -> "进程" via
                  "jincheng").
- ``REGEX``     -- ``re.search`` on the literal text; invalid regex
                  patterns are reported as no-match rather than raised.

A missing pypinyin falls back to plain substring matching for ``PINYIN``;
we never raise from this module so the UI stays responsive even on a
fresh ``pip install myark`` before ``pypinyin`` is added.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Optional


class MatchMode(str, Enum):
    EXACT = "exact"
    PREFIX = "prefix"
    SUBSTRING = "substring"
    PINYIN = "pinyin"
    REGEX = "regex"


_PINYIN = None
_PINYIN_FAILED = False


def _pinyin() -> Optional[object]:
    """Lazy import of pypinyin.lazy_pinyin.

    The import is heavy enough that we defer it past module load -- this
    file is imported by every Tkinter widget, so paying the cost up front
    is wasted when the user never types a CN query.
    """
    global _PINYIN, _PINYIN_FAILED
    if _PINYIN_FAILED:
        return None
    if _PINYIN is not None:
        return _PINYIN
    try:
        from pypinyin import lazy_pinyin

        _PINYIN = lazy_pinyin
        return _PINYIN
    except Exception:  # pragma: no cover -- optional at S3
        _PINYIN_FAILED = True
        return None


def pinyin_key(text: str) -> str:
    """Flatten ``text`` to its full-pinyin + initial-letters form.

    Example: ``"进程"`` -> ``"jinchengjc"``. The initial run is appended so
    a single query like ``"jc"`` matches either the full pinyin tail or
    the initials -- the user's mental model of "abbreviation-style fuzzy"
    search on Windows / macOS file lists.

    Returns ``text`` unchanged if pypinyin is unavailable.
    """
    lazy = _pinyin()
    if lazy is None:
        return text
    try:
        syllables = lazy(text, errors=lambda chars: list(chars))
    except Exception:
        return text
    full = "".join(syllables)
    # Initial letters come from the pinyin syllable list, not from the
    # concatenated string -- ``full.split()`` would only yield one token.
    initials = "".join(s[0] for s in syllables if s)
    return (full + initials).lower()


def match(query: str, text: str, mode: MatchMode = MatchMode.SUBSTRING) -> bool:
    """Return ``True`` if ``query`` matches ``text`` under ``mode``.

    Empty queries always match (used by the tree filter to mean "show
    everything"). Whitespace-only queries are also treated as empty.
    """
    q = (query or "").strip().lower()
    if not q:
        return True

    haystack = text or ""

    if mode is MatchMode.EXACT:
        return q == haystack.strip().lower()

    if mode is MatchMode.PREFIX:
        return haystack.lower().startswith(q)

    if mode is MatchMode.SUBSTRING:
        return q in haystack.lower()

    if mode is MatchMode.PINYIN:
        # Plain substring wins on Latin queries; pinyin-key only adds the
        # initials fallback for CN queries.
        if q in haystack.lower():
            return True
        return q in pinyin_key(haystack)

    if mode is MatchMode.REGEX:
        try:
            return re.search(query, haystack, flags=re.IGNORECASE) is not None
        except re.error:
            return False

    return False


def match_any(query: str, fields: list[str], mode: MatchMode = MatchMode.SUBSTRING) -> bool:
    """Match against any field in ``fields`` (OR semantics)."""
    q = (query or "").strip()
    if not q:
        return True
    for f in fields:
        if match(q, str(f), mode):
            return True
    return False


__all__ = [
    "MatchMode",
    "match",
    "match_any",
    "pinyin_key",
]