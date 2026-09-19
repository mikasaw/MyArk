"""MyArk Registry module: parsers for paths, value names, and value bytes.

The CLI and the UI both speak in human-friendly strings ("HKLM\\SOFTWARE\\...")
and ``--type REG_SZ`` spellings. The standard library :mod:`winreg` API
speaks in handles, integer type codes, and raw bytes. Everything that
translates between those worlds lives here.

Three responsibilities:

1. :func:`parse_path` splits a path string into ``(hive_handle, subkey)``.
2. :func:`parse_type_name` resolves ``"REG_SZ"`` style names into the
   matching ``winreg.REG_*`` constant.
3. :func:`value_to_readable` / :func:`readable_to_value` turn the raw
   bytes returned by ``winreg.QueryValueEx`` into something safe to
   print and back into something ``winreg.SetValueEx`` can write.
"""

from __future__ import annotations

from typing import Any, Optional, Union

import winreg

from myark.modules.registry.protocol import HIVE_PREFIXES, REG_TYPE_FROM_NAME


# Sentinel for the default value of a key -- winreg uses the empty string
# for both the read API ("(Default)") and the write API.
DEFAULT_VALUE_NAME: str = ""


# Maximum subkey length (in characters) the UI / CLI will accept. NT
# itself allows 255 chars per key segment and a 32 KB total path; we cap
# well below that to keep command lines usable.
MAX_SUBKEY_PATH: int = 4096


# ---------------------------------------------------------------------------
# Path parsing
# ---------------------------------------------------------------------------


def _split_root(path: str) -> tuple[str, str]:
    """Split ``HKLM\\foo\\bar`` into ``("HKLM", "foo\\bar")``.

    The leading component is the hive prefix and is case-insensitive.
    ``winreg`` handles do not expose a public comparison API, so we keep
    the prefix as a string and look it up in :data:`HIVE_PREFIXES`.
    """
    if not path:
        raise ValueError("registry path is empty")
    head, sep, tail = path.partition("\\")
    if not sep:
        # No subkey -- caller passed just "HKLM". That is legal for
        # listing root-level subkeys of a hive, so leave ``subkey``
        # empty rather than rejecting the input.
        return head, ""
    return head, tail


def parse_path(path: str) -> tuple[int, str]:
    """Resolve a registry path string to ``(hive_handle, subkey)``.

    Accepts both short ("HKLM\\...") and long ("HKEY_LOCAL_MACHINE\\...")
    hive spellings. The hive prefix match is case-insensitive. The
    subkey may be empty when the user is asking to enumerate a hive's
    direct children (e.g. ``HKLM``).

    Raises:
        ValueError: on an empty path or an unknown hive prefix.
    """
    head, subkey = _split_root(path)
    resolved = HIVE_PREFIXES.get(head.upper())
    if resolved is None:
        raise ValueError(
            f"unknown registry hive prefix {head!r} "
            f"(expected one of: {', '.join(sorted({n for n in HIVE_PREFIXES}))})"
        )
    if len(subkey) > MAX_SUBKEY_PATH:
        raise ValueError(f"registry subkey path exceeds {MAX_SUBKEY_PATH} characters")
    return resolved, subkey


# ---------------------------------------------------------------------------
# Value-type parsing
# ---------------------------------------------------------------------------


def parse_type_name(name: str) -> int:
    """Resolve a CLI-style ``--type`` argument to a ``winreg.REG_*`` code.

    The lookup is case-insensitive. Raises ``ValueError`` if the name is
    not one of the standard ``REG_*`` spellings -- callers can use the
    returned ``int`` directly with ``winreg.SetValueEx``.
    """
    if not name:
        raise ValueError("registry type name is empty")
    code = REG_TYPE_FROM_NAME.get(name.upper())
    if code is None:
        raise ValueError(
            f"unknown registry type {name!r} "
            f"(expected one of: {', '.join(sorted(REG_TYPE_FROM_NAME))})"
        )
    return code


# ---------------------------------------------------------------------------
# Value <-> string conversion for CLI / UI
# ---------------------------------------------------------------------------


def value_to_readable(raw: Any, type_code: int) -> Union[str, int, bytes, list[str]]:
    """Render a ``winreg.QueryValueEx`` payload for display.

    The :mod:`winreg` API returns a heterogeneous tuple of ``(value, type)``
    where ``value`` may be a string, integer, bytes, or list of strings
    depending on the type. This helper collapses that into a single
    printable representation:

    * ``REG_SZ`` / ``REG_EXPAND_SZ`` / ``REG_LINK`` -- the decoded str.
    * ``REG_DWORD`` / ``REG_QWORD`` -- the integer in decimal.
    * ``REG_MULTI_SZ`` -- the list joined by ``"\\n"``.
    * everything else -- the raw ``bytes`` object (caller can hex-encode
      if they want a string).
    """
    if type_code in (winreg.REG_SZ, winreg.REG_EXPAND_SZ, winreg.REG_LINK):
        if raw is None:
            return ""
        return str(raw)
    if type_code == winreg.REG_DWORD or type_code == winreg.REG_DWORD_BIG_ENDIAN:
        # winreg returns a plain int for REG_DWORD on Python 3.
        if raw is None:
            return 0
        return int(raw)
    if type_code == winreg.REG_QWORD:
        if raw is None:
            return 0
        return int(raw)
    if type_code == winreg.REG_MULTI_SZ:
        if raw is None:
            return []
        return [str(s) for s in raw]
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    if raw is None:
        return b""
    return str(raw)


def readable_to_value(text: str, type_code: int) -> Any:
    """Convert a CLI ``--value`` string into the type winreg expects.

    * ``REG_SZ`` / ``REG_EXPAND_SZ`` / ``REG_LINK`` -- ``str(text)``.
    * ``REG_DWORD`` / ``REG_DWORD_BIG_ENDIAN`` / ``REG_QWORD`` -- parsed
      integer; supports ``0x`` prefix for hex. Negative numbers use
      Python's standard signed two's-complement parsing.
    * ``REG_MULTI_SZ`` -- ``str.splitlines()``.
    * everything else -- the raw UTF-8 bytes (``REG_BINARY`` etc).
    """
    if type_code in (winreg.REG_SZ, winreg.REG_EXPAND_SZ, winreg.REG_LINK):
        return text
    if type_code in (winreg.REG_DWORD, winreg.REG_DWORD_BIG_ENDIAN, winreg.REG_QWORD):
        return _parse_int(text)
    if type_code == winreg.REG_MULTI_SZ:
        # ``splitlines`` handles ``\r\n``, ``\n``, and the empty-string
        # edge case (yields an empty list, which is what winreg expects
        # for an empty REG_MULTI_SZ).
        return text.splitlines()
    # REG_BINARY / REG_RESOURCE_* -- caller must accept raw bytes.
    return text.encode("utf-8")


def _parse_int(text: str) -> int:
    s = text.strip()
    if not s:
        raise ValueError("registry integer value is empty")
    # ``int(s, 0)`` accepts "0x...", "0o...", decimal, and rejects junk.
    try:
        return int(s, 0)
    except ValueError as exc:
        raise ValueError(f"could not parse {text!r} as an integer") from exc


# ---------------------------------------------------------------------------
# Convenience: where does a name live on a key?
# ---------------------------------------------------------------------------


def value_kind_name(type_code: Optional[int]) -> str:
    """Best-effort human label for a ``winreg`` type code.

    Returns ``"REG_<UNKNOWN>"`` for codes not in the standard table
    rather than raising -- the registry happily holds vendor-defined
    type codes that winreg never named.
    """
    if type_code is None:
        return "REG_NONE"
    if type_code == winreg.REG_NONE:
        return "REG_NONE"
    # Import here to avoid a circular import between protocol.py and
    # this module's __init__ chain.
    from myark.modules.registry.protocol import REG_TYPE_NAMES
    return REG_TYPE_NAMES.get(int(type_code), f"REG_UNKNOWN(0x{int(type_code):X})")


__all__ = [
    "DEFAULT_VALUE_NAME",
    "MAX_SUBKEY_PATH",
    "parse_path",
    "parse_type_name",
    "value_to_readable",
    "readable_to_value",
    "value_kind_name",
]