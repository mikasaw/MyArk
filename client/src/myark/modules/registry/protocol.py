"""MyArk Registry module: protocol constants (no IOCTL codes).

Quadrant ① modules carry no driver protocol -- every operation is a direct
call into a Win32 / standard-library API. This file documents that
deliberate non-presence: there are no ``IOCTL_MYARK_REGISTRY_*`` codes, no
ctypes mirrors, no shared structs. Anything that needs driver-side state
belongs to a different quadrant.

What lives here instead is a small registry-specific constant table that
both the CLI and the UI consult for hive-prefix resolution and value-type
naming. Keeping the table centralised stops the prefix spelling from
drifting between callers ("HKLM" vs "HKEY_LOCAL_MACHINE" vs "HKEY_LM").
"""

from __future__ import annotations

import winreg


# ---------------------------------------------------------------------------
# Hive prefix resolution.
#
# Users and CLI callers can spell the root hive in either short or long
# form. Resolve the prefix here once so the rest of the module talks in
# the canonical long name and the actual winreg.HKEY_* handle.
# ---------------------------------------------------------------------------

HIVE_PREFIXES: dict[str, int] = {
    # short forms (case-insensitive on input)
    "HKLM": winreg.HKEY_LOCAL_MACHINE,
    "HKCU": winreg.HKEY_CURRENT_USER,
    "HKCR": winreg.HKEY_CLASSES_ROOT,
    "HKU":  winreg.HKEY_USERS,
    "HKCC": winreg.HKEY_CURRENT_CONFIG,
    # long forms
    "HKEY_LOCAL_MACHINE":    winreg.HKEY_LOCAL_MACHINE,
    "HKEY_CURRENT_USER":     winreg.HKEY_CURRENT_USER,
    "HKEY_CLASSES_ROOT":     winreg.HKEY_CLASSES_ROOT,
    "HKEY_USERS":            winreg.HKEY_USERS,
    "HKEY_CURRENT_CONFIG":   winreg.HKEY_CURRENT_CONFIG,
}


# Canonical long-form spelling for each hive, used when re-rendering a
# path back to the user. Index by the winreg HKEY_* value to keep it
# stable across Python releases.
HIVE_CANONICAL_NAME: dict[int, str] = {
    winreg.HKEY_LOCAL_MACHINE:  "HKEY_LOCAL_MACHINE",
    winreg.HKEY_CURRENT_USER:   "HKEY_CURRENT_USER",
    winreg.HKEY_CLASSES_ROOT:   "HKEY_CLASSES_ROOT",
    winreg.HKEY_USERS:          "HKEY_USERS",
    winreg.HKEY_CURRENT_CONFIG: "HKEY_CURRENT_CONFIG",
}


# ---------------------------------------------------------------------------
# Value-type names.
#
# ``winreg`` exposes the integer type code per value; the standard
# library does not ship a human-readable mapping. This table mirrors
# ``winnt.h`` / ``Microsoft.Win32.RegistryValueKind`` names so CLI
# output and UI columns are stable across versions.
# ---------------------------------------------------------------------------

REG_TYPE_NAMES: dict[int, str] = {
    winreg.REG_BINARY:     "REG_BINARY",
    winreg.REG_DWORD:      "REG_DWORD",
    winreg.REG_DWORD_BIG_ENDIAN: "REG_DWORD_BIG_ENDIAN",
    winreg.REG_EXPAND_SZ:  "REG_EXPAND_SZ",
    winreg.REG_LINK:       "REG_LINK",
    winreg.REG_MULTI_SZ:   "REG_MULTI_SZ",
    winreg.REG_NONE:       "REG_NONE",
    winreg.REG_RESOURCE_LIST: "REG_RESOURCE_LIST",
    winreg.REG_FULL_RESOURCE_DESCRIPTOR: "REG_FULL_RESOURCE_DESCRIPTOR",
    winreg.REG_RESOURCE_REQUIREMENTS_LIST: "REG_RESOURCE_REQUIREMENTS_LIST",
    winreg.REG_SZ:         "REG_SZ",
    winreg.REG_QWORD:      "REG_QWORD",
}


# Reverse map: ``--type REG_SZ`` style strings the user types on the CLI
# to the integer code ``winreg`` expects. ``REG_DWORD_BIG_ENDIAN`` and
# the resource-list variants are accepted but rarely useful; they're
# included for completeness.
REG_TYPE_FROM_NAME: dict[str, int] = {name: code for code, name in REG_TYPE_NAMES.items()}


# ---------------------------------------------------------------------------
# Sentinel for "this module has no IOCTL surface" -- guards against
# future contributors reaching for a ctypes / IOCTL pattern by accident.
# ---------------------------------------------------------------------------

NO_IOCTL: str = "registry module is pure R3; no IOCTL codes apply."


__all__ = [
    "HIVE_PREFIXES",
    "HIVE_CANONICAL_NAME",
    "REG_TYPE_NAMES",
    "REG_TYPE_FROM_NAME",
    "NO_IOCTL",
]