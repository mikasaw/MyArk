"""MyArk File module: protocol constants (no IOCTL codes).

Quadrant ① modules carry no driver protocol -- every operation is a direct
call into a Win32 / standard-library API. This file documents that
deliberate non-presence: there are no ``IOCTL_MYARK_FILE_*`` codes, no
ctypes mirrors of driver structs, no shared memory. Anything that needs
driver-side state (raw-NTFS read of metadata, alternate data stream
enumeration, etc.) belongs to a different quadrant.

What lives here instead is the small File-specific constant table that
both the CLI and the UI consult when rendering ``WIN32_FILE_ATTRIBUTE_DATA``
fields and the security-descriptor components returned by
``GetNamedSecurityInfoW``:

* :data:`FILE_ATTRIBUTE_NAMES` -- the canonical human label for every
  documented ``FILE_ATTRIBUTE_*`` flag bit. ``GetFileAttributesEx``
  returns a bitmask; the UI/CLI breaks it into the textual flag list.
* :data:`INTEGRITY_LEVEL_NAMES` -- the canonical human label for every
  documented ``TOKEN_MANDATORY_*`` RID. The mandatory-label ACE in the
  SD carries a SID whose last sub-authority is the integrity RID.
* :data:`NO_IOCTL` -- sentinel that guards against a future contributor
  reaching for a ctypes / IOCTL pattern by accident.

The driver path never receives a packet from this module -- the call
chain is purely ``myark-cli file info <path>`` ->
``parser.fetch_file_info()`` -> ``kernel32.GetFileAttributesExW`` ->
``WIN32_FILE_ATTRIBUTE_DATA`` -> dict.
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Sentinel for "this module has no IOCTL surface" -- guards against future
# contributors reaching for a ctypes / IOCTL pattern by accident.
# ---------------------------------------------------------------------------

NO_IOCTL: str = "file module is pure R3; no IOCTL codes apply."


# ---------------------------------------------------------------------------
# File attribute name table.
#
# ``GetFileAttributesEx`` returns a DWORD bitmask. Microsoft has been
# slowly extending the table (the kernel headers list ``FILE_ATTRIBUTE_
# INTEGRITY_STREAM`` and ``FILE_ATTRIBUTE_NO_SCRUB_DATA`` alongside the
# original two dozen values), so we keep our own list rather than
# hard-coding a single literal in the CLI / UI. Bits outside the table
# render as ``"FILE_ATTRIBUTE_0x<HEX>"`` so a future Windows build does
# not silently mislabel a row.
# ---------------------------------------------------------------------------

FILE_ATTRIBUTE_NAMES: dict[int, str] = {
    0x00000001: "READONLY",
    0x00000002: "HIDDEN",
    0x00000004: "SYSTEM",
    0x00000010: "DIRECTORY",
    0x00000020: "ARCHIVE",
    0x00000040: "DEVICE",
    0x00000080: "NORMAL",
    0x00000100: "TEMPORARY",
    0x00000200: "SPARSE_FILE",
    0x00000400: "REPARSE_POINT",
    0x00000800: "COMPRESSED",
    0x00001000: "OFFLINE",
    0x00002000: "NOT_CONTENT_INDEXED",
    0x00004000: "ENCRYPTED",
    0x00008000: "INTEGRITY_STREAM",
    0x00010000: "VIRTUAL",
    0x00020000: "NO_SCRUB_DATA",
    0x00040000: "EA",
    0x00080000: "PINNED",
    0x00100000: "UNPINNED",
    0x00400000: "RECALL_ON_OPEN",
    0x00800000: "RECALL_ON_DATA_ACCESS",
}


# ---------------------------------------------------------------------------
# Integrity level table.
#
# The mandatory-integrity-label ACE in the SD carries a SID whose final
# sub-authority (``SubAuthority[SidSubAuthorityCount - 1]``) is the
# integrity RID. The values below are from ``winnt.h`` and Microsoft's
# "Windows Integrity Mechanism" white paper. Codes outside the table
# render as ``"INTEGRITY_<n>"`` so a future Windows build does not
# silently mislabel a row.
#
# Note that ``S-1-16-0`` (Untrusted) and ``S-1-16-0xFFFF`` (System) are
# boundary values that do not normally appear on user files, but the
# Windows kernel does issue them, so they are included for completeness.
# ---------------------------------------------------------------------------

INTEGRITY_LEVEL_NAMES: dict[int, str] = {
    0x0000: "UNTRUSTED",
    0x1000: "LOW",
    0x2000: "MEDIUM",
    0x2100: "MEDIUM_PLUS",
    0x3000: "HIGH",
    0x4000: "SYSTEM",
    0x5000: "PROTECTED_PROCESS",
    0xFFFF: "SECURE_PROCESS",
}


# ---------------------------------------------------------------------------
# Security-information flag table.
#
# ``GetNamedSecurityInfoW`` accepts a bitmask selecting which
# components to return. We mirror the ``SECURITY_INFORMATION`` flags so
# CLI / UI can refer to them by name instead of repeating the raw
# constants. Codes outside the table render as ``"SECURITY_INFORMATION_
# 0x<HEX>"`` -- the table is stable across Windows versions because
# it is part of the documented contract for any consumer of security
# descriptors.
# ---------------------------------------------------------------------------

SECURITY_INFORMATION_NAMES: dict[int, str] = {
    0x00000001: "OWNER",
    0x00000002: "GROUP",
    0x00000004: "DACL",
    0x00000008: "SACL",
    0x00000010: "LABEL",
    0x00000020: "ATTRIBUTE",
    0x00000040: "SCOPE",
    0x00010000: "BACKUP",
    0x00020000: "PROTECTED_DACL",
    0x00040000: "PROTECTED_SACL",
    0x00080000: "UNPROTECTED_DACL",
    0x00100000: "UNPROTECTED_SACL",
    0x00200000: "DACL_AUTO_INHERIT_REQ",
    0x00400000: "SACL_AUTO_INHERIT_REQ",
    0x00800000: "DACL_AUTO_INHERITED",
    0x01000000: "SACL_AUTO_INHERITED",
    0x02000000: "DACL_PROTECTED",
    0x04000000: "SACL_PROTECTED",
    0x08000000: "RM_CONTROL_VALID",
}


# ---------------------------------------------------------------------------
# Object types accepted by ``GetNamedSecurityInfoW``.
#
# We use ``SE_FILE_OBJECT`` for files / directories -- the file SDDL
# rendering (with the "O:" / "D:" / "S:" prefixes) is unique to
# file-scoped security descriptors. ``SE_REGISTRY_KEY`` etc. would
# produce the same wire format but the kernel's own ``icacls.exe``
# output treats them differently.
#
# NOTE: the ``SE_FILE_OBJECT`` enum value is **1**, not 2. The
# ``SE_OBJECT_TYPE`` enum in ``winnt.h`` starts at 0 with
# ``SE_UNKNOWN_OBJECT_TYPE`` and increments by one per object type,
# so ``SE_FILE_OBJECT`` lands at index 1. Passing 2 (the value of
# ``SE_SERVICE``) silently produces ``ERROR_INVALID_NAME`` rather
# than a clear error -- the function decodes the object-type byte
# but the kernel doesn't recognise "service" against a file path.
# ---------------------------------------------------------------------------

SE_FILE_OBJECT: int = 1


# ---------------------------------------------------------------------------
# SDDL revision constants.
#
# ``ConvertSecurityDescriptorToStringSecurityDescriptorW`` requires the
# caller to specify the SDDL revision. Microsoft has shipped only one --
# ``SDDL_REVISION_1`` = 1 -- since the original Windows 2000 release,
# but the constant is part of the API contract, so we pin it here.
# ---------------------------------------------------------------------------

SDDL_REVISION_1: int = 1


# ---------------------------------------------------------------------------
# Reserved column width hints for the UI Treeview.
#
# These are advisory -- the Tkinter tab still lets the user resize any
# column -- but they keep the initial layout readable on a 1080p display
# without manual adjustment. Centralising them avoids drift between the
# Tk treeview, the CLI table, and any future HTML export.
# ---------------------------------------------------------------------------

COLUMN_WIDTHS: dict[str, int] = {
    "name":    220,
    "type":    120,
    "size":    120,
    "flags":   180,
    "owner":   220,
    "sddl":    480,
}


__all__ = [
    "NO_IOCTL",
    "FILE_ATTRIBUTE_NAMES",
    "INTEGRITY_LEVEL_NAMES",
    "SECURITY_INFORMATION_NAMES",
    "SE_FILE_OBJECT",
    "SDDL_REVISION_1",
    "COLUMN_WIDTHS",
]