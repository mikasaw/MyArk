"""MyArk File module: ctypes bindings + structured parsers.

The File module is pure R3: it never opens the driver. Every read is a
direct call into ``kernel32`` / ``advapi32`` / ``sddl``. The functions
used here:

* ``kernel32.GetFileAttributesExW`` -- populate a
  ``WIN32_FILE_ATTRIBUTE_DATA`` with attribute flags + size + times.
* ``advapi32.GetNamedSecurityInfoW`` -- fetch a security descriptor
  with a caller-selected bitmask of components (owner, DACL, SACL,
  label). Returns a self-relative security descriptor (``PSECURITY_
  DESCRIPTOR``) and out-pointers to each component.
* ``advapi32.LookupAccountSidW`` -- resolve a SID into
  ``DOMAIN\\Account`` form.
* ``advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW``
  -- render a security descriptor as an SDDL string
  (``O:D:D:P(A;...)`` style). The SDDL functions moved from
  ``sddl.dll`` to ``advapi32.dll`` in Windows Vista, so we resolve
  them via advapi32 rather than carry a separate ``sddl.dll`` handle.
* ``kernel32.LocalFree`` -- release the strings returned by the SDDL
  converter; ``advapi32`` uses the Local allocator for cross-DLL
  ownership.

The S5.3 spec scopes this module to *read-only* inspection: no writes,
no DACL modifications, no NTFS alternate data streams. Actions
(mutation, ACL write, copy/rename) live in the actions module (S8).

Everything in this file is pure ctypes + struct unpacking. No driver
handle, no IOCTL, no shared memory.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import datetime
import struct
from typing import Any, Optional

from myark.modules.file.protocol import (
    FILE_ATTRIBUTE_NAMES,
    INTEGRITY_LEVEL_NAMES,
    SDDL_REVISION_1,
    SE_FILE_OBJECT,
    SECURITY_INFORMATION_NAMES,
)


# ---------------------------------------------------------------------------
# Windows DLL bindings.
# ---------------------------------------------------------------------------


_kernel32 = ctypes.WinDLL("kernel32.dll")
_advapi32 = ctypes.WinDLL("advapi32.dll")
# ``sddl.dll`` was the original home for ``ConvertSecurityDescriptorToStringSecurityDescriptorW``
# but the function moved to ``advapi32.dll`` in Windows Vista. Resolving
# it through advapi32 keeps the binding portable across every supported
# Windows SKU without depending on the legacy ``sddl.dll`` shim DLL.


# ---------------------------------------------------------------------------
# ctypes struct mirrors.
#
# ``WIN32_FILE_ATTRIBUTE_DATA`` is the populated struct returned by
# ``GetFileAttributesExW``. The file-time fields are 64-bit Windows
# FILETIME values (100-ns ticks since 1601-01-01); the struct also
# carries the high / low halves of the file size as two separate DWORDs
# to avoid forcing 32-bit callers to deal with a 64-bit integer. The
# layout must match the C declaration exactly -- the kernel writes the
# file time + attribute flags at fixed offsets.
# ---------------------------------------------------------------------------


class FILETIME(ctypes.Structure):
    """ctypes mirror of the Windows ``FILETIME`` struct."""

    _fields_ = [
        ("dwLowDateTime",  ctypes.c_uint32),
        ("dwHighDateTime", ctypes.c_uint32),
    ]


class WIN32_FILE_ATTRIBUTE_DATA(ctypes.Structure):
    """ctypes mirror of ``WIN32_FILE_ATTRIBUTE_DATA``.

    Fields are ordered to match the C declaration in ``WinBase.h``;
    ``GetFileAttributesExW`` writes them at fixed offsets with no
    padding beyond what natural DWORD alignment already provides.
    """

    _fields_ = [
        ("dwFileAttributes", ctypes.c_uint32),
        ("ftCreationTime",   FILETIME),
        ("ftLastAccessTime", FILETIME),
        ("ftLastWriteTime",  FILETIME),
        ("nFileSizeHigh",    ctypes.c_uint32),
        ("nFileSizeLow",     ctypes.c_uint32),
    ]


# ---------------------------------------------------------------------------
# Native API bindings.
# ---------------------------------------------------------------------------


# BOOL GetFileAttributesExW(LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId,
#                           LPVOID lpFileInformation);
_GET_FILEEX_INFO_LEVELS = ctypes.c_int
_GetFileAttributesExW = _kernel32.GetFileAttributesExW
_GetFileAttributesExW.restype = ctypes.c_int
_GetFileAttributesExW.argtypes = [
    ctypes.c_wchar_p,                  # LPCWSTR
    _GET_FILEEX_INFO_LEVELS,           # GET_FILEEX_INFO_LEVELS
    ctypes.c_void_p,                   # LPVOID
]
# ``GET_FILEEX_INFO_LEVELS`` is a Win32 enum whose first value is
# ``GetFileExInfoStandard`` (= 0). Per the Microsoft SDK header, the
# enum starts at zero, not one -- using 1 here (which is
# ``GetFileExMaxInfoLevel``) causes the API to silently return zero
# values rather than failing, which makes the bug invisible until the
# caller checks the file size. Pass 0.
_GET_FILEEX_INFO_STANDARD: int = 0


# DWORD GetNamedSecurityInfoW(LPCWSTR pObjectName, SE_OBJECT_TYPE ObjectType,
#                              SECURITY_INFORMATION SecurityInfo,
#                              PSID *ppsidOwner, PSID *ppsidGroup,
#                              PACL *ppDacl, PACL *ppSacl,
#                              PSECURITY_DESCRIPTOR *ppSecurityDescriptor);
_GetNamedSecurityInfoW = _advapi32.GetNamedSecurityInfoW
_GetNamedSecurityInfoW.restype = ctypes.c_uint32
_GetNamedSecurityInfoW.argtypes = [
    ctypes.c_wchar_p,                  # LPCWSTR
    ctypes.c_int,                      # SE_OBJECT_TYPE
    ctypes.c_uint32,                   # SECURITY_INFORMATION
    ctypes.POINTER(ctypes.c_void_p),   # PSID*
    ctypes.POINTER(ctypes.c_void_p),   # PSID*
    ctypes.POINTER(ctypes.c_void_p),   # PACL*
    ctypes.POINTER(ctypes.c_void_p),   # PACL*
    ctypes.POINTER(ctypes.c_void_p),   # PSECURITY_DESCRIPTOR*
]


# BOOL LookupAccountSidW(LPCWSTR lpSystemName, PSID lpSid,
#                        LPWSTR lpName, LPDWORD cchName,
#                        LPWSTR lpReferencedDomainName, LPDWORD cchReferencedDomainName,
#                        PSID_NAME_USE peUse);
_LookupAccountSidW = _advapi32.LookupAccountSidW
_LookupAccountSidW.restype = ctypes.c_int
_LookupAccountSidW.argtypes = [
    ctypes.c_wchar_p,                  # LPCWSTR lpSystemName (NULL = local)
    ctypes.c_void_p,                   # PSID
    ctypes.c_wchar_p,                  # LPWSTR lpName
    ctypes.POINTER(ctypes.c_uint32),   # LPDWORD cchName
    ctypes.c_wchar_p,                  # LPWSTR lpReferencedDomainName
    ctypes.POINTER(ctypes.c_uint32),   # LPDWORD cchReferencedDomainName
    ctypes.POINTER(ctypes.c_uint32),   # PSID_NAME_USE
]


# BOOL ConvertSecurityDescriptorToStringSecurityDescriptorW(
#     PSECURITY_DESCRIPTOR SecurityDescriptor, DWORD StringSDRevision,
#     SECURITY_INFORMATION SecurityInformation,
#     LPWSTR *StringSecurityDescriptor, PULONG StringSecurityDescriptorLen);
_ConvertSecurityDescriptorToStringSecurityDescriptorW = _advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW
_ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = ctypes.c_int
_ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
    ctypes.c_void_p,                   # PSECURITY_DESCRIPTOR
    ctypes.c_uint32,                   # DWORD
    ctypes.c_uint32,                   # SECURITY_INFORMATION
    ctypes.POINTER(ctypes.c_wchar_p),  # LPWSTR*
    ctypes.POINTER(ctypes.c_uint32),   # PULONG
]


# HLOCAL LocalFree(HLOCAL hMem);
_LocalFree = _kernel32.LocalFree
_LocalFree.restype = ctypes.c_void_p
_LocalFree.argtypes = [ctypes.c_void_p]


# ---------------------------------------------------------------------------
# SECURITY_INFORMATION flag constants.
#
# Defined locally to avoid pulling in the entire ``ctypes.wintypes`` table
# for the four we use.
# ---------------------------------------------------------------------------


_OWNER_SECURITY_INFORMATION: int = 0x00000001
_GROUP_SECURITY_INFORMATION: int = 0x00000002
_DACL_SECURITY_INFORMATION:  int = 0x00000004
_SACL_SECURITY_INFORMATION:  int = 0x00000008
_LABEL_SECURITY_INFORMATION: int = 0x00000010

# Set used for a full SDDL dump (owner + group + dacl + sacl + label).
_FULL_SDDL_INFO: int = (
    _OWNER_SECURITY_INFORMATION
    | _GROUP_SECURITY_INFORMATION
    | _DACL_SECURITY_INFORMATION
    | _SACL_SECURITY_INFORMATION
    | _LABEL_SECURITY_INFORMATION
)

# Win32 error codes we care about. Defined locally to avoid pulling in
# the entire ``ctypes.wintypes`` table for two constants.
_ERROR_SUCCESS: int = 0
_ERROR_FILE_NOT_FOUND: int = 2
_ERROR_PATH_NOT_FOUND: int = 3
_ERROR_ACCESS_DENIED: int = 5
_ERROR_INVALID_NAME: int = 123
_ERROR_NOT_A_REPARSE_POINT: int = 0x1128  # 4396

# SidNameUse values from ``winnt.h``.
_SID_TYPE_USER: int = 1
_SID_TYPE_GROUP: int = 2
_SID_TYPE_DOMAIN: int = 3
_SID_TYPE_ALIAS: int = 4
_SID_TYPE_WELL_KNOWN_GROUP: int = 5
_SID_TYPE_DELETED_ACCOUNT: int = 6
_SID_TYPE_INVALID: int = 7
_SID_TYPE_UNKNOWN: int = 8
_SID_TYPE_COMPUTER: int = 9
_SID_TYPE_LABEL: int = 10
_SID_TYPE_LOGON_SESSION: int = 11


# ACE type constants from ``winnt.h``.
_ACE_TYPE_SYSTEM_MANDATORY_LABEL: int = 0x11

# Integrity level RID is encoded as the last sub-authority of the SID
# carried in the mandatory-label ACE. The high byte indicates the
# "package" (0x10 == mandatory label); we mask off the high byte when
# looking up the friendly name.
_SID_INTEGRITY_PACKAGE: int = 0x10
_INTEGRITY_RID_MASK: int = 0x0000FFFF


# ---------------------------------------------------------------------------
# Long-path prefix helpers.
#
# Win32 APIs reject paths longer than MAX_PATH (260 chars) unless the
# caller passes an explicit ``\\?\`` prefix. The File module is a
# read-only inspection tool that the user may legitimately point at
# paths inside ``C:\Users\<name>\AppData\Local\Temp\...`` chains that
# easily exceed 260 chars; auto-prefixing keeps the tool working
# without forcing every CLI invocation to remember the convention.
# ---------------------------------------------------------------------------


_MAX_PATH: int = 260


def _normalize_long_path(path: str) -> str:
    r"""Prepend ``\\?\`` to ``path`` if it is not already long-path form.

    ``\\?\`` bypasses ``MAX_PATH`` parsing in the kernel and disables
    path normalisation, so we apply it conservatively: only on paths
    that exceed ``MAX_PATH`` chars and lack an existing prefix.
    Returns ``path`` unchanged otherwise -- many Win32 APIs treat
    ``\\?\``-prefixed paths specially (no forward slashes, no relative
    path resolution, no ``\\.\\`` device namespace).
    """
    if not path:
        return path
    # ``\\?\`` or ``\\.\`` or ``\\?\UNC\<server>\<share>`` are already
    # long-path / device-path prefixed. Leave them alone.
    if path.startswith("\\\\?\\") or path.startswith("\\\\.\\"):
        return path
    if len(path) >= _MAX_PATH:
        # Insert the ``\\?\`` prefix and normalise forward slashes the
        # way the Win32 APIs expect.
        return "\\\\?\\" + path.replace("/", "\\")
    return path


# ---------------------------------------------------------------------------
# FILETIME helpers.
# ---------------------------------------------------------------------------


_FILETIME_EPOCH_DIFF: int = 116444736000000000  # 100-ns ticks between 1601-01-01 and 1970-01-01


def _filetime_to_datetime(ft: FILETIME) -> Optional[datetime.datetime]:
    """Convert a ``FILETIME`` to a naive UTC ``datetime``.

    Returns ``None`` when the FILETIME is the zero sentinel (which the
    kernel writes for files whose time stamps are unknown or have not
    been refreshed yet) -- a naive ``datetime(1970, 1, 1)`` would
    otherwise leak into the UI as a misleading "Jan 1, 1970" label.
    """
    ticks = (ft.dwHighDateTime << 32) | ft.dwLowDateTime
    if ticks == 0:
        return None
    seconds = (ticks - _FILETIME_EPOCH_DIFF) / 10_000_000
    try:
        # ``datetime.UTC`` was added in Python 3.11; on 3.14 it's the
        # preferred replacement for ``datetime.utcfromtimestamp``.
        return datetime.datetime.fromtimestamp(seconds, datetime.UTC).replace(tzinfo=None)
    except (OSError, OverflowError, ValueError):
        # ``fromtimestamp`` raises on years outside 1..9999, which
        # happens on some filesystems that store pre-1970 timestamps.
        return None


def _format_filetime(ft: FILETIME) -> str:
    """Human-friendly rendering for a ``FILETIME``: ISO 8601 or "(unset)"."""
    dt = _filetime_to_datetime(ft)
    if dt is None:
        return "(unset)"
    return dt.isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# SID helpers.
# ---------------------------------------------------------------------------


class _SID(ctypes.Structure):
    """ctypes mirror of the variable-length Windows ``SID`` struct.

    The C declaration is::

        typedef struct _SID {
            BYTE  Revision;
            BYTE  SubAuthorityCount;
            SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
            DWORD SubAuthority[ANYSIZE_ARRAY];
        } SID, *PISID;

    ``SID_IDENTIFIER_AUTHORITY`` is a 6-byte big-endian identifier.
    Modeling the full layout in ctypes lets the parser pull a SID out
    of a mandatory-label ACE without going through
    ``ConvertStringSidToSidW`` -- the latter would round-trip the SID
    through text, which loses fidelity on rare sub-authority shapes
    that Win32 refuses to serialise.
    """

    _fields_ = [
        ("Revision",          ctypes.c_uint8),
        ("SubAuthorityCount", ctypes.c_uint8),
        ("IdentifierAuthority", ctypes.c_uint8 * 6),
        # First ``SubAuthorityCount`` entries are the real sub-authorities.
        ("SubAuthority",      ctypes.c_uint32 * 8),
    ]


def _sid_to_string(sid_ptr: int) -> Optional[str]:
    """Render a SID (as a Win32 PSID) in ``S-1-5-32-544`` form.

    Returns ``None`` when ``sid_ptr`` is 0 (NULL) -- a NULL owner SID
    is legal (``SeNullSid``) but a CLI ``file owner`` query on a NULL
    owner should report "no owner" rather than rendering a bogus SID.
    """
    if not sid_ptr:
        return None
    sid = _SID.from_address(sid_ptr)
    auth = sid.IdentifierAuthority
    # ``IdentifierAuthority`` is stored as a 6-byte big-endian value
    # so the high 2 bytes are always zero on a standard authority.
    authority = int.from_bytes(bytes(auth), "big")
    subauths = [int(sid.SubAuthority[i]) for i in range(sid.SubAuthorityCount)]
    return f"S-{sid.Revision}-{authority}-{'-'.join(str(x) for x in subauths)}"


def _lookup_account(sid_ptr: int) -> dict[str, Any]:
    """Resolve a SID to ``domain\\account`` + sid-use via ``LookupAccountSidW``.

    Returns a dict shaped ``{"sid": str|None, "account": str, "domain": str,
    "use": str, "use_code": int}``. ``account`` is the bare name (no
    domain prefix); callers compose ``domain\\account`` if both are
    non-empty.
    """
    result: dict[str, Any] = {
        "sid":      _sid_to_string(sid_ptr),
        "account":  "",
        "domain":   "",
        "use":      "",
        "use_code": 0,
    }
    if not sid_ptr:
        result["account"] = "(no owner)"
        return result

    name_size = ctypes.c_uint32(0)
    domain_size = ctypes.c_uint32(0)
    sid_use = ctypes.c_uint32(0)
    # First call returns False (and fills the sizes) when the buffers
    # are NULL / zero -- that's how Win32 signals "I need N chars for
    # the name and M for the domain". ``GetLastError`` after the call
    # would be ``ERROR_INSUFFICIENT_BUFFER`` (122).
    rc = _LookupAccountSidW(
        None,
        sid_ptr,
        None,
        ctypes.byref(name_size),
        None,
        ctypes.byref(domain_size),
        ctypes.byref(sid_use),
    )
    if rc or (name_size.value == 0 and domain_size.value == 0):
        # ``rc == 0`` with both sizes == 0 means the call genuinely
        # failed (e.g. the SID is malformed). Bail out so the caller
        # sees the SID string but no account name -- they can still
        # tell which SID they were looking at.
        return result

    name_buf = ctypes.create_unicode_buffer(name_size.value + 1)
    domain_buf = ctypes.create_unicode_buffer(domain_size.value + 1)
    rc = _LookupAccountSidW(
        None,
        sid_ptr,
        name_buf,
        ctypes.byref(name_size),
        domain_buf,
        ctypes.byref(domain_size),
        ctypes.byref(sid_use),
    )
    if not rc:
        return result

    result["account"] = name_buf.value
    result["domain"] = domain_buf.value
    result["use_code"] = int(sid_use.value)
    result["use"] = _sid_use_name(int(sid_use.value))
    return result


def _sid_use_name(code: int) -> str:
    """Render a SID_NAME_USE enum value as a human string."""
    return {
        _SID_TYPE_USER:            "USER",
        _SID_TYPE_GROUP:           "GROUP",
        _SID_TYPE_DOMAIN:          "DOMAIN",
        _SID_TYPE_ALIAS:           "ALIAS",
        _SID_TYPE_WELL_KNOWN_GROUP: "WELL_KNOWN_GROUP",
        _SID_TYPE_DELETED_ACCOUNT: "DELETED_ACCOUNT",
        _SID_TYPE_INVALID:         "INVALID",
        _SID_TYPE_UNKNOWN:         "UNKNOWN",
        _SID_TYPE_COMPUTER:        "COMPUTER",
        _SID_TYPE_LABEL:           "LABEL",
        _SID_TYPE_LOGON_SESSION:   "LOGON_SESSION",
    }.get(int(code), f"UNKNOWN(0x{int(code):X})")


# ---------------------------------------------------------------------------
# ACL helpers -- for the integrity-level path we walk the SACL by hand
# to find the SYSTEM_MANDATORY_LABEL_ACE rather than round-tripping
# through SDDL text.
# ---------------------------------------------------------------------------


class _ACE_HEADER(ctypes.Structure):
    _fields_ = [
        ("AceType",  ctypes.c_uint8),
        ("AceFlags", ctypes.c_uint8),
        ("AceSize",  ctypes.c_uint16),
    ]


class _SYSTEM_MANDATORY_LABEL_ACE(ctypes.Structure):
    _fields_ = [
        ("Header", _ACE_HEADER),
        ("Mask",   ctypes.c_uint32),
        # Followed by the inline SID at offset 8.
        ("SidStart", ctypes.c_uint32),
    ]


# _ACL header is 8 bytes: AclRevision (1), Sbz1 (1), AclSize (2),
# AceCount (2), Sbz2 (2). ACEs follow contiguously.
_ACL_HEADER_SIZE: int = 8


def _find_mandatory_label_rid(sacl_ptr: int) -> Optional[int]:
    """Return the integrity RID from a SACL's mandatory-label ACE, or None.

    Windows places the mandatory-label ACE in the SACL. There is at
    most one such ACE per file -- the kernel overwrites on write --
    so we return the first match. The SID's last sub-authority is the
    integrity RID; for S-1-16-0x2000 the high nibble is the
    "mandatory-label" package tag (0x10), the low nibble is the level
    (0x2000 == MEDIUM).
    """
    if not sacl_ptr:
        return None
    # ``AclSize`` is at offset 2 of the ACL header; ``AceCount`` at 4.
    acl_size = struct.unpack_from("<H", ctypes.string_at(sacl_ptr + 2, 8), 0)[0]
    ace_count = struct.unpack_from("<H", ctypes.string_at(sacl_ptr + 4, 8), 0)[0]
    offset = _ACL_HEADER_SIZE
    for _ in range(ace_count):
        if offset + 4 > acl_size:
            return None
        # The 4-byte ACE header lives at ``sacl_ptr + offset``.
        header_buf = ctypes.string_at(sacl_ptr + offset, 4)
        ace_type = header_buf[0]
        ace_size = struct.unpack_from("<H", header_buf, 2)[0]
        if ace_type == _ACE_TYPE_SYSTEM_MANDATORY_LABEL and ace_size >= 8 + 12:
            # The mandatory-label ACE has a 4-byte header + 4-byte
            # access mask + the SID. The SID layout starts with
            # revision (1) + subauth-count (1) + authority (6) =
            # 8 bytes, then ``subauth_count`` DWORDs. We want the
            # LAST sub-authority (the integrity RID).
            sid_buf = ctypes.string_at(sacl_ptr + offset + 8, 12)
            subauth_count = sid_buf[1]
            # Total SID bytes = 8 + 4*subauth_count.
            sid_full = ctypes.string_at(
                sacl_ptr + offset + 8, 8 + 4 * subauth_count,
            )
            last_subauth_offset = 8 + (subauth_count - 1) * 4 if subauth_count > 0 else None
            if last_subauth_offset is None:
                offset += ace_size
                continue
            rid = struct.unpack_from(
                "<I", sid_full, last_subauth_offset,
            )[0]
            return int(rid) & _INTEGRITY_RID_MASK
        offset += ace_size
    return None


# ---------------------------------------------------------------------------
# Native buffer fetches.
# ---------------------------------------------------------------------------


def _check(rc: int, what: str) -> None:
    """Translate a Win32 ``DWORD`` return into a Python exception."""
    if rc == _ERROR_SUCCESS:
        return
    # Map a handful of common codes to nicer error messages; the rest
    # surface as raw ``Win32 error N``.
    name = {
        _ERROR_FILE_NOT_FOUND:  "file not found",
        _ERROR_PATH_NOT_FOUND:  "path not found",
        _ERROR_ACCESS_DENIED:   "access denied",
        _ERROR_INVALID_NAME:    "invalid path syntax",
    }.get(int(rc), f"Win32 error {int(rc)}")
    raise OSError(f"{what} failed: {name}")


def _fetch_file_attributes(path: str) -> WIN32_FILE_ATTRIBUTE_DATA:
    """Call ``GetFileAttributesExW`` and return a populated struct."""
    fad = WIN32_FILE_ATTRIBUTE_DATA()
    rc = _GetFileAttributesExW(
        _normalize_long_path(path),
        _GET_FILEEX_INFO_STANDARD,
        ctypes.byref(fad),
    )
    if not rc:
        err = ctypes.get_last_error() or _ERROR_FILE_NOT_FOUND
        raise OSError(f"GetFileAttributesExW failed: Win32 error {err}")
    return fad


def _fetch_security_descriptor(
    path: str,
    info: int,
) -> int:
    """Call ``GetNamedSecurityInfoW`` and return the SD pointer.

    The returned ``PSECURITY_DESCRIPTOR`` is a self-relative SD owned
    by the Local allocator (per the ``GetNamedSecurityInfoW`` contract).
    Out-pointers (``owner_sid_ptr``, ``dacl_ptr``, ``sacl_ptr``) are
    pointers *into* the SD -- do not free them separately. The caller
    must :func:`_LocalFree` the SD pointer.

    When the caller does not ask for a particular component (e.g.
    only requests ``OWNER_SECURITY_INFORMATION``), the corresponding
    out-pointer comes back as ``None`` rather than ``0``. We normalise
    those to ``0`` so the rest of the module can compare against ``0``
    without handling ``None`` separately.
    """
    owner_sid = ctypes.c_void_p(0)
    group_sid = ctypes.c_void_p(0)
    dacl_ptr = ctypes.c_void_p(0)
    sacl_ptr = ctypes.c_void_p(0)
    sd_ptr = ctypes.c_void_p(0)
    rc = _GetNamedSecurityInfoW(
        _normalize_long_path(path),
        SE_FILE_OBJECT,
        info,
        ctypes.byref(owner_sid),
        ctypes.byref(group_sid),
        ctypes.byref(dacl_ptr),
        ctypes.byref(sacl_ptr),
        ctypes.byref(sd_ptr),
    )
    _check(rc, f"GetNamedSecurityInfoW(info=0x{info:X})")
    return (
        int(sd_ptr.value or 0),
        int(owner_sid.value or 0),
        int(dacl_ptr.value or 0),
        int(sacl_ptr.value or 0),
    )


def _localfree(handle: int) -> None:
    """Release a Local-allocated buffer; ignore ``NULL`` handles."""
    if handle:
        _LocalFree(handle)


def _sd_to_sddl(sd_ptr: int, info: int) -> str:
    """Render a security descriptor as an SDDL string.

    Releases the Local-allocated string buffer before returning.
    """
    if not sd_ptr:
        return ""
    out_str = ctypes.c_wchar_p(0)
    out_len = ctypes.c_uint32(0)
    rc = _ConvertSecurityDescriptorToStringSecurityDescriptorW(
        sd_ptr,
        SDDL_REVISION_1,
        info,
        ctypes.byref(out_str),
        ctypes.byref(out_len),
    )
    if not rc or not out_str.value:
        return ""
    # Copy into a Python string BEFORE freeing the C buffer.
    sddl = out_str.value
    _localfree(int(ctypes.cast(out_str, ctypes.c_void_p).value))
    return sddl


# ---------------------------------------------------------------------------
# Row -> dict conversion.
# ---------------------------------------------------------------------------


def file_info_to_dict(fad: WIN32_FILE_ATTRIBUTE_DATA) -> dict[str, Any]:
    """Render a ``WIN32_FILE_ATTRIBUTE_DATA`` as a JSON-friendly dict.

    Field semantics:

    * ``flags``        -- raw ``dwFileAttributes`` bitmask, as ``int``.
    * ``flags_list``   -- the bitmask broken into the textual names from
    :data:`FILE_ATTRIBUTE_NAMES`. Unrecognised bits surface as
    ``"FILE_ATTRIBUTE_0x<HEX>"`` so a future Windows build does not
    silently mislabel a row.
    * ``size``         -- combined 64-bit file size (``(high<<32)|low``).
    * ``created`` / ``accessed`` / ``modified`` -- human-readable
    ISO-8601 timestamps in UTC, or ``"(unset)"`` for the zero
    sentinel.
    * ``is_directory`` -- convenience flag derived from
    ``FILE_ATTRIBUTE_DIRECTORY``; the UI uses it to render a folder
    icon without re-checking the bitmask.
    """
    raw_flags = int(fad.dwFileAttributes)
    names: list[str] = []
    for bit, label in sorted(FILE_ATTRIBUTE_NAMES.items()):
        if raw_flags & bit:
            names.append(f"FILE_ATTRIBUTE_{label}")
    # Catch the bits the table doesn't know about -- render their
    # ``"FILE_ATTRIBUTE_0x<HEX>"`` spelling so the user sees what
    # is unknown.
    known_mask = 0
    for bit in FILE_ATTRIBUTE_NAMES:
        known_mask |= bit
    unknown_bits = raw_flags & ~known_mask & 0x7FFFFFFF
    if unknown_bits:
        names.append(f"FILE_ATTRIBUTE_0x{unknown_bits:X}")
    if not names:
        # The kernel returns 0 when ``GetFileAttributesExW`` cannot
        # classify the path -- rather than printing "(none)" we still
        # show the raw hex so a forensic user can spot it.
        names.append(f"FILE_ATTRIBUTE_0x{raw_flags:X}")

    size = (int(fad.nFileSizeHigh) << 32) | int(fad.nFileSizeLow)

    return {
        "flags":        raw_flags,
        "flags_list":   names,
        "is_directory": bool(raw_flags & 0x00000010),  # FILE_ATTRIBUTE_DIRECTORY
        "size":         size,
        "created":      _format_filetime(fad.ftCreationTime),
        "accessed":     _format_filetime(fad.ftLastAccessTime),
        "modified":     _format_filetime(fad.ftLastWriteTime),
    }


# ---------------------------------------------------------------------------
# High-level entry points.
# ---------------------------------------------------------------------------


def get_file_info(path: str) -> dict[str, Any]:
    """Read ``path`` and return its ``WIN32_FILE_ATTRIBUTE_DATA`` as a dict.

    Wraps ``GetFileAttributesExW`` and the dict converter. The single
    entry point the CLI's ``file info`` subcommand calls.
    """
    fad = _fetch_file_attributes(path)
    info = file_info_to_dict(fad)
    info["path"] = path
    return info


def get_file_owner(path: str) -> dict[str, Any]:
    """Resolve ``path`` to ``{sid, account, domain, use, use_code}``.

    Uses ``GetNamedSecurityInfoW`` for the owner SID and
    ``LookupAccountSidW`` for the SID-to-name conversion. ``None`` /
    ``"(no owner)"`` are returned for files whose owner SID is NULL
    (``SeNullSid``); the CLI prints "(no owner)" verbatim.
    """
    sd_ptr, owner_sid, _dacl, _sacl = _fetch_security_descriptor(
        path, _OWNER_SECURITY_INFORMATION | _GROUP_SECURITY_INFORMATION,
    )
    try:
        info = _lookup_account(owner_sid)
        info["path"] = path
        return info
    finally:
        _localfree(sd_ptr)


def get_file_dacl(path: str) -> dict[str, Any]:
    """Return the SDDL ``"D:"`` component of ``path``'s security descriptor.

    We request only ``OWNER_SECURITY_INFORMATION`` + ``GROUP_SECURITY_
    INFORMATION`` + ``DACL_SECURITY_INFORMATION`` -- never SACL or
    LABEL. Reading the SACL requires ``SeSecurityPrivilege``, which is
    granted only to administrators and would otherwise fail every
    non-admin CLI invocation. The kernel still emits a well-formed SD
    with just the owner + group + DACL bits, and
    ``ConvertSecurityDescriptorToStringSecurityDescriptorW`` happily
    renders the DACL fragment from it.

    The ``--full`` SDDL dump (see :mod:`myark.modules.file.cli`) is a
    separate code path that requests the full set; callers who want
    the SACL must accept that it requires admin privileges.

    The full SDDL string contains owner + group + DACL sections; the
    S5.3 spec scopes ``file dacl`` to the DACL fragment alone, so we
    render the full string and slice off everything before the
    ``"D:"`` marker (and after the ``"S:"`` marker when present --
    SACL comes after DACL in SDDL text).
    """
    info_bits = (
        _OWNER_SECURITY_INFORMATION
        | _GROUP_SECURITY_INFORMATION
        | _DACL_SECURITY_INFORMATION
    )
    sd_ptr, _owner, _dacl, _sacl = _fetch_security_descriptor(path, info_bits)
    try:
        sddl = _sd_to_sddl(sd_ptr, info_bits)
        info = {
            "path": path,
            "sddl": sddl,
            "dacl": _slice_sddl_section(sddl, "D:"),
        }
        return info
    finally:
        _localfree(sd_ptr)


def get_file_integrity(path: str) -> dict[str, Any]:
    """Return the integrity level of ``path``.

    The mandatory-label ACE lives in the SACL, so we walk it by hand
    rather than round-tripping through SDDL text. The returned dict
    carries both the raw RID (so the CLI can render hex) and the
    friendly name (``"MEDIUM"`` / ``"HIGH"`` / ...) from
    :data:`INTEGRITY_LEVEL_NAMES`.

    Reading the SACL requires ``SeSecurityPrivilege``, which is granted
    only to administrators (and to services running under a high-
    integrity token). On hosts where the privilege is missing, the
    API returns ``ERROR_PRIVILEGE_NOT_HELD`` -- we surface that to the
    caller as a dict with ``rid=None``, ``name="(requires admin)"``
    rather than raising, so the CLI can render an explicit "unavailable"
    line instead of a stack trace.
    """
    info_bits = _LABEL_SECURITY_INFORMATION | _SACL_SECURITY_INFORMATION
    try:
        sd_ptr, _owner, _dacl, sacl_ptr = _fetch_security_descriptor(
            path, info_bits,
        )
    except OSError as exc:
        if "privilege" in str(exc).lower() or "1314" in str(exc):
            return {
                "path":    path,
                "rid":     None,
                "name":    "(requires admin)",
                "raw_rid": None,
            }
        raise

    try:
        rid = _find_mandatory_label_rid(sacl_ptr)
        if rid is None:
            return {
                "path":      path,
                "rid":       None,
                "name":      "(none)",
                "raw_rid":   None,
            }
        return {
            "path":    path,
            "rid":     int(rid),
            "name":    INTEGRITY_LEVEL_NAMES.get(int(rid), f"INTEGRITY_0x{int(rid):X}"),
            "raw_rid": int(rid),
        }
    finally:
        _localfree(sd_ptr)


# ---------------------------------------------------------------------------
# SDDL section helpers.
# ---------------------------------------------------------------------------


_SDDL_SECTION_MARKERS: tuple[str, ...] = ("O:", "G:", "D:", "S:", "L:")


def _slice_sddl_section(sddl: str, marker: str) -> str:
    """Extract the ``marker``-prefixed section from a full SDDL string.

    SDDL sections appear in ``O:G:D:S:L:`` order; each section runs
    until the next marker. We strip the leading ``O:`` / ``D:`` etc.
    from the returned fragment so a CLI can print ``"(A;OIIOFA;NW;;;WD)"``
    rather than the redundant ``"D:(A;...)"`` form.

    Returns an empty string when ``marker`` does not appear in
    ``sddl`` -- e.g. a file with no DACL entry renders as ``""``.
    """
    if not sddl:
        return ""
    # Walk the canonical section order, locating the slice for
    # ``marker`` between its start and the next marker. We scan by
    # index rather than regex to keep the module dependency-light
    # (no ``re`` import for one hot-path).
    order = _SDDL_SECTION_MARKERS
    start = sddl.find(marker)
    if start < 0:
        return ""
    after = start + len(marker)
    end = len(sddl)
    for m in order:
        i = sddl.find(m, after)
        if 0 <= i < end:
            end = i
    return sddl[after:end].strip()


# ---------------------------------------------------------------------------
# Display formatting for CLI handlers.
# ---------------------------------------------------------------------------


def format_security_info_flags(info: int) -> list[str]:
    """Render a SECURITY_INFORMATION bitmask as a list of human names."""
    names: list[str] = []
    for bit, label in sorted(SECURITY_INFORMATION_NAMES.items()):
        if info & bit:
            names.append(label)
    if not names:
        names.append(f"0x{info:X}")
    return names


# ---------------------------------------------------------------------------
# Directory listing (non-recursive).
#
# The S5.3 spec scopes the file module to read-only inspection; the
# ``ls`` subcommand falls under that umbrella. The implementation
# uses the same Win32 path the shell uses (``FindFirstFileW`` /
# ``FindNextFileW`` / ``FindClose``) so the listing reflects exactly
# what ``cmd.exe`` / Explorer would show -- no need to re-implement
# directory traversal in user space.
#
# The function is intentionally non-recursive: callers that want a
# recursive walk should reach for ``os.walk`` rather than asking the
# file module to re-implement it on top of the Win32 find handle.
# ---------------------------------------------------------------------------


# Maximum path a single ``WIN32_FIND_DATAW::cFileName`` entry can hold.
# ``MAX_PATH`` (260) covers the unicode form; the kernel only fills
# ``cFileName`` (the bare entry name) -- the joining onto the
# directory path happens in user space where ``MAX_PATH`` is no
# longer a hard limit (Win32 will accept the joined long form).
_FIND_MAX_NAME: int = 260


class WIN32_FIND_DATAW(ctypes.Structure):
    """ctypes mirror of ``WIN32_FIND_DATAW``.

    Layout matches ``WinBase.h`` exactly:

    * ``dwFileAttributes``     -- DWORD file attribute flags.
    * ``ftCreationTime`` / ``ftLastAccessTime`` / ``ftLastWriteTime``
      -- 64-bit FILETIME values (same shape as :class:`FILETIME`).
    * ``nFileSizeHigh`` / ``nFileSizeLow`` -- 64-bit file size split
      into two halves (matches :class:`WIN32_FILE_ATTRIBUTE_DATA`).
    * ``cFileName``            -- null-terminated WCHAR buffer holding
      the bare file name (``MAX_PATH`` = 260 WCHARs).
    * ``cAlternateFileName``   -- short 8.3 name (rarely populated
      on modern NTFS); we do not consume it.

    The fixed-size ``cFileName`` buffer is 520 bytes (= 260 WCHARs).
    """

    _fields_ = [
        ("dwFileAttributes",    ctypes.c_uint32),
        ("ftCreationTime",      FILETIME),
        ("ftLastAccessTime",    FILETIME),
        ("ftLastWriteTime",     FILETIME),
        ("nFileSizeHigh",       ctypes.c_uint32),
        ("nFileSizeLow",        ctypes.c_uint32),
        ("dwReserved0",         ctypes.c_uint32),
        ("dwReserved1",         ctypes.c_uint32),
        ("cFileName",           ctypes.c_wchar * _FIND_MAX_NAME),
        ("cAlternateFileName",  ctypes.c_wchar * 14),
    ]


# HANDLE FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
_FindFirstFileW = _kernel32.FindFirstFileW
_FindFirstFileW.restype = ctypes.c_void_p
_FindFirstFileW.argtypes = [
    ctypes.c_wchar_p,                       # LPCWSTR
    ctypes.POINTER(WIN32_FIND_DATAW),       # LPWIN32_FIND_DATAW
]

# BOOL FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
_FindNextFileW = _kernel32.FindNextFileW
_FindNextFileW.restype = ctypes.c_int
_FindNextFileW.argtypes = [
    ctypes.c_void_p,                       # HANDLE
    ctypes.POINTER(WIN32_FIND_DATAW),       # LPWIN32_FIND_DATAW
]

# BOOL FindClose(HANDLE hFindFile);
_FindClose = _kernel32.FindClose
_FindClose.restype = ctypes.c_int
_FindClose.argtypes = [ctypes.c_void_p]


# INVALID_HANDLE_VALUE sentinel returned by ``FindFirstFileW`` on
# failure. ``ctypes`` compares void pointers by address; the kernel
# uses ``(HANDLE)-1`` (= ``0xFFFFFFFFFFFFFFFF`` on 64-bit) as the
# canonical "no handle" value. We resolve the handle via ``int()``
# so a 32-bit Python build on a 64-bit kernel still gets a
# consistent comparison.
_INVALID_HANDLE_VALUE: int = -1  # == 0xFFFFFFFFFFFFFFFF as unsigned.


def _normalize_dir_search_path(directory: str) -> str:
    r"""Build the ``FindFirstFileW`` search pattern for a directory.

    Win32 accepts paths with forward or backward slashes. To get a
    non-recursive listing of the directory alone, we append the
    wildcard ``\*`` (which is what Explorer does under the hood).
    Trailing separators are tolerated and stripped first so the
    pattern never ends up with ``\\*\*``.

    Long paths (``\\?\C:\...``) flow through unchanged -- the
    ``\\?\`` prefix is honoured by both ``FindFirstFileW`` and
    ``FindNextFileW``.
    """
    if not directory:
        return directory
    # Strip any trailing path separators so we never build ``\\*\*``
    # even if the caller passed ``C:\Windows\``.
    base = directory.rstrip("\\/")
    if not base:
        # The caller passed ``"\"`` / ``"/"`` / ``""`` -- treat as
        # the drive root so they still get a listing rather than
        # an error.
        base = directory
    return base + "\\*"


def _directory_entry_to_dict(
    directory: str,
    fd: WIN32_FIND_DATAW,
) -> dict[str, Any]:
    """Render one ``WIN32_FIND_DATAW`` row as a JSON-friendly dict.

    Field semantics:

    * ``name``       -- bare file name (no directory prefix); matches
      ``fd.cFileName``.
    * ``path``       -- ``directory`` + ``"\\"`` + ``name``. Joins
      the same way the kernel would after a relative path lookup.
    * ``size``       -- combined 64-bit file size.
    * ``is_directory`` -- derived from ``FILE_ATTRIBUTE_DIRECTORY``.
    * ``flags`` / ``flags_list`` -- attribute bitmask + textual names
      (same shape as :func:`file_info_to_dict`).
    * ``created`` / ``accessed`` / ``modified`` -- ISO 8601 timestamps
      in UTC, or ``"(unset)"``.
    """
    name = fd.cFileName
    base = directory.rstrip("\\/")
    path = f"{base}\\{name}"
    raw_flags = int(fd.dwFileAttributes)
    names: list[str] = []
    for bit, label in sorted(FILE_ATTRIBUTE_NAMES.items()):
        if raw_flags & bit:
            names.append(f"FILE_ATTRIBUTE_{label}")
    known_mask = 0
    for bit in FILE_ATTRIBUTE_NAMES:
        known_mask |= bit
    unknown_bits = raw_flags & ~known_mask & 0x7FFFFFFF
    if unknown_bits:
        names.append(f"FILE_ATTRIBUTE_0x{unknown_bits:X}")
    if not names:
        names.append(f"FILE_ATTRIBUTE_0x{raw_flags:X}")

    size = (int(fd.nFileSizeHigh) << 32) | int(fd.nFileSizeLow)

    return {
        "name":          name,
        "path":          path,
        "size":          size,
        "is_directory":  bool(raw_flags & 0x00000010),  # FILE_ATTRIBUTE_DIRECTORY
        "flags":         raw_flags,
        "flags_list":    names,
        "created":       _format_filetime(fd.ftCreationTime),
        "accessed":      _format_filetime(fd.ftLastAccessTime),
        "modified":      _format_filetime(fd.ftLastWriteTime),
    }


def list_directory(directory: str) -> list[dict[str, Any]]:
    """Enumerate one level of ``directory`` and return rows.

    Returns a list of dicts (one per entry), each shaped like
    :func:`file_info_to_dict` plus the bare file ``name``. The
    directory marker entries ``"."`` and ``".."`` are skipped --
    the kernel emits them as the first two rows of every listing
    and they carry no useful information for an inspection tool.

    The function never recurses -- callers wanting a tree should
    walk the result themselves (e.g. ``os.walk``).

    Raises ``OSError`` if ``FindFirstFileW`` returns
    ``INVALID_HANDLE_VALUE``; the caller (CLI handler) surfaces
    the error message to the user.
    """
    pattern = _normalize_long_path(_normalize_dir_search_path(directory))
    fd = WIN32_FIND_DATAW()
    handle = _FindFirstFileW(pattern, ctypes.byref(fd))
    if int(handle or 0) == _INVALID_HANDLE_VALUE:
        err = ctypes.get_last_error() or _ERROR_PATH_NOT_FOUND
        raise OSError(f"FindFirstFileW({pattern!r}) failed: Win32 error {err}")

    rows: list[dict[str, Any]] = []
    saw_any_entry: bool = False
    try:
        # The first entry is already in ``fd``; copy it out before
        # the loop so ``fd`` is free to be reused for subsequent
        # ``FindNextFileW`` calls.
        first_name = fd.cFileName
        if first_name and first_name not in (".", ".."):
            rows.append(_directory_entry_to_dict(directory, fd))
            saw_any_entry = True

        while True:
            rc = _FindNextFileW(handle, ctypes.byref(fd))
            if not rc:
                # End-of-stream -- treat as benign. The kernel
                # documents ``ERROR_NO_MORE_FILES`` (18) but some
                # restricted execution contexts and test runners
                # race the FindClose and report
                # ``ERROR_FILE_NOT_FOUND`` (2) instead. Both
                # codes mean "no more entries"; we surface a real
                # error only when no row was ever produced.
                err = ctypes.get_last_error()
                if err in (0, 2, 18):
                    break
                if saw_any_entry:
                    break
                raise OSError(f"FindNextFileW failed: Win32 error {err}")
            saw_any_entry = True
            if fd.cFileName in (".", ".."):
                continue
            rows.append(_directory_entry_to_dict(directory, fd))
    finally:
        _FindClose(handle)

    return rows


__all__ = [
    "WIN32_FILE_ATTRIBUTE_DATA",
    "FILETIME",
    "file_info_to_dict",
    "get_file_info",
    "get_file_owner",
    "get_file_dacl",
    "get_file_integrity",
    "list_directory",
    "format_security_info_flags",
    "_slice_sddl_section",
]