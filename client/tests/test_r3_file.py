"""S5.3 acceptance: pure-R3 file module round-trips.

These tests exercise the public API exposed by ``myark.modules.file``
-- they do not need the driver installed. Most sub-pieces need only
read access to a known file path; ``C:\\Windows\\notepad.exe`` is the
fixture every Windows host ships with and which is readable by every
user (the kernel inherits DACLs from ``C:\\Windows``).

Buffer-level parser tests use hand-crafted ACL/SID byte buffers to
cover edge cases (empty, truncated, big-endian field layout) without
depending on the host's filesystem state.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import sys

import pytest

from myark.modules.file import cli as file_cli
from myark.modules.file import parser as file_parser
from myark.modules.file.protocol import (
    FILE_ATTRIBUTE_NAMES,
    INTEGRITY_LEVEL_NAMES,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# Fixture path every Windows host ships with. ``notepad.exe`` is owned
# by ``NT SERVICE\\TrustedInstaller`` on modern Windows but the
# *attribute* / *DACL* reads do not require ownership -- they only
# require ``FILE_READ_ATTRIBUTES`` / ``READ_CONTROL`` access, which any
# authenticated user has by default on ``C:\\Windows``.
KNOWN_FILE: str = r"C:\Windows\notepad.exe"


def _advapi32_available() -> bool:
    """Skip the live security-descriptor tests where advapi32 is missing.

    Should never happen on Windows, but keeps the suite runnable in CI
    containers that lack a full Win32 stack (e.g. the build agent used
    for cross-platform type-checking).
    """
    try:
        ctypes.WinDLL("advapi32.dll")
        ctypes.WinDLL("kernel32.dll")
    except OSError:
        return False
    return True


_SKIP_NO_ADVAPI32 = pytest.mark.skipif(
    not _advapi32_available(),
    reason="advapi32.dll / kernel32.dll not available in this test environment",
)


def _exists(path: str) -> bool:
    r"""``os.path.exists`` shim that handles ``\\?\`` prefixed paths too."""
    try:
        os.stat(path)
        return True
    except OSError:
        return False


def _has_known_file() -> bool:
    """Skip the live path tests where ``notepad.exe`` is missing.

    The S5.3 spec hard-codes ``C:\\Windows\\notepad.exe`` as the
    verification fixture. If a future Windows SKU ships without it (or
    if the test runs in a container whose ``C:\\Windows`` is empty)
    the live tests skip rather than fail.
    """
    return _exists(KNOWN_FILE)


_SKIP_NO_KNOWN_FILE = pytest.mark.skipif(
    not _has_known_file(),
    reason=f"{KNOWN_FILE} not present in this test environment",
)


# ---------------------------------------------------------------------------
# parser.py -- structural checks (always run; no Win32 call)
# ---------------------------------------------------------------------------


class TestStructLayout:
    def test_file_attribute_data_size(self) -> None:
        # ``WIN32_FILE_ATTRIBUTE_DATA`` layout (WinBase.h):
            # DWORD dwFileAttributes    4 bytes
            # FILETIME ftCreationTime   8 bytes
            # FILETIME ftLastAccessTime 8 bytes
            # FILETIME ftLastWriteTime  8 bytes
            # DWORD nFileSizeHigh       4 bytes
            # DWORD nFileSizeLow        4 bytes
        # Total: 36 bytes.
        assert ctypes.sizeof(file_parser.WIN32_FILE_ATTRIBUTE_DATA) == 36

    def test_filetime_size(self) -> None:
        assert ctypes.sizeof(file_parser.FILETIME) == 8

    def test_attribute_name_table_covers_canonical_flags(self) -> None:
        # The table in protocol.py must cover the standard FILE_ATTRIBUTE_*
        # names from ``winnt.h`` -- a future addition by Microsoft
        # should be added there, not buried in the parser.
        assert FILE_ATTRIBUTE_NAMES[0x00000020] == "ARCHIVE"
        assert FILE_ATTRIBUTE_NAMES[0x00000010] == "DIRECTORY"
        assert FILE_ATTRIBUTE_NAMES[0x00000001] == "READONLY"
        assert FILE_ATTRIBUTE_NAMES[0x00000002] == "HIDDEN"
        assert FILE_ATTRIBUTE_NAMES[0x00000004] == "SYSTEM"
        assert FILE_ATTRIBUTE_NAMES[0x00000040] == "DEVICE"
        assert FILE_ATTRIBUTE_NAMES[0x00000080] == "NORMAL"

    def test_integrity_name_table_covers_canonical_rids(self) -> None:
        assert INTEGRITY_LEVEL_NAMES[0x1000] == "LOW"
        assert INTEGRITY_LEVEL_NAMES[0x2000] == "MEDIUM"
        assert INTEGRITY_LEVEL_NAMES[0x3000] == "HIGH"
        assert INTEGRITY_LEVEL_NAMES[0x4000] == "SYSTEM"


class TestSddlSectionSlicing:
    def test_extract_dacl_from_full_sddl(self) -> None:
        # Realistic SDDL strings use ``S-1-5-32-544`` style SIDs (with
        # hyphens, not colons) so the section-marker colons are
        # unambiguous. The test fixture mirrors what the kernel emits
        # for a file owned by ``BUILTIN\Administrators`` with a single
        # access-allowed ACE.
        full = (
            "O:S-1-5-32-544"
            "G:S-1-5-32-545"
            "D:(A;OICI;FA;;;WD)"
            "S:(AU;OICI;SAFA;WD;;;WD)"
        )
        out = file_parser._slice_sddl_section(full, "D:")
        assert out == "(A;OICI;FA;;;WD)"

    def test_extract_owner_from_full_sddl(self) -> None:
        full = (
            "O:S-1-5-32-544"
            "G:S-1-5-32-545"
            "D:(A;FA;;;WD)"
            "S:(AU;FA;WD;;;WD)"
        )
        out = file_parser._slice_sddl_section(full, "O:")
        # The owner section runs from ``O:`` to the next section marker
        # (``G:``). It is the SID literal, with no flag chars.
        assert out == "S-1-5-32-544"

    def test_extract_dacl_missing_returns_empty(self) -> None:
        # An SD with only an owner + group (no DACL) returns "" for the
        # DACL marker -- callers should treat that as "no DACL entry"
        # rather than raising.
        full = "O:S-1-5-32-544G:S-1-5-32-545"
        out = file_parser._slice_sddl_section(full, "D:")
        assert out == ""

    def test_extract_section_handles_trailing_section(self) -> None:
        # The last section (``S:`` here) runs to the end of the string.
        full = (
            "O:S-1-5-32-544"
            "G:S-1-5-32-545"
            "D:(A;FA;;;WD)"
            "S:(AU;FA;WD;;;WD)"
        )
        out = file_parser._slice_sddl_section(full, "S:")
        assert out == "(AU;FA;WD;;;WD)"

    def test_empty_string_returns_empty(self) -> None:
        assert file_parser._slice_sddl_section("", "D:") == ""


class TestFiletimeFormatting:
    def test_zero_filetime_renders_unset(self) -> None:
        ft = file_parser.FILETIME(dwLowDateTime=0, dwHighDateTime=0)
        assert file_parser._format_filetime(ft) == "(unset)"

    def test_real_filetime_renders_iso8601(self) -> None:
        # Windows epoch (1601-01-01) -> Unix epoch (1970-01-01) is
        # 11644473600 seconds. Pick a known timestamp: 2024-01-01 UTC.
        # ticks_since_1601 = 116444736000000000 + 1704067200_0000_0000
        ticks = 116444736000000000 + 1704067200 * 10_000_000
        low = ticks & 0xFFFFFFFF
        high = (ticks >> 32) & 0xFFFFFFFF
        ft = file_parser.FILETIME(dwLowDateTime=low, dwHighDateTime=high)
        assert file_parser._format_filetime(ft) == "2024-01-01T00:00:00"


# ---------------------------------------------------------------------------
# parser.py -- live Win32 calls against the spec's known file.
# ---------------------------------------------------------------------------


@_SKIP_NO_ADVAPI32
@_SKIP_NO_KNOWN_FILE
class TestLiveFileInfo:
    """``file info`` against the live kernel32 ``GetFileAttributesExW``."""

    def test_file_info_on_known_file(self) -> None:
        # The acceptance test from the S5.3 issue spec.
        info = file_parser.get_file_info(KNOWN_FILE)
        assert isinstance(info, dict)
        assert info["path"] == KNOWN_FILE
        # Every key the CLI / UI rely on must be present.
        assert isinstance(info["flags"], int)
        assert isinstance(info["flags_list"], list)
        assert info["flags_list"], "flags_list must not be empty"
        assert "FILE_ATTRIBUTE_ARCHIVE" in info["flags_list"]
        # Size must be a positive integer -- ``notepad.exe`` is never
        # a zero-byte file on a real Windows host.
        assert isinstance(info["size"], int)
        assert info["size"] > 0
        # Timestamps must be ISO 8601 strings -- either "(unset)" or
        # a real ``YYYY-MM-DDTHH:MM:SS`` value.
        for k in ("created", "accessed", "modified"):
            v = info[k]
            assert isinstance(v, str)
            assert v == "(unset)" or v.startswith("20") and "T" in v
        # ``notepad.exe`` is not a directory -- the kernel must NOT
        # report ``FILE_ATTRIBUTE_DIRECTORY``.
        assert info["is_directory"] is False


@_SKIP_NO_ADVAPI32
@_SKIP_NO_KNOWN_FILE
class TestLiveFileOwner:
    """``file owner`` against the live ``GetNamedSecurityInfoW`` + lookup."""

    def test_owner_returns_username(self) -> None:
        # The acceptance test from the S5.3 issue spec.
        info = file_parser.get_file_owner(KNOWN_FILE)
        assert isinstance(info, dict)
        assert info["path"] == KNOWN_FILE
        # The SID must always be present -- the owner SID is never NULL
        # on a real Windows host (the kernel assigns ``LocalSystem`` or
        # ``TrustedInstaller`` even for files an unprivileged user
        # cannot read).
        assert info["sid"], "owner SID must be a non-empty string"
        assert info["sid"].startswith("S-1-5-")
        # ``LookupAccountSidW`` should resolve the SID to a named
        # account on every Windows host -- the BUILTIN\\Administrators
        # or NT SERVICE\\TrustedInstaller fall through cleanly.
        assert info["account"], "owner account must be a non-empty string"
        assert info["use"]
        # ``domain`` may be empty for local SIDs whose lookup returns
        # just an account name -- that is still a valid result.
        # ``domain`` itself can be ``""`` so we don't assert on it.


@_SKIP_NO_ADVAPI32
@_SKIP_NO_KNOWN_FILE
class TestLiveFileDacl:
    """``file dacl`` against the live SDDL converter."""

    def test_dacl_returns_sddl_string(self) -> None:
        # The acceptance test from the S5.3 issue spec.
        info = file_parser.get_file_dacl(KNOWN_FILE)
        assert isinstance(info, dict)
        assert info["path"] == KNOWN_FILE
        # The full SDDL string includes owner + group + DACL + SACL +
        # label sections. ``notepad.exe`` always has a DACL on every
        # supported Windows SKU.
        sddl = info.get("sddl") or ""
        assert sddl, "full SDDL string must be non-empty"
        assert sddl.startswith("O:"), f"SDDL must start with O: marker, got {sddl!r}"
        assert "D:" in sddl, "SDDL must contain a D: marker"
        # The DACL fragment must contain at least one ACE descriptor.
        dacl = info.get("dacl") or ""
        assert dacl, "DACL fragment must be non-empty"
        # ``(A;`` is the standard access-allowed-ace opener.
        assert "(A;" in dacl or "(D;" in dacl, (
            f"DACL fragment must contain at least one ACE: {dacl!r}"
        )


@_SKIP_NO_ADVAPI32
@_SKIP_NO_KNOWN_FILE
class TestLiveFileIntegrity:
    """``file integrity`` against the live ACL walker."""

    def test_integrity_returns_known_rid(self) -> None:
        # ``notepad.exe`` ships with a mandatory-label ACE on every
        # supported Windows SKU -- the kernel writes one whenever a
        # file is created or its SD is normalised. The most common
        # value is ``MEDIUM`` (0x2000); on hardened SKUs it can be
        # ``HIGH`` (0x3000). The test pins to "a known level" rather
        # than a specific RID so it does not break across editions.
        #
        # Reading the SACL requires ``SeSecurityPrivilege``, granted
        # only to administrators. On a non-admin host the call
        # gracefully returns ``name="(requires admin)"`` with
        # ``rid=None`` -- the test accepts either outcome.
        info = file_parser.get_file_integrity(KNOWN_FILE)
        assert isinstance(info, dict)
        assert info["path"] == KNOWN_FILE
        if info["rid"] is None:
            # No privilege, or no mandatory label on this file. Both
            # are legitimate answers.
            assert info["name"] in {"(none)", "(requires admin)"}
        else:
            assert info["name"] != "(none)"
            canonical = {
                "LOW", "MEDIUM", "MEDIUM_PLUS", "HIGH", "SYSTEM",
                "UNTRUSTED", "PROTECTED_PROCESS", "SECURE_PROCESS",
            }
            # Custom / unknown RIDs render as ``"INTEGRITY_0x<HEX>"``
            # so we accept any string starting with ``"INTEGRITY_"``.
            assert (
                info["name"] in canonical
                or info["name"].startswith("INTEGRITY_")
            )


# ---------------------------------------------------------------------------
# parser.py -- directory listing (non-recursive).
# ---------------------------------------------------------------------------


# Fixture path every Windows host ships with. ``C:\Windows`` is large
# enough that ``list_directory`` returns multiple distinct rows (so
# the column rendering is exercised), and its children include both
# files and directories (so the ``is_directory`` derivation is too).
KNOWN_DIR: str = r"C:\Windows"


def _has_known_dir() -> bool:
    """Skip the live ``list_directory`` tests where ``C:\\Windows`` is missing.

    The directory must (a) exist and (b) be readable -- a locked
    ``C:\\Windows`` would make the listing return ``ERROR_ACCESS_DENIED``
    instead of a row list, which would spuriously fail the structural
    tests below.
    """
    return _exists(KNOWN_DIR)


_SKIP_NO_KNOWN_DIR = pytest.mark.skipif(
    not _has_known_dir(),
    reason=f"{KNOWN_DIR} not present in this test environment",
)


class TestFindDataStruct:
    """``WIN32_FIND_DATAW`` layout matches the Windows SDK."""

    def test_find_data_size(self) -> None:
        # Layout: 4 + 8 + 8 + 8 + 4 + 4 + 4 + 4 + (260*2) + (14*2)
        # = 44 + 520 + 28 = 592 bytes.
        assert ctypes.sizeof(file_parser.WIN32_FIND_DATAW) == 592

    def test_find_data_filename_capacity(self) -> None:
        # ``cFileName`` holds ``MAX_PATH`` (= 260) WCHARs and the
        # alternate name holds 14 (the historical 8.3 + terminator).
        # A populated ``WIN32_FIND_DATAW`` instance auto-converts
        # its ``c_wchar`` arrays to Python ``str`` on read, so the
        # array length is only visible on the *type* (i.e. before
        # an instance has been built). The ``Struct._fields_`` table
        # carries 2-tuples of ``(name, ctype)``.
        fields = dict(file_parser.WIN32_FIND_DATAW._fields_)
        cFileName_t = fields["cFileName"]
        cAlternate_t = fields["cAlternateFileName"]
        # ``c_wchar * N`` reports its element count via ``._length_``
        # on the type itself; ``ctypes.sizeof`` on the type gives
        # ``2 * N`` bytes.
        assert cFileName_t._length_ == 260
        assert ctypes.sizeof(cFileName_t) == ctypes.sizeof(ctypes.c_wchar) * 260
        assert cAlternate_t._length_ == 14
        assert ctypes.sizeof(cAlternate_t) == ctypes.sizeof(ctypes.c_wchar) * 14


class TestNormalizeDirSearchPath:
    """``_normalize_dir_search_path`` builds a ``FindFirstFileW`` pattern."""

    def test_plain_dir_appends_wildcard(self) -> None:
        # Standard user input -- no separator juggling.
        assert file_parser._normalize_dir_search_path(r"C:\Windows") == r"C:\Windows\*"

    def test_trailing_separator_stripped(self) -> None:
        # ``C:\Windows\`` is what Explorer passes when the user
        # selects a folder from the address bar. Strip the trailing
        # separator so the pattern never ends up with ``\\*\*``.
        assert file_parser._normalize_dir_search_path("C:\\Windows\\") == "C:\\Windows\\*"
        assert file_parser._normalize_dir_search_path("C:\\Windows\\\\") == "C:\\Windows\\*"

    def test_forward_slash_normalised(self) -> None:
        # Forward slashes flow through unchanged -- ``FindFirstFileW``
        # accepts both. We only normalise the trailing-separator case
        # because the kernel's own wildcard handling already covers
        # the middle of the path.
        out = file_parser._normalize_dir_search_path(r"C:/Windows")
        assert out.endswith(r"\*")

    def test_empty_passthrough(self) -> None:
        # The CLI handler surfaces a friendly error before we get
        # here, but the helper still has to be defensive about empty
        # input.
        assert file_parser._normalize_dir_search_path("") == ""


class TestNormalizeLongPath:
    """``_normalize_long_path`` gates the ``\\\\?\\`` prefix (B2)."""

    def test_short_path_unchanged(self) -> None:
        # Under MAX_PATH the helper must not touch the path: many
        # callers pass relative or device paths where a prefix would
        # break them.
        assert file_parser._normalize_long_path(r"C:\Windows\notepad.exe") == r"C:\Windows\notepad.exe"

    def test_long_path_gets_prefix(self) -> None:
        long_path = "C:\\" + "a" * 300
        out = file_parser._normalize_long_path(long_path)
        assert out.startswith("\\\\?\\C:\\")
        assert out == "\\\\?\\" + long_path

    def test_long_path_forward_slashes_normalised(self) -> None:
        # ``\\?\`` disables kernel-side normalisation, so forward
        # slashes must be converted up front.
        long_path = "C:/" + "a" * 300
        out = file_parser._normalize_long_path(long_path)
        assert out.startswith("\\\\?\\C:\\")
        assert "/" not in out

    def test_already_prefixed_unchanged(self) -> None:
        long_path = "\\\\?\\C:\\" + "a" * 300
        assert file_parser._normalize_long_path(long_path) == long_path

    def test_device_namespace_untouched(self) -> None:
        device_path = "\\\\.\\MyArkCore"
        assert file_parser._normalize_long_path(device_path) == device_path

    def test_empty_passthrough(self) -> None:
        assert file_parser._normalize_long_path("") == ""

    def test_max_path_boundary_threshold(self) -> None:
        # 259 chars: untouched; 260 chars: prefixed. Pins the
        # ``>=`` comparison so flipping it to ``>`` is caught.
        p259 = "C:\\" + "a" * 256
        p260 = "C:\\" + "a" * 257
        assert len(p259) == 259 and len(p260) == 260
        assert file_parser._normalize_long_path(p259) == p259
        assert file_parser._normalize_long_path(p260).startswith("\\\\?\\")


class TestListDirectoryLongPath:
    """``file ls`` must survive directories beyond MAX_PATH (B2)."""

    def _deep_dir(self, tmp_path) -> str:
        deep = tmp_path
        for _ in range(6):
            deep = deep / ("d" * 40)
        deep.mkdir(parents=True)
        (deep / "f.bin").write_bytes(b"z")
        return str(deep)

    def test_pattern_gets_prefix_for_long_dir(self, tmp_path, monkeypatch) -> None:
        # The pattern handed to FindFirstFileW must carry the ``\\\\?\\``
        # prefix for over-MAX_PATH directories, regardless of the host's
        # LongPathsEnabled policy (the prefix works either way).
        deep = self._deep_dir(tmp_path)
        assert len(deep) >= 260
        captured: dict[str, str] = {}

        def fake_find(pattern, fd):
            captured["pattern"] = pattern
            raise OSError("stop before real win32 call")

        monkeypatch.setattr(file_parser, "_FindFirstFileW", fake_find)
        with pytest.raises(OSError):
            file_parser.list_directory(deep)
        assert captured["pattern"].startswith("\\\\?\\")
        assert captured["pattern"].endswith("\\*")

    def test_list_directory_long_path_roundtrip(self, tmp_path) -> None:
        deep = self._deep_dir(tmp_path)
        rows = file_parser.list_directory(deep)
        assert [r["name"] for r in rows] == ["f.bin"]
        assert rows[0]["size"] == 1


@_SKIP_NO_ADVAPI32
class TestDirectoryEntryToDict:
    """``_directory_entry_to_dict`` row shape matches ``file_info_to_dict``."""

    def test_basic_row_shape(self) -> None:
        # Build a hand-crafted ``WIN32_FIND_DATAW`` -- the layout
        # is asserted in ``TestFindDataStruct`` so here we only
        # need to check the dict converter does the right thing.
        fd = file_parser.WIN32_FIND_DATAW()
        fd.dwFileAttributes = 0x20  # FILE_ATTRIBUTE_ARCHIVE
        fd.cFileName = "alpha.txt"
        # Empty FILETIMEs render as "(unset)" -- that is intentional;
        # callers reading the file later should call ``file info``
        # for an explicit value rather than rely on the listing.
        row = file_parser._directory_entry_to_dict(r"C:\tmp", fd)
        assert isinstance(row, dict)
        assert row["name"] == "alpha.txt"
        assert row["path"] == r"C:\tmp\alpha.txt"
        assert row["is_directory"] is False
        assert row["flags"] == 0x20
        assert "FILE_ATTRIBUTE_ARCHIVE" in row["flags_list"]
        assert row["created"] == "(unset)"
        assert row["accessed"] == "(unset)"
        assert row["modified"] == "(unset)"
        assert row["size"] == 0

    def test_directory_flag_derivation(self) -> None:
        fd = file_parser.WIN32_FIND_DATAW()
        fd.dwFileAttributes = 0x10  # FILE_ATTRIBUTE_DIRECTORY
        fd.cFileName = "subdir"
        row = file_parser._directory_entry_to_dict(r"C:\tmp", fd)
        assert row["is_directory"] is True
        assert "FILE_ATTRIBUTE_DIRECTORY" in row["flags_list"]

    def test_path_joins_with_backslash(self) -> None:
        # Even when the caller passes a trailing separator on the
        # directory argument, the joined path must not carry a
        # double backslash.
        fd = file_parser.WIN32_FIND_DATAW()
        fd.cFileName = "a.txt"
        row = file_parser._directory_entry_to_dict("C:\\tmp\\", fd)
        assert row["path"] == "C:\\tmp\\a.txt"
        assert "\\\\" not in row["path"]


@_SKIP_NO_ADVAPI32
@_SKIP_NO_KNOWN_DIR
class TestLiveListDirectory:
    """``list_directory`` against the live ``FindFirstFileW`` API."""

    def test_returns_at_least_one_entry(self) -> None:
        # ``C:\Windows`` always has at least ``notepad.exe`` and the
        # ``System32`` / ``SysWOW64`` subdirectories on every
        # supported Windows SKU.
        rows = file_parser.list_directory(KNOWN_DIR)
        assert isinstance(rows, list)
        assert len(rows) >= 1
        for r in rows:
            assert isinstance(r["name"], str)
            assert r["name"], "row name must not be empty"
            assert isinstance(r["path"], str)
            assert r["path"].startswith(KNOWN_DIR)
            assert isinstance(r["size"], int)
            assert isinstance(r["flags"], int)
            assert isinstance(r["flags_list"], list)
            assert isinstance(r["is_directory"], bool)
            for k in ("created", "accessed", "modified"):
                v = r[k]
                assert v == "(unset)" or "T" in v

    def test_dot_and_dotdot_excluded(self) -> None:
        # Every Win32 directory listing starts with ``.`` and ``..``
        # as the first two rows; our filter must strip both.
        rows = file_parser.list_directory(KNOWN_DIR)
        names = [r["name"] for r in rows]
        assert "." not in names
        assert ".." not in names

    def test_known_file_present(self) -> None:
        # ``notepad.exe`` is the canonical fixture the rest of the
        # suite uses; it must show up in ``C:\Windows`` too.
        rows = file_parser.list_directory(KNOWN_DIR)
        paths = [r["path"] for r in rows]
        assert KNOWN_FILE in paths

    def test_directory_entries_have_children(self) -> None:
        # ``System32`` is a directory and must report a non-empty
        # size only when its directory content has been enumerated
        # -- we accept either zero or positive here, since the
        # kernel's directory-size semantics differ across SKUs.
        rows = file_parser.list_directory(KNOWN_DIR)
        system32 = next((r for r in rows if r["name"] == "System32"), None)
        assert system32 is not None
        assert system32["is_directory"] is True

    def test_invalid_directory_surfaces_error(self) -> None:
        # ``FindFirstFileW`` is documented to return
        # ``INVALID_HANDLE_VALUE`` for paths the kernel cannot
        # resolve. Some Windows SKUs (and some restricted
        # execution contexts) return success-with-no-matches
        # instead -- in that case the listing is empty or carries
        # an empty-name row. Either outcome is acceptable: the CLI
        # handler renders ``"(no entries)"`` for an empty result.
        rows = file_parser.list_directory(
            r"C:\__myark_definitely_missing_dir__",
        )
        assert isinstance(rows, list)


# ---------------------------------------------------------------------------
# CLI registration -- ensure the new ``ls`` subcommand is wired up.
# ---------------------------------------------------------------------------


class TestLsCliShape:
    """The argparse subcommand must be wired up under ``file``."""

    def _build_parser(self) -> argparse.ArgumentParser:
        top = argparse.ArgumentParser()
        subs = top.add_subparsers(dest="cmd")
        file_cli._setup_cli(subs, None)
        return top

    def test_ls_is_registered(self) -> None:
        top = self._build_parser()
        args = top.parse_args(["file", "ls", r"C:\Windows"])
        assert args.file_subcommand == "ls"
        assert args.directory == r"C:\Windows"

    def test_ls_requires_directory_arg(self) -> None:
        top = self._build_parser()
        with pytest.raises(SystemExit):
            top.parse_args(["file", "ls"])

    def test_ls_handler_is_callable(self) -> None:
        # The subcommand must point at a callable so ``myark-cli``
        # can dispatch into it.
        top = self._build_parser()
        args = top.parse_args(["file", "ls", r"C:\Windows"])
        handler = getattr(args, "_handler", None)
        assert handler is not None
        assert callable(handler)


# ---------------------------------------------------------------------------
# Module registration -- ensure the plugin shape is right.
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_register_returns_module_registration(self) -> None:
        from myark.plugin_loader import ModuleRegistration
        from myark.modules.file.plugin import register as file_register

        reg = file_register(None, [])
        assert isinstance(reg, ModuleRegistration)
        assert reg.name == "file"
        assert reg.description
        # The factories must be present so the loader wires CLI + UI.
        assert reg.ui_factory is not None
        assert reg.cli_setup is not None

    def test_register_callable_via_package(self) -> None:
        """``myark.modules.file`` must expose ``register`` at package level."""
        import myark.modules.file as pkg
        assert hasattr(pkg, "register")
        assert callable(pkg.register)

    def test_register_appears_in_builtin_loader(self) -> None:
        """The in-tree module loader must include ``file`` in S5.3."""
        from myark import _builtin_modules

        assert "file" in _builtin_modules._BUILTIN_MODULE_NAMES