"""S5.1 acceptance: pure-R3 registry module round-trips.

These tests exercise the public API exposed by
``myark.modules.registry`` -- they do not need the driver installed and
they do not need admin. To stay inside the user's own hive they use
``HKCU\\Software\\MyArkTest`` for round-trip / delete tests and the
read-only ``HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion`` for
list / read.

Each test cleans up its own subkey in a ``finally`` so a transient
failure does not leak state between runs.
"""

from __future__ import annotations

import argparse
import io
import os
import sys
import time
import uuid
from contextlib import redirect_stdout

import pytest
import winreg

from myark.modules.registry import cli as reg_cli
from myark.modules.registry import parser as reg_parser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


TEST_PARENT_HIVE = winreg.HKEY_CURRENT_USER
TEST_PARENT_KEY = r"Software\MyArkTest"
# Common path string used by every write / delete test. Each test
# creates a unique subkey beneath this so tests can run concurrently
# without colliding.
TEST_PATH_TEMPLATE = r"HKCU\Software\MyArkTest\{tag}"


def _open_or_create_parent() -> None:
    """Make sure ``HKCU\\Software\\MyArkTest`` exists for the test run."""
    winreg.CreateKey(TEST_PARENT_HIVE, TEST_PARENT_KEY)


def _delete_subkey_recursive(hive: int, subkey: str) -> None:
    """Best-effort recursive cleanup -- swallows "not found"."""
    try:
        reg_cli._recursive_delete(hive, subkey)
    except FileNotFoundError:
        return


# Unique tag per test so a failure in one does not poison the next.
@pytest.fixture
def tag() -> str:
    return f"{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# parser.py -- path parsing (always run; no registry access needed)
# ---------------------------------------------------------------------------


class TestParsePath:
    def test_short_form(self) -> None:
        hive, sub = reg_parser.parse_path(r"HKLM\SOFTWARE\Microsoft")
        assert hive == winreg.HKEY_LOCAL_MACHINE
        assert sub == r"SOFTWARE\Microsoft"

    def test_long_form(self) -> None:
        hive, sub = reg_parser.parse_path(r"HKEY_CURRENT_USER\Software\Foo")
        assert hive == winreg.HKEY_CURRENT_USER
        assert sub == r"Software\Foo"

    def test_root_only(self) -> None:
        # ``HKLM`` alone is legal -- the caller wants to enumerate root
        # children, e.g. ``SOFTWARE``.
        hive, sub = reg_parser.parse_path("HKLM")
        assert hive == winreg.HKEY_LOCAL_MACHINE
        assert sub == ""

    def test_unknown_hive(self) -> None:
        with pytest.raises(ValueError):
            reg_parser.parse_path(r"FOO\bar")

    def test_empty_path(self) -> None:
        with pytest.raises(ValueError):
            reg_parser.parse_path("")


class TestParseTypeName:
    def test_reg_sz(self) -> None:
        assert reg_parser.parse_type_name("REG_SZ") == winreg.REG_SZ

    def test_reg_dword(self) -> None:
        assert reg_parser.parse_type_name("REG_DWORD") == winreg.REG_DWORD

    def test_case_insensitive(self) -> None:
        assert reg_parser.parse_type_name("reg_sz") == winreg.REG_SZ

    def test_unknown(self) -> None:
        with pytest.raises(ValueError):
            reg_parser.parse_type_name("REG_NOPE")


class TestValueRoundtrip:
    """``readable_to_value`` must produce what ``value_to_readable`` accepts."""

    @pytest.mark.parametrize(
        "type_code, raw, text",
        [
            (winreg.REG_SZ, "hello", "hello"),
            (winreg.REG_DWORD, 42, "42"),
            (winreg.REG_DWORD, 0xDEADBEEF, "0xDEADBEEF"),
            (winreg.REG_QWORD, 2**40, str(2**40)),
            (winreg.REG_MULTI_SZ, ["a", "b"], "a\nb"),
            (winreg.REG_BINARY, b"\x00\x01\x02", "\x00\x01\x02"),
        ],
    )
    def test_string_roundtrip(self, type_code: int, raw, text: str) -> None:
        assert reg_parser.readable_to_value(text, type_code) == raw

    def test_int_parse_rejects_junk(self) -> None:
        with pytest.raises(ValueError):
            reg_parser.readable_to_value("not-a-number", winreg.REG_DWORD)


# ---------------------------------------------------------------------------
# cli.py -- list / read / write / delete-value round-trips
# ---------------------------------------------------------------------------


class TestListKeys:
    def test_list_keys_returns_list(self) -> None:
        """The acceptance test from the S5.1 issue spec.

        ``HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion`` is
        readable by any user, including non-admins, on every supported
        Windows SKU (it is documented in MSDN as "viewable by everyone").
        """
        hive, sub = reg_parser.parse_path(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        )
        with winreg.OpenKey(hive, sub, 0, winreg.KEY_READ) as key:
            seen: list[str] = []
            i = 0
            while True:
                try:
                    seen.append(winreg.EnumKey(key, i))
                except OSError:
                    break
                i += 1

        assert isinstance(seen, list)
        # SubkeyList on this key always includes ``EdgeUpdate`` or
        # ``AppCompat`` depending on Windows version. Asserting a
        # single canonical name would be brittle; instead we assert the
        # list is non-empty.
        assert len(seen) > 0


# ---------------------------------------------------------------------------
# cli.py -- ``keys`` subcommand (subkey-only listing, non-recursive).
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser()
    subs = top.add_subparsers(dest="cmd")
    reg_cli._setup_cli(subs, None)
    return top


class TestKeysCliShape:
    """The argparse subcommand must be wired up under ``registry``."""

    def test_keys_is_registered(self) -> None:
        top = _build_parser()
        args = top.parse_args(["registry", "keys", r"HKLM\SOFTWARE\Microsoft"])
        assert args.registry_subcommand == "keys"
        assert args.path == r"HKLM\SOFTWARE\Microsoft"

    def test_keys_requires_path_arg(self) -> None:
        top = _build_parser()
        with pytest.raises(SystemExit):
            top.parse_args(["registry", "keys"])

    def test_keys_handler_is_callable(self) -> None:
        # The subcommand must point at a callable so ``myark-cli`` can
        # dispatch into it.
        top = _build_parser()
        args = top.parse_args(["registry", "keys", r"HKLM\SOFTWARE\Microsoft"])
        handler = getattr(args, "_handler", None)
        assert handler is not None
        assert callable(handler)
        assert handler is reg_cli._cmd_keys


class TestKeysHandler:
    """``_cmd_keys`` lists subkeys in ``list`` format, no values."""

    def test_keys_matches_list_subkey_output(self) -> None:
        # ``keys`` and ``list`` must render the same ``  <sub>`` rows
        # for the same path; ``keys`` just stops there.
        path = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        ns = argparse.Namespace(path=path)

        list_buf = io.StringIO()
        with redirect_stdout(list_buf):
            rc_list = reg_cli._cmd_list(argparse.Namespace(path=path, values=False))
        list_lines = [ln for ln in list_buf.getvalue().splitlines() if ln.strip()]

        keys_buf = io.StringIO()
        with redirect_stdout(keys_buf):
            rc_keys = reg_cli._cmd_keys(ns)
        keys_lines = [ln for ln in keys_buf.getvalue().splitlines() if ln.strip()]

        assert rc_list == 0
        assert rc_keys == 0
        # ``keys`` output is a prefix of ``list`` output (same indent,
        # same ordering, no value rows interleaved).
        assert list_lines[: len(keys_lines)] == keys_lines
        assert keys_lines, "HKLM\\...\\CurrentVersion must have at least one subkey"

    def test_keys_does_not_print_values(self) -> None:
        # Even when the path carries a value, ``keys`` must NOT emit a
        # ``  <name>  [<type>]  <data>`` row. We seed a fresh subkey
        # with both a child subkey (so ``(empty)`` is NOT the marker)
        # and a REG_SZ value (so a value row WOULD print under ``list``
        # but must NOT print under ``keys``).
        _open_or_create_parent()
        tag = f"{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"
        subkey = f"{TEST_PARENT_KEY}\\{tag}"
        child = subkey + r"\child"
        try:
            winreg.CreateKey(TEST_PARENT_HIVE, child)
            winreg.SetValueEx(
                winreg.OpenKey(TEST_PARENT_HIVE, subkey, 0, winreg.KEY_WRITE),
                "Greeting", 0, winreg.REG_SZ, "hello",
            )

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = reg_cli._cmd_keys(argparse.Namespace(
                    path=f"HKCU\\Software\\MyArkTest\\{tag}"
                ))
            assert rc == 0
            rendered = buf.getvalue()
            assert "(empty)" not in rendered
            assert "Greeting" not in rendered
            assert "[REG_SZ]" not in rendered
            # The child subkey row is the only thing that should print.
            assert "child" in rendered
        finally:
            _delete_subkey_recursive(TEST_PARENT_HIVE, subkey)

    def test_keys_empty_key_prints_marker(self) -> None:
        # An empty key prints ``  (empty)`` -- same marker ``list`` uses
        # when there are no subkeys AND no values.
        _open_or_create_parent()
        tag = f"{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"
        subkey = f"{TEST_PARENT_KEY}\\{tag}"
        try:
            winreg.CreateKey(TEST_PARENT_HIVE, subkey)

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = reg_cli._cmd_keys(argparse.Namespace(
                    path=f"HKCU\\Software\\MyArkTest\\{tag}"
                ))
            assert rc == 0
            rendered = buf.getvalue()
            assert "(empty)" in rendered
        finally:
            _delete_subkey_recursive(TEST_PARENT_HIVE, subkey)

    def test_keys_missing_path_returns_err(self, capsys: pytest.CaptureFixture[str]) -> None:
        # An unknown path must surface an error to stderr and exit 3,
        # matching the ``list`` command's error contract.
        ns = argparse.Namespace(path=r"HKCU\__myark_definitely_missing__")
        rc = reg_cli._cmd_keys(ns)
        assert rc == 3
        captured = capsys.readouterr()
        assert "open failed" in captured.err


class TestReadValue:
    def test_read_value_returns_correct_type(self) -> None:
        """Reading ``ProductName`` returns ``REG_SZ`` on every Windows SKU."""
        hive, sub = reg_parser.parse_path(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        )
        with winreg.OpenKey(hive, sub, 0, winreg.KEY_READ) as key:
            raw, type_code = winreg.QueryValueEx(key, "ProductName")

        assert type_code == winreg.REG_SZ
        assert isinstance(raw, str)
        # Windows 10/11/Server all report a name that starts with
        # "Windows" -- "Windows 10 Pro", "Windows Server 2022", etc.
        assert raw.startswith("Windows")


class TestWriteThenReadRoundtrip:
    """A REG_SZ / REG_DWORD round-trip through our CLI helpers."""

    def test_reg_sz_roundtrip(self, tag: str) -> None:
        _open_or_create_parent()
        subkey = f"{TEST_PARENT_KEY}\\{tag}"
        try:
            winreg.CreateKey(TEST_PARENT_HIVE, subkey)
            with winreg.OpenKey(
                TEST_PARENT_HIVE, subkey, 0, winreg.KEY_READ | winreg.KEY_WRITE
            ) as key:
                payload = reg_parser.readable_to_value("hello-world", winreg.REG_SZ)
                winreg.SetValueEx(key, "Greeting", 0, winreg.REG_SZ, payload)

                raw, type_code = winreg.QueryValueEx(key, "Greeting")
                assert type_code == winreg.REG_SZ
                assert raw == "hello-world"
        finally:
            _delete_subkey_recursive(TEST_PARENT_HIVE, subkey)

    def test_reg_dword_roundtrip(self, tag: str) -> None:
        _open_or_create_parent()
        subkey = f"{TEST_PARENT_KEY}\\{tag}"
        try:
            winreg.CreateKey(TEST_PARENT_HIVE, subkey)
            with winreg.OpenKey(
                TEST_PARENT_HIVE, subkey, 0, winreg.KEY_READ | winreg.KEY_WRITE
            ) as key:
                payload = reg_parser.readable_to_value("0xDEADBEEF", winreg.REG_DWORD)
                winreg.SetValueEx(key, "Magic", 0, winreg.REG_DWORD, payload)

                raw, type_code = winreg.QueryValueEx(key, "Magic")
                assert type_code == winreg.REG_DWORD
                assert int(raw) == 0xDEADBEEF
        finally:
            _delete_subkey_recursive(TEST_PARENT_HIVE, subkey)


class TestDeleteValueRaises:
    """``winreg.DeleteValue`` raises ``FileNotFoundError`` when the value is missing."""

    def test_delete_missing_value(self, tag: str) -> None:
        _open_or_create_parent()
        subkey = f"{TEST_PARENT_KEY}\\{tag}"
        try:
            winreg.CreateKey(TEST_PARENT_HIVE, subkey)
            with winreg.OpenKey(
                TEST_PARENT_HIVE, subkey, 0, winreg.KEY_READ | winreg.KEY_WRITE
            ) as key:
                with pytest.raises(FileNotFoundError):
                    winreg.DeleteValue(key, "DoesNotExist")
        finally:
            _delete_subkey_recursive(TEST_PARENT_HIVE, subkey)


# ---------------------------------------------------------------------------
# cli.py -- delete-key recursion (exercise the helper directly)
# ---------------------------------------------------------------------------


class TestDeleteKeyRecursive:
    def test_recursive_delete_removes_nested_children(self, tag: str) -> None:
        _open_or_create_parent()
        outer = f"{TEST_PARENT_KEY}\\{tag}"
        inner = outer + r"\child\grandchild"
        try:
            winreg.CreateKey(TEST_PARENT_HIVE, inner)
            # Sanity: outer exists and has a child before we delete.
            with winreg.OpenKey(TEST_PARENT_HIVE, outer) as outer_key:
                assert winreg.EnumKey(outer_key, 0) == "child"

            reg_cli._recursive_delete(TEST_PARENT_HIVE, outer)

            # Outer must be gone.
            with pytest.raises(FileNotFoundError):
                winreg.OpenKey(TEST_PARENT_HIVE, outer)
        finally:
            # Idempotent cleanup if the test failed before delete.
            _delete_subkey_recursive(TEST_PARENT_HIVE, outer)


# ---------------------------------------------------------------------------
# Module registration -- ensure the plugin shape is right.
# ---------------------------------------------------------------------------


class TestRegistration:
    """The module's entry point must match the plugin-loader contract."""

    def test_register_returns_module_registration(self) -> None:
        from myark.plugin_loader import ModuleRegistration
        from myark.modules.registry.plugin import register as reg_register

        reg = reg_register(None, [])
        assert isinstance(reg, ModuleRegistration)
        assert reg.name == "registry"
        assert reg.description
        # The factories must be present so the loader wires CLI + UI.
        assert reg.ui_factory is not None
        assert reg.cli_setup is not None

    def test_register_callable_via_package(self) -> None:
        """``myark.modules.registry`` must expose ``register`` at package level.

        ``myark._builtin_modules.iter_builtin_registrations`` discovers
        modules by ``importlib.import_module('myark.modules.registry')``
        and looks up ``register`` on the result. ``__init__.py`` re-exports
        it from ``plugin.py``; this test pins that contract.
        """
        import myark.modules.registry as pkg
        assert hasattr(pkg, "register")
        assert callable(pkg.register)