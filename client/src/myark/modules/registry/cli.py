"""MyArk Registry module: CLI subcommands.

Adds ``myark-cli registry {list, keys, read, write, delete-value, delete-key}``
to the parent argparse parser. Each subcommand operates directly on the
local registry via :mod:`winreg` -- no driver handle is required, so the
parent CLI's "driver not installed" fallback never fires for this
subtree. Permission errors (write to a read-only hive) surface as
``PermissionError`` / ``OSError`` and exit code ``3``.

Subcommand surface (matches the S5.1 issue spec):

* ``registry list <path>``                  -- list subkeys at ``path``
  (optionally with ``--values``).
* ``registry keys <path>``                  -- subkey-only listing in
  ``list`` format without values.
* ``registry read <path> <name>``           -- print one value.
* ``registry write <path> <name> <value>``  -- write ``--type REG_SZ``
  by default; ``--type`` accepts any name in ``REG_TYPE_FROM_NAME``.
* ``registry delete-value <path> <name>``   -- remove one value.
* ``registry delete-key <path>``            -- recursive ``DeleteKey``.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, Optional

import winreg

from myark.client.ark_client import ArkClient
from myark.modules.registry import parser as reg_parser


# Default flags applied to every ``winreg.OpenKey`` call in this module.
# ``KEY_READ`` is enough for list / read; ``KEY_WRITE`` is OR'd in by
# the write / delete subcommands explicitly so the read-only ones don't
# request write access.
_DEFAULT_OPEN_FLAGS = winreg.KEY_READ


# ---------------------------------------------------------------------------
# CLI wiring.
# ---------------------------------------------------------------------------


def _setup_cli(subparsers: Any, _client: Optional[ArkClient]) -> None:
    """Wire the ``myark-cli registry ...`` subtree."""
    p_root = subparsers.add_parser(
        "registry",
        help="registry module commands (pure-R3 winreg operations)",
    )
    subs = p_root.add_subparsers(dest="registry_subcommand")

    # ---- list
    p_list = subs.add_parser(
        "list",
        help="list subkeys of <path> (e.g. HKLM\\SOFTWARE\\Microsoft)",
    )
    p_list.add_argument("path", help="registry path, e.g. HKLM\\SOFTWARE\\Microsoft")
    p_list.add_argument(
        "--values",
        action="store_true",
        help="also print (name, type, data) triples for each value at the key",
    )
    p_list.set_defaults(_handler=_cmd_list)

    # ---- keys
    p_keys = subs.add_parser(
        "keys",
        help="list subkey names of <path> (no values, non-recursive)",
    )
    p_keys.add_argument("path", help="registry path, e.g. HKLM\\SOFTWARE\\Microsoft")
    p_keys.set_defaults(_handler=_cmd_keys)

    # ---- read
    p_read = subs.add_parser(
        "read",
        help="read a value at <path> named <name>",
    )
    p_read.add_argument("path", help="registry path")
    p_read.add_argument("name", help="value name; pass empty string for (Default)")
    p_read.set_defaults(_handler=_cmd_read)

    # ---- write
    p_write = subs.add_parser(
        "write",
        help="write a value at <path> named <name>",
    )
    p_write.add_argument("path", help="registry path")
    p_write.add_argument("name", help="value name; pass empty string for (Default)")
    p_write.add_argument("value", help="value payload (string form)")
    p_write.add_argument(
        "--type",
        default="REG_SZ",
        dest="type_name",
        help="value type (REG_SZ, REG_DWORD, REG_MULTI_SZ, ...). default: REG_SZ",
    )
    p_write.set_defaults(_handler=_cmd_write)

    # ---- delete-value
    p_dv = subs.add_parser(
        "delete-value",
        help="delete a value at <path> named <name>",
    )
    p_dv.add_argument("path", help="registry path")
    p_dv.add_argument("name", help="value name")
    p_dv.set_defaults(_handler=_cmd_delete_value)

    # ---- delete-key
    p_dk = subs.add_parser(
        "delete-key",
        help="recursively delete a subkey at <path>",
    )
    p_dk.add_argument("path", help="registry path to delete")
    p_dk.set_defaults(_handler=_cmd_delete_key)


# ---------------------------------------------------------------------------
# Handlers.
# ---------------------------------------------------------------------------


def _open_for_read(path: str) -> Any:
    hive, subkey = reg_parser.parse_path(path)
    return winreg.OpenKey(hive, subkey, 0, _DEFAULT_OPEN_FLAGS)


def _open_for_write(path: str) -> Any:
    hive, subkey = reg_parser.parse_path(path)
    # ``winreg.SetValueEx`` requires the key to already exist; for the
    # common ARK "edit a setting" flow we auto-create. We could have
    # required callers to do it explicitly, but then "set a single value
    # at a new path" would need two CLI invocations, which is not what
    # an ARK user expects.
    if subkey:
        try:
            winreg.CreateKey(hive, subkey)
        except (PermissionError, OSError):
            # Fall through to OpenKey so the caller sees the same
            # OSError on a real permission failure as it would have
            # without the auto-create.
            pass
    return winreg.OpenKey(
        hive,
        subkey,
        0,
        _DEFAULT_OPEN_FLAGS | winreg.KEY_WRITE,
    )


def _err(msg: str) -> int:
    print(msg, file=sys.stderr)
    return 3


def _cmd_list(args: argparse.Namespace) -> int:
    try:
        key = _open_for_read(args.path)
    except (FileNotFoundError, OSError) as exc:
        return _err(f"open failed: {exc}")

    try:
        subkeys: list[str] = []
        i = 0
        while True:
            try:
                subkeys.append(winreg.EnumKey(key, i))
            except OSError:
                break
            i += 1

        values: list[tuple[str, str, str]] = []
        if args.values:
            j = 0
            while True:
                try:
                    name, raw, type_code = winreg.EnumValue(key, j)
                except OSError:
                    break
                values.append(
                    (
                        repr(name) if name == reg_parser.DEFAULT_VALUE_NAME else name,
                        reg_parser.value_kind_name(type_code),
                        _format_value(raw, type_code),
                    )
                )
                j += 1
    finally:
        key.Close()

    for sub in subkeys:
        print(f"  {sub}")
    for name, type_name, data in values:
        print(f"  {name}  [{type_name}]  {data}")
    if not subkeys and not values:
        print("  (empty)")
    return 0


def _cmd_keys(args: argparse.Namespace) -> int:
    """Subkey-only listing in the same format as ``list``.

    Reuses ``list``'s output shape (``  <sub>`` rows, ``  (empty)`` for
    a key with no children) but never touches the value table. Kept as
    a separate handler rather than a flag on ``list`` so the CLI
    surface stays narrow for scripts that only need subkey names.
    """
    try:
        key = _open_for_read(args.path)
    except (FileNotFoundError, OSError) as exc:
        return _err(f"open failed: {exc}")

    try:
        subkeys: list[str] = []
        i = 0
        while True:
            try:
                subkeys.append(winreg.EnumKey(key, i))
            except OSError:
                break
            i += 1
    finally:
        key.Close()

    for sub in subkeys:
        print(f"  {sub}")
    if not subkeys:
        print("  (empty)")
    return 0


def _cmd_read(args: argparse.Namespace) -> int:
    try:
        key = _open_for_read(args.path)
    except (FileNotFoundError, OSError) as exc:
        return _err(f"open failed: {exc}")

    try:
        try:
            raw, type_code = winreg.QueryValueEx(key, args.name)
        except FileNotFoundError:
            return _err(f"value not found: {args.name!r}")
    finally:
        key.Close()

    type_name = reg_parser.value_kind_name(type_code)
    rendered = _format_value(raw, type_code)
    print(f"[{type_name}] {rendered}")
    return 0


def _cmd_write(args: argparse.Namespace) -> int:
    try:
        type_code = reg_parser.parse_type_name(args.type_name)
    except ValueError as exc:
        return _err(str(exc))

    try:
        payload = reg_parser.readable_to_value(args.value, type_code)
    except ValueError as exc:
        return _err(str(exc))

    try:
        key = _open_for_write(args.path)
    except (FileNotFoundError, OSError) as exc:
        return _err(f"open failed: {exc}")
    try:
        winreg.SetValueEx(key, args.name, 0, type_code, payload)
    except (PermissionError, OSError) as exc:
        return _err(f"write failed: {exc}")
    finally:
        key.Close()
    print(f"wrote {args.name!r} = {args.value!r} ({reg_parser.value_kind_name(type_code)})")
    return 0


def _cmd_delete_value(args: argparse.Namespace) -> int:
    try:
        key = _open_for_write(args.path)
    except (FileNotFoundError, OSError) as exc:
        return _err(f"open failed: {exc}")
    try:
        try:
            winreg.DeleteValue(key, args.name)
        except FileNotFoundError:
            return _err(f"value not found: {args.name!r}")
    finally:
        key.Close()
    print(f"deleted value {args.name!r} under {args.path!r}")
    return 0


def _cmd_delete_key(args: argparse.Namespace) -> int:
    """Recursive delete.

    :mod:`winreg` only deletes a leaf key. ``DeleteKey`` raises
    ``OSError`` ("not empty") when the target still has children, so we
    walk the tree depth-first and delete leaves first. Empty intermediate
    keys are then removed.
    """
    try:
        hive, subkey = reg_parser.parse_path(args.path)
    except ValueError as exc:
        return _err(str(exc))

    if not subkey:
        return _err("refusing to delete a hive root")

    try:
        _recursive_delete(hive, subkey)
    except (FileNotFoundError, OSError) as exc:
        return _err(f"delete failed: {exc}")

    print(f"deleted key {args.path!r}")
    return 0


# ---------------------------------------------------------------------------
# Recursive delete implementation.
# ---------------------------------------------------------------------------


def _recursive_delete(hive: int, subkey: str, depth: int = 0) -> None:
    """Delete ``subkey`` under ``hive`` and everything beneath it.

    NTKEY semantics: ``winreg.DeleteKey`` cannot remove a non-empty
    subkey. We open it, recurse into each child, then delete it once it
    has become a leaf.
    """
    with winreg.OpenKey(hive, subkey, 0, _DEFAULT_OPEN_FLAGS | winreg.KEY_WRITE) as key:
        children: list[str] = []
        i = 0
        while True:
            try:
                children.append(winreg.EnumKey(key, i))
            except OSError:
                break
            i += 1

    for child in children:
        _recursive_delete(hive, subkey + "\\" + child, depth + 1)

    winreg.DeleteKey(hive, subkey)


# ---------------------------------------------------------------------------
# Display formatting.
# ---------------------------------------------------------------------------


def _format_value(raw: Any, type_code: int) -> str:
    """Render a raw ``winreg`` payload for terminal output."""
    rendered = reg_parser.value_to_readable(raw, type_code)
    if isinstance(rendered, bytes):
        return rendered.hex()
    if isinstance(rendered, list):
        return "\\n".join(rendered)
    return str(rendered)


__all__ = ["_setup_cli"]