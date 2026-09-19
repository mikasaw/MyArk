"""MyArk File module: CLI subcommands.

Adds ``myark-cli file {info, owner, dacl, integrity, ls}`` to the parent
argparse parser. Each subcommand invokes a Win32 / Security API via the
parser helpers -- no driver handle is required, so the parent CLI's
"driver not installed" fallback never fires for this subtree.

The file module's API surface (matches the S5.3 issue spec):

* ``file info <path>``         -- ``GetFileAttributesExW`` -> attribute
  flags + size + creation / access / write times.
* ``file owner <path>``        -- ``GetNamedSecurityInfoW`` (owner) +
  ``LookupAccountSidW`` -> ``domain\\account``.
* ``file dacl <path>``         -- ``GetNamedSecurityInfoW`` (full SD)
  + ``ConvertSecurityDescriptorToStringSecurityDescriptorW`` -> SDDL
  string.
* ``file integrity <path>``    -- ``GetNamedSecurityInfoW`` (label +
  SACL) + manual mandatory-label ACE walk -> integrity RID + name.
* ``file ls <dir>``            -- ``FindFirstFileW`` / ``FindNextFileW``
  -> one-level listing rendered as ``PATH | SIZE | MTIME`` rows.

All five subcommands operate on paths and never touch the driver.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, Optional

from myark.client.ark_client import ArkClient
from myark.modules.file import parser as file_parser


# ---------------------------------------------------------------------------
# CLI wiring.
# ---------------------------------------------------------------------------


def _setup_cli(subparsers: Any, _client: Optional[ArkClient]) -> None:
    """Wire the ``myark-cli file ...`` subtree."""
    p_root = subparsers.add_parser(
        "file",
        help="file module commands (pure-R3 file info + security descriptor)",
    )
    subs = p_root.add_subparsers(dest="file_subcommand")

    # ---- info
    p_info = subs.add_parser(
        "info",
        help="show WIN32_FILE_ATTRIBUTE_DATA for <path> (flags + size + times)",
    )
    p_info.add_argument("path", help="file or directory path (UTF-16 safe)")
    p_info.set_defaults(_handler=_cmd_info)

    # ---- owner
    p_owner = subs.add_parser(
        "owner",
        help="show the OWNER SID + domain\\account for <path>",
    )
    p_owner.add_argument("path", help="file or directory path")
    p_owner.set_defaults(_handler=_cmd_owner)

    # ---- dacl
    p_dacl = subs.add_parser(
        "dacl",
        help="render the DACL of <path> as an SDDL string",
    )
    p_dacl.add_argument("path", help="file or directory path")
    p_dacl.add_argument(
        "--full",
        action="store_true",
        help="print the full SDDL string (owner + group + DACL + SACL + label) "
             "rather than just the DACL fragment",
    )
    p_dacl.set_defaults(_handler=_cmd_dacl)

    # ---- integrity
    p_int = subs.add_parser(
        "integrity",
        help="show the integrity level (TOKEN_MANDATORY_*) of <path>",
    )
    p_int.add_argument("path", help="file or directory path")
    p_int.set_defaults(_handler=_cmd_integrity)

    # ---- ls
    p_ls = subs.add_parser(
        "ls",
        help="list immediate children of <directory> (path | size | mtime)",
    )
    p_ls.add_argument("directory", help="directory path to enumerate (non-recursive)")
    p_ls.set_defaults(_handler=_cmd_ls)


# ---------------------------------------------------------------------------
# Handlers.
# ---------------------------------------------------------------------------


def _err(msg: str) -> int:
    print(msg, file=sys.stderr)
    return 3


def _cmd_info(args: argparse.Namespace) -> int:
    try:
        info = file_parser.get_file_info(args.path)
    except OSError as exc:
        return _err(f"file info failed: {exc}")

    print(f"path:    {info['path']}")
    print(f"size:    {info['size']} bytes")
    print(f"created: {info['created']}")
    print(f"accessed:{info['accessed']}")
    print(f"modified:{info['modified']}")
    print("flags:   " + " | ".join(info["flags_list"]))
    if info["is_directory"]:
        print("(directory)")
    return 0


def _cmd_owner(args: argparse.Namespace) -> int:
    try:
        info = file_parser.get_file_owner(args.path)
    except OSError as exc:
        return _err(f"file owner failed: {exc}")

    if info["account"] == "(no owner)" and not info["sid"]:
        print("(no owner)")
    else:
        if info["domain"]:
            print(f"owner:   {info['domain']}\\{info['account']}")
        else:
            print(f"owner:   {info['account']}")
        print(f"  sid:   {info['sid']}")
        print(f"  use:   {info['use']} ({info['use_code']})")
    return 0


def _cmd_dacl(args: argparse.Namespace) -> int:
    try:
        info = file_parser.get_file_dacl(args.path)
    except OSError as exc:
        return _err(f"file dacl failed: {exc}")

    if args.full:
        # ``sddl`` is the full SDDL string rendered with every
        # requested security-information bit set.
        sddl = info.get("sddl") or ""
        if not sddl:
            return _err("file dacl failed: empty SDDL string")
        print(sddl)
    else:
        dacl = info.get("dacl") or ""
        if not dacl:
            return _err("file dacl failed: empty DACL fragment")
        print(dacl)
    return 0


def _cmd_integrity(args: argparse.Namespace) -> int:
    try:
        info = file_parser.get_file_integrity(args.path)
    except OSError as exc:
        return _err(f"file integrity failed: {exc}")

    if info["rid"] is None:
        print("integrity: (none)")
    else:
        print(f"integrity: {info['name']} (rid=0x{info['rid']:X})")
    return 0


def _cmd_ls(args: argparse.Namespace) -> int:
    try:
        rows = file_parser.list_directory(args.directory)
    except OSError as exc:
        return _err(f"file ls failed: {exc}")

    print(f"directory: {args.directory}")
    print(f"{'PATH':<60} | {'SIZE':>12} | {'MTIME'}")
    print("-" * 100)
    for row in rows:
        path = row["path"]
        # Trim long paths so the column stays readable; the user
        # can re-run ``file info`` to see the full detail row.
        if len(path) > 60:
            path = "..." + path[-57:]
        print(f"{path:<60} | {row['size']:>12} | {row['modified']}")
    print(f"\nTotal: {len(rows)} entries")
    return 0


__all__ = ["_setup_cli"]