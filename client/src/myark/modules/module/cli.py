"""
module R3 - CLI subcommands

Single subcommand:

    module enum <pid>     -- enumerate loaded modules of <pid>
                              (R3 psapi EnumProcessModules)
"""

from __future__ import annotations

import argparse
import sys

from .parser import enumerate_modules
from .protocol import ModuleError, AccessDeniedError


def _setup_cli(subparsers, _client=None):
    """Wire the ``myark-cli module ...`` subtree."""
    p_root = subparsers.add_parser(
        "module",
        help="module enumeration (R3 EnumProcessModules + GetModuleFileNameExW)",
    )
    subs = p_root.add_subparsers(dest="module_subcommand", required=True)

    p_enum = subs.add_parser(
        "enum",
        help="list loaded modules of <pid> via R3 psapi EnumProcessModules",
    )
    p_enum.add_argument("pid", type=int, help="target process id")
    p_enum.add_argument(
        "--name",
        default="",
        help="substring filter on the base file name (case-insensitive)",
    )
    p_enum.set_defaults(_handler=_cmd_enum)


def _cmd_enum(args):
    try:
        rows = enumerate_modules(args.pid)
    except AccessDeniedError as exc:
        print(
            f"!! module enum {args.pid}: AccessDenied (Win32 error 5) - 需要 admin 权限",
            file=sys.stderr,
        )
        print(f"   {exc}", file=sys.stderr)
        return 5
    except ModuleError as exc:
        print(f"!! module enum {args.pid}: {exc}", file=sys.stderr)
        return 3

    needle = args.name.lower()
    if needle:
        rows = [r for r in rows if needle in r.name.lower()]

    print(f"# method=r3 pid={args.pid} modules={len(rows)}")
    print(f"{'BASE':<18} {'SIZE':<10} {'ENTRY':<18} NAME")
    print("-" * 70)
    for r in rows:
        print(
            f"0x{r.base_address:016X} 0x{r.size:08X} 0x{r.entry_point:016X}  {r.name}"
        )
    return 0


__all__ = ["_setup_cli"]