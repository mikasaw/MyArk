"""
memory R3 - CLI subcommands

R3 implementation, no .sys required for read/write/query. Skip
translate / scan (R0 only).
"""
from __future__ import annotations

import argparse
import sys

from .parser import read_memory, write_memory, query_memory_regions
from .protocol import MemoryError, AccessDeniedError


def _setup_cli(subparsers, _client=None):
    """Wire the ``myark-cli memory ...`` subtree."""
    p_root = subparsers.add_parser(
        "memory",
        help="memory module commands (R3 read/write/query; R0-only translate/scan)",
    )
    subs = p_root.add_subparsers(dest="memory_subcommand", required=True)

    # ---------- read
    p_read = subs.add_parser(
        "read", help="READ_VM -- cross-process virtual read (R3 ReadProcessMemory)",
    )
    p_read.add_argument("pid", type=int, help="target process id")
    p_read.add_argument("addr", help="VA in hex (0x...)")
    p_read.add_argument("size", type=int, help="bytes to read")
    p_read.set_defaults(_handler=_cmd_read)

    # ---------- write
    p_write = subs.add_parser(
        "write", help="WRITE_VM -- cross-process virtual write (R3 WriteProcessMemory)",
    )
    p_write.add_argument("pid", type=int, help="target process id")
    p_write.add_argument("addr", help="VA in hex (0x...)")
    p_write.add_argument("data", help="hex bytes to write (e.g. '90909090')")
    p_write.set_defaults(_handler=_cmd_write)

    # ---------- query
    p_query = subs.add_parser(
        "query", help="QUERY_VM -- R3 EnumProcessModules (loaded modules only)",
    )
    p_query.add_argument("pid", type=int, help="target process id")
    p_query.set_defaults(_handler=_cmd_query)

    # ---------- translate (R0-only)
    p_trans = subs.add_parser(
        "translate",
        help="R0-only (TRANSLATE_VA -- virtual -> physical)",
    )
    p_trans.add_argument("pid", type=int)
    p_trans.add_argument("va", help="VA in hex")
    p_trans.set_defaults(_handler=_cmd_r0_only, r0_name="translate")

    # ---------- scan (R0-only)
    p_scan = subs.add_parser(
        "scan",
        help="R0-only (SCAN_KERNEL_EXECUTABLE -- byte signature search)",
    )
    p_scan.add_argument("signature", help="hex bytes (up to 16)")
    p_scan.add_argument("range_start", help="kernel VA in hex")
    p_scan.add_argument("range_end", help="kernel VA in hex")
    p_scan.set_defaults(_handler=_cmd_r0_only, r0_name="scan")


def _cmd_read(args):
    addr_str = args.addr if args.addr.lower().startswith("0x") else "0x" + args.addr
    try:
        data = read_memory(args.pid, int(args.addr, 16), args.size)
    except AccessDeniedError as exc:
        print(
            f"!! memory read {args.pid}@{addr_str}: AccessDenied (Win32 error 5) - 需要 admin 权限",
            file=sys.stderr,
        )
        print(f"   {exc}", file=sys.stderr)
        return 5
    except MemoryError as exc:
        print(f"!! memory read {args.pid}@{addr_str}: {exc}", file=sys.stderr)
        return 3

    print(f"# method=r3 pid={args.pid} addr={addr_str} size={args.size}")
    for i in range(0, len(data), 16):
        chunk = data[i: i + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  +{i:04X}: {hex_part:<47}  {ascii_part}")
    return 0


def _cmd_write(args):
    addr_str = args.addr if args.addr.lower().startswith("0x") else "0x" + args.addr
    payload = bytes.fromhex(args.data.replace(" ", ""))
    try:
        written = write_memory(args.pid, int(args.addr, 16), payload)
    except AccessDeniedError as exc:
        print(
            f"!! memory write {args.pid}@{addr_str}: AccessDenied (Win32 error 5) - 需要 admin 权限",
            file=sys.stderr,
        )
        print(f"   {exc}", file=sys.stderr)
        return 5
    except MemoryError as exc:
        print(f"!! memory write {args.pid}@{addr_str}: {exc}", file=sys.stderr)
        return 3

    print(
        f"# method=r3 pid={args.pid} addr={addr_str} "
        f"requested={len(payload)} written={written}"
    )
    return 0


def _cmd_query(args):
    try:
        regions = query_memory_regions(args.pid)
    except AccessDeniedError as exc:
        print(
            f"!! memory query {args.pid}: AccessDenied (Win32 error 5) - 需要 admin 权限",
            file=sys.stderr,
        )
        print(f"   {exc}", file=sys.stderr)
        return 5
    except MemoryError as exc:
        print(f"!! memory query {args.pid}: {exc}", file=sys.stderr)
        return 3

    print(f"# method=r3 pid={args.pid} modules={len(regions)}")
    print(f"{'BASE':<18} {'SIZE':<12} NAME")
    print("-" * 60)
    for r in regions:
        print(f"0x{r.base_address:016X} 0x{r.size:08X}  {r.name}")
    return 0


def _cmd_r0_only(args):
    print(
        f"!! {args.r0_name}: R0-only (requires .sys driver loaded, not available in R3)",
        file=sys.stderr,
    )
    print("   Use VM with .sys loaded to access this command.", file=sys.stderr)
    return 2


__all__ = ["_setup_cli"]