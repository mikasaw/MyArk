"""``myark-cli`` console entry point.

Stage S3 ships four core driver subcommands:

- ``driver check``       probe the driver and print the result
- ``driver version``     print ``MYARK_CORE_VERSION_OUTPUT``
- ``driver modules``     list modules reported by the driver
- ``driver capabilities`` list IOCTLs reported by the driver

Stage S4+ extends the dispatcher with module-contributed subcommands, each
registered through ``myark.plugin_loader.ModuleRegistration.cli_setup``.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence

from ..client.ark_client import (
    ArkClient,
    DriverError,
    DriverNotInstalledError,
    open_driver_or_null,
)
from ..client.driver_check import (
    DriverProbe,
    driver_not_installed_message,
    probe_driver,
)
from ..client.module_query import ModuleQuery
from ..client import taskmgr_hijack
from ..plugin_loader import ModuleRegistration, load_modules


PROG = "myark-cli"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="MyArk R3 client (console) -- talks to MyArkCore.sys.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # driver <subcommand>
    driver_p = subparsers.add_parser("driver", help="interact with the MyArkCore driver")
    driver_subs = driver_p.add_subparsers(dest="driver_subcommand")

    p = driver_subs.add_parser("check", help="probe whether the driver is installed")
    p.set_defaults(_handler=_cmd_driver_check)

    p = driver_subs.add_parser("version", help="print MYARK_CORE_VERSION_OUTPUT")
    p.set_defaults(_handler=_cmd_driver_version)

    p = driver_subs.add_parser("modules", help="list registered driver modules")
    p.set_defaults(_handler=_cmd_driver_modules)

    p = driver_subs.add_parser("capabilities", help="list driver IOCTL capabilities")
    p.set_defaults(_handler=_cmd_driver_capabilities)

    # stealth <subcommand> (pure R3, no driver surface)
    stealth_p = subparsers.add_parser(
        "stealth", help="adversarial-hardening helpers (R2-8)")
    stealth_subs = stealth_p.add_subparsers(dest="stealth_subcommand")

    p = stealth_subs.add_parser(
        "taskmgr-hijack",
        help="redirect Task Manager to the MyArk UI via IFEO")
    p.add_argument("--install", action="store_true",
                   help="install the IFEO Debugger redirect (admin)")
    p.add_argument("--uninstall", action="store_true",
                   help="remove our redirect (foreign ones are kept)")
    p.add_argument("--status", action="store_true",
                   help="print the current redirect state")
    p.add_argument("--target", default=taskmgr_hijack.DEFAULT_TARGET,
                   help="program to launch instead of taskmgr.exe")
    p.add_argument("--force", action="store_true",
                   help="uninstall: remove even a foreign Debugger value")
    p.set_defaults(_handler=_cmd_stealth_taskmgr_hijack)

    return parser, subparsers


def _extend_with_modules(subparsers, registered: dict[str, ModuleRegistration]) -> None:
    for name, reg in registered.items():
        try:
            reg.setup_cli(subparsers, None)
        except Exception as exc:
            print(f"[cli] module {name} cli_setup failed: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Driver subcommand handlers.
# ---------------------------------------------------------------------------


def _cmd_stealth_taskmgr_hijack(args: argparse.Namespace) -> int:
    flags = [args.install, args.uninstall, args.status]
    if sum(1 for f in flags if f) != 1:
        print("pick exactly one of --install / --uninstall / --status",
              file=sys.stderr)
        return 2

    if args.status:
        st = taskmgr_hijack.status()
        if st.installed:
            who = "myark" if st.ours else "foreign"
            print(f"installed ({who}) target: {st.target}")
        else:
            print("not installed")
        return 0

    print("[audit] taskmgr-hijack", "install" if args.install else "uninstall")

    if args.install:
        st = taskmgr_hijack.install(args.target)
        print(f"installed: taskmgr.exe now launches: {st.target}")
        print("  remove it any time with --uninstall")
        return 0

    before = taskmgr_hijack.status()
    st = taskmgr_hijack.uninstall(force=args.force)
    if st.installed and before.ours is False:
        print("foreign Debugger value left untouched (use --force to remove)")
        return 2
    if before.installed:
        print("uninstalled: taskmgr.exe restored")
    else:
        print("nothing to uninstall")
    return 0


def _cmd_driver_check(args: argparse.Namespace) -> int:
    probe = probe_driver()
    if probe.installed:
        if probe.version_output is not None:
            print(f"driver installed (version: {probe.version_output.DisplayName})")
        else:
            print("driver installed (version probe failed)")
        return 0
    # The acceptance criteria explicitly want this exact string:
    print(driver_not_installed_message())
    if probe.error_code is not None:
        print(f"  win32 error: 0x{probe.error_code & 0xFFFFFFFF:08X}", file=sys.stderr)
    return 2


def _cmd_driver_version(args: argparse.Namespace) -> int:
    client = open_driver_or_null()
    if client is None:
        print(driver_not_installed_message(), file=sys.stderr)
        return 2
    try:
        ver = client.get_version()
    finally:
        client.close()
    payload = {
        "size": ver.Size,
        "core_protocol_version": ver.CoreProtocolVersion,
        "module_protocol_version": ver.ModuleProtocolVersion,
        "build_number": ver.BuildNumber,
        "active_module_count": ver.ActiveModuleCount,
        "display_name": ver.DisplayName,
    }
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


def _cmd_driver_modules(args: argparse.Namespace) -> int:
    client = open_driver_or_null()
    if client is None:
        print(driver_not_installed_message(), file=sys.stderr)
        return 2
    try:
        mq = ModuleQuery(client)
        modules = mq.query_modules()
    finally:
        client.close()
    payload = [m.as_dict() for m in modules]
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


def _cmd_driver_capabilities(args: argparse.Namespace) -> int:
    client = open_driver_or_null()
    if client is None:
        print(driver_not_installed_message(), file=sys.stderr)
        return 2
    try:
        mq = ModuleQuery(client)
        caps = mq.query_capabilities()
    finally:
        client.close()
    payload = [
        {
            "ioctl_code": f"0x{c.ioctl_code:08X}",
            "name": c.name,
            "module_id": c.module_id,
        }
        for c in caps
    ]
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


# ---------------------------------------------------------------------------
# Entrypoint.
# ---------------------------------------------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser, subparsers = _build_parser()

    # Discover modules so they can register their own CLI subcommands. This
    # must happen before parse_args() so argparse sees the registered choices.
    # We pass client=None so module cli_setup() handlers can choose to use it
    # lazily if they need it.
    registered: dict[str, ModuleRegistration] = load_modules(None, [])
    _extend_with_modules(subparsers, registered)

    args = parser.parse_args(argv)

    handler = getattr(args, "_handler", None)
    if handler is None:
        parser.print_help()
        return 1
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())


__all__ = ["main", "PROG"]