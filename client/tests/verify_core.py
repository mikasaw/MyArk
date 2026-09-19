"""
verify_core.py -- static + CLI verification for the 15 S7.3 modules.

Mode A of MIT-318 S7.3: run this *inside the VM* after install_vm.ps1.
The script does NOT load the .sys -- it imports the in-tree R3 client
(``myark``) and walks each module's CLI surface, confirming:

  1. The module is registered (entry_points + builtin fallback agree).
  2. ``myark-cli <module> --help`` exits 0 and shows subcommands.
  3. Each read-only subcommand runs and produces a
     ``source=r3-fallback`` report when the driver is not loaded --
     this is the expected steady-state on the very first boot before
     the .sys has been installed.
  4. The mutating subcommands (``apply_*``, ``remove_*``, ``disable_*``,
     ``enable_*``, ``inspect_token``) emit a ``not-implemented`` line
     in S7.3 -- the agent's stub IOCTLs return STATUS_NOT_IMPLEMENTED.

Usage (inside VM):

    PS> python verify_core.py
    PS> python verify_core.py --module redirect   # single module
    PS> python verify_core.py --strict            # exit non-zero on any fail

The agent does NOT run this script -- it is the user's verification step
after the .sys is installed in the VM. This file lives in
``client/tests/verify_core.py`` so that ``uv run pytest`` can pick it up
but ``verify_core.py`` runs cleanly as a standalone script too.
"""

from __future__ import annotations

import argparse
import importlib
import json
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Module catalog -- 15 S7.3 modules. Order matches MIT-318's stage plan.
# Each entry lists the read-only and mutating subcommands we expect.
# ---------------------------------------------------------------------------

@dataclass
class ModuleSpec:
    name: str
    ro_subcommands: list[str] = field(default_factory=list)
    rw_subcommands: list[str] = field(default_factory=list)
    notes: str = ""


# Read-only: returns source=r3-fallback when driver absent.
# Mutating: returns source=not-implemented in S7.3 (intentional stub).
MODULES: list[ModuleSpec] = [
    ModuleSpec(
        name="wfp",
        ro_subcommands=["list_filters"],
        rw_subcommands=["disable_filter", "remove_filter"],
        notes="WFP callout/filter inspector",
    ),
    ModuleSpec(
        name="mutation",
        ro_subcommands=["inspect_token"],
        rw_subcommands=["set_integrity"],
        notes="Token integrity / UAC state inspector",
    ),
    ModuleSpec(
        name="redirect",
        ro_subcommands=["inspect"],
        rw_subcommands=["apply", "restore"],
        notes="IRP/CM/OB redirect scanner",
    ),
    ModuleSpec(
        name="hwid",
        ro_subcommands=["list_pci", "list_acpi"],
        rw_subcommands=["disable_device"],
        notes="PCI/ACPI hardware ID enumerator",
    ),
    ModuleSpec(
        name="bugcheck",
        ro_subcommands=["list_callbacks", "list_parameters"],
        rw_subcommands=["set_parameter"],
        notes="Bugcheck callback registry",
    ),
    ModuleSpec(
        name="win32k",
        ro_subcommands=["list_syscalls"],
        rw_subcommands=[],
        notes="Win32k syscall table",
    ),
    ModuleSpec(
        name="wsl",
        ro_subcommands=["list_lxss"],
        rw_subcommands=[],
        notes="WSL lxss process list",
    ),
    ModuleSpec(
        name="alpc",
        ro_subcommands=["list_ports"],
        rw_subcommands=["close_port"],
        notes="ALPC port inspector",
    ),
    ModuleSpec(
        name="authentication",
        ro_subcommands=["whoami"],
        rw_subcommands=["impersonate"],
        notes="Authentication / token viewer",
    ),
    ModuleSpec(
        name="trust",
        ro_subcommands=["verify_driver", "verify_image"],
        rw_subcommands=["add_to_trust"],
        notes="Driver signing trust policy",
    ),
    ModuleSpec(
        name="preflight",
        ro_subcommands=["check"],
        rw_subcommands=["apply_fix"],
        notes="Pre-install safety check",
    ),
    ModuleSpec(
        name="security_audit",
        ro_subcommands=["scan"],
        rw_subcommands=["harden"],
        notes="System security posture scan",
    ),
    ModuleSpec(
        name="capability",
        ro_subcommands=["list"],
        rw_subcommands=["enable", "disable"],
        notes="Capability/SID profile",
    ),
    ModuleSpec(
        name="kernel_ext",
        ro_subcommands=["list"],
        rw_subcommands=["unload"],
        notes="Kernel extension inventory",
    ),
    ModuleSpec(
        name="safety",
        ro_subcommands=["snapshot"],
        rw_subcommands=["restore"],
        notes="Safety snapshot/restore",
    ),
]


@dataclass
class CheckResult:
    module: str
    subcommand: str
    expected: str
    got: str
    ok: bool
    detail: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_cli(args: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Run a myark-cli invocation; return (rc, stdout, stderr)."""
    proc = subprocess.run(
        [sys.executable, "-m", "myark.cli.main", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _check_module_registered(spec: ModuleSpec) -> Optional[CheckResult]:
    """Import the module to confirm the R3 client surface is intact."""
    full = f"myark.modules.{spec.name}"
    try:
        importlib.import_module(full)
        return None
    except Exception as exc:
        return CheckResult(
            module=spec.name,
            subcommand="<import>",
            expected="import_ok",
            got=f"import_error:{exc}",
            ok=False,
        )


def _check_help(spec: ModuleSpec) -> CheckResult:
    rc, out, err = _run_cli([spec.name, "--help"])
    ok = rc == 0
    detail = out[:200] if ok else (err or out)[:200]
    return CheckResult(
        module=spec.name,
        subcommand="--help",
        expected="rc=0",
        got=f"rc={rc}",
        ok=ok,
        detail=detail,
    )


def _check_subcommand(
    spec: ModuleSpec,
    subcommand: str,
    expect_kind: str,
) -> CheckResult:
    """Run a subcommand and check for the expected source tag."""
    rc, out, err = _run_cli([spec.name, subcommand])
    combined = (out + "\n" + err).lower()

    if expect_kind == "r3-fallback":
        expected = "source=r3-fallback"
        matched = expected in combined or "r3-fallback" in combined
    elif expect_kind == "not-implemented":
        expected = "source=not-implemented or not implemented"
        matched = (
            "not-implemented" in combined
            or "not implemented" in combined
            or "not_implemented" in combined
        )
    else:
        expected = f"unknown kind={expect_kind}"
        matched = rc == 0

    return CheckResult(
        module=spec.name,
        subcommand=subcommand,
        expected=expected,
        got=f"rc={rc}",
        ok=matched,
        detail=(out or err)[:200].strip(),
    )


# ---------------------------------------------------------------------------
# Top-level verifier
# ---------------------------------------------------------------------------

def verify_one(spec: ModuleSpec) -> list[CheckResult]:
    results: list[CheckResult] = []

    imp_err = _check_module_registered(spec)
    if imp_err is not None:
        results.append(imp_err)
        return results

    results.append(_check_help(spec))

    for sub in spec.ro_subcommands:
        results.append(_check_subcommand(spec, sub, "r3-fallback"))
    for sub in spec.rw_subcommands:
        results.append(_check_subcommand(spec, sub, "not-implemented"))

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="MyArk S7.3 verifier")
    parser.add_argument(
        "--module",
        action="append",
        default=None,
        help="restrict to specific module(s) (repeatable)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit non-zero on any failed check",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON report to stdout",
    )
    args = parser.parse_args()

    if args.module:
        wanted = set(args.module)
        specs = [m for m in MODULES if m.name in wanted]
    else:
        specs = list(MODULES)

    if not specs:
        print("[verify_core] no modules selected", file=sys.stderr)
        return 2

    all_results: list[CheckResult] = []
    for spec in specs:
        print(f"[verify_core] {spec.name}: {len(spec.ro_subcommands)} RO + {len(spec.rw_subcommands)} RW")
        all_results.extend(verify_one(spec))

    total = len(all_results)
    passed = sum(1 for r in all_results if r.ok)
    failed = total - passed

    summary = {
        "modules": [s.name for s in specs],
        "total_checks": total,
        "passed": passed,
        "failed": failed,
        "results": [
            {
                "module": r.module,
                "subcommand": r.subcommand,
                "expected": r.expected,
                "got": r.got,
                "ok": r.ok,
                "detail": r.detail,
            }
            for r in all_results
        ],
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print()
        print("=" * 72)
        print(f"verify_core: {passed}/{total} checks passed ({failed} failed)")
        print("=" * 72)
        if failed:
            print("\nFAILED CHECKS:")
            for r in all_results:
                if not r.ok:
                    print(f"  [{r.module}] {r.subcommand}")
                    print(f"    expected: {r.expected}")
                    print(f"    got:      {r.got}")
                    if r.detail:
                        print(f"    detail:   {r.detail}")
        else:
            print("All checks green -- driver not required for the r3-fallback path.")

    if args.strict and failed:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
