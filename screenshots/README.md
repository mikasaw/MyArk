# screenshots/

This directory captures text-mode "screenshots" of `myark-cli` outputs,
captured at S10.1 against a Windows 11 24H2 host without the driver
loaded (so the screenshots show the **static / Mode A** behaviour:
driver not installed, R3-only modules still respond from pure Win32).

## Files

| File | Content |
|---|---|
| [myark-cli-help.txt](myark-cli-help.txt)             | top-level `myark-cli --help` |
| [myark-cli-driver.txt](myark-cli-driver.txt)         | `myark-cli driver --help` + check behaviour |
| [myark-cli-modules-help.md](myark-cli-modules-help.md) | per-module `--help` for all 27 sub-modules |
| [README.md](README.md)                                | this index |

## Static-mode behaviour (no driver loaded)

R3-only modules (registry, network, file, process/thread/module, security_audit,
preflight, ...) work fully with `MyArkCore.sys` not installed. Their `--help`
text and pure-R3 subcommands run as in any user-mode tool.

R0 / hybrid subcommands (driver check, memory translate/scan, callback enum,
dyndata, ...) return either:

```
win32 error: 0x00000002
driver not installed (expected device \\.\MyArkCore)
```

(when the device is missing) or the expected kernel output once
`scripts\install_vm.ps1 -DriverPath C:\MyArkCore.sys` has been run
inside a Hyper-V VM with `testsigning on`.

## Captured at

```
$ uv run myark-cli --version
myark-cli 0.1.0
$ uv run python -c "import sys; print(sys.version)"
3.14.x
$ git rev-parse HEAD
622bd4d   doc(changelog): CHANGELOG.md S1-S10.1 变更日志 (中文)
```
