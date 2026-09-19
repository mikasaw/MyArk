# MyArk

[中文](README.md) | **English**

A self-developed Windows ARK (Anti-Rootkit) tool: one KMDF `.sys` with compile-time
module gating, plus a Python user-mode (R3) UI/CLI.

> ## ⚠️ Disclaimer / 免责声明
>
> This project is a Windows kernel security research tool **for authorized test
> environments only**. It exists to study Windows kernel internals and to inspect
> the security posture of systems you own.
>
> - Use it solely in isolated test environments you **own or are explicitly
>   authorized** (in writing) to assess — never against third-party systems;
> - Loading and calling kernel drivers can **crash the OS (BSOD)** — always test
>   inside snapshot-protected virtual machines;
> - MyArk ships **no** malware payload, packer/crypter, detection-evasion or
>   weaponization capability. Every mutating IOCTL is gated by SAFETY_TOKEN +
>   EVAL_GATE, and the device is openable only by SYSTEM/Administrators;
> - Provided "AS IS" under the [LICENSE](LICENSE) (MIT); the authors accept no
>   liability for misuse or resulting damage.

- Single `MyArkCore.sys` (KMDF, non-PnP control device)
- 118 IOCTL protocol definitions (~96 registered on the dispatch surface), covering
  four quadrants (pure R3 / R0 read + R3 display / R0-only / hybrid)
- 31 driver modules, compile-gated via `#if MYARK_MODULE_<NAME>`, runtime
  start/stop via registry `Modules\<Name>=0/1`
- R3: Python 3.14 + Tkinter UI / argparse CLI
- Three-layer search: left-pane filter + Ctrl+P command palette + sidebar advanced
  search (8 scopes + 3 modes), Chinese/pinyin support (pypinyin)
- Multi-window enhancements: Detail / Compare / Filter-builder / Action-history
  popups (S9.2)
- Security model: device SDDL restricts the handle to SYSTEM/Administrators;
  mutating IOCTLs (87_actions + 10_process mutation surface) require a per-boot
  session-key HMAC-SHA256 token (±120 s anti-replay); physical memory access is
  limited to RAM ranges and writes need an explicit registry opt-in
- 831 pytest cases, all passing (7 skipped)

---

## Table of Contents

- [Background](#background)
- [Architecture Overview](#architecture-overview)
- [Module List](#module-list)
- [Build System](#build-system)
- [Run Manual](#run-manual)
- [CLI Manual](#cli-manual)
- [Testing](#testing)
- [Contributing](#contributing)
- [Documentation](#documentation)
- [Release](#release)
- [License](#license)
- [Status](#status)

---

## Background

Windows ARK (Anti-Rootkit) tools detect and investigate kernel-mode rootkits,
hidden processes, DKOM tampering, unsigned drivers, security misconfigurations
and other deep system issues.

Commercial ARK tools (PCHunter / WinArk / XueTr) are closed-source, hard to extend,
and most do not support recent kernels (Windows 11 24H2+).

**MyArk goals**:

| Dimension | Approach |
|---|---|
| Deployment | Single `MyArkCore.sys` (KMDF non-PnP control device); no plugin DLLs, no multi-.sys |
| Modularity | One `.c`/`.h` pair + descriptor per module, `#if MYARK_MODULE_<NAME>` compile gate |
| Start/stop | Compile-time hard switch (`config/myark_*.h`) + runtime soft switch (`HKLM\...\Modules\<Name>=0/1`) |
| R3 | Python 3.14 + Tkinter; master-detail three panes + floating windows |
| Testing | pytest suites for R3 protocol + client + static IOCTL verification + UI |
| Documentation | Chinese-first, English code identifiers |

Progress: S1–S8 done, S9.1 UI integration, S9.2 multi-window, S10.1 wrap-up; the
project has since moved to an R-series hardening roadmap (see `docs/ROADMAP.md`).

---

## Architecture Overview

### R0 driver diagram

```
+---------------------------------------------------------------+
|                     MyArkCore.sys (KMDF)                       |
+---------------------------------------------------------------+
|                                                               |
|  DriverEntry  --> WdfDriverCreate  --> DeviceInit (non-PnP)    |
|                                                               |
|  +-- framework/ -------------------------------------------+ |
|  |   driver_entry.c       -- DriverEntry / DriverUnload     | |
|  |   device_control.c     -- IRP_MJ_DEVICE_CONTROL entry    | |
|  |   io_queue.c           -- WDFQUEUE parallel/serial       | |
|  +---------------------------------------------------------+ |
|                                                               |
|  +-- dispatch/ ---------------------------------------------+ |
|  |   ioctl_dispatch.c     -- IOCTL table lookup             | |
|  |   ioctl_registry.c     -- module descriptor registry     | |
|  |   core_ioctl_handlers.c -- 5 core IOCTLs                 | |
|  |   ioctl_validation.c   -- SAFETY_TOKEN / length checks   | |
|  |   ioctl_helpers.h      -- in/out buffer macros           | |
|  +---------------------------------------------------------+ |
|                                                               |
|  +-- modules/ (31 functional + 2 smoke) -------------------+ |
|  |   00_hello             -- mechanism smoke test            | |
|  |   10_process           -- process enumeration             | |
|  |   11_thread            -- thread enumeration              | |
|  |   12_memory            -- VA translation / arbitrary read | |
|  |   20_handle            -- handle table enumeration        | |
|  |   21_section           -- section object enumeration      | |
|  |   22_kmod              -- kernel module enumeration       | |
|  |   23_storage           -- disk/volume enumeration         | |
|  |   24_device_audit      -- device stack audit              | |
|  |   25_kernel            -- kernel info queries             | |
|  |   30_keyboard          -- keyboard filter audit           | |
|  |   31_debug_output      -- DebugPrint capture              | |
|  |   70_dyndata           -- NtQuerySystemInformation style  | |
|  |   71_callback          -- Ps/Cm/Ob/Image/Dbg callbacks    | |
|  |   72_wfp               -- WFP callout enumeration         | |
|  |   73_mutation          -- EPROCESS token tamper detection | |
|  |   74_redirect          -- CmCallback / IoCallDriver detect| |
|  |   75_hwid              -- MajorFunction / HWID checks     | |
|  |   76_bugcheck          -- last bugcheck + framebuffer     | |
|  |   77_win32k            -- GUI threads / hooks             | |
|  |   78_wsl               -- WSL silo enumeration            | |
|  |   79_alpc              -- ALPC port enumeration           | |
|  |   80_authentication    -- Authenticode signatures         | |
|  |   81_trust             -- PE / catalog signatures         | |
|  |   82_preflight         -- environment health check        | |
|  |   83_security_audit    -- Defender / Secure Boot audit    | |
|  |   84_capability        -- driver self-reported capability | |
|  |   85_kernel_ext        -- Win11 25H2 info-class extension | |
|  |   86_safety            -- 6-step gated evaluator          | |
|  |   87_actions           -- 7 mixed R0+R3 actions           | |
|  +---------------------------------------------------------+ |
+---------------------------------------------------------------+
                                |
                                |  DeviceIoControl (kernel handle)
                                v
+---------------------------------------------------------------+
|                     R3 (Python 3.14)                          |
+---------------------------------------------------------------+
|  +-- client/ ----------------------------------------------+  |
|  |  ark_client.py        -- IOCTL packing/unpacking         |  |
|  |  transport.py         -- CreateFile / DeviceIoControl    |  |
|  |  driver_check.py      -- driver presence/version probe   |  |
|  |  module_query.py      -- module list / capabilities      |  |
|  +---------------------------------------------------------+  |
|  +-- protocol/ --------------------------------------------+  |
|  |  <module>_protocol.py  -- ctypes structs + serialization |  |
|  +---------------------------------------------------------+  |
|  +-- modules/ (26 + 5) ------------------------------------+  |
|  |  8 builtin + 18 in-tree                                  |  |
|  +---------------------------------------------------------+  |
|  +-- cli/main.py -- argparse entry (myark-cli) -------------+  |
|  +-- ui/main_window.py -- Tkinter main window (myark-ui) ---+  |
+---------------------------------------------------------------+
```

### R3 diagram (CLI + UI)

```
+-----------------------------+        +-----------------------------+
|       myark-cli (CLI)       |        |        myark-ui (GUI)        |
+-----------------------------+        +-----------------------------+
| argparse subparsers         |        | Tkinter master-detail panes |
|  27 sub-modules             |        |  left = entity list+filter  |
|  driver + 26 modules        |        |  mid   = detail tabs        |
|                             |        |  right = sidebar            |
|  --help / per-cmd --help    |        |  + floating popup windows   |
|  JSON / Table output        |        |  Ctrl+P palette / Ctrl+Shift+F search |
+-----------------------------+        +-----------------------------+
                |                                       |
                +---------------+-----------------------+
                                |
                                v
                +-----------------------------+
                |     plugin_loader.py        |
                |  ModuleRegistration         |
                |  setup_cli / setup_ui       |
                +-----------------------------+
                                |
                                v
                +-----------------------------+
                |   myark.modules.* (R3)      |
                |   myark.client.ArkClient    |
                +-----------------------------+
                                |
                                |  DeviceIoControl
                                v
                +-----------------------------+
                |      MyArkCore.sys (R0)     |
                +-----------------------------+
```

### R0/R3 communication flow

```
R3 process                                  R0 driver
--------                                  --------
ArkClient.call(ioctl_id, req, resp):
  1. pack request via ctypes struct
  2. CreateFile("\\\\.\\MyArkCore")
  3. DeviceIoControl(h, ioctl_id, in, in_size, out, out_size, &bytes_ret, NULL)
                |
                v
                          IRP_MJ_DEVICE_CONTROL
                                    |
                          1. SAFETY_TOKEN validation
                          2. input length  vs registered expected_in
                          3. output length vs registered expected_out
                                    |
                          ioctl_registry.c: descriptor lookup
                                    |
                          <module>_ioctl.c: module handler
                                    |
                          RtlCopyMemory(output_buf, response, ...)
                          WdfRequestComplete(STATUS_SUCCESS)
                ^
  4. DeviceIoControl returns STATUS_SUCCESS
  5. resp.unpack(output_buf)
  6. return ModuleResponse.ok(data)
```

### Four quadrants

| Quadrant | Meaning | MyArk approach |
|---|---|---|
| ① | Pure user mode (R3) | winreg / IP Helper / PSAPI / WTS / EnumProcesses |
| ② | R0 read + R3 display | kernel reads a buffer; R3 formats the table |
| ③ | R0 mandatory | MmCopyVirtualMemory / ObReferenceObjectByPointer |
| ④ | Hybrid | kill / inject / dump prefer R3, R0 as fallback |

The four quadrants are a design and implementation-order principle (see
[Contributing](#contributing)). On the driver side, each module is assembled from
a descriptor (`MYARK_MODULE_DESCRIPTOR` in `shared/driver/MyArkPluginApi.h`) plus
a static per-module IOCTL table (`MYARK_IOCTL_ENTRY`) — the descriptor carries no
quadrant field.

---

## Module List

### Driver modules (30)

| ID | Module | Type | Notes |
|---|---|---|---|
| core | CORE | core | 5 IOCTLs + descriptor registry + SAFETY_TOKEN |
| 00 | hello | smoke | `MyArkIoctlHello` returns a fixed string |
| 10 | process | process | enum + detail + threads + token |
| 11 | thread | thread | enum + detail |
| 12 | memory | memory | R3 read/write/query + R0 translate/scan |
| 20 | handle | handle | handle table enumeration |
| 21 | section | section | section object enumeration |
| 22 | kmod | kernel module | PsLoadedModuleList walk |
| 23 | storage | storage | volume enumeration |
| 24 | device_audit | device audit | device stack audit |
| 25 | kernel | kernel | kernel info queries |
| 30 | keyboard | keyboard | keyboard filter driver audit |
| 31 | debug_output | DebugPrint | DebugPrint capture |
| 70 | dyndata | NtQuery style | aggregated system info queries |
| 71 | callback | callbacks | Ps/Cm/Ob/Image/Dbg callback enumeration |
| 72 | wfp | WFP | WFP callout enumeration |
| 73 | mutation | DKOM | EPROCESS token tamper detection |
| 74 | redirect | redirect | CmCallback / IoCallDriver detection |
| 75 | hwid | HWID | MajorFunction / device-identifier checks |
| 76 | bugcheck | BugCheck | last bugcheck + framebuffer |
| 77 | win32k | GUI | GUI thread / hook enumeration |
| 78 | wsl | WSL | WSL silo enumeration |
| 79 | alpc | ALPC | ALPC port enumeration |
| 80 | authentication | auth | Authenticode signatures |
| 81 | trust | trust | PE / catalog signatures |
| 82 | preflight | preflight | environment health check |
| 83 | security_audit | security audit | Defender / Secure Boot / Trusted Boot |
| 84 | capability | capability | driver self-reported capabilities |
| 85 | kernel_ext | kernel ext | Win11 25H2 info-class extension |
| 86 | safety | safety | 6-step gated evaluator |
| 87 | actions | actions | 7 mixed R0+R3 actions |

Each module contains:

```
modules/<NN>_<name>/
  descriptor.h         -- MYARK_MODULE_<NAME>_DESCRIPTOR declaration
  descriptor.c         -- descriptor instantiation + registration
  ioctl.h              -- in/out structs + IOCTL id macros
  ioctl.c              -- module IOCTL handlers
  safety.c             -- SAFETY_TOKEN validation / permission checks
  extra.c              -- module-private helpers (KAPC / hooks / ...)
```

### R3 modules (27 CLI subcommands)

`driver`, `hello`, `process`, `thread`, `memory`, `registry`, `file`, `module`,
`network`, `dyndata`, `callback`, `capability`, `preflight`, `safety`,
`security_audit`, `trust`, `kernel_ext`, `hwid`, `alpc`, `wsl`, `win32k`,
`authentication`, `bugcheck`, `wfp`, `mutation`, `redirect`, `actions`.

Each module registers its own subcommands; the authoritative command surface is
`myark-cli --help` and `myark-cli <module> --help` (names evolve with the code).

---

## Build System

### Entry points

```
scripts/make.bat   -- user entry (accepts hyphen and underscore forms)
scripts/build.bat  -- internal, passes MSBuild flags directly
```

### Usage

```bash
# default (full profile + Debug)
scripts\make.bat

# explicit profile
scripts\make.bat full Debug
scripts\make.bat mini Debug
scripts\make.bat core Debug
scripts\make.bat process-only Debug
scripts\make.bat safety-audit Debug

# Release
scripts\make.bat full Release
```

### Profile table (config/myark_*.h)

| Profile | Header | Modules | Purpose |
|---|---|---|---|
| `full` | `myark_full.h` | 35 | default, all functional modules |
| `core` | `myark_core.h` | 4 | core + process/thread/memory |
| `mini` | `myark_mini.h` | 2 | core + hello (mechanism smoke) |
| `process-only` | `myark_process_only.h` | 2 | core + process |
| `safety-audit` | `myark_safety_audit.h` | 7 | core + process/registry/file/kernel/safety/security_audit |

Every profile must:

1. BUILD SUCCEEDED (MSBuild)
2. 0 warnings / 0 errors
3. produce a real `driver/x64/Debug/MyArkCore.sys` (size > 0)
4. `cd client && uv run pytest tests/ -q` — all passing

### MSBuild prerequisites

| Tool | Path |
|---|---|
| Visual Studio (Insiders) | `C:\Program Files\Microsoft Visual Studio\18\Insiders` |
| MSBuild | `...\18\Insiders\MSBuild\Current\Bin\MSBuild.exe` |
| WDK | `C:\Program Files (x86)\Windows Kits\10\10.0.28000.0` (must be ≥ 28000) |

---

## Run Manual

> ⚠️ **Never load the driver on your host machine.** Always inside an isolated,
> snapshot-protected Windows VM.

### 1. Enable testsigning in the VM

```powershell
# inside the VM
bcdedit /set testsigning on
Restart-Computer
bcdedit /enum | Select-String "testsigning"
# expect: testsigning             Yes
```

### 2. Copy MyArkCore.sys into the VM

Build output on the host: `driver/x64/Debug/MyArkCore.sys` (or Release).

### 3. Install the driver

```powershell
# inside the VM (admin PowerShell)
.\scripts\install_vm.ps1 -DriverPath C:\MyArkCore.sys
```

The script detects the testsigning state, then `sc stop/delete/create/start`
`MyArkCore` and verifies `sc query MyArkCore` reports `RUNNING`.

### 4. Verify

```powershell
# inside the VM (admin PowerShell -- device SDDL only allows SYSTEM/Administrators)
myark-cli driver check
myark-cli driver version
myark-cli driver modules
myark-cli driver capabilities

myark-cli process enum
myark-cli thread enum
myark-cli memory query --pid 4 --addr 0xfffff801abcdef00
```

> A non-elevated process opening the device gets `ERROR_ACCESS_DENIED`; the
> CLI/UI will prompt to "run as Administrator". The offset-dependent
> `process`/`thread` driver modules load only on Win11 24H2/25H2
> (build 26100–26299); on other builds they are absent by design.

### 5. Uninstall

```powershell
.\scripts\uninstall_vm.ps1
```

Stops/deletes the service and cleans the `HKLM\...\Services\MyArkCore\Modules`
subkey.

### 6. GUI

```bash
cd client
uv sync
uv run myark-ui
```

- Three panes: entity list (filter/pinyin) / module detail tabs / sidebar
  (Modules, Search, Hex, Log)
- `Ctrl+P` command palette; `Ctrl+Shift+F` advanced search; `F5` refresh
- `F1` help; `Ctrl+Tab` cycle popups; `Ctrl+W` close top popup

S9.2 popups: Detail, Compare, Filter builder, Action history (`~/.myark/history.log`,
JSON lines recorded after every mutating action).

---

## CLI Manual

`myark-cli` is the argparse entry with 27 sub-modules:

```
$ myark-cli --help
usage: myark-cli [-h]
                 {driver,actions,alpc,authentication,bugcheck,callback,capability,dyndata,file,hello,hwid,kernel_ext,memory,module,mutation,network,preflight,process,redirect,registry,safety,security_audit,thread,trust,wfp,win32k,wsl} ...
```

> ⚠️ The examples below illustrate common usage; individual subcommand/flag
> names evolve with the code — `myark-cli <module> --help` is authoritative.

```
myark-cli process enum
myark-cli process detail 1234
myark-cli network tcp-list
myark-cli dyndata query handle --pid 1234
myark-cli callback ps
myark-cli security_audit defender

# mutating actions (SAFETY_TOKEN gated; the token is attached by the R3 client)
myark-cli actions kill --pid 1234                  # R3 preferred
myark-cli actions set-token --pid 1234             # R0 only
```

Output is a compact table for most subcommands; a few driver subcommands emit
JSON. Check `<module> --help` for the real flags.

---

## Testing

### R3 (pytest)

```bash
cd client
uv sync
uv run pytest tests/ -q
# expect: 831 passed, 7 skipped, 2 warnings in ~12s
```

Categories: per-module protocol pack/unpack, client behavior, static IOCTL
verification (`verify_*.py`), UI tests (`test_ui_*.py`).

### Driver (static)

No runtime unit tests; driver quality is enforced by:

1. **MSBuild 0 warnings / 0 errors** (mandatory)
2. **`scripts/verify_core.py`** static analysis
3. **5-profile build matrix** (`full / core / mini / process_only / safety_audit`)
4. **On-target regression**: `verify_core.py` runs inside the test VM and asserts
   per-module behavior end-to-end (see `KNOWN_ISSUES.md` for the current matrix).

---

## Contributing

Hard rules (see [CONTRIBUTING.md](CONTRIBUTING.md) — Chinese):

1. **1 commit = 1 task**, title and description both in the commit message
2. No "done" summary words in commit messages
3. Implementation order: ① pure R3 → ② R0 read + R3 display → ③ R0-only → ④ hybrid
4. Frozen contracts (`driver_entry.c`, `ioctl_dispatch.c`,
   the `shared/driver/MyArk*.h` protocol headers) require a dedicated issue first
5. New IOCTL ⇒ at least 3 pytest cases (empty request, full request, error path)
6. Never commit machine-specific absolute paths or credentials

Module addition flow: create `driver/src/modules/<NN>_<name>/` (descriptor +
ioctl + safety), wire into `MyArkCore.vcxproj.filters`, add
`#define MYARK_MODULE_<NAME> 1` to the profile header, add the R3 protocol +
client module + tests, run the build matrix + pytest.

---

## Documentation

Deep-dive documents are currently **Chinese-only**:

| File | Purpose |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | R0/R3 architecture, IOCTL protocol, module lifecycle |
| [CONTRIBUTING.md](CONTRIBUTING.md) | dev rules, commit template, module addition flow |
| [CHANGELOG.md](CHANGELOG.md) | full S1–S10 changelog |
| [RELEASE.md](RELEASE.md) | v1.0.0 release checklist |
| [KNOWN_ISSUES.md](KNOWN_ISSUES.md) | known issues / limits / compatibility / security |
| [docs/ROADMAP.md](docs/ROADMAP.md) | roadmap (R1–R3 hardening phases) |
| [LICENSE](LICENSE) | MIT License |

Module sample outputs live in `screenshots/` (text format).

---

## Release

v1.0.0 (2026-08-26) was the first release tag; the project is now in the
R-series hardening phases (see `docs/ROADMAP.md`). Key v1.0.0 metrics:

| Metric | Value |
|---|---|
| IOCTLs (protocol definitions) | 112 (127 incl. reserved surface) |
| pytest cases | 657 (at v1.0.0), 831 (current) |
| Driver modules (R0) | 35 |
| R3 modules | 26 + 5 (8 builtin + 18 in-tree) |
| Build profiles | 5 (full / core / mini / process_only / safety_audit) |
| .sys size (full Debug) | 150,016 bytes |
| .sys size (mini Debug) | 31,232 bytes |
| R3 memory (ui / cli) | ~40 MB / ~20 MB |
| License | MIT (independent) |

Deployment discipline unchanged: one .sys, macro-gated modules, runtime
start/stop via registry, Tkinter-only UI.

Known-issue highlights: test-signed only (no WHQL), Win11 24H2 quirks, see
[KNOWN_ISSUES.md](KNOWN_ISSUES.md).

---

## License

MIT — see [LICENSE](LICENSE). MyArk is an independent implementation; it
borrows no code from other projects.

## Status

After the v1.0.0 tag the project entered the S11.1 security/defect-fix phase
(client raw-IOCTL API breakage, driver WRITE_VM null-pointer, EPROCESS reference
imbalance, missing device symlink, SDDL/physical-memory/token gating — all fixed,
see CHANGELOG) and then the R-series hardening roadmap
([docs/ROADMAP.md](docs/ROADMAP.md)): offset-dehardcoding (Tier B runtime
discovery / Tier C pinned profiles), DKOM/timer/WFP/network inventories, HWID
device-identifier classes, and an on-target regression matrix (1903 + 23H2 green).
