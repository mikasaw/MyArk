# MyArk

**中文** | [English](README.en.md)

自研 Windows ARK(Anti-Rootkit)工具,KMDF 单 .sys + 模块化宏门控 + Python R3 UI/CLI。

> ## ⚠️ 免责声明 / Disclaimer
>
> 本项目是面向**授权测试环境**的 Windows 内核安全研究工具，用于学习 Windows
> 内核机制与在自有系统上自查安全状况。
>
> - 仅限在你**拥有或已获得明确书面授权**的隔离测试环境中使用，不得用于任何未授权的第三方系统；
> - 内核驱动的加载与调用存在**蓝屏与系统不稳定风险**，请始终在快照保护的虚拟机内测试；
> - 本项目**不提供也不集成**任何恶意载荷、免杀/加壳、检测规避或攻击性武器化能力；全部变更型 IOCTL 受 SAFETY_TOKEN + EVAL_GATE 门控，仅授权账户可打开设备；
> - 软件按 "AS IS" 提供（见 [LICENSE](LICENSE)），作者不对任何滥用行为或由此造成的损害承担责任。
>
> This project is a Windows kernel security research tool **for authorized test
> environments only**: use it solely in isolated VMs you own or are explicitly
> authorized to test. Kernel drivers can crash the OS — test inside snapshot-protected
> VMs. MyArk ships no malware payload, no packer/evasion or weaponization capability;
> all mutating IOCTLs are gated by SAFETY_TOKEN + EVAL_GATE. Provided "AS IS" under
> [LICENSE](LICENSE) with no liability for misuse.

- 单个 `MyArkCore.sys` (KMDF,非 PnP Control Device)
- 118 个 IOCTL 协议定义 (注册分发面约 96),覆盖四象限(纯 R3 / R0 读 + R3 展示 / 必须 R0 / 混合)
- 31 个驱动模块,编译期 `#if MYARK_MODULE_<NAME>` 宏门控,运行时通过注册表 `Modules\<Name>=0/1` 启停
- R3 Python 3.14 + Tkinter UI / argparse CLI
- 三层搜索:左栏过滤 + Ctrl+P 命令面板 + 侧栏高级搜索 (8 scope + 3 mode),中文/拼音支持 (pypinyin)
- 多窗口增强:详情 / 比较 / 过滤构造 / 操作历史 浮窗 (S9.2)
- 安全模型:设备 SDDL 仅 SYSTEM/Administrators 可打开;变更型 IOCTL (87_actions + 10_process 变更面) 需 per-boot 会话密钥的 HMAC-SHA256 安全令牌 (+/-120s 防重放);物理内存读写限定 RAM 区间,写路径注册表显式开启
- 831 个 pytest 用例全 PASS (7 skipped)

---

## 目录

- [项目背景](#项目背景)
- [架构概览](#架构概览)
- [模块列表](#模块列表)
- [构建系统](#构建系统)
- [运行手册](#运行手册)
- [命令行手册](#命令行手册)
- [测试](#测试)
- [贡献指南](#贡献指南)
- [文档](#文档)

---

## 项目背景

Windows ARK(Anti-Rootkit)工具用于检测 / 排查内核态 rootkit、隐藏进程、DKOM 篡改、未签名驱动、安全配置缺陷等深层系统问题。

商业 ARK (PCHunter / WinArk / XueTr) 闭源、二次开发困难,且多数不支持新内核 (Win11 24H2+)。

**MyArk 目标**:

| 维度 | 做法 |
|---|---|
| 部署 | 单一 `MyArkCore.sys` (KMDF 非 PnP Control Device),不做插件 DLL,不做多 .sys |
| 模块化 | 每个模块独立 `.c` / `.h` + 描述符,`#if MYARK_MODULE_<NAME>` 宏门控 |
| 启停 | 编译期硬切 (`config/myark_*.h`) + 运行时软切 (`HKLM\...\Modules\<Name>=0/1`) |
| R3 | Python 3.14 + Tkinter,主从三栏 + 浮动窗口多任务 |
| 测试 | pytest 657 用例,R3 协议 + 客户端 + 静态 IOCTL 验证 + 8 UI 弹窗 (S9.2) |
| 文档 | 中文为主,英文代码标识符,六段式长描述 / 3 段式 commit |

**进度**: S1-S8 done,S9.1 UI 集成,S9.2 多窗口增强,S10.1 收尾。

---

## 架构概览

### R0 驱动框图

```
+---------------------------------------------------------------+
|                     MyArkCore.sys (KMDF)                       |
+---------------------------------------------------------------+
|                                                               |
|  DriverEntry  --> WdfDriverCreate  --> DeviceInit (non-PnP)    |
|                                                               |
|  +-- framework/ -------------------------------------------+ |
|  |   driver_entry.c       -- DriverEntry / DriverUnload     | |
|  |   device_control.c     -- IRP_MJ_DEVICE_CONTROL 入口     | |
|  |   io_queue.c           -- WDFQUEUE 并行串行策略          | |
|  +---------------------------------------------------------+ |
|                                                               |
|  +-- dispatch/ ---------------------------------------------+ |
|  |   ioctl_dispatch.c     -- IOCTL 表查找                  | |
|  |   ioctl_registry.c     -- 模块描述符注册表               | |
|  |   core_ioctl_handlers.c -- 核心 5 IOCTL                 | |
|  |   ioctl_validation.c   -- SAFETY_TOKEN / 长度校验       | |
|  |   ioctl_helpers.h      -- 输入/输出缓冲宏                | |
|  +---------------------------------------------------------+ |
|                                                               |
|  +-- modules/ (31 functional + 2 smoke) -------------------+ |
|  |   00_hello             -- 机制烟测                       | |
|  |   10_process           -- 进程枚举 (R3 优先 + R0 备用)  | |
|  |   11_thread            -- 线程枚举                       | |
|  |   12_memory            -- 虚拟地址翻译 / 任意读          | |
|  |   20_handle            -- 句柄表枚举                     | |
|  |   21_section           -- Section 对象枚举               | |
|  |   22_kmod              -- 内核模块枚举                   | |
|  |   23_storage           -- 磁盘卷枚举                     | |
|  |   24_device_audit      -- 设备栈审计                     | |
|  |   25_kernel            -- 内核信息查询                   | |
|  |   30_keyboard          -- 键盘过滤驱动审计               | |
|  |   31_debug_output      -- DebugPrint 捕获                | |
|  |   70_dyndata           -- NtQuerySystemInformation 风格  | |
|  |   71_callback          -- Ps/Cm/Ob/Image/Dbg 回调枚举    | |
|  |   72_wfp               -- WFP callout 枚举               | |
|  |   73_mutation          -- EPROCESS Token 篡改检测         | |
|  |   74_redirect          -- CmCallback / IoCallDriver 检测 | |
|  |   75_hwid              -- MajorFunction 检查              | |
|  |   76_bugcheck          -- 最后一次 BugCheck 帧缓冲       | |
|  |   77_win32k            -- GUI 线程 / 钩子枚举            | |
|  |   78_wsl               -- WSL Silo 枚举                  | |
|  |   79_alpc              -- ALPC 端口枚举                  | |
|  |   80_authentication    -- Authenticode 签名              | |
|  |   81_trust             -- PE / 目录签名                  | |
|  |   82_preflight         -- 环境健康检查                   | |
|  |   83_security_audit    -- Defender / Secure Boot 审计   | |
|  |   84_capability        -- 驱动自报能力                   | |
|  |   85_kernel_ext        -- Win11 25H2 信息类扩展          | |
|  |   86_safety            -- 6 步门控评估器                 | |
|  |   87_actions           -- 7 mixed R0+R3 actions          | |
|  +---------------------------------------------------------+ |
|                                                               |
+---------------------------------------------------------------+
                                |
                                |  DeviceIoControl (kernel handle)
                                v
+---------------------------------------------------------------+
|                     R3 (Python 3.14)                          |
+---------------------------------------------------------------+
|                                                               |
|  +-- client/ ----------------------------------------------+  |
|  |  ark_client.py        -- IOCTL 打包 / 解包              |  |
|  |  transport.py         -- CreateFile / DeviceIoControl    |  |
|  |  driver_check.py      -- 探测驱动存在 / 版本            |  |
|  |  module_query.py      -- 模块列表 / capabilities 查询   |  |
|  +---------------------------------------------------------+  |
|                                                               |
|  +-- protocol/ --------------------------------------------+  |
|  |  <每个模块> _protocol.py -- ctypes 结构 + 序列化       |  |
|  +---------------------------------------------------------+  |
|                                                               |
|  +-- modules/ (26 + 5) ------------------------------------+  |
|  |  8 builtin + 18 in-tree                                  |  |
|  |  hello / process / thread / memory / registry / file    |  |
|  |  network / module / dyndata / callback / ...            |  |
|  +---------------------------------------------------------+  |
|                                                               |
|  +-- cli/main.py -- argparse 入口 (myark-cli) -------------+  |
|  +-- ui/main_window.py -- Tkinter 主窗口 (myark-ui) -------+  |
|                                                               |
+---------------------------------------------------------------+
```

### R3 框图 (CLI + UI)

```
+-----------------------------+        +-----------------------------+
|       myark-cli (CLI)       |        |        myark-ui (GUI)        |
+-----------------------------+        +-----------------------------+
| argparse subparsers         |        | Tkinter 主从三栏            |
|  27 个 sub-modules          |        |  左 = 实体列表 + 过滤      |
|  driver + 26 modules        |        |  中 = 详情 Tab             |
|                             |        |  右 = 侧栏 (Modules/...)   |
|                             |        |  + 浮动窗口多任务         |
|  --help / 子命令 --help     |        |  Ctrl+P 命令面板          |
|  JSON / Table 输出          |        |  Ctrl+Shift+F 高级搜索    |
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

### R0/R3 通信流程

```
R3 进程                                  R0 驱动
--------                              --------
ArkClient.call(ioctl_id, req, resp):
  1. ctypes 结构打包请求
  2. CreateFile("\\\\.\\MyArkCore")
  3. DeviceIoControl(
       h, ioctl_id,
       input_buf,  in_size,
       output_buf, out_size,
       &bytes_ret, NULL)
                |
                |    kernel handle
                v
                          IRP_MJ_DEVICE_CONTROL
                                    |
                                    v
                          WdfRequestGetInputBuffer / Output
                                    |
                                    v
                          ioctl_dispatch.c:MyArkDispatchIoctl
                                    |
                            1. SAFETY_TOKEN 校验
                            2. 输入长度 vs 注册表 expected_in
                            3. 输出长度 vs 注册表 expected_out
                                    |
                                    v
                          ioctl_registry.c:找到描述符
                                    |
                                    v
                          <module>_ioctl.c:ModuleHandler
                                    |
                                    v
                          RtlCopyMemory(output_buf, response, ...)
                                    |
                                    v
                          WdfRequestComplete with STATUS_SUCCESS
                ^
                |
                4. DeviceIoControl 返回 STATUS_SUCCESS
                5. resp.unpack(output_buf)
                6. return ModuleResponse.ok(data)
```

### 四象限

| 象限 | 含义 | MyArk 做法 |
|---|---|---|
| ① | R3 纯用户态 | winreg / IP Helper / PSAPI / WTS / EnumProcesses |
| ② | R0 读 + R3 展示 | 内核读 buffer,R3 格式化表格 |
| ③ | 必须 R0 | MmCopyVirtualMemory / ObReferenceObjectByPointer |
| ④ | 混合 | kill / inject / dump R3 优先,R0 备用 |

四象限是模块的立项与实施顺序原则（见 [CONTRIBUTING.md](CONTRIBUTING.md)）；驱动侧由模块描述符（`shared/driver/MyArkPluginApi.h` 的 `MYARK_MODULE_DESCRIPTOR`）与各模块的静态 IOCTL 表（`MYARK_IOCTL_ENTRY`）装配，描述符本身不携带象限字段。

---

## 模块列表

### 驱动模块 (30 个)

| ID | 模块 | 类型 | 简称 |
|---|---|---|---|
| core | CORE | 核心 | 5 IOCTL + 描述符注册 + SAFETY_TOKEN |
| 00 | hello | 烟测 | `MyArkIoctlHello` 返回固定字符串 |
| 10 | process | 进程 | 枚举 + 详情 + 线程 + token |
| 11 | thread | 线程 | 枚举 + 详情 |
| 12 | memory | 内存 | R3 read/write/query + R0 translate/scan |
| 20 | handle | 句柄 | 句柄表枚举 |
| 21 | section | Section | Section 对象枚举 |
| 22 | kmod | 内核模块 | PsLoadedModuleList 遍历 |
| 23 | storage | 存储 | 卷枚举 |
| 24 | device_audit | 设备审计 | 设备栈审计 |
| 25 | kernel | 内核 | 内核信息查询 |
| 30 | keyboard | 键盘 | 键盘过滤驱动审计 |
| 31 | debug_output | DebugPrint | DebugPrint 捕获 |
| 70 | dyndata | NtQuery 风格 | 系统信息综合查询 |
| 71 | callback | 回调 | Ps/Cm/Ob/Image/Dbg 回调枚举 |
| 72 | wfp | WFP | WFP callout 枚举 |
| 73 | mutation | DKOM | EPROCESS Token 篡改检测 |
| 74 | redirect | 重定向 | CmCallback / IoCallDriver 检测 |
| 75 | hwid | HWID | MajorFunction 检查 |
| 76 | bugcheck | BugCheck | 最后一次 BugCheck + 帧缓冲 |
| 77 | win32k | GUI | GUI 线程 / 钩子枚举 |
| 78 | wsl | WSL | WSL Silo 枚举 |
| 79 | alpc | ALPC | ALPC 端口枚举 |
| 80 | authentication | 认证 | Authenticode 签名 |
| 81 | trust | 信任 | PE / 目录签名 |
| 82 | preflight | 预检 | 环境健康检查 |
| 83 | security_audit | 安全审计 | Defender / Secure Boot / Trusted Boot |
| 84 | capability | 能力 | 驱动自报能力 |
| 85 | kernel_ext | 内核扩展 | Win11 25H2 信息类扩展 |
| 86 | safety | 安全 | 6 步门控评估器 |
| 87 | actions | 行为 | 7 mixed R0+R3 actions |

每个模块组成:

```
modules/<NN>_<name>/
  descriptor.h         -- MYARK_MODULE_<NAME>_DESCRIPTOR 声明
  descriptor.c         -- descriptor 实例化与注册
  ioctl.h              -- 输入/输出结构 + IOCTL id 声明
  ioctl.c              -- 模块 IOCTL 处理函数
  safety.c             -- SAFETY_TOKEN 校验 / 权限检查
  extra.c              -- 模块私有辅助 (KAPC / 钩子 等)
```

### R3 模块 (27 个 CLI 子命令)

> 子命令名以 `myark-cli <module> --help` 实际输出为准——下表为立项规划面，可能滞后于代码。

| 名称 | 来源 | 主要子命令 |
|---|---|---|
| `driver` | builtin | `check / version / modules / capabilities` |
| `hello` | builtin | `ping` |
| `process` | builtin | `enum / detail / threads / terminate / suspend / inject` |
| `thread` | builtin | `enum / detail / suspend / resume` |
| `memory` | builtin | `read / write / query / scan / translate` |
| `registry` | builtin | `list / get / set / delete / watch` |
| `file` | builtin | `info / read / write / sd` |
| `module` | builtin | `enum / info` |
| `network` | builtin | `tcp-list / udp-list / connections` |
| `dyndata` | builtin | `system-info / handles / processes` |
| `callback` | builtin | `enum / info` |
| `capability` | builtin | `list / info` |
| `preflight` | builtin | `check / list` |
| `safety` | builtin | `evaluate / gate` |
| `security_audit` | builtin | `defender / secureboot / trustedboot` |
| `trust` | builtin | `verify / catalog` |
| `kernel_ext` | builtin | `info-classes / queries` |
| `hwid` | builtin | `enumerate-mj / info` |
| `alpc` | builtin | `enum-ports` |
| `wsl` | builtin | `enum-silos` |
| `win32k` | builtin | `enum-threads / enum-hooks` |
| `authentication` | builtin | `verify` |
| `bugcheck` | builtin | `last / framebuffer` |
| `wfp` | builtin | `enum-callouts` |
| `mutation` | builtin | `eprocess-token / dk` |
| `redirect` | builtin | `cmcallback / iocalldriver` |
| `actions` | builtin | `kill / terminate / inject / dump / set-token / hide-process / protect-process` |

---

## 构建系统

### 入口

```
scripts/make.bat   -- 用户入口 (接受 hyphen 与 underscore 形式)
scripts/build.bat  -- 内部调用,直接传 MSBuild 标志
```

### 用法

```bash
# 默认 (full profile + Debug)
scripts\make.bat

# 显式 profile
scripts\make.bat full Debug
scripts\make.bat mini Debug
scripts\make.bat core Debug
scripts\make.bat process-only Debug
scripts\make.bat safety-audit Debug

# Release
scripts\make.bat full Release
```

### Profile 表 (config/myark_*.h)

| Profile | Header | 模块数 | 用途 |
|---|---|---|---|
| `full` | `myark_full.h` | 35 | 默认,所有功能模块 |
| `core` | `myark_core.h` | 4 | core + process/thread/memory (基础三件套) |
| `mini` | `myark_mini.h` | 2 | core + hello (机制烟测) |
| `process-only` | `myark_process_only.h` | 2 | core + process (S6.1 基础) |
| `safety-audit` | `myark_safety_audit.h` | 7 | core + process/registry/file/kernel/safety/security_audit |

### 完整构建矩阵

```bash
scripts\make.bat full Debug
scripts\make.bat core Debug
scripts\make.bat mini Debug
scripts\make.bat process_only Debug
scripts\make.bat safety_audit Debug
```

每个 profile 都应:

1. BUILD SUCCEEDED (MSBuild)
2. 0 warning / 0 error
3. `driver/x64/Debug/MyArkCore.sys` 真实生成 (size > 0)
4. `cd client && uv run pytest tests/ -q` 全 PASS

### MSBuild 前置

| 工具 | 路径 |
|---|---|
| VS Insiders | `C:\Program Files\Microsoft Visual Studio\18\Insiders` |
| MSBuild | `C:\Program Files\Microsoft Visual Studio\18\Insiders\MSBuild\Current\Bin\MSBuild.exe` |
| WDK | `C:\Program Files (x86)\Windows Kits\10\10.0.28000.0` (必须 ≥ 28000) |

---

## 运行手册

### 1. 在 VM 中启用 testsigning

⚠️ 驱动加载 **绝不** 在主机上做。始终在 Hyper-V Gen2 guest 内,且 VM 已 `bcdedit /set testsigning on` + reboot。

```powershell
# 在 VM 内执行
bcdedit /set testsigning on
Restart-Computer
bcdedit /enum | Select-String "testsigning"
# 期望: testsigning             Yes
```

### 2. 拷贝 MyArkCore.sys 到 VM

构建产物在 host 上:`driver/x64/Debug/MyArkCore.sys` 或 `driver/x64/Release/MyArkCore.sys`。

```powershell
# PowerShell (host)
Copy-Item driver\x64\Debug\MyArkCore.sys -Destination \\vm-host\C$\MyArkCore.sys
```

或在 VM 上共享主机路径。

### 3. 安装驱动

```powershell
# 在 VM 内执行 (管理员 PowerShell)
.\scripts\install_vm.ps1 -DriverPath C:\MyArkCore.sys
```

`install_vm.ps1` 会自动:

- 检测 testsigning 状态
- `sc stop MyArkCore` (若已注册)
- `sc delete MyArkCore`
- `sc create MyArkCore type= kernel binPath= C:\MyArkCore.sys`
- `sc start MyArkCore`
- 验证 `sc query MyArkCore` 状态 = `RUNNING`

### 4. 验证

```powershell
# 在 VM 内 (管理员 PowerShell -- 设备 SDDL 仅 SYSTEM/Administrators 可打开)
myark-cli driver check
myark-cli driver version
myark-cli driver modules
myark-cli driver capabilities

myark-cli process enum
myark-cli thread enum
myark-cli memory query --pid 4 --addr 0xfffff801abcdef00
```

> 非 elevated 进程打开设备会得到 `ERROR_ACCESS_DENIED`,CLI/UI 会提示
> "run as Administrator"。process/thread 模块 (偏移型枚举) 仅在
> Win11 24H2/25H2 (build 26100-26299) 上加载,其他 build 自动缺席。

### 5. 卸载驱动

```powershell
# 在 VM 内执行 (管理员 PowerShell)
.\scripts\uninstall_vm.ps1
```

`uninstall_vm.ps1` 会自动:

- `sc stop MyArkCore`
- `sc delete MyArkCore`
- 清理 `HKLM\...\Services\MyArkCore\Modules` 子项
- 验证 `sc query MyArkCore` 返回空

### 6. GUI 启动 (UI 模式)

```bash
# 安装 R3 (host 或 VM 均可,只需 Python 3.14)
cd client
uv sync
uv run myark-ui

# 三栏布局
#   左: 实体列表 (过滤 / 拼音)
#   中: 当前模块 Tab
#   右: 侧栏 (Modules 列表 / Search / Hex / Log)
# Ctrl+P: 命令面板
# Ctrl+Shift+F: 高级搜索
# F1: 帮助窗 / Ctrl+Tab 循环切浮窗 / Ctrl+W 关浮窗
```

#### 6.1 S9.2 多窗口增强

S9.2 在 S9.1 三栏 + 三层搜索的基础上,加了 4 个浮出弹窗和 4 个全局快捷键,
全部纯 UI / 纯 R3,不需要驱动。

| 弹窗 | 入口 | 作用 |
|---|---|---|
| Detail (详情) | 选中模块行 → View → Detail / `F1` | 单条实体的完整 key-value 表,鼠标位置浮出 |
| Compare (比较) | View → Compare / DiffWindow | 两个实体的 side-by-side diff,按 kind 输出语义化摘要 |
| Filter builder (过滤构造) | View → Filter / Ctrl+Shift+F | name regex + size 范围 + year 范围 + 3 权限复选框,Apply 合并到侧栏 advanced filter |
| History (操作历史) | View → Action history / Ctrl+Shift+H | 读 `~/.myark/history.log`,显示最近 N 条 kill/terminate/read/write 记录 |
| Help (帮助) | Driver → Help / F1 | 快捷键 + 弹窗速查 |

全局快捷键 (来自 `myark/ui/keybindings.py`):

| 键 | 行为 |
|---|---|
| `F1` | 打开 Help 弹窗 / 当前选中行无 Detail 入口时显示 help |
| `F5` | 刷新当前模块 Tab (S9.1 已有,S9.2 接入统一 keybindings 模块) |
| `Ctrl+Tab` | 在打开的浮窗之间循环焦点 (Shift 翻转) |
| `Ctrl+W` | 关闭最上层浮窗;主窗按 Ctrl+W 是 no-op,避免误关 |
| `Ctrl+Shift+H` | 打开 Action history 浮窗 |

`Ctrl+P` (命令面板) / `Ctrl+Shift+F` (高级搜索) / `F5` (刷新) 是 S9.1 已经存在
的快捷键,S9.2 把 `F1` / `Ctrl+Tab` / `Ctrl+W` 也接到主窗。

所有弹窗通过 `PopupStack` 注册到主窗,`Ctrl+Tab` 自动取栈顶并 `focus_force + lift`,
`Ctrl+W` 直接 `destroy()` 栈顶 (没有弹窗时主窗不响应,避免误操作)。

#### 6.2 操作历史 (`~/.myark/history.log`)

S9.2 引入 `myark.history` 模块,以 JSON 单行追加格式写入 `~/.myark/history.log`:

```json
{"ts": 1700000123.456789, "action": "kill", "target": "pid=1234",
 "result": "ok", "detail": "reason=test"}
```

`actions` CLI 子命令在每次执行结束后自动调 `history.record()` 写一条;
UI 弹窗 (`HistoryWindow`) 读取该文件并显示在 ttk.Treeview 中 (when/action/target/result/detail)。

测试通过 `set_history_path()` 切到 tempfile,不污染真实 `~/.myark/`。

---

## 命令行手册

`myark-cli` 是 argparse 入口,27 个 sub-modules。完整列表由 `myark-cli --help` 生成:

> ⚠️ 下文示例为常用面示意,个别子命令/参数名可能随版本演进——以 `myark-cli <module> --help` 实际输出为准。

```
$ myark-cli --help
usage: myark-cli [-h]
                 {driver,actions,alpc,authentication,bugcheck,callback,capability,dyndata,file,hello,hwid,kernel_ext,memory,module,mutation,network,preflight,process,redirect,registry,safety,security_audit,thread,trust,wfp,win32k,wsl} ...
```

### driver -- 驱动交互

```
myark-cli driver check          # 探测驱动是否安装
myark-cli driver version        # 打印 MYARK_CORE_VERSION_OUTPUT
myark-cli driver modules        # 列出注册的驱动模块
myark-cli driver capabilities   # 列出 IOCTL capabilities
```

### process -- 进程

```
myark-cli process enum          # 枚举进程 (R3 PSAPI 优先)
myark-cli process detail --pid 1234
myark-cli process threads --pid 1234
myark-cli process terminate --pid 1234    # R3 优先 + R0 备用
myark-cli process suspend --pid 1234
myark-cli process inject --pid 1234 --dll path
```

### thread -- 线程

```
myark-cli thread enum
myark-cli thread detail --tid 5678
myark-cli thread suspend --tid 5678
myark-cli thread resume --tid 5678
```

### memory -- 内存

```
myark-cli memory read --pid 1234 --addr 0x0000012345678900 --size 16
myark-cli memory write --pid 1234 --addr 0x0000012345678900 --bytes "..."
myark-cli memory query --pid 1234 --info-class 1
myark-cli memory scan --pid 1234 --pattern "..."
myark-cli memory translate --pid 1234 --addr 0x0000012345678900    # R0 only
```

### registry -- 注册表

```
myark-cli registry list HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
myark-cli registry get HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion /v ProductName
myark-cli registry set HKLM\...\Key /v Value --data "..."
myark-cli registry delete HKLM\...\Key /v Value
myark-cli registry watch HKLM\...\Key
```

### file -- 文件

```
myark-cli file info C:\Windows\System32\notepad.exe
myark-cli file read --path C:\file.bin --offset 0 --size 256
myark-cli file write --path C:\file.bin --offset 0 --bytes "..."
myark-cli file sd --path C:\file.bin      # 安全描述符
```

### module -- 模块 (R3 PSAPI)

```
myark-cli module enum --pid 1234
myark-cli module info --pid 1234 --name kernel32.dll
```

### network -- 网络 (R3 IP Helper)

```
myark-cli network tcp-list
myark-cli network udp-list
myark-cli network connections
```

### dyndata -- NtQuery 风格 (R0)

```
myark-cli dyndata system-info
myark-cli dyndata handles --pid 1234
myark-cli dyndata processes
```

### callback -- 回调枚举 (R0)

```
myark-cli callback enum
myark-cli callback info --type ps
```

### capability -- 驱动能力 (R0)

```
myark-cli capability list
myark-cli capability info --ioctl 0x800
```

### preflight -- 环境健康检查

```
myark-cli preflight check
myark-cli preflight list
```

### safety -- 6 步门控评估

```
myark-cli safety evaluate --pid 1234
myark-cli safety gate --action kill --pid 1234
```

### security_audit -- 安全审计

```
myark-cli security-audit defender
myark-cli security-audit secureboot
myark-cli security-audit trustedboot
```

### trust -- PE / 目录签名验证

```
myark-cli trust verify --path C:\drivers\foo.sys
myark-cli trust catalog --path C:\drivers\foo.sys
```

### kernel_ext -- Win11 25H2 信息类扩展

```
myark-cli kernel_ext info-classes
myark-cli kernel_ext queries
```

### actions -- 7 mixed R0+R3 actions

```
myark-cli actions kill --pid 1234                  # R3 优先
myark-cli actions terminate --pid 1234             # R3 优先
myark-cli actions inject --pid 1234 --dll path     # R3 优先
myark-cli actions dump --pid 1234 --output file    # R3 优先
myark-cli actions set-token --pid 1234 --token ... # R0 only
myark-cli actions hide-process --pid 1234          # R0 only
myark-cli actions protect-process --pid 1234       # R0 only
```

### 其它 R0-only / stub 模块

`alpc` / `wsl` / `win32k` / `authentication` / `bugcheck` / `wfp` / `mutation` / `redirect` / `hwid` 大多为 S7.3 的 stub 实现,枚举路径打 `R0 only`。
`hello` 是机制烟测,`myark-cli hello ping`。

### 输出格式

大部分 subcommand 默认输出简洁表格;具体参数与个别 JSON 输出以 `--help` 为准:

```
$ myark-cli process enum
PID     Name                 Session    User             Path
1234    explorer.exe         1          DOMAIN\alice      C:\Windows\explorer.exe
...
```

---

## 测试

### R3 测试 (pytest 831 用例)

```bash
cd client
uv sync
uv run pytest tests/ -q
# 期望: 831 passed, 7 skipped, 2 warnings in ~12s
```

### 测试分类

```
client/tests/
  test_core_ioctl.py            -- 核心 5 IOCTL 协议
  test_<module>_protocol.py     -- 每模块协议打包/解包
  test_<module>_client.py       -- R3 客户端实现
  verify_*.py                   -- 静态 / Mode A 验证
  test_ui_*.py                  -- S9 UI (layout / search / safety / S9.2 弹窗)
  conftest.py                   -- 共享 Tk root (S9.2 抽出,避免 Tcl 资源耗尽)
```

### 驱动测试 (静态)

无运行时单元测试,所有驱动测试通过:

1. **MSBuild 0 warning / 0 error** (强制)
2. **`scripts/verify_core.py`** 静态分析 (`/analyze` 等价)
3. **5 profile build 矩阵** (`full / core / mini / process_only / safety_audit`)

```bash
scripts\verify_core.py
# 期望: ALL profiles PASS
```

---

## 贡献指南

### 纪律 (硬性)

1. **1 commit 1 task**: 一个 commit 只做一件事,标题与 description 都写在 commit message
2. **不写"完成"**: commit message 内不出现"完成"、"完结"、"done" 等总结词
3. **中文 3 段式**:
   ```
   feat(process): 添加 EPROCESS Token 字段读取

   角色: MyArkCppDev
   任务: S6.3 process 扩展
   改动: 在 10_process/ioctl.c 添加 MyArkIoctlProcessToken 处理器
   ```
4. **实施顺序**: ① R3 纯用户态 → ② R0 读 + R3 展示 → ③ 必须 R0 → ④ 混合
5. **不动 frozen contract**: `driver_entry.c` / `ioctl_dispatch.c` / `shared/driver/MyArk*.h` 协议头改动需单独 issue
6. **W4 WX (workspace discipline)**: 不在 working tree 留临时文件,不写绝对机器路径

### 模块新增流程

新模块加进 MyArkCore.sys:

1. 在 `driver/src/modules/<NN>_<name>/` 创建目录
2. 写 `descriptor.h` (声明) + `descriptor.c` (实例化)
3. 写 `ioctl.h` + `ioctl.c` (+ `safety.c` 若需)
4. 添加到 `MyArkCore.vcxproj.filters`
5. 添加 `#define MYARK_MODULE_<NAME> 1` 到 `config/myark_full.h`
6. 添加 R3 协议 `client/src/myark/protocol/<name>_protocol.py`
7. 添加 R3 客户端 `client/src/myark/modules/<name>/__init__.py`
8. 在 `cli/main.py` 注册 subcommand (如需 CLI 暴露)
9. 写测试 `client/tests/test_<name>_protocol.py` + `test_<name>_client.py`
10. 跑 `scripts/make.bat full Debug` + `cd client && uv run pytest tests/ -q`
11. 提交 commit

### 测试要求

- 每加 1 个新 IOCTL,至少 3 个 pytest 用例 (空请求、满请求、错误路径)
- 长描述六段式 (角色/目标/前置/任务步骤/验收/行为红线)
- commit 后立即 fresh 跑 `uv run pytest tests/ -q` 验证未回归

---

## 文档

| 文件 | 用途 |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | R0/R3 架构详解、IOCTL 协议、模块生命周期 |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 开发规范、commit message 模板、模块新增流程 |
| [CHANGELOG.md](CHANGELOG.md) | S1-S10 完整变更日志 (15KB,9 个 [版本] 段) |
| [RELEASE.md](RELEASE.md) | v1.0.0 发布 checklist (10 段 + DoD) |
| [KNOWN_ISSUES.md](KNOWN_ISSUES.md) | 已知问题 / 限制 / 兼容性 / 性能 / 安全 |
| [docs/ROADMAP.md](docs/ROADMAP.md) | 正式路线图 (Phase R1-R3) |
| [LICENSE](LICENSE) | MIT License |

### screenshots/

模块的真测输出 (文本格式) 落在 `screenshots/`:

```
screenshots/
  README.md                      # 索引
  process_enum.txt               # myark-cli process enum
  registry_list.txt              # myark-cli registry list ...
  network_tcp_list.txt           # myark-cli network tcp-list
  ...
```

---

## v1.0.0 发布 (2026-08-26)

MyArk v1.0.0 正式 release tag。S1 (KMDF 骨架) → S10.2 (收尾文档) 全阶段交付。

### 关键指标

| 指标 | 数值 | 说明 |
|---|---|---|
| 总 commit 数 | 96 | 1 commit 1 task 纪律,无合并 commit |
| 总 IOCTL 数 | 127 | 5 核心 + 13 process + 10 memory + 5 thread + 1 kernel + 5 S6.4 + 9 dyndata + 10 callback + 40 S7.3 + 7 actions + 21 misc |
| 总 pytest | 657 | 全 PASS,5 skipped (UI 不需要 root),2 warnings (pypinyin 内部) |
| 驱动模块 (R0) | 35 | 编译期 `#if MYARK_MODULE_<NAME>` 宏门控 |
| R3 模块 | 26 + 5 | 8 builtin + 18 in-tree |
| profile 数 | 5 | full / core / mini / process_only / safety_audit |
| 单 .sys 字节数 (full Debug) | 150016 | 见 `config/BUILD_MATRIX.md` |
| 单 .sys 字节数 (mini Debug) | 31232 | mini 是 full 的 21% (验证宏门控真生效) |
| R3 进程内存 (ui) | ~40 MB | 含 Tkinter + pypinyin |
| R3 进程内存 (cli) | ~20 MB | 不含 GUI |
| 驱动驻留 (R0) | ~2 MB | 5 profile 字节数 × 1.5 |
| 文档总字数 | ~90 KB | README 30KB + ARCHITECTURE 16KB + CONTRIBUTING 12KB + CHANGELOG 19KB + RELEASE 6KB + KNOWN_ISSUES 10KB |
| LICENSE | MIT | 项目独立采用 |

### 已验证场景

| 场景 | 范围 | 方式 | 结果 |
|---|---|---|---|
| 静态单元 | R3 client + protocol | `uv run pytest tests/ -q` | 657 passed, 5 skipped |
| R0 构建 | driver/x64/Debug | `scripts/make.bat <profile> Debug` × 5 | 0 warning / 0 error |
| 静态 IOCTL | 5 核心 + 5 thread + 1 kernel + 7 actions | `python scripts/verify_core.py` | 18 IOCTL 协议对齐 PASS |
| VM 实物 | Hyper-V Gen2 guest 内 | `scripts/install_vm.ps1` + verify_core.py | 59 IOCTL 端到端 (S7.1 9 + S7.2 10 + S7.3 40) PASS |
| UI smoke | Tkinter 主窗 + 4 弹窗 | `myark-ui` 启动 + View 菜单 | 70 UI pytest 全 pass + 手动弹窗确认 |
| CLI smoke | 27 模块 + driver | `myark-cli --help` + 子命令 | 烟测输出落 `screenshots/` |

### 4 大纪律 (不变)

1. **部署极简**:1 个 .sys + 1 个 INF + 1 个 sc create,无多 .sys 插件 DLL
2. **模块门控**:每个模块独立 .c/.h + 描述符,`#if MYARK_MODULE_<NAME>` 包裹
3. **运行时启停**:`HKLM\SYSTEM\CurrentControlSet\Services\MyArkCore\Modules\<Name>=0/1`
4. **UI 仅 Tkinter**:不引入 PySide / PyQt / dearpygui,主从三栏 + 浮动窗口

### 安装与运行 (1 分钟上手)

```bash
# 1. 构建 (任意 profile)
scripts\make.bat full Debug

# 2. 拷贝 .sys 到 VM 内
# (在 VM 内 Hyper-V Enhanced Session / VMware 共享文件夹 / scp)

# 3. VM 内安装 (启用 testsigning 后)
powershell -ExecutionPolicy Bypass -File scripts\install_vm.ps1
# → 自动检测 VM 环境 + testsigning 校验 + sc create + verify_core.py 烟测

# 4. UI / CLI 任选
myark-ui            # 三栏 GUI
myark-cli --help    # argparse CLI (27 模块 + driver)
```

### 已知问题摘要

详见 [KNOWN_ISSUES.md](KNOWN_ISSUES.md):

- L1 WHQL 正式签名未做 (test-signed only)
- L2-L5 4 项设计纪律 (单 .sys / Tkinter / 本地 IOCTL / Windows-only)
- B1-B4 4 个不阻塞的轻微 bug (Win11 24H2 network / 长路径 / DPI / 老 CPU SSDT)
- S1-S5 5 项安全注意点 (S3 无 per-user ACL,S4 SAFETY_TOKEN 复用为主)

### 下一阶段路线 (S11+)

- v1.0.1 patch:B2 / B3 / S5 修
- v1.1.0 minor:per-session SAFETY_TOKEN + self-integrity (S2 / S4)
- v1.2.0:per-user ACL (S3) + WHQL 流程启动 (L1)
- 工具链升级:Python 3.15 / WDK 10.0.29000 / VS 19

---

## 许可

LICENSE (MIT),见 [LICENSE](LICENSE)。

## Status

v1.0.0 发布 tag 后进入 S11.1 安全与缺陷修复阶段:客户端 raw-IOCTL API 断裂、驱动
WRITE_VM 空指针、EPROCESS 引用倒挂、设备符号链接缺失、SDDL/物理内存/安全令牌门禁
等已修 (见 CHANGELOG),831 pytest 全过,full/mini profile R0 build 0 warning /
0 error。**本批驱动改动尚未做 VM 运行时回归** (见 KNOWN_ISSUES),VM Mode A 实测
前的历史基线:96 commit,VM 内 59 IOCTL 端到端烟测全 pass。
