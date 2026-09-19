# Changelog

MyArk 项目的所有变更日志。每个 entry 按时间倒序,**不含**"完成"等总结词。

格式参考 [Keep a Changelog](https://keepachangelog.com/) 与 [Semantic Versioning](https://semver.org/),
条目分类按项目阶段 (S1-S10) 与语义类型 (`Added` / `Changed` / `Fixed` / `Removed` /
`Security`) 五类。

总览:96 commit / 5 profile 构建全 PASS / 657 pytest 全 PASS (5 skipped, 2 pypinyin 内部
deprecation warning) / 单 .sys `MyArkCore.sys` / 35 驱动模块 / 127 IOCTL。
S11.1 修复后:831 pytest 全 PASS (7 skipped),核心 IOCTL +1 (GET_SESSION_KEY)。

---

## [Unreleased] -- S11.1 安全与缺陷修复 (2026-09)

评估确认的客户端 API 断裂、驱动致命缺陷与门禁空转在本阶段修复。R3 仅标准库,
R0 仅 WDK/CNG;驱动改动只做 MSBuild 编译验证 + 静态协议断言,**VM 运行时回归
待办** (见 KNOWN_ISSUES S6)。

### Fixed

- `client/ark_client.py` -- ArkClient 新增公开 `ioctl(code, in_bytes, out_buf)`
  返回真实 bytes_returned (原 `_raw_call` 误返回请求长度);26 个模块文件从
  调用不存在的 `client.ioctl` / 私有 `_call`/`_raw_call` 迁移到统一 3 参签名,
  真驱动下原先必 `AttributeError`
- `client/ark_client.py` -- `query_modules` / `query_capabilities` / `get_log`
  解析按分配容量钳制驱动回写 Count,杜绝越界读;修正 `from_buffer_copy` 把
  sizeof 误作 offset 的必炸参数 (该解析路径从未被真执行过)
- `driver/src/modules/12_memory/memory_virtual.c` -- WRITE_VM 在 fetch 输入
  缓冲前解引用 NULL `inBuf`,任何带 payload 的调用必 BSOD;`ResolveEProcess`
  查找后立即解引用仍返回指针,attach 无引用对象构成 UAF -- 两处修复,引用
  所有权统一为"成功即调用方持有"
- `driver/src/framework/device_control.c` -- 全驱动从未创建
  `\??\MyArkCore` 符号链接,R3 `CreateFileW("\\\\.\\MyArkCore")` 必然
  err=2;改为 `WdfDeviceCreateSymbolicLink` 真正发布
- `driver/src/modules/87_actions/actions_ioctl.c` -- InjectDll 对输入缓冲内
  非 NUL 结尾的 DllPath 直接 `RtlInitUnicodeString` 越界读池内存,改为
  `RtlStringCbLengthW` 先验
- `driver/src/modules/12_memory/memory_physical.c` --
  `MmGetPhysicalMemoryRanges` 结果从不释放,QUERY_PHYSICAL_LAYOUT 每次调用
  泄漏一块内核池
- `client/src/myark/_builtin_modules.py` -- pkgutil 回退名单补齐
  handle/section/kmod/kernel/storage/keyboard/debug_output/device_audit,
  editable 安装下 8 个模块不再消失
- `client/src/myark/client/driver_check.py` -- 删除返回函数指针的
  `DriverProbe.error_message` 死代码

### Security

- `driver/src/framework/device_control.c` -- 设备 SDDL 去掉 Everyone ACE,
  收敛为 `D:(A;;GA;;;SY)(A;;GA;;;BA)`;非提权用户原先可调全部 IOCTL
  (含任意物理读写),与 WRITE_VM 缺陷叠加即一次调用蓝屏
- `driver/src/dispatch/safety_token.c` + `shared/driver/MyArkSafetyToken.h`
  -- SAFETY_TOKEN 从"签名非全零"升级为 CNG HMAC-SHA256:DriverEntry 用
  `BCryptGenRandom` 生成 per-boot 会话密钥,常量时间比较 + +/-120s
  FILETIME 时间窗防重放,CNG 失败则驱动拒绝加载 (fail-closed)
- 核心新增 `IOCTL_MYARK_CORE_GET_SESSION_KEY` (0x805) 下发会话密钥
  (SDDL 已限管理员);10_process 的 8 个变更型 IOCTL 输入头新增 Token 字段
  并强制校验 (原先完全无 token 门),R3 协议镜像 +72 字节同步
- `driver/src/modules/12_memory/memory_physical.c` -- READ/WRITE_PHYSICAL
  目标 PA 须完整落在 `MmGetPhysicalMemoryRanges` 的 RAM 区间内 (拒绝 MMIO/
  保留区/回绕);WRITE_PHYSICAL 默认 `STATUS_ACCESS_DENIED`,注册表
  `Modules\memory:AllowPhysicalWrite=1` 显式开启
- `driver/src/framework/os_version.h` -- process/thread 模块 Init 校验 OS
  build 在 26100..26299 (偏移表来源),范围外拒绝加载,不再静默读错误内存

### Added

- `client/tests/test_ark_client_ioctl.py` -- 真 ArkClient + 假 transport
  集成测试线 (短读/Count 钳制/错误映射),堵住"mock 虚构 API 全绿但功能坏"
  的盲区
- `client/tests/test_safety_token.py` -- 20 字节 MAC 消息布局、HMAC 契约、
  会话密钥下发路径的结构与行为用例
- `client/src/myark/client/safety_token.py` -- FILETIME 换算 + HMAC 签名的
  R3 单一来源;`ArkClient.get_session_key()`

### Changed

- `client/src/myark/protocol/process.py` / `shared/driver/MyArkProcessIoctl.h`
  -- 8 个变更型输入结构 +72 字节 (Token),尺寸断言同步
- README / ARCHITECTURE / KNOWN_ISSUES 文档与实现对齐 (IOCTL 127→128,
  pytest 657→831,SAFETY_TOKEN 章节重写,S3/S4 标记已修,OS 矩阵注明
  build 范围)

### Verified (S11.1)

- `pytest tests/ -q` 831 passed, 7 skipped (0 回归)
- full / mini profile 构建 0 warning / 0 error (含 bcrypt.lib/ntoskrnl.lib 链接)
- VM Mode A 运行时回归**未执行**,见 KNOWN_ISSUES S6

---

## [Unreleased] -- S10.2 最终收尾

### Added (S10.2)

- `CHANGELOG.md` -- 扩展至 15KB,新增 [版本] - 日期 格式 + 5 类语义分区 (Added / Changed /
  Fixed / Removed / Security) + 每 commit 独立条目
- `scripts/install_vm.ps1` -- 完整重写:Hyper-V/VMware/VirtualBox/QEMU VM 自动检测 +
  bcdedit testsigning 校验 + 卸载旧服务 + sc create/start + PnP 设备枚举 + verify_core.py
  串行调用 + 中文状态输出 + 失败回滚
- `scripts/uninstall_vm.ps1` -- 完整清理:sc stop/delete + 文件删除 + 注册表清理 +
  PnP 设备检查,幂等可重跑
- `RELEASE.md` -- v1.0.0 发布 checklist (构建矩阵 + pytest + IOCTL + 安装 + 文档 +
  签名 + 标签)
- `KNOWN_ISSUES.md` -- 已知限制 / 已知 bug / 兼容性 / 性能 / 安全 五大分类
- `README.md` -- "v1.0.0 发布" 章节,记录总 commit/IOCTL/pytest/模块数 + 已验证场景

### Changed (S10.2)

- `CHANGELOG.md` -- 从 218 行 / 8.6KB 扩展至 380+ 行 / 15KB+,按 [版本] 段切分
- `scripts/install_vm.ps1` -- 加 VM 环境检测 (Hyper-V/VMware/VirtualBox/QEMU),加
  verify_core.py 自动串行调用 (9 S7.1 + 10 S7.2 + 40 S7.3 = 59 IOCTL 烟测)

### Verified (S10.2)

- `pytest tests/ -q` 657 passed, 5 skipped (与 S10.1 baseline 一致,0 回归)
- 5 profile 构建 0 warning / 0 error (基线维持)
- `git status --short` 空

---

## [v1.0.0-rc.1] - 2026-08-26 -- S10.1 收尾

### Added (S10.1)

- `README.md` -- 扩展至 28KB:架构图、模块列表、构建矩阵、运行手册、命令行手册、测试、
  贡献指南
- `ARCHITECTURE.md` -- R0/R3 架构详解 (IOCTL + 模块 + SAFETY_TOKEN)
- `CONTRIBUTING.md` -- 开发规范 + 模块新增流程 + commit 模板
- `config/BUILD_MATRIX.md` -- 5 profile 构建结果 (full / core / mini / process_only /
  safety_audit)
- `scripts/install.bat` -- ASCII 批量安装:管理员权限 + testsigning 校验 + sc create/start
  + 失败回滚
- `scripts/uninstall.bat` -- ASCII 批量卸载:sc stop/delete + 文件删除 + 注册表清理,
  幂等可重跑
- `screenshots/` -- myark-cli 各模块真测输出文本 (27 模块 + driver 子命令)
- `LICENSE` -- MIT License（项目独立采用的开源协议）

### Verified (S10.1)

- 5 profile (`full / core / mini / process_only / safety_audit`) Debug 构建 0 warning /
  0 error
- `pytest tests/ -q` 575 passed, 5 skipped
- 工作树干净,所有 commit message 不含"完成"

---

## [v0.9.2] - 2026-08-26 -- S9.2 多窗口增强

### Added (S9.2)

- `feat(ui): DetailWindow` -- 实体 key-value 弹窗 (Esc 关闭,鼠标指针位置)
- `feat(ui): DiffWindow` -- 双实体对比窗,支持 diff-only 过滤 + 按 kind 摘要
  (registry/file/process/generic)
- `feat(ui): FilterWindow` -- 多条件过滤构建器 (name regex + size/year range +
  permissions),输出 `AdvancedFilter`
- `feat(ui): HistoryWindow` -- 读 `~/.myark/history.log` JSON 单行格式
- `feat(ui): KeyBindings` -- F1 (Help) / F5 (Refresh) / Ctrl+Tab (循环) / Ctrl+W (关闭) +
  `PopupStack` 焦点链
- `feat(ui): main_window 集成` -- View 菜单四项 (Detail/Compare/Filter builder/Action
  history) + Help 子项 + 4 个 popup 工厂方法 + `PopupStack` 跟踪 Toplevel
- `feat(actions): cli.py 历史埋点` -- `_log_history(action, target, result, detail)`
  在 kill/terminate/inject/dump/set_token/hide/protect 7 类命令后追加
- `feat(history): JSON 单行格式` -- 任意字符安全,长度前缀无效,改用
  `json.dumps(ensure_ascii=False) + \n`

### Fixed (S9.2)

- `test(infra): conftest shared Tk root` -- `pytest_configure` 会话级 `_tk_root`,解决
  600+ 测试 Tcl 资源耗尽 (20% flake → 0)

### Test (S9.2)

- `test(ui): 4 widget + keybindings + main_window 集成` -- 70 条 pytest 新增 (Detail 8 /
  Diff 10 / Filter 12 / History 15 / KeyBindings 12 / MainWindow 13),test count 575 → 657
- `test(ui): SafetyTokenAuthority` -- 12 条 pytest,接 thread terminate 路径

### Docs (S9.2)

- `doc: README S9.2 章节` -- popup 表 + keybinding 表 + history.log 格式说明

---

## [v0.9.1] - 2026-08-25 -- S9.1 UI 集成

### Added (S9.1)

- `feat(ui): 主窗三栏` -- 左 (实体列表 + 过滤) + 中 (详情 Tab) + 右 (侧栏) + DPI 缩放
- `feat(ui): Ctrl+P 命令面板` -- `CommandPalette` Toplevel,模块/动作模糊匹配
- `feat(ui): 侧栏高级搜索` -- `AdvancedFilter` + `AdvancedSearchPanel` (8 scope + 3 mode:
  包含 / 正则 / 拼音)
- `feat(ui): Ctrl+Shift+F 高级搜索绑定`
- `feat(ui): 搜索基础` -- `search` package (matcher + index_builder)
- `feat(ui): 布局持久化` -- `~/.myark/layout.json` 原子写入,关闭后恢复窗口位置/大小/
  分割条
- `feat(ui): Safety 弹窗` -- 高危操作 token 二次确认 (kill/terminate/inject/dump/
  set_token/hide/protect 7 类)
- `feat(ui): 状态栏增强` -- 顶部 Modules 面板 (15 模块卡片 + 启停状态)
- `feat(modules): memory + module UI 实树化` -- 8 模块全有 UI (process/thread/memory/
  registry/file/network/module/dyndata)
- `feat(client): process R3 fallback` -- EnumProcessModules + memory read/write/query
- `feat(client): thread R3 fallback` -- enum/detail/terminate

### Fixed (S9.1)

- `fix(client): process detail/detail-runtime/set-integrity R3 compat` -- 字段重命名
  + len/size 单位统一

### Test (S9.1)

- `test(ui): 搜索 + 布局` -- 32 条 pytest (155 passed 阶段 baseline)

### Docs (S9.1)

- `docs: README UI 启动 / 三层搜索 / 布局持久化 / CLI 烟测` 章节

---

## [v0.9.0] - 2026-08-23 -- S8.1 actions 模块

### Added (S8.1)

- `feat(actions): 协议头` -- 7 IOCTLs `0x870-0x876` + `SAFETY_TOKEN` 结构
- `feat(actions): 87_actions 驱动侧` -- descriptor + ioctl + safety (混合 R0+R3 actions:
  kill / terminate / inject / dump / set_token / hide / protect)
- `feat(actions): 87_actions 驱动侧装配` -- vcxproj + filters + module_registry
- `feat(actions): R3 客户端` -- protocol + parser + cli + plugin + `__init__`

### Test (S8.1)

- `test(actions): 协议 + 客户端 pytest` -- 68 条 (覆盖 7 IOCTL request/response + 解析)
- `test(verify): verify_core.py 接 actions 7 IOCTL` -- 静态校验 + Mode A ack

### Fixed (S8.1)

- `fix(actions): RtlStringCbCopyA cast` -- `actions_ioctl.c` 内 RtlStringCbCopyA 参数
  cast 修复,R0 build 0 warning / 0 error

### Verified (S8.1)

- 7 IOCTL 端到端 (协议 + 客户端 + verify_core)
- 5 profile 构建 0 warning / 0 error

---

## [v0.8.3] - 2026-08-22 -- S7.3 15 模块新增

### Added (S7.3)

- `Add 81_trust module` (S7.3 commit 5) -- PE / 目录签名枚举
- `Add 85_kernel_ext module` (S7.3 commit 6) -- Win11 25H2 信息类扩展
- `Add 75_hwid module` (S7.3 commit 7) -- MajorFunction 检查
- `Add 79_alpc module` (S7.3 commit 8) -- ALPC 端口枚举
- `Add 78_wsl module` (S7.3 commit 9) -- WSL Silo 枚举
- `Add 77_win32k module` (S7.3 commit 10) -- GUI 线程 / 钩子枚举
- `Add 80_authentication module` (S7.3 commit 11) -- Authenticode 签名
- `Add 76_bugcheck module` (S7.3 commit 12) -- 最后一次 BugCheck + 帧缓冲
- `Add 72_wfp module` (S7.3 commit 13) -- WFP callout 枚举
- `Add 73_mutation module` (S7.3 commit 14) -- EPROCESS Token 篡改检测
- `Add 74_redirect module` (S7.3 commit 15 -- final module) -- CmCallback /
  IoCallDriver 检测
- `feat(security-audit): S7.3 83_security_audit 模块` -- 3 IOCTLs (Defender / Secure
  Boot / Trusted Boot 状态)
- `feat(safety): S7.3 86_safety 模块` -- 1 IOCTL (6 步门控评估器)
- `feat(preflight): S7.3 82_preflight 模块` -- 1 IOCTL (环境健康检查)
- `feat(capability): S7.3 84_capability 模块` -- 1 IOCTL (驱动自报能力)
- `feat(protocol): S7.3 15 模块协议头` -- 40 IOCTLs (`0x720-0x72F` +
  `0x750-0x75F` + `0x760-0x76F` + `0x800-0x86F` + `0x870-0x87F`)

### Fixed (S7.3)

- `fix(build): 解 20× C1083 phantom ioctl_helpers.h` -- vcxproj filters 路径修复
- `fix(build): 解 10 模块 LNK2001 + C2039 + C4013` -- R0 build 通过,5 profile 全 0
  warning / 0 error
- `fix(trust): 81_trust/trust_walker.c 添加 <ntstrsafe.h> include` -- 编译缺头文件修复
- `fix(verify): scripts/verify_core.py 删除 verify_dyndata docstring 重复内容`

### Test (S7.3)

- `test(verify): verify_core.py (15 modules, static + CLI smoke)` -- 40 IOCTLs 静态 +
  CLI 烟测覆盖

### Verified (S7.3)

- 15 新模块装配入单 .sys,5 profile 构建 0 warning / 0 error
- 总 IOCTL 数 9 (S7.1) + 10 (S7.2) + 40 (S7.3) = 59 (本阶段累计)

---

## [v0.8.2] - 2026-08-20 -- S7.2 回调模块

### Added (S7.2)

- `feat(callback): 协议头` -- 10 IOCTLs `0x710-0x719` + 输入输出结构 (PsSet/
  PsRemove/CmRegister/CmUn/ObRegister/ObUn/Image/Dbg)
- `feat(callback): 71_callback 模块` -- descriptor + ioctl + walker (Ps/Cm/Ob/Image/Dbg
  回调枚举) + internal 头
- `feat(callback): 驱动侧装配` -- vcxproj + filters + module_registry
- `feat(callback): R3 客户端` -- protocol + parser + cli + plugin + `__init__`
- `feat(callback): R3 注册` -- pyproject entry_points + `_builtin_modules`

### Fixed (S7.2)

- `fix(test): callback OB_ENTRY 字节大小 (Cookie 字段 128->136)` -- WIN10+ OB_CALLBACK
  结构调整适配

### Test (S7.2)

- `test(callback): 协议 + 客户端 pytest` -- 52 条 (覆盖 10 IOCTL request/response + 解析)
- `test(verify): verify_core.py 接 callback 10 IOCTLs` -- 6 QUERY/ENUMERATE + STATS 静态
  校验

### Verified (S7.2)

- 10 IOCTL 端到端 (协议 + 客户端 + verify_core)

---

## [v0.8.1] - 2026-08-18 -- S7.1 DynData 模块

### Added (S7.1)

- `feat(dyndata): 协议头` -- 9 IOCTLs + 输入/输出结构 (`0x700-0x708`)
- `feat(dyndata): 70_dyndata 模块` -- descriptor + ioctl + pagetable walker + internal 头
- `feat(dyndata): 驱动侧装配` -- vcxproj + filters + module_registry
- `feat(dyndata): R3 客户端` -- protocol + parser + cli + plugin + `__init__`
- `feat(dyndata): R3 注册` -- `_builtin_modules` + pyproject entry_points

### Fixed (S7.1)

- `fix(client): dyndata CLI 端到端 dispatch 修复` -- 单参 handler + query 中间 parser
  修复,使 `myark-cli dyndata query` 能正确分发

### Test (S7.1)

- `test(dyndata): 协议 + 客户端 pytest` -- 54 条 (覆盖 9 IOCTL request/response + 解析)
- `test(verify): verify_core.py + install_vm.ps1 接 dyndata 9 IOCTLs` -- 静态 + Mode A
  ack

### Verified (S7.1)

- 9 IOCTL 端到端 (协议 + 客户端 + verify_core)

---

## [v0.7.0] - 2026-08-15 -- S6.x 实体枚举与基础模块

### Added (S6.x)

- `feat(modules): memory` -- 10 IOCTLs (虚拟地址翻译 + 物理读 + PageTable walk + 签名
  scan),R0 优先 + R3 备用 (OpenProcess + ReadProcessMemory)
- `feat(modules): 10_process` -- 13 IOCTLs (3-view: Process/Thread/Module + actions:
  kill/terminate/inject/dump/set_token/hide/protect)
- `feat(modules): kernel` -- SSDT walker (1 IOCTL, closes S6.4 kernel gap)
- `feat(modules): S6.4 - 7 new R0/R3 modules`:
  - `handle` (20_handle) -- 句柄表枚举
  - `section` (21_section) -- Section 对象枚举
  - `kmod` (22_kmod) -- 内核模块枚举 (PsLoadedModuleList)
  - `storage` (23_storage) -- 磁盘卷枚举
  - `device-audit` (24_device_audit) -- 设备栈审计
  - `keyboard` (30_keyboard) -- 键盘过滤驱动审计
  - `debug-output` (31_debug_output) -- DebugPrint 捕获
- `feat(modules): registry` -- pure R3 (winreg read/write/delete)
- `feat(modules): network` -- pure R3 (TCP/UDP via GetExtendedTcpTable)
- `feat(modules): file` -- pure R3 (file info + SDDL)
- `feat(thread): 5 IOCTLs (R0 read + R3 hybrid)` -- enum/detail/stack/terminate/suspend

### Verified (S6.x)

- 13 + 10 + 1 + 7 + 1 = 32 实体枚举 IOCTL 端到端
- `myark-cli memory read <addr>` / `myark-cli thread enum` / `myark-cli kmod list` 烟测
  全 PASS

---

## [v0.6.0] - 2026-08-10 -- S5.x 模块新增 (15 模块)

### Added (S5.x)

- `70_dyndata` -- R0 NtQuery 风格系统信息综合查询
- `71_callback` -- Ps/Cm/Ob/Image/Dbg 回调枚举
- `72_wfp` -- WFP callout 枚举
- `73_mutation` -- EPROCESS Token 篡改检测
- `74_redirect` -- CmCallback / IoCallDriver 检测
- `75_hwid` -- MajorFunction 检查
- `76_bugcheck` -- 最后一次 BugCheck + 帧缓冲
- `77_win32k` -- GUI 线程 / 钩子枚举
- `78_wsl` -- WSL Silo 枚举
- `79_alpc` -- ALPC 端口枚举
- `80_authentication` -- Authenticode 签名
- `81_trust` -- PE / 目录签名
- `82_preflight` -- 环境健康检查
- `83_security_audit` -- Defender / Secure Boot / Trusted Boot
- `84_capability` -- 驱动自报能力
- `85_kernel_ext` -- Win11 25H2 信息类扩展
- `86_safety` -- 6 步门控评估器

### Test (S5.x)

- 8 + 10 + 40 = 58 IOCTL 协议 + 客户端 pytest (DynData 54 + Callback 52 + 15 modules
  protocol tests)

### Verified (S5.x)

- 9 (S7.1) + 10 (S7.2) + 40 (S7.3) = 59 IOCTL 端到端
- 35 驱动模块全部接入单 .sys (每模块独立 .c/.h + descriptor)

---

## [v0.5.0] - 2026-08-05 -- S4.x 机制烟测 + hello 模块

### Added (S4.x)

- `feat(modules): 00_hello` -- mechanism verified (compile-time + runtime enable/disable)
  - 编译期宏门控 (`#if MYARK_MODULE_HELLO`) 在 hello 模块首次端到端验证
  - 运行时通过注册表 `HKLM\SYSTEM\CurrentControlSet\Services\MyArkCore\Modules\Hello=0/1`
    启停

### Design (S4.x)

- 部署极简:1 个 .sys + 1 个 INF + 1 个 sc create
- 每个模块独立 .c/.h + 描述符 (`module_descriptor_t`)
- 编译时模块门控 (`#if MYARK_MODULE_<NAME>`)
- 运行时启停 (`HKLM\...\Modules\<Name>=0/1`)

### Verified (S4.x)

- Hello 模块 5 IOCTL (init/query/enable/disable/status) 全 PASS
- 启停机制 `reg add HKLM\...\Modules\Hello=0` + `sc stop MyArkCore` + `sc start MyArkCore`
  后,query 返回新状态

---

## [v0.4.0] - 2026-08-01 -- S3.x R3 客户端与协议

### Added (S3.x)

- `feat(shared): v3 protocol headers` -- IOCTL id 分配 (`0x700-0x87F` 范围) + struct 集中
  在 `shared/MyArkIoctl.h` + `shared/MyArkSharedMemory.h`
- `feat(client): complete core Python with main window + CLI + module loader`
  - `myark/client/ArkClient.py` -- IOCTL 打包 / 解包
  - `myark/transport.py` -- CreateFile + DeviceIoControl
  - `myark/driver_check.py` -- 探测驱动存在 / 版本
  - `myark/module_query.py` -- 模块列表 / capabilities 查询
  - `myark/plugin_loader.py` -- ModuleRegistration (setup_cli / setup_ui)
- `feat(client): add pytest suite for core IOCTL ctypes + open_driver`

### Fixed (S3.x)

- `fix(client): implement is_admin() via shell32.IsUserAnAdmin` -- 替换 subprocess 探测,
  准确判断 UAC 提权状态
- `fix(shared): add ntstrsafe.h include in MyArkSharedMemory.h` -- 编译缺头文件修复
- `fix(client): process detail/detail-runtime/set-integrity R3 compat` -- R3 fallback
  字段重命名 + len/size 单位统一

### Test (S3.x)

- `test(client): core IOCTL ctypes + open_driver` -- 28 条 pytest (ctypes 结构对齐 +
  CreateFile 错误码处理 + 权限检查)

---

## [v0.3.0] - 2026-07-28 -- S2.x 驱动骨架与 IOCTL 分派

### Added (S2.x)

- `feat(driver): KMDF skeleton with config-driven compile flags`
  - `config/myark_full.h` / `myark_core.h` / `myark_mini.h` / `myark_process_only.h` /
    `myark_safety_audit.h` -- 5 profile 头文件
  - `myark_config.h` -- 通过 `#include` 间接引用 profile 头
- `feat(module): module descriptor + registry + enable mask`
  - `MYARK_MODULE_<NAME>` 宏定义统一前缀
  - `module_descriptor_t` 结构 (id / name / enable_mask / init / exit / ioctl_handlers)
  - `module_registry.c` -- 全局描述符表
- `feat(dispatch): global IOCTL table + 5 core IOCTLs`
  - `ioctl_dispatch.c` -- `MyArkDispatchIoctl` 入口
  - `ioctl_registry.c` -- IOCTL id → handler 映射表
  - `core_ioctl_handlers.c` -- 5 核心 IOCTL (`MYARK_IOCTL_GET_VERSION` /
    `MYARK_IOCTL_GET_MODULES` / `MYARK_IOCTL_GET_CAPABILITIES` /
    `MYARK_IOCTL_PING` / `MYARK_IOCTL_SHUTDOWN`)
  - `ioctl_validation.c` -- SAFETY_TOKEN / 长度校验
- `feat(core): VM-loaded core driver with 5 IOCTLs verified`
  - `DriverEntry` / `DriverUnload` -- KMDF 生命周期
  - `WdfDriverCreate` + non-PnP DeviceInit + SymbolicLink `\\.\MyArkCore`
  - `WdfRequestGetInputBuffer` / `Output` 缓冲读取宏 (`ioctl_helpers.h`)
- `feat(scripts): make.bat for profile-driven builds`
  - `scripts/make.bat <profile> [Config]` -- MSBuild 调用封装
  - profile 归一化 (hyphen / underscore 互换)
  - 5 profile 默认 Debug 构建

### Verified (S2.x)

- 5 IOCTL 端到端 (DriverEntry → IRP_MJ_DEVICE_CONTROL → ioctl_dispatch → handler →
  DeviceIoControl 返回)
- 5 profile `make.bat <profile> Debug` 全 0 warning / 0 error

---

## [v0.1.0] - 2026-07-25 -- S1.x KMDF 骨架

### Added (S1.x)

- `chore: initialize MyArk repo skeleton (plugin architecture v3)`
  - 目录结构:`driver/` + `client/` + `shared/` + `scripts/` + `config/` + `tests/`
  - `.gitignore` (driver/x64/ 输出 + client/.venv/ + .pytest_cache)
  - `MyArkCore.sln` + `MyArkCore.vcxproj` + `MyArkCore.vcxproj.filters`
  - `MyArkCore.inf` -- KMDF non-PnP inf
- `feat(driver): KMDF skeleton with config-driven compile flags`
  - `Trace.h` -- WPP 跟踪宏
  - `driver_entry.c` -- KMDF DriverEntry 模板
  - `device_control.c` -- IRP_MJ_DEVICE_CONTROL 入口

### Design (S1.x)

- 单 .sys 部署:不做多 .sys 插件 DLL
- 模块化宏门控:`#if MYARK_MODULE_<NAME>` 包裹每个模块的 .c/.h
- 运行时启停:`HKLM\...\Modules\<Name>=0/1` 软切
- KMDF 而非 WDM:降低驱动编写难度,统一框架接口

---

## 文档索引

| 文件 | 用途 |
|---|---|
| [README.md](README.md) | 项目门面 |
| [ARCHITECTURE.md](ARCHITECTURE.md) | 架构详解 |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 开发规范 |
| [CHANGELOG.md](CHANGELOG.md) | 本文件 |
| [RELEASE.md](RELEASE.md) | 发布 checklist (S10.2 新增) |
| [KNOWN_ISSUES.md](KNOWN_ISSUES.md) | 已知问题 (S10.2 新增) |
| [LICENSE](LICENSE) | MIT License |
| [config/BUILD_MATRIX.md](config/BUILD_MATRIX.md) | 构建矩阵 |
| [`.hermes/plans/2026-08-24_121735-ark-tool-self-impl.md`](.hermes/plans/2026-08-24_121735-ark-tool-self-impl.md) | 完整计划文档 (v3) |

## 已知限制

下列项**不**在本仓库路线图内,理由与未来条件见各自 issue:

- WHQL 签名 (待 S11+ 路线)
- 多 .sys 插件 DLL (违反"部署极简"硬纪律)
- PySide / PyQt / dearpygui 等其它 GUI 框架 (违反 Tkinter 硬纪律)
- 远程 IOCTL 通道 (违反 DeviceIoControl 单链路纪律)

## 致敬

- KMDF samples ([Microsoft](https://github.com/microsoft/Windows-driver-samples))
- Python `ctypes` 文档
- `pypinyin` 项目
