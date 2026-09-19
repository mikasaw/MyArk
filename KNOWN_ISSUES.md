# KNOWN_ISSUES

MyArk v1.0.0 已知问题、限制、兼容性、性能、安全清单。

每条按 **严重度 / 范围 / 是否阻塞 v1.0.0** 三字段标注:

- 严重度: `阻塞` / `一般` / `轻微`
- 范围: `所有用户` / `VM 内` / `特定 OS 版本`
- 阻塞: `是` / `否`

---

## 一、已知限制 (设计层面, 非 bug)

### L1. WHQL 正式签名未做

- **严重度**: 阻塞 (生产) / 一般 (研究)
- **范围**: 所有用户
- **阻塞 v1.0.0**: 否 (项目以研究 / 内部测试为定位)
- **详情**: 驱动用 self-signed test cert 签名,**不**通过 WHQL 认证。
  Windows 10/11 默认开启 Secure Boot 的主机上,test-signed 驱动加载
  会被拒绝,必须 `bcdedit /set testsigning on`。
- **何时修**: 拿到 EV cert + 微软提交账号后,走 WHQL 流程。预估 6-12 月。
- **缓解**: VM 内启用 testsigning;物理机用户可手动 `bcdedit /set testsigning on`。
- **不在范围原因**: EV cert 单价 $300-700/年,WHQL 提交流程需 2-3 个月往返。

### L2. 单 .sys 部署,不做插件 DLL

- **严重度**: 阻塞 (架构)
- **范围**: 所有用户
- **阻塞 v1.0.0**: 否 (这是设计纪律)
- **详情**: 所有 35 模块编译进单一 `MyArkCore.sys`,模块启停靠
  编译期宏 (`#if MYARK_MODULE_<NAME>`) + 运行时注册表 (`HKLM\...\Modules\<Name>=0/1`)。
  无独立 `.dll` 插件系统。
- **何时修**: 永不修。这违反项目"部署极简"硬纪律。
- **缓解**: N/A (by design)。

### L3. 仅 Tkinter,不做 PySide/PyQt/dearpygui

- **严重度**: 阻塞 (GUI 框架)
- **范围**: 所有用户
- **阻塞 v1.0.0**: 否 (这是设计纪律)
- **详情**: UI 仅用 Python 3.14 stdlib `tkinter`。无 Qt / wxPython / Web
  前端。界面风格受 Tkinter 主题限制。
- **何时修**: 永不修。这违反项目"Tkinter 硬纪律"。
- **缓解**: ttk theme (`clam` / `alt` / `default`) 可缓解外观,但功能集
  受 Tkinter 限制。

### L4. 仅本地 DeviceIoControl 链路

- **严重度**: 阻塞 (远程)
- **范围**: 所有用户
- **阻塞 v1.0.0**: 否 (这是设计纪律)
- **详情**: IOCTL 通过 `CreateFile("\\\\.\\MyArkCore")` 本地内核 handle
  通信。无 TCP/HTTP/ALPC 远程通道,无 RPC server。
- **何时修**: 永不修。这违反"单链路"硬纪律,且大幅增加攻击面。
- **缓解**: N/A (by design)。

### L5. Windows-only

- **严重度**: 阻塞 (跨平台)
- **范围**: 所有用户
- **阻塞 v1.0.0**: 否 (ARK 本就是 Windows-only 工具类)
- **详情**: 驱动编译依赖 WDK + KMDF,R3 依赖 `ctypes` + `winreg` + Win32
  API。无 macOS / Linux / WSL2 内核模块适配 (用户态 WSL 走
  `78_wsl` 模块枚举,不修改 WSL 内核)。
- **何时修**: 不计划。WSL2 内核修需 WSL team 配合。

### L6. 测试签名模式 (Mode A) 是唯一支持的实物验证

- **严重度**: 一般
- **范围**: VM 内
- **阻塞 v1.0.0**: 否
- **详情**: 实物验证仅在 `testsigning on` 的 VM guest 内跑 (Hyper-V Gen2 /
  VMware Workstation / VirtualBox / QEMU)。**不**在物理机主 OS 上跑。
- **何时修**: WHQL 后可扩到物理机。
- **缓解**: 本机静态验证 (`pytest` + `make.bat` 5 profile) 已覆盖所有
  单元 + 集成路径。

### L7. ARP 改写仅作用于 NSI 用户缓冲 (旧 API 与内核缓存不受影响)

- **严重度**: 一般 (设计边界, 行为差异需知晓)
- **范围**: 75_hwid ARP 类 (R3-1b)
- **阻塞 v1.0.0**: 否
- **详情**: ARP 邻表 MAC 改写发生在 nsiproxy 完成例程, 只补丁
  GetIpNetTable2 / Get-NetNeighbor 等 NSI 大枚举路径的**用户态列缓冲**。
  旧 `GetIpNetTable` (0x120007 逐行小查询) 与内核邻表缓存零接触——
  同一台机器上两条路径读回的结果会不同 (NSI 路径显示伪装 MAC, 旧
  路径显示真值), 重启后自然回到内核真值。
- **何时修**: 不修 (设计边界, 与 T-B 各类"完成例程用户缓冲改写"同一
  范围声明); 若需旧路径一致需额外拦截 0x120007 响应 (暂不排期)。
- **缓解**: Tier C profile (18362/18363/22631 已钉, 24H2 待虚机)
  之外 build 优雅拒绝; SAFETY_TOKEN + EVAL_GATE 门控不变。

---

## 二、已知 bug (待修, 不阻塞)

### B1. `myark-cli network list` 在某些 Win11 24H2 上返回空 TCP 表

- **严重度**: 轻微
- **范围**: Win11 24H2 部分 build
- **阻塞 v1.0.0**: 否
- **详情**: 走 `GetExtendedTcpTable`,Win11 24H2 在某些 recent cumulative
  update 后,non-elevated 进程调用返回 `ERROR_INSUFFICIENT_BUFFER` 但
  size 不更新,导致空表。
- **重现**: Win11 24H2 build >= 26100.1297,非管理员 cmd 跑
  `myark-cli network list`。
- **临时修**: 提权运行 (`Run as Administrator`)。
- **何时修**: 下一个 minor version (v1.1.0) — 改用 raw NtDeviceIoControlFile
  或要求提权。

### B2. ~~`myark-cli file info <locked.bin>` 长路径 (> 260 char) 抛 `OSError`~~ 已修复 (2026-09-15)

- **严重度**: 轻微
- **范围**: 所有用户
- **阻塞 v1.0.0**: 否
- **详情与修复**: `file info/owner/dacl/integrity` 内部早已接入
  `_normalize_long_path`（`\\?\` 前缀 + 正斜杠归一, 仅在 ≥260 字符且
  未带前缀时插入）; 本轮补上遗漏的 `file ls`（`list_directory` 的
  FindFirstFileW pattern 同样规范化）。`\\?\` 前缀无论宿主机
  LongPathsEnabled 策略开关均有效。554 字符路径实测四条子命令全通过;
  单测覆盖规范化函数边界与前缀注入 (test_r3_file.py,
  TestNormalizeLongPath / TestListDirectoryLongPath)。

### B3. ~~`myark-ui` 在 DPI > 175% 下字体偶尔超出 Treeview 单元~~ 已修复 (2026-09-15, v1.1.0)

- **严重度**: 轻微
- **范围**: 高 DPI 屏
- **阻塞 v1.0.0**: 否
- **详情与修复**: UI 已 SetProcessDpiAwareness(1), Tk 只缩放字体
  不缩放列宽。新增 `myark/ui/scaling.py`
  (`scaled_width` = 写死像素 × 实际 DPI/96, 钳位 [0.5, 8], TclError
  回退 1.0), 四个共享组件 (tree_table / history_window /
  diff_window / detail_window) 的列宽全部接入。
  **覆盖范围说明**: `modules/*/ui.py` 各自构建的 Treeview 已接入
  (2026-09-16 R3-12: 8 模块 9 个 Treeview 10 处列宽调用点全部改
  scaled_width; network 模块 width=0 的自动列宽重置保持原样, 0 不是
  设计像素); system-aware DPI 下多显示器/运行时改 DPI 不重算
  (窗口创建时一次性缩放)。
  12 个单测覆盖缩放数学、钳位与 modules/*/ui.py 源码级守护——新增
  Treeview 面板若再出现裸固定列宽会直接挂测试
  (client/tests/test_ui_scaling.py)。

### B4. `verify_core.py` 在 SSDT 烟测段偶现 `OSError: [Errno 22] Invalid argument`

- **严重度**: 轻微
- **范围**: 某些老 CPU (无 SMEP)
- **阻塞 v1.0.0**: 否
- **详情**: 极少数老 AMD CPU 无 SMEP,驱动内 SSDT walker 跨页读触发
  `STATUS_ACCESS_VIOLATION`,R3 端收到 `OSError 22`。
- **重现**: AMD Athlon X2 / Phenom I 等 + Win10 22H2。
- **修复 (2026-09-15, 两层)**:
  (1) 驱动侧——25_kernel 与 70_dyndata 两个 SSDT walker 的
  `MmIsAddressValid + 裸解引用` 改为 `MmCopyMemory(MM_COPY_MEMORY_VIRTUAL)`
  容错读 (缺页/未映射安全失败, 跳过该槽位), 该 CPU 类上不再蓝屏/出错;
  (2) 验证侧——verify_core.py 的 QUERY_SSDT 探针对 win32 87 降级 SKIP
  (见 T7)。
- **收口 (2026-09-16, R3-13)**: 剩余两处同模式用法
  `MyArkDynDataReadDwell` 与 `MyArkKernelReadDwellBytes` 已迁移
  `MmCopyMemory(MM_COPY_MEMORY_VIRTUAL)`, 返回实际拷贝字节数
  (旧 dyndata 慢路径部分拷贝仍返回 MAX 的失真、kernel 版 `return 8`
  脏契约一并修复); 双 build 1903/22631 全绿。范围外残留:
  10_process / 11_thread / 12_memory 等模块的 MmIsAddressValid 门控
  裸读 (descriptor / Limit / Base 等生命周期常驻目标), 候选后续
  加固项。2026-09-20 起 77_win32k 的 MyArkWin32kRead 亦为同模式
  (内核地址 MmIsAddressValid 门 + 用户地址 __try), 且 0x772 堆
  候选扫描使其成为解引用面最大的一处 (解对象为不可信候选值,
  跨页/TOCTOU 残余见 tests/CRASH_DEBUG_LOG.md 2026-09-20 条),
  加固顺位第一位。

---

## 三、兼容性

### OS 支持矩阵

| OS | x86 | x64 | ARM64 | 状态 |
|---|---|---|---|---|
| Windows 10 21H2 | ❌ | ✅ | ❌ | 已测 (本机 + VM Mode A) |
| Windows 10 22H2 | ❌ | ✅ | ❌ | 已测 (本机 + VM Mode A) |
| Windows 11 22H2 | ❌ | ✅ | ❌ | 已测 (本机 + VM Mode A) |
| Windows 11 23H2 | ❌ | ✅ | ❌ | 已测 (本机 + VM Mode A) |
| Windows 11 24H2 | ❌ | ✅ | ✅ | x64 已测,ARM64 仅 build pass |
| Windows 11 25H2 | ❌ | ✅ | ✅ | x64 build pass,实物待测 |
| Windows Server 2022 | ❌ | ✅ | ❌ | 未测 (理论支持) |
| Windows Server 2025 | ❌ | ✅ | ❌ | 未测 (理论支持) |

**说明**:
**S11.4 起 (2026-09-14)**: process / thread 模块不再做 build 门禁。偏移改为运行时
解析（导出访问器优先 + 两个链表偏移自校验发现），两个模块在 Win10 1903 起即可加载
并注册 18 个 IOCTL。
- 当前状态: ActiveProcessLinks 发现已在 1903 实测成功；ETHREAD 的
  ThreadListEntry / ThreadListHead 发现尚未成功，故 ENUM / CROSSVIEW 在这些
  build 上返回 STATUS_NOT_SUPPORTED（明确降级、不崩溃），ENUM_THREAD 返回
  NOT_FOUND。DETAIL 的调试字段会回报实际解析出的偏移，便于确认能力边界。
- 改造过程中修复的两个蓝屏都是模块首次真正执行才暴露的潜伏问题（栈上
  160 KiB 大结构、SystemProcessInformation 走查无边界），详见
  tests/CRASH_DEBUG_LOG.md。

- x86 不支持:WDK 10.0.28000 不再发 x86 KMDF 库。
- ARM64: 编译通过 (`arm64` config),实物验证需要 ARM64 VM guest,本仓库无对应 CI。
- Win10 21H2 之前版本:WDK 不保证 API 兼容,可能需调整 INF 段。
- **S11.1 起**: process / thread 模块 (偏移型枚举) 在 build 26100..26299
  (Win11 24H2/25H2) 之外拒绝加载,上表 Win10 / Win11 22H2-23H2 的驱动其余
  模块仍可加载,但 `driver modules` 中不会出现 process/thread;这是从
  "静默读错内存" 到 "明确缺席" 的行为变更。

### 工具链

- Visual Studio Insiders 18 (MSVC v145)
- Windows SDK 10.0.28000
- WDK 10.0.28000 (26100 无 km 库,见 README)
- Python 3.14 (R3 端)
- PowerShell 5.1+ (脚本端)

### 驱动签名

- 测试签名:`New-SelfSignedCertificate -Type Kernel`,见 RELEASE § 9
- WHQL 正式签名:**未做**,见 L1

---

## 四、性能

### CPU

- 静态 (无 R3 调用):`< 0.1%` 本机 CPU
- 中等负载 (5 R3 client × 10 IOCTL/s):`< 1%` 本机 CPU
- 重负载 (50 R3 client × 100 IOCTL/s):`2-5%` 本机 CPU,单核瓶颈

### 内存

- 驱动驻留:`~2 MB` (单 .sys,5 profile 字节数 × 1.5,见 BUILD_MATRIX.md)
- R3 进程 (myark-ui):`~40 MB` (含 Tkinter + pypinyin)
- R3 进程 (myark-cli):`~20 MB`

### IOCTL 延迟

| IOCTL 类别 | 平均延迟 | P99 延迟 |
|---|---|---|
| GET_VERSION / PING | < 1 µs | < 5 µs |
| QUERY_MODULES / CAPABILITIES | < 10 µs | < 50 µs |
| 实体枚举 (process/thread/memory) | 0.5-2 ms | < 10 ms |
| 回调枚举 (callback ps/cm/ob/image/dbg) | 1-5 ms | < 20 ms |
| 签名 scan (memory scan) | 50-200 ms | < 1 s |

---

## 五、安全

### S1. 驱动用 self-signed test cert

- **严重度**: 阻塞 (生产部署)
- **范围**: 所有用户
- **阻塞 v1.0.0**: 否
- **详情**: 见 L1。test-signed 驱动加载到 `testsigning on` 机器即可,无
  EV cert,无 WHQL 认证。
- **风险模型**: 任意能物理访问 + 提权的攻击者可加载**自己改过的**
  MyArkCore.sys 替换原版。攻击者可借此注入任意 IOCTL handler,获取
  内核 R/W 任意进程内存 + 进程句柄。
- **何时修**: WHQL (L1)。

### S2. 无 anti-tamper / 无 self-integrity

- **严重度**: 一般
- **范围**: 所有用户
- **阻塞 v1.0.0**: 否
- **详情**: 驱动不校验自身 .text 段 hash,攻击者改 sys 文件后加载,
  R3 也无法察觉。
- **何时修**: v1.1.0 — 加 IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY +
  启动时 self-hash 比对。

### S3. IOCTL 无 per-user ACL

- **严重度**: ~~一般~~ **已于 S11.1 修复 (2026-09)**
- **范围**: 多用户机器
- **阻塞 v1.0.0**: 否
- **详情**: `\\.\MyArkCore` device 原 SDDL 给 `Everyone` GRGW,任意登录用户
  可打开设备并发送全部 IOCTL。S11.1 将 SDDL 收紧为
  `D:(A;;GA;;;SY)(A;;GA;;;BA)` -- 仅 SYSTEM/Administrators,非提权进程
  `CreateFileW` 返回 `ERROR_ACCESS_DENIED`。
- **残留**: per-session 细粒度 ACL (按 TokenIntegrityLevel 分级授权) 仍留待
  v1.2.0。

### S4. SAFETY_TOKEN 是单 token 复用

- **严重度**: ~~轻微~~ **已于 S11.1 修复 (2026-09)**
- **范围**: 所有用户
- **阻塞 v1.0.0**: 否
- **详情**: 原 87_actions 校验仅要求签名"非全零",无密码学强度;10_process
  的 8 个变更型 IOCTL 完全无 token 门。S11.1 改为 CNG HMAC-SHA256 (per-boot
  `BCryptGenRandom` 会话密钥,`IOCTL_MYARK_CORE_GET_SESSION_KEY` 下发) +
  +/-120s FILETIME 时间窗防重放 + 常量时间比较,并覆盖 process 变更面
  (输入头新增 Token 字段,协议结构 +72 字节)。非提权进程拿不到会话密钥,
  无法伪造令牌。
- **残留**: per-session 一次一密 (S4 原始目标) 仍留待 v1.2.0。

### S6. VM 运行时回归

- **严重度**: ~~一般~~ **已闭环 (2026-09-08 首轮 + 2026-09-14 S11.3 扩展)**
- **范围**: VM 内
- **阻塞**: 否
- **详情**: S11.1 的驱动改动在 VMware Win10 1903 (18362) guest 内完成端到端
  回归。2026-09-08 覆盖 core/actions/process 门/物理门控 (50 PASS);
  2026-09-14 (S11.3) 扩展到 memory 虚拟路径 (QUERY_VM/READ_VM/WRITE_VM/
  TRANSLATE_VA/QUERY_PT_ENTRY/两个 SCAN) 与全量 IOCTL 矩阵
  (45 只读 + 6 变更型可达性 + 零参数拒绝), 当前 **117 PASS / 0 FAIL /
  0 SKIP**。回归脚本 `scripts/verify_core.py` 按段输出并可 grep。
- **回归中发现并修复的阻塞** (两轮共 12 项, 详见
  `tests/CRASH_DEBUG_LOG.md`):
  1. actions 7 处先清共享缓冲后验 token (恒拒);
  2. 控制设备 SDDL 拼写错误 (sc start 87);
  3. WdfDeviceCreateDeviceInterface 在控制设备被 KMDF 拒绝;
  4. SAFETY_TOKEN 时间窗常数 1200s 与文档不符;
  5. 链接 um bcrypt.lib 导致内核导入 bcrypt.dll (加载报错 2);
  6. ExAllocatePool2 仅 Win11+ 导出 (加载报错 127);
  7. WRITE_PHYSICAL 取缓冲前解引用指针 (opt-in 路径必 BSOD);
  8. **storage 与 device-audit 用 `IoEnumerateDeviceObjectList(NULL, ...)`
     枚举设备 → 0x0A 蓝屏** (两处同源拷贝, 改用 \Device 目录 +
     ObReferenceObjectByName);
  9. **memory 模块 7 处共缓冲清零** (Pid/Address/Va/Signature 被抹零);
  10. 写路径 `sizeof` 当载荷起点造成 8 字节错位;
  11. **页表 walker 用 MmMapIoSpace 读页表页恒失败** (该 API 对 RAM 页返回
      NULL), 改用文档化的 `MmCopyMemory(MM_COPY_MEMORY_PHYSICAL)`;
  12. 回归脚本自身的探针布局/判据错误 (数据偏移、随机负样本、注册判据)。
- **回归矩阵 (2026-09-15)**: 1903 (18362) 全绿 + **Win11 23H2 (22631) 全绿** (133 项; Win11 虚机 vTPM partial 加密, 口令在凭据管理器, 舰队 MYARK_VP 传递; guest 账号见本地 build\vm_env_local.bat（不入库）; python 用 embeddable 包 C:\Users\Public\python312)。links_off 运行时发现自动适配 (1903=0x640, 22631=0x350)。仍缺 24H2 (26100+) 虚机 —— ProfileMatched 分支 (26100..26299) 待 24H2 guest 验证;
  (a) process/thread 变更面 8 IOCTL 的 token 正/负路径已在 1903 与 22631 双 build 通过, 24H2 待补;
  (b) ~~86_safety 与 core 撞码 (0x800) 致该模块 IOCTL 缺席~~
  已修复 (2026-09-15): EVAL_GATE 迁至空闲块 0xD00, 纳入 MATRIX 覆盖;
  (c) ~~READ/WRITE_PHYSICAL 受 MmMapIoSpace 限制, 非页对齐 PA 未测~~
  已修复 (2026-09-15): READ 改 MmCopyMemory(MM_COPY_MEMORY_PHYSICAL),
  WRITE 改 \Device\PhysicalMemory 区段映射, 非对齐探针 (读交叉验证 +
  真实写往返) 实测通过; 改造过程中暴露并修复 WritePhysical 快照早于
  fetch 的空指针 (六次 0x3B, 见 CRASH_DEBUG_LOG S11.6); (d) 快照回滚会还原 KDNET 专用 key/端口,
  需重跑 `build/vm_kdnet_set.bat` + 重启; (e) **ETHREAD 链表偏移
  (ThreadListEntry/ThreadListHead) 在 1903 未发现** (`thread_off=0x0`),
  ENUM_THREAD 已用 TID 扫描绕开 —— 已知局限: 扫描 TID 空间 [0,0x100000)
  是 O(全空间) 探测, miss 早退阈值 32768 下极低频线程可能漏报;
  24H2 上 ProfileMatched 分支走偏移直读不受影响 (待 (a) 项验证)。

### S5. ~~历史日志 (history.log) 明文存储~~ 已修复 (2026-09-15, v1.1.0)

- **严重度**: 轻微
- **范围**: 所有用户
- **阻塞 v1.0.0**: 否
- **详情与修复**: `myark/history.py` 新增 DPAPI 加密线格式
  （`ENC1:<base64>`，crypt32 CryptProtectData，当前用户作用域）。
  开关：`MYARK_HISTORY_ENCRYPT=1` 环境变量或
  `myark.history.set_encryption_enabled(True)`，**默认关闭**保持历史
  格式；读取端同时兼容明文与 ENC1 两种行，开启加密不影响旧记录；
  `migrate_to_encrypted()` 就地转换存量明文（坏行原样保留）。
  威胁模型边界：DPAPI 防的是"其它用户账户/其它机器"，同用户进程
  仍可解密——这是 DPAPI 的设计语义。13 个单测覆盖
  （client/tests/test_history.py），全套 853 通过。

---

## 六、报告新 issue

发现上面没列的问题:

1. 在 GitHub issue tracker 提交,标签 `bug` 或 `security`。
2. 安全问题**不要**公开 issue,直接邮件 `security@myark.local` (TODO: 配置)。
3. 复现步骤必须含:OS 版本 + 驱动 profile (full/core/mini) + R3 调用命令 + 期望 vs 实际。

---

## 文档

- [README.md](README.md) -- 项目门面
- [RELEASE.md](RELEASE.md) -- 发布 checklist
- [CHANGELOG.md](CHANGELOG.md) -- 变更日志
- [ARCHITECTURE.md](ARCHITECTURE.md) -- 架构详解
- [CONTRIBUTING.md](CONTRIBUTING.md) -- 开发规范 + 报告 issue

## SHADOWSSDT (0xE24) 22631 boot variability (2026-09-16)

- win32k 影子表的锚定依赖 ntoskrnl 内 KeServiceDescriptorTableShadow 相邻
  双描述符 + 解码评分（前 32 项 ≥24 落在 win32k 模块并集内）。
- 22631 上存在逐 boot 变体：部分 boot 的枚举并集/布局使真表无法达标，
  驱动如实返回 STATUS_PROCEDURE_NOT_FOUND；verify 记 SKIP（err=127）。
- 1903 稳定锚定（1258 项、零 suspect）。24H2 未验。
- 若要根治：改走 PsLoadedModuleList 直查 win32kfull 的 PE 导出
  （W32pServiceTable 无导出，需 .data 形态定位）或 KTHREAD ServiceTable
  偏移解析器（Tier B/C）。

## FILEINTEG SET (0xE12) guest wedge (2026-09-16)

- ZwSetSecurityObject 写手工构造的强制标签 SD（SYSTEM_MANDATORY_LABEL_ACE
  写入文件 SACL）会让 guest exec 通道不可恢复卡死；无 minidump，KDNET
  附加后落在 SeCaptureSecurityDescriptor 附近的 AV 循环。
- 三种 SD 构造全部复现：rev-2 ACL、rev-4 ACL（RtlCreateAcl+RtlAddAce）、
  精确尺寸 label ACE（20B）。QUERY-only（0xE13）不复现。
- 处置：SET 处理器降级为确定性 STATUS_NOT_SUPPORTED（win32 50，与未注册
  的 win32 1 可区分），延迟实现保留在 #if 0；已打标文件的读回断言改用
  icacls fixture（/setintegritylevel H）+ 驱动 QUERY。
- 根治计划：KDNET 附加下隔离复现，逐步二分 SD 字段；或改用
  SeSetSecurityDescriptorInfo 内核内部路径调研。

## ASK_USER (R2-11) parked-notify deadlock (2026-09-16)

- 设计目标：ASK 规则把进程创建停在 PsSetCreateProcessNotifyRoutineEx
  回调内，等 R3 经 WAIT_EVENT/ANSWER_EVENT IOCTL 应答（超时 fail-open）。
- 实测（1903，干净 boot，100% 复现）：ASK 规则启用后 verify 在早期
  IOCTL 阶段整体卡死（连未缓冲输出都停在 CORE QUERY_MODULES 一带），
  guest exec 文件通道存活但 runProgramInGuest 永久阻塞；多次硬重启后
  仍复现。驻留已代码禁用（notify 内 ASK 走 LOG_ONLY、parking 机制
  #if 0 搁置于 git 历史）后需再回归确认恢复。
- 根因候选：notify 回调驻留与 WDF 顺序队列/R3 轮询 IOCTL 的管线级
  串行化交互；未定位到单一语句。
- 处置：R2-11 整体延后。0x71C/0x71D/0x71E 协议与队列机制待专用
  调试轮（KDNET 附加 + 每 IOCTL 隔离）后再落地。

## FILEMON minifilter 加载/卸载模型 (2026-09-16)

- 混合驱动(legacy 控制设备 + FltRegisterFilter)的 minifilter 注册要求
  服务键 Instances 子键(本驱动 DriverEntry 自建,idempotent)。曾因子键
  拼接缺分隔符出现 0xC000000E / 0xC0000034,已修复并用 reg query 回读验证。
- **禁用 fltmc load MyArkCore**(实测 1903,100% 复现 0xCE):fltmc 加载后
  FLTMGR 接管 DriverUnload,FilterUnloadCallback=NULL 时 sc stop 走
  FLTMGR 自有卸载路径,驱动侧清理(含 FltUnregisterFilter)不执行,
  镜像释放后 post-callback 仍被调用 → DRIVER_UNLOADED_WITHOUT_CANCELLING_
  PENDING_OPERATIONS,断点取证 EvtDriverUnload/MyArkFileMonStop 均未命中。
  正确通道:sc create type= filesys + sc start(vm_svc_create.bat 与
  elevated_deploy.cmd 已固化)。
- 一次 sc stop 卡死事件(1903,内核栈全空闲、sc.exe 已退出,疑似
  Tools/Session-0 exec 通道挂起而非驱动问题;同日同周期已成功 3 次):
  处置以 reset-first 纪律覆盖——重部署一律 vm_reset_hard,避免依赖
  健康态 sc stop。
- 事件结构 MYARK_FILEMON_EVENT 尾部显式 Reserved2 保持 sizeof=568
  (C_ASSERT 钉死);R3 按 568 步长解析,改布局必须同步 verify_core.py。

## REDIRECT REG 方案与 sc stop 挂起补充 (2026-09-16)

- R2-9 REG 重定向: CmCallback 的 RegNtPreOpenKey(Ex) 改 CompleteName 在
  18362 不被采纳(CM 先解析后回调, swap 被计数但无效)——值级方案
  (PreQueryValueKey 存 CallContext, PostQueryValueKey 改写 PARTIAL/FULL,
  不足时 ReturnStatus=STATUS_BUFFER_OVERFLOW 触发 R3 重试)替代。
- **sc stop 挂起与 minifilter 注册强相关**(1903, 2/2 复现: R2-7 终版与
  R2-9 均挂; 注册失败时期从未挂): sc stop 停加载了已注册 filter 的
  MyArkCore 时 exec 通道失联、内核栈无可辨识的 unload 线程。根因待查
  (FltUnregisterFilter 等待/WDF 卸载次序)。**纪律: 一律 reset-first
  重部署, 活机禁止对已加载(注册过 filter 的)驱动执行 svc_clean。**
- 工具链: Git Bash heredoc 会剥一层反斜杠——源文件内嵌转义必须用
  chr(92) 构造并做写入后 NUL 检查(本日 vcxproj/C 源/Python 三连中招)。

### 更正 (2026-09-16 晚, R2-9 调试轮)
- 上述 "type= filesys 固化" 的结论**错误**,已回退: sc create MyArkCore
  **type= kernel** 才是正确形态。filesys 型驱动并非真正文件系统,启动后
  会被 I/O 管理器异步卸载,产生自发性 0xCE(minidump 091626-12062,
  验证中途崩溃,无任何人调 stop);kernel 型 + 修好的 Instances 键下
  FltRegisterFilter 注册正常(reg=1)。
- **0xCE 与 sc stop 挂起的共同根因**: FltRegisterFilter 成功后 FLTMGR
  接管 DriverObject->DriverUnload,驱动侧 WDF EvtDriverUnload(含
  FltUnregisterFilter 与其余模块清理)在 stop 时**不再被调用**;镜像
  释放后 pre/post 回调仍挂卷,下一次文件打开即 0xCE(现场栈:
  FLTMGR!FltpPerformPreCallbacks -> Unloaded_MyArkCore+off,调用方是
  sc.exe 自己的 FormatMessage NtOpenFile)。挂起则是同一时序的非崩溃变体。
- **修复**: 注册 MyArkFileMonFilterUnload(FLTMGR 的 FilterUnloadCallback),
  在其中执行全驱动清理(MyArkCoreRunModuleTeardown: 模块反序 Cleanup +
  IOCTL 表复位 + 安全令牌卸载)并按惯例 FltUnregisterFilter;带
  Interlocked 双跑保护。修复后 1903 实测: verify 全绿 + sc stop 成功 +
  guest 存活,卸载路径闭环。

### R3-1 (T-B) HWID 伪装细分遗留 (2026-09-17)
- **过滤 DO 不处理 surprise-removal**: IRP_MJ_PNP 走无条件透传,目标磁盘
  栈在附着期间被移除(USB 热拔)会让 router 的下一次 IoCallDriver 打到
  已删除的 DO。测试 VM 固定盘可容忍;对外发布前需在透传路径观察
  IRP_MN_SURPRISE_REMOVAL/REMOVE_DEVICE 并触发摘除。
- **uid 类(类 3)在 NVMe 盘上是干净的 no-op**: VMware NVMe 的
  StorageDeviceUniqueIdProperty 响应只带 0x83 ID 描述符
  (StorageDeviceOffset=0),没有内嵌可改写的串;驱动按 NOT_FOUND 干净
  拒绝。0x83 标识符改写留 R3-1b(与 ARP 同轮)。
- **partition 类在 GPT 盘的端到端闭环未实测**(test2 是 MBR 盘):python
  读回偏移已按 WDK 头文件修正(PARTITION_INFORMATION_GPT 第一成员是
  PartitionType,PartitionId@union+16);驱动侧用 C 结构成员天然正确。
- **CaptureQueryContext 每-IRP 池抖动**: 附着期间每个
  IOCTL_STORAGE_QUERY_PROPERTY 在 dispatch 分配 24B ctx、完成释放。
  可换 NPAGED_LOOKASIDE_LIST,当前查询频率下不值得。
