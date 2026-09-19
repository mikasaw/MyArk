# MyArk 正式 ROADMAP

- **建立日期**: 2026-09-15
- **对齐基准**: 内部同类工具对标矩阵（不入发布树；差距结论已折入 R1-R3 各项）
- **开发纪律**: 每项先在 `scripts/verify_core.py` 加断言（先断言后实现），实现后经子代理代码验收 + 虚机实机回归全绿方可提交；变更面一律走 SAFETY_TOKEN + EVAL_GATE。
- **回归矩阵基线**: Win10 1903 (18362) 133 项全 PASS ✅ ｜ Win11 23H2 (22631) 133 项全 PASS ✅ ｜ 24H2 待虚机

---

## 当前完成基线（截至 2026-09-15）

30 模块 / 42 协议头定义 116 个 IOCTL（注册分发面约 94）/ 137 项虚机断言。进程与线程全套（枚举/终止/挂起/PPL/完整性/可见性/DKOM/注入 DLL/CrossView/详情）、物理与虚拟内存读写+扫描、句柄/ALPC/Section、SSDT 枚举、回调枚举注销、WFP、win32k/键盘探针、存储/设备五件套、安全姿态三条、WSL/HWID 基座/调试输出/BugCheck 诊断/Safety 门/Preflight、R3 file 五命令、history 加密、DPI 缩放。

---

## Phase R1 — 高频刚需补齐（P0）

| # | 项目 | 交付物 | IOCTL 面 | 门控 | 验收标准 | 预估 |
|---|------|--------|----------|------|----------|------|
| R1-1 | 注册表 R0 读/枚举 | dyndata 或新 registry 模块 IOCTL：READ_VALUE / ENUM_KEY | 0x823/0x840 语义（自行编码） | 只读 | verify 断言：读 HKLM 已知值 + 枚举键数 ≥1 | 1 天 |
| R1-2 | 注册表 R0 写/删/建/重命名 | SET_VALUE / DELETE_VALUE / CREATE_KEY / DELETE_KEY / RENAME_VALUE / RENAME_KEY | 0x841-846 语义 | TOKEN+GATE | 写→读回→删→确认不存在 + 重命名往返，5 断言 | 1.5 天 |
| R1-3 | R0 文件删除/查询 | DELETE_PATH（Disposition→DispositionEx→Section flush 三级）/ QUERY_FILE_INFO | 0x804/0x812 语义 | TOKEN+GATE；锁定文件走 Section flush 分支 | 对被占用文件删除的降级路径断言 | 1.5 天 |
| R1-4 | Inline Hook 扫描 | kernel 模块 SCAN_INLINE_HOOKS（E9/EB/FF25/MOV RAX+JMP 形态分类，命中需落在已知模块内） | 0x81F 语义 | 只读 | 对 ntoskrnl .text 全量扫描 0 命中断言（干净机）+ 人工 hook 一处后命中断言 | 2 天 |

**R1 出口标准**: verify_core 新增 ≥10 断言全绿；1903 + 22631 双 build 回归无退化。

---

## Phase R2 — 内核深度 + 对抗强化首批（P1）

> 进度：R2-1 ✅（2026-09-15，PATCH_INLINE_HOOK 0xE21 + QUERY_PATCH_TARGET
> 0xE22，verify 新增 PATCHHOOK 段 10 断言，1903/22631 双 build 全绿；
> 验收回路打在驱动自身哑函数上，ntoskrnl 扫描总数不变作代理断言）。
> R2-2 ✅（2026-09-15，ENUM_IAT_EAT 0xE23——EAT 出像 RVA + IAT 非映像目标
> 判定，verify 新增 IATEAT 段 7 断言，ntdll EAT 2379 / kernel32 IAT>50
> 全零 hook，双 build 全绿）。
> R2-3 ✅（2026-09-15，QUERY_SHADOW_SSDT 0xE24——ntoskrnl 内定位
> KeServiceDescriptorTableShadow 相邻双描述符（字段布局经 KDNET 实证），
> 4 字节带符号表基址相对偏移走查，1903=1024/1258 零 suspect、
> 22631=1024/1458 零 suspect，双 build 全绿）。
> R2-4 ✅（2026-09-16，QUERY_DRIVER_INTEGRITY 0xE25——KeIpiGenericCall
> 全 CPU 快照（GDT/IDT 基址+量测、LSTAR/CSTAR/STAR/SFMASK、CR0/CR4）+
> UnloadedDrivers 证据；KVA Shadow 窗口向下扩 4MB（KDNET 实证）；
> PiDDB 如实降级声明；verify 新增 INTEGRITY 段 3 断言，双 build 全绿）。
> R2-5 ✅（2026-09-16，FORCE_UNLOAD 0xE26——token('NRK2')+FORCE 双门、
> 启动关键黑名单、ZwUnloadDriver、模块表闭环回读；新增 MyArkTestDrv
> 测试驱动工程并入流水线；verify 新增 TESTDRV 段 8 断言，双 build 全绿）。
> R2-10 ✅（部分，2026-09-16，FILEINTEG 0xE12/0xE13——QUERY 只读标签查询
> 全量交付并验证（icacls 阳性 fixture + label-less 负例）；SET 写路径
> 因 Se wedge 降级为确定性 NOT_SUPPORTED（KNOWN_ISSUES 2026-09-16），
> 延迟实现保留 #if 0 待 KDNET 调试轮；双 build 全绿）。
> R2-8 ✅（2026-09-16，stealth taskmgr-hijack——IFEO Debugger 重定向，
> 纯 R3（client/taskmgr_hijack.py + CLI stealth 子命令），所有权标记防
> 误删外来值；verify 新增 TASKMGR 段 4 断言（真实 spawn 双向验证），
> 双 build 全绿）。
> R2-7 ✅（2026-09-16，文件监控 minifilter——FILEMON CONTROL/DRAIN/STATUS
> 0x815-0x817：90_filemon 模块在 DriverEntry 上下文自建 Instances 键并
> FltRegisterFilter，post-op 采样 CREATE/删除 disposition 进 256 槽环形
> 缓冲，CONTROL token 门控（'FMR1'），DRAIN/STATUS 只读；事件路径为
> NT 规范化名、C_ASSERT 钉 568 字节 wire 步长；加载通道必须 legacy
> sc start（type= filesys），fltmc load 会因 FLTMGR 接管 DriverUnload
> 导致 0xCE（KNOWN_ISSUES 2026-09-16）；verify 新增 FILEMON 段 10 断言，
> 双 build 全绿）。
> R2-9 ✅（2026-09-16，文件/注册表重定向——SET_RULES/QUERY_STATUS 0x827/0x828：
> FILE 规则走 filemon pre-create 换 FileName（卷相对余量，替换块随 FILE_OBJECT
> 保留，泄漏以命中数为界）；REG 规则为 CmCallback 值级改写（pre 存 CallContext、
> post 改 PARTIAL/FULL + BUFFER_OVERFLOW 重试；pre-open 改 CompleteName 在
> 18362 不被采纳——CM 先解析后回调）；TOKEN('RRD1')+GATE、默认不激活、CLEAR
> 恢复；verify 新增 REDIRECT 段 8 断言，双 build 全绿。
> 同轮修正 R2-7 遗留的卸载缺陷：FltRegisterFilter 接管 DriverUnload 后
> EvtDriverUnload 不再执行——新增 FilterUnloadCallback 做全驱动清理后
> sc stop 闭环；服务类型回退 type= kernel（filesys 型会被异步卸载，
> KNOWN_ISSUES 2026-09-16 晚）。
> R2-11 ✅（2026-09-16 晚，重设计后落地）：死锁根因定案——旧 ASK_WAIT 把
> 轮询请求驻留在顺序队列里饿死全部 IOCTL（"停在 CORE QUERY_MODULES"即
> 首批 IOCTL 冻结），叠加 notify 内无限期等待冻结创建管线。重设计：
> ASK_WAIT 非阻塞快照轮询（绝不驻留队列）、notify 内驻留限时 5s
> fail-open、槽位表 ICX 预约 + SynchronizationEvent、CANCEL 全量 flush；
> verify 新增 ASK 段 7 断言（DENY/ALLOW/CANCEL/TIMEOUT/队列存活），双
> build 全绿。已知代价：驻留窗口内全系统创建停顿 <=5s（KNOWN_ISSUES）。

| # | 项目 | 交付物 | IOCTL 面 | 门控 | 验收标准 | 预估 |
|---|------|--------|----------|------|----------|------|
| R2-1 | Inline Hook 修复 | PATCH_INLINE_HOOK（expected/restore 字节校验，MDL 改写） | 0x820 语义 | FORCE 必需 | 修复 R1-4 的人工 hook 后扫描归零 | 1.5 天 |
| R2-2 | IAT/EAT Hook 枚举 | ENUM_IAT_EAT_HOOKS | 0x821 语义 | 只读 | 对 ntdll 导出表扫描断言 | 1 天 |
| R2-3 | Shadow SSDT | ENUM_SHADOW_SSDT（win32k 表，R3 探针辅助定位） | 0x81E 语义 | 只读 | 22631 上枚举数 >0 断言 | 1 天 |
| R2-4 | 驱动完整性 | IDT/GDT/MSR/CR0/CR4 只读快照 + UnloadedDrivers/PiDDB 证据 | 0x849 语义 | 只读 | 断言：字段齐全 + 值域合理；无 PDB 时降级声明 | 2 天 |
| R2-5 | 强制卸载驱动 | FORCE_UNLOAD_DRIVER（preflight→ZwUnload→fallback 三级 + 卸载后闭环验证） | 0x826 语义 | TOKEN+GATE+FORCE | 对自装测试驱动（非 MyArkCore）卸载并验证消失 | 1.5 天 |
| R2-6 | 回调拦截规则引擎（首批：进程创建 DENY/LOG_ONLY） | SET_CALLBACK_RULES + RUNTIME_STATE | 0x880/0x881 语义 | TOKEN+GATE | 规则命中断言（记日志/DENY 生效）+ 清理恢复 | 3 天 |
| R2-7 | 文件监控（minifilter） | FILE_MONITOR_CONTROL/DRAIN/STATUS（IRP_MJ_CREATE/SET_INFORMATION 采样） | 0x815-817 语义 | 只读 drain | 对自建文件创建/删除事件 drain 断言 | 3 天 |
| R2-8 | **对抗强化 T-A：任务管理器劫持** | myark-cli stealth taskmgr-hijack --install/--uninstall/--status | 纯 R3（IFEO 注册表） | TOKEN+GATE(AUDIT) | install→taskmgr 拉起 myark-ui→uninstall→恢复，3 断言 | 0.5 天 |
| R2-9 | 文件/注册表重定向落地 | redirect 模块 SET_RULES/QUERY_STATUS 实装（minifilter CREATE 改名 + Cm 回调 bypass） | 0x827/0x828 语义 | TOKEN+GATE，默认不激活 | 规则命中断言 + 关闭后恢复 | 2 天 |
| R2-10 | R0 文件完整性设置 | SET_FILE_INTEGRITY（Win32/UNC 路径规范化为 NT 路径） | 0x84D 语义 | TOKEN+GATE | 设置→读回断言 | 0.5 天 |
| R2-11 | 回调 ASK_USER 交互决策（wait/answer/cancel，依赖 R2-6） | WAIT_EVENT / ANSWER_EVENT / CANCEL_PENDING | 0x882-884 语义 | TOKEN+GATE | 挂起→应答 DENY 断言 + 超时取消断言 | 1 天 |

**R2 出口标准**: 新增 ≥25 断言全绿；双 build 回归无退化；所有变更操作审计留痕（history 加密格式）。

---

## Phase R3 — 广度补全 + 对抗强化二批（P2）

| # | 项目 | 说明 | 预估 |
|---|------|------|------|
| R3-1 | **对抗强化 T-B：HWID 伪装细分 ✅（2026-09-17）** | 0x752 QUERY_SPOOF_STATUS / 0x753 SET_SPOOF_CONFIG：disk serial/partition(MBR 签名+GPT id)/mountmgr UniqueId 完成例程改写 + GPU 注册表改写，DRY_RUN→APPLY(双标志门)→RESTORE 回探闭环，SAFETY_TOKEN 门控；verify HWID 段 17 断言，1903 全绿 | 2-3 天 |
| R3-1b | **HWID 续作：0x83 标识符 ✅ + ARP 改写 ✅（2026-09-19）** | 0x83（StorageDeviceIdProperty/VPD 0x83）类 6：完成例程长度门控改写 + 探测，1903 NVMe 无标识符→契约级拒绝验证。ARP 类 5：nsiproxy 捕获工具（0x754）+ **改写落地**——完成例程内 RW 缓冲（NSI 0x12001B count×32，记录起点 +0x80）全缓冲匹配原 MAC→ProbeForWrite 替换，值契约 16B {ip, 原 MAC, fake}；Tier C profile 18362/18363/22631（guest 逐行解码实证同构）；verify roundtrip 7 断言双机全绿（fake 进表/原 MAC 消失/RESTORE 确定性复原）。改写仅 NSI 用户缓冲，内核邻表缓存零接触 | 2 天 |
| R3-2 | **对抗强化 T-C：R0 shellcode 注入 ✅（2026-09-16 晚）** | 0x877 INJECT_SHELLCODE：ZwAlloc→MmCopyVirtualMemory→回读校验→ZwProtect(ER)→KeInsertQueueApc USER APC（ZwCreateThreadEx 非导出；目标线程须可警醒）；≤256KB；PPL 天然拒绝；TOKEN 门控；verify INJECT 段 4 断言含交付证明，双 build 全绿 | 1-2 天 |
| R3-3 | 定时器/DPC 枚举 ✅（2026-09-17） | 0x8A4 逐 CPU TimerTable（TimerExpiry+桶，解码 KiWaitNever/Always 混淆的 KTIMER.Dpc）+ 0x8A5 DPC 队列快照；Tier C 双构建 profile（18362/22621，KDNET 实测）；1903 实测 170 timers owner 全解析；verify TIMERDPC 2 断言双绿 | 2 天 |
| R3-4 | PspCidTable 全表 + DKOM 隐藏检测 ✅（2026-09-17） | 0xA0D 逐页走查 PspCidTable（Tier C profile 18362=0x574530 / 22621=0xD1EC30），条目解码 obj=(entry>>16)\|0xFFFF…，ObGetObjectType 判别进程/线程，join ActiveProcessLinks 标记 HIDDEN；DKOM hide 往返双绿；修复既有 DKOM 蓝屏（0x1D8 Tier C 硬编码偏移改 Tier B 运行时发现）；内核对象/IPC 摘要留后续 | 2 天 |
| R3-5 | 进程/线程 RUNTIME_FIELDS 采样补全 ✅（2026-09-16 晚） | 0xA03=ProcessVmCounters 精确长度级联 {80,88,72,128}+CycleTime(class 26)；0xA12=KeQueryRuntimeThread+Tier C StateFlags；verify RUNTIME 段 3 断言，双 build 全绿 | 1 天 |
| R3-6 | 安全审计广度 ✅（2026-09-17） | 0x7D3 SECURITY_POSTURE：CPUID hypervisor 探测 + VBS/HVCI 注册表三态 + AppLocker SrpV2 执法状态 + WDAC 活动策略文件计数（Zw 目录枚举，与 guest 对账一致）+ BAM 服务状态；双 build 全绿 | 1.5 天 |
| R3-7 | Minifilter 清单 + 旁路 PID ✅（2026-09-17） | 0x818 FltEnumerateFilters+ASI 清单（11 项实测含自身 altitude）；0x819 采样器旁路 PID（token 门控，ADD/REMOVE/CLEAR/QUERY + BypassDrops 计数）；双 build 全绿 | 1.5 天 |
| R3-8 | mutation 事务化 ✅（2026-09-17） | 0x732 PREPARE / 0x733 COMMIT / 0x734 ROLLBACK / 0x735 TX_LIST：Flags2 mask-and-set 事务化 + 32 项审计环；PPL 字节写就绪；verify MUTTX 6 断言双 build 全绿 | 2 天 |
| R3-9 | ObCallbacks STRIP_ACCESS 反杀 ✅（2026-09-17） | 0x723 SET / 0x724 STATUS：ObRegisterCallbacks(PsProcessType) 预操作剥 0x087B 七位危险权限（TERMINATE/CREATE_THREAD/VM_*/DUP/SUSPEND），KernelHandle 豁免，token 门控 ADD/REMOVE/CLEAR + 计数器；verify OBPROTECT 6 断言 + MATRIX 两行，双 build 全绿；修复 WFP 0x720 撞号 P0 | 2 天 |
| R3-10 | win32k 补全（定时器/事件钩子/窗口详情） | 按需 | 2 天 |
| R3-11 | CE 内存编辑集成（可选，依赖 R0 读写已有面） | CE 插件桥 → 驱动读写 IOCTL | 3 天 |
| R3-12 | modules/* UI 自建 Treeview 接入 scaling.py（B3 残留）✅（2026-09-16） | 8 模块 9 个自建 Treeview 10 处列宽调用点全部改 scaled_width（network width=0 自动重置除外）；新增 2 个源码级守护单测；client 全套 865 passed | 0.5 天 |
| R3-13 | ReadDwell 系迁移 MmCopyMemory（B4 残留）✅（2026-09-16） | `MyArkKernelReadDwellBytes` 与 `MyArkDynDataReadDwell` 改 MmCopyMemory(MM_COPY_MEMORY_VIRTUAL)，返回实际拷贝字节数（顺带修复 return 8 脏契约与慢路径 MAX 失真）；双 build 全绿；全仓其余 25+ 处 MmIsAddressValid 门控裸读为候选后续加固项 | 0.5 天 |
| R3-14 | CPU/硬件信息（逐核 CR/MSR/IDTR/GDTR）✅（2026-09-17） | 0x84A IPI 广播快照：CR0-4/CR8 + GDT/IDT + MSR 白名单（LSTAR/EFER/PAT/APIC base），只读；新模块 65_cpu；verify CPU 段 5 断言双 build 全绿 | 1 天 |
| R3-15 | WFP inventory / NDIS 链枚举 ✅（2026-09-16） | 0x8A2 NetService 类注册表走查（已装过滤实例，兼容 26100+ GUID 记录布局）+ 0x8A3 PsLoadedModuleList PE 导入解析（fwpkclnt/ndis 能力位 + tcpip.sys 确定性断言）；verify WFPINV 段 + MATRIX 52 项双 build 全绿；验收揪出 PE 导入目录偏移 P0（0x70 Export→0x78 Import）已修；运行时协议无 INF 拿不到绑定句柄，实时挂载序留后续 | 1 天 |
| 暂缓 | ARKLight 轻量版 | Tk 精简入口替代方案评估后再排期 | - |

---

## 明确不做 / 设计性拒绝

- 免杀、加壳、加密器、载荷生成器、加载器链——不提供任何 weaponized 载荷与规避检测链的辅助设施；注入类仅交付 IOCTL + 参数 + 良性测试 stub。
- 同类工具常见的"内核任意写"面（任意内核地址裸写）——MyArk 物理写已限定 RAM 区间校验，保持。
- 破坏 PatchGuard/绕过 HVCI 类能力。

## 外部依赖 / 待办

- **24H2 (26100+) 虚机**: ProfileMatched 分支（Tier C 真实读数）唯一剩余验证环境——需要新建一台 24H2 虚机（现有 Win11 虚机为 23H2/22631）。
- 同类开源 ARK 工具发布新版本时，在内部重扫对标矩阵（不入发布树）。
