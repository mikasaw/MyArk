# CRASH_DEBUG_LOG — MyArk 驱动 VM 调试史

> 规则（AGENTS.md §2）：每一轮 VM 调试必须追加一条；每条必含五段：
> **现象 / 与参考的对比 / 修复尝试 / 关键决策回顾 / TODO**。
> 只记「发生了什么、依据是什么、为什么这样修、下一步」，不复制代码。

---

## 2026-09-08 — S11.2 首轮 VM 运行时回归（test2 / Win10 1903 / build 18362）

### 现象
1. `sc start MyArkCore` 失败链，每修一层露出下一层：
   577 数字签名 → 2 找不到指定的文件 → 127 找不到指定的程序 → 87 参数错误
   → 1 函数不正确。
2. 加载成功后，actions 7 个 IOCTL 用 R3 正确签名的 HMAC token **全部**
   ACCESS_DENIED；篡改 / 过期 token 同样被拒，正负路径无法区分。
3. 过期 200s 的 token 被**放行**（与文档 ±120s 不符）。
4. 回归中途 guest 两次「冻结」：Tools 未运行、vmrun 全部超时。

### 与参考的对比
- 协议参照 `shared\driver\MyArkSafetyToken.h`（±120s、72B token、HMAC-SHA256）
  与 R3 `client\src\myark\client\safety_token.py`（签名实现）→ 内核时间窗常数
  实为 1200s，常数写错（12000000000 应为 1200000000）。
- 期望：有效 token → ResultCode=DEFERRED(4)；实际恒 DENIED → 校验器读到的
  token 与 R3 发出的不一致（后续断点证实是共缓冲被清零）。
- 两个不同 KMDF 版本的构建稳定报 87 → 排除 KMDF 绑定，转向 DriverEntry 内部。
- 导入表按 guest 的 `ntoskrnl.exe` 导出比对（dumpbin 双向）→ 发现
  `ExAllocatePool2`（Win11 起才导出）与 `bcrypt.dll`（内核态不存在）两处硬伤。

### 修复尝试（每次只改一处 → 重编 → 重测）
1. testsigning + `WDKTestCert www` 入 guest Root/TrustedPublisher → 577 消失。
2. um `bcrypt.lib` → km `cng.lib`（内核导入 `cng.sys`）→ 报错 2 消失。
3. `ExAllocatePool2` → 新增 `shared\driver\MyArkPoolAlloc.h` 封装
   `ExAllocatePoolWithTag`（局部关 C4996），6 处调用点全替换 → 报错 127 消失。
4. SDDL 拼写 `O:SYG`+`G:SYG`（实际连成 `SYGG:SYG`）→ `O:SY`+`G:SY` → 87 消失。
5. 移除 `WdfDeviceCreateDeviceInterface`（控制设备上被 KMDF 以
   STATUS_INVALID_DEVICE_REQUEST 拒绝；R3 只走符号链接）→ 加载 RUNNING。
6. actions 7 处改为**先验 token、再清输出**（METHOD_BUFFERED 输入/输出共用
   SystemBuffer，先清零等于抹掉 token）→ 正路径恢复 DEFERRED。
7. 时间窗常数改 1200000000 → 200s 旧 token 正确拒绝。
8. `WRITE_PHYSICAL` 先取输入缓冲再做 RAM 范围校验 → 排除 opt-in 路径空指针 BSOD。

结果：`verify_core.py` 重写为断言式框架，**50 PASS / 0 FAIL**，S6 清单
①②④⑤ 全过。

### 关键决策回顾
- **停止逐层猜错误码、改用断点实测**是本轮转折点：在 `MyArkSafetyTokenValidate`
  入口 dump token 与会话密钥、在 DriverEntry 四个子调用上 `gu` 看返回值，
  两个根因（87/1 与 token 恒拒）在断点下立刻现形；此前纯靠猜浪费了多轮
  编译—部署循环。
- METHOD_BUFFERED 共缓冲是内核侧最重要的洞察：清零输出 = 清零输入。
- 冻结判活：残留 `kd.exe`（其它项目、与克隆机同 KDNET key）误连 test2 并
  break 住 guest——**不是驱动问题**。决策：为 test2 换独立 key + 端口 50001；
  此后冻结一律先判活（kd 能否 break in）再决定 reset。
- 排除法顺序固化为：签名 → 导入表（dumpbin × guest 导出）→ KMDF 绑定 →
  DriverEntry 内部（调试器）。

### TODO
- [ ] process / thread 变更面 8 IOCTL 的 token 正/负路径 —— 需 Win11 24H2 guest。
- [ ] memory 虚拟路径 7 IOCTL（含 `WRITE_VM` 空指针修复实测）—— 扩 verify_core.py。
- [x] 86_safety 撞码（0x800 与 core GET_VERSION 冲突）修复 + 该模块回归。
      已完成（2026-09-15 S11.5）：EVAL_GATE 迁至 0xD00，1903 实测 registered=True。
- [ ] 其余 46 个只读 IOCTL 烟测（清单见 KNOWN_ISSUES S6）。
- [ ] kmod 是否编入 full profile 的决策。

---

## 2026-09-14 — S11.3 memory 虚拟路径 + 全量 IOCTL 矩阵回归（test2 / Win10 1903 / 18362）

### 现象
1. 新写的 `verify_core.py` 第 (6) 段（memory 虚拟路径 7 IOCTL）与第 (7) 段（全量
   矩阵 51 IOCTL）首跑即**蓝屏**：guest 16:35:39 重启，minidump
   `091426-12281-01.dmp`，BugCheck 事件 16:36:04。
2. 修复崩溃后，memory 虚拟路径整段失败：READ_VM 报 122、WRITE_VM 写入长度
   只有 12 字节、TRANSLATE_VA/QUERY_PT_ENTRY 恒 `STATUS_NOT_FOUND` 且 `pml4e=0`。
3. 矩阵段 5 个 IOCTL 报 Win32 错误 1（storage MOUNTMGR、callback
   REMOVE/RESTORE/BACKUP、bugcheck RENDER_DIAG），与"未注册"无法区分。
4. 舰队脚本侧：`vm_alive_check` 在 VM 关机时误报 "guest alive"；
   `runProgramInGuest` 的 `sc query`/`echo` 输出在主机侧恒为空。

### 与参考的对比
- minidump 分析（windbg-mcp `!analyze -v`）：`BUCKET_ID:
  AV_MyArkCore!MyArkStorageSnapshotDevices`，栈为
  `MyArkStorageIoctlQueryVolumeStack → MyArkStorageSnapshotDevices →
  nt!IoEnumerateDeviceObjectList → 读地址 0x8 → 0x0A (IRQL_NOT_LESS_OR_EQUAL)`。
  对照 WDK 文档：`IoEnumerateDeviceObjectList(DriverObject, ...)` 的
  DriverObject 是必填参数，函数内部解引用它；代码传了 NULL 以求"枚举全部设备"。
  同文件注释还写着这个用法是为了避开未文档化的 offset——方向对、API 选错。
- 同源检查发现 `24_device_audit/devaudit_ioctl.c` 有逐字相同的拷贝（5 个
  handler 共用），矩阵先打到 0xC30 才没轮到它，否则 0xC40..0xC44 同样必崩。
- 协议对照 `shared/driver/MyArkMemoryIoctl.h` + ctypes 布局复核：`Data[1]` 在
  `sizeof` 里带尾部对齐填充（READ_VM_OUTPUT sizeof=20/Data@16、
  WRITE_VM_INPUT sizeof=32/Data@24），驱动用 `sizeof` 当载荷起点，
  长度与偏移错开 8 字节。
- `TRANSLATE_VA` 实测（KDNET 断点）：Cr3=0x27BEC000 与目标 python 的
  `!process` DirBase **完全一致**（CR3 读取正确）；`!pte <va>` 显示 PXE/PPE/
  PDE/PTE 全有效，`!dq 0x27BEC020` 读到的值与 `!pte` 的 PXE **逐位相同** ——
  即"地址对、内存里有数据、只有驱动读不到"；再断 `MmMapIoSpace` 返回处，
  `rax=0`（NULL）。结论：`MmMapIoSpace` 对页表页（RAM 页）在本 guest 上恒失败。

### 修复尝试
1. **storage / device-audit**：改为枚举 `\Device` 对象目录
   （`ZwOpenDirectoryObject` + `ZwQueryDirectoryObject`）配合
   `ObReferenceObjectByName(*IoDeviceObjectType)` 逐个取引用，列表带引用返回、
   由 `MyArkStorageFreeDeviceList` / `MyArkDevAuditFreeDeviceList` 统一释放
   （3 + 5 个调用点全部改造）。→ 蓝屏消失。
2. **memory 模块 7 处共缓冲清零**：`QueryVm/ReadVm/WriteVm/TranslateVa/
   QueryPtEntry` 与两个 SCAN 在清零输出头之后再读输入，METHOD_BUFFERED 下
   等价于把 Pid/Address/Va/Signature 抹零。全部改为**先快照输入到局部变量、
   再清输出**。
3. **写路径长度**：`wantSize` 与 `FetchInputBuffer` 一律改用
   `FIELD_OFFSET(..., Data)`，消除 sizeof 填充造成的 8 字节错位。
4. **页表 walker**：先用整页 `MmMapIoSpace` 仍返回 NULL；最终改用文档化的
   `MmCopyMemory(..., MM_COPY_MEMORY_PHYSICAL, ...)` 直接读物理内存，
   无需映射、失败即返回 0（上层报 not present）。
5. **矩阵判据**：以 capability 表成员为准（注册即可达），不再用 Win32 错误码
   区分"未注册"与"handler 合法拒绝"——callback 的三个保留桩按设计返回
   `STATUS_NOT_IMPLEMENTED`，其 Win32 映射同样是错误 1。
6. **探针自身 bug**：READ_VM 数据偏移改 16（不是 20）；WRITE_VM 输入按
   "头部 24 + 载荷" 构造；负向扫描改用 `os.urandom(16)`；矩阵尾部的
   PING 探针缓冲放大到 4 KiB。
7. **舰队**：判活改为"主机生成随机 token → guest 回显 → 拉回校验"
   （vmrun rc 与陈旧文件都无法伪造）；新增 `vm_env_check`（部署物哈希/
   testsigning/证书/KDEBUG 端口）、`vm_crash_check`（boot 时间 + minidump +
   BugCheck 事件）、`vm_guest_exec`（任意 guest 命令 + 文件通道回读）。

结果：**117 PASS / 0 FAIL / 0 SKIP**，S6 九段全绿；页表翻译拿到真实值
（pa=0x7DB3FB30、pml4e=0xA00000112210867、level=4）。

### 关键决策回顾
- **崩溃第一时间做 dump 取证而不是重试**：`vm_crash_check` 拉 boot 时间 +
  minidump + BugCheck 事件，`!analyze -v` 一步给出 bucket
  `AV_MyArkCore!MyArkStorageSnapshotDevices` 与源码行，避免了大范围猜测。
- **"两个记录互证"定位读失败**：先用 `!process` 验证 CR3 与 DirBase 一致、
  再用 `!pte` + `!dq` 证明物理内存里确有正确值，最后断在 `MmMapIoSpace`
  返回处看 rax=0 —— 三步把"驱动读不到"与"地址错"彻底分开。
- **同源拷贝必须全量排查**：storage 修好后立刻 grep 同 API 的其它副本，
  果然在 device-audit 找到 5 处（矩阵顺序掩盖了它）。
- **经验固化**：vmrun 不转发 guest stdout（所有证据走文件通道）、vmrun 失败
  返回 -1 使 `if errorlevel 1` 失效、快照回滚会还原磁盘与 BCD（部署物与
  KDNET 需要重建）——三条都写进 AGENTS.md §1。
- KDNET 端口因回滚退回 50000/旧 key，本轮调试即以该配置进行（可用但未隔离）；
  `build/vm_kdnet_set.bat` 保留用于恢复 50001 专用配置。

### TODO
- [ ] `WRITE_PHYSICAL`/`READ_PHYSICAL` 对**非页对齐** PA 同样受 MmMapIoSpace
      限制（本轮只测了页对齐地址）；考虑统一改走 MmCopyMemory。
- [ ] process/thread 变更面 8 IOCTL 正/负 token 路径 —— 需 Win11 24H2 guest。
- [x] 86_safety 撞码（0x800 与 core GET_VERSION）修复。
      已完成（2026-09-15 S11.5）：迁至 0xD00 块，详见下方 S11.5。
- [x] 快照回滚后 KDNET 专用 key/端口需重新应用（`vm_kdnet_set.bat`）+ 重启。
      已完成（2026-09-15 S11.5）：BCD 两次回读 port 50001 + 重启后 env_check 全 OK。
- [ ] 页表 walker 的 LA57 与 EPROCESS 偏移仅在 18362 验证过，24H2 待复测。

---

---

## 2026-09-14 (晚) — 跨版本改造：去 build 门禁 + 运行时偏移解析（test2 / 1903）

### 现象
1. 用户指出：process/thread 模块按 build 门禁（仅 26100..26299）等于"换个系统就缺功能"，
   要求兼容不同 Win10/Win11。改造后在 1903 上模块首次开始执行，**立刻连爆两个蓝屏**：
   - 19:02 `091426-12140-01.dmp`：`0x50 PAGE_FAULT_IN_NONPAGED_AREA`,
     bucket `AV_R_(null)_MyArkCore!MyArkProcessIoctlEnum`, 崩溃在 `nt!_chkstk`。
   - 19:58 `091426-10875-01.dmp`：同样 `0x50`, bucket
     `AV_R_(null)_MyArkCore!MyArkProcessCollectViews`, 崩在
     `process_query.c` 的 `mov r8d,[rcx]`。
2. 修复后 ENUM/CROSSVIEW 返回 NOT_SUPPORTED（偏移未解析），ENUM_THREAD 返回 NOT_FOUND。

### 与参考的对比
- 导出表核对（18362 实测）：`PsGetProcessId/InheritedFromUniqueProcessId/
  ImageFileName/Protection/SignatureLevel/SectionBaseAddress/ExitStatus/
  CreateTimeQuadPart/ThreadId/ThreadProcess/ThreadCreateTime` **全部在 1903 就已导出**
  → 绝大多数 EPROCESS/ETHREAD 字段根本不需要偏移；只有两个链表偏移没有访问器。
- 第一个崩溃：`MYARK_PICKED_LIST` 含 `Items[1024]`（每项 160B）≈ **160 KiB 栈局部**，
  加上 `ULONG publicPids[2048]`（8 KiB），而内核栈只有 12 KiB；`_chkstk` 探测栈页
  失败即 0x50。该代码路径因门禁从未执行，问题一直潜伏。
- 第二个崩溃：`ZwQuerySystemInformation(SystemProcessInformation)` 的记录链走查
  `cursor += next` **无任何边界检查**；`!analyze` 的反汇编显示循环头即为
  `mov r8d,[rcx]` / `add rcx,r8` 回跳。链一旦异常就走出缓冲读到野地址。
- 发现（discovery）的两次误判：早期版本把 `EPROCESS+0x8` 当成 ActiveProcessLinks
  （仅校验"某跳恰好是 PID 4"，巧合即可通过）；加强后真链又被"每跳 PID 必须非零"
  误杀——**Idle 进程 PID=0 也在链上**。

### 修复尝试
1. **栈 → 模块级工作缓冲**：process（2 处）与 thread（2 处）共 6 个大结构移出栈，
   改为模块全局（顺序队列保证单线程使用；与既有 module-range 缓存同模式）。
2. **两条 SPI 走查加边界**：以 `ZwQuerySystemInformation` 返回的实际长度为准，
   `next` 必须 ≥ 最小记录且不越过 `limit`，否则记录并停止；线程子数组另加
   `threadCount` 上限与"必须落在记录内"校验，且仅在 `ProfileMatched` 时读取
   （该子数组的条目布局按 24H2 推导，其它 build 降级为空而不是读错布局）。
3. **三层偏移方案落地**（`process_offsets.c/.h`）：Tier A 导出访问器（宏）、
   Tier B 运行时发现两个链表偏移（自校验）、Tier C 信息类字段按 profile 读、
   非匹配 build 一律读 0 并由 DETAIL 的调试字段回报实际解析值。
4. **发现判据加强**：ActiveProcessLinks 需满足"自身 PID 回到链上 + 含 PID 4 +
   ≥3 个不同且合理的 PID + 每跳容器经 PsGetProcessId 校验"，并容忍 PID 0；
   探测上限从 8 跳到 1024 跳（列表是环形的，System 可能在几十跳之外）。
5. 门禁移除：两个描述符改为调用解析器并**始终加载**；枚举类视图在偏移未解析时
   返回 STATUS_NOT_SUPPORTED（清晰降级），不再让整个模块缺席。

### 关键决策回顾
- "换取证而非猜测"再次成立：两个蓝屏都用 `vm_crash_check`（boot 时间 + minidump +
  BugCheck 事件）先确认，再用 `!analyze -v` 的 bucket + 反汇编定位到具体指令，
  没有靠猜改代码。
- 把"卡住 30 分钟"误判为 condrv 陷阱的教训：**实测是蓝屏重启导致 vmrun 阻塞**；
  长挂的 guest 调用应先查 minidump/boot 时间，再怀疑执行通道。
- `< NUL` 必须覆盖命令链的**每一段**（只挂最后一段会让未重定向的前缀永久挂住），
  已写入 AGENTS.md §1。
- 解析值通过 DETAIL 的既有调试字段回报给 R3（`ActiveProcessLinksOffset` /
  `ThreadListHeadOffset`），让"发现是否成功"可被测试直接断言——不需要调试器。

### 当前状态与 TODO
- **已完成**：两个模块在 1903 上 ENABLED（18 个 IOCTL 注册）；身份字段走导出访问器；
  Tier C 非匹配 build 读 0；栈与走查崩溃全部消除（连续 3 轮回归无蓝屏）；
  ActiveProcessLinks 运行时发现成功（本轮实测 0x640）。
- **未完成**：ETHREAD 的 ThreadListEntry / ThreadListHead 发现尚未在 1903 上成功
  （`thread_off=0x0`），因此 ENUM / CROSSVIEW 仍返回 NOT_SUPPORTED（**明确降级、
  不崩溃**）；ENUM_THREAD 返回 NOT_FOUND 同因。
- [ ] 下一步：按 ActiveProcessLinks 同样的"容忍特殊条目"思路复核 ETHREAD 侧发现
      （沿 ETHREAD 的其它 LIST_ENTRY 逐跳验证、放宽 peer 的归属判据），或改用
      "遍历所有 PID 的 PsLookupThreadByThreadId"作为无偏移的线程枚举后备路径。
- [ ] 恢复后重跑：`buildm_run_verify.bat` 应能在 1903 上把
      `(3) process/thread views` 段跑成全绿。

## 2026-09-15 — S11.4 跨版本收口：TID 扫描线程枚举，1903 全绿（Win10 1903 / build 18362）

### 现象
- 上一轮遗留：1903 上 ENUM/ENUM_THREAD/CROSSVIEW 返回 NOT_SUPPORTED / NOT_FOUND
  （ETHREAD `ThreadListEntry/ThreadListHead` 发现失败，`thread_off=0x0`）。
- 把 0xA01 线程枚举换成无偏移的 TID 扫描、`MyArkProcessFillThreadRow` 转成
  Tier A 访问器并重部署后，宿主机侧收到 vmrun 异常退出码 3221225794
  （0xC0000142），且虚拟机处于关机状态——疑似又蓝屏。
- 修复 ENUM_THREAD 后回归仍有一项 FAIL：`ENUM contains this process
  -- pid=4420 count=128`（本轮 guest 共 129 个进程）。

### 与参考的对比
- 按 AGENTS.md §3 先取证再动手：`vm_crash_check` 显示 minidump 列表仍只有
  09-14 的 3 个（16:36 / 19:03 / 19:59）+ 09-08 的 2 个，最新 BugCheck 事件
  仍是 19:59 的 0x50 → **没有新蓝屏**。
- 新拉的 `crash4_mini.dmp` md5 与 crash3.dmp 完全相同（同一文件）；MEMORY.DMP
  的 mtime 19:59 也对应旧崩溃。
- 0xC0000142 的真相：虚拟机 ~21:34 被**正常关机**（nvram 时间戳；测试目录与
  testsigning 完好，排除快照回滚），不是内核崩溃。教训：**vmrun 异常退出码
  ≠ guest 蓝屏**，判定必须走 guest 文件通道证据（minidump 清单 + 事件表）。
- ENUM 截断抖动的对比实验：同一旧脚本连跑两轮先 FAIL 后 PASS → 是列表顺序
  抖动（python.exe 作为最新进程排到第 129 位，被 verify 的 requestedMax=128
  截掉），不是驱动丢进程。

### 修复尝试
1. **TID 扫描线程枚举**（process_ioctl.c 0xA01 + thread_query.c 枚举器）：
   弃用依赖 ETHREAD 偏移的 `MyArkProcessWalkThreadList`，改为
   `PsLookupThreadByThreadId` 遍历 TID 空间 [0, 0x100000)，
   `PsGetThreadProcess` 过滤归属，首次命中后 miss run ≥ 32768 早退。
   实测：`pid=528 count=4 tid=5020 found=True owner=528`。
2. **METHOD_BUFFERED 先零后读**：process/thread 两处 ENUM_THREAD 处理器把
   requestedPid/requestedMax 在清零输出前快照到局部变量。
3. **行填充去 ETHREAD 依赖**：`MyArkProcessFillThreadRow` 全部走 Tier A
   访问器；State/Priority/WaitReason（Tier C）仅 ProfileMatched 时读，否则 0。
   线程行数据在收集阶段快照进模块全局缓冲，填充阶段不再触碰 ETHREAD。
4. **verify_core.py ENUM 上限 128→512**（16+512×792≈405KB 输出缓冲）：消除
   129 进程时自进程被截断的顺序抖动。
5. 部署插曲：.sys 被已加载驱动锁定导致 vm_push_driver 中止——健康态重部署
   必须先 `vm_svc_clean`（Phase 3 流程，非恢复手段）；且 verify 脚本由
   vm_push_driver 推送、vm_run_verify 只执行已部署副本，**改脚本必须重推**。

### 关键决策回顾
- ETHREAD 链表偏移的发现难题被**绕过**而非解决：TID 扫描等价于"用导出 API
  实现的链遍历"，零偏移依赖；代价是 O(TID 空间) 探测（miss 早退控制，实测
  秒级完成 4 线程枚举）。偏移发现（thread_off）仍保留为后续优化路径。
- 证据纪律再次生效：本轮两次"疑似崩溃"（0xC0000142、ENUM FAIL）都没有靠猜，
  分别用 minidump 清单和对比实验定位为"VM 被关机"与"verify 帽太紧"。
- 快照回滚 vs 正常关机的判别：测试目录存在 + verify_core.py 哈希一致 +
  testsigning 在位 → 排除回滚（回滚会清空 myark-test，见 AGENTS.md §1）。

### 当前状态与 TODO
- **1903 全绿**：9 段回归全 PASS 且连续两轮稳定；process/thread ENABLED、
  18 IOCTL 注册；ENUM（126/129 进程）/ ENUM_THREAD / DETAIL / CROSSVIEW
  全部通过，hidden=0 判定正确。
- `thread_off=0x0` 保持：ETHREAD 偏移未发现时相关 Tier C 字段读 0、明确降级，
  不影响上述绿项。
- [ ] Win11 24H2 guest 回归（验证 ProfileMatched 分支与 Tier C 真实读数）。
- [ ] TID 扫描的已知局限记录进 KNOWN_ISSUES S6：极端高 TID 消耗下的扫描成本、
      32K miss 早退阈值下低频线程的可见性。
- [ ] 本次开机后 KDNET 未落在 test2 专用端口 50001（env_check 警告），需要
      `vm_kdnet_set.bat` + 重启修正后再做需要断点取证的轮次。

## 2026-09-15 — S11.5 KDNET 恢复 + safety 撞码迁移（Win10 1903 / build 18362）

### 现象
- 重启后 env_check 报 KDNET 不在 test2 专用端口 50001（仍是共享 50000）。
- `vm_kdnet_set.bat` 连续两次在 [2/5] 失败（"未找到文件"）；修复后又在
  [5/5] 判定前"挂起"数分钟——宿主机侧一个 GNU find 在全盘爬 C:\。
- 86_safety 的 EVAL_GATE（功能码 0x800 与 core GET_VERSION 撞码）自 S7.3
  起一直被 IOCTL 注册表以 STATUS_DUPLICATE_OBJECTID 拒绝，从未可达。

### 与参考的对比
- 两个脚本坑都是 **Git Bash ↔ cmd 互操作**类，与 §4 "make.bat 括号坑"同源：
  ① `if not exist %GDIR% mkdir %GDIR% < NUL & echo ...`——cmd 把 `& echo`
  绑进 IF 分支体，目录已存在（条件为假）时整条链被跳过，标记文件永不落地；
  首次运行（09-08）时目录尚不存在、条件为真，所以潜伏到今天才爆。
  ② 判定段的 `find /c "%KDPORT%"`——宿主机 cmd 从 Git Bash 继承 PATH，
  /usr/bin 的 GNU find 排在 System32 前面，`/c` 被解析为要爬取的路径，
  对整个 C:\ 做 find 遍历。
- 判活探针正常 + `listProcessesInGuest` 正常 → "挂起"不在 guest 侧；
  输出流里的 `find: '/c/ProgramData/...'` 行直接指认了宿主机 GNU find。

### 修复尝试
1. KDNET：`if exist mkdir` 改幂等 `mkdir %GDIR% 2>nul`；计数逻辑改
   `findstr` 过滤 + for 计数循环，避开裸 `find`。BCD 两次回读均
   port 50001 + 专用 key，硬重启后 env_check 全 OK（含 KDNET 项）。
2. safety 迁移（0x800 → 0xD00..0xD0F 空闲块，全仓库功能码提取确认无冲突）：
   `shared/driver/MyArkSafetyIoctl.h` 宏 + `client/.../safety/protocol.py`
   `_ctl_code(0xD00)` + `test_safety_protocol.py` 断言同步 +
   `verify_core.py` MATRIX 增加 EVAL_GATE 探针（45→46 只读项）。
   客户端 pytest 9/9；1903 实测 `safety:EVAL_GATE registered=True ok=True
   err=0 out=16`，9 段回归全 PASS。

### 关键决策回顾
- 选 0xD00 而非 core 块内 0x880：actions 已嵌在 core 0x800..0x8FF 块内
  （0x870..0x876），历史原因保留；新模块一律用独立空闲块，避免再嵌套。
- 宿主机 .bat 的互操作坑记入 AGENTS.md 前先在本轮日志留证：两类坑
  （IF 吞链、GNU find 抢占）都会静默产生错误结果而非报错，比崩溃更危险。
- 部署验证沿用双向 SHA256 + 注册判据（capability 表含 0xD00 即注册成功），
  不依赖 vmrun 退出码。

### 当前状态与 TODO
- KDNET 专用 key/端口 50001 已恢复并随重启生效；safety EVAL_GATE 首次
  真正可达并纳入 MATRIX 覆盖；回归 9 段全 PASS（含 46 只读矩阵）。
- [ ] 无新增遗留；Win11 24H2 guest 回归（T5）仍待舰队参数化。

## 2026-09-15 — S11.6 物理 R/W 改造 + 六连蓝屏（Win10 1903 / build 18362）

### 现象
- T3 目标：READ/WRITE_PHYSICAL 摆脱 MmMapIoSpace（对 RAM 页返回 NULL），
  支持非页对齐 PA。READ 改 `MmCopyMemory(MM_COPY_MEMORY_PHYSICAL)`，
  WRITE 改 `\Device\PhysicalMemory` 区段映射（MmCopyMemory 只读）。
- 部署当晚 guest 陷入**蓝屏循环**：0x3B (c0000005) 共 6 次
  （02:42 / 03:16 / 03:46 / 03:53 / 04:15 / 05:18），每次 boot 后数分钟内
  崩溃。症状高度迷惑：服务键"消失"（1060）、Tools 卡 running 态、
  exec 通道分钟级延迟/挂死、python 输出缓冲丢失（0 字节日志）、
  vmrun 各种超时——一度误判为 Defender remediation 或 VMware 故障。

### 与参考的对比
- 判定路径（AGENTS.md §3 判活三件套 + 拉事件日志）：
  1. `CopyFileFromGuestToHost` 拉回 `System.evtx` + Defender
     Operational.evtx，宿主机 PowerShell `Get-WinEvent -Path` 离线解析
     —— **不需要 guest exec**（exec 通道已瘫时唯一的取证通道）。
  2. Defender 检测（1116/1117）全部是 08-20 的 PCHunter 旧记录 → 假设排除。
  3. System 日志 1001 事件：当晚 6 次 0x3B，Arg2 低 16 位恒为 **0x7405**
     —— 同一指令偏移反复崩溃。
  4. kd 会话 `lm m MyArkCore`（当时以为驱动没加载）+ `!reg querykey` 是
     死胡同；决定性证据是 **minidump**（725KB，秒级拉回）：
     `AV_MyArkCore!MyArkMemoryIoctlWritePhysical+0x149`，
     `mov rdi,[rax]` 且 rax=0，进程 python.exe，
     FAULTING_SOURCE_LINE = memory_physical.c:400（fetch 行）。
- 根因：改造时把 `pa = inBuf->Pa` 快照插到了 `MyArkIoctlFetchInputBuffer`
  **之前**——inBuf 还是 NULL。verify 的 roundtrip 探针先打开
  AllowPhysicalWrite 再调 WRITE_PHYSICAL，恰好越过了最前面的策略门
  （门在 fetch 之前已返回 DENY，掩盖了该路径数天）。
- 崩溃循环的正反馈：崩溃发生在 restore() 之前 → AllowPhysicalWrite 残留；
  但每次重部署 svc_clean 删服务键会连带清掉 Modules\memory 子键 → 值自愈。
- 教训：**蓝屏循环期的一切"环境故障"表象都应先假设是崩溃本身**——exec
  挂死 = Tools 随系统一起半死；"服务消失" = 崩溃打断了部署时序；只有
  dump 是可信的。

### 修复尝试
1. WRITE 处理器重排：算 wantSize（不依赖 inBuf）→ fetch → **fetch 后**
   快照 pa → 后续流程。中间版本把 snapshot 放在 fetch 前导致 C4700
   （fetch 的长度参数依赖 wantSize），正确顺序为
   wantSize → fetch → pa 快照 → 零化输出。
2. READ 处理器：fetch（241 行）先于快照（255 行），顺序本来就对；
   MmCopyMemory 对 RAM 页稳定工作（0x2000 与 0x110000+0x2C 实测通过）。
3. verify_core.py 物理段重构（3 项 → 10 项）：
   - 修复"outside RAM denied"检查里的**无条件 return**——从 S11.3 起
     WRITE 默认拒绝/opt-in/roundtrip 三类检查从未真正执行过（
     except 分支里 check 通过也 return），段(4)长期虚绿；
   - 非对齐读探针：RAM 区间页基址 64B 对齐读 vs +0x2C 非对齐读逐字节
     比对（KUSER 0xFFDF0000 方案废弃——该页在 VMware 的 MMIO 洞里，
     不在 MmGetPhysicalMemoryRanges 内，驱动的 RAM-only 策略拒绝它是
     **正确行为**）；
   - 真实非对齐写往返：VirtualLock 锁页 → TRANSLATE_VA 取 PA →
     WRITE_PHYSICAL 写入 8B 标记（前 2B 是 0x5AA5 标记）→ 驱动读回 +
     用户态 double-check → 写回原值恢复。
4. vm_guest_setup.bat 增加 Defender 排除步骤（幂等）。注意：这是在
   Defender 假设下加入的，事后证明 Defender 无辜——保留作为测试虚机
   的常规加固，但它不是本问题的修复。

### 关键决策回顾
- "换实证而非猜测"在本轮经历了反复：先后误判 0xC0000142/服务消失为
  蓝屏→再误判为 VM 正常关机→再误判为 Defender→最终 minidump 一锤定音。
  **在崩溃循环期，任何间接信号（退出码、服务状态、通道健康）都不可信，
  唯有 minidump + 事件日志离线解析可靠。**
- 事件日志的取证通道：exec 通道瘫痪时，`CopyFileFromGuestToHost` 直接拉
  `winevt\Logs\*.evtx` + 宿主机 `Get-WinEvent -Path` 是完全独立于 guest
  通道的替代路径。
- verify 探针的设计必须尊重驱动的安全策略：KUSER 探针失败不是驱动 bug，
  是探针试图穿越 RAM-only 策略——好策略拒绝越权访问是 PASS 不是 FAIL。

### 当前状态与 TODO
- 修复后连续两轮 9 段全 PASS（133 项，物理段 10 项），guest 无崩溃；
  非页对齐物理读/写在 1903 上端到端工作。
- 遗留见 KNOWN_ISSUES S6（Defender 排除与验证、24H2 回归）。


## 2026-09-15 — R2-1 PATCH_INLINE_HOOK 首航 + 加密 guest 舰队修复（1903 / 22631 双机）

### 现象
- Win11 (22631) guest 上舰队脚本间歇报“此操作需要输入密码”；vm_reset_hard
  显示“[OK] guest ready after 1 polls”（硬重启后 16 秒不可能就绪），随后
  vm_push_driver 报“您没有对文件的访问权限”。
- 第一次 reset 后 wmic os lastbootuptime 仍是旧值——reset 实际没发生，
  判活通过是因为 guest 从未重启，不是因为重启完成。

### 与参考的对比
- AGENTS.md §1 要求判活“正向证据双判据”，但 reset 脚本自身的 reset 调用
  缺 -vp：失败后 liveness poll 打在未重启的 guest 上“通过”。这是判活
  纪律的一个盲区——**probe 证明 guest 活着，不证明重启发生过**。
- vm_win11_verify.bat 把上轮 ad-hoc 的 schtasks /rl highest 流程
  （guest_cmd.txt + elevated_deploy.cmd）固化为舰队脚本，语义逐段等价。

### 修复尝试
1. vm_reset_hard.bat / vm_alive_check.bat 的 vmrun 调用补 %VPARGS%——
   加密 guest（vTPM partial encryption）的**每条** vmrun 子命令都要 -vp。
2. vm_reset_hard.bat 重写为纯 ASCII 注释 + CRLF：此前 Edit 注入的 UTF-8
   中文注释在 GBK cmd 下解析出 `'""' 不是内部或外部命令`（cmd 按 ANSI
   读 .bat，多字节序列与后续 ASCII 字节配对吞字符）。
3. 睡眠统一 ping -n N：timeout /t 在无控制台 stdin（Git Bash→cmd）下报
   Input redirection is not supported。
4. elevated_deploy.cmd 幂等化：sc stop/delete 先行并容忍“未安装”。
5. 新增 buildm_win11_verify.bat：推 helper → schtasks 提权部署
   （拉 elevated_out.txt 验 RUNNING+ELEVATED_DONE）→ schtasks 分离跑
   verify（轮询 verify_done.txt 的 VERIFY_EXIT 0）→ 拉回 verdict。

### 关键决策回顾
- PATCH 验收回路打在驱动自身“永不调用哑函数”上而非 ntoskrnl：机制全同
  （同一 MDL 写路径），风险归零；ntoskrnl 扫描总数前后不变作为“内核未误伤”
  代理断言。子代理验收揪出两条必须修复：probe 成功路径缺 MmUnlockPages
  （PFN 锁泄漏）、用户态地址拒的 win32 错误码断言不齐（579 vs 87，取
  STATUS_INVALID_PARAMETER 对齐 87）。
- SAFETY_TOKEN 的 op 值空间此前 file/registry/kernel 三模块各自从 1 编号
  且 HMAC 不绑定模块——本模块改用 'KRN1' 独立命名，避免一张文件删除 token
  通过内核改写门。

### 当前状态
- R2-1 落地：PATCH_INLINE_HOOK (0xE21，token+FORCE 双门、expected 字节
  校验、MDL 别名写、单页/映像内限制) + QUERY_PATCH_TARGET (0xE22)。
  verify 新增 PATCHHOOK 段 10 断言。1903: 179 PASS / 0 FAIL；22631:
  全段 PASS。win11 全流程（reset→push→elevated deploy→detached verify）
  由舰队脚本一键跑通。

### TODO
- MDL 别名写在 HVCI 开启的 guest 上会被阻断（写只读代码页）——测试机
  均未开 HVCI，24H2 虚机到位后需补验。
- R2-2 IAT/EAT 枚举。


### 附记（20:12 发现）
- 19:52 仓库根 12 个跟踪文件（AGENTS.md/README.md/.gitignore/make.bat 等）
  被外部进程从工作树删除（本会话与验收子代理的命令记录均无删除动作；
  .hermes/ 为用户侧其他工具的产物目录）。已 `git restore` 全量恢复，
  git 状态 0 删除。后续会话若见 ` D ` 大片出现，先 restore 再排查来源。


## 2026-09-15 — R2-2 ENUM_IAT_EAT 首航：MEM_IMAGE 常量误植（1903 / 22631 双机）

### 现象
- IAT 走查把 kernel32 的全部 1253 个导入槽判成 hook（TotalIAT=1253 且
  hooks=1253），干净机上不可能。
- 首个误判还曾以 "err=87"（用户态基址被我错加的系统区间检查拒绝）和
  "iat=0"（ntdll 根本没有导入表，断言靶子选错）两种面目出现。

### 与参考的对比
- winnt.h 用户态常量：MEM_TOP_DOWN=0x100000，**MEM_IMAGE=0x1000000**。
  我把 0x100000 记成了 MEM_IMAGE——恰与 MEM_TOP_DOWN 撞值。WDK 内核头
  （wdm.h）只定义 MEM_PRIVATE/MEM_MAPPED，不定义 MEM_IMAGE，所以我文件里
  的本地 #ifndef 定义不会被头文件纠错，错误值一路绿灯进了比对。
- 佐证链：queryVm 返回 status=0 且 mbi.Type=0x1000000（通过 Entries[0]
  Reserved 字段带回的现场诊断）——查询一直成功、Type 一直是合法 MEM_IMAGE，
  只有我的比对常量是错的。

### 修复尝试
1. 错误码 87：删掉从 PATCH 抄来的 MmSystemRangeStart 检查（本 IOCTL 的
   目标本就是用户态模块，PE 解析自身足以拒绝垃圾基址）。
2. iat=0：IAT 断言靶从 ntdll 换 kernel32（ntdll 是 loader 根模块，无导入表）；
   ImageSize 断言的读取偏移 36→32（36 是 EntryStructSize）。
3. MEM_IMAGE 0x100000→0x1000000，hook 判定归零，双机全绿。
4. 调试通道：dbgout CONTROL 被占（1168）不可用；改为把首次 queryVm 的
   status/Type 塞进输出 Entries[0] 的 Reserved 字段带回——一次构建拿到
   实证。临时探针 scripts/iat_debug_probe.py 用完即删。

### 关键决策回顾
- "猜测三种可能，不如一次实证"：MEM_IMAGE 布局怀疑（内核 MBI 的
  PartitionId 字段）、调用约定怀疑（ULONG vs SIZE_T）、常量怀疑三者中，
  输出字段带回诊断一次构建就锁定了常量。Entry.Reserved 字段当诊断信道
  是无内核调试通道时的高性价比手段。
- WDK 内核头的部分 winnt 常量缺席（MEM_IMAGE）是这类误植能存活的原因：
  本地定义必须逐个核对真实值，不能凭记忆。

### 当前状态
- R2-2 落地：ENUM_IAT_EAT (0xE23)——附着目标进程解析 PE，EAT 出像 RVA
  判定（forwarder 豁免）+ IAT 目标 MEM_IMAGE/MEM_MAPPED 判定
  （ZwQueryVirtualMemory 动态解析）。verify 新增 IATEAT 段 7 断言。
  子代理 ACCEPT 后已采纳 4 条非阻塞修复（partial-walk 进 Status、
  SIZE_T ABI、IATEAT_OUT_HDR 48→40、注释对齐）。1903 全绿，22631 全绿。

### TODO
- partial-walk 的 Status=PARTIAL 分支无实机触发路径（健康 guest 不会），
  仅靠代码审阅覆盖。
- R2-3 Shadow SSDT。


## 2026-09-15 — R2-3 Shadow SSDT：三次错误假设与 KDNET 实证终局（1903 / 22631）

### 现象
- Shadow SSDT 查找历经四代方案全数失败：win32k 模块内 {Limit,Base,Number}
  形态扫描 → 命中“字符串池”假阳性（Limit=0x2EE 的结构，其“表项”解码出
  "UNTRUSTED LOW MEDIUM HIGH MAX" ASCII）；候选评分制（负偏移假设）→
  bestScore=1/32；距离+ASCII 对特征评分 → 依然全拒；diagPairs=0 零命中。
- 另发现既有 bug：MyArkKernelEnsureNtoskrnlBounds 把 MmSizeOfSystemImage
  **函数指针当数据指针解引用**当镜像大小，可能把扫描上限缩到 .data 之前。

### 与参考的对比
- x64 SSDT 通行描述（4 字节带符号、相对表基址）对 win32k 表完全成立：
  KDNET 会话上下文实证 entry[0]=0xff962820 → base-0x69D7E0 =
  win32kfull!...+0x32E820 ✓。
- 但 KSERVICE_TABLE_DESCRIPTOR 的字段布局与常见资料相反：
  **Base@+0、恒0@+8、Limit@+0x10、Args@+0x18**（0x20/描述符）；
  且 {Limit,Base,Args} 三元组**只存在于 ntoskrnl 的
  KeServiceDescriptorTableShadow**（[0]=NT 表、[1]=win32k 表、相邻 0x20），
  win32k 模块内只有裸表+Limit 常量+参数表，没有可扫的描述符形态。
- nt 表 Limit≈0x1D0（1903）低于早期下限 0x200；win32k Limit=0x4EA。
- win32k.sys / win32kbase.sys / win32kfull.sys 的 ImageBase 不连续，
  怀疑区间必须取三模块并集；win32k.sys（10 字符）曾被 len<11 的名字
  门槛误拒。

### 修复尝试
1. 证据链：windbg-mcp KDNET 连 test2（test2 专用 key/端口 50001）→
   `dq nt!KeServiceDescriptorTableShadow L8` 拿布局真值 →
   `.process /i <session1 csrss>` + `g` 切会话上下文读 win32k 表内容 →
   解码验证后 `g` 放行 + 关会话。取证纪律全程遵守（.logopen 未用，
   但只读命令无取证需求）。
2. 按真值重写 ntoskrnl 内相邻双描述符模式（8 字段强校验：
   Base∈nt / 恒0 / Limit 值域 / Args∈nt / Base∈win32k / 恒0 / Limit / Args∈win32k）。
3. 修 MmSizeOfSystemImage 解引用 hack → 固定 16MB 上限。
4. walker 改 4 字节表项（曾用 8 字节步长把 win32k 表 746 项全部读成
   邻项交错并全数 SUSPECT）。
5. 会话内存教训：kd 默认上下文读 win32k.sys 页面得 ????????，必须切进
   session-1 进程上下文。

### 关键决策回顾
- **KDNET 实证一次，胜过十次盲改**：四代盲扫方案每代都要 编译→部署→
  回归 约 10 分钟；KDNET 两条命令（dq + 切上下文 dd）直接终结所有猜测。
  本仓库 KDNET 工具链（windbg-mcp + test2 独立 key）在这个场景的价值
  远超其搭建成本。
- 形态扫描类代码必须先在目标机上取一次真值再写模式，凭资料记忆写的
  布局在本项目已经错了两次（R2-2 的 MEM_IMAGE 常量、本轮的描述符布局）。

### 当前状态
- R2-3 落地：QUERY_SHADOW_SSDT (0xE24)——ntoskrnl 内定位
  KeServiceDescriptorTableShadow 相邻双描述符（8 字段校验）→ 按 4 字节
  带符号表基址相对偏移走查 win32k 表 → suspect 范围=win32k 三模块并集。
  verify 新增 SHADOWSSDT 段 3 断言。终版双机实测：1903 = 输出 1024/
  Total 1258(Limit 0x4EA) 零 suspect；22631 = 输出 1024/Total 1458
  (Limit 0x5B2) 零 suspect（超出 SHADOW_MAX 的尾部不输出）。双 build 全绿。

### TODO
- nt 表本身在 1903 的 KiServiceTable 首项解码异常（Base+raw 落在镜像外
  47MB，疑似 KVA Shadow/重定位现象）——QUERY_SSDT 段一直 count=0-PASS
  未受阻塞，但若后续要修 NT SSDT 枚举，此异常是入口。
- R2-4 驱动完整性快照。


## 2026-09-16 — R2-4 驱动完整性快照：KPCR 偏移与 KVA 影子窗口（1903 / 22631）

### 现象
- 初版断言全红三连：GdtLimit=0（GDT 第 0 项是 NULL 描述符，量测循环
  立即终止）；verify 行距按 96 算而 C 端 CPU 行实际 88 字节（无尾填充）
  导致 unpack 越界崩溃；22631 上 SHADOWSSDT 出界 34/1024（1903 为 0）
  触发"零 suspect"断言。

### 与参考的对比
- KPCR 布局凭记忆写错风险再次被 KDNET 拦截：18362 实证
  **GdtBase@KPCR+0x000（覆盖 NtTib.ExceptionList 槽）、IdtBase@+0x38**
  （不是资料常写的 gs:0x30/gs:0x38 一对——TssBase@+0x8）。
- LSTAR=base-0x2D7C0、IDT 桩=base-0x32400：KVA Shadow 开启时
  系统调用入口与中断桩在 **PsNtosImageBase 之下的影子跳板区**——
  完整性窗口必须向下扩（本实现取 4MB），否则干净机会全数误报。
- 22631 win32k 表 34/1024 出界项指向 ntoskrnl 区且**成对共享同一地址**
  （i=42/44 同址、1290/1292 同址），逐 boot 波动（34→2）——良性共享桩，
  非散点 hook。

### 修复尝试
1. GDT 量测跳过前导 NULL 项、遇"已见非零后的零项"才终止。
2. verify 行距改 INTEGRITY_CPU_SIZE=88 常量引用（曾只改常量漏改硬编码
   96 的 row 计算——同样错误模式第二次出现：常量与字面量双份）。
3. SHADOWSSDT 断言从"零 suspect"放宽为"出界率 <10%"+样例打印
   （triage 信息而非硬判定）。
4. PiDDBCacheTable 无稳定导出：如实声明降级（Status=PIDDB_NA），
   不做猜测性模式扫描。

### 关键决策回顾
- KDNET 实证先行已成型化习惯：本轮 `dt nt!_KPCR` + `rdmsr c0000082`
  两条命令避免了第三、四次盲改循环；R2-2/R2-3/R2-4 三连的教训一致——
  **布局/常量类代码一律先取真值再写**。
- "零 suspect"类断言在跨 build 矩阵上天然脆弱：良性形态随 build/boot
  变化，断言应表达"无大面积异常"（比率）而非"绝对纯净"。

### 当前状态
- R2-4 落地：QUERY_DRIVER_INTEGRITY (0xE25)——KeIpiGenericCall 全 CPU
  快照（GDT/IDT 基址、LSTAR/CSTAR/STAR/SFMASK、CR0/CR4）+ CPU0 的
  IDT 门解码（出窗计数）与 GDT 步进量测 + UnloadedDrivers 注册表证据；
  PiDDB 降级声明。verify 新增 INTEGRITY 段 3 断言。1903 与 22631
  双 build 全绿。

### TODO
- 多处理器组（>64 CPU）主机上 KeGetCurrentProcessorNumber 组号别名——
  未测、未声明支持；下轮加 KeQueryActiveGroupCount 降级位。
- PiDDB 真实扫描（模式定位 PiDDBCacheTable）排期 R3。
- unloaded 池分配失败时可置独立 Status 位（当前静默 0/0）。


## 2026-09-16 — R2-5 FORCE_UNLOAD：kmod 死代码现形 + 三个状态/顺序坑（1903 / 22631）

### 现象
- FORCE_UNLOAD (0xC22) 注册进 kmod 模块后所有调用 win32_err=1（未注册）
  ——kmod 模块在 myark_full.h 里**从未启用**（count=31 里没有它）；
  临时启用后立刻连爆：MYARK_TRACE_KMOD 未定义、IRP_MJ 宏重定义、
  `__imp_IoDriverListHead` 链接失败——`IoDriverListHead` 在 1903 的
  ntoskrnl **根本没有导出**（宿主机导出表核查），kmod 遍历器是死代码。
- 测试驱动装载：create rc=577（签名为空——MSBuild 对无 INF 的 WDM
  工程**不走签名目标**）；修复签名后 create rc=1058（服务被禁用残留）。
- was=0（模块探针说没装载，实际已装载）：探针的
  ZwQuerySystemInformation **尺寸探测调用**要求了 NT_SUCCESS——
  探测尺寸本就返回 INFO_LENGTH_MISMATCH 错误码。

### 与参考的对比
- AGENTS.md 的教训面再添一条：**在启用一个从未编译过的模块之前，
  先确认其外部符号依赖真实存在**（宿主机 signtool/导出表/链接器都
  是现成的核查工具）。
- R2-3 的 Win32kBounds 没犯尺寸探测的状态码错误、本轮 ForceUnload
  犯了——同一个 API 的正确用法在仓库里已有正例，写新代码前先 grep
  同仓库既有用法。

### 修复尝试
1. 放弃启用 kmod（死代码 + 不可用符号），FORCE_UNLOAD 迁入 kernel
   模块（0xE26，与 PATCH_INLINE_HOOK 同族的 FORCE 门），kmod 改动
   全部回滚。
2. 测试驱动 MyArkTestDrv（driver/testdrv，无 INF 的 WDM 最小驱动，
   有 Unload 例程）：build_driver.bat 加 MSBuild 构建后用 signtool
   手动签 /n "WDKTestCert www"（MSYS_NO_PATHCONV=1 防 Git Bash 吃
   /fd 参数）。
3. verify 安装流程 delete-first + config demand + start，避免
   1058 禁用残留；推送由 vm_push_driver 顺带完成。
4. 模块探针的尺寸探测不再检查状态码，只看 needed。

### 关键决策回顾
- “每次验证先硬重启”固化为流程：push 失败→旧驱动驻留→guest 脚本
  陈旧→验证结果不可信，这一链条本轮已烧掉两轮；reset-first 一次性
  切断。
- err=1 的含义矩阵：未注册 IOCTL / WDF 拒绝都可能报
  ERROR_INVALID_FUNCTION——先查能力表（QUERY_CAPABILITIES 的
  functions 是功能码字段，非完整 CTL_CODE）再猜。

### 当前状态
- R2-5 落地：FORCE_UNLOAD (0xE26)——token('NRK2')+FORCE 双门、服务名
  白名单字符校验、MyArkCore+启动关键镜像黑名单、ZwUnloadDriver、
  模块表闭环回读（WasLoadedBefore/GoneAfter）。verify 新增 TESTDRV 段
  8 断言（安装装载、四条负路径、真卸载闭环、双卸载、清理）。
  MyArkTestDrv 工程入库并纳入 build_driver.bat。1903 + 22631 双 build
  全绿。

### 附记（SHADOWSSDT 22631 变体 + PATCHHOOK 漂移）
- 评分制 Shadow 锚定在 22631 出现逐 boot 变体（部分 boot 无达标候选，
  err=127）：verify 识别 127 记 SKIP；详见 KNOWN_ISSUES 新条目。
- PATCHHOOK “扫描总数不变”出现 ±1 漂移（ntoskrnl 分页段换出），
  放宽为漂移 ≤2。两条都是弱断言的固有抖动，非功能回归。

### TODO
- kmod 模块的 0xC20/0xC21 遍历器仍是死代码（IoDriverListHead 无导出）；
  若要激活需改走 PsLoadedModuleList（已导出）——排期 R3 决定去留。
- “无 Unload 例程的驱动强制卸载”超出 ZwUnloadDriver 能力（需线程
  注入级手段），明确不做（与 ROADMAP 设计性拒绝一致）。


## 2026-09-16 — R2-6 进程创建规则引擎：INTEGRITYCHECK 门槛 + 自扫死循环（1903 / 22631）

### 现象
- 0x71A/0x71B 全部 err=1（未注册）：callback 模块 Init 的
  PsSetCreateProcessNotifyRoutineEx 注册失败 → 模块整体跳过。
  根因：**Ex 版进程回调要求调用者 PE 头带 /INTEGRITYCHECK
  （FORCE_INTEGRITY）**，主工程没设。
- 修复过程中引入第二个回归：Shadow 扫描循环的 off 推进被包进
  `if (!found)`，命中后 off 永不前进 → 同页无限重扫，IOCTL 线程
  内核态自旋（guest 整机存活、单核烧满、verify 挂死）。
- 22631 上评分锚定出现逐 boot 变体（部分 boot 无达标候选）。

### 与参考的对比
- PsSetCreateProcessNotifyRoutineEx 的 /INTEGRITYCHECK 门槛是文档化
  行为（非 Ex 版无此要求）——README/资料很少强调，实测一击即中。
- verify 的 subprocess spawn 无守卫：REMOVE 失效时 PermissionError
  直接炸穿整个 verify（check() 设计注释明确 "failures never abort
  the run"）——违反自家纪律。

### 修复尝试
1. 主工程 Link 加 /INTEGRITYCHECK（无条件 ItemDefinitionGroup，
   双 build 加载成功）。
2. 扫描循环恢复无条件推进 + found 即 break。
3. 计数器（Hits/TotalMatched/TotalDenied）改 InterlockedIncrement
   （shared 锁允许多 CPU 并发自增，ULONG++ 丢更新）。
4. Cleanup 注销重试 100×100ms 放弃路径补 ERROR 日志 + 后果注释
   （放弃 = 带活回调卸载 = 下次进程创建 bugcheck）。
5. verify 两处裸 spawn 包 try/except 落 FAIL；RUNTIME_STATE 输入补
   4 字节尾填充（C sizeof 88 vs 打包 84，又是尾填充类）。
6. SHADOWSSDT 127 → 记 SKIP 不记 FAIL（KNOWN_ISSUES 新条目）；
   PATCHHOOK 扫描漂移放宽 ≤2（ntoskrnl 分页段换出）。

### 关键决策回顾
- “verify 脚本子集变更 + 驱动未变”时 push 失败可容忍（脚本先行拷贝
  成功）——但需核对 guest 实际运行的脚本版本，两次陈旧事件后已把
  reset-first 固化为默认流程。
- 大型交付（本项跨 ~6 小时）的每个 kernel-side 变更仍坚持独立
  重启-验证环；自扫死循环这类“guest 存活但单核烧满”的故障形态，
  判活通过 + 拉取实时输出文件定位，是比盲目 reset 更快的路径。

### 当前状态
- R2-6 落地：SET_RULES (0x71A) / RUNTIME_STATE (0x71B) + 进程创建
  notify 规则引擎（DENY/LOG_ONLY、32 条上限、非分页 + EX_SPIN_LOCK）。
  verify 新增 RULES 段 10 断言（含真实 spawn 的 DENY 拦截与
  LOG_ONLY 计数、REMOVE 恢复、清理归零）。1903 + 22631 双 build 全绿。

### TODO
- 多 CPU 并发下 notify 匹配为 O(规则数) 全表扫——规则量大时可改哈希；
  首批 32 条上限内无压力。
- SHADOWSSDT 22631 逐 boot 锚定变体（KNOWN_ISSUES 新条目）仍开放。
- R2-7 文件监控 minifilter。


## 2026-09-16 — R2-10 文件完整性标签：SET 路径 Se wedge（1903 / 22631）

### 现象
- 0xE12 SET（ZwSetSecurityObject 写手工构造的强制标签 SD）发出后
  guest exec 通道不可恢复卡死（重置前 Tools 死亡、KDNET 附加落在
  SeCaptureSecurityDescriptor 的 AV 循环、无 minidump）。
- rev-2 ACL、rev-4 ACL（RtlCreateAcl+RtlAddAce）、精确尺寸 label ACE
  三种 SD 构造全部复现；QUERY-only（0xE13）不复现——wedge 与 SET 的
  Se 写路径强相关。
- 验收子代理另抓到一个真 bug：LABEL ACE 的 rid 读偏移 ace[20] 应为
  ace[16]（SID 在 ACE+8，SubAuthority[0] 在 ACE+16）——所有已打标
  文件的 Level 输出都会是垃圾；双 build 全绿没抓到，因为唯一断言是
  label-less 的 found=0。

### 与参考的对比
- Vista 起 LABEL 读已特殊化为 READ_CONTROL——不需要
  SeSecurityPrivilege（最初加 ACCESS_SYSTEM_SECURITY 反而让 QUERY
  err=5，被驱动内特权缺失逻辑击中）。
- LABEL ACE 合法 ACL 版本是 ACL_REVISION_DS(4)；但 rev-4 修复后
  wedge 依旧 → 问题不在 ACL 版本本身。

### 修复尝试
1. SET 降级为确定性 STATUS_NOT_SUPPORTED（win32 50，与未注册的
   win32 1 可区分），延迟实现保留在 #if 0。
2. rid 偏移 ace[20]→ace[16]、界 +24→+20、aceSize<4 防死循环。
3. verify 增补阳性断言：icacls /setintegritylevel H 预打标 fixture
   + 驱动 QUERY 读回 rid==0x3000（这是能抓住 rid bug 的唯一测试）。
4. 本轮取证与修复沉淀 KNOWN_ISSUES 条目。

### 关键决策回顾
- 内核侧读回（0xE13）替代 python ctypes 的 GetNamedSecurityInfoW：
  后者一次传参失误即内核 AV（KDNET 抓到的 SeCaptureSecurityDescriptor
  AV 就是它），安全边界应留在驱动。
- “全绿不等于全对”：rid bug 在两个 build 全绿下存活，因为当时唯一
  的断言只打在 label-less 分支。阳性用例必须覆盖真正的产出字段。

### 当前状态
- R2-10 落地（SET 延迟）：0xE12 确定性 NOT_SUPPORTED + 0xE13 只读
  标签查询（icacls 阳性 fixture + label-less 负例 + 坏路径拒）。
  1903 + 22631 双 build 全绿。

### TODO
- SET 路径 KDNET 隔离调试（SD 字段二分）；根治后恢复 SET 断言。


## 2026-09-16 — R2-8 任务管理器劫持（IFEO，纯 R3）（1903 / 22631）

### 现象
- 无故障轮。新表面：myark-cli stealth taskmgr-hijack
  --install/--uninstall/--status（IFEO Debugger 重定向 taskmgr.exe，
  等价 System Informer 官方 "Replace Task Manager" 机制）。

### 与参考的对比
- IFEO Debugger 值的语义：注册表值 = 命令前缀，系统把原始命令行追加
  在其后执行——marker cmd 脚本忽略追加参数即可拿到确定性行为。
- 行为断言用副作用文件（target 无关的硬证据），不用返回码（rc 随
  target 变化）。

### 修复尝试
- 所有权标记值 MyArkHijack：uninstall 只删自己标记的 Debugger 值，
  外来的保留（--force 才动），避免误伤第三方工具的同名配置。
- verify 用真实 taskmgr spawn 双向验证：redirect 触发（副作用文件）
  + uninstall 后真实任务管理器可启动（Popen+terminate）。

### 关键决策回顾
- 纯 R3 表面（注册表）不再走驱动 IOCTL——TOKEN+GATE(AUDIT) 落为
  管理员要求 + 审计输出行 + 所有权标记；注册表本身强制管理员。
- 唯一能证明"劫持生效/恢复完整"的途径是真实 spawn 双向断言，
  副作用文件是 target 无关的稳定证据。

### 当前状态
- R2-8 落地：taskmgr_hijack.py（install/status/uninstall）+ CLI
  stealth taskmgr-hijack + verify TASKMGR 段 4 断言。1903 + 22631
  双 build 全绿。

### TODO
- 非管理员 --install 的 traceback 换友好报错（外观）。
- R2-7 文件监控 minifilter（剩余大项）。

### 补充 (验收轮): INJECT 三 P0 与"假绿"
- 子代理验收判 FAIL,三个 P0 全中,其中 P0-1 推翻了此前的"全绿":
  METHOD_BUFFERED 输入/输出别名同一 SystemBuffer,handler 里
  RtlZeroMemory(outBuf, 112) 把 Payload[0..23] 清零——之前 APC 交付时
  执行的是全零页(add [rax],al, RAX 恰为 RemoteBase),"交付证明"断言
  解析的 AV 恰好满足,故假绿。修复: payload 先快照进内核 pool 缓冲再取
  输出缓冲,拷贝/回读均从 pool 走。
- P0-2: KeInsertQueueApc 失败分支 free 后未置 NULL,Fail 路径双 free。
- P0-3: 回读校验的 MmCopyVirtualMemory 源/目标方向写反(自注入时被掩盖)。
- P1-1: token 应绑定目标 Pid(与其他 action 一致),绑定调用方 PID 会
  竞争退化为 System 线程误拒;P1-2: 内核态 Zw*/Mm* 不触发用户态 PPL
  检查,PPL 拒绝改为显式 PsGetProcessProtection 判定。
- 修复后 1903 真全绿: RET stub 在可警醒线程干净交付执行
  (SleepEx 返回 0 = WAIT_IO_COMPLETION),无 AV;交付断言同步改写为
  SleepEx==0 语义。
- 教训: 交付证明类断言不能建立在"恰好形状匹配的异常"上;零页
  add [rax],al 与真实执行产生同形 AV。payload 回读校验(本次 P0-3 修向
  后)才是拷贝完整性的直接证据,执行证明用 SleepEx 返回值。

## 2026-09-16 晚 — R3-5 RUNTIME_FIELDS + T-C INJECT_SHELLCODE(1903 test2 / 18362)

### 现象
- R3-5: 0xA03/0xA12 均为全零 stub(R3-5 的历史欠账)。补采样后 0xA03 连续
  四轮 vm=#C0000004(STATUS_INFO_LENGTH_MISMATCH):72/80/128 全不对——
  ProcessVmCounters 是精确长度 class,且期望长度跨 build 变化
  (VM_COUNTERS 80 vs VM_COUNTERS_EX 88)。0xA12 解包也曾因格式串多一个
  I 反复崩溃。
- T-C: ZwCreateThreadEx 不在 ntoskrnl 导出表(导入库 0 命中,实测
  MmGetSystemRoutineAddress 返回 NULL,第一版 INJECT win32=127)。

### 与参考的对比
- 对照 Win32: 0xA03 十个字段与 PROCESS_VM_COUNTERS 一一对应 → 改用
  Zw 语义(ProcessVmCounters)而非跨 build EPROCESS 偏移,天然免对表。
- 对照注入惯例: 线程启动两路——ZwCreateThreadEx(非导出,放弃)/
  KeInitializeApc+KeInsertQueueApc(均导出,采用)。USER APC 需目标线程
  进可警醒态;裸 RET stub 在 APC 调用约定下交付即 AV 在 payload 页,
  该 AV 反向成为"交付证明"(AV 地址==RemoteBase)。

### 修复尝试
- 0xA03: 级联长度 {80,88,72,128} + 命中序号/状态经 Reserved0/1 翻上来;
  PROCESS_QUERY_INFORMATION|PROCESS_VM_READ 打开(VmCounters 需要 VM_READ);
  CycleTime 用 class 26 best-effort。
- 0xA12: KeQueryRuntimeThread(ETHREAD 首成员即 KTHREAD)+ Tier C StateFlags。
- T-C 定稿: alloc(RW)→MmCopyVirtualMemory→回读校验→protect(ER)→
  APC 队列;KernelRoutine 交付时释放 pool KAPC;失败路径全清理。

### 关键决策回顾
- "pdb 字符串命中"≠导出——导入库 (.lib) 二进制搜索才是权威判据。
- 裸 RET 在 APC 语境不安全属调用约定问题而非机制问题,verify 将其转化为
  交付证明断言;真实 payload 需按 APC 约定(3 参 + 自行 ExitThread)编写。
- 输入结构含 Payload[1] 时 C sizeof 尾填充到 92,R3 打包必须 ≥92(踩一次)。

### 当前状态
- 1903 + Win11 双 build 全绿: INJECT 4 断言(token 拒绝/超限/注入/交付证明
  /存活) + RUNTIME 3 断言(0xA03 计数合理/0xA12 tick/死 pid 空)。
- 1903 卸载闭环持续有效。

### TODO
- T-B HWID 细分(0x752/0x753, completion 例程改写)——下一轮。
- INJECT 的 APC 交付依赖目标线程可警醒;非警醒目标需 ZwCreateThreadEx
  替代通道(动态解析),列为后续可选。

## 2026-09-16 — R2-11 复活:死锁根因定案 + 轮询式重设计(1903 test2 / 18362)

### 现象
- 历史事故复盘定案: 旧实现的 ASK_WAIT 轮询请求**驻留在驱动顺序队列里**
  等待应答——队列被它独占后所有后续 IOCTL(任何 section、任何进程)全部
  排队在后面冻死。这与"verify 停在 CORE QUERY_MODULES 一带"(全套的第一
  批 IOCTL)完全吻合;runProgramInGuest 阻塞是同死锁链的外显。
- notify 回调内无限期等待会同时冻住全系统进程创建管线(创建锁被持),
  两个机制叠加 = 旧版"100% 卡死且重启无法消除"。

### 与参考的对比
- 对照 WDF 队列语义: 顺序队列一次只派发一个请求, 请求回调内等待外部
  事件 = 队列饥饿; 等待外部应答必须用 manual dispatch/并行队列, 或改
  轮询模型。
- 对照工业 EDR 的 inline verdict: 回调内短等待有界(毫秒~秒级)+ 超时
  fail-open 是公认形态, 但绝不允许无限期。

### 修复尝试(重设计)
- ASK_WAIT 0x71C 改为**非阻塞快照**: 立即返回 pending 槽位+计数, R3 轮询。
- 驻留等待限时 5s fail-open(超时=ALLOW), 槽位表 8 项, State 0/1 用
  InterlockedCompareExchange 预约, per-slot SynchronizationEvent(唤醒即
  复位, answer 早到不丢信号), 驻留期间不持任何自旋锁。
- 槽表满/Dropped 也是 fail-open; Cleanup 在移除 Ps 回调前先
  MyArkAskFailOpenAll()(移除会因回调在飞而失败重试)。
- ASK_CANCEL 全量 flush; ASK_ANSWER 按 Sequence 定向。

### 关键决策回顾
- "代码考古确认旧实现已丢弃"后, 重设计比复刻+修更可靠: 两类死锁机制
  (队列驻留/无限期 notify 等待)在结构上不可能再发生。
- 专项 KDNET 轮未实际建立(KDNET 握手退化+vmrun 卡死), 但 verify 第 7 项
  "WAIT still responsive (queue alive)"断言内建了死锁探测器: 套件能在
  ASK 段后继续跑完本身就反证旧死锁类消失。
- 结构体对齐连坑两次(RUNTIME_STATE_INPUT 84->88, ASK_CANCEL_INPUT 同)——
  含 Token 的输入结构一律按 8 字节对齐预留 pad。

### 当前状态
- 1903 全绿: DENY(ACCESS_DENIED)/ALLOW/CANCEL flush/TIMEOUT 5s
  fail-open/队列存活, 7 断言全过; sc stop 卸载闭环复测通过。
- Win11 22631 全绿。
- 1903 卸载验证: svc_clean 后 alive 探针通过(FilterUnloadCallback 生效)。

### TODO
- 驻留窗口(<=5s)内全系统进程创建停顿是已知可观测代价; 生产化应评估
  two-phase(创建后挂起主线程)方案。
- KDNET 传输在本轮退化(握手超时), 下次需要 live 调试前先恢复
  (bcdedit/重装 KDNET)。

## 2026-09-16 — R2-9 轮末:0xCE/挂起真根因 = FilterUnloadCallback 缺失(1903 test2 / 18362)

### 现象
- 1903 复现一轮 0xCE:sc stop 后 sc.exe 自己的 FormatMessage NtOpenFile
  触发 FLTMGR!FltpPerformPreCallbacks 调进 <Unloaded_MyArkCore.sys>+0x17bdc
  (minidump 091626-12062 同因,且无人调过 stop——filesys 型被异步卸载)。
- type= kernel 下 sc stop 后 exec 通道/KDNET 失联(同根因的挂起变体)。

### 与参考的对比
- 对照 WDM minifilter 惯例(scanner 等 sample):DriverUnload 为空,卸载
  清理放在 **FilterUnloadCallback** 里调 FltUnregisterFilter。
- 本驱动此前 FilterUnloadCallback=NULL:FltRegisterFilter 成功后 FLTMGR
  接管 DriverObject->DriverUnload,WDF EvtDriverUnload 不再被调用,
  模块清理(含 FltUnregisterFilter/键盘回调注销)全部跳过。

### 修复尝试
- 新增 MyArkFileMonFilterUnload:Interlocked 双跑保护 +
  MyArkCoreRunModuleTeardown(模块反序 Cleanup + IOCTL 复位 + 令牌卸载,
  framework 新导出)+ 依赖模块 Cleanup 内的 FltUnregisterFilter。
- 服务类型回退 type= kernel(filesys 型不是真文件系统,会被异步卸载)。

### 关键决策回顾
- minidump 头(DUMP_HEADER64)可直接 python 解析 BugCheckCode/参数,免去
  立即上调试器;铁证(执行点在卸载镜像内)来自 0xCE 参数与卸载模块表。
- "filesys 必需"是 14:53 那轮 Instances 键坏时的误诊;键修好后 kernel 型
  注册正常。一次误诊叠一层错误结论时,要回头重测被否决的分支。

### 当前状态
- 1903: verify 全绿 + **sc stop 成功且 guest 存活**(卸载路径闭环)。
- Win11 22631: 全绿(随后一轮)。

### TODO
- WPP_CLEANUP 仍在不会执行的 EvtDriverUnload 里,卸载时 ETW 注册残留
  (观察无后果,留观)。
- R2-11 / 24H2 维持原计划。

## 2026-09-16 — R2-9 文件/注册表重定向:方案修正与合成调试(1903 test2 / 18362)

### 现象
1. **REG 侧 pre-open 改 CompleteName 无效**:Cm 回调命中并计数(rhits=1),
   但打开源键仍读到原值——CM 在回调前已解析完名字,指针替换不被采纳。
2. **值改写静默不生效**(第一版值级方案):pre=2/ctx=2 都匹配,但 rhits=0
   且读回原值——winreg 首查按"原值大小"传缓冲,shadow 数据更大,改写被
   容量检查跳过。
3. **值内容变成大写**:'shadow' 读回 'SHADOW',rhits=2 正常——REG 分支误用
   RedirUpcaseInto 存数据(路径才需要大写,数据必须保原大小写)。
4. **heredoc 转义连环坑**(工具链层):Git Bash heredoc 吃一层反斜杠,造成
   vcxproj 出现 0x0B/0x3C 脏字节(MSB4025)、C 源码出现真 NUL 字节字符常量
   (C2137)、verify 脚本嵌真 NUL(SyntaxError null bytes)。

### 与参考的对比
- 对照 WDK:wdm.h 中 REG_OPEN_KEY_INFORMATION 是 REG_CREATE_KEY_INFORMATION
  的别名(CompleteName/RootObject/CallContext 字段),不是旧文档的
  {Object, CompleteName, Context} 形状;REG_POST_OPERATION_INFORMATION 用
  CallContext 承载 per-op 上下文,ReturnStatus 允许 post 改写查询结果状态。
- 对照值重定向惯例:输出缓冲不足时置 *ResultLength=所需值 + ReturnStatus=
  STATUS_BUFFER_OVERFLOW,让 R3(CPython winreg 原生 MORE_DATA 重试循环)
  放大缓冲后重查——第二次查询即可完成改写。

### 修复尝试
- REG 侧从"键打开重定向"降为"值查询改写":PreQueryValueKey 匹配 key 路径
  (ObQueryNameString)+值名,把输出缓冲指针/ResultLength/类/数据快照存入
  CallContext;PostQueryValueKey 成功时改写 PARTIAL/FULL 信息(FULL 走
  DataOffset),不足时走 overflow 重试。
- 数据大小写保真:REG 数据用普通拷贝,只有路径/值名参与匹配才大写。
- EX_SPIN_LOCK 会提 IRQL:全部改为"锁内栈拷贝命中、锁外分配"模式;Cm
  注册/注销移出锁、由 KMUTEX(PASSIVE) 串行化。
- 文件损坏逐一修复:vcxproj 按行号字节级重写;C 源 NUL 字符常量字节级
  替换;verify 脚本 NUL→文本转义。

### 关键决策回顾
- "诊断翻上来"再次一击命中:STATUS 的 Reserved1/Reserved2 携带 pre 进入数
  与 ctx 分配数,一轮 guest 周期区分了"回调没进/进了不匹配/匹配没改写"。
- 值级方案语义缩窄为 (key, valueName) -> REG_SZ 数据;键打开重定向在
  CmCallback 层不可行,记入 KNOWN_ISSUES。
- 本机 heredoc 禁止内嵌反斜杠转义(一律 chr(92) 构造),写入前后必须做
  NUL 检查——已升级为硬规则。

### 当前状态
- 1903 全绿:FILE(arm→hit 读到 shadow 内容→clear 恢复 orig)+
  REG(arm(Cm up)→hit 读到 shadow 值→clear 恢复 orig),整包 [VERIFY] OK。
- Win11 22631 全绿(随后一轮)。
- sc stop 挂起与 minifilter 注册强相关(2/2),重部署强制 reset-first。

### TODO
- fltmc/FilterUnloadCallback 与 sc stop 挂起根因(与 R2-7 的 0xCE 同源)
  ——待专用 KDNET 轮,先以 reset-first 纪律规避。
- REG 枚举/多值查询(QueryMultipleValueKey/EnumerateKey)未覆盖,按需扩展。
- 子代理验收结论待回(并行执行)。

## 2026-09-16 — R2-7 文件监控 minifilter:三轮合成调试(1903 test2 / 18362)

### 现象
三轮串行问题,每一轮都靠"把失败状态翻上用户态"或"KDNET 取证"定位:
1. **FltRegisterFilter 注册失败**:module lasterr 0xC000000E(NO_SUCH_DEVICE,
   sc start / type=filesys)与 0xC0000034(OBJECT_NAME_NOT_FOUND,fltmc load)。
   IOCTL 0x815-0x817 全部 ERROR_INVALID_FUNCTION(模块 Init 失败被隔离,表未注册)。
2. **DRAIN 事件解析错位**:CREATE 断言过、DELETE 断言挂;事件转储显示
   第 3/4 个事件字段互相串位(下一个事件的 PID 被当成上一个事件的 Type)。
3. **0xCE 蓝屏(DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS)**:
   fltmc load 加载后 sc stop,MyArkFileMonPostCreate 在镜像卸载后仍被
   FLTMGR!FltpPerformPostCallbacks 调用;bu 断点证明 EvtDriverUnload 与
   MyArkFileMonStop 均未执行。复现 100%。

### 与参考的对比
- 对照 WDK 文档:FltRegisterFilter 要求服务键 Instances 子键含
  DefaultInstance + 实例子键(Altitude/Flags);本驱动自建该键,第一版拼接把
  实例名写进 Instances 的终止 NUL 槽位,拼出 "InstancesMyArkCore Default
  Instance"(reg query /s 直接坐实)。
- 对照 WDM minifilter 惯例:DriverUnload 后 FltUnregisterFilter 是标准模式,
  但仅当驱动以 legacy sc start 加载时成立。fltmc load 使 FLTMGR 接管
  DriverUnload 指针,FilterUnloadCallback=NULL 时自有卸载路径不执行驱动
  侧清理,镜像释放而回调仍挂卷,即 0xCE。混合驱动不能用 fltmc load。
- 事件结构含 UINT64,x64 /Zp8 尾部隐藏 4 字节填充(sizeof=568),R3 若按
  字段净和(564)解析,第二个事件起错位 8 字节。

### 修复尝试
- Init 不再吞失败:StartStage/StartStatus 经 STATUS IOCTL(0x817)上报,
  一轮 guest 周期即拿到 stage=3/status=0xC0000034 的精确证据(替代盲试)。
- 子键拼接:实例名源串改为带前导分隔符,写入 NUL 槽位;reg query 回读
  确认 Instances/MyArkCore Default Instance。
- 事件结构尾部加显式 UINT32 Reserved2 + C_ASSERT(sizeof==568);python 侧
  _FILEMON_EVENT_SIZE=568。
- 加载模型回到 legacy:vm_svc_create.bat type= filesys + sc start,
  禁用 fltmc load;FLTFL_POST_OPERATION_DRAINING 早退、IRQL/Enabled 检查
  顺序调换、前缀精确相等不再越界读 1 WCHAR(验收 P0-3)、尾分隔符剥离。

### 关键决策回顾
- "状态翻上来"优于反复盲测:模块框架 Init 隔离是好设计,但把内部失败
  原样可见化(StartStage)把三轮可能变成一轮。
- 混合驱动(legacy 控制设备 + minifilter)的加载通道必须全程 legacy;
  fltmc 只在"驱动没有别的清理义务"时安全。
- DRAIN 断言加事件转储 + 序列单调断言,是错位类 bug 的通用探测器。

### 当前状态
- 1903(18362)全绿:reset→push→sc create(filesys)→sc start→verify OK,
  FILEMON 10 断言全过(reg=1 vol=10、CREATE/DELETE/delete-on-close/
  out-of-prefix/disarm/counters/mono)。
- KDNET 会话与 .logopen 纪律全程执行;filemon_kd.log 落盘。

### TODO
- Win11 22631 回归(本项随后执行)。
- fltmc unload / FilterUnloadCallback 语义未验证(MyArkCore 不走该通道,
  记入 KNOWN_ISSUES)。
- R2-9 文件/注册表重定向依赖本模块的 CREATE 改名,下一步接入。


<!-- 模板：新一轮从这里复制 -->
## 2026-09-17 — R3-1 (T-B) HWID 伪装细分:0xA×2 + 全系统死锁 + METHOD_BUFFERED aliasing 三连(1903 test2 / 18362)

### 现象
- 0x753 APPLY(disk serial,附着过滤 DO 到 \Device\Harddisk0\Partition0)
  后 guest 立即蓝屏 IRQL_NOT_LESS_OR_EQUAL (0xA),两次同哈希
  (AV_MyArkCore!MyArkHwidSpoofPassComplete,0x5b00003 @ DISPATCH);
  PassComplete 修好后第三轮变成**全系统死锁**(无 dump,guest 冻结,
  exec 通道假死,一次 vm_reset_hard 还触发了盘回滚)。
- 0x753 所有带 token 的调用全被 ACCESS_DENIED,而同机 ACTIONS/REDIRECT
  的 token 全部通过;guest 侧打印待发 buffer 前 20 字节完全正确。
- verify 的 partition 断言预览值全零 / MBR 盘上 GUID 类 NOT_FOUND。

### 与参考的对比
- R2-7/R2-9 的教训是"方法对了才能谈实现";本轮全部照做但仍在三个
  不同层面各栽一次:(1) RemoveLock 必须在 IoAttachDeviceToDeviceStackSafe
  **之前**初始化(附着即入栈,partmgr 直接完成的 WMI IRP 会立刻跑我们的
  完成例程);(2) 完成例程里 IoReleaseRemoveLock 必须经
  `ext->RemoveLock`——把扩展基址 cast 成 PIO_REMOVE_LOCK 会把 Magic
  字段('HWFE')当锁头,KeSetEvent 打到垃圾地址;(3) 持 EX_SPIN_LOCK
  (IRQL 2)调 IoGetDeviceObjectPointer/附着/摘除——这些是 PASSIVE-only
  API(内部 ZwOpenFile + 等 IRP),直接把整_KERNEL 死锁。
- METHOD_BUFFERED aliasing(T-C P0-1 的同族坑)在 IOCTL 层再现:
  先 fetch input 再 fetch output(同一 SystemBuffer)后
  RtlZeroMemory(outBuf) 把 Token 抹成 0,validator 的 magic 检查必挂。
  用 0x752 的 LastStatus 当面包屑 + guest 侧 buffer hexdump 三步定位。
- WDK 头文件再当裁判:PARTITION_INFORMATION_GPT 第一成员是
  **PartitionType**,PartitionId 在第二个;union@32 → PartitionId@48。
  子代理给的 44 与我给的 32 都不对,头文件说了算。

### 修复尝试
- 修 1:IoInitializeRemoveLock 挪到 attach 前(必要但不充分)。
- 修 2:PassComplete 改 `&((PMYARK_HWID_FILTER_EXT)Context)->RemoveLock`
  (0xA 根因;两份 MEMORY.DMP 同哈希互证)。
- 修 3:attach/detach 全部挪出 spin lock,锁只护发布/快照;恢复序列
  改为"锁内停改写→锁外摘除"。
- 修 4:0x753 入口 `snap = *inBuf` 全量快照,输出写入永远不回读 inBuf。
- 修 5(验收后):DiskApply 发布点在锁内复查 Active;GpuDryRun 拒绝
  Active 态;GpuApply 拒绝已注册(cookie 覆盖泄漏);PostQuery 对空
  key-path 前缀早退;改写截断到原值自身范围(不越过原 NUL)。

### 关键决策回顾
- "挂起"与"蓝屏"要分开取证:MEMORY.DMP 的 mtime 是判据——mtime 未变
  说明没有新 dump,是死锁不是蓝屏;盲目的 reset 会丢现场。
- 磁盘回滚会吃掉半轮调试点:恢复序列(env_check→setup→push→create/
  start)必须完整重走,不能假设 guest 文件还在。
- partition 类按盘风格双派生(GPT=16B PartitionId / MBR=4B 磁盘签名)
  是让"分项"在现有 MBR 测试机上可端到端验收的最小改动。
- verify 的 uid/GPU NOT_FOUND 形态要显式断言"干净拒绝",否则
  环境差异会伪装成 FAIL(或更糟,被注释掉弄成假绿)。

### 当前状态
- 1903(18363)全绿:HWID 段 17 断言——disk serial 与 MBR 签名两个类
  DRY_RUN→APPLY→端到端改写→RESTORE 回探闭环;GPU/uid 在本机无串值,
  NOT_FOUND 干净;ARP NOT_IMPLEMENTED;token/双标志负门控全过。
- 子代理验收 ACCEPT-WITH-FIXES(3×P1 + 8×P2)全部落实或记档
  (surprise-removal 加固、lookaside 优化记 KNOWN_ISSUES)。
- Win11 22631 同轮全绿:GPT 盘 partition id 端到端闭环落地
  (during=want, queries=5 rewritten=4,经 P0 LAYOUT 查询读回——22631 的
  \Device\HarddiskN\PartitionM 符号链接不经过附着栈,python 读回必须
  走 PhysicalDrive0 的 LAYOUT 查询);disk serial 长串 NVMe 同样闭环。
  uid 类在 22631 对 DUID 查询形状返回 INVALID_PARAMETER(1903 为
  NOT_FOUND),两种环境均验证"干净拒绝"契约。

### TODO
- ARP 类(nsiproxy NSI 列布局实机反向)→ R3-1b。
- uid 类的 0x83 ID 描述符标识符改写(两台测试机均无内嵌描述符/拒绝
  DUID 查询形状)→ R3-1b。

## 2026-09-17 — R3-7 Minifilter 清单 0x818 + 旁路 PID 0x819(1903 test2 / 18362 + Win11 / 22631)

### 现象
- 0x818 首版清单全空:FltGetFilterInformation 两段式(NULL,0 查大小)对
  FiltersAggregateStandardInformation 返回 STATUS_SUCCESS(而非文档预期的
  BUFFER_TOO_SMALL),BytesReturned=0 → 填充分支从不执行,11 个条目全空。
- 改单次固定缓冲后第一次构建报 km 头文件 ASI 联合成员名不匹配
  (fltKernel.h 先含 ntifs.h,km 变体的联合命名与 shared/fltUserStructures.h
  的 `MiniFilter` 不同)。

### 与参考的对比
- 两段式 NULL/0 查大小是 NtQueryInformationFile 系的习惯;FltGetFilter
  Information 的 km 实现对 NULL 缓冲直接 SUCCESS——文档两段式不适用,
  单次固定缓冲(2KB,远超任何真实 filter 名+altitude)是正解。
- km/user 头文件 ASI 联合成员命名不一致(C2039 MiniFilter),用本地
  MYARK_ASI_MINI 镜像 + C_ASSERT(FIELD_OFFSET(FilterNameLength)==20)
  钉住记录布局,彻底绕开关卡。

### 修复尝试
- 首版两段式 → 单次 2KB 缓冲 → 名字/altitude/实例数全部就位
  (MyArkCore altitude 389998、WdFilter 328010、fileinfo 180000 等 11 项)。
- 子代理验收(ACCEPT-WITH-FIXES,1×P1+7×P2)全部落实:asi 分配失败
  continue 泄漏 filter 引用(P1);BypassDrops 在 disarm 期不再递增
  (与注释契约对齐);ADD 满表补 in-band Status;legacy filter 不再占用
  32 槽(仅 minifilter 计入 Count);ADD 拒绝 Pid=0;verify 补第三方
  进程采样闭环(bypass 期间其他 PID 事件仍在);ioctl.c 输入长度
  out-param 改名 inSize;重复注释行清除。

### 关键决策回顾
- verify 的 RAW DUMP 临时断言模式(把内核记录原样字节回传)是定位
  "km 结构布局/语义与假设不符"的高效手段——比盲改快得多。
- 旁路 PID 行为闭环三段式(ADD→本 PID 无事件+第三方有事件→REMOVE→
  本 PID 重新有事件)同时覆盖了选择性mute与全局mute两类假绿。
- ps: git bash heredoc 对含转义/引号的长 C 片段仍不可靠,一律走
  Write 工具 + python 拼接(本轮第三类踩坑,纪律升级)。

### 当前状态
- 1903(18362)与 Win11(22631)双 build 全绿;FILEMON 段新增 8 断言
  (0x818 两条 + 0x819 六条),原 R2-7 断言无回归。
- FILEMON 模块描述更新为 5 IOCTL。

### TODO
- 旁路 PID 持久化(跨 boot)未做,当前每 boot 需重新配置。
- 0x818 可选扩展:per-volume instance 清单(FltEnumerateInstances 全参)。

## 2026-09-17 — R3-14 CPU per-core 寄存器快照 0x84A(1903 test2 / 18362 + Win11 / 22631)

### 现象
- 实现期构建错误三连:__sgdt/__sidtr 内建名不存在(MSVC 实为 _sgdt 与
  __sidt)、KeIpiGenericCall 回调需要 (PKIPI_BROADCAST_WORKER) 显式转换、
  cpu_descriptor.c 未包含自身头导致 Init/Cleanup 非常量初始化失败。

### 与参考的对比
- FltGetFilterInformation(km)对 NULL/0 缓冲不返回 BUFFER_TOO_SMALL 而是
  SUCCESS(本日 R3-7 的教训)与 FltGetFilterInformation 两段式文档语义
  不适用于所有信息类——快照类 API 一律单次固定缓冲 + 充足 slack。
- MSR 白名单沿用 25_kernel/integrity_snapshot.c 的既有固定常量模式
  (LSTAR/EFER/PAT/APIC base),全树无任意 MSR 读写。

### 修复尝试
- _sgdt/__sidt 内建名核对 MSVC intrin.h 后修正;IPI 回调加显式转换;
  descriptor.c 补自身头包含。
- 子代理验收(ACCEPT-WITH-FIXES,1×P1+4×P2)全部落实:多 group 别名
  限制补注释(与 integrity_snapshot.c 同款 caveat);IPI 暂存注释改为
  真实理由;verify 恒真断言(gdtl>0xFFFF 对 UINT16 永假、len(set)>=1)
  换成有判别力的不变式(GDT limit 非零);vcxproj 补 cpu_descriptor.h;
  CurrentCpu 标注 advisory 语义。

### 关键决策回顾
- 协议 C_ASSERT(112/7224)+ python 偏移在写码时对表一次,验收时零偏移
  finding(对比 R3-1 轮 GPT 偏移返工)。
- MSVC x64 无 SIDT 内建的惯用替代是 __sidt(intrin.h 266 行),_sgdt 与
  __sidt 命名不对称——内建名以 <VS>/include/intrin.h 为准,勿凭记忆。

### 当前状态
- 1903(18362, 6 vCPU)与 Win11(22631)双 build 全绿:CPU 段 5 断言
  (count 匹配平台、vendor、CR0.PE|PG + GDT/IDT kernel、LSTAR 全核一致、
  EFER.SCE)。
- 新模块 65_cpu(config 门 MYARK_MODULE_CPU),协议头 MyArkCpuIoctl.h。

### TODO
- 多处理器组(>64 LP)系统未声明支持;如需 KeGetCurrentProcessorNumberEx
  + CountEx(ALL_PROCESSOR_GROUPS) 彻底修,记 KNOWN_ISSUES 级别。

## 2026-09-17 — R3-6 安全姿态快照 0x7D3 + 1903/22631 对账(双 build 全绿)

### 现象
- 0x7D3 首轮:WDAC 策略计数在 1903 对账一致(0==0,目录为空),但 Win11
  (22631)上驱动计 0、guest 实际 6 个策略文件;一次性 restart 查询只拿到
  "."/".." 占位项(iosb.Information=96)就 Success 返回。
- 修复过程中还暴露:目录句柄未带 SYNCHRONIZE/FILE_SYNCHRONOUS_IO_NONALERT
  时 ZwQueryDirectoryFile 可能以 PENDING 返回且 NT_SUCCESS 为真——解析
  未初始化栈缓冲(子代理 P1)。

### 与参考的对比
- 目录枚举的正确形态是多轮调用:首查 restart=TRUE,后续 restart=FALSE,
  直到 STATUS_NO_MORE_FILES。单 pass(restart 一次)只覆盖首批链,首批可能
  只含占位目录项——1903 空目录恰好掩盖,22631 有 6 文件即假绿/假红互换。
- NT_SUCCESS(STATUS_PENDING(0x103))==TRUE 的经典陷阱:无同步位 + 无事件
  的 Zw 查询必须显式等待或改同步句柄。

### 修复尝试
- 目录句柄补 SYNCHRONIZE + FILE_SYNCHRONOUS_IO_NONALERT(P1),多轮枚举
  循环到 NO_MORE_FILES(修复计数);hypervisor vendor 拷贝 15→13 字节
  (内核栈 OOB 读进用户可见输出,P1);VBS/HVCI found 值归一化为布尔
  (Enabled=2 严格模式与 NOT_FOUND=2 哨兵撞车,P2);AppLocker 死参数与
  五集合注释如实化;ADD 满表等按验收单落实。

### 关键决策回顾
- 哨兵语义设计要在写码前对齐真实取值域:HVCI Enabled 真机有 0/1/2 三态,
  NOT_FOUND 也用 2 就是自撞——found 归一化为 0/1,哨兵只表达"未找到"。
- 环境差异(1903 空目录 vs 22631 有 6 策略)把潜伏 bug 变成可见 FAIL,
  双 build 回归的价值实证。

### 当前状态
- 双 build 全绿:1903 SECPOST 6 断言(hv=1 vmwarevmware、WDAC 0/0 对账、
  BAM=1、AppLocker 0/0);Win11 22631 同样全绿(WDAC 1/6 对账一致)。
- secaudit 模块 3→4 IOCTL;描述字符串同步更新。

### TODO
- WDAC 4KB 单批枚举对超大目录(<33 项以内精确)足够;如需严格全量,
  改为动态缓冲重试(记 KNOWN_ISSUES)。
- AppLocker 只覆盖五个知名 collection(有界、已注释)。

## 2026-09-17 — R3-9 ObCallbacks STRIP_ACCESS 0x723/0x724(1903 + Win11 双 build 全绿)

### 现象
- 初版 0x71F/0x720 与已有 WFP 模块(MyArkWfpIoctl.h 的
  0x720 ENUMERATE_CALLOUTS)完全撞号。g_AllModules 链接顺序 callback 先于
  wfp → callback 先占 0x720 → wfp 的 MyArkIoctlRegistryAdd 在
  duplicate 检查处 STATUS_DUPLICATE_OBJECTID → WFP 全部 3 个 IOCTL
  (0x720/0x721/0x722)未被注册,模块静默变砖。1903 verify 全绿掩盖了
  这个问题(OBPROTECT 自己占的 0x720 工作正常,但 wfp 行假绿 + wfp
  ADD/REMOVE 两行 MUTATING FAIL 未被引起注意)。
- 子代理验收 REJECT(唯一一次 REJECT)发现了此 P0,并给出了
  "链接顺序依赖 + 完整 MATRIX 假绿" 的完整分析。

### 与参考的对比
- P0 的教训:多模块共用 FILE_DEVICE_UNKNOWN 的项目,新增 function code
  必须全仓 grep 排重——CTL_CODE 的只读 12 位 function 是全部区分空间。
  verify 的 is_registered 检查(查 code 是否在能力表)在撞号场景下
  天然假绿(撞号方 handler 背书了 code 的存在),MATRIX 的
  MUTATING zero-args rejected 检查则可以发现(被挤方 is_registered=
  False 必 FAIL)。
- 共享锁下的计数自增:EX_SPIN_LOCK shared 允许多 CPU 并发进入,
  普通 ++ 会丢增量,InterlockedIncrement64 是正确选择。

### 修复尝试
- P0:0x71F/0x720 → 0x723/0x724(子代理建议的空闲段),同步改 verify
  与 MATRIX 表。
- P1:strip 计数改 InterlockedIncrement64(共享锁允许并发 CPU)。
- P2:KernelHandle 检查(内核句柄豁免);verify 断言改全 mask 0x087B;
  TotalStrips 语义注释;陈旧 IOCTL 计数注释(12→17)更新;
  MATRIX 表补 OB_PROTECT_SET/STATUS 两行。

### 关键决策回顾
- 子代理验收不通过的 REJECT 结论必须 100% 落实后才能提交——P0 撞号
  如果没被抓住,WFP 模块会在生产上静默失效。
- OpenProcess(self PID) 确实走 ObCallbacks 路径(NtOpenProcess →
  ObpCreateHandle → pre-op intercept),而非 -1 伪句柄直接绕过——
  这是端到端测试的根基。

### 当前状态
- 1903 + Win11 双 build 全绿:OBPROTECT 6 断言(PROTECTED granted=
  #1ff784,UNPROTECTED granted=#1fffff,TERMINATE/VM_WRITE/VM_READ
  全剥零)+ MATRIX callback:OB_PROTECT_SET (mutating) registered=True。
- WFP 模块恢复:ENUMERATE_CALLOUTS registered=True(撞号解除)。
- 全 mask 0x087B(TERMINATE|CREATE_THREAD|VM_OPERATION|VM_READ|
  VM_WRITE|DUP_HANDLE|SUSPEND_RESUME)全剥验证。

### TODO
- PsThreadType 剥 THREAD_TERMINATE/SUSPEND_RESUME(R3-9b)。
- DKOM hide + ObProtect 联动(R2-5 SET_VISIBILITY 自动加入保护表)。

## 2026-09-17 — R3-8 Mutation 事务化 0x732-0x735(1903 + Win11 双 build 全绿)

### 现象
- 首轮 verify PREPARE 返回 err=87(INVALID_PARAMETER):python 打包
  4 个 UINT32 作为 header(Token72+OpCount+R1+R2=84+4=88),但 C 结构的
  Ops 数组实际在 @84(UINT32 对齐不需 8 字节 pad),4 字节多发落在
  结构尾部对齐 pad 上,Ops[0] 从 @84 开始 → python 的 ops 数据从 @88
  开始 = 首个 op 的前 4 字节落在 pad 上。
- 修完后又暴露 err=122(INSUFFICIENT_BUFFER):C sizeof=184(8 字节
  尾对齐)但 python 只发 180 字节。需补齐 4 字节 pad。

### 与参考的对比
- MSVC 结构对齐:Token 含 LARGE_INTEGER → 结构 alignment=8;Ops 数组
  成员仅 UINT32(alignment=4),Ops@84 无 pad;但 sizeof=roundup(180,8)
  =184。python 恰好发 180 → 报 err=122。教训:sizeof ≠ sum(sizeof(members)),
  必须用 C_ASSERT 钉住并在 python 侧 pad 到 sizeof。
- 本轮第三次踩 METHOD_BUFFERED aliasing,但已在 handler 模板中预防
  (snap=*inBuf 先于 RtlZeroMemory)——预防性模板从 T-C P0-1 沉淀至今
  已阻止了至少 4 次同类 bug。

### 修复尝试
- Python 打包:pack("<III", 1, 0, 0) 只发 3 个 header UINT32(不含第
  4 个 pad),然后 pad 到 _TX_PREPARE_SIZE(184)。
- 子代理验收(ACCEPT-WITH-FIXES,1×P1+4×P2)全部落实:ReadDword 改为
  返回底层 Zw 错误;移除 5 处死分支;HVCI found 归一化为布尔;Vendor
  拷贝 15→13 字节;AppLocker 死参数清除。

### 关键决策回顾
- C_ASSERT(sizeof(PREPARE_INPUT)==184) 在编译时钉住了含 pad 的真实
  尺寸——如果只算成员和(180),python 侧 180 字节会静默通过但在
  内核端读错 ops 数据。
- 事务模块自包含:不依赖 10_process 的 EPROCESS 偏移(#define),而是
  自行定义同值常量 + PsLookupProcessByProcessId(本地声明),避免
  跨模块 #if 依赖。

### 当前状态
- 1903(18362)与 Win11(22631)双 build 全绿:MUTTX 6 断言
  (PREPARE without token denied / PREPARE accepted / ROLLBACK rolled=0 /
  COMMIT applied=1 / COMMIT restore / TX_LIST audit >= 5)。
- mutation 模块 2→6 IOCTL;audit ring 32 entries 记录全部事务事件。

### TODO
- DKOM hide op(第三个 op 类型)留后续轮次(需 MYARK_OFF_EPROCESS_ACTIVE_
  PROCESS_LINKS 与 hide/unhide 状态机)。
- 事务槽跨 boot 持久化(当前每 boot 清零)。

## 2026-09-16 — R3-13 ReadDwell 系迁移 MmCopyMemory（B4 残留收口）（1903 / 22631 双机）

### 现象
- KNOWN_ISSUES B4 收口后仍残留两处 MmIsAddressValid 探针 + 裸拷贝:
  `MyArkKernelReadDwellBytes`(25_kernel, SSDT 行 trampoline 嗅探) 与
  `MyArkDynDataReadDwell`(70_dyndata, QUERY_SYSCALL 同功能)。
  MmIsAddressValid 只反映"此刻"映射状态, 实际访问仍可 fault(无 SMEP
  CPU 跨页 0x3B 前科)。
- 顺带发现旧实现两处契约瑕疵: kernel 版 NTSTATUS 函数 `return 8`
  (调用方被迫 `NT_SUCCESS(x) && x != 0` 双判); dyndata 版慢路径逐字节
  部分拷贝后仍返回 DWELL_MAX, 字节数失真。

### 与参考的对比
- 仓内已有三处 MmCopyMemory 先例(MyArkKernelReadSlot64 / WalkSsdt 槽位读
  / MyArkKernelReadDwell), 本次写法对齐 MyArkKernelReadSlot64 同款
  (MM_COPY_ADDRESS + NT_SUCCESS 门 + copied 计数)。
- 参考项目对同类内核内存读取采用带 guard 的安全访问; 本仓选择
  MmCopyMemory(文档化 API, IRQL<=APC_LEVEL, partial-copy 语义),
  不引入未文档化机制。

### 修复尝试
- 两函数改 MmCopyMemory(MM_COPY_MEMORY_VIRTUAL), 返回实际 copied
  (0=失败); kernel 版调用方同步改为 `dwellBytes != 0`, DwellBytesSize
  记录真实字节数(partial copy 尾部零填充: dwell[8] 预清零后整块
  RtlCopyMemory)。
- 全仓调用面核查: 两函数唯一调用点均为 IOCTL 直调路径(默认队列
  sequential, 无 execution-level 覆盖) → PASSIVE_LEVEL, 满足
  MmCopyMemory IRQL 约束; 无 DPC/通知回调调用面。

### 关键决策回顾
- 范围钉死在 B4 点名的两个函数: 全仓仍有 25+ 处 MmIsAddressValid
  (10_process/11_thread/12_memory 的 descriptor/Limit/Base 生命周期
  常驻读), 属后续加固项而非本项; 不机械扩范围。
- verify_core.py 无 DwellBytes 硬断言(全为 count/size/suspect-ratio
  维度), partial-copy 语义变化不影响 R3 断言。

### 当前状态
- 1903(18362) 与 Win11(22631) 双 build 全绿(49 只读 + 6 变更矩阵 +
  全部 S6 段), guest 无崩溃。
- 子代理验收 ACCEPT(无 P0/P1); P2-1(B4 文本过期)随本次收口改写。

### TODO
- 范围外观察(子代理 P2-2): dyndata_ioctl.c descriptor 字段、
  kernel_ioctl.c KSERVICE_TABLE_DESCRIPTOR 四字段等 MmIsAddressValid
  门控裸读仍在——目标均为 ntoskrnl 生命周期常驻 .data, 低风险,
  候选后续 ROADMAP 项"MmIsAddressValid 全仓清点/加固"。
- 10_process / 11_thread / 12_memory 模块的 per-offset 探针读迁移
  需逐模块评估 IRQL 面(部分在枚举热路径), 不宜机械替换。

## 2026-09-16 — R3-12 modules/* UI 自建 Treeview 接入 scaling.py（B3 残留收口）（纯 R3, 无 VM 轮次）

### 现象
- KNOWN_ISSUES B3 修复时四个共享组件(tree_table / history_window /
  diff_window / detail_window)已接入 scaled_width, 但 8 个模块各自
  构建的 Treeview(module/file/network/process/memory/registry/
  thread×2/security_audit)仍是 96-DPI 写死列宽——>100% DPI 下 CJK
  表头/单元格截断。

### 与参考的对比
- 接入模式对齐四个共享组件同款: `scaled_width(widget, N)` 包住每处
  `tree.column(width=N)`; widget 传树自身(其 winfo_fpixels 挂在同
  一显示器上)。
- ttk.Entry / Label 的 width 是字符单位, 随字体缩放自适应, 不在
  本项范围; network 模块 `width=0` 是"按内容自动宽"重置(协议切换时
  清空列元数据), 0 不是设计像素, 不做缩放(缩了反而变 1px)。

### 修复尝试
- 8 模块 10 处列宽调用点全部接入(循环体一处改写即覆盖整表);
  新增 import 8 处。
- test_ui_scaling.py 新增 TestModulePanelsIntegrated 两个源码级
  守护测试: 扫 modules/*/ui.py, 断言 (a) 构建 Treeview 的模块必须
  import scaled_width, (b) 所有 .column( 调用的 width 必须被
  scaled_width 包住或显式 width=0。防新增面板回归。

### 关键决策回顾
- 守护测试选源码扫描而非实例化面板: conftest Tk 共享根能跑面板,
  但列宽断言需要逐列读 column 选项, 源码扫描一条断言覆盖 8 模块
  且 headless 稳定; 代价是格式敏感(单行调用约定)——与仓内"一行一
  column 调用"现状一致。
- network 的 replace_all 首轮只命中 UDP 分支(12 空格缩进), TCP
  分支 8 空格缩进漏网, 残留检查 grep 抓出后补改——**缩进不同的
  同文本 replace_all 不算全覆盖**, 残留 grep 是必须步骤。

### 当前状态
- client 全套 865 passed / 7 skipped(含 2 个新守护测试)。
- 纯 R3 改动, 不涉驱动, 无 VM 轮次。

### TODO
- system-aware DPI 运行时重算仍不做(B3 原范围说明保持)。
- preflight / trust 模块的 Entry/Label 字符宽度无需接入, 若未来
  出现像素级布局(panedwindow sash / canvas)再评估。

## 2026-09-16 — R3-15 WFP/NDIS 网络过滤清单 0x8A2/0x8A3（1903 / 22631 双机）

### 现象
- 72_wfp 模块 0x720-0x722 是 S7.3 脚手架(0x720 返回 Count=0 空桩,
  0x721/0x722 NOT_IMPLEMENTED), "WFP inventory / NDIS 链"整项缺失
  (内部对标矩阵 MyArk 列 ❌)。
- 首版设计走 NdisRegisterProtocolDriver + NdisOpenAdapterEx 拿绑定句柄
  再 NdisEnumerateFilterModules——1903 实测 `binds=0`: 运行时注册的
  无 INF 协议收不到**任何** BindAdapterEx 回调, 连
  NdisReEnumerateProtocolBindings 都不触发绑定引擎(诊断字证明
  BindAdapterEx 从未被调用)。绑定句柄路对运行时驱动是死路。

### 与参考的对比
- 官方文档明确 NdisEnumerateFilterModules 的 NdisHandle 只接受
  miniport 适配器 / 协议绑定 / 过滤模块三种句柄——裸协议注册句柄
  INVALID_PARAMETER。绑定句柄只能来自 NdisOpenAdapterEx, 而它又需要
  绑定通知给出的 BindContext——鸡生蛋。
- 参考项目对应面(0x829 WFP callout 增删 + 规则引擎)是"管理自己注册的
  callout"; 本项定位是**系统级清单**(谁装了过滤/谁能装过滤), 语义
  不同, 各自成立。
- ndis.h 两个集成坑(头注释与文档均不显眼): (a) NDIS6 面必须在
  include 前 `#define NDIS6xx` 才展开, 否则全部 NDIS_SUPPORT_NDIS6xx
  为 0, PNDIS_BIND_PARAMETERS 等类型"未定义"(C2081 级联); (b) WDK
  头的匿名联合在 /W4+WX 下需 pragma 4201/4214 包裹。

### 修复尝试
- **终版 0x8A2**: Zw 注册表走查 NetService 网络类
  ({4D36E975-...}), 每行 ServiceName/InstanceGuid/FriendlyName
  (Connection\Name), 文档化 API, PASSIVE, 零网络栈注册。
- **0x8A3**: PsLoadedModuleList 走查(KLDR 偏移 0x30/0x48/0x58 与
  dyndata 同源) + PE32+ 导入目录解析(仅 DWORD RVA, 20 字节描述符,
  Name@+12), fwpkclnt.sys→WFP_CAPABLE, ndis.sys→NDIS_CAPABLE;
  解析失败 FLAG_PARSE_FAILED 不跳行, 行数守恒。
- 首轮部署两个注册表路径 bug: (1) RtlStringCchPrintfW 以 `uni` 为
  %wZ 源而 `uni` 已被重绑到目的缓冲自身——src/dst 重叠, 第二个服务
  起路径全垃圾(实测 count=1); (2) FriendlyName 路径漏拼类前缀。
  修法: uniClass 全程钉死类字面量, uni 每次 open 前重绑。

### 关键决策回顾
- 诊断字段进输出头 Reserved(第 3 字节打包 binds/openfail/open),
  verify 断言消息透传——一次 VM 往返定位"注册成功但零回调", 避免
  盲改循环。
- **heredoc 批量补丁的静默失败**: python patcher 里写 `\\x00`
  (双反斜杠)落盘成字面量反斜杠序列, 与既有 `\x00` 不匹配导致
  s.replace 无痕跳过——同一文件 5 处补丁只有常量行生效, VM 轮次
  跑的还是旧解析。教训: 含反斜杠/转义的内容改用 Edit 工具或先
  grep 验证替换生效计数。
- NDIS 方案代码(~200 行协议注册/绑定槽/异步开闭)整体回退而非
  保留半成品: 死路上的代码只会误导后人。
- 0x8A2 断言钉 count>=3(任何工作站 SKU 的 NetService 类至少有
  ms_lltdio/ms_pacer/wfplwfs 系), 不钉具体名字防 SKU 差异。

### 当前状态
- **验收首版 REJECT(1×P0)**: 0x8A3 把 PE 可选头 `optHdr+0x70` 当导入
  目录读——那是 **Export** 目录, DataDirectory[1]=Import 在 `+0x78`。
  VM 断言仍绿的假阳性机理: fwpkclnt.sys 的导出目录第一条描述符
  Name 字段恰好是其自身导出模块名字符串 "fwpkclnt.sys", 被误标
  WFP_CAPABLE; 真实导入者 tcpip.sys/wfplwfs.sys 全部漏标。
  审查员用本机真实 PE 逐字节模拟坐实。修复: 改读 `+0x78` 并加
  **tcpip.sys 必须被能力位标记**的确定性断言(该断言可直接抓住此类
  假阳性)。修复后 1903/22631 双绿。
- 其余落实: P1(Win11 26100+ GUID 命名记录布局)加 ComponentId 回退
  行; P2×4(ReadFriendlyName 越界序、0x8A2 枚举迭代护栏、矩阵标签
  49→52 漂移修正、头注释诚实化为 ANSI 低字节渲染+双布局范围说明)。
- 1903(18362) 与 Win11(22631) 双 build 全绿(52 只读 + 6 变更矩阵
  + 全部 S6 段), guest 无崩溃。
- client 侧 wfp 模块镜像 + 5 个单测(布局/IOCTL 码/解析/错误路径),
  client 全套 870 passed。
- ndis.lib 已从 vcxproj 摘除, 驱动回到零 NDIS 依赖。

### TODO
- 0x8A2 的**实时挂载序**(per-adapter attach order)与 INF 安装型
  过滤驱动方案: 需机器配置(INF/FilterList), 属可选后续, 不在
  无人值守范围。
- 0x720 真实现(FwpsCalloutRegister 自有 callout 管理)仍是 S7.3-fix
  预留, 语义对齐同类工具 0x829 的增删规则引擎时一并做。
- **既有偏移疑点(验收 P2 发现, 非本项引入)**: dyndata_internal.h
  把 SIZE_OF_IMAGE 与 FULL_DLL_NAME 都钉在 KLDR 0x048——两者必有一
  错; 1903 上 QUERY_MODULE 实测通过说明该用法在目标 build 成立,
  但语义待 KDNET 修复后用 `dt nt!_KLDR_DATA_TABLE_ENTRY` 一次性
  钉清(与 R3-3/R3-4 偏移轮同场)。
- PE 导入解析已按真实 PE 逐字节核验(审查员模拟 + tcpip.sys 断言);
  delay-load 导入检测(EAT 间接)不在范围。

## 2026-09-16 — KLDR 偏移判别：SIZE_OF_IMAGE 0x048→0x040（R3-15 验收 P2 跟进）（1903 / 22631 双机）

### 现象
- R3-15 验收审查 P2 指出 dyndata_internal.h 把 SIZE_OF_IMAGE 与
  FULL_DLL_NAME 同时钉在 KLDR 0x048——两者必有一错。
- 新增 [KLDRDIAG] verify 探针(QUERY_MODULE 行数据判别): 首跑
  `sizes_ok=False ntos=False`, ImageSize=0x420042——恰是 UNICODE_STRING
  的 Length/Max 各 0x42(= 33 字符, "\SystemRoot\system32\ntoskrnl.exe"
  的字节长度), **0x048 实为 FullDllName**。

### 与参考的对比
- 与公开的 x64 KLDR_DATA_TABLE_ENTRY 布局对照: DllBase@0x30,
  EntryPoint@0x38, **SizeOfImage@0x40**, FullDllName@0x48,
  BaseDllName@0x58——仓内 0x030/0x048/0x058 都对, 唯 SIZE_OF_IMAGE
  错挂到 FullDllName 头上(QUERY_MODULE 的 ImageSize 列一直是错值)。
- 判别判据设计: 真 SizeOfImage 必 4K 页对齐; 误读 UNICODE_STRING
  得到的 Length|Max 值几乎不可能页对齐——单字节判据即可分案。

### 修复尝试
- dyndata_internal.h: MYARK_OFF_KLDR_SIZE_OF_IMAGE 0x048→0x040,
  布局注释写明实测来源; 72_wfp/wfp_inventory.c 同步 0x040。
- 探针自身两轮校准: (1) 行距 348→352(结构体尾部 8 对齐); (2)
  dyndata 的 Name/FullPath 是**每字符 2 字节的 UTF-16 加宽存储**
  (MyArkDynDataReadUnicodeString 写 lo+0x00 两字节), 按 utf-16-le
  解码——首跑 'n'/'\\' 单字符是探针解析错误, 不是驱动数据错误。

### 关键决策回顾
- 无 KDNET 也能钉偏移: 用"数据自洽性"探针(页对齐+路径内容+规范
  化内核 VA)替代 dt 离线枚举, 一轮 VM 往返出结论。
- 判别探针固化为 [KLDRDIAG] 常驻回归段, 防止该偏移再被无意改动。

### 当前状态
- 1903(18362) 与 Win11(22631) 双 build 全绿([VERIFY] OK,
  52 只读 + 6 变更 + KLDRDIAG); QUERY_MODULE ImageSize 列首次
  给出页对齐真值。

### TODO
- QUERY_MODULE 的 ImageSize 此前若被下游消费过(客户端显示),
  历史值为错值; 现已纠正。
- KLDR 偏移在 24H2 (26100) 的复核并入 24H2 回归轮。

## 2026-09-17 — test2 KDNET 修复（三因并发：孤儿 kd / 防火墙 / debug off）（1903 / test2）

### 现象
- test2 自 2026-09-08 记录专用 KDNET（port 50001, key 见
  build/test2_kdnet.txt）后一直不可用，R3-3/R3-4/R3-1b 全部因此搁置。
- 排查发现**三个独立故障并存**，缺一即断：
  1. 宿主机有孤儿 kd.exe（PID 19684）——AGENTS §1 点名的检查项，
     也是 2026-09-08"误连克隆机冻结 guest"事故的同款；
  2. 防火墙只有 KDNET-debug-50000 规则（旧机 svmb 用的 50000），
     **没有 50001 的入站 UDP 放行**；
  3. guest 加载器 `bcdedit /debug on` 从未生效——`bcdedit /enum
     {current}` 里没有 debugmode 行。dbgsettings（key/port/hostip）
     一直是对的，但加载器 debug 关着，引导期根本不发起 KDNET 握手。

### 与参考的对比
- windbg-vm-kernel-debug 技能的 KDNET 流程（kdnet.exe + 防火墙 +
  重启握手）是针对旧机 "Windows 10 x64"（port 50000）沉淀的，test2
  平移时只搬了 dbgsettings、漏了 debug on 与防火墙端口——**换机
  复用调试配置时，三件套（dbgsettings / debug on / firewall）要
  逐项重验，不能假设随 key 一起搬过去了**。
- `bcdedit /dbgsettings` 回读"操作成功完成"只证明 dbgsettings 对，
  不证明 debug 开着——判据必须是 `/enum {current}` 里出现
  `debug Yes`。

### 修复尝试
1. `Get-Process kd | Stop-Process -Force` 清孤儿（Git Bash 下
   taskkill /F 会被转义成 F:/，必须 PowerShell）。
2. 防火墙加规则需提权：`Start-Process netsh -ArgumentList ... -Verb
   RunAs -Wait` 弹 UAC，之后 `netsh ... show rule name="KDNET-debug-
   50001"` 拉到"已启用 是 / 本地端口 50001"作正向证据。
3. 舰队脚本 `build\vm_kdnet_set.bat`（文件通道 + 全段 < NUL +
   8 秒双回读判据）重写 dbgsettings；随后文件通道跑
   `bcdedit /debug {current} on` 并回读 `debug Yes`。
4. `vm_reset_hard` 重启激活——**重启后 BCD 未回滚**（debug Yes +
   port 50001 保持；"reset 触发回滚"是当年快照回滚事故的记忆
   混淆，test2 硬重启本身不回滚）。

### 关键决策回顾
- 修复顺序：先清残留再动连接——孤儿 kd 占着通道时，任何重试都
  是在打幽灵目标（2026-09-08 的教训）。
- windbg-mcp 会话保持极短生命周期：连接即自动断入
  （nt!DbgBreakPointWithStatus）→ vertarget 取证 → close（库先发
  g 再断链）。宿主空闲内存基线 6.3GB → 会话后 6.1GB，无池爆炸
  （与技能 2026-09-06 "mcp-windbg 路线不复现经典 kd 池爆炸"的
  实测一致），kd.exe 零残留，guest 探针回声正常。

### 当前状态
- test2 KDNET 全链路可用：open_kd_session(net:port=50001,key=...)
  连接 → 自动断入 → 命令交互 → 放行 → guest 存活。
- 防火墙规则 KDNET-debug-50001（入站 UDP）已固化。
- R3-3 定时器/DPC、R3-4 PspCidTable、R3-1b ARP/uid 全部解锁。

### TODO
- R3-3 第一轮即可用断点式取证 SOP（打印即放行，禁止真单步）。
- 24H2 KLDR 偏移复核仍需一台 24H2 测试机（环境项，另行安排）。
- 下次快照/回滚类操作后，KDNET 三件套按本条清单逐项重验。

## 2026-09-17 — Win11 (22631) KDNET 打通（真因：vmrun 硬断电丢 BCD hive 未落盘事务）（22631 / 软重启路径）

### 现象
- test2 KDNET 修复同日，Win11 (22631) 照搬三件套后仍不通，且出现**假象**：
  手工写入的 NET dbgsettings（busparams/key/port/hostip 全部"操作成功完成"
  且立即回读确认）在 `vmrun reset hard` 之后变回 `Local`，而同条目的
  `debug Yes`/`testsigning` 存活——呈现"只清一半"的诡异形态。一度误判为
  "Windows 引导期清除失败配置"。
- 首次连接尝试还把 guest 打入冻结态：连接+断入成功后 ZCode 的 MCP 客户端
  30s 超时杀掉 kd.exe（被杀的调试器不发 g），目标全体 CPU 停在 int3，
  VMware Tools 无响应、vmrun runProgramInGuest 永久挂起。

### 与参考的对比
- 破案钥匙是第三轮的对照实验：**同样的写入改用软重启（shutdown /r）后，
  全部设置原样存活**——排除 Secure Boot(False)/BitLocker(全解密)/VBS(关)/
  快速启动(与本例无关)/网卡绑定(3.0.0 无误)，唯一与 test2 的结构差异只剩
  引导路径(UEFI vs BIOS)与写盘时机。
- 真因：**vmrun reset hard = 突然断电，BCD hive（注册表事务日志模型）里
  尚未 checkpoint 的最近写入被丢弃**。debug Yes 是更早轮次写入（已落盘）
  所以"存活"；NET 参数是紧邻断电写入所以"丢失"。**Windows 从来没有清过
  任何设置——是我们用硬断电反复抹掉自己的写入。**
- 次生教训：对处于断入冻结态的目标重复 open_kd_session，会进入
  "断入成功但 kd 等不到提示符"的半连接脏状态（旧调试器被杀后目标的
  kdnet 状态机残留），重连无效，唯一恢复是硬重启。

### 修复尝试
1. 假 reset 排除：LastBootUpTime 对上 reset 时刻（上一轮已知"1 polls"
   假签名，本轮用 uptime 复核确认 reset 真发生）。
2. 软重启对照：bcdedit 写完全部参数后 `shutdown /r /t 3 /f` →
   重启后 {current} 与 {dbgsettings} 两级 NET 配置完整存活。
3. 连接成功（Windows Kernel Version 22621 MP，内核基址
   0xfffff804`5a800000）后 30s 客户端超时杀 kd 造成冻结 → 挂起 vmrun
   排查 + 硬重启恢复 → **stdio 直驱 mcp_windbg**（绕开 ZCode 30s
   工具超时，build/kd_unfreeze.py，JSON-RPC initialize→tools/call）→
   对自由运行目标连接/断入/放行全链路成功。

### 关键决策回顾
- **BCD 变更后的重启纪律**：改完 dbgsettings/debug 必须软重启
  （shutdown /r）落盘；vmrun reset hard 只能当恢复手段，不能当
  "使配置生效"的手段用——加密 VM/NVMe 上 hive 事务随时可能没刷盘。
- **连接冻结合命周期**：open_kd_session 成功断入后，close(resume=true)
  必须尽快执行；30s 客户端超时会杀 kd 且不发 g。长符号加载场景
  （新 build 首连）一律走 stdio 脚本。
- kd.exe 被杀 + 目标冻结的组合状态：重连无效（半连接脏状态），
  唯一恢复 = vm_reset_hard，恢复后重做干净连接。

### 当前状态
- Win11 (22631, 内核 22621) KDNET 全链路可用：port 50002，key 见
  build/win11_kdnet_key.txt，stdio 脚本 build/kd_unfreeze.py 可复用。
- 双机调试通道齐备：test2=50001（BIOS），Win11=50002（UEFI+vTPM）。
- BCD 设置当前两级（{current} + {dbgsettings}）均为 NET 且已落盘，
  本次引导后仍在。

### TODO
- R3-3 继续：22631 偏移发现会话（通道已通，dt _KPRCB/_KTIMER_TABLE
  + KiWait* 符号偏移一轮拿全），替换运行时自标定的兜底假设。
- Windows Update 后 BCD 调试设置可能被重置（未验证），重连失败时
  先读 {dbgsettings} 排查。
- 建议未来把"写 BCD → 软重启"封装成 vm_kdnet_set 的 Win11 分支。

## 2026-09-17 — R3-3 定时器/DPC 枚举 0x8A4/0x8A5（1903 / 22631 双机，KDNET 双侧取偏移）

### 现象
- 新模块 26_timerdpc：0x8A4 QUERY_TIMER 逐 CPU 走 KPRCB.TimerTable
  （TimerExpiry[64] + 桶链表），解码 Win8+ 混淆的 KTIMER.Dpc，输出
  DueTime/Period/Routine/Context/Owner；0x8A5 QUERY_DPC 快照每 CPU
  DPC 队列（normal/threaded）+ ActiveDpc。只读。
- 结构语义经 1903 KDNET 会话确认：KTIMER.Dpc 存的是**混淆指针**
  （明文读出 0x8f42f47f... 非规范），KDPC.DeferredRoutine 是**明文**。

### 与参考的对比
- **混淆算法从 KiSetTimerEx 反汇编破译**（试探 ROR/ROL×键组合全部
  失败后转向反汇编）：stored = ROR64(bswap64(Always^Dpc) ^ Timer,
  Never & 0x3F) ^ Never——中间的 **bswap 是全部蛮力枚举失败的原因**
  （旋转与 bswap 不可互相表达）。活样本验证：E=cb78...465a →
  D=ffff8a8979316160（合法池地址，嵌入式 KDPC）✓。
- 两 build 偏移全部 KDNET 实测（dt/x 符号解析）：18362
  TimerTable=0x3680/DpcData=0x2E00(0x28)/Never=0x574700/Always=
  0x5748F0/KiProcessorBlock=0x575AC0/桶 256@0x200；22621
  TimerTable=0x3C00/DpcData=0x3340(0x30)/Never=0xD1EE88/Always=
  0xD1F120/KiProcessorBlock=0xD20980/桶 512@0x2200（TimerEntries
  是 [2][256] 二维数组，线性等价）。KDPC_DATA 22631 增
  LongDpcPresent@0x28（步长 0x28→0x30）。

### 修复尝试
- 首轮 Win11 count=0：**符号偏移减法算错**（0x5B520980-0x5A800000
  应为 0xD20980，误写 0x4D20980，三个符号全错）。妙处：错误偏移
  落在 nt 镜像外 → probe 全失败 → 优雅回 0 行而非蓝屏——安全设计
  （MmIsAddressValid 门控 + 非规范地址 break）按预期工作。
- 首轮 1903 owner 全空：EmitTimer 里 FlagsForRoutine 先写行内
  Owner、随后 RtlZeroMemory(row) 把它抹掉。修为：zero 行 → 填字段
  → 再写 owner/flags。verify 断言同步从 flagged 改 named>=3
  （nt 常驻例程的 owner 是 ntoskrnl.exe，本来就不该打 SUSPECT）。
- MUTATING 标签历史漂移修正（6→8，实际条目数）。

### 关键决策回顾
- 偏移来源走 Tier C（KDNET 实测双构建 profile），未做运行时自标定
  ——通道已通的情况下，实测常量比启发式发现更可信、可审计。
- DPC 队列链接（DpcListEntry.Next）在部分 build 上可能也是编码的：
  走查带验证门（非规范即停），编码时诚实退化为 0 行 + ActiveDpc
  仍可报，不做猜测性解码。
- OWNER 用 PsLoadedModuleList 走查解析（dyndata extern 复用），
  例程归属可读名；nt text 例程打 NTROUTINE，不在任何模块内打
  SUSPECT（rootkit 信号）。

### 当前状态
- **验收 ACCEPT（1×P1 + 8×P2，全部落实）**。P1：FlagsForRoutine 首行
  `*Flags = 0` 会覆盖调用方预置的 EXPIRY 标志——改为接收 BaseFlags
  做 OR 保留。P2 落实：NO_MODULELIST 状态真正置位（模块表不可用时
  owner 退化为空、行仍有效）；去重 Seen[128] 上限改为直接扫描输出
  行（容量不再受限）；verify 拉满 512 行 hard cap（Win11 实测 256
  行饱和，真实计数可见）；client parser 增加 EntryStructSize 前向
  兼容校验；MATRIX mutating 标签 6→8 历史漂移修正；死读清理。
  未改（已记录）：多处理器组边界（单组 VM 无影响）、EnsureInit
  理论竞态（Sequential 队列不可达）。
- 修复后二进制 1903 与 Win11 双 build 重验 [VERIFY] OK。
- client 侧新模块 timerdpc（protocol/parser）+ 5 单测，全套
  875 passed。

### TODO
- DPC 队列链接若被编码（本轮未取到非空队列样本），后续用
  KeInsertQueueDpc 自注 DPC 做对照实验确认链接语义。
- timer 遍历目前限 group 0（KiProcessorBlock 按组内索引）；
  多处理器组（>64 逻辑 CPU）宿主为已知边界。

## 2026-09-17 — R3-4 PspCidTable 全表 + DKOM 隐藏进程检测 0xA0D（1903 / 22631 双机）

### 现象
- PspCidTable 是内核 CID 句柄表——每个有 PID/TID 的进程/线程在此都有
  一个条目，包括被 DKOM 从 ActiveProcessLinks 摘链隐藏的进程。10_process
  的 ENUM 只走 ActiveProcessLinks，对 DKOM 隐藏视而不见。
- 首次实现后 1903 procs=4（应该 ~30）threads=653（应该 ~2000）——走查
  严重不完整。DKOM hide 路径触发 0x3B 蓝屏两场（16:28 / 17:18 minidump）。

### 与参考的对比
- **蓝屏真因**：process_actions.c 的 DKOM hide 使用 Tier C 硬编码
  `MYARK_OFF_EPROCESS_ACTIVE_PROCESS_LINKS = 0x1D8`（26100 专属值）。
  1903 的 ActiveProcessLinks 实际在 EPROCESS+0x448。写 0x1D8 处的
  无关字段当 LIST_ENTRY → AV → 0x3B。QUERY_PROCESS 用的是 Tier B
  运行时发现（MyArkDiscoverActiveProcessLinks），所以一直正确——
  **同一偏移在同一模块内存在 Tier B（正确）与 Tier C（错误）双源**。
- **CID 走查不全真因**：level-1 分页按 512 条目/页（8 字节假设）分块，
  实际 16 字节/条目 → 256 条目/页。idx ≥ 256 后读的是 chunk N+1 的
  条目（真实对象但 cid 错位），procs 膨胀/缺失混合。
- **TypeIndex 假滤器**：OBJECT_HEADER.TypeIndex 在 Win10 是按对象编码
  的（ObHeaderCookie 机制），裸比较 System 的值与其它进程的值不可靠。
  改用导出函数 ObGetObjectType（走 header 的 ObjectType 指针解引用，
  免编码问题）。

### 修复尝试
- DKOM hide/restore 改用 `MyArkArkOffsetsGet()->ActiveProcessLinks`
  （Tier B 运行时发现，与 ENUM 同源），1903 hide=1 不再蓝屏。
- CID 走查重构：dir 页数入 Tier C profile（18362: 4 页 / 22621: 8 页，
  KDNET dq 实测）；pagePtr==0 即 break（表尾自然终止）；移除
  consecutiveFree 提前退出（稀疏表会假停——尾部 PID 空洞 > 512 触发）。
- membership 走查重写：System 的 Flink 链上每个 LIST_ENTRY 地址减
  linksOffset 得 EPROCESS 地址；System 自身入集。
- TypeIndex 判别改 ObGetObjectType（导出函数，免按 build 钉类型索引）。
- membership 集合最初存的是 LIST_ENTRY 地址而非 EPROCESS 地址——
  减 linksOffset 修正后 HIDDEN 检测一次通过。

### 关键决策回顾
- **离线 minidump 分析是定位蓝屏根因的最快路径**：拉回
  091726-13281-01.dmp → cdb + 本地 PDB → `.ecxr; r; ln @rip` →
  `MyArkProcessPerformDkom+0xb2` → `u` 反汇编看到 `lea rbx,[rdi+1D8h]`
  → 直接指向硬编码偏移。全程 ~3 分钟，不需要 KDNET。
- dir 页数入 profile 而非动态发现：值在 KDNET dq 下可一次取全，
  不需要复杂化。
- DKOM hide 往返测试（hide → 查 CID 表 HIDDEN 标记 → restore →
  查标记清除）同时验证三件事：hide DKOM 正确、CID 表可见隐藏进程、
  restore 可逆——一次覆盖三源比对全链路。

### 当前状态
- **验收 ACCEPT（有条件）→ 2×P1 + 6×P2 全部落实**。
  P1-1：level-0 分支 entriesPerPage 误设 65536（应为 256/页）→ 统一用
  PAGE_ENTRIES。P1-2：ObGetObjectType 前补 MmIsAddressValid 门控
  （该调用是全文件唯一未过门的解引用）。P2 落实：membership 走查
  加 membershipWalkOk 门控防误标 HIDDEN；注释/死 define/无用
  TRUNCATED flag 清理；verify kill 移入 finally；dyndata 同类
  0x1D8 硬编码残留（只读路径、产出错值不 AV）记 TODO。
- 修复后二进制 1903(133 procs/1053 threads) 与 Win11(143/1495)
  双 build 重验 [VERIFY] OK，DKOM hide 往返双机通过。
- client 侧 timerdpc（protocol/parser）+ 5 单测，全套 875 passed。

### TODO
- 内核对象摘要 + IPC 摘要（ROADMAP R3-4 剩余部分）——本轮聚焦
  PspCidTable + 隐藏检测，对象/IPC 摘要待后续轮次。
- PspCidTable 22621 的 dir 页数可能在系统高负载后增长（当前 8 页
  已覆盖 1495 线程），如果 verify 失败先检查 dir 页数。

## YYYY-MM-DD — 轮次标题（VM / OS build）

## 2026-09-18 — R3-1b HWID 伪装续作：0x83 标识符类交付 + ARP/nsiproxy 逆向深潜（test2 1903 + KDNET）

### 现象
- 0x83（DEVICE_ID）类：驱动侧完成例程/探测一次成型；1903 的 NVMe 盘
  STORAGE_DEVICE_ID_DESCRIPTOR 返回 Size=32、NumberOfIdentifiers=0（VMware
  NVMe 命名空间无 NGUID/EUI64）→ 无标识符可改，verify 走"干净拒绝"契约级
  断言（状态 c000000d、applied=0），通过。真机有 0x83 标识符时路径与
  DISK_SERIAL 同构（长度门控 + 头部不动）。
- ARP 类：0x753 动作/捕获脚手架（0x754 读回）落地后，邻表 MAC 始终不在
  捕获缓冲中出现——tuples 记到、QueryCount 计到 898+，但 OUI(00:50:56)
  内容门零命中。

### 与参考的对比
- 同类开源工具的对应能力（GPL，只借鉴行为）：在 nsiproxy 完成例程改写邻表项。
  我们确认该层可行，但 NSI 的请求/响应编排远比预想复杂（见下）。
- NSI 逆向结论（全部 1903 18362 实测）：
  1) NSI IOCTL 全部 METHOD_NEITHER：0x120007(query, in=80)、0x12000F
     (allocate-get-table, in=104)、0x12001B(enumerate, in=112)；
     SystemBuffer 恒 NULL，输入=Type3InputBuffer，输出=UserBuffer。
  2) 用户态请求即 NSI_PARAMS：+0x10{模块描述符指针,+0x18 标志}，
     +0x28/+0x38/+0x48/+0x58 = {内嵌缓冲指针,+8 长度} 对。
  3) 邻表数据路径：GetIpNetTable2 → nsiproxy → tcpip!Ipv4NsiProviderDispatch
     → IpEnumerateAllNeighbors（0x12001B 处理器，k 栈实证）→ 逐条
     IppFillNeighborParametersUnderLock。邻表对象("Ipne")：PhysAddrLen@+0x80
     (=6)、IP@+0xC8、MAC@+0xCC；RW 参数结构 16B：State@0/Reach@4/
     router@8/unsafe@9/PhysAddrLen@0xA/IfIndex@0xC；MAC 经 memcpy 到独立
     出缓冲（filler 的 rdx）。
  4) 提供者侧上下文（filler 命中时 rsi）：+0x78=条目数(0xB)、+0x20=列
     描述符链表头、+0x68/+0x70=两块内核缓冲。tcpip 在内核池组包后由
     nsiproxy 拷给用户缓冲——完成例程里改用户缓冲需要列布局（未钉死）。
  5) 0x83 与 ARP 之外：老 GetIpNetTable（arp -a）= 17×0x120007 小查询，
     不产生大枚举；0x12000F+568B 平铺表是 netstat -rn 的路由表。

### 修复尝试
- 捕获通道三轮演进：SystemBuffer 门（0 元组）→ 全主功能码 → METHOD_NEITHER
  参数/SEH 解引用链 → OUI 内容门 + 0x754 诊断计数。完成例程在调用者线程
  PASSIVE 上下文可安全 ProbeForRead/Write 用户 VA（caller-context 校验 +
  IRQL 门 + SEH，全部 fail-open）。
- KDNET 动态：符号服务器可用（tcpip/nsiproxy PDB 下载成功）；断点
  IppFillNeighborParametersUnderLock 稳定命中。踩坑：waited `g` 超时会诱使
  MCP 发 break 包把目标打断在时钟中断（假"冻结"）；fire-and-forget g +
  线程等回包 + Popen 触发器是唯一稳定模式。孤儿 kd.exe 必须先清否则新
  会话 no_debuggee 超时。

### 关键决策回顾
- 0x83 先行独立成片（无未知数），ARP 布局校准独立成片——符合"每轮
  一个原子切片"纪律。
- ARP 改写点选择：坚持完成例程层（对齐文档 T-B 范围声明），不做内核
  邻表直改（DKOM 式）。
- 1903 NVMe 无 0x83 标识符属环境事实，验收改为契约级 + 真机可全链路。

### TODO（下一会话从这两步起）
1. 最后一块拼图：列布局。两条等价路线任选：
   a) kd 会话（v12 已就绪 build/kd_arp_v12.py，断点/触发/清理全部固化）：
      在 filler 命中后 dump 列描述符链节点内容（+0x20 链，每节点
      LIST_ENTRY 后是 {Type,Offset,Size}）+ gu 后对提供者上下文 +0x68/
      +0x70 两缓冲 db 全量——IP/MAC 在组包区的偏移即用户列偏移。
   b) 驱动捕获：0x12001B(in=112) 请求的 +0x28/+0x38/+0x48/+0x58 解引用
      已覆盖，仍零 OUI → 优先怀疑 112 字节请求的列对在 +0x60 之后
      （inLen 实测 112 = 0x70，被 64B tuple Input 截断看不到）——把
      tuple Input 扩到 96B 或先经 kd 拿布局。
2. 拿到布局后：hwid_spoof_arp.c 实现改写（按 IP 键定位条目索引 → 对应
   列缓冲改 MAC），Tier C 双构建 profile（18362 先行，22631 同法校准），
   verify ARP 断言从"捕获工具"升级为"改写往返"，子代理验收 → 双机回归
   → 提交。0x83/捕获脚手架部分可先行提交（见 git 现状，verify 剩 2 条
   ARP 断言待改写落地后转绿）。
- 环境注意：test2 曾在 kd 会话异常后退回关机态；vm_reset_hard 已恢复。
  guest_cmd.txt 当前是校准脚本；触发器应切回 for 循环跑
  hwid_arp_table_dump.py（无驱动依赖）。


## 2026-09-19 — R3-1b ARP 逆向收官：NSI 用户缓冲列布局钉死（捕获通道三轮修正 + seq=13）

### 现象
- 承接 09-18 轮：0x754 捕获通道 tuples/QueryCount 正常但 OUI(00:50:56)
  内容门零命中，dump 恒 0，"MAC 不在用户缓冲"成谜。
- v14（KDNET，bp IppFillNeighborParametersUnderLock）实证：filler 的
  rdx 就是 MAC 暂存写口——hit#1 填入 01 00 5e 00 00 fb（=224.0.0.251），
  与 guest 平面表（GetIpNetTable 真值 11 行）吻合；filler 逐列逐行调用
  （hit#2 的 rdx 已变标量）。+0x60/+0x68 两块内核缓冲全零，不是表落点。
- v15/v16/v17（KDNET）：NsippDispatchDeviceControl 不是热路径（90s 零
  命中，v14 那次 0001 命中计数是 reload 期间的杂散）；无条件
  Ipv4NsiProviderDispatch 断点 90s 也不停——说明校准流量根本没经过断点
  窗口/该边界，KDNET 路线对"用户缓冲内容"问题无增量，放弃。
- 捕获通道侧修正三轮后：seq=13、dump=1328B，网关 005056fb20c6、
  005056ee7c43、ffffffffffff、01005e000016/fb/fc、01005e7ffffa 全部
  在 0x754 dump 中现身，键列 IP 与 11 行 ifindex(1,1,3,...) 列同步落盘。

### 与参考的对比
- 同类开源工具的对应能力（GPL，只借鉴行为）：在 nsiproxy 完成例程改写
  邻表项。本轮证实该层的数据面完全可达：MAC 以明文躺在用户态列缓冲，
  完成例程（caller-context, PASSIVE）可读可写。

### 修复尝试（根因链四层，逐层剥开）
1) offTab 偏 8：旧 {0x28,0x38,0x48,0x58} 把"上一列 size + 下一列指针低
   位"当 {ptr,len} 读，ptr/len 门全部跳过——第一轮修正为 {0x20..0x60}。
2) 固定偏移本身不成立：128B 全量 params 快照显示三个 opcode 布局互异
   （0x120007 模块指针@0x18、对@0x30/0x50；0x12000F 模块@0x10、对@0x28..；
   0x12001B 模块@0x10、对@0x28/0x38/0x48/0x58）→ 改滑动扫描（用户 VA+
   合理 size 的 qword 组合都解引用，按指针去重，0x7ff 段=模块 GUID）。
3) big 判据失效：sizeSum>=0x200 在滑动扫描下永假（0x12000F/1B 的对多为
   4/8 字节计数器）→ 改 opcode 门：inCaller && inLen∈{104,112}。
4) ring 被冲 + 步长陷阱：0x120007 洪水把大元组冲出 ring → slot0 专供
   112B 表枚举；"size 字段=整缓冲"错误，实为**每行步长**——cap 改为
   min(stride*16,384) 后整列（11 行）才落进 scratch，OUI 门随即命中。
- 协议扩容：MYARK_HWID_CAPTURE_IN_BYTES 64→128（tuple 80→144B、输出
  4776→5288B，C_ASSERT 钉死），否则 112B NSI_PARAMS 只能看到前 64B。
- 验证：verify 全绿（新增 GetIpNetTable2 探针断言；0xA12 首轮为时序
  flake 重跑自愈）；calib 单跑 seq=13/dump=1328。

### 关键决策回顾
- 从"kd 死磕内核布局"切换回"驱动捕获+离线分析"：KDNET 三连败证明
  用户态问题的证据在用户态（0x754 完成例程天然在 caller 上下文）。
- 捕获工具按"校准专用"扩容（128B 快照/无条件 big dump/slot0），不追求
  一次改到位——rewrite 落地后本通道收缩为回归断言。
- MCP 状态机实证：g 在目标运行中被拒（"already running"）、在停止态
  被接受且**立即返回 running ack**（不阻塞到停）——v14 的 hit 回包是
  巧合时序；正确原语 = g 后接 wait_for_break 工具。

### 0x12001B 布局结论（1903 18362，邻表模块，count=11 实测）
- params 112B：count@0x18；四列对 @0x28{keys,步长24} @0x38{步长32}
  @0x48{步长16} @0x58{步长4}，size=每行步长，缓冲=count×stride；
  尾@0x68=count 副本。
- keys 行 24B：IP(x86 网络序 4B)@rec+16（rec0=224.0.0.22@+0x90、
  rec7=224.0.0.251@+0x138、rec10=255.255.255.255@+0x180 全对上）。
- MAC 出现在两处：pairB(32B 步长) rec 内 MAC@+0（005056fb20c6@0x260、
  005056ee7c43@0x280、ffffffff@0x2a0、01005e000016@0x2c0）；
  pairC(16B 步长) 亦见 MAC（01005e0000fc@0x300 起）；pair@0x48 记录为
  {len=6, 用户 VA 指针, 0, 1} 形态（间接指向 MAC）。
- **未定（下一步第一件事）**：keys 行序与 pairB 行序的对应关系——
  按 index 直配 rec7 出现 224.0.0.251↔005056fb20c6 的错位（应为
  01005e0000fb），存在压缩/过滤序或间接表。需同跑 child 端
  GetIpNetTable2 结果 dump 与 0x754 dump 对齐，或以 IP 为键在
  完成例程内全列扫描（不依赖行序）。

### TODO
1. IP→MAC 行对应关系定案（同进程对照 dump 或键扫描法），随即实现
   hwid_spoof_arp.c 完成例程改写：IP 定位→ProbeForWrite 改写 MAC→
   Tier C 18362 profile 钉死偏移（22631 同法校准）。
2. verify ARP 断言升级：改写往返（APPLY 后 GetIpNetTable2 读回校验）。
3. 捕获通道在 rewrite 落地后收缩（big-dump 改回 OUI-only 可选）。
4. 环境注意：KDNET 会话 v15-v17 三连败未伤 guest（判活全过）；本机
   kd 前必查孤儿（本轮两次 taskkill kd.exe）。


## 2026-09-19（第二轮）— R3-1b ARP 改写落地：完成例程全缓冲匹配直写 + 改写往返全绿

### 现象
- 承接上轮：keys/RW 列内容已可读，但"按 index 直配"发现错位
  （keys[7]=224.0.0.251 ↔ RW[7]=网关 MAC），首版 index 改写
  （State value={ip,fake} 10B）把 224.0.0.251 行改成了假 MAC 而网关行
  原样——行序错位从"疑似"变"实锤"。
- profile 首钉 18362 后 0x752 仍报 UNSUPPORTED：guest 实际
  RtlGetVersion=18363（1909，与 1903 同 NSI 面；此前文档"1903"为近似）。

### 与参考的对比
- 同类开源工具的对应能力（GPL，只借鉴行为）：nsiproxy 完成例程改写
  邻表项。本轮实现后，用户态 GetIpNetTable2 读回可见假 MAC，
  RESTORE 后立即回到内核真值——行为与对标面一致且为纯用户缓冲改写
  （内核邻表缓存零接触）。

### 修复尝试
1. 离线解码 1328B OUI dump：RW 列 MAC 记录起点 = RW 缓冲 +0x80、
   步长 32、MAC@rec+0——keys[i]↔RW[i] 全表对齐自洽（此前错位是把
   0x80 头当记录起点）。
2. index 改写版仍错位（RW 列与 keys 列行序在不同 enumerate 间不保证
   一致）→ 终版放弃一切索引假设：**全缓冲匹配**——在 RW 缓冲
   （count*stride，钳 1024）内找原 6 字节 MAC 的全部出现并替换为
   fake（ProbeForWrite + SEH，RewrittenCount 计数）。
3. 值契约 10B→16B：{IPv4[4], 原 MAC[6], fake MAC[6]}——原 MAC 由
   调用方先探明，APPLY 即确定性写入 Cache，DRY_RUN/RESTORE 不再依赖
   "学习时序"（RESTORE 确定性返回原 MAC）。
4. profile 补 18363 行（与 18362 同值）；verify 目标选择改
   "arp -a 地面真值 × NSI blob 子串校验"（flat 表两种布局均曾跨行
   错配，弃用；ROW2 92B 布局亦跨 build 不稳，弃用）。
5. 完成"armed 门重构"：rewrite 钩子独立于捕获 ring，class Active 即
   工作（捕获 disarm 也可）；捕获 ring 的 scan/dump 仅 Armed 时跑。

### 关键决策回顾
- "以 IP 为键扫描"升级为"以原 MAC 字节全缓冲匹配"：6 字节 MAC 在
  RW 缓冲内唯一，比 IP 定位少一层布局假设（IP 定位仍需 keys 步长）。
- RESTORE 语义定为"停改写 + 确定性报告调用方提供的原值"——与 T-B 类
  的 Cache 语义一致且可离线断言。
- verify 的目标/读回一律走 GetIpNetTable2(AF_INET)（与改写同面），
  arp -a 仅作目标身份真值；flat/ROW2 结构解析全部弃用（跨 build 不稳）。

### 实测（1903/18363 test2，verify 343 项全绿）
- ARP DRY_RUN 预览原 MAC ✓；APPLY 激活（flags=#f）✓；
- 改写可见：readback fake_in=True / orig_gone=True，rewritten=1 ✓；
- RESTORE：real=005056fb20c6（确定性）✓，复原后原 MAC 回表 ✓。

### TODO
1. 22631 校准：Win11 侧 RtlGetVersion=22631，需加 profile 行（RW
   缓冲 0x80 头/32 步长是否同值待 capture 验证），vm_win11_verify 全绿。
2. 改写范围声明落 KNOWN_ISSUES（仅 NSI 用户缓冲；旧 GetIpNetTable
   路径与内核缓存不受影响——行为差异已计入设计）。
3. 捕获通道瘦身后备：rewrite 稳定后 0x754 大 dump 可裁剪（暂保留）。
4. 其余队列见 task-queue（R3-4b 摘要 / dyndata 26100 清点）。


## 2026-09-19（第三轮）— R3-1b 收官：22631 校准 + 双机改写往返全绿

### 现象
- 承接第二轮：改写在 18363 全绿，但 Tier C profile 只有 18362/18363
  两行——22631（Win11 23H2）上 class 会优雅拒绝，R3-1b 不算收官
  （仓库纪律：1903 + 22631 双绿）。

### 与参考的对比
- 同类开源工具的对应能力（GPL，只借鉴行为）：nsiproxy 用户缓冲改写
  在两代内核上行为一致。本轮实测 22631 的 NSI 邻表布局与
  18362/18363 完全同构（见下），单一代码路径直接覆盖三代 build。

### 修复尝试
1. Win11 虚机上电（vTPM 加密虚机需 -vp）→ 判活 → vm_push_driver
   （.sys+脚本，SHA256 双向）→ schtasks 提权部署（sc create/start,
   非提权 token 过不了 SDDL/服务创建）。
2. calib 经 schtasks /rl highest 运行（run_calib_guest.cmd, 本地
   不入库；设备打开需提权 token）：0x754 读回 dump=1328B。
3. 离线逐行对齐：count@0x18=11、keys 步长 24/IPv4@rec+16、RW 列对
   @0x38 {ptr, stride 32}、记录起点 +0x80、MAC@rec+0——与 18363
   逐字节同构（keys[3]=c0a8c702↔rw[3]=005056fb20c6 等 11 行全对齐，
   含 VMnet host 行 .1↔005056c00008）。
4. 加 22631 profile 行（与 18362/18363 同值）→ 编译 → 停删旧驱动
   （stop_driver_guest.cmd 提权解锁 .sys）→ 推新 .sys →
   vm_win11_verify 全量（提权部署 + 脱离验证）。

### 关键决策回顾
- 布局校准方法复用第二轮的离线解码（不再碰 KDNET/内核布局），
  校准成本 = 一次 calib 运行 + 一次逐行对齐。
- verify 目标选择天然适配（arp -a 真值 × blob 交叉校验），22631 上
  自选中 .1 行（005056c00008）完成改写+复原闭环——目标行无关性
  （全缓冲匹配设计）得到跨机验证。

### 实测（Win11 22631，vm_win11_verify 350 项全 PASS / 0 FAIL）
- profile 钉住（无 UNSUPPORTED）；DRY_RUN 预览 ✓；APPLY 激活 ✓；
- 改写可见 fake_in=True/orig_gone=True，rewritten=1 ✓；
- RESTORE real=005056c00008 确定性复原，复原读回原 MAC 回表 ✓。

### TODO
1. R3-4b 内核对象/IPC 摘要；dyndata QUERY_HANDLE/FILE/OBJECT 26100
   清点。
2. KNOWN_ISSUES 落"ARP 改写仅 NSI 用户缓冲"行为差异声明（旧
   GetIpNetTable 路径与内核缓存不受影响）。
3. 24H2 (26100+) 虚机仍缺——profile 表待第四行（环境项）。

## 2026-09-19 — R3-4b 内核对象/IPC 摘要：kernel_object 模块落地 + METHOD_BUFFERED 别名/NPFS 根语义三连坑（test2 1903 + Win11 22631）

### 现象
- R3-4 遗留的"内核对象摘要 + IPC 摘要"立项为 91_object 模块（KOBJ，
  0x910 ENUM_DIRECTORY / 0x911 IPC_SUMMARY），占位头
  MyArkKernelObjectIoctl.h 与 myark_full.h 的 MYARK_MODULE_KERNEL_OBJECT
  门早在 S4/S7 就预留好了。设计走全导出面（零 profile）：
  对象目录用 ZwOpenDirectoryObject+ZwQueryDirectoryObject，IPC 用
  ZwCreateFile+ZwQueryDirectoryFile。
- 首轮 1903 实测：0x910 对 `\`、`\ObjectTypes`、`\NoSuchDir` 一律
  open=0xC000003B（PATH_NOT_FOUND，与"空对象名"同码）；0x911 对
  `\Device\NamedPipe`/`\Device\MailSlot` open=0xC0000024
  （INVALID_PARAMETER）。

### 与参考的对比
- 宿主机 ntdll NtOpenDirectoryObject 对照（build/probe_ntdir.py）：
  用户态 `\` 打开成功、`\NoSuchDir` 精确回 NAME_NOT_FOUND
  （0xC0000034），`\ObjectTypes` 回 ACCESS_DENIED（用户态有权限检查，
  内核 Zw 面 PreviousMode=Kernel 跳过）——同一名字内核侧回
  PATH_NOT_FOUND 说明不是对象管理器语义，而是**传入名有问题**。
- 结论链：`\NoSuchDir` 内核侧回 PATH_NOT_FOUND ≈ 空名/相对名的回码
  （探针：空串→PATH_NOT_FOUND、"O"→PATH_NOT_FOUND）。

### 修复尝试（按定位顺序）
1. 临时诊断：把收到的输入前 16 字节原样回显到输出头 →
   **raw=[00000000 ...] 全零**。根因：METHOD_BUFFERED 的 in_buf 与
   out_buf 是**同一块 SystemBuffer**——handler 先
   RtlZeroMemory(out_buf, 49KB) 把输入路径副本一起抹了（校验在抹零前
   通过、走查在抹零后读路径→空名→PATH_NOT_FOUND）。修复：校验后先把
   DirectoryPath 拷进局部 WCHAR[96]，再碰 out_buf。仓库级教训：
   **所有"输入结构+大输出"的 METHOD_BUFFERED handler 都必须在写输出前
   拷走输入**（registry/file 系列侥幸没踩：它们先读输入后写输出）。
2. `\Device\NamedPipe`/`\Device\MailSlot` 是 NPFS/MSFS 的**设备对象**
   而非对象目录——ZwOpenDirectoryObject 对它们回 INVALID_PARAMETER
   （类型检查失败）。IPC 改走文件系统目录查询。
3. 改后管道 open 成功但查询 0xC000000D。宿主机 NtCreateFile 矩阵
   （build/probe_openmatrix.py）复现并锁定语义：**裸设备名 open =
   控制设备句柄（建管道入口），不支持目录查询**；唯一可行组合 =
   **尾部反斜杠根路径** `\Device\NamedPipe\` + DesiredAccess
   FILE_LIST_DIRECTORY + CreateOptions FILE_OPEN_FOR_BACKUP_INTENT +
   查询带非空模式 L"*"（NPFS 无默认模板）。MailSlot 同法
   （`\Device\MailSlot\`）。
4. 对象目录查询回 0xC0000023（BUFFER_TOO_SMALL）：
   ZwQueryDirectoryObject 的单条记录**及其字符串必须放同一缓冲**，32 字节
   的 OBJECT_DIRECTORY_INFORMATION 头不够 → 512 字节缓冲。另修复一处
   低级错误：分配 512 却仍把 sizeof(结构)（32）当 Length 传。
5. 诊断基建教训：guest 探针 win32 侧把 CTL_CODE 的 METHOD 位写成 2
   （METHOD_OUT_DIRECT）导致全军 err=1——用户态 DeviceIoControl 的
   METHOD_BUFFERED=0；驱动端永远收不到请求，别当驱动 bug 查。

### 关键决策回顾
- 零 profile 路线再次胜出：两 API 全导出、全构建同语义，1903/22631
  同一份代码直绿（对比 R3-3/R3-4 的 Tier C 偏移钉版成本）。
- 管道真值交叉用 `os.listdir('//./pipe/')`（同 NPFS 根的 win32 视图），
  实测 1903 24==24、22631 51==51 零差异；瞬时管道抖动容忍
  |对称差|<=3。
- mailslot 枚举是 best-effort：MSFS 根为空/不可用时回
  NO_MORE_FILES 族状态，verify 断言"走查干净结束 + 计数仅报告"，
  不卡 >=1（Server 服务可被裁剪）。
- ZwQueryDirectoryFile 多条批量（ReturnSingleEntry=FALSE）+ NextEntryOffset
  链走查，比单条循环少往返；对象目录保持单条循环（带 RestartScan）。
- 顺手把 MYARK_MAX_MODULES 36→40（第 36 个描述符恰好把数组占满）。

### 结果
- 1903 [VERIFY] OK：\ObjectTypes 67 类型、\ 56 项、\Device 256 项、
  管道 24 条与 win32 视图零差异、拒绝路径 err=87、缺失目录带内
  NAME_NOT_FOUND。
- 22631 [VERIFY] OK：70 类型、65 项、管道 51 条零差异。
- client：`myark object dir|types|ipc` 三命令；875 单测全绿。

### TODO
1. dyndata QUERY_HANDLE/FILE/OBJECT 26100 常量清点（原队列任务4）。
2. KNOWN_ISSUES 落"ARP 改写仅 NSI 用户缓冲"行为差异声明（R3-1b 遗留）。
3. 24H2 (26100+) 虚机仍缺——环境项。
4. 若未来要"每类型对象计数"（PCHunter 式），需 ObTypeIndexTable
   Tier C profile——本切片刻意不做。

## 2026-09-19 — R3-10a win32k 用户对象句柄表：0x772 落地 + aheList 用户副本布局校准（test2 1903 + Win11 22631）

### 现象
- R3-10（win32k 补全）第一切片：77_win32k 模块从 S7.3 stub 做实。
  路线选型：窗口/钩子面走 user32!gSharedInfo 句柄表（全导出面 + PEB
  走查，零 win32k 内核偏移），win32k 定时器/WinEvent 深枚举留 Tier C
  下一切片。
- 首轮 1903 实测：0x772 open/解析全通（gSharedInfo=0x7FFAB43D7FC0，
  PEB→Ldr→EAT 三级全对），但 Count=0——走查把全部记录判成空闲。

### 与参考的对比
- 经典公开资料（XP~Win7 时代）HANDLEENTRY = {pHead, pUser, bType,
  bFlags, uwSpare} 16 字节，type 在记录头偏移 12~16；按此实现全部判空。
- 宿主机/guest 差分探针（build/probe_win32k.py、probe_ahe.py）：创建 3
  个加速表前后对 aheList 用户映射做逐槽 diff，槽位号 [185,189,205]
  与新句柄低 16 位精确对应 → 步长 32 与槽位模型证实；变化字节为
  @24=0x0008（TYPE_ACCELTABLE）、@26=代际。

### 修复尝试（按定位顺序）
1. HeEntrySize 硬性要求 16 → 实测 32，直接拒走。改白名单 {16,24,32}
   并按 stride 适配解码。
2. 走查故障（映射区页尾 0xC0000005）被当成 IOCTL 失败状态返回 →
   改带内 DiagStatus（有行时区域末尾 = 干净停止）。
3. "pHead 与 type 双零 = 空闲"判据误杀：用户映射副本**抹零内核指针**，
   活记录可能只有 @8 小偏移（0x6C4）+ @24 类型。改按 type@24 ∈
   1..0x40 判活（USHORT @26 是代际/unique，释放后残留非零字节，
   任意非零判据会误判 + 多出 150 行幽灵行）。
4. guest 探针 CTL_CODE 的 METHOD 位误写 2（OUT_DIRECT）→ 全部
   err=1，一度误导为驱动问题。用户态 DeviceIoControl 的
   METHOD_BUFFERED=0。

### 关键决策回顾
- Tier B 优先再胜：PEB.Ldr / LDR_DATA_TABLE_ENTRY / SHAREDINFO 头部
  / HANDLEENTRY 步长全部跨构建稳定，1903 与 22631 同码直绿，
  免掉一轮 KDNET 校准。
- 验证设计以**差分为真值**：加速表创建/销毁 → 新槽位集合出现又消失
  （1903: [371,373,375]、22631: [1041,1119,1409]，与句柄低 16 位
  精确对应），不依赖任何未解码字段的语义。
- 内核指针被用户副本掩码 = Windows 的内核地址泄漏防护的一部分，
  ARK 语义上 pHead 需 Tier C 内核侧补齐（R3-10b）。
- 诊断基建：guest 探针必须 use GetLastResult 语义正确
  （use_last_error=True）、CTL_CODE method 位为 0；"先怀疑探针再
  怀疑驱动"省了两轮盲调。

### 结果
- 1903 [VERIFY] OK：0x772 count=316、accel 探针 [371,373,375] 精确；
  Win11 22631 [VERIFY] OK：count=1129、探针 [1041,1119,1409]。
- 中途 1903 出现 MUTTX PREPARE err=1450 连续失败——与 win32k 无关，
  硬重置 guest 后消失（多轮部署后的 guest 状态劣化，第 N 次验证
  AGENTS §3 纪律）。
- client `myark win32k handles [--type N]`；875 单测全绿。

### TODO
1. R3-10b：win32k 定时器/WinEvent 钩子深枚举（Tier C，需 KDNET 校准
   win32k 会话空间偏移）；pHead 内核指针的内核侧补齐。
2. dyndata QUERY_MODULE/QUERY_SSDT 的 26100 门控备查（KLDR/SSDT
   布局跨构建历史稳定，风险低）。
3. 24H2 虚机（环境项）。

## 2026-09-19 — R3-10b 前置：win32k 会话空间 KDNET 校准（test2 1903）——数据落袋，运行时基址锚点列为独立切片

### 现象
- R3-10b 需要 win32kbase 会话基址的运行时锚点（内核 gSharedInfo /
  gptmrMaster 全局），走 KDNET 校准。
- 校准四轮才成功：轮 1（explorer 上下文）符号全通但只查了符号名没
  dump 数据；轮 2/3 改 python.exe（session 0 探针）上下文全废
  （"Couldn't resolve" + lm 空）；轮 4 发现轮 2-4 共同根因：新 kd
  会话没有 .sympath/.reload（符号路径为空，缓存 PDB 也不加载）。

### 与参考的对比
- 轮 3 选进程按"第一个 python.exe"取到 HandleCount=0 的僵尸进程
  （session-0 win32k 根本未初始化，lm 连 win32k 模块都不列）——
  会话驱动只在挂到该会话 GUI 进程上下文时可见。
- session-0 探针（runProgramInGuest）SetTimer 不可用：session 0 非
  GUI 进程无 win32k；vmrun 1.17 的 -interactive 旗标报
  "Invalid argument"（帮助文本泛化，Workstation 实现不支持）；
  schtasks /it 被 session-0 过滤令牌拒绝——三路 session-1 投递
  全堵，最终用 explorer（session 1）自身的系统定时器做对象来源。

### 修复尝试 / 校准结果（test2 18363, win32kbase 基址 ffff8562`07ab0000）
- 内核 gSharedInfo = win32kbase+0x213750（ffff8562`07cc3750）：
  psi = ffff8525`c0e01040（会话池，非模块内！）、**内核 aheList =
  ffff8525`c0c00000**（真句柄表，pHead 未抹零）、HeEntrySize = 0x20。
- gptmrMaster = win32kbase+0x215938（USER 定时器主锚点 TIMER 对象，
  @0 = LIST_ENTRY 链入全体 TIMER）。
- gTimerHashTable（+0x215de0）/ gTimerId（+0x21561e0-基址）存在。
- WinEvent 钩子：gpeg*/gEventHook* 在 win32k* 三模块均无符号
  （列表挂 DESKTOP 内部，需 DESKTOPINFO 偏移，更重）。

### 关键决策回顾
- R3-10b 实现的真正阻塞点收敛为**一个问题**：运行时如何定位
  win32kbase 会话基址。psi 在会话池（非模块内，派生不了基址）；
  会话驱动不在 PsLoadedModuleList；候选：①shadow SSDT 已给出
  win32k.sys 基址（R2-3 现成代码）→ 其 IAT 里有 win32kbase 导出
  函数指针 → 基址 = 指针 - 标定 RVA（每构建 2 个常量）；②
  EPROCESS.Session → MM_SESSION_SPACE 会话驱动链（Tier C 更深）。
  两者都是独立验证轮的量级——按"不做半成品"纪律拆为独立切片，
  本轮只落数据。
- KDNET 教训新增：**每个新 kd 会话都要完整走 .sympath + .reload**
  （符号缓存不等于符号路径）；!process 输出选 EPROCESS 必须核对
  HandleCount 非零（僵尸进程上下文会让会话模块整体隐身）。
- guest 定时器探针三路投递失败的全记录（session-0 无 win32k、
  -interactive 不支持、/it 拒绝）——后人勿再踩。

### 结果
- 全部标定数据落袋（本段 + build/kd_win32k_calib*_out.txt 本地留存，
  脚本不入库）。R3-10a 本体不受影响（已收官）。
- 1903 [VERIFY] OK、22631 [VERIFY] OK（R3-10a 提交后复验态）。

### TODO
1. R3-10b-i：win32kbase 会话基址锚点切片（shadow SSDT+IAT 或
   MM_SESSION_SPACE 路线，先验证再实现）。
2. R3-10b-ii：内核句柄表 pHead 补齐 + gptmrMaster 定时器枚举
   （RVA 已备：0x213750 / 0x215938，需 22631 对应行）。
3. WinEvent 钩子：DESKTOPINFO 偏移链，工作量另估。
4. dyndata QUERY_MODULE/QUERY_SSDT 26100 门控备查；24H2 虚机。

## 2026-09-19 — R3-10b-i：win32kbase 会话基址锚点全链路验证成功（test2 1903，KDNET 第 5-6 轮）

### 现象
- R3-10b 的阻塞点 = 运行时定位 win32kbase 会话基址。候选①
  PsWin32kImageBase（nt 导出）→ win32k.sys PE 导入表 → win32kbase
  导出函数指针 − 标定 RVA；候选② MM_SESSION_SPACE 会话驱动链。

### 与参考的对比
- 路线①全链路 KDNET 实证（轮 5b）：win32k.sys（会话基址来自
  PsWin32kImageBase/lm）导入表 import[2] = **win32kbase.sys**
  （OriginalFirstThunk=0x5ee88, FirstThunk=0x5c018），导入函数名实测
  W32CalloutDispatch / IsWin32KSyscallFiltered / NtVisualCaptureBits /
  NtUser* 等——win32k.sys 的 IAT 就是现成的 win32kbase 指针表。

### 修复尝试 / 标定结果
- `x win32kbase!W32CalloutDispatch` → **RVA = 0x26250**（test2 18363，
  win32kbase 基址 ffff8562`07ab0000，同一 boot 跨 6 轮会话稳定）。
- 运行时解析链（驱动侧实现蓝图）：
  MmGetSystemRoutineAddress("PsWin32kImageBase") 读值 → win32k.sys
  会话基址 → 安全读 PE（e_lfanew=0xE0 实测）→ dir[1] 导入表 → 找
  "win32kbase.sys" 描述符 → OriginalFirstThunk 名单匹配
  "W32CalloutDispatch" 序号 i → FirstThunk[i] 指针值 − 0x26250 =
  win32kbase 会话基址 → 内核 gSharedInfo = 基址 + 0x213750 → 内核
  aheList（真表）→ 同槽位 pHead 补齐 / gptmrMaster(+0x215938) 定时器链。
- 运行时自校验：内核 gSharedInfo.psi 应与用户副本 psi 一致（相等即
  基址推导正确）。

### 关键决策回顾
- **KDNET 第 5 轮踩出一条铁律：kd 默认基数是 16**——表达式里的
  十进制 24/112 被当 0x24/0x112（偏移全错且无报错），所有偏移必须
  显式 0x 前缀。
- JSON-RPC 文本要用 content[0].text（json.dumps 后的 
 是字面量，
  正则跨行解析会静默失败）。
- 轮 5 的 nt! 符号未加载（.reload /f ntoskrnl.exe 静默空输出）——
  校准脚本不能依赖 nt! 符号，改从 lm 直接取 win32k.sys 基址。
- 内核句柄表记录（aheList@ffff8525`c0c00000）的 @0 是**小偏移**
  （0x10d0/0x32a0/0x238c0，非内核指针）——内核副本的 pHead 语义与
  用户副本不同源，字段级解码需要"加速表创建/销毁 × 内核表差分"的
  下一轮标定（R3-10b-ii；session-1 投递问题届时再解，或用已知句柄
  低 16 位对齐）。

### 结果
- R3-10b-i 交付达成：锚点链验证成功，阻塞点解除。标定常量（18363）：
  W32CalloutDispatch RVA=0x26250、gSharedInfo RVA=0x213750、
  gptmrMaster RVA=0x215938、HeEntrySize=0x20。
- 22631 行待同法一轮 KDNET（win11_kdnet_key.txt，端口 50002）。

### TODO
1. R3-10b-ii：驱动实现（会话基址解析器 + 0x772 内核表扩展 +
   定时器枚举），22631 标定行。
2. 内核记录字段级标定：加速表差分 × 内核表（解决 @0 偏移语义）。
3. WinEvent 钩子（DESKTOPINFO 链）；dyndata QUERY_MODULE/SSDT
   26100 门控备查；24H2 虚机。

## 2026-09-19 — R3-10b-ii：win32k 内核句柄表暴露落地（0x772 扩展，双机验证）

### 现象
- 实现会话基址解析器时，最初走 PsWin32kImageBase+IAT 链，实测
  stage=1：`MmGetSystemRoutineAddress(L"PsWin32kImageBase")` 在 18363
  返回 NULL——该导出在 1903 不存在（dyndata 的同款解析从未在此构建
  成功过，SHADOWSSDT 段的 win32k 基址另有来源）。

### 与参考的对比
- 25_kernel 的 MyArkKernelWin32kBounds（R2-3）早已证明：**win32k
  三件套出现在 SystemModuleInformation (class 11) 列表里**——尽管
  它们不在 PsLoadedModuleList。直接扫该列表找 "win32kbase.sys" 取
  ImageBase，比 IAT 链少两次 PE 解析、无构建相关函数名依赖。

### 修复尝试 / 实现
- 解析器重写为 ZwQuerySystemInformation(11)（经
  MmGetSystemRoutineAddress 取函数指针，池缓冲 + 双调用模式），
  找 win32kbase.sys → ImageBase = 会话基址 → 内核 gSharedInfo =
  base + 0x213750（profile 行 18362/18363；22631 行留 0 = 干净拒绝）。
- 0x772 输出头扩展 {Win32kBase, KernelAheList, KernelPsi, PsiMatch,
  Reserved2(breadcrumb)} → 72 字节头；解析失败带内降级（stage 码）。
- **实测发现（finding）**：内核 gSharedInfo.psi（0xFFFF8525C0E01040）
  ≠ 用户副本 psi（0xFFFFF2091040）——两个 SERVERINFO 实例。psi
  匹配从硬门降级为信息性字段，内核表解析本身以 aheList 内核 VA
  自洽验证。
- 1903 解析值与 KDNET 交叉验证完全一致：w32kbase=0xFFFF856207AB0000
  （=lm）、kern_ahe=0xFFFF8525C0C00000（=round-4 dq）。

### 关键决策回顾
- 验证脚本的三次自身翻车（解构/返回元组/lambda 索引）全部是
  "协议扩展后多处同步"的老问题——verify 手工 struct 解析在协议
  演进时是高频错误源，后续考虑让 R3 侧复用 ctypes 镜像解析。
- psi 双 SERVERINFO 结论修正了 R3-10a 时"psi 可作运行时自校验"的
  预设：内核表与用户表是并行的两份结构，不是主从映射。
- 调试手段：Reserved2 当 breadcrumb（stage 码 / 值片段）+ verify
  detail 打印，两轮迭代定位到 psi 不相等——比盲改快。

### 结果
- 1903 [VERIFY] OK：内核表解析成功，w32kbase/kern_ahe 与 KDNET
  完全一致；22631 [VERIFY] OK：干净 fallback（profile 行待标定）。
- 875 client 单测全绿。

### TODO
1. 22631 标定行（KDNET：x win32kbase!gSharedInfo → RVA）。
2. 内核记录字段解码（@0 小偏移语义）——加速表差分 × 内核表。
3. R3-10b-iii：USER 定时器枚举（gTimerHashTable 路线，gptmrMaster
   @0 是 DISPATCHER 头不是 LIST_ENTRY，节点遍历需重新标定）。
4. 会话标识注意点（验收 P1）：SystemModuleInformation 每会话驱动
   只列一条（非每会话一条），多会话主机（RDP）上解析出的可能是
   其它会话的 win32kbase 实例——22631 标定轮需补 heSize 与用户
   heEntrySize 交叉校验 + 调用者会话核对。
5. verify WIN32K 段 lambda 位置索引提取脆弱（已三次翻车）——
   具名解构韧性修复待办。

### TODO 补充（轮 8，同日）
- **22631 标定行落地**（KDNET 轮 8，Win11 explorer 上下文）：
  win32kbase 基址 fffff9ca`f4e00000、gSharedInfo fffff9ca`f5085e80 →
  **RVA = 0x285e80**（已入 profile 表，22621-22631）。运行时验证：
  0x772 kernel table 解析成功（w32kbase=0xFFFFF9CAF4E00000 与 lm 一致、
  kern_ahe=0xFFFFF80171000000 内核 VA、psi_match=0 与双 SERVERINFO
  finding 一致）。1903 回归 OK。
- 顺带标定（Win11）：gTimerHashTable RVA=0x288320、gTimerId
  RVA=0x288720（供 R3-10b-iii 定时器路线用）。

### TODO 补充（轮 9，同日）
- 窗口定时器探针 v2（probe_w32timer2.py：RegisterClass→CreateWindow→
  SetTimer(hwnd, 0x4141..)，配合 DefWindowProcW argtypes 修正）——
  **gTimerHashTable 出现非空桶**（桶 0/2/3 → 节点 ffff8525`c061bf20 /
  c061bb60 / c061bc00，session-1 池 tag "Usmt" 可见）。窗口定时器
  （SetTimer(hwnd,…)）确认进哈希表；NULL-hwnd 线程定时器路线
  （v1 探针）哈希表为空。
- 节点 128B 原始 dump 已留存（本日志 + calib9_out.txt 本地）：
  @0x00 LIST_ENTRY（Flink/Blink 指回桶头=单元素链）、@0x10 计数
  0xaa1cd4、@0x24 池 tag、@0x30 内核指针（疑似 PTHREADINFO）、
  @0x40 用户指针 0x7ff8950572c0（疑似 timer proc 回调）、@0x48
  0x493e0（疑似周期相关）。nID 0x4141 未在前 0x80 字节出现——
  下轮 L20 深 dump 全部非空桶节点 + 以 0x4141 离线定位 nID 偏移。
- 附加数据点：本轮 accel 槽（0xc5/0x9b/0x15d）内核记录同前布局。

## 2026-09-19 — R3-10b-iii 前置：内核记录布局经加速表实证 + 定时器路线探测（test2 1903，KDNET 轮 7）

### 现象
- 组合探针（build/probe_w32calib.py：3 加速表 + 5 定时器（id
  0x4141-0x4545，句柄 0x7fd3-0x7fd7）+ 存活 600s）落地后 KDNET dump。
- 首轮 dump 时探针已超时退出——加速表槽位仍有 type/gen 匹配的残留
  记录（证实布局），但 gTimerHashTable 全空（定时器随进程销毁）；
  次轮探针存活期内 dump，哈希表 16 桶仍全自指（空）。

### 与参考的对比
- **内核句柄表记录布局 = 用户副本完全一致**：加速表三槽
  （0x10d/0x14f/0x14b，与句柄低 16 位精确对应）在内核表
  （aheList=ffff8525`c0c00000）的记录 @24 = 0x0008
  （TYPE_ACCELTABLE）、@26 = 代际（0x3e/0x25/0x3e 与句柄高 16 位
  精确对应）。同一 32B 步长、同一 type/gen 偏移。
- 内核记录 @0/@8 = 0 或小偏移（0x9fc0/0xe60 等，desktop-heap 语义）
  ——内核对象指针不在记录内（与用户副本同为掩码/偏移形态），
  "pHead 补齐"需要 desktop-heap 基址推导（W32PROCESS 链，另切片）。

### 修复尝试 / 发现
- 定时器注册点未定位：gTimerHashTable（win32kbase+0x215de0）16 桶
  全空、gptmrMaster.Flink 在两轮间变化（f20f81d0 → f20f7af0，说明
  主链活跃但其 @0 是 DISPATCHER 头不是 LIST_ENTRY，节点遍历模型
  需重设计）。候选：定时器挂线程/桌面级列表，或 gTimerHashTable
  非本会话实例。需"存活定时器 + 正确会话上下文"的专用差分轮。
- guest 探针投递的 marker 文件权限坑：cmd 重定向预先创建的目标
  文件 ACL 与后续 python 写冲突（PermissionError）——探针一律
  print + 外层重定向捕获（python -u），不自己写文件。

### 关键决策回顾
- 内核表可走查性确认：驱动用与用户副本相同的解码器（type@24/
  gen@26、存活=type∈1..0x40）即可走查内核表——R3-10b-ii 的
  解析器+0x772 扩展无需改动即可覆盖。
- "pHead 补齐"降级为远期：内核指针需 desktop-heap 基址推导
  （EPROCESS→W32PROCESS→...），独立切片。
- 校准节奏：探针存活窗口（600s）与 KDNET 会话建立耗时要匹配，
  先探针后 kd，符号已缓存时会话建立 <2 分钟。

### 结果
- 内核记录布局实证落袋；定时器枚举与 pHead 补齐保留在
  R3-10b-iii/iv 队列。R3-10b-ii 已收官态（双机绿）未被改动。

### TODO
1. 22631 gSharedInfo RVA 标定（Win11 KDNET 一轮）→ profile 行。
2. 定时器注册点定位：存活定时器 + 逐会话上下文 dq
   gTimerHashTable/gptmrMaster 链差分。
3. pHead 补齐：desktop-heap 基址推导（W32PROCESS 链）。
4. WinEvent 钩子（DESKTOPINFO 链）。

## 2026-09-19 — R3-10b-iii：0x773 会话定时器枚举落地 + 三连校准坑（nID 偏移 / 桶数 32→64 / 表成员资格抖动与脏表语义）（test2 1903 + Win11 22631，KDNET 轮 8-12b）

### 现象
- 0x773 ENUM_TIMERS 首版实现后，1903 验证套件 5 个标记定时器
  （窗口定时器，探针/verify 进程自建）0/5 或 2/5 可见，且多次重跑
  稳定地只有 2 个出现；KillTimer 全部成功后仍有 1-2 个"已杀"节点
  留在枚举结果里。
- KDNET 轮 9-10 逐桶 dump 时 walk 脚本零节点输出：主机侧
  parse_qwords 正则要求每个 qword 后都有尾随空白，dq 行最后一个值
  永远匹配不上，整行被丢（regex 无报错、静默零数据）。
- Win11 侧 `dt win32kbase!_TIMER` 公共 PDB 无类型信息
  （Symbol not found）——离线解码是唯一路径。

### 与参考的对比
- **TIMER 节点布局（18363，双样本 0x4343/0x4444 落袋）**：
  sizeof=0xA0；+0x00 LIST_ENTRY（哈希桶链）；+0x10 tick；+0x24 池
  tag "Usmt"；+0x48 PTHREADINFO（探针 5 定时器同值）；+0x50 用户态
  pTimerProc（同一 ctypes 回调同值；系统 caret 定时器为 0）；+0x58
  uElapse 毫秒（10000=SetTimer 实参）；+0x60 dword flags；+0x88 内核
  PWND（0=线程定时器）；+0x90 nID（UINT）。同一节点 +0x90 在系统
  定时器上为 0/1、垃圾节点上为杂值——字段语义按对象类别分形。
- **桶数 = 64 不是 32**：表总长 1KB（L100），bucket 35/41/45/48/62
  非空（0x84c0/0x95a0/0x5353/0x5353/5min 系统定时器等），全部落在
  32-bucket 视野之外。这是"稳定 2/5"的根因：哈希落进前 32 桶的
  子集才可见。修 64 桶后单轮 count 5→11→25（新 boot 会话系统定时
  器更多）。
- **表成员资格语义（多轮冻结对拍）**：线程不泵消息时，定时器首次
  触发（WM_TIMER 入队无人取）后从哈希摘链，节点随 tick 进出链——
  同一探针两次冻结 2/5 vs 0/5；泵消息/静默无差别；KillTimer 对
  "当前不在链上"的节点返回 FALSE（重试后全部成功），KillTimer=TRUE
  后部分节点仍长期滞留（脏表语义，死节点数据仍是有效取证内容）。
  历史泄漏节点（进程已死的探针残留：wnd=0、pti/proc 悬垂）长期
  在表中——本身就是 ARK 可见面的取证素材。

### 修复尝试 / 关键决策回顾
- nID 偏移定位走"标记差分"：探针定时器用已知 id（0x4141-0x4545、
  0x4343/0x4444 双样本在 +0x90 精确命中），一次性把 5 个字段偏移
  全部闭环；公共 PDB 无类型信息，dt 捷径不存在。
- 驱动解析器/r3 解析器偏移对拍法：0x773 首验全字段错位 8 字节
  （C 头 64B，python 误抄 0x772 的 72B——错位模式：python.Index 读
  到 C.ElapseMs、python.pti 读到 C.TimerProc、python.window 读到
  C.Node）。guest 内字段诊断脚本（复用 verify_core 管道）一次定位。
- verify 断言设计服从 OS 语义：60s elapse（验证窗口全程 pre-fire，
  免触发摘链）+ pid 派生 id（杜绝跨运行泄漏节点自碰撞）+ 泵消息
  助链入 + KillTimer 重试（churn-FALSE）+ 可见性 ≥2（严格解码：
  elapse 60000 / 单 pti / 单非零 window）+ KillTimer 全 ACK 严格；
  死节点滞留仅信息披露不 gate。
- 1903 guest 长会话退化再现身（PREPARE #1 err=1450）：硬重置后
  全绿——MUTEX 1450 是环境态不是代码态。
- KDNET `s -d` 池搜索语法：范围必须在前（`s -d <start> L?size <val>`），
  `L?size <start>` 顺序报 Couldn't resolve。

### 结果
- 0x773 ENUM_TIMERS 落地：驱动 walker（64 桶全走查、节点 0xA0 守护
  读、DiagStatus 带 stage 面包屑）+ 共享协议（48B 条目 ×256，头部
  64B）+ verify_core 探针与断言 + 客户端
  `myark win32k timers`（protocol/parser/cli/plugin 四件套）。
- 1903 全绿 [VERIFY] OK（每 boot 会话基址 ASLR 变化，驱动逐调用
  解析正确）；22631 复用 18363 节点偏移 + RVA 0x288320，验证套件
  的标记重校验即其正确性证明。
- 附带成果：verify WIN32K 段遗留的位置参数 lambda（P2 韧性项）
  改为显式元组索引。

### TODO
1. 22631 TIMER 节点偏移与 18363 差异核查（若 Win11 标记断言失败，
   一次 KDNET 轮差分 + profile 分行）。
2. pHead/desktop-heap 推导（W32PROCESS 链，远期）。
3. WinEvent 钩子（DESKTOPINFO 链）。
4. 发布后轮换 KDNET key 与 guest 口令（用户侧）。

### 追记（同日晚）：22631 结构差异判定 + 0x773 build 门控落地
- **22631 差分结论**：KDNET 轮 13（token 防陈旧探针 + 全桶 walk 63
  节点）证实 RVA 0x288320 处的表在 22631 上是内联 LIST_ENTRY 桶
  阵列（空桶自指），但链上分配的池 tag 为 "Wnf "/"Ntfc"/"Rspp" 等
  而非 1903 的 "Usmt"，+0x10 tick 模式不符——轮 8 的符号名识别
  （x win32kbase!gTimer*）在该 build 不可靠。标记差分零命中。
- **决策**：0x773 按 build 门控——仅 18362/18363 出行；未标定
  build 返回 DiagStatus=STATUS_NOT_IMPLEMENTED(0xC0000002)+
  Count=0（dyndata 26100 门控同款先例）。verify 对未标定 build
  显式 skip。宁缺毋错：拒绝服务另一 build 的偏移。
- **运维坑两枚**：① Win11 Tools exec 通道随时间退化（schtasks
  创建命令被静默丢弃）→ 硬重置 guest 恢复；② 后台 shell 丢 cwd
  导致 vm_win11_verify 未带 win11 环境跑到 test2 上（"时间倒流"
  假象 = 两个 guest 的文件状态被误认为同一台）——舰队调用一律
  显式 `call vm_env_win11.bat`。
- Win11 guest 快照回滚丢 python312：embeddable 包重装脚本
  （build/vm_win11_python_setup.cmd，schtasks 方式）已沉淀。

### 追记 2（同日晚）：1903 哈希占空比定量 + 断言降为信息性
- 行级诊断（同 boot 创建 5 标记 30 分钟 elapse + 3 轮 re-arm 采样）：
  自有标记仅 2/5 在链（id/elapse 解码全对），且 verify 轮观测过
  8 样本全 0 的运行（当时 11 行 = 6 系统 + 5 历史泄漏；KillTimer
  顺带清了泄漏行 11→6）。结论：1903 上活定时器节点在
  gTimerHashTable 的占空比约 40% 且随机相位——可见性是随机面，
  不是确定性不变量。
- 断言调整：marker 可见性检查恒 PASS（信息性），0 现象=本 run 只
  采到离相节点；严格解码（elapse 60000 / 单 pti / 非零 window）仅在
  有现象时执行。基线解析/64 桶走查/KillTimer 全 ACK 保持严格。
- 顺带落实评审 P2：0x773 进 MATRIX_READ_ONLY（计数标签 48→58 修正，
  旧标签本就过期）；CLI handles/timers 头行输出 truncated。

## 2026-09-19 晚 — R3-10b-iv 前置：22631 定时器判决轮（关闭）+ desktop-heap 推导第一链（test2 1903 + Win11 22631，KDNET 轮 13-16e）

### 现象
- 22631 判决轮：token 防陈旧探针存活下，在**正确的**节点区域
  （ffffcb0d`6e-6f，由 gTimerHashTable 实际链头推导）扫 Usmt tag
  （0x746d7355）与明文 elapse（0x1B7740），256MB 窗口均零命中。
- desktop-heap 推导（1903）：W32PROCESS 内全部 ffffafd1`40-46 区
  指针（+0x20/0x58/0xc0/0xc8/0xd0/0xd8/0xe0/0xe8/0x100/0x140/
  0x148/0x158/0x160/0x170/0x178）逐一作为堆基址候选验证
  （pHead=B+rec@0 的首 qword 应等于窗口句柄）——全部 0/4。

### 与参考的对比
- 22631：gTimerHashTable 的链语义本身有效（Flink/Blink 自洽），
  但链上对象带 "Wnf "/"Ntfc"/"Rspp" 等杂 tag 且无 Usmt、无明文
  elapse——定时器对象在该 build 换了 tag/编码（同 R3-3 DPC 值
  编码一类）。**0x773 门控维持，此项关闭**。
- 1903 desktop-heap 第一链已通：`dt nt!_EPROCESS <ep> Win32Process`
  = **+0x3b0**，explorer W32PROCESS=ffffafd1`4582d010（+0x00 回指
  EPROCESS ✓）。psi=ffffafd1`40E01040、内核 aheList=ffffafd1`
  40C00000（会话池区域 = ffffafd1`40-46）。TYPE_WINDOW 内核行
  rec@0 = 0x10d0/0x1340/0x1520（随句柄递增的堆偏移，WND 尺寸
  ~0x1e0-0x270 合理）。
- 跨进程验证：explorer 与 dwm 的 W32PROCESS+0xa0/a8/b0 三指针
  完全一致（ffffaf88`c603c7a0 区）——但该区在 win32kbase **镜像**
  内，是会话全局数据非堆基址（假候选已排除）。

### 修复尝试 / 关键决策回顾
- 池搜索语法：`s -d <start> L?count <value>`（范围在前）；kd dq
  输出解析必须排除行地址列（首列混入值列表导致 +2 错位）。
- lm 输出会间歇性截断（只剩表头）——改用
  `x win32kbase!gSharedInfo` 拿符号地址（首 token=地址，稳定），
  且**每个新 kd 会话都必须先 .reload /f win32kbase.sys**（16c 两轮
  因漏 .reload 符号全失）。re.match 不可用于多行响应——逐行匹配。
- W32PROCESS+0xa0/a8/b0 三指针跨进程一致曾误判为堆基址——用
  win32kbase 镜像区间过滤即排除；真堆基址不在 W32PROCESS 内。
- 下一步正确锚点：**DESKTOP 对象**（W32THREAD→pDesktop 或
  WindowStations 目录→DESKTOP），DESKTOP 内含桌面堆基址字段；
  ETHREAD→KTHREAD.Win32Thread 有符号偏移可直达 W32THREAD。

### 结果
- 22631 定时器差分标定正式关闭（结构异构实锤，0x773 门控维持）。
- desktop-heap 推导完成第一链（W32PROCESS 锚点 + 会话池区域定位 +
  候选排除法），堆基址字段的最终定位（DESKTOP 对象锚）留下一轮。

### TODO
1. W32THREAD→pDesktop→DESKTOP→堆基址字段定位（1903 一轮 kd）。
2. 22631 同链复核（若 1903 通，22631 大概率同构）。
3. 驱动实现：PsGetProcessWin32Process/PsGetThreadWin32Thread（运行
   时 MmGetSystemRoutineAddress）+ 每行 KernelObject = base + rec@0。
4. verify：0x772 内核行 kobj 非零且落在堆区间断言。

### 追记（16f 轮）：W32THREAD 直猜失败
- explorer 首线程 KTHREAD.Win32Thread = ffffb28d`64804250（内核池，
  与 EPROCESS 同区）；THREADINFO+0x0 = ffffafd1`4584e830（会话池）。
  以 pDeskInfo-0x30/0x20/0x10/0x0 四假设验证全部 0/4——桌面堆基址
  不在 THREADINFO 头部直接可达。
- 结论：需要先系统化差分 THREADINFO/DESKTOP 布局（找 pDeskInfo/
  pDesktop 字段），再推堆基址。kd 轮 16a-16f 的 dump 数据已在
  build/kd_heap_calib16*_out.txt 留存，供下一轮离线分析。
