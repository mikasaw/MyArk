# AGENTS.md — MyArk 驱动调试与发布纪律

> 仓库级硬规则，优先级高于默认行为。只写规则与踩坑，不写背景知识（见 §6）。
> 适用范围：一切在 VM 内做驱动加载 / IOCTL / 内核调试 / 取证的会话。

## §1 驱动 VM 调试：严格走 vm-driver-debug-loop Phase 0–7

- 驱动 VM 调试（部署 → 加载 → 触发 → 冻结取证 → 改码重编 → 重测）**必须**按
  `vm-driver-debug-loop` 技能的 Phase 0–7 执行；方法、判据、陷阱以该技能为准。
- 所有 guest 操作**只允许**经 `build\vm_*.bat` 舰队：

| 脚本 | Phase | 作用 |
|---|---|---|
| `build\build_driver.bat` | 0 | MSBuild 走 sln 编 Release，校验产物落点 |
| `build\vm_guest_setup.bat` | 0.5 | 一次性：testsigning + 信任签名证书 |
| `build\vm_alive_check.bat` | 判活 | Tools 状态 + exec 探针（reset 前必跑） |
| `build\vm_reset_hard.bat` | 1 | 硬重启并等待 guest 真正可 exec |
| `build\vm_push_driver.bat` | 2 | 推 .sys 到 guest + 双向 SHA256 校验 |
| `build\vm_svc_clean.bat` | 3 | sc stop + sc delete（仅健康态重部署用） |
| `build\vm_svc_create.bat` | 3 | sc create MyArkCore（kernel 类型） |
| `build\vm_svc_start.bat` | 3 | sc start + sc query（期望 STATE 4 RUNNING） |
| `build\vm_run_verify.bat` | 4/5 | guest 内跑 verify_core.py 并拉回输出 |
| `build\vm_pull_log.bat` | 6 | 拉任意 guest 日志到 build\ |

- **禁止**裸 `vmrun` 一次性命令、裸 PowerShell 远程 IO（内联长命令的
  `runProgramInGuest`、`Enter-PSSession` / `Invoke-Command`）——一律视为绕过，
  结果不可复现、不可信。
- **vmrun 的退出码不可信**：失败时返回 `-1`（0xFFFFFFFF），而 cmd 的
  `if errorlevel 1` 是有符号比较，**判不出 -1**（2026-09-14 实测：VM 关机时
  exec 探针仍被误判为 "alive"）。脚本一律用
  `if not "%errorlevel%"=="0"` **加输出里的正向证据**（alive token / RUNNING /
  SHA256 相等 / 1060 服务已消失）双判据。
- **vmrun 不转发 guest stdout**（2026-09-14 实测：`runProgramInGuest` 成功
  返回 rc=0 但主机管道零字节，`echo X` 与 `sc query` 都是如此，同一条 boot 内
  `listProcessesInGuest` 正常）。**一切证据必须走文件通道**：guest 内写文件 →
  `CopyFileFromGuestToHost` 拉回 → 在主机上断言。舰队脚本里 `type`/`findstr`
  一律针对拉回的主机副本。判活还要防陈旧文件：主机生成随机 token，guest 回显，
  主机校验 token（`vm_alive_check.bat` 已实现）。
- **guest 命令串必须带 `< NUL`**：vmrun 把 cmd 起在 Session 0 假控制台，不重定向
  stdin 时读取 IRP 永不完成（技能铁律 4）；**`< NUL` 是承重结构，不是装饰**，
  去掉会让命令静默不执行。**链式命令的"每一段"都要各自带 `< NUL`**——
  形如 `cmd /c cd /d X < NUL & del /q Y 2>nul < NUL & prog > log 2>&1 < NUL`。
  只挂在最后一段时，未重定向的前缀会永久挂住（2026-09-14 实测：guest 里留下
  一个 Session 0 的 cmd 卡死，主机侧 `runProgramInGuest` 被它堵住 30+ 分钟）。
- **快照回滚会还原磁盘、vmx 和 BCD**（2026-09-14 实测）：`myark-test` 目录整个
  消失、KDNET 退回克隆来源的共享 key/端口、驱动服务不存在。回滚或长时间未用的
  guest，先按 `vm_env_check.bat` → `vm_guest_setup.bat` → `vm_push_driver.bat`
  → `vm_reset_hard.bat` → `vm_env_check.bat` 的顺序恢复，再进 Phase 2。
- **KDNET / WinDbg 一律走 windbg-mcp**（`mcp_windbg` 系列工具），禁止命令行
  `kd.exe` 一次性命令。代价案例：前项目 r60 用裸 kd.exe 一次性命令把宿主机拖死；
  本仓库 2026-09-08 遇到残留 kd.exe（占 UDP 50000）误连克隆机 test2 并冻结 guest。
  调试前先 `tasklist | findstr kd.exe`，有残留先清。
- kd 会话纪律：任何命令都会 halt 目标 → **下一条必须 `g`**；取证第一件事
  `.logopen`（实时落盘，guest 冻结后仍可读）。
- test2 专用 KDNET key/端口（50001）见 `build\test2_kdnet.txt`；**不得**用其它
  项目的 key/端口连本测试机。

## §2 知识沉淀：每轮追加 tests\CRASH_DEBUG_LOG.md

- 每一轮 VM 调试**必须**在 `tests\CRASH_DEBUG_LOG.md` 追加一条记录。
- 每条必含五段：**现象 / 与参考的对比 / 修复尝试 / 关键决策回顾 / TODO**。
- 没写进日志的一轮等于没做——后续会话无法接手。

## §3 硬重启是唯一恢复手段

- 疑似冻结先做**判活三件套**，禁止直接 reset（会浪费 boot 轮次）：
  1. `build\vm_alive_check.bat`：`Tools 未运行` 可能只是 Tools 失联，**exec 探针**
     才是判据；
  2. windbg-mcp 尝试 break in：KDNET 能断 → 内核活着 → 多半是 kd 挂了目标没放行，
     `g` 放行即可；
  3. 前两项都失败，才判定冻结。
- 冻结恢复**只许** `build\vm_reset_hard.bat`。
- **禁止**把 `sc stop MyArkCore` 当恢复手段（冻结态必然卡死）。
  例外：健康状态下的正常重部署（换 .sys 前停驱动）属 Phase 3 流程，由
  `build\vm_svc_clean.bat` 承担，不算恢复动作。

## §4 构建与版本纪律

- 改动后必跑 `build\build_driver.bat`；产物必须落
  `driver\x64\Release\MyArkCore.sys`（vcxproj 以 `$(SolutionDir)` 钉死 OutDir）。
- **禁止**裸编 `driver\MyArkCore.vcxproj`：直编丢 SolutionDir 且**跳过测试签名**
  （2026-09-08 踩坑：NotSigned 产物在 guest 报 577）。一律走 `driver\MyArkCore.sln`。
- `make.bat` 在 Git Bash 下会被 `Program Files (x86)` 的括号解析搞崩——用
  `build\build_driver.bat`。
- 宿主机 .bat 从 Git Bash 启动还有两类**静默互操作坑**（2026-09-15
  vm_kdnet_set 实测）：① `if not exist X mkdir X < NUL & cmd2`——cmd 把
  `& cmd2` 绑进 IF 分支体，条件为假时整条链被跳过（改用幂等
  `mkdir X 2>nul`）；② 脚本里按名调用 `find` 会被 /usr/bin 的 GNU find
  抢占，`find /c` 变成对 C:\ 的全盘爬取（改 findstr 过滤 + for 计数）。
- 部署前必须 host/guest 双向 SHA256 一致（`build\vm_push_driver.bat` 内置，
  不一致立即中止）。
- 签名：`SignMode=Test` 自动签 `WDKTestCert www`；guest 需该证书在
  Root + TrustedPublisher（`build\vm_guest_setup.bat`）。换 VM / 换账户后重做。

## §5 技能边界

| 技能 | 职责 |
|---|---|
| vm-driver-debug-loop | Phase 0–7 总控；`build\vm_*.bat` 舰队的语义来源 |
| vmware-vm-control | 电源 / 开机 / 登录 / 桌面就绪 |
| vmware-file-transfer | 传输与哈希校验底层（`vm-guest.sh` / `verify-hash.sh`，不重复包装） |
| windbg-vm-kernel-debug | KDNET 连接 / 断点 / 寄存器 / 符号知识 |
| computer-use、browser-use | 仅截屏与 web 操作；**禁用于驱动调试**（会绕过 Phase 1–7） |

- KDNET 的实际执行一律经 windbg-mcp（§1）；上述技能只提供方法与话术。

## §6 本文件不包含什么

- 架构：`ARCHITECTURE.md`；协议/API：`shared\driver\*.h`、`BUILD_EXE.md`；
  调试史：`tests\CRASH_DEBUG_LOG.md`；已知问题：`KNOWN_ISSUES.md`；
  VM 安装手册：`VM_SETUP.md`。
- 本文件保持短而硬：只写规则与踩坑，新知识进各自文档。

## §7 GitHub 发布纪律（Plan A：orphan 单根提交）

- `main` 永远**单根**；`master` 永不 push、永不创建。
- root commit 作者必须用 GitHub noreply（`<id>+<user>@users.noreply.github.com`）。
- 身份注入**唯一正确**方式：`git -c user.name=... -c user.email=... commit-tree`
  （per-invocation 作用域，不受 shell 链影响）。

```bash
# Plan A 可复现流程（先把目标内容 git add 成树）
git add -A
tree=$(git write-tree)
root=$(git -c user.name="<name>" \
            -c user.email="<id>+<user>@users.noreply.github.com" \
            commit-tree "$tree" -m "initial commit")
git switch --detach
git branch -f main "$root"   # main 指向新的单根提交
git switch main
```

- **Never**：
  - `export GIT_AUTHOR_EMAIL=...` 塞进 `&&` 链（作用域丢失，2026-09-14 踩坑）；
  - 改 `.git/config` 的 `user.*` 再改回；
  - 在孤儿树之外直接 commit 后 push 到 main；
  - 对任何已发布分支 `git push --force`。

- **现状（2026-09-19 已发布）**：`main` 已按 Plan A 重建为孤儿单根
  （root = `74693e7`，作者/提交者均为
  `MyArkCppDev <57830391+mikasaw@users.noreply.github.com>`）并发布到
  `https://github.com/mikasaw/MyArk`（public，仅 `main` 分支）。旧
  218-commit 历史（含敏感值，**永不 push**）保存在本地 reflog，旧
  末端 = `db971c3`；本地遗留分支 `feat/mit-254-shared-driver-headers`
  与 `s9.2-multiwindow` 不得推送。敏感值排查（KDNET key/guest 账密/
  个人路径）在发布树为零命中，真实值住 `build/vm_env_local.bat`
  （gitignored）。
