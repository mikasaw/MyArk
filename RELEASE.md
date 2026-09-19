# RELEASE

MyArk v1.0.0 发布 checklist / cut / sign / tag。

每个条目都是**二进制**的:要么打勾 (满足),要么不打 (阻塞发布)。
跑完前请复制这份到 PR description。

---

## 1. Pre-flight (代码 + 文档)

- [ ] `git status` 工作树空
- [ ] `git log --oneline | wc -l` >= 96 commit
- [ ] 最新 commit 在 `main` 分支
- [ ] 所有 commit message 不含"完成"字 (项目硬纪律)
- [ ] `LICENSE` 存在 (MIT)
- [ ] `CHANGELOG.md` 存在, >= 15KB, [版本]-日期 格式 + 5 类语义分区
- [ ] `KNOWN_ISSUES.md` 存在, >= 1KB
- [ ] `README.md` 存在, >= 28KB, 含 "v1.0.0 发布" 章节
- [ ] `ARCHITECTURE.md` 存在, >= 15KB
- [ ] `CONTRIBUTING.md` 存在, >= 10KB
- [ ] `config/BUILD_MATRIX.md` 5 profile size 记录完整

## 2. Build matrix (R0)

- [ ] `scripts/make.bat full Debug` -- 0 warning / 0 error
- [ ] `scripts/make.bat core Debug` -- 0 warning / 0 error
- [ ] `scripts/make.bat mini Debug` -- 0 warning / 0 error
- [ ] `scripts/make.bat process_only Debug` -- 0 warning / 0 error
- [ ] `scripts/make.bat safety_audit Debug` -- 0 warning / 0 error
- [ ] 5 profile `MyArkCore.sys` 字节数已写入 `config/BUILD_MATRIX.md`
- [ ] full profile 字节数 >= mini profile × 4 (验证宏门控真生效)

## 3. Tests (R3)

- [ ] `cd client && uv run pytest tests/ -q` -- >= 600 passed, <= 10 skipped
- [ ] 0 来自 MyArk 自身代码的 warning (允许 pypinyin 内部 codecs.open
  DeprecationWarning, 但不增 MyArk 自身 warning)
- [ ] `tests/test_core_ioctl.py` 5 core IOCTL 全 pass
- [ ] `tests/test_dyndata_*` 54 条全 pass
- [ ] `tests/test_callback_*` 52 条全 pass
- [ ] `tests/test_actions_*` 68 条全 pass
- [ ] 8 个 UI 弹窗 widget 测试 全 pass (Detail 8 / Diff 10 / Filter 12 /
  History 15 / KeyBindings 12 / MainWindow 13 = 70 条)

## 4. Static IOCTL verification (R3 端到端)

- [ ] `python scripts/verify_core.py --all` 59 IOCTL 全 pass (S7.1 9 +
  S7.2 10 + S7.3 40)
- [ ] verify 输出含 "All IOCTLs OK" 或等价结尾行
- [ ] verify 退出码 = 0

## 5. Host-side install (ASCII batch)

- [ ] `scripts/install.bat` 在**已启用 testsigning 的 VM 内**全流程通过
      (admin 检测 + 拷贝 .sys + sc create + sc start + STATE RUNNING)
- [ ] `scripts/uninstall.bat` 在 VM 内清理后状态全 0 (无残留 service / 文件 /
      registry)
- [ ] 双重 install → 第二次成功 (幂等性)
- [ ] 双重 uninstall → 第二次返回 exit 0 (幂等性)

## 6. VM-side install (PowerShell)

- [ ] `powershell scripts/install_vm.ps1` 在 Hyper-V Gen2 guest 内:
      - 检测到 VM 环境 (hyperv marker)
      - testsigning 校验通过
      - sc create + sc start 通过
      - verify_core.py 串行调用全 pass (exit 0)
- [ ] `powershell scripts/uninstall_vm.ps1` 清理后:
      - service 不存在
      - registry key 不存在
      - .sys 文件保留 (caller-owned,仅提示手动删除)
- [ ] `install_vm.ps1 -AllowBareMetal` 在非 VM 测试机可绕过 VM 守卫

## 7. UI smoke test (R3)

- [ ] `myark-ui` 启动无异常 (Python 3.14 + Tkinter)
- [ ] 左栏显示实体列表,Ctrl+P 命令面板可弹出
- [ ] Ctrl+Shift+F 高级搜索可弹出 (8 scope + 3 mode)
- [ ] View → Detail Window 可弹出 (DetailWindow)
- [ ] View → Compare 可弹出 (DiffWindow)
- [ ] View → Filter builder 可弹出 (FilterWindow)
- [ ] View → Action history 可弹出 (HistoryWindow,读 `~/.myark/history.log`)
- [ ] F1 弹出 Help Window,Esc 关闭
- [ ] Ctrl+W 关闭顶层 popup,Ctrl+Tab 在 popup 间循环
- [ ] 关闭后重启,布局从 `~/.myark/layout.json` 恢复

## 8. CLI smoke test (R3)

- [ ] `myark-cli --help` 列出 27 模块 + driver 子命令
- [ ] `myark-cli driver version` 返回 MyArkCore 版本号
- [ ] `myark-cli driver modules` 列出 35 模块 (含 enable/disable 状态)
- [ ] `myark-cli process list` 在 host 内返回进程列表
- [ ] `myark-cli dyndata query process` 在 VM 内返回进程列表 (S7.1)
- [ ] `myark-cli callback enumerate --type ps` 在 VM 内返回 5+ PsSetCreateProcess
      (S7.2)
- [ ] `myark-cli --json <subcommand>` JSON 输出合法

## 9. Signing

- [ ] 用户在 VM 内生成 self-signed test cert:
      `New-SelfSignedCertificate -Type Kernel -Subject "CN=MyArk Test" -CertStoreLocation Cert:\LocalMachine\My`
- [ ] cert 用 `signtool sign /fd SHA256 /a driver/x64/Debug/MyArkCore.sys`
      签名成功
- [ ] `signtool verify /v MyArkCore.sys` 报告 "Signing Certificate is found"
- [ ] 注:正式 WHQL 签名**不在** v1.0.0 范围,见 KNOWN_ISSUES.md

## 10. Tag + Release

- [ ] `git tag -a v1.0.0 -m "MyArk v1.0.0"` (GPG 可选)
- [ ] `git push origin main --tags`
- [ ] GitHub release:标题 `MyArk v1.0.0`,body 贴本 RELEASE.md 内容
- [ ] 上传产物:
      - `MyArkCore.sys` (full profile, Debug)
      - `MyArkCore.sys` (core profile, Release)
      - `scripts/install_vm.ps1` + `scripts/uninstall_vm.ps1`
      - `scripts/install.bat` + `scripts/uninstall.bat`
      - `scripts/verify_core.py`
      - `CHANGELOG.md` + `KNOWN_ISSUES.md` + `LICENSE`
- [ ] GitHub release 链接已贴回 Multica issue MIT-343

---

## 完成定义 (Definition of Done)

本 RELEASE 的所有 checkbox 全部勾选,**且**以下 3 项满足时,才视为 v1.0.0
可发布:

1. **R0 build 矩阵**:5 profile × 2 config (Debug/Release) = 10 个 build 全
   0 warning / 0 error。
2. **R3 测试**:pytest >= 600 passed,0 MyArk 内部 warning。
3. **VM 实物**:Hyper-V Gen2 guest 内 install_vm.ps1 + verify_core.py
   59+ IOCTL 全 pass,exit code 0。

---

## 不在 v1.0.0 范围

下列项目标 `KNOWN_ISSUES.md` 而非本 checklist,因为它们不阻塞发布:

- WHQL 正式签名 (需 EV cert + 微软提交,见 KNOWN_ISSUES § 安全)
- 多 .sys 插件 DLL (违反"部署极简"硬纪律)
- PySide / PyQt / dearpygui 等其它 GUI 框架 (违反 Tkinter 硬纪律)
- 远程 IOCTL 通道 (违反 DeviceIoControl 单链路纪律)
- macOS / Linux 适配 (Windows-only ARK)

## 风险与回滚

如果发布后发现严重 bug (例如某 IOCTL 触发 BSOD):

1. GitHub release 标记为 pre-release / yank。
2. `git revert` 引入 bug 的 commit (回滚 PR,而非 reset --hard)。
3. 升级到 v1.0.1 (patch bump)。
4. 在 KNOWN_ISSUES.md 加 regression 记录。

绝不在已 tag 的 commit 上 force-push 或 amend。
