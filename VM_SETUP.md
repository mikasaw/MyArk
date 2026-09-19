# MyArk VM 实物验证设置

> 文档目的: 引导用户在 VM 内安装 + 运行 + 验证 MyArk 驱动
> 适用版本: MyArk v1.0.0
> 更新日期: 2026-08-27

---

## 1. 前置条件

### 1.1 操作系统
- Windows 11 22H2 / 23H2 / 24H2 (推荐 24H2)
- Windows 10 21H2 / 22H2 (兼容性, 测试少)
- 64-bit (x64 only)
- 用户必须 **Administrator** (安装驱动需要 admin)

### 1.2 主机 VM 环境
推荐使用以下 VM:
- Hyper-V (Win11 自带)
- VMware Workstation Pro 17+（同类项目已验证）
- VirtualBox 7+

VM 配置:
- 内存 ≥ 4 GB (推荐 8 GB)
- 磁盘 ≥ 60 GB
- 启用嵌套虚拟化 (nested virtualization) 如果要测试 AMD-V/SVM 类的 MyArkCore 功能

---

## 2. 准备 VM

### 2.1 安装 Windows (略)

### 2.2 启用测试签名
```cmd
bcdedit /set testsigning on
shutdown /r /t 0
```
重启后桌面右下角显示 "测试模式" 水印, 表示成功。

### 2.3 复制 MyArk 到 VM
把以下文件复制到 VM (建议 `C:\MyArk\`):
- `driver\x64\Release\MyArkCore.sys` (驱动)
- `client\src\myark\` (R3 客户端源码)
- `scripts\install_vm.ps1` (安装脚本)
- `scripts\verify_core.py` (验证脚本)

---

## 3. 安装驱动 (主机 / VM 都跑)

### 3.1 编译产物 (主机)
在主机 (Win11, 需 Insiders VS + WDK 10.0.28000):
```cmd
cd C:\Users\YourName\source\repos\MyArk
make full
```
产物:
- `driver\x64\Release\MyArkCore.sys` (Release 编译)

### 3.2 在 VM 安装
打开管理员 PowerShell, 在 VM 内:
```powershell
# 安装驱动
.\scripts\install_vm.ps1
```
脚本自动:
- 复制 .sys 到 `C:\Windows\System32\drivers\MyArkCore.sys`
- 创建服务 `MyArkCore` (类型 = kernel)
- 设置依赖关系
- 启动服务

或者手工安装:
```cmd
sc create MyArkCore type=kernel binPath="C:\Windows\System32\drivers\MyArkCore.sys"
sc start MyArkCore
```

### 3.3 验证安装
```cmd
sc query MyArkCore
```
预期输出 `STATE: 4 RUNNING`.

---

## 4. 验证 MyArk

### 4.1 R3 客户端测试
```cmd
cd C:\MyArk
uv sync
uv run myark-cli --help
uv run myark-cli registry list HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion
uv run myark-cli network tcp-list
uv run myark-cli process enum
uv run myark-cli callback enum-callback
```

### 4.2 驱动功能测试
```powershell
.\scripts\verify_core.py
```
脚本执行:
- 50+ 项 IOCTL 调用
- 验证进程 / 线程 / 内存 / 注册表 / 网络 / 回调 / dyndata / actions 模块
- 输出 PASS/FAIL 报告

### 4.3 UI 测试
```cmd
uv run myark-ui
```
GUI 启动, 测试:
- 主窗 + 三层搜索 (Ctrl+P 调色板)
- 浮动窗口 (详情窗 / 比较窗 / 过滤窗 / 历史窗)
- 模块切换

---

## 5. 卸载

### 5.1 卸载驱动
打开管理员 PowerShell:
```powershell
.\scripts\install_vm.ps1 -Uninstall
```

### 5.2 清理
```cmd
del C:\MyArk
```

---

## 6. 故障排查

### 6.1 驱动加载失败
```
错误: 0xC0000034 (STATUS_OBJECT_NAME_NOT_FOUND)
解决: 确认 .sys 在 `C:\Windows\System32\drivers\`
```

### 6.2 测试签名失败
```
错误: 0xC0000428 (STATUS_INVALID_IMAGE_HASH)
解决: 重新 `bcdedit /set testsigning on` + 重启
```

### 6.3 R3 客户端连不上驱动
```
错误: WinError 2 (系统找不到文件)
解决: 确认 MyArkCore 服务已启动 (`sc query MyArkCore`)
```

---

## 7. 已知限制 (KNOWN_ISSUES.md 摘要)

- VM 实物验证只覆盖 R3 fallback + 部分 R0 模块
- WDK 10.0.28000 是唯一验证的编译环境
- AMD-V/SVM 嵌套虚拟化在 Win11 24H2 上有限制 (见 multica 相关文档)
- 5 profile sizes (full/mini/process-only/core/safety-audit) 各自只测基础 IOCTL

---

## 8. 报告问题

发现 bug 请:
1. 在 VM 内 `python -m myark.debug.bug_report`
2. 提交到 GitHub Issues
3. 附上 verify_core.py 完整输出

---

文档维护: hermes | 最后更新: 2026-08-27
