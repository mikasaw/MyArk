# Contributing to MyArk

本文定义 MyArk 项目的开发纪律、commit message 写法、模块新增流程、测试与发布要求,供所有 contributor 遵守。

---

## 目录

- [硬纪律 (用户硬性要求)](#硬纪律)
- [commit message 模板](#commit-message-模板)
- [分支策略](#分支策略)
- [模块新增流程](#模块新增流程)
- [测试与验证](#测试与验证)
- [代码风格](#代码风格)
- [路径与文件命名](#路径与文件命名)
- [issue / PR 协作](#issue--pr-协作)
- [作者与署名](#作者与署名)

---

## 硬纪律

以下规则由项目所有者在 issue / CLAUDE.md 中明确,**所有 contributor 必须遵守**:

1. **实施顺序严格按四象限递进**

   ```
   ① R3 纯用户态  → winreg / IP Helper / PSAPI / WTS
   ② R0 读 + R3 展示 → 内核读 buffer,R3 解析展示
   ③ 必须 R0        → MmCopyVirtualMemory / ObReferenceByPointer
   ④ 混合          → R3 优先 + R0 备用 (kill / inject / dump)
   ```

   一个 issue 不能跨阶段。S5-S8 各完成 4 项验证才进下一阶段。

2. **编译期模块门控**

   每个模块独立 `.c` / `.h` + 描述符,`#if MYARK_MODULE_<NAME>` 包裹。任何模块都不应"半条件编译"。

3. **运行时启停**

   启停由注册表控制,不改代码:

   ```
   HKLM\SYSTEM\CurrentControlSet\Services\MyArkCore\Modules\<Name>=0   禁用
   HKLM\SYSTEM\CurrentControlSet\Services\MyArkCore\Modules\<Name>=1   启用
   ```

4. **部署极简**

   1 个 `.sys` + 1 个 INF + 1 个 `sc create`。**不做**多 .sys 插件 DLL。

5. **UI 框架**

   Tkinter 主从三栏 + 浮动窗口多任务。不引入其它 GUI 框架 (PySide / PyQt / dearpygui)。

6. **三层搜索 (强制)**

   - 左栏过滤 (substring + pinyin)
   - Ctrl+P 命令面板 (跨模块 jump list)
   - 侧栏高级搜索 (8 scope + 3 mode)

   中文/拼音支持用 `pypinyin`,**不引入**新依赖。

7. **不夹带其它模块改动**

   一个 commit 一件事。提交前必须 `git diff --stat` 自检。

8. **不动 frozen contract**

   下列文件改动需单独 issue 提议:

   - `driver_entry.c`
   - `ioctl_dispatch.c`
   - `ioctl_registry.h` / `ioctl_registry.c` 表结构
   - `shared/driver/MyArk*.h` (公共协议头, 每模块一个 MyArk<N>Ioctl.h)

9. **commit 后必须 fresh 跑一次 ad-hoc verification**

   ```bash
   cd client && uv run pytest tests/ -q       # 期望 575+ passed
   scripts\make.bat full Debug                 # 期望 BUILD SUCCEEDED
   ```

10. **bat 纯 ASCII**

    `.bat` / `.ps1` / `.vbs` / `.cmd` 文件内不允许出现中文字符。中文说明一律走 README / .md。

11. **不写"完成"**

    commit message / issue description / 内部说明中不出现"完成"、"完结"、"done"等总结词。`git log` 必须 0 条含"完成"。

---

## commit message 模板

### 标题

```
<type>(<scope>): <subject>  (中文)
```

| type | scope example | 使用 |
|---|---|---|
| feat | process / thread / memory / module / scripts | 新 IOCTL / 新功能 |
| fix | build / dispatch / actions | 修复 bug / build error |
| test | verify / client / pytest | 测试代码 |
| doc | readme / architecture / changelog | 仅文档 |
| refactor | client / dispatch / safety | 重构不改行为 |
| chore | scripts / deps / .gitignore | 杂项 |

### 标题要求

- < 50 字符 (中文 30 字以内)
- 不写"完成" "添加成功" "实现" 等总结词
- 用动词开头 (添加 / 修改 / 修复 / 拆分 / 提取)
- scope 用 issue / plan 中的正式名称

### 三段式 body

```
角色: MyArkCppDev
任务: S6.3 process 扩展
改动: 在 10_process/ioctl.c 添加 MyArkIoctlProcessToken 处理器,
     写 ctypes 结构 MyArkProcessTokenRequest / Response,
     添加 pytest 7 条 (request pack/unpack + handler 镜像),
     CLI 暴露 myark-cli process token --pid 1234
```

或长描述六段式 (issue / PR description):

```
角色:
目标:
前置:
任务步骤:
验收:
行为红线:
```

### 示例 (良好)

```
doc(readme): 扩展 README 至 28KB (架构 + 命令行 + 模块列表 + 构建矩阵)

角色: MyArkCppDev
任务: S10.1 收尾
改动: 重新组织 README 结构,新增架构图 (R0/R3 框图、通信流程、四象限)、
模块列表 (35 驱动 + 27 R3)、构建矩阵 5 profile、运行手册 (VM testsigning +
install_vm.ps1)、命令行手册 (27 模块子命令)、测试说明、贡献指南
```

### 示例 (错误)

```
实现 process 模块 done
```

```
fix: 一些 bug 修复
```

```
完成了 R3 客户端
```

### 静态校验 (发布前)

```bash
git log --all --format='%s%n%b' | grep -i "完成\|done" | head -5
# 期望: 无输出
```

---

## 分支策略

```
main                 -- 受保护,所有 commit 都要可重建
feature/s6.3-process -- 单个功能分支 (issue 编号)
fix/s7.2-callback    -- 单 bug 分支
```

- `main` 不允许 force-push
- 单 commit 在 `main` 上 squash-rebase 后 push
- 功能分支命名 `<type>/<issue-id>-<slug>`

---

## 模块新增流程

新增一个驱动模块 (示例 S9.2 加 `90_sample`):

### 1. 目录结构

```
driver/src/modules/90_sample/
  sample_descriptor.h  # 描述符声明 (g_MyArkModule_Sample)
  sample_descriptor.c  # 描述符实例化 + 静态 IOCTL 表
  sample_ioctl.h       # IOCTL id 宏 + request/response 结构
  sample_ioctl.c       # IOCTL handler 实现
  sample_safety.c      # SAFETY_TOKEN 与额外权限检查 (可选)
```

### 2. 描述符

描述符契约见 `shared/driver/MyArkPluginApi.h` (`MYARK_MODULE_DESCRIPTOR`,
符号约定 `g_MyArkModule_<Name>`); IOCTL 表项是 `driver/src/dispatch/ioctl_registry.h`
的 `MYARK_IOCTL_ENTRY { IoctlCode, Handler, Name, RequiredCapability, Flags }`:

```c
// sample_descriptor.h
#pragma once
#include "module_descriptor.h"      // driver/src/module/module_descriptor.h

extern MYARK_MODULE_DESCRIPTOR g_MyArkModule_Sample;

// sample_descriptor.c
#include <ntddk.h>
#include <wdf.h>
#include "module_descriptor.h"
#include "ioctl_registry.h"         // driver/src/dispatch/ioctl_registry.h
#include "sample_ioctl.h"

static MYARK_IOCTL_ENTRY g_SampleIoctls[] = {
    {
        IOCTL_MYARK_SAMPLE_ENUM,        // IoctlCode
        MyArkSampleEnumHandler,         // Handler
        "IOCTL_MYARK_SAMPLE_ENUM",      // Name
        0,                              // RequiredCapability
        0                               // Flags
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_Sample = {
    "sample",                           // ModuleName (PCSTR)
    "Sample enumeration module",        // ModuleDescription (PCSTR)
    0x53414D50UL,                       // ModuleId 'SAMP' -- 新 id 加进 MyArkPluginApi.h
    ARRAYSIZE(g_SampleIoctls),          // IoctlCount
    g_SampleIoctls,                     // Ioctls
    SampleInit,                         // Init (DriverEntry, PASSIVE_LEVEL)
    SampleCleanup,                      // Cleanup (DriverUnload)
    FALSE                               // Initialized
};
```

最后在 `driver/src/module/module_registry.c` 的 `g_AllModules[]` 里按
`#if MYARK_MODULE_SAMPLE` 门控登记 `g_MyArkModule_Sample` 符号 (参照
`00_hello/hello_descriptor.c` 的接法)。

### 3. MSBuild 接入

`MyArkCore.vcxproj.filters` 添加虚拟路径:

```xml
<ClInclude Include="src\modules\90_sample\sample_descriptor.h">
  <Filter>modules</Filter>
</ClInclude>
<ClCompile Include="src\modules\90_sample\sample_descriptor.c">
  <Filter>modules</Filter>
</ClCompile>
```

### 4. 编译期门控

`config/myark_full.h` 添加:

```c
#define MYARK_MODULE_SAMPLE          1
```

### 5. R3 协议

`client/src/myark/protocol/sample.py`:

```python
import ctypes

class SampleEnumRequest(ctypes.Structure):
    _fields_ = [("head", ctypes.c_uint32)]

class SampleEnumResponse(ctypes.Structure):
    _fields_ = [
        ("count", ctypes.c_uint32),
        ("entries", ctypes.c_uint32 * 64),  # 限 64 条
    ]
```

### 6. R3 客户端

`client/src/myark/modules/sample/__init__.py`:

```python
from .module import register
```

`module.py`:

```python
from ..plugin_loader import ModuleRegistration

def register(client, capabilities):
    return ModuleRegistration(
        name="sample",
        cli=[...],
        ui={"tab_factory": ...},
        describe=lambda: ModuleInfo(...),
    )
```

### 7. 测试

`client/tests/test_sample_protocol.py`:

```python
import ctypes
from myark.protocol.sample import SampleEnumRequest, SampleEnumResponse

def test_pack_unpack_roundtrip():
    req = SampleEnumRequest(head=42)
    data = req.pack()
    out = SampleEnumRequest.unpack(data)
    assert out.head == 42

def test_empty_request():
    req = SampleEnumRequest()
    assert req.pack()  # 不抛
```

`client/tests/test_sample_client.py`:

```python
import pytest
from myark.client.ark_client import ArkClient

def test_enum_when_driver_missing(capsys):
    with ArkClient() as client:
        client.call(ioctl_id=..., request=..., response_type=...)
    # ...
```

### 8. 验证

```bash
cd client && uv run pytest tests/ -q
scripts\make.bat full Debug
```

### 9. commit

```
feat(sample): 90_sample 模块 — 描述符 + IOCTL + R3 + 测试 (7 条)

角色: MyArkCppDev
任务: S9.2 sample 模块新增
改动: 新增 driver/src/modules/90_sample/{sample_descriptor.h,.c,sample_ioctl.h,.c,sample_safety.c},
       MyArkCore.vcxproj.filters 接入 + module_registry.c 登记,
       config/myark_full.h #define MYARK_MODULE_SAMPLE 1,
       client/src/myark/protocol/sample.py,
       client/src/myark/modules/sample/{__init__,module}.py,
       client/tests/test_sample_{protocol,client}.py (7 条)
验收: scripts\make.bat full Debug 0 warning / 0 error,
       pytest 575+7 passed
```

---

## 测试与验证

### 单元测试

```bash
cd client
uv sync
uv run pytest tests/ -q                 # 快 (~5s)
uv run pytest tests/ --cov=myark --cov-report=term-missing  # 覆盖率
```

期望: **575 passed, 5 skipped** (跳过的是依赖外部驱动 / VM 的项)。

### 驱动构建

```bash
scripts\make.bat full Debug                # 完整
scripts\make.bat full Release              # 发布
scripts\make.bat mini Debug                # 最小烟测
scripts\make.bat core Debug                # 基础三件套
scripts\make.bat process_only Debug        # 单模块烟测
scripts\make.bat safety_audit Debug        # 安全审计模式
```

期望: 每个 profile `BUILD SUCCEEDED`,`MyArkCore.sys` 真实生成,`/WX` 等价 (0 warning)。

### 静态验证脚本

```bash
python scripts/verify_core.py
```

期望: 全 PASS。失败时给出模块名 + 行号。

### 实物 (VM 内, host 不可)

```bash
# 在 VM 内 (Hyper-V Gen2, testsigning on):
.\scripts\install_vm.ps1 -DriverPath C:\MyArkCore.sys

myark-cli driver check           # 应该 SUCCESS
myark-cli driver modules         # 应列出所有 enabled 模块
myark-cli process enum           # 应返回当前进程列表
```

---

## 代码风格

### C / KMDF

| 项 | 风格 |
|---|---|
| 缩进 | 4 spaces,不用 tab |
| 命名 | PascalCase (函数) / camelCase (变量) / UPPER_CASE (宏) |
| 行长 | < 100 |
| 头文件防护 | `#pragma once` |
| 错误路径 | NTSTATUS 显式检查,不吞错误 |
| 资源管理 | RAII 通过 KMDF object 自动释放 |
| WPP | Trace.h 标注,无 printf 风格日志 |

### Python (R3)

| 项 | 风格 |
|---|---|
| 缩进 | 4 spaces |
| 命名 | snake_case (函数/变量) / PascalCase (类) / UPPER_CASE (常量) |
| 类型提示 | 全函数必须有 type hints (`from __future__ import annotations`) |
| 行长 | < 88 (Ruff 默认) |
| 工具 | `ruff check` / `ruff format` |
| import | 绝对 import,`from __future__ import annotations` |

### 错误处理

- 不抛裸 `Exception`,抛业务特定 (e.g. `DriverError`)
- `try` 块最小,`except` 只捕获已知
- fallback 显式标注 (`# R3 fallback` 等)

---

## 路径与文件命名

- `绝对机器路径`:**禁止**(例如 `C:\Users\<you>\...`)
- 仓库内路径用相对根目录,例:`driver/src/modules/10_process/ioctl.c:42`
- `.bat` / `.ps1` 文件夹名:`scripts/` (单数小写)
- 模块目录:`<NN>_<name>/` (两位数字前缀保证字典序)
- 协议文件名:`<module>_protocol.py`
- 测试文件:`test_<module>_<aspect>.py`

---

## issue / PR 协作

### 创建 issue

```markdown
## 角色
MyArkCppDev

## 目标
(S6.3 process 扩展)

## 前置
- S6.1 process 基础 done
- config/myark_full.h 已经开了 MODULE_PROCESS

## 任务步骤
1. 加 MYARK_IOCTL_PROCESS_TOKEN IOCTL
2. 驱动实现 EPROCESS Token 字段读取
3. R3 协议 + 客户端 + CLI 暴露
4. 测试 7 条

## 验收
- scripts\make.bat full Debug 0 warning / 0 error
- pytest 7 条新用例 PASS
- myark-cli process token --pid 1234 输出真实 Token SID

## 行为红线
- 不动 frozen contract (driver_entry.c / ioctl_dispatch.c / shared/driver/MyArk*.h)
- 不写"完成"
- 1 commit 1 task
```

### PR description

```
fixes #<issue-id>

## 改动
(same as commit body 3-段式)

## 测试
- pytest 575 passed
- scripts\make.bat full Debug BUILD SUCCEEDED

## 红线检查
- [ ] 没有跨模块改动
- [ ] commit 标题不含"完成"
- [ ] 没有动 frozen contract
```

---

## 作者与署名

- 主线 contributor:`MyArkCppDev` (单 agent,持久)
- helper agent:按需 spawn,完成后从 git log 可识别
- commit 一次只一个 author (`git config user.name`)
- 大段代码借用第三方:在文件头添加 SPDX 注释:

```c
// SPDX-License-Identifier: MIT
// Adapted from <source> on <date>, MIT
```
