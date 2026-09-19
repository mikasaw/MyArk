# MyArk Architecture (R0/R3)

本文讲解 MyArk 内核驱动与 R3 客户端的架构、IOCTL 协议、模块生命周期、配置与运行时的双层开关,以及四象限实现的边界划分。

---

## 目录

- [总体结构](#总体结构)
- [R0 驱动结构](#r0-驱动结构)
- [R3 客户端结构](#r3-客户端结构)
- [IOCTL 协议](#ioctl-协议)
- [模块描述符与注册表](#模块描述符与注册表)
- [编译期 / 运行时双层门控](#编译期-运行时双层门控)
- [四象限划分](#四象限划分)
- [SAFETY_TOKEN](#safety_token)
- [错误码与状态映射](#错误码与状态映射)
- [生命周期](#生命周期)
- [依赖与外部调用](#依赖与外部调用)

---

## 总体结构

```
+-----------------------------+         +--------------------------------+
|         R3 (Python)         |  IPC    |          R0 (MyArkCore.sys)    |
|  +-----------------------+  |  ----> |  +---------------------------+ |
|  | myark-cli / myark-ui  |  | DeviceIoControl                   |
|  +-----------------------+  |        |  +---------------------------+ |
|  | myark.client.*        |  |        |  | KMDF DriverEntry          | |
|  |   ArkClient           |  |        |  +---------------------------+ |
|  +-----------------------+  |        |  | ioctl_dispatch.c          | |
|  | myark.protocol.*      |  |        |  | ioctl_registry.c          | |
|  +-----------------------+  |        |  | ioctl_validation.c        | |
|  | myark.modules.*       |  |        |  +---------------------------+ |
|  +-----------------------+  |        |  | modules/<NN>_<name>/*     | |
|                             |        |  +---------------------------+ |
+-----------------------------+        +--------------------------------+
```

通信仅一条链路: 用户态 `CreateFile("\\\\.\\MyArkCore")` 拿到 kernel handle,所有 IOCTL 都走 `DeviceIoControl`。**没有** ALPC、命名管道、共享内存或 file-filter 通道。简单、显式、易于在 DevView / Process Monitor 中观察。

---

## R0 驱动结构

### 目录

```
driver/
  MyArkCore.inf                              # INF: service / registry layout
  MyArkCore.sln                              # MSBuild 解决方案
  MyArkCore.vcxproj                          # MSBuild 项目
  MyArkCore.vcxproj.filters                  # 虚拟目录映射
  Trace.h                                    # WPP 跟踪宏
  myark_config.h                             # 转发到 config/myark_*.h

  src/
    framework/                               # 驱动骨架
      driver_entry.c                         # DriverEntry / DriverUnload
      device_control.c                       # IRP_MJ_DEVICE_CONTROL 入口
      io_queue.c                             # WDFQUEUE 并行串行策略

    dispatch/                                # IOCTL 分派 + 校验
      ioctl_dispatch.c                       # MyArkDispatchIoctl
      ioctl_registry.c                       # 模块描述符 IOCTL 表
      ioctl_validation.c                     # SAFETY_TOKEN / 长度校验
      core_ioctl_handlers.c                  # 核心 5 IOCTL handler
      ioctl_helpers.h                        # 输入/输出缓冲宏

    modules/                                 # 业务模块 (functional)
      00_hello                               # 机制烟测
      10_process ... 87_actions              # 30 functional modules
```

### 入口流

```
DriverEntry (driver_entry.c)
  -> WdfDriverCreate
     -> Driver object callbacks registered:
        - EvtDriverUnload (DriverUnload)
        - EvtDeviceAdd   (DeviceAdd)            [in device_control.c]

DeviceAdd (device_control.c)
  -> WdfDeviceInitSetIoType(Direct)
  -> WdfDeviceCreate(&deviceInit, ...)
  -> WdfDeviceCreateSymbolicLink ("\\.\MyArkCore")
  -> WdfIoQueueCreate (WdfIoQueueDispatchSequential, default queue)
     -> EvtIoDeviceControl = MyArkEvtIoDeviceControl

MyArkEvtIoDeviceControl (device_control.c)
  -> WdfRequestGetInputBuffer / WdfRequestGetOutputBuffer
  -> MyArkDispatchIoctl (ioctl_dispatch.c)
     -> 1. 校验 WdfRequest-传来的 IOCTL id 在 core_ioctl_handlers 的固定表里
        2. 校验 SAFETY_TOKEN
        3. 校验输入/输出长度
        4. 查找 ioctl_registry 中对应描述符
        5. 转发到模块 handler
     -> WdfRequestComplete with STATUS_SUCCESS / STATUS_INVALID_* / BUFFER_TOO_SMALL
```

### 锁与 IRQL

驱动默认在 `PASSIVE_LEVEL` 完成所有工作 (非中断、非 DPC)。`PROCESSOR` 模式锁定 (MMCSS 不参与)。涉及 KAPC / 自旋锁的少部分钩子 (`70_dyndata` / `71_callback` / `73_mutation` 等) 在内部局部使用,不暴露给 R3。

### KMDF 版本

```
KMDF 1.x 头文件 + Library (.lib linked from DDK)
NTIFS / WDM 头文件来自 WDK
```

构建工具链:

| 工具 | 版本 |
|---|---|
| MSVC | 2022 (cl 19.5x via VS 18 Insiders) |
| WDK  | 10.0.28000.0 (强制) |
| MSBuild | VS 18 Insiders (`MSBuild\Current\Bin\MSBuild.exe`) |

---

## R3 客户端结构

### 目录

```
client/
  pyproject.toml
  uv.lock

  src/myark/
    __init__.py                                # 包入口 / 版本
    _builtin_modules.py                        # in-tree 模块遍历
    plugin_loader.py                           # ModuleRegistration / entry points

    client/
      __init__.py
      ark_client.py                            # IOCTL 入口 (`ArkClient.call`)
      transport.py                             # CreateFile + DeviceIoControl 包装
      driver_check.py                          # 探测驱动存在 / 版本
      module_query.py                          # 驱动能力 / 模块列表查询

    protocol/
      <module>_protocol.py                     # 每个模块一个: ctypes + 序列化

    modules/
      <module>/__init__.py                     # register(client, capabilities)

    cli/
      main.py                                  # argparse 入口 (myark-cli)

    ui/
      main_window.py                           # Tkinter 三栏主窗口
      layout.py                                # 布局持久化
      search/                                  # 三层搜索实现
      widgets/                                 # 自定义控件
      safety_dialog.py                         # SAFETY Token dialog
```

### 模块注册机制

每个 R3 模块都通过 `register(client, capabilities)` 暴露能力。两种来源:

```
1. in-tree  (myark/modules/<name>/__init__.py)
   -> pkgutil.iter_modules(...)
   -> iter_builtin_registrations(...)

2. entry-point (myark.<name>  via pyproject.toml [project.entry-points])
   -> importlib.metadata.entry_points(group="myark")
```

两种来源都产生 `ModuleRegistration`:

```python
@dataclass
class ModuleRegistration:
    name: str
    cli: list[CliCommand]        # 给 myark-cli 注册的 subcommand
    ui: dict                     # 给 myark-ui 注册的 tab
    describe: () -> ModuleInfo   # myark-cli driver modules 输出
```

### 客户端调用模式

```python
from myark.client.ark_client import ArkClient

with ArkClient() as client:
    info = client.call(
        ioctl_id=0x100,                             # MYARK_IOCTL_PROCESS_ENUM
        request=ProcessEnumRequest(head=64),
        response_type=ProcessEnumResponse,
    )
    for row in info.processes:
        print(row.pid, row.name)
```

`call` 内部:

```
1. request.pack() -> bytes
2. transport.send(ioctl_id, bytes, response_type.size)
3. DeviceIoControl returns output buffer
4. response_type.unpack(output_bytes) -> struct
5. return
```

错误路径:

| 异常 | 触发 |
|---|---|
| `DriverNotInstalledError` | `OpenFile("\\.\MyArkCore")` 返回 `ERROR_FILE_NOT_FOUND` |
| `DriverError(code, status)` | DeviceIoControl 返回 `!STATUS_SUCCESS` |

`DriverError` 把 NTSTATUS 转换为人读字符串 (`driver_check.driver_not_installed_message`)。

---

## IOCTL 协议

### 头文件

```
shared/driver/ioctl_protocol.h
  - IOCTL id 宏 (0x0.. 0x87 范围)
  - quadrant_t 枚举
  - common header (magic / version / quadrant)
  - 每个模块的 request / response 结构 (在 <module>_protocol.h)
```

### IOCTL id 分配

```
0x000-0x0FF  : 核心 5 IOCTL (core_ioctl_handlers)
0x100-0x1FF  : 10_process  (P)
0x200-0x2FF  : 20_handle   (H)
0x300-0x3FF  : 30_keyboard (K)
0x700-0x7FF  : 70_dyndata  (D)
0x710-0x71F  : 71_callback (C)
...
0x870-0x87F  : 87_actions  (A)
```

### 通用请求头 (部分模块)

```c
typedef struct _MYARK_REQUEST_HEADER {
    UINT32 Magic;           // 'M','A','r','k'
    UINT32 Version;         // MYARK_PROTOCOL_VERSION
    UINT32 Quadrant;        // quadrant_t
    UINT32 Flags;           // reserved
} MYARK_REQUEST_HEADER;
```

### 通用响应头 (部分模块)

```c
typedef struct _MYARK_RESPONSE_HEADER {
    UINT32 Magic;
    UINT32 Version;
    UINT32 Status;          // NTSTATUS
    UINT32 PayloadSize;     // bytes after this header
} MYARK_RESPONSE_HEADER;
```

### 协议升级

每个模块描述符都有 `ProtocolMinorVersion`,版本不兼容时 R3 拒绝调用,提示用户在 R3 重新跑 `python -m myark.regen_constants`。

---

## 模块描述符与注册表

每个驱动模块提供一个静态描述符:

```c
// modules/10_process/descriptor.c
#include "descriptor.h"

MYARK_MODULE_REGISTER(process, {
    .id              = MYARK_MODULE_ID_PROCESS,
    .quadrant        = QUADRANT_R3_PREFERRED,
    .ioctl_count     = 7,
    .ioctls          = {
        &MyArkProcessEnumIoctl,
        &MyArkProcessDetailIoctl,
        ...
    },
    .safety_check    = MyArkProcessSafetyCheck,
    .init            = MyArkProcessModuleInit,
    .unload          = MyArkProcessModuleUnload,
});
```

驱动在 `DriverEntry` 中调用 `MyArkModuleRegistryRegisterAll()`,把所有 enabled 模块的描述符合并到 `ioctl_registry::g_ioctls[]`。R3 通过 IOCTL 0x004 (`CapabilityList`) 得到完整描述符表 (每个 entry: ioctl id、模块名、quadrant、最小输入长度、最小输出长度)。

R3 模块注册:

```python
# client/src/myark/modules/process/__init__.py
def register(client, capabilities):
    return ModuleRegistration(
        name="process",
        cli=[...],
        ui={"tab": ...},
        describe=lambda: ModuleInfo(...),
    )
```

---

## 编译期 / 运行时双层门控

### 编译期

```
config/myark_*.h -> MYARK_MODULE_<NAME>  0 或 1
                  -> myark_config.h 强制 #include 这个头
                  -> 编译期条件编译:
                       #if MYARK_MODULE_PROCESS
                       #include "modules/10_process/descriptor.c"
                       #endif
```

每个模块的 `descriptor.h` / `descriptor.c` / `ioctl.c` 全部用 `#if MYARK_MODULE_*` 包裹。`ioctl_registry.c` 包含同样条件,所以禁用模块的代码与数据都不会进 .sys。

### 运行时

```
HKLM\SYSTEM\CurrentControlSet\Services\MyArkCore\Modules\<Name>
    REG_DWORD 0   -- 禁用 (即使编译期已 enabled,运行时也不响应)
    REG_DWORD 1   -- 启用
```

`MyArkDispatchIoctl` 在转发到模块 handler 前查这个键。**默认**为 1 (即编译期 enabled 就是 1)。

> 关键不变量: 编译期 disabled 的模块在 R0 根本不存在,运行时无论 0/1 都不会被调用;运行时 0 disable 是"已编译但不出场"的精细控制。

### 三类使用场景

| 场景 | 做法 |
|---|---|
| 全功能发布 | `full` profile 编译,运行时全开 |
| 简化发行 | `core` profile 编译,功能裁剪进 .sys |
| 现场调查 (临时) | `full` 编译,临时关掉 `process` 模块减少日志 |

---

## 四象限划分

每个 IOCTL 在描述符里标 `quadrant_t`:

```c
typedef enum {
    QUADRANT_R3_PREFERRED = 1,   // R3 即可 (registry / network / process enum)
    QUADRANT_R0_READ,            // R0 读 + R3 展示 (callback / dyndata)
    QUADRANT_R0_REQUIRED,        // 必须 R0 (memory translate / scan / injection)
    QUADRANT_MIXED,              // R3 优先 + R0 备用 (kill / inject / dump)
} quadrant_t;
```

### 实施顺序纪律

```
① QUADRANT_R3_PREFERRED:
   先实现 R3 路径 (winreg / IP Helper / PSAPI),
   不动驱动。

② QUADRANT_R0_READ:
   驱动读 buffer,R3 解析展示。
   R0 仅做 read-only 操作,不修改内核状态。

③ QUADRANT_R0_REQUIRED:
   MmCopyVirtualMemory / ObReferenceObjectByPointer
   等必须 R0 的操作。R3 调用,驱动转发。

④ QUADRANT_MIXED:
   R3 优先 (TerminateProcess / WriteProcessMemory),
   R0 备用 (PspTerminateThreadByPointer / APC injection)。
   R3 失败时降级到 R0。
```

---

## SAFETY_TOKEN

驱动不接受未经校验的变更型 IOCTL。87_actions 全部 7 个动作与 10_process 的
8 个变更型 IOCTL (terminate / suspend / set-ppl / set-integrity /
set-visibility / set-special-flags / dkom / inject) 的输入缓冲都携带
`MYARK_SAFETY_TOKEN` (shared/driver/MyArkSafetyToken.h):

```c
typedef struct _MYARK_SAFETY_TOKEN {
    UINT32 Magic;           // 'MARK'
    UINT32 Pid;             // 目标进程 PID
    UINT32 Operation;       // 操作码 (MYARK_ACTION_OP_* / MYARK_PROCESS_OP_*)
    UINT32 Reserved1;       // 不参与 MAC
    LARGE_INTEGER Timestamp;// FILETIME (100ns),校验窗口 +/-120s
    UINT8  Signature[32];   // HMAC-SHA256(会话密钥, Magic|Pid|Operation|Timestamp)
    UINT8  Reserved2[16];
} MYARK_SAFETY_TOKEN;
```

R0 端 (`dispatch/safety_token.c`):

1. DriverEntry 用 `BCryptGenRandom` 生成 per-boot 32 字节会话密钥 (非分页池,
   不出内核;CNG 初始化失败则驱动拒绝加载, fail-closed)。
2. `IOCTL_MYARK_CORE_GET_SESSION_KEY` (0x805) 把密钥下发给 R3 -- 设备 SDDL
   已限制仅 SYSTEM/Administrators 可打开设备, 非提权进程拿不到密钥。
3. 每次变更型 dispatch: 校验 Magic / Pid / Operation 绑定 -> Timestamp 落在
   +/-120s 窗口 (防重放: 密钥每 boot 轮换) -> 常量时间比较 HMAC-SHA256 摘要。

R3 端 (`myark.client.safety_token`) 提供 FILETIME 时间戳换算与同布局的 20
字节 MAC 消息签名;`SafetyToken.build(session_key)` 产出签名后的 wire token。

> 历史注: v1.0.0 的 Mode A 校验只检查"签名非全零", 密码学校验在 S11.1 补齐;
> process 变更面此前完全无 token, 同批修复。

---

## 错误码与状态映射

| NTSTATUS | 含义 | R3 异常 |
|---|---|---|
| `STATUS_SUCCESS` (0) | 成功 | — |
| `STATUS_INVALID_PARAMETER` (0xC000000D) | SAFETY_TOKEN / 长度 错 | `DriverError` |
| `STATUS_BUFFER_TOO_SMALL` (0xC0000023) | 输出缓冲不足 | `DriverError` |
| `STATUS_NOT_FOUND` (0xC0000225) | 进程 / 对象不存在 | `DriverError` |
| `STATUS_ACCESS_DENIED` (0xC0000022) | R3 caller 权限不足 | `DriverError` |
| `STATUS_PRIVILEGE_NOT_HELD` (0xC0000061) | R0 权限不足 | `DriverError` |
| `STATUS_DEVICE_NOT_CONNECTED` (0xC000023D) | 驱动未启动 | `DriverNotInstalledError` |

R3 错误信息:

```
myark-cli process enum
[ERROR] driver not installed. Run scripts\install.bat inside the VM.

myark-cli memory translate --pid 1234 --addr 0x...
[ERROR] STATUS_INVALID_PARAMETER 0xC000000D: SAFETY_TOKEN mismatch or length error.
```

---

## 生命周期

### 驱动

```
1. DriverEntry
   - WPP init
   - WdfDriverCreate
   - MyArkModuleRegistryRegisterAll()   (条件编译的 module 描述符合并进表)
   - SAFETY_TOKEN epoch 生成
   - 返回 STATUS_SUCCESS

2. DeviceAdd
   - 创建设备对象
   - 创建符号链接 "\\.\MyArkCore"
   - 创建默认 sequential queue

3. DriverUnload (DriverFlag = WdfDriverInitNonPnpDriver)
   - 通知模块 unload (调用 *_ModuleUnload)
   - 删除符号链接
   - WdfDeviceDelete (cascade triggers queue cleanup)
   - MyArkModuleRegistryClear()
```

### 客户端

```
1. myark-cli / myark-ui 启动
2. ArkClient.__init__:
   - OpenDriver("\\\\.\\MyArkCore")
   - 生成 SAFETY_TOKEN
3. 模块加载:
   - iter_builtin_registrations(...)
   - importlib.metadata.entry_points("myark")
4. myark-cli: argparse subparser 装入每个注册模块的 cli
   myark-ui : Tkinter 主窗口 + 模块 Tab
5. 用户调用子命令 / 点 tab:
   - 走 ArkClient.call
   - 调成功后清退出
```

### 持久化

```
~/.myark/layout.json
  - 窗口尺寸
  - 三栏 sash 位置
  - 当前 tab
  - 上次高级搜索过滤
```

原子写入 (temp + rename)。读取时若 JSON 不合法,整个文件当不存在处理,不影响启动。

---

## 依赖与外部调用

### 驱动依赖

| 模块 | 调用的内核 API |
|---|---|
| 10_process | `PsGetCurrentProcess` / `KeStackAttachProcess` |
| 11_thread | `PsGetCurrentThread` / `ETHREAD` 遍历 |
| 12_memory | `MmCopyVirtualMemory` / `ZwQueryVirtualMemory` |
| 22_kmod | `PsLoadedModuleList` 遍历 |
| 31_debug_output | `vDbgPrintEx` / `DbgPrint` 拦截 |
| 70_dyndata | `NtQuerySystemInformation` 同源算法 |
| 71_callback | `Ps*` / `Cm*` / `Ob*` 回调表头遍历 |
| 76_bugcheck | `KeBugCheck` 帧 / `BugCheckCallback` 链 |
| 81_trust | `Authenticode` (`SeLocateProcessImage`, but R3 priority) |

### R3 依赖

```
pypinyin              -- 三层搜索拼音支持
tkinter (stdlib)      -- myark-ui
argparse (stdlib)     -- myark-cli
ctypes (stdlib)       -- IOCTL 打包
win32api / pywin32    -- (optional) 进程 / 模块枚举的 fallback
iphlpapi              -- network 模块 (R3)
winreg                -- registry 模块 (R3)
psapi                 -- module / process 模块 (R3)
```

### 内核签名 / 部署

| 状态 | 部署方式 |
|---|---|
| 开发 (Win11 24H2 / 25H2 VM) | `testsigning on` + `scripts\install_vm.ps1` |
| Release | WHQL 签名 (S10+ 路线) |
| 内部 | 自签 (MakeCert + SignTool) |
