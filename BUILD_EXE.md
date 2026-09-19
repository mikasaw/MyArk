## Standalone exe build (PyInstaller)

默认 `uv tool install` 生成 `~/.local/bin/myark-*.exe` (wrapper, 需 .venv 环境)。

如果需要**独立 exe** (可复制到其他机器, 含 Python runtime):

```cmd
scripts\build_exe.bat                  REM Build myark-cli + myark-ui 独立 exe
scripts\build_exe.bat clean            REM 清理 dist/ + build/ + *.spec
```

产物:
- `client\dist\myark-cli\myark-cli.exe` (独立控制台 exe)
- `client\dist\myark-ui\myark-ui.exe` (独立 GUI exe)

依赖: PyInstaller (脚本自动 `pip install`)

注意:
- PyInstaller 入口是 `client\pyinstaller\cli_launch.py` / `ui_launch.py`,内部用**绝对
  import** 引入 `myark.*`。直接拿 `src/myark/...` 文件当入口会因为 "attempted relative
  import with no known parent package" 启动崩溃 —— PyInstaller 把入口脚本当顶层模块跑。
- `--collect-submodules myark` 是必须的:`_builtin_modules.py` 用 `pkgutil.iter_modules`
  动态发现内置插件,静态分析看不到这些 import。
- 驱动侧构建不受影响,仍走 `scripts\make.bat` → `scripts\build.bat`(MSBuild)。

重新打包时机:
- `uv tool install` 的 wrapper 启动器运行时调 `.venv` Python,源码改动 wrapper 自动跟
  着变,**无需重做**。
- PyInstaller 独立 exe 打包了 Python runtime 的**代码快照**,`src/myark/**` 每次改动后
  必须重跑 `scripts\build_exe.bat`,否则用户拿到的独立 exe 仍是旧代码(S10.7 教训:
  S10.5 ActionsPanel + S10.6 R3ModulePanel 落地后未重打,旧 exe 时间戳落后 UI commit)。
