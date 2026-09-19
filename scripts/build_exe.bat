@echo off
REM build_exe.bat: standalone exe build for myark-cli / myark-ui (ASCII only)
REM
REM Wraps PyInstaller. scripts\build.bat remains the DRIVER MSBuild wrapper;
REM this file only builds the R3 Python client exes.
REM
REM Usage:
REM   build_exe              Build myark-cli.exe + myark-ui.exe into client\dist\
REM   build_exe clean        Clean client\dist\ + client\build\ + *.spec
REM   build_exe help         Show help
REM
REM Output:
REM   client\dist\myark-cli\myark-cli.exe  (standalone console exe)
REM   client\dist\myark-ui\myark-ui.exe    (standalone Tkinter GUI exe)
REM
REM Entry points live in client\pyinstaller\*_launch.py and use ABSOLUTE
REM imports because PyInstaller runs its entry script as a top-level module
REM (relative imports inside myark.* would otherwise break at runtime).

setlocal enabledelayedexpansion
set SUBCMD=%~1
if "%SUBCMD%"=="" set SUBCMD=build
if "%SUBCMD%"=="help" goto :show_help
if "%SUBCMD%"=="/?" goto :show_help
if "%SUBCMD%"=="clean" goto :do_clean
if /I not "%SUBCMD%"=="build" (
    echo [ERROR] unknown subcommand "%SUBCMD%". Use build / clean / help.
    exit /b 1
)

pushd "%~dp0..\client"
if errorlevel 1 (
    echo [ERROR] Cannot cd to client directory
    exit /b 1
)

REM PyInstaller via python -m to avoid PATH issues
python -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo [INFO] PyInstaller not found, installing...
    pip install pyinstaller
    if errorlevel 1 (
        popd
        echo [ERROR] Failed to install PyInstaller
        exit /b 1
    )
)

REM Clean old artifacts for a fresh build
if exist dist rmdir /s /q dist
if exist build rmdir /s /q build

echo [INFO] Building myark-cli.exe ...
python -m PyInstaller --noconfirm --clean --name myark-cli ^
    --paths src ^
    --console ^
    --distpath dist ^
    --workpath build ^
    --collect-submodules myark ^
    pyinstaller\cli_launch.py
if errorlevel 1 (
    popd
    echo [ERROR] myark-cli build failed
    exit /b 1
)

echo [INFO] Building myark-ui.exe ...
python -m PyInstaller --noconfirm --clean --name myark-ui ^
    --paths src ^
    --windowed ^
    --distpath dist ^
    --workpath build ^
    --collect-submodules myark ^
    pyinstaller\ui_launch.py
if errorlevel 1 (
    popd
    echo [ERROR] myark-ui build failed
    exit /b 1
)

popd

echo.
echo [OK] Build complete
echo [Output]:
dir /b "%~dp0..\client\dist" 2>nul
exit /b 0

:do_clean
    pushd "%~dp0..\client" >nul 2>&1
    if exist dist rmdir /s /q dist
    if exist build rmdir /s /q build
    if exist myark-cli.spec del /q myark-cli.spec
    if exist myark-ui.spec del /q myark-ui.spec
    popd
    echo [OK] Cleaned
    exit /b 0

:show_help
    echo Usage: build_exe [subcommand]
    echo.
    echo Subcommands:
    echo   build              Build myark-cli + myark-ui standalone exes (default)
    echo   clean              Clean dist + build + generated spec files
    echo   help               Show this help
    echo.
    echo Output:
    echo   client\dist\myark-cli\myark-cli.exe
    echo   client\dist\myark-ui\myark-ui.exe
    exit /b 0
