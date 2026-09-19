@echo off
REM make.bat: MyArk build script (ASCII only per project rules)
REM Usage:
REM   make full              Build full profile (default)
REM   make mini              Build mini profile
REM   make process-only      Build process-only profile
REM   make core              Build core profile
REM   make safety-audit      Build safety-audit profile
REM   make clean             Clean build artifacts
REM   make help              Show help

setlocal enabledelayedexpansion
set PROFILE=%1
if "%PROFILE%"=="" set PROFILE=full
if "%PROFILE%"=="help" goto :show_help
if "%PROFILE%"=="/?" goto :show_help

if "%PROFILE%"=="clean" goto :do_clean

REM Check MSBuild (Insiders VS 2026)
set MSBUILD=C:\Program Files\Microsoft Visual Studio\18\Insiders\MSBuild\Current\Bin\MSBuild.exe
if not exist "%MSBUILD%" (
    echo [ERROR] MSBuild not found: %MSBUILD%
    echo [HINT] Install Insiders VS 2026
    exit /b 1
)

REM Check WDK 10.0.28000
set WDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.28000.0\km\x64
if not exist "%WDK_LIB%" (
    echo [ERROR] WDK 10.0.28000 lib not found: %WDK_LIB%
    echo [HINT] Install WDK 10.0.28000
    exit /b 1
)

REM Build
echo [INFO] Building MyArkCore.sys with profile=%PROFILE%
"%MSBUILD%" driver\MyArkCore.vcxproj /p:Configuration=Release /p:Platform=x64 /p:MyArkProfile=%PROFILE% /m /v
if errorlevel 1 (
    echo [ERROR] Build failed
    exit /b 1
)

echo [OK] Built driver\x64\Release\MyArkCore.sys
echo [INFO] Profile: %PROFILE%
dir /b driver\x64\Release\MyArkCore.sys
exit /b 0

:do_clean
    echo [INFO] Cleaning build artifacts
    if exist driver\x64 rmdir /s /q driver\x64
    if exist driver\obj rmdir /s /q driver\obj
    exit /b 0

:show_help
    echo Usage: make [profile]
    echo.
    echo Profiles:
    echo   full              All 30 modules
    echo   mini              Minimal set
    echo   process-only      Process modules
    echo   core              Core modules
    echo   safety-audit      Safety audit
    echo.
    echo Special:
    echo   clean             Clean build artifacts
    echo   help              Show help
    exit /b 0