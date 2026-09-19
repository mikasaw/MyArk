@echo off
REM ============================================
REM MyArkCore driver uninstaller (Windows batch)
REM Usage: scripts\uninstall.bat
REM
REM Removes:
REM   - MyArkCore kernel service (sc stop + sc delete)
REM   - Copied .sys at %SystemRoot%\System32\drivers\MyArkCore.sys
REM   - Registry key HKLM\SYSTEM\CurrentControlSet\Services\MyArkCore
REM     (and any Modules subkey used at runtime)
REM
REM Idempotent: safe to re-run; missing service / file / key is OK.
REM ============================================

setlocal EnableExtensions EnableDelayedExpansion

set "DEST_FILE=%SystemRoot%\System32\drivers\MyArkCore.sys"
set "SVC_KEY=HKLM\SYSTEM\CurrentControlSet\Services\MyArkCore"
set "MOD_KEY=%SVC_KEY%\Modules"

echo [uninstall] MyArkCore driver uninstaller

REM ---- Admin required for service + registry operations ----
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [uninstall][ERROR] Administrator privileges required.
    exit /b 1
)

REM ---- stop + delete service ----
sc query MyArkCore >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [uninstall] stopping MyArkCore service...
    sc stop MyArkCore >nul 2>&1
    if %ERRORLEVEL% NEQ 0 (
        echo [uninstall][WARN] sc stop returned non-zero (continuing).
    )
    timeout /t 2 /nobreak >nul
    echo [uninstall] deleting MyArkCore service...
    sc delete MyArkCore >nul 2>&1
    if %ERRORLEVEL% NEQ 0 (
        echo [uninstall][WARN] sc delete returned non-zero (continuing).
    )
    timeout /t 2 /nobreak >nul
) else (
    echo [uninstall] service MyArkCore not registered.
)

REM ---- delete .sys copy ----
if exist "%DEST_FILE%" (
    echo [uninstall] removing %DEST_FILE%
    del /F /Q "%DEST_FILE%" >nul 2>&1
    if %ERRORLEVEL% NEQ 0 (
        echo [uninstall][WARN] failed to delete .sys (file may be in use).
    )
) else (
    echo [uninstall] copied .sys not present.
)

REM ---- clean registry ----
reg query "%SVC_KEY%" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [uninstall] removing registry key %SVC_KEY%
    reg delete "%SVC_KEY%" /F >nul 2>&1
    if %ERRORLEVEL% NEQ 0 (
        echo [uninstall][WARN] failed to delete registry key.
    )
) else (
    echo [uninstall] registry key %SVC_KEY% not present.
)

REM ---- ensure no stragglers ----
sc query MyArkCore >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [uninstall][WARN] service still reported. Retry or reboot.
    exit /b 2
)

if exist "%DEST_FILE%" (
    echo [uninstall][WARN] file still present: %DEST_FILE%
    exit /b 2
)

reg query "%SVC_KEY%" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [uninstall][WARN] registry key still present: %SVC_KEY%
    exit /b 2
)

echo [uninstall] MyArkCore removed.
endlocal
