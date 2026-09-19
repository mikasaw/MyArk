@echo off
REM ============================================
REM MyArkCore driver installer (Windows batch)
REM Usage: scripts\install.bat [DriverPath]
REM   DriverPath: full path to MyArkCore.sys
REM                default: C:\MyArkCore.sys
REM
REM Prereqs (must be satisfied inside the VM):
REM   1. Run as Administrator
REM   2. bcdedit /set testsigning on (reboot required)
REM   3. MyArkCore.sys present at the supplied path
REM
REM Side effects:
REM   - Copies .sys to %SystemRoot%\System32\drivers\MyArkCore.sys
REM   - Registers kernel service MyArkCore
REM   - Starts the service
REM
REM Rollback on failure:
REM   - Deletes the service and registry key
REM   - Removes the copied .sys
REM ============================================

setlocal EnableExtensions EnableDelayedExpansion

REM ---- default arguments ----
set "DRIVER_PATH=%~1"
if "%DRIVER_PATH%"=="" set "DRIVER_PATH=C:\MyArkCore.sys"
set "DEST_DIR=%SystemRoot%\System32\drivers"
set "DEST_FILE=%DEST_DIR%\MyArkCore.sys"

echo [install] MyArkCore driver installer
echo [install] target path: %DRIVER_PATH%

REM ---- check Administrator ----
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [install][ERROR] Administrator privileges required. Right-click run as administrator.
    exit /b 1
)

REM ---- check driver file ----
if not exist "%DRIVER_PATH%" (
    echo [install][ERROR] driver not found: %DRIVER_PATH%
    exit /b 1
)

REM ---- check testsigning ----
echo [install] checking testsigning state...
bcdedit /enum "{default}" 2>nul | findstr /C:"testsigning" >nul
if %ERRORLEVEL% NEQ 0 (
    bcdedit /enum "{default}" 2>&1 | findstr /C:"testsigning" >nul
    if !ERRORLEVEL! NEQ 0 (
        echo [install][ERROR] unable to query bcdedit. Confirm testsigning state manually.
        exit /b 1
    )
)
bcdedit /enum "{default}" 2>&1 | findstr /C:"testsigning             Yes" >nul
if %ERRORLEVEL% NEQ 0 (
    echo [install][ERROR] testsigning is not on. Run: bcdedit /set testsigning on ^(then reboot^).
    exit /b 1
)
echo [install] testsigning is on.

REM ---- ensure destination directory ----
if not exist "%DEST_DIR%" (
    echo [install][ERROR] driver directory missing: %DEST_DIR%
    exit /b 1
)

REM ---- remove existing service (best-effort) ----
echo [install] checking for existing service...
sc query MyArkCore >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [install] existing MyArkCore service found, removing.
    sc stop MyArkCore >nul 2>&1
    timeout /t 2 /nobreak >nul
    sc delete MyArkCore >nul 2>&1
    timeout /t 2 /nobreak >nul
)

REM ---- copy driver file ----
echo [install] copying %DRIVER_PATH% -^> %DEST_FILE%
copy /Y "%DRIVER_PATH%" "%DEST_FILE%" >nul
if %ERRORLEVEL% NEQ 0 (
    echo [install][ERROR] copy failed.
    exit /b 1
)

REM ---- create service ----
echo [install] creating service MyArkCore...
sc create MyArkCore type= kernel binPath= system32\drivers\MyArkCore.sys DisplayName= "MyArk ARK Core" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [install][ERROR] sc create MyArkCore failed.
    if exist "%DEST_FILE%" del /F /Q "%DEST_FILE%" >nul 2>&1
    exit /b 1
)

REM ---- start service ----
echo [install] starting service MyArkCore...
sc start MyArkCore >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [install][ERROR] sc start MyArkCore failed.
    sc delete MyArkCore >nul 2>&1
    if exist "%DEST_FILE%" del /F /Q "%DEST_FILE%" >nul 2>&1
    exit /b 1
)

REM ---- verify ----
timeout /t 2 /nobreak >nul
sc query MyArkCore | findstr /C:"STATE" | findstr /C:"RUNNING" >nul
if %ERRORLEVEL% NEQ 0 (
    echo [install][ERROR] MyArkCore did not reach RUNNING state.
    sc delete MyArkCore >nul 2>&1
    if exist "%DEST_FILE%" del /F /Q "%DEST_FILE%" >nul 2>&1
    exit /b 1
)

echo [install] MyArkCore is RUNNING.
echo [install] use scripts\uninstall.bat to remove.
endlocal
