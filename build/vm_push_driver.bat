@echo off
REM Phase 2 - push the built MyArkCore.sys and the regression script into
REM the guest, and require both .sys copies to agree on SHA256 before
REM anything is loaded (AGENTS.md 4).
REM Evidence path is the file channel (vmrun does not forward guest stdout).
setlocal
set REPO=%~dp0..
set VMRUN=C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe
call "%~dp0vm_env_defaults.bat"
set "GDIR=%MYARK_GDIR%"
set SYS=%REPO%\driver\x64\Release\MyArkCore.sys
set VERIFY=%REPO%\scripts\verify_core.py
set TESTSYS=%REPO%\driver\testdrv\x64\Release\MyArkTestDrv.sys
set HOSTHASH=
set GUESTHASH=

if not exist "%SYS%" (
    echo [FAIL] artifact missing: %SYS%
    echo [HINT] run build\build_driver.bat first
    exit /b 1
)
if not exist "%VERIFY%" (
    echo [FAIL] regression script missing: %VERIFY%
    exit /b 1
)

echo [1/4] ensure guest test directory
"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% runProgramInGuest "%VMX%" "cmd.exe" "/c if not exist %GDIR% mkdir %GDIR% < NUL"

echo [2/4] copy verify_core.py first, then .sys
REM The regression script goes first: it never locks, so a script-only
REM update succeeds even while the driver is loaded. A locked .sys still
REM aborts below (real deploy = stop the driver first).
"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromHostToGuest "%VMX%" "%VERIFY%" "%GDIR%\verify_core.py"
if not "%errorlevel%"=="0" (
    echo [FAIL] verify_core.py copy failed ^(vmrun rc=%errorlevel%^)
    exit /b 1
)
REM R3-1b bring-up tool (non-fatal when absent).
set CALIB=%REPO%\scripts\hwid_arp_calib.py
if exist "%CALIB%" (
    "%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromHostToGuest "%VMX%" "%CALIB%" "%GDIR%\hwid_arp_calib.py"
    if not "%errorlevel%"=="0" (
        echo [FAIL] hwid_arp_calib.py copy failed
        exit /b 1
    )
    echo [OK] hwid_arp_calib.py pushed
)
set TDUMP=%REPO%\scripts\hwid_arp_table_dump.py
if exist "%TDUMP%" (
    "%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromHostToGuest "%VMX%" "%TDUMP%" "%GDIR%\hwid_arp_table_dump.py"
    if not "%errorlevel%"=="0" (
        echo [FAIL] hwid_arp_table_dump.py copy failed
        exit /b 1
    )
    echo [OK] hwid_arp_table_dump.py pushed
)
"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromHostToGuest "%VMX%" "%SYS%" "%GDIR%\MyArkCore.sys"
if not "%errorlevel%"=="0" (
    echo [FAIL] .sys copy failed ^(vmrun rc=%errorlevel%^)
    echo [HINT] a loaded driver locks the file - run build\vm_svc_clean.bat first
    exit /b 1
)

REM R2-5 acceptance target (non-fatal when absent: the test driver only
REM matters for the TESTDRV section).
if exist "%TESTSYS%" (
    "%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromHostToGuest "%VMX%" "%TESTSYS%" "%GDIR%\MyArkTestDrv.sys"
    if not "%errorlevel%"=="0" (
        echo [FAIL] MyArkTestDrv.sys copy failed
        exit /b 1
    )
    echo [OK] MyArkTestDrv.sys pushed
)

echo [3/4] host SHA256
for /f "tokens=1" %%h in ('certutil -hashfile "%SYS%" SHA256 ^| findstr /r /c:"^[0-9a-fA-F][0-9a-fA-F ]*$"') do set HOSTHASH=%%h

echo [4/4] guest SHA256 + compare
"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% runProgramInGuest "%VMX%" "cmd.exe" "/c certutil -hashfile %GDIR%\MyArkCore.sys SHA256 > %GDIR%\hash_guest.txt < NUL"
del /q "%~dp0hash_guest.txt" 2>nul
"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromGuestToHost "%VMX%" "%GDIR%\hash_guest.txt" "%~dp0hash_guest.txt"
if not exist "%~dp0hash_guest.txt" (
    echo [FAIL] could not pull guest hash - guest may be frozen
    exit /b 1
)
for /f "tokens=1" %%h in ('findstr /r /c:"^[0-9a-fA-F][0-9a-fA-F ]*$" "%~dp0hash_guest.txt"') do set GUESTHASH=%%h

set HOSTHASH=%HOSTHASH: =%
set GUESTHASH=%GUESTHASH: =%
echo   host  : %HOSTHASH%
echo   guest : %GUESTHASH%
if "%HOSTHASH%"=="" (
    echo [FAIL] empty host hash - certutil output not parsed
    exit /b 1
)
if "%GUESTHASH%"=="" (
    echo [FAIL] empty guest hash - certutil output not parsed
    exit /b 1
)
if /i "%HOSTHASH%"=="%GUESTHASH%" (
    echo [OK] SHA256 match - safe to load
    exit /b 0
)
echo [FAIL] SHA256 MISMATCH - do NOT load this artifact
exit /b 1
endlocal
