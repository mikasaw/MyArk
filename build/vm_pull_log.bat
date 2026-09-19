@echo off

REM Phase 6 - pull one file from the guest test directory to build\ and

REM print it. Usage: build\vm_pull_log.bat <file name inside myark-test>

REM The host copy is deleted first and must exist afterwards, so a stale

REM file can never fake a successful pull (vmrun's own exit code is -1 on

REM failure, which "if errorlevel 1" cannot see).

setlocal

set VMRUN=C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe

call "%~dp0vm_env_defaults.bat"

set "GDIR=%MYARK_GDIR%"



if "%~1"=="" (

    echo [FAIL] usage: build\vm_pull_log.bat ^<file name inside myark-test^>

    exit /b 1

)



rem Source is %GDIR%\<name> by default; a name containing ":" (e.g.
rem "C:\Users\Public\x.txt") is treated as an absolute guest path so any
rem guest file can be pulled without a per-file wrapper.

set "GSRC=%GDIR%\%~1"

set "HNAME=%~nx1"

echo %~1 | findstr /c:":" >nul

if not errorlevel 1 (

    set "GSRC=%~1"

    set "HNAME=%~nx1"

)



del /q "%~dp0%HNAME%" 2>nul

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromGuestToHost "%VMX%" "%GSRC%" "%~dp0%HNAME%"

if not exist "%~dp0%HNAME%" (

    echo [FAIL] pull failed: %GSRC%  ^(vmrun rc=%errorlevel%^)

    exit /b 1

)

echo ---- %HNAME% ----

type "%~dp0%HNAME%"

echo ----------------

endlocal

