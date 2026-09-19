@echo off

REM Generic guest command runner with output capture over the file channel.

REM

REM The guest command line is read from %~dp0guest_cmd.txt (a file avoids the

REM bash->cmd->bat quoting maze entirely). Its output is redirected into a

REM guest file that is pulled back and printed here, because vmrun does not

REM forward guest stdout. "< NUL" is appended for the fake Session-0 console.

setlocal enabledelayedexpansion

set VMRUN=C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe

call "%~dp0vm_env_defaults.bat"

set CMDDIR=%~dp0

set CMDFILE=%CMDDIR%guest_cmd.txt

set GLOG=C:\Users\Public\myark_exec_out.txt

set OUT=%CMDDIR%exec_out.txt



if not exist "%CMDFILE%" (

    echo [FAIL] missing %CMDFILE% - put the guest command line there first

    exit /b 1

)

set /p GCMD=<"%CMDFILE%"

if not defined GCMD (

    echo [FAIL] %CMDFILE% is empty

    exit /b 1

)

rem Delayed expansion keeps an "&" inside the reported command from being

rem parsed as a host-side command separator.

echo [INFO] guest command: !GCMD!



"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% runProgramInGuest "%VMX%" "cmd.exe" "/c del /q %GLOG% 2>nul < NUL & %GCMD% > %GLOG% 2>&1 < NUL"



del /q "%OUT%" 2>nul

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromGuestToHost "%VMX%" "%GLOG%" "%OUT%"

if not exist "%OUT%" (

    echo [FAIL] guest command produced no output file - exec channel or command broken

    echo [NEXT] run build\vm_alive_check.bat

    exit /b 1

)

echo ---- guest output ----

type "%OUT%"

echo ----------------------

endlocal

