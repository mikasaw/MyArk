@echo off

REM Phase 3 - start the driver and require STATE 4 RUNNING.

REM A non-running state is a real result: the failure is in the pulled log,

REM and debugging continues with windbg-mcp instead of guessing.

REM Evidence path is the file channel (vmrun does not forward guest stdout).

setlocal

set VMRUN=C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe

call "%~dp0vm_env_defaults.bat"

set "GDIR=%MYARK_GDIR%"

set LOG=%GDIR%\svc_start.txt

set OUT=%~dp0svc_start_out.txt



echo [1/2] sc start + query

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% runProgramInGuest "%VMX%" "cmd.exe" "/c del /q %LOG% 2>nul < NUL & sc start MyArkCore >> %LOG% 2>&1 < NUL & sc query MyArkCore >> %LOG% 2>&1 < NUL"



echo [2/2] pull + assert RUNNING

del /q "%OUT%" 2>nul

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromGuestToHost "%VMX%" "%LOG%" "%OUT%"

if not exist "%OUT%" (

    echo [FAIL] could not pull svc_start.txt

    echo [NEXT] run build\vm_alive_check.bat

    exit /b 1

)

type "%OUT%"

findstr /c:"RUNNING" "%OUT%" >nul

if errorlevel 1 (

    echo [FAIL] MyArkCore is not RUNNING - see %OUT%

    exit /b 1

)

echo [OK] MyArkCore RUNNING

endlocal

