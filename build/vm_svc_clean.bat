@echo off

REM Phase 3 - stop and delete the driver service. HEALTHY GUEST ONLY: this

REM is the normal redeploy step (the kernel locks the .sys file while the

REM driver is running). If the guest is frozen, do NOT run this - recover

REM with build\vm_reset_hard.bat instead (AGENTS.md 3).

REM Evidence: after the delete, sc query must answer 1060 (service absent).

REM An absent service already answers 1060, so this is idempotent.

setlocal

set VMRUN=C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe

call "%~dp0vm_env_defaults.bat"

set "GDIR=%MYARK_GDIR%"

set LOG=%GDIR%\svc_clean.txt

set OUT=%~dp0svc_clean_out.txt



echo [1/2] sc stop + sc delete + sc query

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% runProgramInGuest "%VMX%" "cmd.exe" "/c del /q %LOG% 2>nul < NUL & sc stop MyArkCore >> %LOG% 2>&1 < NUL & ping -n 5 127.0.0.1 >nul & sc delete MyArkCore >> %LOG% 2>&1 < NUL & sc query MyArkCore >> %LOG% 2>&1 < NUL"



echo [2/2] pull + assert absent

del /q "%OUT%" 2>nul

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromGuestToHost "%VMX%" "%LOG%" "%OUT%"

if not exist "%OUT%" (

    echo [FAIL] could not pull svc_clean.txt

    echo [NEXT] run build\vm_alive_check.bat

    exit /b 1

)

type "%OUT%"

findstr /c:"1060" "%OUT%" >nul

if errorlevel 1 (

    echo [FAIL] service still present after clean - see %OUT%

    exit /b 1

)

echo [OK] service removed - .sys file is now unlocked

endlocal

