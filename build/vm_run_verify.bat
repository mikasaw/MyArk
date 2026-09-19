@echo off

REM Phase 4/5 - run the S6 regression suite inside the guest and pull the

REM full output back to the host. Exit code mirrors the suite verdict:

REM [VERIFY] OK -> 0, anything else -> 1.

REM Both the guest and the host copy are deleted first, and the verdict

REM reads positive evidence, so a stale log can never fake a pass.

setlocal

set VMRUN=C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe

call "%~dp0vm_env_defaults.bat"

set "GDIR=%MYARK_GDIR%"

set OUT=%~dp0verify_out.txt



del /q "%OUT%" 2>nul



echo [INFO] %MYPY% verify_core.py in guest

rem Every segment of the chain carries its own "< NUL": the redirect only

rem binds to the last command otherwise, and the un-redirected prefix can

rem hang on the fake Session-0 console (observed: a guest cmd stuck forever

rem with the host-side runProgramInGuest blocked behind it).

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% runProgramInGuest "%VMX%" "cmd.exe" "/c cd /d %GDIR% < NUL & del /q verify_out.txt 2>nul < NUL & python -u verify_core.py > verify_out.txt 2>&1 < NUL"



"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromGuestToHost "%VMX%" "%GDIR%\verify_out.txt" "%OUT%"

if not exist "%OUT%" (

    echo [FAIL] could not pull verify_out.txt - guest may be frozen

    echo [NEXT] run build\vm_alive_check.bat

    exit /b 1

)



echo ---- FAIL lines / S6 summary / verdict ----

findstr /c:"[FAIL]" /c:"[S6]" /c:"[VERIFY]" "%OUT%"

echo -------------------------------------------

findstr /c:"[VERIFY]" "%OUT%" >nul

if errorlevel 1 (

    echo [FAIL] pulled log is not a verify run - full log: %OUT%

    exit /b 1

)

findstr /c:"[VERIFY] OK" "%OUT%" >nul

if errorlevel 1 (

    echo [FAIL] regression reported failures - full log: %OUT%

    exit /b 1

)

echo [OK] regression passed - full log: %OUT%

endlocal

