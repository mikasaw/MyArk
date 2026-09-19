@echo off

REM Phase 4/5 - run the S6 regression suite inside the guest and pull the
REM full output back to the host. Exit code mirrors the suite verdict:
REM [VERIFY] OK -> 0, anything else -> 1.
REM Stale-evidence discipline (2026-09-19 lessons):
REM  - vmrun exec can SILENTLY NO-OP on a degraded channel; a pull then
REM    returns the PREVIOUS run's files as "success" (vmrun preserves
REM    guest mtimes, so timestamps cannot be trusted either).
REM  - Countermeasure: the host mints a random token, the guest chain
REM    echoes it into BOTH artifacts before/after the run, and the host
REM    only accepts evidence carrying the exact token (same rule as
REM    vm_alive_check.bat).
REM  - Large-file pulls (30KB+) can fail while tiny pulls succeed: the
REM    tiny verdict file is the fallback channel, with a retry poll.

setlocal

set VMRUN=C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe

call "%~dp0vm_env_defaults.bat"

set "GDIR=%MYARK_GDIR%"

set OUT=%~dp0verify_out.txt
set VVERDICT=%~dp0verify_verdict.txt
set VT=%RANDOM%%RANDOM%

del /q "%OUT%" 2>nul
del /q "%VVERDICT%" 2>nul

echo [INFO] %MYPY% verify_core.py in guest (token %VT%)

rem Every segment of the chain carries its own "< NUL": the redirect only
rem binds to the last command otherwise, and the un-redirected prefix can
rem hang on the fake Session-0 console.
rem Chain: wipe artifacts -> token into OUT -> suite appends -> verdict
rem lines + token into VVERDICT.

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% runProgramInGuest "%VMX%" "cmd.exe" "/c cd /d %GDIR% < NUL & del /q verify_out.txt verify_verdict.txt 2>nul < NUL & echo TOKEN=%VT%> verify_out.txt < NUL & python -u verify_core.py >> verify_out.txt 2>&1 < NUL & findstr /c:""[VERIFY]"" verify_out.txt > verify_verdict.txt 2>&1 < NUL & echo TOKEN=%VT%>> verify_verdict.txt < NUL"

set /a VPULL=0

:out_poll

ping -n 3 127.0.0.1 >nul

set TOKOK=0

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromGuestToHost "%VMX%" "%GDIR%\verify_out.txt" "%OUT%" >nul 2>&1

rem errorlevel is polluted by the failed vmrun above (signed -1 is not
rem visible to "if errorlevel 1" -- AGENTS.md §1), so gate on a flag var.

if exist "%OUT%" findstr /c:"TOKEN=%VT%" "%OUT%" >nul && set TOKOK=1

if "%TOKOK%"=="1" goto out_got

set /a VPULL+=1

if %VPULL% LSS 10 goto out_poll

goto small_channel

:out_got

echo ---- FAIL lines / S6 summary / verdict ----

findstr /c:"[FAIL]" /c:"[S6]" /c:"[VERIFY]" "%OUT%"

echo -------------------------------------------

findstr /c:"[VERIFY] OK" "%OUT%" >nul

if errorlevel 1 (

    echo [FAIL] regression reported failures - full log: %OUT%

    exit /b 1

)

echo [OK] regression passed - full log: %OUT%

endlocal

exit /b 0

:small_channel

echo [INFO] big-log token missing - using small-file channel

set /a VPULL=0

:verdict_poll

ping -n 3 127.0.0.1 >nul

set TOKOK=0

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromGuestToHost "%VMX%" "%GDIR%\verify_verdict.txt" "%VVERDICT%" >nul 2>&1

rem Same signed-errorlevel trap as above: flag var, not errorlevel.

if exist "%VVERDICT%" findstr /c:"TOKEN=%VT%" "%VVERDICT%" >nul && set TOKOK=1

if "%TOKOK%"=="1" goto verdict_got

set /a VPULL+=1

if %VPULL% LSS 10 goto verdict_poll

echo [FAIL] no fresh tokened verdict from either channel - guest may be degraded

echo [NEXT] run build\vm_alive_check.bat then build\run_diag.cmd

exit /b 1

:verdict_got

findstr /c:"[VERIFY] OK" "%VVERDICT%" >nul

if errorlevel 1 (

    echo [FAIL] regression reported failures - guest verdict: %VVERDICT%

    type "%VVERDICT%"

    exit /b 1

)

echo [OK] regression passed - verdict via small-file channel ^(big log lives in guest: %GDIR%\verify_out.txt^)

type "%VVERDICT%"

endlocal

exit /b 0

