@echo off
REM Win11 guest (22631) elevated deploy + detached regression.
REM Why schtasks: the Win11 Tools exec channel degrades (runProgramInGuest
REM hangs/fails), and sc against a kernel driver needs an elevated token
REM anyway -- both run via schtasks /rl highest, evidence via the file
REM channel only (vmrun does not forward guest stdout).
REM Prereq: build\vm_push_driver.bat already ran against this guest
REM (fresh boot or stopped driver), SHA256 verified.
setlocal
set REPO=%~dp0..
set VMRUN=C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe
call "%~dp0vm_env_defaults.bat"
set "GDIR=%MYARK_GDIR%"
set PUB=C:\Users\Public

del /q "%~dp0elevated_out.txt" 2>nul
del /q "%~dp0verify_done.txt" 2>nul
del /q "%~dp0verify_out11.txt" 2>nul

echo [1/5] push helper cmd files (elevated deploy + detached verify runner)
"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromHostToGuest "%VMX%" "%REPO%\build\elevated_deploy.cmd" "%GDIR%\elevated_deploy.cmd"
if not "%errorlevel%"=="0" (
    echo [FAIL] elevated_deploy.cmd copy failed
    exit /b 1
)
"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromHostToGuest "%VMX%" "%REPO%\build\run_verify_guest.cmd" "%GDIR%\run_verify_guest.cmd"
if not "%errorlevel%"=="0" (
    echo [FAIL] run_verify_guest.cmd copy failed
    exit /b 1
)

echo [2/5] elevated service create/start via schtasks
REM Every chain segment carries its own "< NUL" (Session-0 console rule).
"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% runProgramInGuest "%VMX%" "cmd.exe" "/c schtasks /create /tn MyArkDeploy /tr %GDIR%\elevated_deploy.cmd /sc once /st 23:58 /rl highest /f > %PUB%\sch.txt 2>&1 < NUL & schtasks /run /tn MyArkDeploy >> %PUB%\sch.txt 2>&1 < NUL"

set /a TRIES=0
:elev_poll
ping -n 4 127.0.0.1 >nul
"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromGuestToHost "%VMX%" "%PUB%\elevated_out.txt" "%~dp0elevated_out.txt" >nul 2>&1
set /a TRIES+=1
if not exist "%~dp0elevated_out.txt" (
    if %TRIES% LSS 20 goto elev_poll
    echo [FAIL] elevated deploy produced no output file
    exit /b 1
)
findstr /c:"ELEVATED_DONE" "%~dp0elevated_out.txt" >nul
if errorlevel 1 (
    if %TRIES% LSS 20 goto elev_poll
    echo [FAIL] elevated deploy incomplete - see build\elevated_out.txt
    exit /b 1
)
findstr /c:"RUNNING" /c:"4  RUNNING" "%~dp0elevated_out.txt" >nul
if errorlevel 1 (
    echo [FAIL] MyArkCore not RUNNING - see build\elevated_out.txt
    type "%~dp0elevated_out.txt" | findstr /i "sc start failed 1058 1073 5"
    exit /b 1
)
echo [OK] MyArkCore RUNNING

echo [3/5] detached verify run via schtasks
REM The done marker must echo this run's random token (pushed next to the
REM runner) -- a stale marker from a previous run would otherwise pass the
REM poll when the flaky exec channel silently drops the task start.
set "MYARK_VTOKEN=VT_%RANDOM%%RANDOM%"
> "%~dp0verify_token_host.txt" echo %MYARK_VTOKEN%
"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromHostToGuest "%VMX%" "%~dp0verify_token_host.txt" "%GDIR%\verify_token.txt"
if not "%errorlevel%"=="0" (
    echo [FAIL] token copy
    exit /b 1
)
"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% runProgramInGuest "%VMX%" "cmd.exe" "/c schtasks /create /tn MyArkVerify /tr %GDIR%\run_verify_guest.cmd /sc once /st 23:59 /rl highest /f > %PUB%\sch.txt 2>&1 < NUL & schtasks /run /tn MyArkVerify >> %PUB%\sch.txt 2>&1 < NUL"

echo [4/5] poll guest verify_done.txt (token %MYARK_VTOKEN%)
set /a TRIES=0
:verify_poll
ping -n 11 127.0.0.1 >nul
del /q "%~dp0verify_done.txt" 2>nul
"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromGuestToHost "%VMX%" "%GDIR%\verify_done.txt" "%~dp0verify_done.txt" >nul 2>&1
set /a TRIES+=1
if not exist "%~dp0verify_done.txt" (
    if %TRIES% LSS 30 goto verify_poll
    echo [FAIL] verify did not finish - see build\vm_alive_check.bat
    exit /b 1
)
findstr /c:"VERIFY_EXIT 0 TOKEN=%MYARK_VTOKEN%" "%~dp0verify_done.txt" >nul
if errorlevel 1 (
    echo [FAIL] verify exited nonzero or stale marker - see build\verify_out11.txt
    goto pull_log
)

echo [5/5] pull verdict
:pull_log
"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromGuestToHost "%VMX%" "%GDIR%\verify_out.txt" "%~dp0verify_out11.txt"
if not exist "%~dp0verify_out11.txt" (
    echo [FAIL] could not pull verify_out.txt
    exit /b 1
)
findstr /c:"[FAIL]" /c:"[S6]" /c:"[VERIFY]" "%~dp0verify_out11.txt"
findstr /c:"[VERIFY] OK" "%~dp0verify_out11.txt" >nul
if errorlevel 1 (
    echo [FAIL] regression reported failures - full log: %~dp0verify_out11.txt
    exit /b 1
)
echo [OK] regression passed - full log: %~dp0verify_out11.txt
endlocal
