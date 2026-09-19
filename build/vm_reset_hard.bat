@echo off
REM Phase 1 - hard reset, then wait until the guest REALLY answers exec.
REM A "running" Tools state right after reset is not proof (boot still in
REM progress), and vmrun rc=0 is not proof either: the verdict is a
REM host-generated random token echoed back through the file channel
REM (vmrun does not forward guest stdout).
REM %VPARGS% matters for encrypted guests (vTPM partial encryption):
REM without -vp the reset fails with "operation requires a password" and
REM the liveness poll below trivially passes against the never-rebooted
REM guest (2026-09-15 observed on the Win11 guest).
setlocal
set VMRUN=C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe
call "%~dp0vm_env_defaults.bat"
set PROBE=%~dp0alive_probe.txt

echo [INFO] vmrun reset hard
"%VMRUN%" -T ws %VPARGS% reset "%VMX%" hard

echo [INFO] polling guest liveness (token echo + pull)
for /l %%i in (1,1,40) do (
    ping -n 16 127.0.0.1 >nul
    call :poll
    if not errorlevel 1 (
        echo [OK] guest ready after %%i polls
        exit /b 0
    )
)
echo [FAIL] guest not ready after 40 polls - try build\vm_alive_check.bat
exit /b 1

:poll
set TOKEN=MYARK_ALIVE_%RANDOM%%RANDOM%
"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% runProgramInGuest "%VMX%" "cmd.exe" "/c echo %TOKEN% > %GPROBE% < NUL" >nul 2>&1
del /q "%PROBE%" 2>nul
"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromGuestToHost "%VMX%" "%GPROBE%" "%PROBE%" >nul 2>&1
if not exist "%PROBE%" exit /b 1
findstr /c:"%TOKEN%" "%PROBE%" >nul
exit /b %errorlevel%
