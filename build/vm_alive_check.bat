@echo off

REM Liveness triage. Run BEFORE any reset (AGENTS.md 3): a "Tools not

REM running" answer may only mean Tools lost its channel; the exec probe is

REM the judge. If the probe fails, try a KDNET break-in via windbg-mcp

REM before declaring the guest frozen.

REM

REM Two hard-won facts shape this script:

REM   * vmrun does NOT forward guest stdout to the host pipe - all evidence

REM     must come back through the file channel (write in guest, pull).

REM   * vmrun returns rc=0 even when nothing executed, so the verdict is a

REM     host-generated random token echoed back by the guest. A stale file

REM     from an earlier boot carries an old token and cannot fake a pass.

REM   * The guest command keeps "< NUL" (fake Session-0 console) and writes

REM     to the Desktop, which always exists even after a snapshot rollback.

setlocal

set VMRUN=C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe

call "%~dp0vm_env_defaults.bat"

set PROBE=%~dp0alive_probe.txt

set TOKEN=MYARK_ALIVE_%RANDOM%%RANDOM%



echo [1/3] checkToolsState:

"%VMRUN%" -T ws %VPARGS% checkToolsState "%VMX%"



echo [2/3] exec probe (token %TOKEN%)

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% runProgramInGuest "%VMX%" "cmd.exe" "/c echo %TOKEN% > %GPROBE% < NUL"



echo [3/3] pull probe result

del /q "%PROBE%" 2>nul

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromGuestToHost "%VMX%" "%GPROBE%" "%PROBE%"

if not exist "%PROBE%" (

    echo [WARN] exec probe FAILED - result file could not be pulled

    echo [NEXT] try windbg-mcp break-in on KDNET; if that fails too:

    echo [NEXT] run build\vm_reset_hard.bat  - only recovery allowed

    exit /b 1

)

findstr /c:"%TOKEN%" "%PROBE%" >nul

if errorlevel 1 (

    echo [WARN] exec probe STALE - guest did not echo this run's token

    type "%PROBE%"

    echo [NEXT] try windbg-mcp break-in on KDNET; if that fails too:

    echo [NEXT] run build\vm_reset_hard.bat  - only recovery allowed

    exit /b 1

)

echo [OK] guest alive ^(token echoed back^)

endlocal

