@echo off

REM Crash forensics preflight: pushes guest_crash_probe.cmd, runs it, pulls

REM the report. Used to answer "did the guest bugcheck?" with evidence

REM instead of guessing (boot time + minidumps + BugCheck events + service

REM state all come from the guest itself).

setlocal

set VMRUN=C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe

call "%~dp0vm_env_defaults.bat"

set "GDIR=%MYARK_GDIR%"

set PROBE=%~dp0guest_crash_probe.cmd

set OUT=%~dp0crash_report.txt



if not exist "%PROBE%" (

    echo [FAIL] probe not found: %PROBE%

    exit /b 1

)



echo [1/3] ensure directory + push probe

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% runProgramInGuest "%VMX%" "cmd.exe" "/c if not exist %GDIR% mkdir %GDIR% < NUL"

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromHostToGuest "%VMX%" "%PROBE%" "%GDIR%\guest_crash_probe.cmd"

if not "%errorlevel%"=="0" (

    echo [FAIL] push failed - run build\vm_alive_check.bat

    exit /b 1

)



echo [2/3] run probe

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% runProgramInGuest "%VMX%" "cmd.exe" "/c %GDIR%\guest_crash_probe.cmd < NUL"



echo [3/3] pull report

del /q "%OUT%" 2>nul

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromGuestToHost "%VMX%" "%GDIR%\crash_report.txt" "%OUT%"

if not exist "%OUT%" (

    echo [FAIL] could not pull crash_report.txt - run build\vm_alive_check.bat

    exit /b 1

)

if exist "%OUT%" (

    echo ---- crash report ----

    type "%OUT%"

    echo ----------------------

)

endlocal

