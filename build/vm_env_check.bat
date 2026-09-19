@echo off

REM Environment preflight: pushes guest_env_probe.cmd, runs it, and asserts

REM every guest-side prerequisite of the driver test loop.

REM

REM Evidence path is the file channel: the probe writes

REM %GDIR%\env_report.txt and the host pulls it (vmrun does not forward

REM guest stdout). Localized text is never parsed - only TOKEN=VALUE lines.

setlocal

set REPO=%~dp0..

set VMRUN=C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe

call "%~dp0vm_env_defaults.bat"

set "GDIR=%MYARK_GDIR%"

set PROBE=%~dp0guest_env_probe.cmd

set OUT=%~dp0env_check_out.txt

set SYS=%REPO%\driver\x64\Release\MyArkCore.sys

set HOSTHASH=

set GUESTHASH=

set RC=0



if not exist "%PROBE%" (

    echo [FAIL] probe not found: %PROBE%

    exit /b 1

)



echo [1/5] ensure guest test directory

rem A snapshot rollback can leave the disk without the test directory; the

rem push below would then fail before the probe ever runs.

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% runProgramInGuest "%VMX%" "cmd.exe" "/c if not exist %GDIR% mkdir %GDIR% < NUL"



echo [2/5] push guest_env_probe.cmd

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromHostToGuest "%VMX%" "%PROBE%" "%GDIR%\guest_env_probe.cmd"

if not "%errorlevel%"=="0" (

    echo [FAIL] push failed ^(vmrun rc=%errorlevel%^)

    echo [NEXT] run build\vm_alive_check.bat

    exit /b 1

)



echo [3/5] run probe in guest

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% runProgramInGuest "%VMX%" "cmd.exe" "/c %GDIR%\guest_env_probe.cmd < NUL"



echo [4/5] pull env_report.txt

del /q "%OUT%" 2>nul

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromGuestToHost "%VMX%" "%GDIR%\env_report.txt" "%OUT%"

if not exist "%OUT%" (

    echo [FAIL] could not pull env_report.txt

    echo [NEXT] run build\vm_alive_check.bat

    exit /b 1

)

findstr /c:"MYARK_ENV_END" "%OUT%" >nul

if errorlevel 1 (

    echo [FAIL] probe did not complete - report: %OUT%

    type "%OUT%"

    exit /b 1

)



echo [5/5] asserting prerequisites

type "%OUT%" | findstr /c:"="



call :require "TESTSIGNING=YES"  "testsigning enabled"

call :require "CERT_ROOT=YES"    "WDK test cert in Root"

call :require "CERT_TP=YES"      "WDK test cert in TrustedPublisher"

call :require "PYTHON=YES"       "python on PATH"

call :require "GDIR=YES"         "guest test directory exists"

call :require "VERIFY_PRESENT=YES" "verify_core.py deployed"

rem KDNET isolation is informational: the regression does not need the

rem debugger. A mismatch here means the guest reverted to the clone-source

rem key (50000) - see tests\CRASH_DEBUG_LOG.md TODO.

findstr /c:"DBG_port=50001" "%OUT%" >nul

if errorlevel 1 (

    echo [WARN] KDNET is NOT on the test2-dedicated port 50001 - run build\vm_kdnet_set.bat

) else (

    echo [OK] KDNET dedicated port 50001

)



rem Deployed script vs repo copy: catches zero-filled files.

set SCRIPTHOST=

set SCRIPTGUEST=

for /f "tokens=1" %%h in ('certutil -hashfile "%REPO%\scripts\verify_core.py" SHA256 ^| findstr /r /c:"^[0-9a-fA-F][0-9a-fA-F ]*$"') do set SCRIPTHOST=%%h

set SCRIPTHOST=%SCRIPTHOST: =%

for /f "tokens=2 delims==" %%h in ('type "%OUT%" ^| findstr /c:"SCRIPT_SHA256="') do set SCRIPTGUEST=%%h

set SCRIPTGUEST=%SCRIPTGUEST: =%

if "%SCRIPTGUEST%"=="" (

    echo [FAIL] deployed verify_core.py has no hash - redeploy it

    set RC=1

) else if /i "%SCRIPTHOST%"=="%SCRIPTGUEST%" (

    echo [OK] deployed verify_core.py matches repo copy

) else (

    echo [FAIL] deployed verify_core.py is corrupt or stale - run build\vm_push_driver.bat

    set RC=1

)



rem Deployed .sys vs freshly built artifact, when both are present.

if not exist "%SYS%" (

    echo [WARN] host artifact missing - run build\build_driver.bat

    goto :hash_done

)

for /f "tokens=1" %%h in ('certutil -hashfile "%SYS%" SHA256 ^| findstr /r /c:"^[0-9a-fA-F][0-9a-fA-F ]*$"') do set HOSTHASH=%%h

set HOSTHASH=%HOSTHASH: =%

for /f "tokens=2 delims==" %%h in ('type "%OUT%" ^| findstr /c:"SYS_SHA256="') do set GUESTHASH=%%h

set GUESTHASH=%GUESTHASH: =%

if "%GUESTHASH%"=="" (

    echo [INFO] no .sys deployed yet - run build\vm_push_driver.bat

    goto :hash_done

)

if /i "%HOSTHASH%"=="%GUESTHASH%" (

    echo [OK] deployed .sys matches host artifact

) else (

    echo [WARN] deployed .sys differs from host artifact - run build\vm_push_driver.bat

    echo        host : %HOSTHASH%

    echo        guest: %GUESTHASH%

)

:hash_done



if %RC%==0 (

    echo [OK] guest environment ready - report: %OUT%

    exit /b 0

)

echo [FAIL] guest environment missing prerequisites - report: %OUT%

exit /b 1



:require

findstr /c:%1 "%OUT%" >nul

if errorlevel 1 (

    echo [FAIL] %~2 ^(%1 not found^)

    set RC=1

) else (

    echo [OK] %~2

)

exit /b 0

