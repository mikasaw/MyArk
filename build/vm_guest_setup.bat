@echo off

REM One-time guest preparation: testsigning, WDK test certificate, and the

REM test2-dedicated KDNET key/port. Idempotent. A reboot is required for

REM bcdedit changes - run build\vm_reset_hard.bat afterwards.

REM

REM The dedicated KDNET key matters: test2 is a clone of the other test VM

REM and used to share its key on port 50000, so a debugger opened for that

REM project could break into (freeze) test2 by accident.

setlocal

set REPO=%~dp0..

set VMRUN=C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe

call "%~dp0vm_env_defaults.bat"

set "GDIR=%MYARK_GDIR%"

REM KDNET coordinates are credentials: they come from the local untracked
REM env file, never from this script. Copy build\vm_env_local.bat.example
REM to build\vm_env_local.bat and fill MYARK_KDKEY / MYARK_KDHOST /
REM MYARK_KDPORT (use your environment's dedicated port).
if "%MYARK_KDKEY%"=="" (
    echo [FAIL] MYARK_KDKEY not set - fill build\vm_env_local.bat ^(see .example^)
    exit /b 1
)
if "%MYARK_KDHOST%"=="" (
    echo [FAIL] MYARK_KDHOST not set - fill build\vm_env_local.bat ^(see .example^)
    exit /b 1
)
if "%MYARK_KDPORT%"=="" set "MYARK_KDPORT=50000"
set "KDKEY=%MYARK_KDKEY%"

set "KDPORT=%MYARK_KDPORT%"

set "KDHOST=%MYARK_KDHOST%"

set CER=%REPO%\build\wdk_test.cer

set LOG=%GDIR%\guest_setup_report.txt

set OUT=%~dp0guest_setup_out.txt



if not exist "%CER%" (

    echo [FAIL] certificate not found: %CER%

    echo [HINT] run powershell build\export_wdkcert.ps1 against a signed .sys first

    exit /b 1

)



echo [1/5] ensure guest test directory

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% runProgramInGuest "%VMX%" "cmd.exe" "/c if not exist %GDIR% mkdir %GDIR% < NUL"



echo [2/5] push certificate

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromHostToGuest "%VMX%" "%CER%" "%GDIR%\wdk_test.cer"

if not "%errorlevel%"=="0" (

    echo [FAIL] cert copy failed ^(vmrun rc=%errorlevel%^)

    echo [NEXT] run build\vm_alive_check.bat

    exit /b 1

)



echo [3/5] apply testsigning / certificate / KDNET / Defender exclusion in guest

REM Best-effort hardening for a driver test VM: exclude the test directory

REM from Defender real-time scanning. NOTE (CRASH_DEBUG_LOG S11.6): the

REM 2026-09-15 BSOD loop was NOT Defender -- it was a driver NULL deref.

REM The exclusion stays as generic test-VM hygiene; idempotent.

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% runProgramInGuest "%VMX%" "cmd.exe" "/c del /q %LOG% 2>nul < NUL & powershell -NoProfile -Command \"Add-MpPreference -ExclusionPath '%GDIR%'\" >> %LOG% 2>&1 < NUL & bcdedit /set testsigning on >> %LOG% 2>&1 < NUL & certutil -addstore Root %GDIR%\wdk_test.cer >> %LOG% 2>&1 < NUL & certutil -addstore TrustedPublisher %GDIR%\wdk_test.cer >> %LOG% 2>&1 < NUL & bcdedit /dbgsettings net hostip:%KDHOST% port:%KDPORT% key:%KDKEY% >> %LOG% 2>&1 < NUL & bcdedit /dbgsettings >> %LOG% 2>&1 < NUL & bcdedit >> %LOG% 2>&1 < NUL"



echo [4/5] pull setup report

del /q "%OUT%" 2>nul

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromGuestToHost "%VMX%" "%LOG%" "%OUT%"

if not exist "%OUT%" (

    echo [FAIL] could not pull setup report

    echo [NEXT] run build\vm_alive_check.bat

    exit /b 1

)



echo [5/5] asserting guest setup

findstr /i /c:"testsigning" "%OUT%" | findstr /i /c:"Yes" >nul

if errorlevel 1 (

    echo [FAIL] testsigning not enabled - report: %OUT%

    exit /b 1

)

echo [OK] testsigning enabled

findstr /c:"Root" "%OUT%" >nul

if errorlevel 1 (

    echo [FAIL] Root store not confirmed - report: %OUT%

    exit /b 1

)

findstr /c:"TrustedPublisher" "%OUT%" >nul

if errorlevel 1 (

    echo [FAIL] TrustedPublisher store not confirmed - report: %OUT%

    exit /b 1

)

echo [OK] WDK test cert trusted

findstr /c:"port" "%OUT%" | findstr /c:"%KDPORT%" >nul

if errorlevel 1 (

    echo [FAIL] KDNET port is not %KDPORT% - report: %OUT%

    exit /b 1

)

findstr /c:"key" "%OUT%" | findstr /c:"%KDKEY%" >nul

if errorlevel 1 (

    echo [FAIL] KDNET key is not the test2-dedicated one - report: %OUT%

    exit /b 1

)

echo [OK] KDNET dedicated to port %KDPORT%



echo [OK] guest setup written - run build\vm_reset_hard.bat to apply bcdedit

endlocal

