@echo off

REM KDNET maintenance for test2: write the dedicated port/key into the

REM {dbgsettings} entry and prove it sticks. Steps run as separate guest

REM invocations so a failure points at one command instead of a chain.

REM Evidence path is the file channel (vmrun does not forward guest stdout).

setlocal

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

set LOG=%GDIR%\kdnet_diag.txt

set OUT=%~dp0kdnet_diag_out.txt



echo [1/5] create report file

REM Idempotent mkdir (2>nul) instead of "if not exist X mkdir X & echo":

REM cmd binds "& echo" into the IF body, so when the dir already exists the

REM whole chain is skipped and the marker never lands (2026-09-15 fix).

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% runProgramInGuest "%VMX%" "cmd.exe" "/c mkdir %GDIR% 2>nul < NUL & echo STEP1_MARKER > %LOG% < NUL"



echo [2/5] verify marker landed

del /q "%OUT%" 2>nul

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromGuestToHost "%VMX%" "%LOG%" "%OUT%"

if not exist "%OUT%" (

    echo [FAIL] step 1 produced no file - exec or file channel broken

    echo [NEXT] run build\vm_alive_check.bat

    exit /b 1

)

echo        marker ok



echo [3/5] write KDNET settings

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% runProgramInGuest "%VMX%" "cmd.exe" "/c echo STEP3_WRITE >> %LOG% < NUL & bcdedit /dbgsettings net hostip:%KDHOST% port:%KDPORT% key:%KDKEY% >> %LOG% 2>&1 < NUL"



echo [4/5] read back now, then again after 8s

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% runProgramInGuest "%VMX%" "cmd.exe" "/c echo STEP4_READ1 >> %LOG% < NUL & bcdedit /dbgsettings >> %LOG% 2>&1 < NUL & ping -n 9 127.0.0.1 >nul < NUL & echo STEP4_READ2 >> %LOG% < NUL & bcdedit /dbgsettings >> %LOG% 2>&1 < NUL"



echo [5/5] pull + verdict

del /q "%OUT%" 2>nul

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromGuestToHost "%VMX%" "%LOG%" "%OUT%"

if not exist "%OUT%" (

    echo [FAIL] could not pull report

    exit /b 1

)

type "%OUT%"

findstr /c:"STEP4_READ2" "%OUT%" >nul

if errorlevel 1 (

    echo [FAIL] second read-back missing - see %OUT%

    exit /b 1

)

REM Windows find.exe must NOT be called by name here: invoked from Git Bash,

REM the host cmd inherits a PATH where /usr/bin (GNU find) comes first, so

REM "find /c 50001" crawls the whole C:\ drive for minutes. Count with a

REM findstr filter loop instead (2026-09-15 fix).

set OKCOUNT=0

for /f "delims=" %%l in ('type "%OUT%" ^| findstr /c:"port"') do (

    echo(%%l  | findstr /c:"%KDPORT%" >nul 2>nul

    if not errorlevel 1 set /a OKCOUNT+=1

)

if "%OKCOUNT%"=="2" (

    echo [OK] {dbgsettings} holds port %KDPORT% on both read-backs

    exit /b 0

)

echo [WARN] {dbgsettings} did not hold %KDPORT% on both reads ^(matched %OKCOUNT%/2^)

echo        report: %OUT%

exit /b 1

endlocal

