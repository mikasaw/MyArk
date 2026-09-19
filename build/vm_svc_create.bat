@echo off

REM Phase 3 - create the MyArkCore kernel service pointing at the pushed

REM .sys inside the guest test directory.

REM Evidence is the guest-written log pulled over the file channel (vmrun

REM does not forward guest stdout); sc qc must show BINARY_PATH_NAME.

setlocal

set VMRUN=C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe

call "%~dp0vm_env_defaults.bat"

set "GDIR=%MYARK_GDIR%"

set LOG=%GDIR%\svc_create.txt

set OUT=%~dp0svc_create_out.txt



echo [1/2] sc create MyArkCore

REM type= kernel: with the Instances key fixed (R2-9 day) the minifilter

REM registers fine under a plain kernel service, and kernel-type services

REM keep normal unload semantics -- type= filesys made the I/O manager

REM asynchronously unload the driver after DriverEntry (it is not a real

REM FS), leaving filter callbacks wired into a freed image (0xCE).

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% runProgramInGuest "%VMX%" "cmd.exe" "/c del /q %LOG% 2>nul < NUL & sc create MyArkCore type= kernel start= demand binPath= %GDIR%\MyArkCore.sys DisplayName= MyArkCore >> %LOG% 2>&1 < NUL & sc qc MyArkCore >> %LOG% 2>&1 < NUL"



echo [2/2] pull + assert

del /q "%OUT%" 2>nul

"%VMRUN%" -T ws %VPARGS% -gu %MYARK_GUEST_USER% -gp %MYARK_GUEST_PASS% CopyFileFromGuestToHost "%VMX%" "%LOG%" "%OUT%"

if not exist "%OUT%" (

    echo [FAIL] could not pull svc_create.txt

    echo [NEXT] run build\vm_alive_check.bat

    exit /b 1

)

type "%OUT%"

findstr /c:"BINARY_PATH_NAME" "%OUT%" >nul

if errorlevel 1 (

    echo [FAIL] service not confirmed by sc qc - see %OUT%

    exit /b 1

)

echo [OK] service created

endlocal

