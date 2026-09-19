@echo off
REM Runs INSIDE the guest. Writes one TOKEN=VALUE line per prerequisite into
REM the guest test directory; the host pulls that file and asserts on it.
REM (vmrun does not forward guest stdout, so a file is the only channel.)
REM Runs wherever the pusher deployed it (%GDIR%); %~dp0 keeps this file
REM free of machine-specific paths.
set "GDIR=%~dp0"
if "%GDIR:~-1%"=="\" set "GDIR=%GDIR:~0,-1%"
set R=%GDIR%\env_report.txt

if not exist "%GDIR%" mkdir "%GDIR%" 2>nul
del /q "%R%" 2>nul

echo MYARK_ENV_BEGIN >> "%R%"

bcdedit | find /i "testsigning" | find /i "Yes" >nul 2>&1
if errorlevel 1 (echo TESTSIGNING=NO >> "%R%") else (echo TESTSIGNING=YES >> "%R%")

certutil -verifystore Root WDKTestCert >nul 2>&1
if errorlevel 1 (echo CERT_ROOT=NO >> "%R%") else (echo CERT_ROOT=YES >> "%R%")

certutil -verifystore TrustedPublisher WDKTestCert >nul 2>&1
if errorlevel 1 (echo CERT_TP=NO >> "%R%") else (echo CERT_TP=YES >> "%R%")

python --version >nul 2>&1
if errorlevel 1 (echo PYTHON=NO >> "%R%") else (echo PYTHON=YES >> "%R%")

if exist "%GDIR%" (echo GDIR=YES >> "%R%") else (echo GDIR=NO >> "%R%")

if exist "%GDIR%\MyArkCore.sys" (echo SYS_PRESENT=YES >> "%R%") else (echo SYS_PRESENT=NO >> "%R%")
if exist "%GDIR%\MyArkCore.sys" for /f "tokens=1" %%h in ('certutil -hashfile "%GDIR%\MyArkCore.sys" SHA256 ^| findstr /r /c:"^[0-9a-fA-F][0-9a-fA-F ]*$"') do echo SYS_SHA256=%%h >> "%R%"

if exist "%GDIR%\verify_core.py" (echo VERIFY_PRESENT=YES >> "%R%") else (echo VERIFY_PRESENT=NO >> "%R%")
rem Hash the deployed script: a power-cut can leave the file present but
rem zero-filled (size ok, data pages lost), which only a hash catches.
if exist "%GDIR%\verify_core.py" for /f "tokens=1" %%h in ('certutil -hashfile "%GDIR%\verify_core.py" SHA256 ^| findstr /r /c:"^[0-9a-fA-F][0-9a-fA-F ]*$"') do echo SCRIPT_SHA256=%%h >> "%R%"

sc query MyArkCore >nul 2>&1
if errorlevel 1 (
    echo SERVICE=ABSENT >> "%R%"
) else (
    sc query MyArkCore | find "RUNNING" >nul 2>&1
    if errorlevel 1 (echo SERVICE=STOPPED >> "%R%") else (echo SERVICE=RUNNING >> "%R%")
)

for /f "tokens=1,2" %%a in ('bcdedit /dbgsettings ^| findstr /i "port key"') do echo DBG_%%a=%%b >> "%R%"

rem Boot time proves whether a reset actually applied the BCD changes.
for /f "tokens=2 delims==" %%t in ('wmic os get lastbootuptime /value ^| findstr /i "LastBootUpTime"') do echo BOOTTIME=%%t >> "%R%"

rem Raw BCD dumps: parsed on the host, so locale never matters here.
echo BCD_LOADER_BEGIN >> "%R%"
bcdedit /enum {current} >> "%R%" 2>&1
echo BCD_LOADER_END >> "%R%"

echo MYARK_ENV_END >> "%R%"