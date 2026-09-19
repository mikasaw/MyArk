@echo off
REM Crash forensics, runs INSIDE the guest. Writes a KEY=VALUE / listing
REM report that the host pulls over the file channel.
REM Runs wherever the pusher deployed it (%GDIR%); %~dp0 keeps this file
REM free of machine-specific paths.
set "GDIR=%~dp0"
if "%GDIR:~-1%"=="\" set "GDIR=%GDIR:~0,-1%"
set R=%GDIR%\crash_report.txt
set DUMPDIR=C:\Windows\Minidump

if not exist "%GDIR%" mkdir "%GDIR%" 2>nul
del /q "%R%" 2>nul
echo MYARK_CRASH_BEGIN >> "%R%"

rem ---- boot time (CIM query: locale-independent) ----
powershell -NoProfile -Command "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime" >> "%R%" 2>&1

rem ---- minidumps, newest first ----
echo --- minidump list --- >> "%R%"
dir /b /o-d "%DUMPDIR%" >> "%R%" 2>&1
echo --- minidump end --- >> "%R%"

rem ---- live kernel reports (WHEA / watchdog style) ----
echo --- livekernel --- >> "%R%"
dir /b C:\Windows\LiveKernelReports >> "%R%" 2>&1
echo --- livekernel end --- >> "%R%"

rem ---- BugCheck events (Event ID 1001 from BugCheck source) ----
echo --- bugcheck events --- >> "%R%"
wevtutil qe System "/q:*[System[Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting']]]" /c:3 /rd:true /f:text >> "%R%" 2>&1
echo --- bugcheck end --- >> "%R%"

rem ---- driver test directory contents ----
echo --- gdir --- >> "%R%"
dir /b "%GDIR%" >> "%R%" 2>&1
echo --- gdir end --- >> "%R%"

rem ---- is the driver still loaded ----
sc query MyArkCore >> "%R%" 2>&1

echo MYARK_CRASH_END >> "%R%"