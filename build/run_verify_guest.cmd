@echo off
REM Runs wherever the pusher deployed it (%GDIR%); %~dp0 keeps this file
REM free of machine-specific paths. The done marker carries the token the
REM host pushed (verify_token.txt) so a stale marker from an earlier run
REM can never pass the poll (same discipline as vm_alive_check.bat).
cd /d "%~dp0"
del /q verify_out.txt 2>nul
del /q verify_done.txt 2>nul
set /p MYARK_VTOK=<"%~dp0verify_token.txt" 2>nul
C:\Users\Public\python312\python.exe -u verify_core.py > verify_out.txt 2>&1
echo VERIFY_EXIT %errorlevel% TOKEN=%MYARK_VTOK% > verify_done.txt
schtasks /delete /tn MyArkVerify /f >nul 2>&1
