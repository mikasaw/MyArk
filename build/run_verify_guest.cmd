@echo off
REM Runs wherever the pusher deployed it (%GDIR%); %~dp0 keeps this file
REM free of machine-specific paths.
cd /d "%~dp0"
del /q verify_out.txt 2>nul
del /q verify_done.txt 2>nul
C:\Users\Public\python312\python.exe -u verify_core.py > verify_out.txt 2>&1
echo VERIFY_EXIT %errorlevel% > verify_done.txt
schtasks /delete /tn MyArkVerify /f >nul 2>&1
