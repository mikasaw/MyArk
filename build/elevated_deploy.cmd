@echo off
REM Guest-side elevated deploy (Win11): run via schtasks /rl highest --
REM runProgramInGuest gets a filtered token, so sc create/start fails there.
REM Idempotent: stop+delete tolerate "not installed/running" errors so a
REM re-run after a service registry leftover still reaches RUNNING.
REM Runs wherever the pusher deployed it (%GDIR%); %~dp0 keeps this file
REM free of machine-specific paths.
set "GDIR=%~dp0"
if "%GDIR:~-1%"=="\" set "GDIR=%GDIR:~0,-1%"
sc stop MyArkCore > C:\Users\Public\elevated_out.txt 2>&1
sc delete MyArkCore >> C:\Users\Public\elevated_out.txt 2>&1
certutil -addstore Root "%GDIR%\wdk_test.cer" >> C:\Users\Public\elevated_out.txt 2>&1
certutil -addstore TrustedPublisher "%GDIR%\wdk_test.cer" >> C:\Users\Public\elevated_out.txt 2>&1
REM type= filesys (SERVICE_FILE_SYSTEM_DRIVER=2) required for the filemon
REM minifilter (R2-7): FltRegisterFilter fails on kernel-type services.
sc create MyArkCore type= kernel start= demand binPath= "%GDIR%\MyArkCore.sys" DisplayName= MyArkCore >> C:\Users\Public\elevated_out.txt 2>&1
sc start MyArkCore >> C:\Users\Public\elevated_out.txt 2>&1
sc query MyArkCore >> C:\Users\Public\elevated_out.txt 2>&1
echo ELEVATED_DONE >> C:\Users\Public\elevated_out.txt
schtasks /delete /tn MyArkDeploy /f >> C:\Users\Public\elevated_out.txt 2>&1
