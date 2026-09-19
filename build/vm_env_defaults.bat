@echo off
REM Shared fleet defaults, included by every vm_*.bat right after setlocal.
REM Real credentials, VM paths and KDNET coordinates are NOT committed.
REM Copy build\vm_env_local.bat.example to build\vm_env_local.bat (gitignored)
REM and fill in: MYARK_VMX, MYARK_GDIR, MYARK_GUEST_USER, MYARK_GUEST_PASS,
REM MYARK_GPROBE, MYARK_KDKEY, MYARK_KDHOST, MYARK_KDPORT and, for encrypted
REM VMs, MYARK_VP. Precedence: per-invocation "set MYARK_*" > the local file
REM (both use if-not-defined guards, callers first) > the placeholders below.
REM MYARK_VP is the ENCRYPTION password (--vp), only needed for VMs whose
REM vmx carries encryption.keySafe (vTPM partial encryption). No setlocal
REM here on purpose: the variables must survive the call.
if exist "%~dp0vm_env_local.bat" call "%~dp0vm_env_local.bat"
if "%MYARK_VMX%"=="" set "MYARK_VMX=C:\Path\To\Your.vmx"
if "%MYARK_GDIR%"=="" set "MYARK_GDIR=C:\myark-test"
if "%MYARK_GUEST_USER%"=="" set "MYARK_GUEST_USER=CHANGE_ME_USER"
if "%MYARK_GUEST_PASS%"=="" set "MYARK_GUEST_PASS=CHANGE_ME_PASS"
set "VMX=%MYARK_VMX%"
set "GDIR=%MYARK_GDIR%"
if "%MYARK_GPROBE%"=="" set "MYARK_GPROBE=C:\Users\Public\myark_alive.txt"
set "GPROBE=%MYARK_GPROBE%"
if "%MYARK_PYTHON%"=="" set "MYARK_PYTHON=python"
set "MYPY=%MYARK_PYTHON%"
set "VPARGS="
if not "%MYARK_VP%"=="" set "VPARGS=-vp %MYARK_VP%"
