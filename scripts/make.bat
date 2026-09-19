@echo off
REM ============================================
REM MyArk build entry
REM Usage: make.bat <profile> [configuration]
REM   profile: full / mini / core / process-only / process_only / safety-audit / safety_audit
REM   configuration: Debug (default) | Release
REM ============================================

setlocal

if "%~1"=="" (
    set PROFILE=full
) else (
    set PROFILE=%~1
)

REM Accept both hyphen and underscore forms for profile names -- the
REM headers under config/ use underscores, the README / issue text use
REM hyphens. Normalising here means both spellings work.
set "PROFILE_FILE=%PROFILE:-=_%"

if not exist "%~dp0..\config\myark_%PROFILE_FILE%.h" (
    echo ERROR: profile "%PROFILE%" not found. Available: full / mini / core / process-only / safety-audit
    exit /b 1
)

set BUILD_CONFIG=%~2
if "%BUILD_CONFIG%"=="" set BUILD_CONFIG=Debug

echo Building MyArk with profile "%PROFILE%" (%BUILD_CONFIG%)...
call "%~dp0build.bat" myark_%PROFILE_FILE%.h %BUILD_CONFIG%

endlocal