@echo off
REM Internal build script. Usage: build.bat <config_header> [configuration]
REM Reads profile from config/<config_header>, sets MSBuild preprocessor flag.
REM   configuration: Debug (default) | Release

setlocal

set CONFIG_HEADER=%~1
if "%CONFIG_HEADER%"=="" set CONFIG_HEADER=myark_full.h

set BUILD_CONFIG=%~2
if "%BUILD_CONFIG%"=="" set BUILD_CONFIG=Debug

REM Validate configuration value to avoid passing garbage to MSBuild.
if /I not "%BUILD_CONFIG%"=="Debug" if /I not "%BUILD_CONFIG%"=="Release" (
    echo ERROR: configuration "%BUILD_CONFIG%" not supported. Use Debug or Release.
    exit /b 1
)

REM Set MSBuild properties
set MSBUILD_PROPS=/p:Configuration=%BUILD_CONFIG% /p:Platform=x64 /p:MYARK_CONFIG_HEADER=%CONFIG_HEADER%

cd "%~dp0..\driver"

REM Find MSBuild
set MSBUILD="C:\Program Files\Microsoft Visual Studio\18\Insiders\MSBuild\Current\Bin\MSBuild.exe"
if not exist %MSBUILD% (
    echo ERROR: MSBuild not found at %MSBUILD%
    exit /b 1
)

%MSBUILD% MyArkCore.sln %MSBUILD_PROPS% /v:m /t:Rebuild
if %ERRORLEVEL% NEQ 0 (
    echo BUILD FAILED
    exit /b 1
)

echo BUILD SUCCEEDED with %CONFIG_HEADER% (%BUILD_CONFIG%)
endlocal