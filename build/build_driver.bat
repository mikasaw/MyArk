@echo off
REM Phase 0 - build MyArkCore.sys (Release|x64) from the solution.
REM The artifact must land in driver\x64\Release\ : the vcxproj pins OutDir
REM with $(SolutionDir), and building MyArkCore.vcxproj directly drops
REM SolutionDir and SKIPS the test signature (known trap, see AGENTS.md 4).
setlocal
set REPO=%~dp0..
set SLN=%REPO%\driver\MyArkCore.sln
set SYS=%REPO%\driver\x64\Release\MyArkCore.sys
set MSBUILD=C:\Program Files\Microsoft Visual Studio\18\Insiders\MSBuild\Current\Bin\MSBuild.exe

if not exist "%MSBUILD%" (
    echo [FAIL] MSBuild not found: %MSBUILD%
    echo [HINT] install Insiders VS 2026 ^(see README^)
    exit /b 1
)
if not exist "%SLN%" (
    echo [FAIL] solution not found: %SLN%
    exit /b 1
)

echo [INFO] building Release^|x64
"%MSBUILD%" "%SLN%" /p:Configuration=Release /p:Platform=x64 /m /v:minimal /nologo
if errorlevel 1 (
    echo [FAIL] build failed
    exit /b 1
)

if not exist "%SYS%" (
    echo [FAIL] artifact missing: %SYS%
    exit /b 1
)
echo [OK] artifact: %SYS%
dir /b "%SYS%"
echo [INFO] MSBuild test-signed the artifact ^(SignMode=Test, WDKTestCert^)

REM R2-5 acceptance target: a disposable unload-capable test driver.
REM Built from its own vcxproj (standalone, SolutionDir-independent
REM OutDir is pinned inside the project file).
set TESTDRV=%REPO%\driver\testdrv\MyArkTestDrv.vcxproj
set TESTSYS=%REPO%\driver\testdrv\x64\Release\MyArkTestDrv.sys
echo [INFO] building MyArkTestDrv Release^|x64
"%MSBUILD%" "%TESTDRV%" /p:Configuration=Release /p:Platform=x64 /m /v:minimal /nologo
if errorlevel 1 (
    echo [FAIL] testdrv build failed
    exit /b 1
)
if not exist "%TESTSYS%" (
    echo [FAIL] artifact missing: %TESTSYS%
    exit /b 1
)

REM MSBuild does not run the signing target for INF-less WDM projects,
REM so sign here with the same test certificate the main build uses
REM (a NotSigned artifact fails guest load with 577 -- AGENTS.md 4).
set SIGTOOL=\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x64\signtool.exe
REM single-line if: the (x86) in the expanded path would close a
REM parenthesized block early (AGENTS.md 4 trap recurrence).
if not exist "%SIGTOOL%" echo [FAIL] signtool not found & exit /b 1
"%SIGTOOL%" sign /fd SHA256 /n "WDKTestCert www" "%TESTSYS%" >nul
if errorlevel 1 echo [FAIL] testdrv signing failed & exit /b 1
echo [OK] artifact signed: %TESTSYS%
endlocal
