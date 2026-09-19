<#
.SYNOPSIS
    Standalone uninstaller for MyArkCore (mirrors install_vm.ps1).

.DESCRIPTION
    Companion to install_vm.ps1. When installed via the all-in-one
    Install-MyArkCore cmdlet, the driver is loaded directly from the caller's
    path (no copy to %SystemRoot%\System32\drivers\). Therefore this
    uninstaller only needs to:

      1. Stop the MyArkCore kernel service.
      2. Delete the MyArkCore service registration.
      3. Clean up the registry key
         HKLM\SYSTEM\CurrentControlSet\Services\MyArkCore
         (including the runtime Modules subkey).
      4. NOT delete the caller-supplied .sys -- that lives at whatever path
         the install used. The user owns it.

    Idempotent: safe to re-run. If the service / file / registry key is
    missing, that step is reported and the script continues.

.PARAMETER DriverPath
    Path the .sys lives at. Only used to print a hint; no file is removed.

.EXAMPLE
    Uninstall-MyArkCore
    Uninstall-MyArkCore -DriverPath 'C:\MyArkCore.sys'
#>

[CmdletBinding()]
param(
    [string]$DriverPath = 'C:\MyArkCore.sys'
)

$ErrorActionPreference = 'Stop'

$ServiceName = 'MyArkCore'
$SvcKey = 'HKLM\SYSTEM\CurrentControlSet\Services\MyArkCore'
$ModKey = "$SvcKey\Modules"

function Write-Status {
    param([string]$Message, [string]$Level = 'INFO')
    $stamp = (Get-Date).ToString('HH:mm:ss')
    Write-Host "[$stamp][$Level] $Message"
}

function Uninstall-MyArkCore {
    [CmdletBinding()]
    param()

    Write-Status 'MyArkCore uninstaller starting.'

    # ---- Admin required for service + registry operations --------------
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator privileges required. Right-click run as administrator.'
    }

    # ---- 1. stop + delete service ---------------------------------------
    $query = & sc.exe query $ServiceName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Status "Stopping $ServiceName..."
        & sc.exe stop $ServiceName | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Status "sc stop returned $LASTEXITCODE (continuing)." 'WARN'
        }
        Start-Sleep -Seconds 1
        Write-Status "Deleting $ServiceName..."
        & sc.exe delete $ServiceName | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Status "sc delete returned $LASTEXITCODE (continuing)." 'WARN'
        }
        Start-Sleep -Seconds 1
    } else {
        Write-Status "$ServiceName not registered; nothing to stop."
    }

    # ---- 2. registry: Modules subkey (runtime enable mask) --------------
    $regOut = & reg.exe query $ModKey 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Status "Removing registry key $ModKey"
        & reg.exe delete $ModKey /F | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Status "reg delete $ModKey returned $LASTEXITCODE (continuing)." 'WARN'
        }
    } else {
        Write-Status "Registry key $ModKey not present."
    }

    # ---- 3. registry: service root key ----------------------------------
    $regOut = & reg.exe query $SvcKey 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Status "Removing registry key $SvcKey"
        & reg.exe delete $SvcKey /F | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Status "reg delete $SvcKey returned $LASTEXITCODE (continuing)." 'WARN'
        }
    } else {
        Write-Status "Registry key $SvcKey not present."
    }

    # ---- 4. file hint ---------------------------------------------------
    if (Test-Path -LiteralPath $DriverPath) {
        Write-Status "Driver still present at $DriverPath (caller-owned, NOT deleted)."
        Write-Status '  Delete it manually if desired: Remove-Item -LiteralPath <path>'
    } else {
        Write-Status "No caller-supplied driver at $DriverPath."
    }

    # ---- 5. ensure no stragglers ----------------------------------------
    $stillThere = & sc.exe query $ServiceName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Status "Service still reported after cleanup -- retry or reboot." 'WARN'
        exit 2
    }
    $stillReg = & reg.exe query $SvcKey 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Status "Registry key still reported after cleanup -- retry or reboot." 'WARN'
        exit 2
    }

    Write-Status 'MyArkCore uninstaller SUCCESS.'
}

# When this file is dot-sourced the functions are exposed; when it is run
# directly default to uninstall.
if ($MyInvocation.InvocationName -ne '.' -and $MyInvocation.InvocationName -ne '&') {
    Uninstall-MyArkCore
}
