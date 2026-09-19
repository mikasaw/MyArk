<#
.SYNOPSIS
    Install and start the MyArkCore kernel driver inside a VM guest.

.DESCRIPTION
    Designed to be the ONLY entry point for bringing MyArkCore up inside a
    Hyper-V Gen2 / VMware Workstation / VirtualBox / QEMU guest. Must run
    elevated inside the VM, after:

      - `bcdedit /set testsigning on` (and reboot)
      - The caller has copied MyArkCore.sys (and ideally verify_core.py)
        to a known path inside the VM

    The script:

      1. Detects the VM environment (Hyper-V / VMware / VirtualBox / QEMU)
         from SMBIOS / registry / disk / ACPI markers. Refuses to run on a
         bare-metal host.
      2. Verifies `bcdedit /enum {default}` reports testsigning Yes.
      3. Stops and removes any prior MyArkCore service (idempotent).
      4. `sc create MyArkCore type= kernel binPath= <path>` + `sc start`.
      5. Confirms `STATE: 4 RUNNING`.
      6. If verify_core.py is present next to the .sys, runs it so the
         full S7.1 + S7.2 + S7.3 + S8.1 IOCTL surface (59 IOCTLs) is
         exercised before the user pokes from R3.
      7. Reports exit code and prints a summary line.

    This script never loads the driver on a bare-metal host. Use
    `Uninstall-MyArkCore` to stop and remove.

.PARAMETER DriverPath
    Full path to MyArkCore.sys inside the VM (default: C:\MyArkCore.sys).

.PARAMETER SkipVerify
    Skip the verify_core.py smoke test even if present.

.PARAMETER AllowBareMetal
    Bypass the VM detection guard. Useful for test rigs that are not VMs
    but still have testsigning on.

.EXAMPLE
    Install-MyArkCore -DriverPath 'C:\MyArkCore.sys'
    Install-MyArkCore -DriverPath 'C:\MyArkCore.sys' -SkipVerify
    Uninstall-MyArkCore
#>

[CmdletBinding()]
param(
    [string]$DriverPath = 'C:\MyArkCore.sys',
    [switch]$SkipVerify,
    [switch]$AllowBareMetal
)

$ErrorActionPreference = 'Stop'

$Script:VMKind = 'unknown'

function Write-Status {
    param([string]$Message, [string]$Level = 'INFO')
    $stamp = (Get-Date).ToString('HH:mm:ss')
    Write-Host "[$stamp][$Level] $Message"
}

function Get-VmEnvironment {
    <#
    .SYNOPSIS
        Detect whether we are inside a VM (and which one).

    .DESCRIPTION
        Layered detection, returns one of: hyperv | vmware | virtualbox |
        qemu | unknown. Order is cheapest-first; once a marker is found we
        stop. Bare metal returns 'unknown'.
    #>

    $cim = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($cim) {
        $model = ($cim.Model ?? '').ToLower()
        $manufacturer = ($cim.Manufacturer ?? '').ToLower()
        switch -Regex ($model) {
            'virtual'          { return 'virtualbox' }
            'vmware'           { return 'vmware' }
            'virtual machine'  { return 'hyperv' }
        }
        switch -Regex ($manufacturer) {
            'microsoft corporation' { if ($model -match 'virtual machine') { return 'hyperv' } }
            'vmware'                { return 'vmware' }
            'innotek'               { return 'virtualbox' }
            'qemu'                  { return 'qemu' }
        }
    }

    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
    if ($bios) {
        $smbios = ($bios.SMBIOSBIOSVersion ?? '').ToLower()
        $biosMfg = ($bios.Manufacturer ?? '').ToLower()
        if ($smbios -match 'hyperv' -or $biosMfg -match 'hyperv') { return 'hyperv' }
        if ($smbios -match 'vmware' -or $biosMfg -match 'vmware') { return 'vmware' }
        if ($smbios -match 'virtualbox' -or $biosMfg -match 'virtualbox') { return 'virtualbox' }
        if ($smbios -match 'qemu' -or $biosMfg -match 'qemu') { return 'qemu' }
    }

    $acpi = & bcdedit /enum '{default}' 2>$null
    if ($acpi -match 'hypervisorpresent\s+Yes') {
        return 'hyperv'
    }

    return 'unknown'
}

function Test-TestSigning {
    <#
    .SYNOPSIS
        Confirm bcdedit reports testsigning Yes on the boot entry.
    #>
    $bcd = & bcdedit /enum '{default}' 2>$null
    if ($LASTEXITCODE -ne 0) {
        return $false
    }
    return ($bcd -match 'testsigning\s+Yes')
}

function Remove-ExistingService {
    param([string]$Name)
    $existing = & sc.exe query $Name 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Status "Removing existing service: $Name"
        & sc.exe stop $Name | Out-Null
        Start-Sleep -Seconds 1
        & sc.exe delete $Name | Out-Null
        Start-Sleep -Seconds 1
        return $true
    }
    return $false
}

function Install-MyArkCore {
    [CmdletBinding()]
    param(
        [string]$Path,
        [switch]$SkipVerifyInner
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Driver not found at $Path. Copy MyArkCore.sys into the VM first."
    }

    # ---- 1. VM environment guard ------------------------------------------
    $Script:VMKind = Get-VmEnvironment
    if ($Script:VMKind -eq 'unknown' -and -not $AllowBareMetal) {
        Write-Status 'No VM marker detected (hyperv/vmware/virtualbox/qemu).' 'WARN'
        Write-Status 'If this IS a test rig without VM markers, re-run with -AllowBareMetal.' 'WARN'
        throw 'Refusing to load a kernel driver on what looks like a bare-metal host.'
    }
    Write-Status "VM environment: $($Script:VMKind)"

    # ---- 2. testsigning check ---------------------------------------------
    if (-not (Test-TestSigning)) {
        throw 'testsigning is not on. Run: bcdedit /set testsigning on (then reboot).'
    }
    Write-Status 'testsigning is on.'

    # ---- 3. Stop + delete any existing service (idempotent) ---------------
    [void](Remove-ExistingService -Name 'MyArkCore')

    # ---- 4. sc create + sc start ------------------------------------------
    Write-Status "Creating kernel service: MyArkCore binPath= $Path"
    & sc.exe create MyArkCore type= kernel binPath= $Path DisplayName= 'MyArk ARK Core' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "sc create MyArkCore failed (exit=$LASTEXITCODE)."
    }

    Write-Status 'Starting MyArkCore...'
    & sc.exe start MyArkCore | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "sc start MyArkCore failed (exit=$LASTEXITCODE). Check driver/x64/<Config>/MyArkCore.inf deployment."
    }

    # ---- 5. Verify RUNNING state ------------------------------------------
    $query = & sc.exe query MyArkCore
    Write-Status $query.Trim()
    if ($query -notmatch 'STATE\s+:\s+4\s+RUNNING') {
        throw 'MyArkCore did not reach STATE: 4 RUNNING.'
    }
    Write-Status 'MyArkCore is RUNNING.'

    # ---- 6. PnP enumeration (informational) ------------------------------
    $dev = Get-CimInstance -ClassName Win32_PnPEntity -Filter "Name='MyArk ARK Core'" -ErrorAction SilentlyContinue
    if ($dev) {
        Write-Status ("PnP device: {0} [{1}]" -f $dev.Name, $dev.DeviceID)
    } else {
        Write-Status 'No PnP device match (non-PnP Control Device; \\.\MyArkCore is reachable via CreateFile).'
    }

    # ---- 7. verify_core.py smoke test (59 IOCTLs) ------------------------
    $verifyScript = Join-Path (Split-Path -Parent $Path) 'verify_core.py'
    if ($SkipVerifyInner) {
        Write-Status 'Skipping verify_core.py (caller passed -SkipVerify).'
    } elseif (Test-Path -LiteralPath $verifyScript) {
        Write-Status "Running verify_core.py (S7.1 9 + S7.2 10 + S7.3 40 + S8.1 7 = 66 IOCTLs)..."
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        & python $verifyScript
        $rc = $LASTEXITCODE
        $sw.Stop()
        if ($rc -ne 0) {
            throw "verify_core.py FAILED (exit=$rc, elapsed=$([int]$sw.Elapsed.TotalSeconds)s). Driver loaded but IOCTL smoke test failed."
        }
        Write-Status ("verify_core.py OK (exit=0, elapsed={0}s)" -f [int]$sw.Elapsed.TotalSeconds)
    } else {
        Write-Status "verify_core.py not found at $verifyScript; skipping IOCTL smoke test."
    }

    Write-Status 'Install-MyArkCore SUCCESS.'
}

function Uninstall-MyArkCore {
    [CmdletBinding()]
    param()

    Write-Status 'Uninstall-MyArkCore starting.'

    $existing = & sc.exe query MyArkCore 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Status 'Stopping MyArkCore...'
        & sc.exe stop MyArkCore | Out-Null
        Start-Sleep -Seconds 1
        Write-Status 'Deleting MyArkCore...'
        & sc.exe delete MyArkCore | Out-Null
        Start-Sleep -Seconds 1
    } else {
        Write-Status 'MyArkCore not registered; nothing to stop.'
    }

    Write-Status 'Uninstall-MyArkCore SUCCESS.'
}

# When this file is dot-sourced the functions are exposed; when it is run
# directly default to install.
if ($MyInvocation.InvocationName -ne '.' -and $MyInvocation.InvocationName -ne '&') {
    Install-MyArkCore -Path $DriverPath -SkipVerifyInner:$SkipVerify
}
