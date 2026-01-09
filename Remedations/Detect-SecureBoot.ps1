<#PSScriptInfo
.VERSION        1.0.1
.GUID           feedbeef-beef-4dad-beef-88c9893120b1
.AUTHOR         @MrTbone_se (T-bone Granheden)
.COPYRIGHT      (c) 2026 T-bone Granheden. MIT License - free to use with attribution.
.TAGS           Intune Graph PrimaryUser DeviceManagement MicrosoftGraph Azure
.LICENSEURI     https://opensource.org/licenses/MIT
.PROJECTURI     https://github.com/Mr-Tbone/Intune
.RELEASENOTES
    1.0.0 2026-01-08 Initial Build
    1.0.1 2026-01-09 Fixed header to comply with best practice
#>

<#
.SYNOPSIS
    Script for Intune remediation to detect if Secure Boot is enabled

.DESCRIPTION
    The script detects if Secure Boot is enabled on the device and also collects diagnostic info on the device.
    Returns Compliant (exit 0) if enabled, Non-Compliant (exit 1) if disabled or not supported.
    The compact function invoke-TboneTinyLog is used to capture logs and return them to Intune and disk for troubleshooting.

.NOTES
    Please feel free to use this, but make sure to credit @MrTbone_se as the original author

.LINK
    https://tbone.se
#>

#region ---------------------------------------------------[Modifiable Parameters and Defaults]------------------------------------
$ScriptName = "Detect Secure Boot"                                          # Name of the script (Used for log file name)
$LogPath    = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"   # Path to save logs (Default Intune log path)
#endregion
#region ---------------------------------------------------[Set global script settings]--------------------------------------------
$RemediateMode  = $MyInvocation.ScriptName -like "*Remediate*"              # Auto-detect mode based on script name
$AllCompliant   = $true                                                     # Assume compliant until a check fails
$Summary        = [ordered]@{}                                              # Summary hashtable for last reporting string to Intune
#endregion
#region ---------------------------------------------------[Functions]------------------------------------------------------------
function Invoke-TboneTinyLog {
<#
.SYNOPSIS
    Unified tiny logger for PS4-PS7, overrides Write-* commands and captures all messages
.DESCRIPTION
    Captures all Write-Host, Write-Output, Write-Warning, Write-Error and Write-Verbose messages in memory.
    On 'Stop' mode, restores original Write-* commands and returns an array of all captured log messages.
.NOTES
    Version: 1.0.0
    Author:  @MrTbone_se (T-bone Granheden)
    Releasenotes:
        2026-01-08 - Initial release
#>
  param(
    [ValidateSet('Start','Stop')][string]$Mode='Start',
    [string]$Name = $(if($MyInvocation.ScriptName){[System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.ScriptName)}else{'TboneTinyLog'}),
    [string]$LogPath = $(if($MyInvocation.PSScriptRoot){$MyInvocation.PSScriptRoot}elseif($PSScriptRoot){$PSScriptRoot}else{$pwd.Path})
  )
  if ($Mode -eq 'Start') {
    if (-not $script:_l) {
        $script:_l = New-Object 'System.Collections.Generic.List[string]'
    # Override write-*** cmdlets to capture log messages and return an array of all messages on 'Stop' mode
        function global:Write-Host {$m = $args -join ' ';if ($m) {$script:_l.Add("[INFO]$m");Microsoft.PowerShell.Utility\Write-Host "[INFO]$m"}}
        function global:Write-Output {$m = $args -join ' ';if ($m) {$script:_l.Add("[INFO]$m");Microsoft.PowerShell.Utility\Write-Host "[INFO]$m"}}
        function global:Write-Warning {$m = $args -join ' ';if ($m) {$script:_l.Add("[WARN]$m");Microsoft.PowerShell.Utility\Write-Host "[WARN]$m" -ForegroundColor Yellow}}
        function global:Write-Error {$m = $args -join ' ';if ($m) {$script:_l.Add("[ERR]$m");Microsoft.PowerShell.Utility\Write-Host "[ERR]$m" -ForegroundColor Red}}
        function global:Write-Verbose {$m = $args -join ' ';if ($m) {$script:_l.Add("[VERBOSE]$m");if ($VerbosePreference -ne 'SilentlyContinue') {Microsoft.PowerShell.Utility\Write-Host "[VERBOSE]$m" -ForegroundColor Cyan}}}    }
  } else {
    'Write-Host','Write-Output','Write-Warning','Write-Error','Write-Verbose'|ForEach-Object{Remove-Item "function:$_" -ea 0}
    if ($script:_l) {try{[System.IO.File]::WriteAllLines("$($LogPath)\$($Name).log",$script:_l)}catch{};,$script:_l.ToArray();$script:_l=$null} else {@()}
  }
}

function Test-SecureBootEnabled {
<#
.SYNOPSIS
    Test if Secure Boot is enabled, returns $true or $false
.DESCRIPTION
    Test if Secure Boot is enabled on the device using Confirm-SecureBootUEFI cmdlet.
.NOTES
    Version: 1.0.0
    Author:  @MrTbone_se (T-bone Granheden)
    Releasenotes:
        2026-01-08 - Initial release
#>
    try {
        if (-not (Confirm-SecureBootUEFI)) {
            Write-Warning "Secure Boot is disabled"; return $false
        }
        Write-Host "Secure Boot is enabled"; return $true
    } catch {
        Write-Error "Secure Boot not supported (Legacy BIOS): $_"; return $false
    }
}

function Get-SecureBootDiagnostics {
    <#
.SYNOPSIS
    Gather diagnostic info to understand why Secure Boot may not be enabled
.DESCRIPTION
    Gathers info about firmware type, partition style, device model, BIOS version, TPM status and OS build.
    Returns an ordered hashtable with the collected info.
.NOTES
    Version: 1.0.0
    Author:  @MrTbone_se (T-bone Granheden)
    Version History:
        2026-01-08 - Initial release
#>
    $diag = [ordered]@{} #Initialize ordered dictionary
    # Firmware type (UEFI or Legacy) - fast registry check
    $diag['FirmwareType'] = if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State") { "UEFI" } else { "Legacy/Unknown" }
    # Disk partition style (GPT = UEFI capable, MBR = Legacy)
    try {
        $osDisk = Get-Disk | Where-Object { $_.IsBoot -eq $true } | Select-Object -First 1
        $diag['PartitionStyle'] = $osDisk.PartitionStyle
    } catch { $diag['PartitionStyle'] = "Unknown" }
    # Device info + VM check
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -Property Manufacturer,Model
        $diag['Manufacturer'] = $cs.Manufacturer
        $diag['Model'] = $cs.Model
        $diag['IsVirtualMachine'] = if ($cs.Model -match "Virtual|VMware|VirtualBox|Hyper-V|QEMU|Parallels") { "Yes" } else { "No" }
    } catch { $diag['Manufacturer'] = "Unknown"; $diag['Model'] = "Unknown"; $diag['IsVirtualMachine'] = "Unknown" }
    # BIOS info
    try {
        $bios = Get-CimInstance Win32_BIOS -Property SMBIOSBIOSVersion,ReleaseDate
        $diag['BIOSVersion'] = $bios.SMBIOSBIOSVersion
        $diag['BIOSDate'] = if ($bios.ReleaseDate) { $bios.ReleaseDate.ToString("yyyy-MM-dd") } else { "Unknown" }
    } catch { $diag['BIOSVersion'] = "Unknown"; $diag['BIOSDate'] = "Unknown" }
    # TPM status and version
    try {
        $tpmWmi = Get-CimInstance -Namespace "Root\CIMv2\Security\MicrosoftTpm" -ClassName Win32_Tpm -EA Stop
        $diag['TPMPresent'] = $true
        $diag['TPMEnabled'] = $tpmWmi.IsEnabled_InitialValue
        $diag['TPMVersion'] = if ($tpmWmi.SpecVersion) { $tpmWmi.SpecVersion.Split(",")[0].Trim() } else { "Unknown" }
    } catch { 
        $diag['TPMPresent'] = $false
        $diag['TPMEnabled'] = "N/A"
        $diag['TPMVersion'] = "N/A"
    }
    # OS Version
    $diag['OSBuild'] = [System.Environment]::OSVersion.Version.Build
    return $diag
}
#endregion
#region -------------------------------------------------[Script Executions]--------------------------------------------------
try {
    Invoke-TboneTinyLog     # Start logging

    # Check if running as SYSTEM or Administrator (required for UEFI checks)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $isElevated = $identity.User.Value -eq "S-1-5-18" -or ([Security.Principal.WindowsPrincipal]$identity).IsInRole(544)
    if ($isElevated) {

        # Check if Secure Boot is enabled
        $SecureBootEnabled = Test-SecureBootEnabled
        $Summary['SecureBoot'] = if ($SecureBootEnabled) { "Enabled" } else { "Disabled" }
        Write-Host "SecureBoot=$($Summary['SecureBoot'])"
        if (!$SecureBootEnabled) { $AllCompliant = $false }

        # Gather diagnostic info
        $diagnostics = Get-SecureBootDiagnostics
        foreach ($key in $diagnostics.Keys) {
            $Summary[$key] = $diagnostics[$key]
            Write-Host "$key=$($diagnostics[$key])"
        }
    }
    else { Write-Error "Not running as SYSTEM or Admin"; $AllCompliant = $false }
}
catch {
    Write-Error "Unexpected error: $_"
    $AllCompliant = $false
}
finally {
    # End logging and collect the logs from memory to return to Intune, also save to log folder
    $Log = Invoke-TboneTinyLog -mode Stop -Name "$(('Detect','Remediate')[$RemediateMode])-$ScriptName" -LogPath $LogPath

    # Build result message and exit
    $Status = if ($RemediateMode) { ('Remediation failed','Remediated')[$AllCompliant] } else { ('Non-Compliant','Compliant')[$AllCompliant] }
    Write-Output "$Status - $Log"
    Exit ([int](-not $AllCompliant))
}
#endregion


