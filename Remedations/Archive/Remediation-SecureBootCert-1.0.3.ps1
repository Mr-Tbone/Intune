<#PSScriptInfo
.VERSION        1.0.3
.AUTHOR         @MrTbone_se (T-bone Granheden)
.GUID           feedbeef-beef-4dad-beef-85924e86a608
.COPYRIGHT      (c) 2026 T-bone Granheden. MIT License - free to use with attribution.
.TAGS           Intune Graph PrimaryUser DeviceManagement MicrosoftGraph Azure
.LICENSEURI     https://opensource.org/licenses/MIT
.PROJECTURI     https://github.com/Mr-Tbone/Intune
.RELEASENOTES
    1.0.0 2026-01-08 Initial Build
    1.0.1 2026-01-09 Patch Remediate Secure Boot Certificates
    1.0.2 2026-01-09 fix redundant reg read
    1.0.3 2026-01-14 fix detection bugs
#>

<#
.SYNOPSIS
    Script for Intune Remediation to both detect and remediate if Secure Boot Certificate is old and need to be updated to Secure Boot CA 2023
 
.DESCRIPTION
    The script detects and remediates regkeys and other settings required for Secure Boot CA 2023 certificate to be deployed.
    The script is both for detect and remediate and can self detect if running as detect or remediate based the Intune assigned scriptname
    The script invoke logging in the start and send the logs to Intune after it is done. It will also save a log on disk for troubleshooting.

.NOTES
    Please feel free to use this, but make sure to credit @MrTbone_se as the original author

.LINK
    https://tbone.se
#>

#region ---------------------------------------------------[Modifiable Parameters and Defaults]------------------------------------
$ScriptName = "Remediate Secure Boot Certificate"                           # Name of the script (Used for log file name)
$LogPath    = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"   # Path to save logs (Default Intune log path)

# Required KBs for Secure Boot CA 2023 (informational check)
$requiredKBs = @("KB5025885", "KB5027215", "KB5028185")

# Registry keys to READ for status checking (set by Windows after update)
$registryKeysStatus = @(
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"; Key = "UEFICA2023Status";         Description = "Update status";  ExpectedValue = "Updated" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"; Key = "WindowsUEFICA2023Capable"; Description = "Capable state";  ExpectedValue = 2 }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"; Key = "UEFICA2023Error";          Description = "Error code";     ExpectedValue = $null }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"; Key = "UEFICA2023ErrorEvent";     Description = "Error event ID"; ExpectedValue = $null }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot";           Key = "AvailableUpdates";         Description = "Update trigger"; ExpectedValue = $null }
)

# Registry key to SET for triggering update (remediate mode) - 0x200 = Phase 2 opt-in
$registrySettingsRemediate = @(
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"; Key = "AvailableUpdates"; Value = 0x200; Type = "DWord" }
)
#endregion
#region ---------------------------------------------------[Set global script settings]--------------------------------------------
$RemediateMode  = $MyInvocation.ScriptName -like "*Remediate*"              # Auto-detect mode based on script name
$AllCompliant   = $true                                                     # Assume compliant until a check fails
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
function Read-RegValue {
<#
.SYNOPSIS
    Read a registry value and return the value, or $null if not found
.DESCRIPTION
    Reads a single registry value from the specified path and key.
    Returns $null if the path or key doesn't exist, without throwing errors.
.NOTES
    Version: 1.0.0
    Author:  @MrTbone_se (T-bone Granheden)
    Releasenotes:
        2026-01-09 - Initial release
#>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Key
    )
    try {
        if (!(Test-Path $Path)) { return $null }
        $value = (Get-ItemProperty -Path $Path -Name $Key -ErrorAction SilentlyContinue).$Key
        return $value
    } catch {
        return $null
    }
}
function Detect-SecureBootEnabled {
<#
.SYNOPSIS
    Detect if Secure Boot is enabled, returns $true or $false
.DESCRIPTION
    Detect if Secure Boot is enabled on the device using Confirm-SecureBootUEFI cmdlet.
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
function Remediate-RegValue {
<#
.SYNOPSIS
    Remediate by setting a registry value
.DESCRIPTION
    Remediate by setting a registry value, creates path and key if missing
.NOTES
    Version: 1.0.0
    Author:  @MrTbone_se (T-bone Granheden)
    Releasenotes:
        2026-01-08 - Initial release
#>
    param([hashtable]$S)
    try {
        if(!(Test-Path $S.Path)){
            New-Item -Path $S.Path -Force -ErrorAction Stop | Out-Null
            Write-Host "[NEW]Created path $($S.Path)"
        }
        $existingValue = Get-ItemProperty -Path $S.Path -Name $S.Key -EA SilentlyContinue | Select-object -Exp $S.Key -EA SilentlyContinue
        if ($null -eq $existingValue) {
            Write-Host "[NEW]Creating key $($S.Key)"
        }
        Set-ItemProperty -Path $S.Path -Name $S.Key -Value $S.Value -Type $S.Type -Force -ErrorAction Stop
        Write-Host "[SET]$($S.Path)\$($S.Key) = $($S.Value)"
        $true
    } catch {
        Write-Error "[ERR]Failed to set $($S.Path)\$($S.Key): $_"
        $false
    }
}
function Detect-SecureBootCA2023 {
<#
.SYNOPSIS
    Check if Secure Boot CA 2023 certificate is present in UEFI DB (informational)
.NOTES
    Version: 1.0.1
    Author:  @MrTbone_se (T-bone Granheden)
#>
    try {
        $db = Get-SecureBootUEFI -Name db -EA Stop
        if ([System.Text.Encoding]::ASCII.GetString($db.Bytes) -match "Windows UEFI CA 2023") {
            Write-Host "[OK]CA 2023 found in UEFI DB"
        } else { Write-Warning "[INFO]CA 2023 not in UEFI DB yet" }
    } catch { Write-Warning "[INFO]Unable to read UEFI DB: $_" }
}
function Detect-TPMEvent1808 {
<#
.SYNOPSIS
    Detect if TPM-WMI Event ID 1808 is present in System event log
.NOTES
    Version: 1.0.1
    Author:  @MrTbone_se (T-bone Granheden)
#>
    try {
        $latest = Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='TPM-WMI';ID=1808} -MaxEvents 1 -EA SilentlyContinue
        if ($latest) { Write-Host "[OK]TPM Event 1808 found ($($latest.TimeCreated))" }
        else { Write-Warning "[INFO]TPM Event 1808 not found" }
    } catch { Write-Warning "[INFO]TPM Event 1808 query failed: $_" }
}
function Detect-RequiredKB {
<#
.SYNOPSIS
    Check if Secure Boot CA 2023 related KBs are installed (informational)
.NOTES
    Version: 1.0.1
    Author:  @MrTbone_se (T-bone Granheden)
#>
    param([string[]]$KBs = @())
    $installed = Get-HotFix -EA SilentlyContinue | Where-Object { $KBs -contains $_.HotFixID }
    if ($installed) { Write-Host "[OK]KB found: $($installed.HotFixID -join ', ')" }
    else { Write-Warning "[INFO]KB not explicitly found - may be in cumulative update" }
}
#endregion
#region -------------------------------------------------[Script Executions]--------------------------------------------------
try {
    Invoke-TboneTinyLog     # Start logging

    # UEFI cmdlets require 64-bit PowerShell
    if ([IntPtr]::Size -ne 8) {
        Write-Error "Script requires 64-bit PowerShell (running $([IntPtr]::Size * 8)-bit)"
        $AllCompliant = $false
    }
    # Check if running as SYSTEM or Administrator (required for UEFI checks)
    elseif (-not (([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq "S-1-5-18") -or ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(544))) {
        Write-Error "Not running as SYSTEM or Admin"
        $AllCompliant = $false
    }
    else {

        # Check if Secure Boot is enabled (If not, it cannot be remediated - skip remaining checks)
        $SecureBootEnabled = Detect-SecureBootEnabled
        if (!$SecureBootEnabled) { 
            Write-Warning "Secure Boot is disabled - cannot proceed with CA 2023 update"
            $AllCompliant = $false 
        }
        else {
            # Read current status values - Array indexes: [0]=Status, [1]=Capable, [2]=Error, [3]=ErrorEvent, [4]=AvailableUpdates
            $statusValue = Read-RegValue -Path $registryKeysStatus[0].Path -Key $registryKeysStatus[0].Key
            $capableValue = Read-RegValue -Path $registryKeysStatus[1].Path -Key $registryKeysStatus[1].Key
            
            # Determine state based on registry key value in UEFICA2023Status
            switch ($statusValue) {
                "Updated" {
                    if ($capableValue -eq 2) {
                        # EARLY EXIT - Update is complete
                        Write-Host "Secure Boot CA 2023 update complete (Status=Updated, Capable=2)"
                    } else {
                        # Status says Updated but Capable is not 2 - unusual state
                        Write-Warning "UEFICA2023Status=Updated but Capable=$capableValue (expected 2)"
                        $AllCompliant = $false
                    }
                }
                "Staged" {
                    # Update is staged, pending reboot - report COMPLIANT
                    Write-Host "UEFICA2023Status=Staged - pending reboot (Compliant)"
                }
                "Failed" {
                    # Update failed - get error details
                    $errorCode = Read-RegValue -Path $registryKeysStatus[2].Path -Key $registryKeysStatus[2].Key
                    $errorEvent = Read-RegValue -Path $registryKeysStatus[3].Path -Key $registryKeysStatus[3].Key
                    $errHex = if ($null -ne $errorCode) { "0x$([Convert]::ToString($errorCode, 16))" } else { "N/A" }
                    Write-Error "UEFICA2023Status=Failed! Error=$errHex, EventID=$errorEvent"
                    $AllCompliant = $false
                }
                default {
                    # Status not set or unknown - check trigger
                    $currentValue = Read-RegValue -Path $registryKeysStatus[4].Path -Key $registryKeysStatus[4].Key
                    $triggerBit = $registrySettingsRemediate[0].Value
                    $alreadyTriggered = ($null -ne $currentValue) -and (([int]$currentValue -band $triggerBit) -eq $triggerBit)
                    
                    if ($alreadyTriggered) {
                        # Trigger already set - report COMPLIANT
                        Write-Host "AvailableUpdates=0x$([Convert]::ToString($currentValue, 16)) - pending reboot (Compliant)"
                    }
                    elseif ($RemediateMode) {
                        # Set the trigger
                        foreach ($trigger in $registrySettingsRemediate) {
                            if (!(Remediate-RegValue -S $trigger)) { $AllCompliant = $false }
                        }
                        Write-Host "Reboot required to complete Secure Boot CA 2023 update"
                    }
                    else {
                        # Detect mode - gather diagnostics and report non-compliant
                        Write-Warning "UEFICA2023Status=$statusValue, AvailableUpdates=$currentValue - needs remediation"
                        Detect-RequiredKB -KBs $requiredKBs
                        Detect-SecureBootCA2023
                        Detect-TPMEvent1808
                        $AllCompliant = $false
                    }
                }
            }
        }
    }
}
catch {
    Write-Error "Unexpected error: $_"
    $AllCompliant = $false
}
finally {
    # End logging and collect the logs from memory to return to Intune, also save to log folder
    $Log = Invoke-TboneTinyLog -mode Stop -Name "$(('Detect','Remediate')[$RemediateMode])-$ScriptName" -LogPath $LogPath

    # Return log results and exit code to Intune
    switch ($RemediateMode) {
        $true { # Return remediate results
            if ($AllCompliant) {write-output "Remediated - $Log";Exit 0}
            else {write-output "Remediation failed - $Log";Exit 1}
        }
        default { # Return detect results
            if ($AllCompliant) {write-output "Compliant - $Log";Exit 0}
            else {write-output "Non-Compliant - $Log";Exit 1}
        }
    }
}
#endregion
