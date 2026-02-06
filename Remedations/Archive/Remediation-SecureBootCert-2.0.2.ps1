<#PSScriptInfo
.VERSION        2.0.2
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
    1.0.4 2026-01-20 Fixed a syntax error
    1.0.5 2026-01-28 Changed AvailableUpdates to 0x340 to include DB, Boot Manager, and SVN updates
    1.0.6 2026-01-28 Added comprehensive system diagnostics for troubleshooting failed or non-compliant devices
    1.0.7 2026-01-28 Fixed $isElevated variable definition for proper output gating in finally block
    2.0.0 2026-01-30 Major update to collect diagnostics better and faster
    2.0.1 2026-01-30 Fixed scriptmode detection
    2.0.2 2026-01-30 fix small cosmetic in logs
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

# Registry key to SET for triggering update (remediate mode)
# 0x340 is a binary combination of 0x40 (DB update) + 0x100 (Boot Manager update) + 0x200 (SVN firmware update)
# 0x5944 is a binary combination to update ALL. It is required by some devices but also more larger risk of failures.
$registrySettingsRemediate = @(
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"; Key = "AvailableUpdates"; Value = 0x5944; Type = "DWord" }
)
$RemediateTaskName = "\Microsoft\Windows\PI\Secure-Boot-Update"
# Registry keys to READ for diagnosticsi (Most set by Windows and should not be changed)
$registryKeysStatus = @(
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"; Key = "UEFICA2023Status";         Description = "Update status";  ExpectedValue = "Updated" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"; Key = "WindowsUEFICA2023Capable"; Description = "Capable state";  ExpectedValue = 2 }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"; Key = "UEFICA2023Error";          Description = "Error code";     ExpectedValue = $null }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"; Key = "UEFICA2023ErrorEvent";     Description = "Error event ID"; ExpectedValue = $null }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot";           Key = "AvailableUpdates";         Description = "Update trigger"; ExpectedValue = $null }
)
# Os Versions and the required July patch level to be compliant with Secure Boot Update
$OSversions = @(
    @{ Name='Insider'; Build=26200; Patch=0 }
    @{ Name='24H2'; Build=26100; Patch=1150 }
    @{ Name='23H2'; Build=22631; Patch=3880 }
    @{ Name='22H2'; Build=22621; Patch=3880 }
    @{ Name='21H2'; Build=22000; Patch=3079 }
    @{ Name='22H2(Win10)'; Build=19045; Patch=4651 }
    @{ Name='21H2(Win10)'; Build=19044; Patch=4651 }
    @{ Name='1809(LTSC)'; Build=17763; Patch=6054 }
    @{ Name='1609(LTSC)'; Build=14393; Patch=7259 }
)
<# Saved for future development
$AvailableUpdateFlags = @{
    0x0002 = '0x2:DBX update (apply latest revocations)'
    0x0004 = '0x4:KEK update (add KEK 2K CA 2023)'
    0x0008 = '0x8:Unknown'
    0x0010 = '0x10:Unknown'
    0x0020 = '0x20:SkuSiPolicy update (VBS anti-rollback)'
    0x0040 = '0x40:DB update (add Windows UEFI CA 2023)'
    0x0080 = '0x80:DBX revocation (add Windows PCA 2011 to DBX)'
    0x0100 = '0x100:Install 2023 BootMgr (PCA2023 chain)'
    0x0200 = '0x200:SVN update (anti-rollback counter)'
    0x0340 = '0x340:Update DB, BootMgr and SVN'
    0x0400 = '0x400:SBAT update (firmware targeting)'
    0x0800 = '0x800:Option ROM CA 2023 -> DB'
    0x1000 = '0x1000:Microsoft UEFI CA 2023 -> DB'
    0x4000 = '0x4000:Post reboot stage during BootMgr update'
    0x4100 = '0x4100:Reboot required'
    0x5944 = '0x5944:Update all relevant flags'
    # Add more flags if known here
}
#>
#endregion
#region ---------------------------------------------------[Set global script settings]--------------------------------------------
[string]$ExecutionMode = switch -Wildcard (Split-Path $PSCommandPath -Leaf) {
    "*Detect*"      { "Detection"; break }      # Script running as detection script
    "*remediate*"   { "Remediation"; break }    # Script running as remediation script
    default         { "Standalone" }            # Script running standalone
}
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
function Test-Prerequisites {
<#
.SYNOPSIS
    Validate script prerequisites (64-bit PowerShell and elevated privileges).
.DESCRIPTION
    Checks for PowerShell prerequisites and return $true if all is good
    Use for checking admin, system, bitness, and PowerShell version requirements.
.NOTES
Version: 1.0.0
Author:  @MrTbone_se (T-bone Granheden)
Releasenotes:
    2026-01-09 - Initial release
#>
    param (
        [Parameter(Mandatory=$false, HelpMessage="Require the script to be run with elevated privileges (Administrator or SYSTEM)")]
        [switch]$RequireElevated,
        [Parameter(Mandatory=$false, HelpMessage="Require the script to be run as SYSTEM user (Admin is not enough)")]
        [switch]$RequireSystem,
        [Parameter(Mandatory=$false, HelpMessage="Require the script to be run in 64-bit PowerShell")]
        [switch]$Require64Bit,
        [Parameter(Mandatory=$false, HelpMessage="Require the script to be run in 32-bit PowerShell")]
        [switch]$Require32Bit,
        [Parameter(Mandatory=$false, HelpMessage="Minimum required PowerShell version (e.g., 7.1)")]
        [version]$RequirePsVersion,
        [Parameter(Mandatory=$false, HelpMessage="PowerShell version to exclude (for example if not supported on 7.1)")]
        [version]$ExcludePsVersion
    )
    $allGood = $true
    if ($Require64Bit) {
        if ([IntPtr]::Size -ne 8) {
            Write-Warning "Script requires 64-bit PowerShell (running $([IntPtr]::Size * 8)-bit)"
            $allGood = $false
        }
    }
    if ($Require32Bit) {
        if ([IntPtr]::Size -ne 4) {
            Write-Warning "Script requires 32-bit PowerShell (running $([IntPtr]::Size * 8)-bit)"
            $allGood = $false
        }
    }
    if ($RequireElevated) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $isElevated = $identity.User.Value -eq "S-1-5-18" -or ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isElevated) {
            Write-Warning "Not running as SYSTEM or Admin"
            $allGood = $false
        }
    }
    if ($RequireSystem) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $isSystem = $identity.User.Value -eq "S-1-5-18"
        if (-not $isSystem) {
            Write-Warning "Not running as SYSTEM"
            $allGood = $false
        }
    }
    if ($PSBoundParameters.ContainsKey('RequirePsVersion')) {
        if ($PSVersionTable.PSVersion -lt $RequirePsVersion) {
            Write-Warning "Script requires PowerShell version $RequirePsVersion or higher (running $($PSVersionTable.PSVersion))"
            $allGood = $false
        }
    }
    if ($PSBoundParameters.ContainsKey('ExcludePsVersion')) {
        if ($PSVersionTable.PSVersion -eq $ExcludePsVersion) {
            Write-Warning "Script cannot run in PowerShell version $ExcludePsVersion (currently running $($PSVersionTable.PSVersion))"
            $allGood = $false
        }
    }
    return $allGood
}
function Get-SecureBootDiagnostics {
    <#
.SYNOPSIS
    Gather diagnostic info to understand why Secure Boot may not be enabled
.DESCRIPTION
    Gathers info about firmware type, partition style, device model, BIOS version, TPM status and OS build.
    Require function Get-SecureBootCertSubjects
    Returns an ordered hashtable with the collected info.
.NOTES
    Version: 1.0.2
    Author:  @MrTbone_se (T-bone Granheden)
    Version History:
        2026-01-08 - Initial release
        2026-01-28 - Added better check for BIOS vs UEFI
        2026-01-29 - Added Certificates, regkeys and more to diagnostics
#>
    param(
        [Parameter(Mandatory=$false, HelpMessage="Array of hashtables describing registry keys to read. Each hashtable should contain: Path, Key, Description, ExpectedValue.")]
        [hashtable[]]$registrykeys = $null,
        [Parameter(Mandatory=$false, HelpMessage="Array of hashtables describing OS versions and required patch levels.")]
        [hashtable[]]$OSversions = $null        
    )
    $diag = [ordered]@{} #Initialize ordered dictionary
    try {
        # Get secureboot status and certificates
        Try{
            if(Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {$diag['SecureBootEnabled'] = "Enabled"}
            else {$diag['SecureBootEnabled'] = "Disabled"}
        }Catch{$diag['SecureBootEnabled'] = "Disabled"}
        $PKcerts = Get-SecureBootCertSubjects -Database pk
        if($PKcerts){$diag['SecureBootPK'] = ($PKcerts | ForEach-Object { if ($_.SignatureSubject -match 'CN=(.+?),') { $matches[1] } else { $_.SignatureSubject } }) -join '; '}
        $KEKcerts = Get-SecureBootCertSubjects -Database kek
        if($KEKcerts){$diag['SecureBootKEK'] = ($KEKcerts | ForEach-Object { if ($_.SignatureSubject -match 'CN=(.+?),') { $matches[1] } else { $_.SignatureSubject } }) -join '; '}
        $dbcerts = Get-SecureBootCertSubjects -Database db
        if($dbcerts){$diag['SecureBootDB'] = ($dbcerts | ForEach-Object { if ($_.SignatureSubject -match 'CN=(.+?),') { $matches[1] } else { $_.SignatureSubject } }) -join '; '}
        $diag['SecureBootDBHas2023'] = [bool] ($dbcerts | Where-Object { $_.SignatureSubject -match 'Windows UEFI CA 2023' })
        # Firmware info and versions
        $BootMode = bcdedit | Select-String "path.*efi" -ErrorAction SilentlyContinue
        $diag['FirmwareType'] = if ($null -eq $BootMode) { "BIOS" } elseif ($null -ne $BootMode) { "UEFI" } else { "Unknown" }
        $bios = Get-CimInstance Win32_BIOS -Property SMBIOSBIOSVersion,ReleaseDate -ErrorAction SilentlyContinue
        $diag['FirmwareVersion'] = if ($bios) { $bios.SMBIOSBIOSVersion } else { "Unknown" }
        $diag['FirmwareDate'] = if ($bios -and $bios.ReleaseDate) { $bios.ReleaseDate.ToString("yyyy-MM-dd") } else { "Unknown" }
        # TPM status and version
        $tpmWmi = Get-CimInstance -Namespace "Root\CIMv2\Security\MicrosoftTpm" -ClassName Win32_Tpm -ErrorAction SilentlyContinue
        $diag['TPMPresent'] = if ($tpmWmi) { $true } else { $false }
        $diag['TPMEnabled'] = if ($tpmWmi) { $tpmWmi.IsEnabled_InitialValue } else { "N/A" }
        $diag['TPMVersion'] = if ($tpmWmi -and $tpmWmi.SpecVersion) { $tpmWmi.SpecVersion.Split(",")[0].Trim() } else { "N/A" }
        # Get TPM events on the current update status: 1808 indicate success, 1801 indicate failure)
        $TPMevent = Get-WinEvent -FilterHashtable @{LogName = 'System'; ProviderName = 'Microsoft-Windows-TPM-WMI'; Id = @(1808,1801)} -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($TPMevent) {
            $shortMsg = ($TPMevent.Message -replace '\s+',' ') -replace '(.{200}).+','$1...'
            $diag['TPMEventlogStatus'] = "$($TPMevent.Id) - $($TPMevent.TimeCreated.ToString('s')) - $shortMsg"
        } else {$diag['TPMEventlogStatus'] = "No logs"}
        # Device hardware info and VM check
        $cs = Get-CimInstance Win32_ComputerSystem -Property Manufacturer,Model -ErrorAction SilentlyContinue
        $diag['HWMake'] = if ($cs) { $cs.Manufacturer } else { "Unknown" }
        $diag['HWModel'] = if ($cs) { $cs.Model } else { "Unknown" }
        $diag['HWIsVm'] = if ($cs -and $cs.Model -match "Virtual|VMware|VirtualBox|Hyper-V|QEMU|Parallels") { "Yes" } elseif ($cs) { "No" } else { "Unknown" }
        Try{$osdisk = Get-Disk -ErrorAction SilentlyContinue | Where-Object { $_.IsBoot -eq $true } | Select-Object -First 1}
        catch{$osdisk = $null}
        $diag['HWDiskType'] = if ($osDisk) { $osDisk.PartitionStyle } else { "Unknown" }
        # Determine current Windows build and Patch level
        $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
        $Build = if ($cv.CurrentBuildNumber) { try {[int]$cv.CurrentBuildNumber} catch { $null } } elseif ($cv.CurrentBuild) { try {[int]$cv.CurrentBuild} catch { $null } } else { $null }
        $Patch   = if ($null -ne $cv.UBR) { try {[int]$cv.UBR} catch { $null } } else { $null }
        $OSversionsSorted = $OSversions | Sort-Object { [int]$_.Build } -Descending
        $OSversion = $OSversionsSorted | Where-Object { ($Build -ne $null) -and ([int]$_.Build -le $Build) } | Select-Object -First 1
        if ($OSversion) {
            $diag['OSVersion'] = $OSversion['Name'] + " Version:" + $Build + "." + $Patch
            if ($OSversion['Patch'] -eq 0) { $osCompliant = $true }
            elseif ($null -ne $Patch -and $Patch -ge $OSversion['Patch']) { $osCompliant = $true }
            else { $osCompliant = $false }
            $diag['OSJulySecureBootPatch'] = [bool]$osCompliant
        } else {
            $diag['OSVersion'] = 'Unknown' + " Version:" + $Build + "." + $Patch
            $diag['OSJulySecureBootPatch'] = "unknown"
        }
        # Loop provided registry keys and add each value to diagnostics
        if ($registrykeys -and $registrykeys.Count -gt 0) {
            foreach ($RegKey in $registrykeys) {
                try {
                    $val = Get-ItemPropertyvalue -Path $RegKey.Path -Name $RegKey.Key -ErrorAction SilentlyContinue
                    if ($val.gettype().name -eq "Int32") {$val = '0x{0:x}' -f $val}
                    $diag["Reg:$($RegKey.Key)"] = $val
                } catch {
                    $diag["Reg:$($RegKey.Key)"] = ""
                }
            }
        }
    }
    Catch { Write-Error "Diagnostics failed with error: $($_.Exception.Message)" }
    return $diag
}
function Get-SecureBootCertSubjects {
<#
.SYNOPSIS
    Parse Secure Boot database signatures and return them as objects
.DESCRIPTION
    Parses the EFI signature database (db) and returns an array of PSCustomObjects representing the signatures.
.NOTES
    Version: 1.0.0
    Author:  @MrTbone_se (T-bone Granheden)
#>
    param(
        [Parameter(Mandatory=$true, HelpMessage="Name of the Secure Boot database to parse")]
        [string]$Database
    )
    $db = (Get-SecureBootUEFI -Name $Database).Bytes
    $EFI_CERT_X509_GUID = [guid]"a5c059a1-94e4-4aa7-87b5-ab155c2bf072"
    $EFI_CERT_SHA256_GUID = [guid]"c1c41626-504c-4092-aca9-41f936934328"
    $signatures = @()
    for ($o = 0; $o -lt $db.Length; ) {
        $guid = [Guid][Byte[]]$db[$o..($o+15)]
        $signatureListSize = [BitConverter]::ToUInt32($db, $o+16)
        $signatureSize = [BitConverter]::ToUInt32($db, $o+24)
        $signatureCount = ($signatureListSize - 28) / $signatureSize
        $so = $o + 28
        for ($i = 0; $i -lt $signatureCount; $i++) {
            $signatureOwner = [Guid][Byte[]]$db[$so..($so+15)]
            if ($guid -eq $EFI_CERT_X509_GUID) {
                $certBytes = $db[($so+16)..($so+16+$signatureSize-1)]
                try {
                    $cert = if ($PSEdition -eq "Core") {
                        [System.Security.Cryptography.X509Certificates.X509Certificate]::new([Byte[]]$certBytes)
                    } else {
                        $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                        $c.Import([Byte[]]$certBytes)
                        $c
                    }
                    $signatures += [PSCustomObject]@{SignatureOwner=$signatureOwner; SignatureSubject=$cert.Subject; Signature=$cert; SignatureType=$guid}
                } catch {
                    $signatures += [PSCustomObject]@{SignatureOwner=$signatureOwner; SignatureSubject="Failed to parse cert"; Signature=$null; SignatureType=$guid}
                }
            } elseif ($guid -eq $EFI_CERT_SHA256_GUID) {
                $sha256Hash = ([Byte[]]$db[($so+16)..($so+47)] | ForEach-Object { $_.ToString('X2') }) -join ''
                $signatures += [PSCustomObject]@{SignatureOwner=$signatureOwner; Signature=$sha256Hash; SignatureType=$guid}
            } else { 
                $unknownData = [Byte[]]$db[($so+16)..($so+16+$signatureSize-1)]
                $signatures += [PSCustomObject]@{SignatureOwner=$signatureOwner; SignatureSubject="Unknown signature type"; Signature=$unknownData; SignatureType=$guid}
            }
            $so += $signatureSize
        }
        $o += $signatureListSize
    }
    return $signatures
}

#endregion
#region -------------------------------------------------[Script Executions]--------------------------------------------------
try {
    Invoke-TboneTinyLog     # Start logging
    # Test prerequisites
    $AllPreRec = Test-Prerequisites -RequireElevated -Require64Bit 
    if ($AllPreRec) {
        # Run diagnostics 
        $diagnostics = Get-SecureBootDiagnostics -registryKeys $registryKeysStatus -OSversions $OSversions

        # Use Diagnostics to determine the state and if remediation is needed
        if ($diagnostics -and $diagnostics.SecureBootEnabled) {
            # Determine state based on registry key value in UEFICA2023Status
            switch ($diagnostics.'Reg:UEFICA2023Status') {
                "Updated" { 
                    # Updated and ready state
                    if ($diagnostics.'Reg:WindowsUEFICA2023Capable' -eq '0x2') {
                        Write-Host "Secure Boot CA 2023 update complete: (Status=$($diagnostics.'Reg:UEFICA2023Status'), Capable=$($diagnostics.'Reg:WindowsUEFICA2023Capable'))"
                        $AllCompliant = $true 
                    } 
                    # Updated but invalid state
                    else {
                        Write-Warning "Secure Boot in unexpected state: Status=$($diagnostics.'Reg:UEFICA2023Status') but Capable=$($diagnostics.'Reg:WindowsUEFICA2023Capable') (expected 2)"
                        $AllCompliant = $false
                    }
                }
                "InProgress" { 
                    # in-progress and waiting for reboot
                    if (($diagnostics.'Reg:AvailableUpdates' -band 0x4100) -eq 0x4100) {
                        Write-Warning "BootMgr stage pending reboot (AvailableUpdates=$($diagnostics.'Reg:AvailableUpdates'))."
                        $AllCompliant = $true 
                    } 
                    # in-progress and waiting for other tasks
                    else {
                        Write-Host "Update in progress (AvailableUpdates=$($diagnostics.'Reg:AvailableUpdates'))."
                        $AllCompliant = $true 
                    }
                }
                "NotStarted" {
                    # If trigger AvailableUpdates already set correct, let keep it compliant and let the system update
                    if (($diagnostics.'Reg:AvailableUpdates' -band $registrySettingsRemediate[0].Value) -eq $registrySettingsRemediate[0].Value) {
                        Write-Host "Trigger present (AvailableUpdates=$($diagnostics.'Reg:AvailableUpdates')). waiting for task or reboot."
                        $AllCompliant = $true 
                    }
                    # If running in Remediation, set the trigger AvailableUpdates and start schedule task
                    elseif ($ExecutionMode -eq 'Remediation') {
                        try {
                            # Set trigger AvailableUpdates in registry
                            try{
                                Set-ItemProperty -Path $registrySettingsRemediate[0].Path -Name $registrySettingsRemediate[0].Key -Value $registrySettingsRemediate[0].Value -Type $registrySettingsRemediate[0].Type
                                Write-Host ("Secure Boot Registry AvailableUpdates set to 0x{0:X}" -f $registrySettingsRemediate[0].Value)
                            }catch {Write-Error "Failed to set registry trigger: $_"}
                            # Start the scheduled task to trigger the process
                            try {
                                Start-ScheduledTask -TaskName "$RemediateTaskName"
                                Write-Host 'Secure Boot update Schedule Task triggered. A reboot may be required.'
                            } catch {Write-Error "Secure Boot update Schedule Task Failed to start: $_"}
                            $AllCompliant = $true
                        }
                        Catch {
                            Write-Error "Remediation failed with error: $_"
                            $AllCompliant = $false
                        }
                    } 
                    # If Running in detect mode, only report Non compliant
                    else {
                        Write-Warning "Update not started UEFICA2023Status=$($diagnostics.'Reg:UEFICA2023Status') and trigger AvailableUpdates=$($diagnostics.'Reg:AvailableUpdates') - needs remediation."
                        $AllCompliant = $false
                    }
                }
                # catch if UEFICA2023Status has any other unknown states
                default {
                        Write-Warning "Unknown State: UEFICA2023Status=$($diagnostics.'Reg:UEFICA2023Status') AvailableUpdates=$($diagnostics.'Reg:AvailableUpdates'), needs investigation."
                        $AllCompliant = $false
                    }
                }
            }
        else {
            Write-Warning "Secure Boot is disabled - cannot proceed with CA 2023 update"
            $AllCompliant = $false
        }
    } else {
        write-error "Prerequisites not met: Script requires elevated privileges and 64-bit PowerShell."
        $AllCompliant = $false
    }
}
catch {
    Write-Error "Unexpected error: $_"
    $AllCompliant = $false
}
finally {
    # Output diagnostics information
    if ($diagnostics) {foreach ($key in $diagnostics.Keys) {Write-Host "$key=$($diagnostics[$key])"}}
    # End logging and collect logs from memory
    $Log = Invoke-TboneTinyLog -mode Stop -Name "$($ExecutionMode)-$ScriptName" -LogPath $LogPath
    
    # Return results and exit code
    switch ($ExecutionMode) {
        "Detection" {
            if ($AllCompliant) { Write-Output "Compliant - $Log"; Exit 0 }
            else { Write-Output "Non-Compliant - $Log"; Exit 1 }
        }
        "Remediation" {
            if ($AllCompliant) { Write-Output "Remediated - $Log"; Exit 0 }
            else { Write-Output "Remediation failed - $Log"; Exit 1 }
        }
        "Standalone" {
            if ($AllCompliant) { Write-Output "Compliant"}
            else { Write-Output "Non-Compliant"}
        }
    }
}
#endregion



