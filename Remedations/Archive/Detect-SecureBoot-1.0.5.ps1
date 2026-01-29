<#PSScriptInfo
.VERSION        1.0.5
.GUID           feedbeef-beef-4dad-beef-88c9893120b1
.AUTHOR         @MrTbone_se (T-bone Granheden)
.COPYRIGHT      (c) 2026 T-bone Granheden. MIT License - free to use with attribution.
.TAGS           Intune Graph PrimaryUser DeviceManagement MicrosoftGraph Azure
.LICENSEURI     https://opensource.org/licenses/MIT
.PROJECTURI     https://github.com/Mr-Tbone/Intune
.RELEASENOTES
    1.0.0 2026-01-08 Initial Build
    1.0.1 2026-01-09 Fixed header to comply with best practice
    1.0.2 2026-01-09 Patch Remediate Secure Boot Certificates
    1.0.3 2026-01-28 Improved error handling with -ErrorAction SilentlyContinue for WMI/CIM cmdlets
    1.0.4 2026-01-28 Patch the detectionss to not generate hard fails
    1.0.5 2026-01-28 Improved firmware type detection using PEFirmwareType registry value
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
[string]$ExecutionMode = switch -Wildcard (Split-Path $PSCommandPath -Leaf) {
    "*detect*"      { "Detection"; break }      # Script running as detection script
    "*remediate*"   { "Remediation"; break }    # Script running as remediation script
    default         { "Standalone" }            # Script running standalone
}
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
function Get-SecureBootDiagnostics {
    <#
.SYNOPSIS
    Gather diagnostic info to understand why Secure Boot may not be enabled
.DESCRIPTION
    Gathers info about firmware type, partition style, device model, BIOS version, TPM status and OS build.
    Returns an ordered hashtable with the collected info.
.NOTES
    Version: 1.0.1
    Author:  @MrTbone_se (T-bone Granheden)
    Version History:
        2026-01-08 - Initial release
        2026-01-28 - Added better check for BIOS vs UEFI
        2026-01-29 - Added Certificates and regkeys to diagnostics
#>
    $diag = [ordered]@{} #Initialize ordered dictionary
    # Detect firmware type using bcdedit (UEFI/BIOS) and get more info on firmare
    $BootMode = bcdedit | Select-String "path.*efi" -ErrorAction SilentlyContinue
    $diag['Firmware'] = if ($BootMode) { "UEFI" } elseif ($BootMode -eq $null) { "BIOS" } else { "Unknown" }
    $bios = Get-CimInstance Win32_BIOS -Property SMBIOSBIOSVersion,ReleaseDate -ErrorAction SilentlyContinue
    $diag['FirmwareVersion'] = if ($bios) { $bios.SMBIOSBIOSVersion } else { "Unknown" }
    $diag['FirmwareDate'] = if ($bios -and $bios.ReleaseDate) { $bios.ReleaseDate.ToString("yyyy-MM-dd") } else { "Unknown" }
    # Get secureboot certificates
    $PKcerts = Get-SecureBootCertSubjects -Database pk
    if($PKcerts){$diag['SecureBootPK'] = ($PKcerts | ForEach-Object { if ($_.SignatureSubject -match 'CN=(.+?),') { $matches[1] } else { $_.SignatureSubject } }) -join '; '}
    $KEKcerts = Get-SecureBootCertSubjects -Database kek
    if($KEKcerts){$diag['SecureBootKEK'] = ($KEKcerts | ForEach-Object { if ($_.SignatureSubject -match 'CN=(.+?),') { $matches[1] } else { $_.SignatureSubject } }) -join '; '}
    $dbcerts = Get-SecureBootCertSubjects -Database db
    if($dbcerts){$diag['SecureBootDB'] = ($dbcerts | ForEach-Object { if ($_.SignatureSubject -match 'CN=(.+?),') { $matches[1] } else { $_.SignatureSubject } }) -join '; '}
    $diag['SecureBootDBHas2023'] = [bool] ($dbcerts | Where-Object { $_.SignatureSubject -match 'Windows UEFI CA 2023' })
    # Device info + VM check
    $cs = Get-CimInstance Win32_ComputerSystem -Property Manufacturer,Model -ErrorAction SilentlyContinue
    $diag['Manufacturer'] = if ($cs) { $cs.Manufacturer } else { "Unknown" }
    $diag['Model'] = if ($cs) { $cs.Model } else { "Unknown" }
    $diag['IsVirtual'] = if ($cs -and $cs.Model -match "Virtual|VMware|VirtualBox|Hyper-V|QEMU|Parallels") { "Yes" } elseif ($cs) { "No" } else { "Unknown" }
    # Disk partition style (GPT = UEFI capable, MBR = Legacy)
    $osDisk = Get-Disk -ErrorAction SilentlyContinue | Where-Object { $_.IsBoot -eq $true } | Select-Object -First 1
    $diag['DiskType'] = if ($osDisk) { $osDisk.PartitionStyle } else { "Unknown" }    # TPM status and version
    # TPM status and version
    $tpmWmi = Get-CimInstance -Namespace "Root\CIMv2\Security\MicrosoftTpm" -ClassName Win32_Tpm -ErrorAction SilentlyContinue
    $diag['TPMPresent'] = if ($tpmWmi) { $true } else { $false }
    $diag['TPMEnabled'] = if ($tpmWmi) { $tpmWmi.IsEnabled_InitialValue } else { "N/A" }
    $diag['TPMVersion'] = if ($tpmWmi -and $tpmWmi.SpecVersion) { $tpmWmi.SpecVersion.Split(",")[0].Trim() } else { "N/A" }
    # OS Version
    $osVer = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
    $diag['OSRelease'] = if ($osVer.DisplayVersion) { $osVer.DisplayVersion + " / " + [System.Environment]::OSVersion.Version.Build } else { $osVer.ReleaseId + " / " + [System.Environment]::OSVersion.Version.Build }
    # Registry key for status, Updated = Update completed, Staged = Pending reboot, Failed = Update failed
    if ($value = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name "UEFICA2023Status" -ErrorAction SilentlyContinue).UEFICA2023Status) { $diag['RegKeyUEFICA2023Status'] = $value } else { $diag['RegKeyUEFICA2023Status'] = $null }
    # Registry key for capability, 0 = Not Capable, 1 = Partly Capable, 2 = Fully Capable 
    $diag['Regkey-WindowsUEFICA2023Capable'] = switch ($value = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name "WindowsUEFICA2023Capable" -ErrorAction SilentlyContinue).WindowsUEFICA2023Capable) { 2 { "$value - Fully capable" } 1 { "$value - Partially capable" } 0 { "$value - Not capable" } default { if ($value) { "$value - Unknown capability level" } else { $null } } }
    # Registry key AvailableUpdates show the 
    $diag['Regkey-AvailableUpdates'] = if ($value = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name "AvailableUpdates" -ErrorAction SilentlyContinue).AvailableUpdates) { 
        $updateFlags = @{
        0x0002 = '0x2:DBX update (apply latest revocations)'
        0x0004 = '0x4:KEK update (add KEK 2K CA 2023)'
        0x0008 = '0x8:Unknown'
        0x0010 = '0x10:Unknown'
        0x0020 = '0x20:SkuSiPolicy update (VBS anti-rollback)'
        0x0040 = '0x40:DB update (add Windows UEFI CA 2023)'
        0x0080 = '0x80:DBX revocation (add Windows PCA 2011 to DBX)'
        0x0100 = '0x100:Install 2023 BootMgr (PCA2023 chain)'
        0x0200 = '0x200:SVN update (anti-rollback counter)'
        0x0400 = '0x400:SBAT update (firmware targeting)'
        0x0800 = '0x800:Option ROM CA 2023 -> DB'
        0x1000 = '0x1000:Microsoft UEFI CA 2023 -> DB'
        0x4000 = '0x4000:Post reboot stage during BootMgr update'
            # Add more flags here
        }
        $updates = @()
        $matched = 0
        foreach ($flag in $updateFlags.Keys | Sort-Object -Descending) {
            if (($value -band $flag) -eq $flag) { 
                $matched = $matched -bor $flag
                $updates += $updateFlags[$flag] 
            }
        }
        if ($matched -ne $value) { $updates += "Unknown update(s)" }
        $prefix = if ($updates.Count -gt 1) { "Combination of: " } else { "" }
        "0x$($value.ToString('X')) - $prefix$($updates -join ', ')"
    } else { $null }
    if ($value = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name "UEFICA2023Error" -ErrorAction SilentlyContinue).UEFICA2023Error) { $diag['Regkey-UEFICA2023Error'] = '0x' + $value.ToString('X') }
    if ($value = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name "UEFICA2023ErrorEvent" -ErrorAction SilentlyContinue).UEFICA2023ErrorEvent) { $diag['Regkey-UEFICA2023ErrorEvent'] = '0x' + $value.ToString('X') }
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
        [Parameter(Mandatory=$true)]
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
                $sha256Hash = ([Byte[]]$db[($so+16)..($so+47)] | % {$_.ToString('X2')}) -join ''
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

    # Check if running as SYSTEM or Administrator (required for UEFI checks)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $isElevated = $identity.User.Value -eq "S-1-5-18" -or ([Security.Principal.WindowsPrincipal]$identity).IsInRole(544)
    if ($isElevated) {

        # Check if Secure Boot is enabled
        try {if (-not (Confirm-SecureBootUEFI)) {Write-Warning "Secure Boot is disabled"; $AllCompliant = $false}}
        catch {Write-Error "Secure Boot not supported (Legacy BIOS): $_"; $AllCompliant = $false}
        $Summary['SecureBoot'] = if ($AllCompliant -eq $true) { "Enabled" } else { "Disabled" }
        Write-Host "SecureBoot=$($Summary['SecureBoot'])"
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
    # End logging and collect logs from memory
    $Log = Invoke-TboneTinyLog -mode Stop -Name "$($ExecutionMode)-$ScriptName" -LogPath $LogPath
    
    # Return results and exit code (only for SYSTEM context running as Intune remediation)
    if ($isElevated) {
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
                Write-Output "Completed - $Log"; Exit 0
            }
        }
    }
}
#endregion