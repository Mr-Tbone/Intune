<#
.SYNOPSIS
    Script for Intune to configure Usersettings in Onedrive  
 
.DESCRIPTION
    This script will configure Onedrive settings in Onedrive for the User
    Settings are collected from https://docs.microsoft.com/en-us/onedrive/use-group-policy
    The script is designed to be deployed with Microsoft Intune Management Extention
    It will return True if success and false if unsuccessfull configuration of the settings.
    
.EXAMPLE
   .\Intune-OnedriveUser.ps1
    Will configure onedrive for the executing user with settings in the modifyable region. 

.PARAMETER Variable1
    This parameter accepts... 

.PARAMETER Variable2
    This parameter accepts... 

.NOTES
    Written by Torbjörn Granheden Coligo AB
    torbjorn.granheden@coligo.se

#>

#region ---------------------------------------------------[Set script requirements]-----------------------------------------------
#
#Requires -Version 3.0
#endregion

#region ---------------------------------------------------[Modifyable Parameters and defaults]------------------------------------

# Set value to $null for "not configured", then script will not write the setting to the client
$DisablePersonalSync =    0     #Prevent users from synchronizing personal OneDrive accounts (1 Enable, 0 Disable)
$UploadBandwidthLimit =   $null #Set the maximum upload bandwidth that OneDrive.exe uses (value between 1-99 in Percent)
$EnableAllOcsiClients =   1     #Coauthoring and in-app sharing for Office files (1 Enable, 0 Disable)
$EnableEnterpriseUpdate = 0     #Delay updating OneDrive.exe until the second release wave (1 Enable, 0 Disable)
$EnableHoldTheFile =      1     #Users can choose how to handle Office files in conflict (1 Enable, 0 Disable)
$DownloadBandwidthLimit = $null #Set the maximum download bandwidth that OneDrive.exe uses (value between 1-99 in Percent)
$DisableTutorial =        1     #Prevent users from seeing the tutorial in the OneDrive Sign in Experience (1 Enable, 0 Disable)
$EnableADAL =             1     #Enable Adal Modern authentication (1 Enable, 0 Disable)

#Log settings
$Global:LogEnabled = $True      #Creates a log file for troubleshooting
$Global:GUILogEnabled = $False  #$true for test of script in manual execution
$logPath = [environment]::GetEnvironmentVariable("temp","user")      # puts log in user temp directory

#endregion

#region ---------------------------------------------------[Set global script settings]--------------------------------------------
Set-StrictMode -Version Latest
#endregion

#region ---------------------------------------------------[Static Variables]------------------------------------------------------
#Log File Info
$startTime = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$logFile = $LogPath + "\OnedriveUser" + $startTime + ".log"
$result = $True
#endregion

#region ---------------------------------------------------[Import Modules and Extensions]-----------------------------------------
#endregion

#region ---------------------------------------------------[Functions]------------------------------------------------------------

Function LogWrite {
    Param(
        $logfile = "$logfile",
        [validateset("Info", "Warning", "Error")]$type = "Info",
        [string]$Logstring
    )
    Begin { }
    Process {
        If ($Global:LogEnabled) {
            Try {
                Add-content $Logfile -value "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') - $type - $logstring"
                if ($Global:GUILogEnabled) {
                    if ($type -eq "Info") {$foreGroundColor = "Green"}
                    elseif ($type -eq "Warning") {$foreGroundColor = "Cyan"}
                    elseif ($type -eq "Error") {$foreGroundColor = "Red"}
                    Write-Host $(Get-Date -Format 'dd-MM-yy yy HH:mm:ss') - $logstring -ForegroundColor $foreGroundColor
                }
            }    
            Catch {
                Write-Host $(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') - $_ -ForegroundColor Cyan
                Break
            }
        }
    }
    End { }
}

#endregion

#region ---------------------------------------------------[[Script Execution]------------------------------------------------------
logwrite -Logstring "Starting script" -type Info

$registryPath = "HKCU:\SOFTWARE\Microsoft\OneDrive"
IF(!(Test-Path $registryPath)) {
    logwrite -Logstring "Regkey for Onedrive $registryPath does not exist, trying to create" -type Info
    try{
        New-Item -Path $registryPath -Force | Out-Null
        logwrite -Logstring "Regkey for Onedrive $registryPath create success" -type Info}
    Catch{
        logwrite -Logstring "Regkey for Onedrive $registryPath create Failed" -type Error
        $result = $false
        logwrite -Logstring "Regkey for Onedrive $registryPath cannot be created, script ends" -type Error
        return $result}
    }
else
{logwrite -Logstring "Regkey for Onedrive $registryPath alredy exists" -type Info}

$registry_list = New-Object System.Collections.ArrayList;
# Use the Add() function to add records.  The [void] type is here to make it silent.
if (![string]::IsNullOrEmpty($DisablePersonalSync))
{[void]$registry_list.Add(@{Value='DisablePersonalSync';Path=$registryPath;Key='DisablePersonalSync';Type="DWORD";Data=$DisablePersonalSync})}
if (![string]::IsNullOrEmpty($UploadBandwidthLimit))
{[void]$registry_list.Add(@{Value='UploadBandwidthLimit';Path=$registryPath;Key='UploadBandwidthLimit';Type="DWORD";Data=$UploadBandwidthLimit})}
if (![string]::IsNullOrEmpty($EnableAllOcsiClients))
{[void]$registry_list.Add(@{Value='EnableAllOcsiClients';Path=$registryPath;Key='EnableAllOcsiClients';Type="DWORD";Data=$EnableAllOcsiClients})}
if (![string]::IsNullOrEmpty($EnableEnterpriseUpdate))
{[void]$registry_list.Add(@{Value='EnableEnterpriseUpdate';Path=$registryPath;Key='EnableEnterpriseUpdate';Type="DWORD";Data=$EnableEnterpriseUpdate})}
if (![string]::IsNullOrEmpty($EnableHoldTheFile))
{[void]$registry_list.Add(@{Value='EnableHoldTheFile';Path=$registryPath;Key='EnableHoldTheFile';Type="DWORD";Data=$EnableHoldTheFile})}
if (![string]::IsNullOrEmpty($DownloadBandwidthLimit))
{[void]$registry_list.Add(@{Value='DownloadBandwidthLimit';Path=$registryPath;Key='DownloadBandwidthLimit';Type="DWORD";Data=$DownloadBandwidthLimit})}
if (![string]::IsNullOrEmpty($DisableTutorial))
{[void]$registry_list.Add(@{Value='DisableTutorial';Path=$registryPath;Key='DisableTutorial';Type="DWORD";Data=$DisableTutorial})}
if (![string]::IsNullOrEmpty($EnableADAL))
{[void]$registry_list.Add(@{Value='EnableADAL';Path=$registryPath;Key='EnableADAL';Type="DWORD";Data=$EnableADAL})}


ForEach ($RegSetting in $registry_list){
    $RegPath = $RegSetting.Path
    $regKey = $RegSetting.Key
    $RegData = $Regsetting.Data
    $RegType = $Regsetting.Type
    logwrite -Logstring "Regkey for Onedrive $RegPath\$regkey with value $RegData and type $RegType will be created" -type Info
    try{
        New-ItemProperty $RegPath -Name $RegKey -Value $RegData -propertytype $RegType -Force -ErrorAction Continue | Out-Null
        logwrite -Logstring "Regkey for Onedrive $RegPath\$regkey with value $RegData and type $RegType create succeded" -type Info
        }
    catch{
        logwrite -Logstring "Regkey for Onedrive $RegPath\$regkey with value $RegData and type $RegType create Failed" -type Error
        $result = $false}
    }

Set-StrictMode -Off
logwrite -Logstring "Script finished" -type info
return $result
#endregion