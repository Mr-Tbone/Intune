<#
.SYNOPSIS
    Scritp for Intune to configure Computersettings in Onedrive  

.DESCRIPTION
    This script will configure Onedrive settings in Onedrive for the Computer
    Settings are collected from https://docs.microsoft.com/en-us/onedrive/use-group-policy
    The script is designed to be deployed with Microsoft Intune Management Extention
    It will return True if success and false if unsuccessfull configuration of the settings.
   
.EXAMPLE
   .\Intune-OnedriveComputer.ps1
    Will configure onedrive for the executing computer with settings in the modifyable region. 

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

$tenantID = "648f480a-ee3c-43b0-ad37-4223a62ca7e3"  #TenantID is found in Portal.azure.com under AAD properties

# Set value to $null for "not configured", then script will not write the setting to the client
$AllowTenantList =                    $Null     #Allow syncing OneDrive accounts for only specific organizations (Tenant Ids)
$BlockTenantList =                    $Null     #Block syncing OneDrive accounts for specific organizations (Tenant Ids)
$FilesOnDemandEnabled =               1         #Enable OneDrive Files On-Demand (1 Enable, 0 Disable)
$DeHydrateSyncedTeamSites =           1         #Migrate pre-existing team sites with OneDrive Files On-Demand (1 Enable, 0 Disable)
$PreventNetworkTrafficPreUserSingin = 0         #Prevent OneDrive from generating network traffic until the user signs in to OneDrive (1 Enable, 0 Disable)
$AutomaticUploadBandwidthPercentage = $Null     #Set the maximum percentage of upload bandwidth that OneDrive.exe uses (Value between 1-99 in Percent)
$SilentAccountConfig =                1         #Silently configure OneDrive using Windows 10 or domain credentials (1 Enable, 0 Disable)
$DiskSpaceCheckThresholdMB =          $Null     #Configure the maximum OneDrive size for downloading all files automatically (Value in MB)
$KFMOptInWithWizard =                 $null     #Prompt users to move Windows known folders to OneDrive (1 Enable, 0 Disable)
$KFMSilentOptIn =                     $tenantID #Silently move Windows known folders to OneDrive (Tenant ID)
$KFMSilentOptInWithNotification =     0         #Display a notification after successful redirection (1 Enable, 0 Disable)
$KFMBlockOptOut =                     1         #Prevent users from redirecting their Windows known folders to their PC (1 Enable, 0 Disable)
$KFMBlockOptIn =                      1         #Prevent users from moving their Windows known folders to OneDrive (1 Enable, 0 Disable)

#Log settings
$Global:LogEnabled = $True      #Creates a log file for troubleshooting
$Global:GUILogEnabled = $False  #$true for test of script in manual execution
$logPath = [environment]::GetEnvironmentVariable("temp","machine")      # puts log in computers temp directory

#endregion

#region ---------------------------------------------------[Set global script settings]--------------------------------------------
Set-StrictMode -Version Latest
#endregion

#region ---------------------------------------------------[Static Variables]------------------------------------------------------
#Log File Info
$startTime = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$logFile = $LogPath + "\OnedriveComputer" + $startTime + ".log"
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

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
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

if ([string]::IsNullOrEmpty($tenantID)){
    logwrite -Logstring "TenantID not available cannot configure some settings." -type warning}

$registry_list = New-Object System.Collections.ArrayList;
# Use the Add() function to add records.  The [void] type is here to make it silent.
if (![string]::IsNullOrEmpty($AllowTenantList) -And ![string]::IsNullOrEmpty($tenantID))
{[void]$registry_list.Add(@{Value='AllowTenantList';Path=$registryPath;Key='AllowTenantList';Type="string";Data=$AllowTenantList})}
if (![string]::IsNullOrEmpty($BlockTenantList) -And ![string]::IsNullOrEmpty($tenantID))
{[void]$registry_list.Add(@{Value='BlockTenantList';Path=$registryPath;Key='BlockTenantList';Type="string";Data=$BlockTenantList})}
if (![string]::IsNullOrEmpty($FilesOnDemandEnabled))
{[void]$registry_list.Add(@{Value='FilesOnDemandEnabled';Path=$registryPath;Key='FilesOnDemandEnabled';Type="DWORD";Data=$FilesOnDemandEnabled})}
if (![string]::IsNullOrEmpty($DeHydrateSyncedTeamSites))
{[void]$registry_list.Add(@{Value='DeHydrateSyncedTeamSites';Path=$registryPath;Key='DeHydrateSyncedTeamSites';Type="DWORD";Data=$DeHydrateSyncedTeamSites})}
if (![string]::IsNullOrEmpty($PreventNetworkTrafficPreUserSingin))
{[void]$registry_list.Add(@{Value='PreventNetworkTrafficPreUserSingin';Path=$registryPath;Key='PreventNetworkTrafficPreUserSingin';Type="DWORD";Data=$PreventNetworkTrafficPreUserSingin})}
if (![string]::IsNullOrEmpty($AutomaticUploadBandwidthPercentage))
{[void]$registry_list.Add(@{Value='AutomaticUploadBandwidthPercentage';Path=$registryPath;Key='AutomaticUploadBandwidthPercentage';Type="DWORD";Data=$AutomaticUploadBandwidthPercentage})}
if (![string]::IsNullOrEmpty($SilentAccountConfig))
{[void]$registry_list.Add(@{Value='SilentAccountConfig';Path=$registryPath;Key='SilentAccountConfig';Type="DWORD";Data=$SilentAccountConfig})}
if (![string]::IsNullOrEmpty($DiskSpaceCheckThresholdMB))
{[void]$registry_list.Add(@{Value='DiskSpaceCheckThresholdMB';Path=$registryPath;Key='DiskSpaceCheckThresholdMB';Type="DWORD";Data=$DiskSpaceCheckThresholdMB})}
if (![string]::IsNullOrEmpty($KFMOptInWithWizard))
{[void]$registry_list.Add(@{Value='KFMOptInWithWizard';Path=$registryPath;Key='KFMOptInWithWizard';Type="DWORD";Data=$KFMOptInWithWizard})}
if (![string]::IsNullOrEmpty($KFMSilentOptIn))
{[void]$registry_list.Add(@{Value='KFMSilentOptIn';Path=$registryPath;Key='KFMSilentOptIn';Type="string";Data=$KFMSilentOptIn})}
if (![string]::IsNullOrEmpty($KFMSilentOptInWithNotification))
{[void]$registry_list.Add(@{Value='KFMSilentOptInWithNotification';Path=$registryPath;Key='KFMSilentOptInWithNotification';Type="DWORD";Data=$KFMSilentOptInWithNotification})}
if (![string]::IsNullOrEmpty($KFMBlockOptOut))
{[void]$registry_list.Add(@{Value='KFMBlockOptOut';Path=$registryPath;Key='KFMBlockOptOut';Type="DWORD";Data=$KFMBlockOptOut})}
if (![string]::IsNullOrEmpty($KFMBlockOptIn))
{[void]$registry_list.Add(@{Value='KFMBlockOptIn';Path=$registryPath;Key='KFMBlockOptIn';Type="DWORD";Data=$KFMBlockOptIn})}


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