<#PSScriptInfo
.SYNOPSIS
    Script for Intune to set Primary User on Device
 
.DESCRIPTION
    This script will get the Azure Sign in logs for Windows Sign ins 
    The script then determine who has logged on to the device the most times in the last 30 days and set the Primary user to that user
    The script uses Ms Graph with MGGraph module
        
.EXAMPLE
   .\Intune-Set-PrimaryUser.ps1
    Will set the primary user for devices in Intune 

.NOTES
    Written by Mr-Tbone (Tbone Granheden) Coligo AB
    torbjorn.granheden@coligo.se

.VERSION
    1.0

.RELEASENOTES
    1.0 2023-02-14 Initial Build

.AUTHOR
    Tbone Granheden 
    @MrTbone_se

.COMPANYNAME 
    Coligo AB

.GUID 
    00000000-0000-0000-0000-000000000000

.COPYRIGHT
    Feel free to use this, But would be grateful if My name is mentioned in Notes 

.CHANGELOG
    1.0.2202.1 - Initial Version
#>

#region ---------------------------------------------------[Set script requirements]-----------------------------------------------
#
#Requires -Modules Microsoft.Graph.Authentication
#Requires -Modules Microsoft.Graph.DeviceManagement
#Requires -Modules Microsoft.Graph.Reports
#
#endregion

#region ---------------------------------------------------[Script Parameters]-----------------------------------------------
#endregion

#region ---------------------------------------------------[Modifiable Parameters and defaults]------------------------------------
# Customizations
$Enrollmentaccounts = @("wds@tbone.se","wds2@tbone.se") # @() = No Enrollment accounts. @("wds@tbone.se","wds2@tbone.se") = will filter them out and not assign them as primary users.
$AzureAutomation = $True                # $True = The script will be executed in Azure Automation. $False The script will be executed manually 
$VerbosePreference = "SilentlyContinue" # "SilentlyContinue" = Doesn't display the verbose message. Continues executing. "Continue" = Show Verbose Messages

#endregion

#region ---------------------------------------------------[Set global script settings]--------------------------------------------
Set-StrictMode -Version Latest
#endregion

#region ---------------------------------------------------[Static Variables]------------------------------------------------------
$RequiredScopes = ("DeviceManagementManagedDevices.Read.All", "DeviceManagementManagedDevices.ReadWrite.All", "AuditLog.Read.All", "User.Read.All")
$i=0
$IntuneDevices  = $null
$SignInLogs     = $null
$accessToken    = $null
$EnrollmentaccountsFilter = ($Enrollmentaccounts|%{[regex]::escape($_)}) -join '|'
#endregion

#region ---------------------------------------------------[Import Modules and Extensions]-----------------------------------------
#endregion

#region ---------------------------------------------------[Functions]------------------------------------------------------------
#endregion

#region ---------------------------------------------------[[Script Execution]------------------------------------------------------
$ErrorActionPreference = 'stop'
if ($AzureAutomation)
    {
    #Get Microsoft Graph AccessToken
    Try{
    	$resourceURL = "https://graph.microsoft.com/" 
	    $response = [System.Text.Encoding]::Default.GetString((Invoke-WebRequest -UseBasicParsing -Uri "$($env:IDENTITY_ENDPOINT)?resource=$resourceURL" -Method 'GET' -Headers @{'X-IDENTITY-HEADER' = "$env:IDENTITY_HEADER"; 'Metadata' = 'True'}).RawContentStream.ToArray()) | ConvertFrom-Json 
	    $accessToken = $response.access_token
	    Write-verbose "Success getting an Access Token to Graph"
	    }
    Catch{Write-Error "Failed getting an Access Token to Graph, with error: $_"}
    #Connect to the Microsoft Graph using the AccessToken
    Try{
	    Connect-mgGraph -AccessToken $accessToken
	    Write-verbose "Success to connect to Graph"}
    Catch{Write-Error "Failed to connect to Graph, with error: $_"}
    }
else{Connect-MgGraph -Scope $RequiredScopes}

# Get Intune Devices
try{$IntuneDevices = Get-MgDeviceManagementManagedDevice -filter "operatingSystem eq 'Windows'" -all
    write-verbose "Success to get Device List"}
catch{write-Error "Failed to get Device List with error: $_"}

# Get Sign-In logs
try{$SignInLogs = Get-MgAuditLogSignIn -Filter "appDisplayName eq 'Windows Sign In'" -All
    write-verbose "Success to get Sign-In logs"}
catch{write-Error "Failed to get Sign-In logs with error: $_"}

$ErrorActionPreference = 'continue'
# Loop through Intune Devices

if (($IntuneDevices) -and ($SignInLogs))
    {
    write-verbose "Start Processing $($IntuneDevices.count) Intune Devices"
    Foreach ($IntuneDevice in $IntuneDevices){
        $i++
        $SignInLogsOnDevice             = $null
        $MostFrequentUser               = $null
        $MostFrequentUserPrincipalname  = $null
        $MostFrequentUserID             = $null
        $IntuneDeviceID                 = $null
        $primaryUser                    = $null

        if ($AzureAutomation){write-output "Processing Intune device $($IntuneDevice.DeviceName). Processing $($i)/$($IntuneDevices.count). $(($i/$($IntuneDevices.count)*100))% completed"}
        else{Write-Progress -Activity "Processing Intune device $($IntuneDevice.DeviceName)e" -Status "$i/$($IntuneDevices.count)" -PercentComplete ($i/$($IntuneDevices.count)*100)}

        # Getting sign in logs for the device
        if ($enrollmentaccounts.count -ge 1){$SignInLogsOnDevice = $SignInLogs | where {$_.devicedetail.deviceid -eq $IntuneDevice.AzureAdDeviceId -and $_.userprincipalname -notmatch $EnrollmentaccountsFilter}}
        else {$SignInLogsOnDevice = $SignInLogs | where {$_.devicedetail.deviceid -eq $IntuneDevice.AzureAdDeviceId}}

        if ($SignInLogsOnDevice){$SignInUsers = $SignInLogsOnDevice | select userprincipalname, UserId | Group userprincipalname}
        else{write-warning "Device $($IntuneDevice.DeviceName) is skipped due to failing to find Sign-In logs ";continue}
        $MostFrequentUser = $SignInUsers | sort count | select -Last 1
        $MostFrequentUserPrincipalname = $MostFrequentUser.group[0].UserPrincipalName
        $MostFrequentUserID = $MostFrequentUser.group[0].UserID

        #Getting Current Primary User on Device
        $IntuneDeviceID = $IntuneDevice.id
        try {$primaryUser = (Get-MgDeviceManagementManagedDeviceUser -ManagedDeviceId $IntuneDeviceID -property "UserPrincipalName").UserPrincipalName
            write-verbose "Success to get Primary User for device"}
        catch{write-Warning "Failed to get Primary User for device with error: $_"}
        if (!$primaryUser){$primaryUser = "";write-verbose "Device $($IntuneDevice.DeviceName) had no Primary User"}
        #Set primary User if needed
        if (($MostFrequentUserPrincipalname) -and ($MostFrequentUserid) -and ($MostFrequentUserPrincipalname -ne $PrimaryUser))
            {
            write-output "Changing Device $($IntuneDevice.DeviceName) primaryuser from $($PrimaryUser) to $($MostFrequentUserPrincipalname)"
            $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$IntuneDeviceID')/users/`$ref"
            $Body = @{ "@odata.id" = "https://graph.microsoft.com/beta/users/$MostFrequentUserid" } | ConvertTo-Json
            $Method = "POST"
            Invoke-MgGraphRequest -Method $Method -uri $uri -body $Body
            }
        else{if (!$MostFrequentUserPrincipalname){write-Output "Device $($IntuneDevice.DeviceName) has no logins last 30 days"}
            else {write-Output "Device $($IntuneDevice.DeviceName) have correct Primary User"}
            }
        }
    }
else {write-Error "Failed to collect Intune Devices or Sign In logs, exit script"}
disconnect-mggraph
$VerbosePreference = "SilentlyContinue"