<#PSScriptInfo
.SYNOPSIS
    Script for Intune to set Primary User on Device

.DESCRIPTION
    This script will get the Entra Sign in logs for Windows Sign ins
    The script then determine who has logged on to the device the most times in the last 30 days and set the Primary user to that user
    The script uses Ms Graph with MGGraph modules

.EXAMPLE
   .\Intune-Set-PrimaryUser.ps1
    Will set the primary user for devices in Intune

.NOTES
    Written by Mr-Tbone (Tbone Granheden) Coligo AB
    torbjorn.granheden@coligo.se

.VERSION
    2.0

.RELEASENOTES
    1.0 2023-02-14 Initial Build
    2.0 2021-03-01 Large update to use Graph batching and reduce runtime
    3.0 2024-07-19 Added support for Group filtering and some bug fixes

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
    2.0.2312.1 - Large update to use Graph batching and reduce runtime
    3.0.2407.1 - Added support for Group filtering
    3.0.2407.2 - Added a verification of required permissions
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
[System.Object]$Enrollmentaccounts  = @("temp@Tbone.se","wds@tbone.se") # @() = No Enrollment accounts. @("wds@tbone.se","wds2@tbone.se") = will filter them out and not assign them as primary users.
[System.Object]$DeviceGroups        = @() # Group filter. @() = all devices. @("tbone-devices", "tbone-devices2") will filter only members of those groups
[int]$SigninsTimeSpan   = 30        # Number of days back in time to look back for Sign-In logs (Default 30 days)
[int]$DeviceTimeSpan    = 30        # Number of days back in time to look back for active devices (Default 30 days)
[Bool]$TestMode         = $true    # $True = No changes will be made on Primary owner, $False = Primary Owner will be changed
[Bool]$Verboselogging   = $false    # $Ture = Enable verbose logging for t-shoot. $False = Disable Verbose Logging
[Bool]$ReturnReport     = $True     # $True = Will return a report with all devices and primary users. $False = No report will be returned
#Batch Runtime settings
[Bool]$RunBatchMode     = $true     #Run the script in batch mode, faster but uses more memory, recommended for large environments
[int]$Batchsize         = 20        #How many objects to process in each batch
[int]$waittime          = 0         #How many seconds to wait between Batches to avoid throttling
[int]$MaxRetry          = 50        #How many retries of trottled requests before error
#endregion

#region ---------------------------------------------------[Set global script settings]--------------------------------------------
Set-StrictMode -Version Latest
#endregion

#region ---------------------------------------------------[Import Modules and Extensions]-----------------------------------------
import-Module Microsoft.Graph.Authentication
import-Module Microsoft.Graph.DeviceManagement
import-Module Microsoft.Graph.Reports
if ($DeviceGroups){Import-Module Microsoft.Graph.Groups}
#endregion

#region ---------------------------------------------------[Static Variables]------------------------------------------------------
[Int64]$MemoryUsage                         = 0
[System.Object]$report                      = @()
[System.Object]$IntuneDevices               = @()
[System.Object]$AllDeviceGroupMembers       = @()
[System.Object]$SignInLogs                  = @()
[System.Object]$AllPrimaryUsersHash         = @()
if($DeviceGroups){[System.Collections.ArrayList]$RequiredScopes      = "DeviceManagementManagedDevices.ReadWrite.All", "AuditLog.Read.All", "User.Read.All", "Group.Read.All","groupmember.read.all"}
else{[System.Collections.ArrayList]$RequiredScopes      = "DeviceManagementManagedDevices.ReadWrite.All", "AuditLog.Read.All", "User.Read.All"}
[datetime]$scriptStartTime                  = Get-Date
[datetime]$SignInsStartTime                 = (Get-Date).AddDays(-$SigninsTimeSpan )
[datetime]$DeviceStartTime                  = (Get-Date).AddDays(-$DeviceTimeSpan )
if ($Verboselogging){$VerbosePreference     = "Continue"}
else{$VerbosePreference                     = "SilentlyContinue"}
#endregion

#region ---------------------------------------------------[Functions]------------------------------------------------------------
function Invoke-ConnectMgGraph {
    param (
        [System.Collections.ArrayList]$RequiredScopes
    )
    Begin {
        $ErrorActionPreference = 'stop'
        [String]$resourceURL = "https://graph.microsoft.com/"
        $GraphAccessToken = $null
        if ($env:AUTOMATION_ASSET_ACCOUNTID) {  [Bool]$ManagedIdentity = $true}  # Check if running in Azure Automation
        else {                                  [Bool]$ManagedIdentity = $false} # Otherwise running in Local PowerShell
        }
    Process {
        if ($ManagedIdentity){ #Connect to the Microsoft Graph using the ManagedIdentity and get the AccessToken
            Try{$response = [System.Text.Encoding]::Default.GetString((Invoke-WebRequest -UseBasicParsing -Uri "$($env:IDENTITY_ENDPOINT)?resource=$resourceURL" -Method 'GET' -Headers @{'X-IDENTITY-HEADER' = "$env:IDENTITY_HEADER"; 'Metadata' = 'True'}).RawContentStream.ToArray()) | ConvertFrom-Json
                $GraphAccessToken = $response.access_token
                Write-verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to get an Access Token to Graph for managed identity"
                }
            Catch{Write-Error "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Failed to get an Access Token to Graph for managed identity, with error: $_"}
            $GraphVersion = ($GraphVersion = (Get-Module -Name 'Microsoft.Graph.Authentication' -ErrorAction SilentlyContinue).Version | Sort-Object -Desc | Select-Object -First 1)
            if ('2.0.0' -le $GraphVersion) {
                Try{Connect-MgGraph -Identity -Nowelcome
                    $GraphAccessToken = convertto-securestring($response.access_token) -AsPlainText -Force
                    Write-verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to connect to Graph with module 2.x and Managedidentity"}
                Catch{Write-Error "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Failed to connect to Graph with module 2.x and Managedidentity, with error: $_"}
                }
            else {#Connect to the Microsoft Graph using the AccessToken
                Try{Connect-mgGraph -AccessToken $GraphAccessToken -NoWelcome
	                Write-verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to connect to Graph with module 1.x and Managedidentity"}
                Catch{Write-Error "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Failed to connect to Graph with module 1.x and Managedidentity, with error: $_"}
                }
            }
        else{
            Try{Connect-MgGraph -Scope $RequiredScopes -NoWelcome
                Write-verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to connect to Graph manually"}
            Catch{Write-Error "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Failed to connect to Graph manually, with error: $_"}
            }
        #Checking if all permissions are granted to the script identity in Graph and exit if not
        [System.Collections.ArrayList]$CurrentPermissions  = (Get-MgContext).Scopes
        foreach ($RequiredScope in $RequiredScopes) {
            if (Compare-Object $currentpermissions $RequiredScope -IncludeEqual | Where-Object -FilterScript {$_.SideIndicator -eq '=='}){
                Write-Verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success, Script identity has a scope permission: $RequiredScope"
                }
            else {Write-Error "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Failed, Script identity is missing a scope permission: $RequiredScope"}
            }
        #Return the access token or username if available
        $GraphAccessToken = (Get-MgContext).Account
        return $GraphAccessToken
        }
    End {#Cleanup memory after connecting to Graph
        $MemoryUsage = [System.GC]::GetTotalMemory($true)
        Write-Verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to cleanup Memory usage after connect to Graph to: $(($MemoryUsage/1024/1024).ToString('N2')) MB"
        }
}
function get-mggraphrequestbatch {
    Param(
        [string]$RunProfile,
        [string]$Object,
        [String]$Method,
        [system.object]$Objects,
        [string]$Uri,
        [int]$BatchSize,
        [int]$WaitTime,
        [int]$MaxRetry
        )
    Begin {
        $Retrycount = 0
        $CollectedObjects = [System.Collections.ArrayList]@()
        $LookupHash = @{}
        if ($env:AUTOMATION_ASSET_ACCOUNTID) {  [Bool]$ManagedIdentity = $true}  # Check if running in Azure Automation
        else {                                  [Bool]$ManagedIdentity = $false} # Otherwise running in Local PowerShell
        }
    Process {
        $starttime = get-date
        do {
            $TotalObjects = $objects.count
            [int]$i = 0
            $currentObject = 0
            $RetryObjects = [System.Collections.ArrayList]@()
        #Start looping all objects and run batches
            for($i=0;$i -lt $TotalObjects;$i+=$BatchSize){
                # Create Requests of id, method and url
                [System.Object]$req = @()
                if($i + ($BatchSize-1) -lt $TotalObjects){
                    $req += ($objects[$i..($i+($BatchSize-1))] | Select-Object @{n='id';e={$_.id}},@{n='method';e={'GET'}},@{n='url';e={"/$($Object)/$($_.id)$($uri)"}})
                } elseif ($TotalObjects -eq 1) {
                    $req += ($objects[$i] | Select-Object @{n='id';e={$_.id}},@{n='method';e={'GET'}},@{n='url';e={"/$($Object)/$($_.id)$($uri)"}})
                } else {
                    $req += ($objects[$i..($TotalObjects-1)] | Select-Object @{n='id';e={$_.id}},@{n='method';e={'GET'}},@{n='url';e={"/$($Object)/$($_.id)$($uri)"}})
                }

                #Send the requests in a batch
                $responses = invoke-mggraphrequest -Method POST `
                    -URI "https://graph.microsoft.com/$($RunProfile)/`$batch" `
                    -body (@{'requests' = $req} | convertto-json)
                 #Process the responses and verify status
                foreach ($respons in $responses.responses) {
                    $CurrentObject++
                    switch ($respons.status) {
                        200 {
                            [void] $CollectedObjects.Add($respons)
                            Write-Verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to get object $($respons.id) from Graph batches" 
                        }
                        403 { write-error "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Error Access denied during Graph batches - Status: $($respons.status)" }
                        404 { write-error "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Error Result not found during Graph batches- Status: $($respons.status)" }
                        429 {
                            [void] $RetryObjects.Add($respons)
                            write-warning "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Warning, Throttling occured during Graph batches- Status: $($respons.status)"
                        }
                        default {
                            [void] $RetryObjects.Add($respons)
                            write-error "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Error Other error occured during Graph batches - Status: $($respons.status)"
                        }
                    }
                }

                #progressbar
                $Elapsedtime = (get-date) - $starttime
                $timeLeft = [TimeSpan]::FromMilliseconds((($ElapsedTime.TotalMilliseconds / $CurrentObject) * ($TotalObjects - $CurrentObject)))
                if (!$ManagedIdentity){
                    Write-Progress -Activity "Get $($uri) $($CurrentObject) of $($TotalObjects)" `
                        -Status "Est Time Left: $($timeLeft.Hours) Hour, $($timeLeft.Minutes) Min, $($timeLeft.Seconds) Sek - Throttled $($retryObjects.count) - Retry $($Retrycount) of $($MaxRetry)" `
                        -PercentComplete $([math]::ceiling($($CurrentObject / $TotalObjects) * 100))
                }
                $throttledResponses = $responses.responses | Select-Object -last 20 | Where-Object {$_.status -eq "429"}
                    $throttledResponse = $throttledResponses |Select-Object -last 1
                    # | Select-Object -Property *,@{Name='HasDelay';Expression={$null -ne $_.headers."retry-after"}} | Where-Object HasDelay -eq $true
                if ($throttledResponse) {
                    [int]$recommendedWait = ($throttledResponses.headers.'retry-after' | Measure-object -Maximum).maximum
                    write-warning "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Warning Throttling occured during Graph batches, Will wait the recommended $($recommendedWait+1) seconds"
                    Start-Sleep -Seconds ($recommendedWait + 1)
                }
                elseif($CurrentObject % ($BatchSize * 4) -eq 0){Start-Sleep -Seconds $waittime } #to avoid throttling
                else { Start-Sleep -Milliseconds $WaitTime } #to avoid throttling
            }
            if ($RetryObjects.Count -gt 0 -and $MaxRetry -gt 0){
                $Retrycount++
                $MaxRetry--
                write-verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to start rerun batches with $($RetryObjects.Count) collected a total of $($CollectedObjects.count))"
                $objects = @()
                $objects = $RetryObjects
            }
        }While ($RetryObjects.Count -gt 0 -and $MaxRetry -gt 0)
    Write-Progress -Completed -Activity "make progress bar dissapear"
    write-verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success returning $($CollectedObjects.count) objects from Graph batching"
    foreach ($CollectedObject in $CollectedObjects) {$LookupHash[$CollectedObject.id] = $CollectedObject}
    return $LookupHash
    }
    End {#Cleanup memory after Graph batching
        $MemoryUsage = [System.GC]::GetTotalMemory($true)
        Write-Verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to cleanup Memory usage after Graph batching to: $(($MemoryUsage/1024/1024).ToString('N2')) MB"
    }   
}
function Set-IntunePrimaryUser {
    param (
        [System.Object]$IntuneDevices,
        [System.Object]$SignInLogs,
        [System.Object]$AllPrimaryUsersHash,
        [System.Object]$Enrollmentaccounts,
        [Bool]$Testmode,
        [Bool]$ReturnReport
    )
    Begin {
        $ErrorActionPreference = 'stop'
        [int]$i=0
        [String]$EnrollmentaccountsFilter           = ($Enrollmentaccounts|ForEach-Object{[regex]::escape($_)}) -join '|'
        }
    Process {
        [System.Object]$report  = @()
        Foreach ($IntuneDevice in $IntuneDevices){
            [System.Object]$SignInLogsOnDevice      = $null
            [System.Object]$MostFrequentUser        = $null
            [hashtable]$primaryuserHash             = @{}
            [String]$MostFrequentUserPrincipalname  = $null
            [String]$MostFrequentUserID             = $null
            [String]$primaryUser                    = $null
            $i++
            #Get current Primary User
            if ($AllPrimaryUsersHash.count -gt 0){$PrimaryuserHash = $AllPrimaryUsersHash[$IntuneDevice.id]
                $primaryUserJson = ($primaryuserHash.body.value | ConvertTo-Json -Depth 9 | ConvertFrom-Json)
                if ($primaryUserJson -and $primaryUserJson.PSObject.Properties.Name -contains 'userprincipalname') {
                    $primaryuser = $primaryUserJson.userprincipalname}
                write-verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to get Primary User $($Primaryuser) for $($IntuneDevice.DeviceName) from batch lookup"}
            else {
                try {$primaryUser = (Get-MgDeviceManagementManagedDeviceUser -ManagedDeviceId $IntuneDevice.ID -property "UserPrincipalName").UserPrincipalName
                    write-verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to get Primary User $($Primaryuser) for device $($IntuneDevice.DeviceName) from Graph"
                    }
                catch{write-Warning "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Failed to get Primary User $($Primaryuser) for device $($IntuneDevice.DeviceName) from Graph with error: $_"
                    }
                }
            if (!$primaryUser){$primaryUser = "";write-verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success getting Primary user for device $($IntuneDevice.DeviceName) but device has no Primary User"}

            # Get sign in logs for the device
            if ($enrollmentaccounts.count -ge 1){$SignInLogsOnDevice = $SignInLogs | Where-Object {$_.deviceid -eq $IntuneDevice.AzureAdDeviceId -and $_.userprincipalname -notmatch $EnrollmentaccountsFilter}}
            else {$SignInLogsOnDevice = $SignInLogs | Where-Object {$_.deviceid -eq $IntuneDevice.AzureAdDeviceId}}
            if ($SignInLogsOnDevice){$SignInUsers = $SignInLogsOnDevice | Select-Object userprincipalname, UserId | Group-Object userprincipalname}
            else{
                write-verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Warning Device $($IntuneDevice.DeviceName) is skipped due to failing to find Sign-In logs"
                if ($ReturnReport){$report += "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Warning Device $($IntuneDevice.DeviceName) is skipped due to failing to find Sign-In logs"}
                continue}
            $MostFrequentUser = $SignInUsers | Sort-Object count | Select-Object -Last 1
            $MostFrequentUserPrincipalname = $MostFrequentUser.group[0].UserPrincipalName
            $MostFrequentUserID = $MostFrequentUser.group[0].UserID
            $IntuneDeviceID = $IntuneDevice.id

            #Set primary User if needed
            if (($MostFrequentUserPrincipalname) -and ($MostFrequentUserid) -and ($MostFrequentUserPrincipalname -ne $PrimaryUser))
                {
                write-verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to determine change needed on Device $($IntuneDevice.DeviceName) primaryuser from $($PrimaryUser) to $($MostFrequentUserPrincipalname)"
                $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$IntuneDeviceID')/users/`$ref"
                $Body = @{ "@odata.id" = "https://graph.microsoft.com/beta/users/$MostFrequentUserid" } | ConvertTo-Json
                $Method = "POST"
                if (!$TestMode){
                    try{Invoke-MgGraphRequest -Method $Method -uri $uri -body $Body
                        write-verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to set Primary User $($MostFrequentUserPrincipalname) for device $($IntuneDevice.DeviceName)"
                        if ($ReturnReport){$report += "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to set Primary User $($MostFrequentUserPrincipalname) for device $($IntuneDevice.DeviceName)"}}
                    catch{write-Warning "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Failed to set Primary User $($MostFrequentUserPrincipalname) for device $($IntuneDevice.DeviceName) with error: $_"
                    if ($ReturnReport){$report += "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Failed to set Primary User $($MostFrequentUserPrincipalname) for device $($IntuneDevice.DeviceName) with error: $_"}}
                    }
                else{write-verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Testmode - Will not set Primary User $($MostFrequentUserPrincipalname) for device $($IntuneDevice.DeviceName)"
                if ($ReturnReport){$report += "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Testmode - Will not set Primary User $($MostFrequentUserPrincipalname) for device $($IntuneDevice.DeviceName)"}}
                }
            else{
                if (!$MostFrequentUserPrincipalname){
                    write-verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to determine that Device $($IntuneDevice.DeviceName) has no logins in collected logs"
                    if ($ReturnReport){$report += "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to determine that Device $($IntuneDevice.DeviceName) has no logins in collected logs"}}
                else {write-Verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to determine that Device $($IntuneDevice.DeviceName) have correct Primary User $($PrimaryUser)"
                if ($ReturnReport){$report += "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to determine that Device $($IntuneDevice.DeviceName) have correct Primary User $($PrimaryUser)"}}
                }
            }
        return $report
        }
    End {$MemoryUsage = [System.GC]::GetTotalMemory($true)
        Write-Verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to cleanup Memory usage after set Primary Users to: $(($MemoryUsage/1024/1024).ToString('N2')) MB"
        }
    }
#endregion
function get-DeviceGroupMembers {
    param (
        [System.Object]$DeviceGroups
        )
    Begin {
        $ErrorActionPreference = 'stop'
        }
    Process {
            [system.object]$DeviceGroupIds = @()
            [System.Collections.ArrayList]$AllDeviceGroupMembers = @()
            foreach ($Devicegroup in $DeviceGroups) {
                try{$DeviceGroupObject = Get-MgGroup -Filter "displayName eq '$Devicegroup'" -Property id
                    write-verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to get Device Group $($Devicegroup)"
                    }
                catch{write-Warning "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Failed to get Device Group $($Devicegroup) with error: $_"}
                if ($DeviceGroupObject) {$DeviceGroupIds += $DeviceGroupObject
                write-verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to add Device Group $($Devicegroup) to list"}
                else {write-Warning "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Could not find Device Group $($Devicegroup)"}
            }
            foreach ($DeviceGroupId in $DeviceGroupIds) {
                $DeviceGroupMembers = @()
                try{$DeviceGroupMembers = Get-MgGroupMemberAsDevice -GroupId $DeviceGroupId.id -All -Property deviceid
                    write-verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to get $($DeviceGroupMembers.count) Device Group Members for Group $($DeviceGroupId.displayname)"
                    }
                catch{write-Warning "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Failed to get Device Group Members for Group $($DeviceGroupId.displayname) with error: $_"}
                $AllDeviceGroupMembers += $DeviceGroupMembers
            }
            $AllDeviceGroupMembers = $AllDeviceGroupMembers |Sort-Object -Property deviceid -Unique
        return $AllDeviceGroupMembers
    }
End {$MemoryUsage = [System.GC]::GetTotalMemory($true)
    Write-Verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to cleanup Memory usage after get Device Group Members to: $(($MemoryUsage/1024/1024).ToString('N2')) MB"
    }
}
#region ---------------------------------------------------[[Script Execution]------------------------------------------------------
$StartTime = Get-Date
#Sign in to Graph
try{$MgGraphAccessToken = Invoke-ConnectMgGraph -RequiredScopes $RequiredScopes
    write-verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to get Access Token to Graph"}
catch{write-Error "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Failed to get Access Token to Graph with error: $_"}

#Get Intune Devices only members of the specified groups if specified
if ($DeviceGroups.Count -gt 0) {
    #Get Device Group Members
    try{$AllDeviceGroupMembers = get-DeviceGroupMembers -DeviceGroups $DeviceGroups
        write-verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to get $($AllDeviceGroupMembers.count) Device Group Members"}
    catch{write-Error "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Failed to get Device Group Members with error: $_"}
    #Get Intune Devices only members of the specified groups
    try{$IntuneDevices = Get-MgDeviceManagementManagedDevice -filter "operatingSystem eq 'Windows'and LastSyncDateTime gt $($DeviceStartTime.ToString("yyyy-MM-ddTHH:mm:ssZ"))" -all -Property "AzureAdDeviceId,DeviceName,Id" | where-object {$AllDeviceGroupMembers.deviceid.Contains($_.azureaddeviceid)}
    write-verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to get $($IntuneDevices.count) Devices with selected properties for devices synced last $($DeviceTimeSpan) days"}
    catch{write-Error "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Failed to get Devices with error: $_"}    
    }
else{   #Get all Intune Devices
    try{$IntuneDevices = Get-MgDeviceManagementManagedDevice -filter "operatingSystem eq 'Windows'and LastSyncDateTime gt $($DeviceStartTime.ToString("yyyy-MM-ddTHH:mm:ssZ"))" -all -Property "AzureAdDeviceId,DeviceName,Id"
        write-verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to get $($IntuneDevices.count) Devices with selected properties for devices synced last $($DeviceTimeSpan) days"}
    catch{write-Error "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Failed to get Devices with error: $_"}
    }

#Memory Garbage collection
$MemoryUsage = [System.GC]::GetTotalMemory($true)
Write-Verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to cleanup Memory usage after get devices to: $(($MemoryUsage/1024/1024).ToString('N2')) MB"

#Get Sign-In logs
try{$SignInLogs = Get-MgAuditLogSignIn -Filter "appDisplayName eq 'Windows Sign In' and status/errorCode eq 0 and IsInteractive eq true and ClientAppUsed eq 'Mobile Apps and Desktop clients' and CreatedDateTime gt $($SignInsStartTime.ToString("yyyy-MM-ddTHH:mm:ssZ"))" -All | Select-Object devicedetail.deviceid,userprincipalname, UserId -ExpandProperty devicedetail
    write-verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to get $($SignInLogs.count) Sign-In logs with selected properties for last $($SigninsTimeSpan) days"}
catch{write-Error "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Failed to get Sign-In logs with error: $_"}

#Memory Garbage collection
$MemoryUsage = [System.GC]::GetTotalMemory($true)
Write-Verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to cleanup Memory usage after get Sign-In logs to: $(($MemoryUsage/1024/1024).ToString('N2')) MB"

if (($IntuneDevices) -and ($SignInLogs)){
    If ($RunBatchMode){ #Getting Primary Users in batch mode
        try{$AllPrimaryUsersHash = get-mggraphrequestbatch -RunProfile "beta" -method GET -Object "deviceManagement/managedDevices" -objects $IntuneDevices -uri "/users" -BatchSize $Batchsize -WaitTime $waittime -MaxRetry $MaxRetry
            Write-Verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Success to get Primary Users for $($AllPrimaryUsersHash.count) Devices"
            }
        catch{Write-Error "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Failed to get Primary Users for Devices with error: $_"}
        $report = Set-IntunePrimaryUser -IntuneDevices $IntuneDevices -SignInLogs $SignInLogs -AllPrimaryUsersHash $AllPrimaryUsersHash -Enrollmentaccounts $Enrollmentaccounts -TestMode $TestMode -ReturnReport $ReturnReport
        }
    else{ #Getting Primary Users in foreach mode
        $report = Set-IntunePrimaryUser -IntuneDevices $IntuneDevices -SignInLogs $SignInLogs -AllPrimaryUsersHash $AllPrimaryUsersHash -Enrollmentaccounts $Enrollmentaccounts -TestMode $TestMode -ReturnReport $ReturnReport
        }
    }
else{write-Warning "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),No Devices or Sign-In logs found, exiting script"}

if ($ReturnReport){write-Output -InputObject $report}

disconnect-mggraph | out-null
[datetime]$scriptEndTime    = Get-Date
$MemoryUsage                = [System.GC]::GetTotalMemory($false)
write-Output "Script execution time: $(($scriptEndTime-$scriptStartTime).ToString('hh\:mm\:ss'))"
Write-Output "Memory Usage at the end of script execution: $(($MemoryUsage/1024/1024).ToString('N2')) MB"
$VerbosePreference = "SilentlyContinue"