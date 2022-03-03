<#PSScriptInfo
.SYNOPSIS
    Script for Intune 
 
.DESCRIPTION
    This script will enumerate all devices in Intune and their primary users. The device will be added to the Primary Users country group.
    The script uses an Azure Application to authenticate and get permissions
        
.EXAMPLE
   .\Intune-UpdateCountryGroups.ps1
    Will update a group specified in variables. 

   .\Intune-UpdateCountryGroups.ps1 -filterByEnrolledLastMinutes 1440 
    Will update a group specified in variables. But only devices registered the last 24H

 .NOTES
    Written by Mr-Tbone (Tbone Granheden) Coligo AB
    torbjorn.granheden@coligo.se

.VERSION
    1.0

.RELEASENOTES
    1.0 2022-02-18 Initial Build

.AUTHOR
    Tbone Granheden @MrTbone_se

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
#Requires -Version 4.0
#endregion
#region ---------------------------------------------------[Script Parameters]-----------------------------------------------

param (
    #change this attribute if you want to get devices enrolled within the last ‘n’ minutes. 
    #Change this to 0 to get all devices. The time is in minutes.
    #1440 is 24 hours
    [int]$filterByEnrolledWithinMinutes=0
)
#endregion

#region ---------------------------------------------------[Modifiable Parameters and defaults]------------------------------------
#Azure AD  App Details for Auth
$global:tenant = "sirtbone.onmicrosoft.com"
$global:clientId = "6f7b0eeb-3367-4052-9ea6-0fd03401f6be"
$global:clientSecret = "oJy7Q~evvkTKzulAGRY2HK29XE7.yT3vRVtHG"

#set to true to filter the devices retrieved to personal devices
$OsFilter = @("iOS","Android")
$UpdateOnlyPersonalOnly=$false

#Record the list of user group to scope tag group mapping here
$UserToGroupMapping=@()
$CountryGroups = @{                         
        UserGroupID            = "aef1fdde-12a9-4bc2-a5ca-098b441582dd" #User Group NL
        ScopeTagGroupID    = "1c837874-6bb9-4627-8d20-124068ee3c44" # Device Group NL
        }                                              
$UserToGroupMapping+=(New-Object PSObject -Property $CountryGroups
$CountryGroups = @{                       
        UserGroupID             = "a19e3daa-58b3-4933-bf07-236dc14c76ca" #User Group SE
        ScopeTagGroupID    = "96a94252-b247-4e8c-a908-96081a736cbe"   # Device Group SE
        }                                              
$UserToGroupMapping+=(New-Object PSObject -Property $CountryGroups)                                             

#endregion

#region ---------------------------------------------------[Set global script settings]--------------------------------------------
#endregion

#region ---------------------------------------------------[Static Variables]------------------------------------------------------

#create the property to keep a cached copy of user group membership while the script runs
$cachedUserGroupMemberships=@()
#Verbose settings
$global:VerbosePreference = 'SilentlyContinue'

#endregion

#region ---------------------------------------------------[Import Modules and Extensions]-----------------------------------------
$AadModule = Get-Module -Name "AzureAD" -ListAvailable
if ($null -eq $AadModule) {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    install-module AzureAD -Force
    $AadModule = Get-Module -Name "AzureAD" -ListAvailable
    }
# Getting path to ActiveDirectory Assemblies
# If the module count is greater than 1 find the latest version
if($AadModule.count -gt 1){
    $Latest_Version = ($AadModule | select version | Sort-Object)[-1]
    $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }
    # Checking if there are multiple versions of the same module found
    if($AadModule.count -gt 1){
        $aadModule = $AadModule | select -Unique
    }
    $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
} else {
    $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
}
[System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
#endregion

#region ---------------------------------------------------[Functions]------------------------------------------------------------
function Get-AuthToken {
    [cmdletbinding()]
    param (
    )
    #variables
    $DateTime = (Get-Date).ToUniversalTime()
    # Checking if authToken exists before running authentication, If the authToken exists checking when it expires
    $TokenExpires = ($global:authToken.ExpiresOn.datetime - $DateTime).Minutes
    if($TokenExpires -le 1){
        write-host "Authentication Token expired" $TokenExpires "minutes ago. Updating Token" -ForegroundColor Yellow
        $global:authToken = Get-AuthTokenClientSecret
    }
}

####################################################

function Get-AuthTokenClientSecret {
[cmdletbinding()]
    param (
    )
    #variables
    $resourceAppIdURI = "https://graph.microsoft.com"
    $authority = "https://login.microsoftonline.com/$global:tenant"

    try {
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
        $clientCredential = New-Object -TypeName "Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential"($global:clientId, $global:clientSecret)
        $authResult=$authContext.AcquireTokenAsync($resourceAppIdURI, $clientCredential).result

        # If the accesstoken is valid then create the authentication header
        if($authResult.AccessToken){
            # Creating header for Authorization token
            $authHeader = @{
                'Content-Type'='application/json'
                'Authorization'="Bearer " + $authResult.AccessToken
                'ExpiresOn'=$authResult.ExpiresOn
                }
            return $authHeader
        }
        else {
            write-error "Authorization Access Token is null, please re-run authentication..."
            break
        }
    }
    catch {
        write-output $_.Exception.Message 
        write-output $_.Exception.ItemName 
        break
    }
}

####################################################

Function Get-UserGroups {
   
[cmdletbinding()]
    param (
        $id
    )
    #variables
    $graphApiVersion = "Beta"
    $Resource = "users/$id/getMemberGroups"
    $body='{"securityEnabledOnly": true}'
    
    try
    {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $body).value
    }
    catch
    {
        $ex = $_.Exception
        If ($ex.Response) {
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            write-verbose "Response content:`n$responseBody" 
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        } else {
            write-error $ex.message
        }
        break
    }
}

####################################################

Function Get-GroupMembers {
	
[cmdletbinding()]
    param (
        $id
    )
    #variables
	$graphApiVersion = "Beta"
	$Resource = "groups/$id/transitiveMembers"
    $body='{"securityEnabledOnly": true}'
    $results=@()
	
	try
	{
		$uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
		$result=(Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get)
        $results+=$result.value.id

        #page if necessary - https://docs.microsoft.com/en-us/graph/paging
        if ($result."@odata.nextLink") {
            write-verbose "$($results.count) returned. More results are available, will begin paging."
            $noMoreResults=$false
            do {
                #retrieve the next set of results
                $result=Invoke-RestMethod -Uri $result."@odata.nextLink" -Headers $authToken -Method Get -ErrorAction Continue
                $results+=$result.value.id

                #check if we need to continue paging
                If (-not $result."@odata.nextLink") {
                    $noMoreResults=$true
                    write-verbose "$($results.count) returned. No more pages."
                } else {
                    write-verbose "$($results.count) returned so far. Retrieving next page."
                }
            } until ($noMoreResults)
        }
        return $results
	}
	catch
	{
		$ex = $_.Exception
        If ($ex.Response) {
		    $errorResponse = $ex.Response.GetResponseStream()
		    $reader = New-Object System.IO.StreamReader($errorResponse)
		    $reader.BaseStream.Position = 0
		    $reader.DiscardBufferedData()
		    $responseBody = $reader.ReadToEnd();
		    write-verbose "Response content:`n$responseBody" 
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        } else {
            write-error $ex.message
        }
		break
	}
}

####################################################

Function Get-User {
    
[cmdletbinding()]
    param (
        $id
    )
    #variables
    $graphApiVersion = "Beta"
    $Resource = "users/$id"
    
    try
    {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
    }
    catch
    {
        $ex = $_.Exception
        If ($ex.Response) {
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            write-verbose "Response content:`n$responseBody" 
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        } else {
            write-error $ex.message
        }
        break
    }
}

####################################################

Function Get-Devices {
    
[cmdletbinding()]

param
(
    $filterByEnrolledWithinMinutes,
    $UpdateOnlyPersonalOnly
)
    #variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/managedDevices"

    If ($filterByEnrolledWithinMinutes -and $filterByEnrolledWithinMinutes -ne 0) {
        $minutesago = "{0:s}" -f (get-date).addminutes(0-$filterByEnrolledWithinMinutes) + "Z"
        $filter = "?`$filter=enrolledDateTime ge $minutesAgo"
        If ($UpdateOnlyPersonalOnly) {
            $filter ="$filter and managedDeviceOwnerType eq 'Personal'"
        }
    } else {
        If ($UpdateOnlyPersonalOnly) {
            $filter ="?`$filter=managedDeviceOwnerType eq 'Personal'"
        } else {
            $filter = ""
        }
    }
    try
    {
        $results=@()
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)$($filter)"
        $result=Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
        $results+=$result

        #page if necessary - https://docs.microsoft.com/en-us/graph/paging
        if ($result."@odata.nextLink") {
            write-verbose "$($results.count) returned. More results are available, will begin paging."
            $noMoreResults=$false
            do {
                #retrieve the next set of results
                $result=Invoke-RestMethod -Uri $result."@odata.nextLink" -Headers $authToken -Method Get -ErrorAction Continue
                $results+=$result

                #check if we need to continue paging
                If (-not $result."@odata.nextLink") {
                    $noMoreResults=$true
                    write-verbose "$($results.count) returned. No more pages."
                } else {
                    write-verbose "$($results.count) returned so far. Retrieving next page."
                }
            } until ($noMoreResults)
        }
        return $results
    }
    catch
    {
        $ex = $_.Exception
        If ($ex.Response) {
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            write-verbose "Response content:`n$responseBody" 
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        } else {
            write-error $ex.message
        }
        break
    }
}

####################################################

Function Get-DeviceUsers {
	
[cmdletbinding()]

param
(
    $ID
)
    #variables
	$graphApiVersion = "beta"
	$Resource = "deviceManagement/managedDevices('$ID')/users"

try
	{
		$uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
		(Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).value.id
	}
	catch
	{
		$ex = $_.Exception
        If ($ex.Response) {
		    $errorResponse = $ex.Response.GetResponseStream()
		    $reader = New-Object System.IO.StreamReader($errorResponse)
		    $reader.BaseStream.Position = 0
		    $reader.DiscardBufferedData()
		    $responseBody = $reader.ReadToEnd();
		    write-verbose "Response content:`n$responseBody" 
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        } else {
            write-error $ex.message
        }
		break
	}
}

####################################################

Function Get-AADDevice(){

[cmdletbinding()]
param
(
    $DeviceID
)
    #variables
    $graphApiVersion = "v1.0"
    $Resource = "devices"
   
    try {
    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=deviceId eq '$DeviceID'"
    (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).value 
    }
    catch {
        $ex = $_.Exception
        If ($ex.Response) {
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            write-verbose "Response content:`n$responseBody" 
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        } else {
            write-error $ex.message
        }
        break
    }
}

####################################################

Function Add-DeviceMember {
    
[cmdletbinding()]
param
(
    [Parameter(Mandatory=$true)]
    [string]$GroupId,
    [Parameter(Mandatory=$true)]
    [string]$DeviceID
)
    #variables
    $graphApiVersion = "Beta"
    $Resource = "groups/$groupid/members/`$ref"
    
    try
    {
    $JSON=@"
{
"`@odata.id": "https://graph.microsoft.com/$graphApiVersion/directoryObjects/$deviceid"
}
"@
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
    }
    catch
    {
        $ex = $_.Exception
        If ($ex.Response) {
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            write-verbose "Response content:`n$responseBody" 
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        } else {
            write-error $ex.message
        }
        break
    }
}

#endregion
#region ---------------------------------------------------[[Script Execution]------------------------------------------------------

# Authenticate
Get-AuthToken

#get devices
IF ($filterByEnrolledWithinMinutes -ne 0) {
    $devices=(Get-Devices -filterbyenrolledwithinminutes $filterByEnrolledWithinMinutes -UpdateOnlyPersonalOnly $UpdateOnlyPersonalOnly).value
    } 
else {$devices=(Get-Devices -UpdateOnlyPersonalOnly $UpdateOnlyPersonalOnly).value}

#loop through devices
foreach ($device in $devices) {
    #Verify valid access token
    Get-AuthToken
    #filter out devices on operatingsystem
    if ($osfilter -match [string]$device.operatingSystem -and $device.operatingSystem)
        {
        #Get the primary user of the device
        $PrimaryUser=Get-DeviceUsers $device.id
        #devices without a valid Azure AD Device ID cause script issues and need to be excluded
        If ($PrimaryUser -and $device.azureADDeviceId -ne "00000000-0000-0000-0000-000000000000") {
        write-output "Processing device: $($device.devicename). Serial: $($device.serialnumber). AADDeviceID= $($device.azureADDeviceId). User: $PrimaryUser"
        #check if we have the user group membership in our user group cache to speedup execution
        If ($cachedUserGroupMemberships.UserID -contains $PrimaryUser) {
            foreach ($cachedGroup in $cachedUserGroupMemberships) {
                IF ($cachedGroup.userid -eq $PrimaryUser) {$userGroupMemership=$cachedGroup.Groups}
                }
            } 
        else {
            #Get user group membership and store in cache
            $userGroupMemership=Get-UserGroups -id $PrimaryUser
            $CheckedUser = @{            
                UserID          = $PrimaryUser                
                Groups            = $userGroupMemership
                }                                              
            $cachedUserGroupMemberships+=(New-Object PSObject -Property $CheckedUser)
            }

        #Loop through all groups to determine memberships 
        foreach ($userGroup in $userGroupMemership) {
            If ($UserToGroupMapping.UserGroupID -contains $userGroup) {
                #assign device group
                foreach ($deviceGroup in $UserToGroupMapping) {
                    If ($deviceGroup.UserGroupID -eq $userGroup) {
                        #get group members if needed and cache
                        if (-not $deviceGroup.ScopeTagGroupMembers) {
                            $deviceGroup | add-member -MemberType NoteProperty -Name ScopeTagGroupMembers -Value (get-groupmembers $deviceGroup.ScopeTagGroupID) -Force
                        }
                        #get the device id from Azure AD - needed to add it to the group
                        $deviceID=(get-aaddevice $device.azureADDeviceId).id
                        #check if alredy member, otherwise add it
                        IF ($deviceID) {
                            If ($deviceGroup.ScopeTagGroupMembers -notcontains $deviceID) {
                                write-output "`tadding device $deviceID to device scope tag group $($deviceGroup.ScopeTagGroupID)"
                                $result=Add-DeviceMember -GroupId $deviceGroup.ScopeTagGroupID -DeviceID $deviceID
                            } else {
                            }
                        } else {
                        }
                    }
                }
                
            }
        }

    }
}
}
#endregion