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
    4.0 2025-03-21 New functions and new structure for the script

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
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false,
        HelpMessage = "Device operating systems to process ('All', 'Windows', 'Android', 'iOS', 'macOS')")]
    [ValidateSet('All', 'Windows', 'Android', 'iOS', 'macOS')]
    [string[]]$OperatingSystems = @('Windows'),    # Default to Windows only

    [Parameter(Mandatory = $false,
        HelpMessage = "Array of device group names to filter devices")]
    [string[]]$DeviceGroups = @(),    # Empty array means all devices

    [Parameter(Mandatory = $false,
        HelpMessage = "Array of enrollment accounts to exclude from primary user assignment")]
    [string[]]$EnrollmentAccounts = @(),   # Empty array means no exclusions

    [Parameter(Mandatory = $false,
        HelpMessage = "Number of days to look back for sign-in logs")]
    [ValidateRange(1,365)]
    [int]$SignInsTimeSpan = 30,    # Default 30 days

    [Parameter(Mandatory = $false,
        HelpMessage = "Number of days to look back for active devices")]
    [ValidateRange(1,365)]
    [int]$DeviceTimeSpan = 30,     # Default 30 days

    [Parameter(Mandatory = $false,
        HelpMessage = "Enable batch processing mode")]
    [bool]$RunBatchMode = $true,    # Default to batch mode for better performance

    [Parameter(Mandatory = $false,
        HelpMessage = "Return execution report")]
    [bool]$ReturnReport = $true,    # Default to returning report

    [Parameter(Mandatory = $false,
        HelpMessage = "Include detailed device status in report")]
    [bool]$DetailedReport = $true,  # Default to detailed reporting

    [Parameter(Mandatory = $false,
        HelpMessage = "Save report to disk")]
    [bool]$ReportDisk = $true,     # Default to saving report

    [Parameter(Mandatory = $false,
        HelpMessage = "Path where to save the report")]
    [string]$ReportPath = (Join-Path $PSScriptRoot "Reports"),

    [Parameter(Mandatory = $false,
        HelpMessage = "Enable verbose logging")]
    [bool]$VerboseLogging = $true,  # Default to verbose logging

    [Parameter(Mandatory = $false,
        HelpMessage = "Number of devices to process in each batch")]
    [ValidateRange(1,20)]
    [int]$BatchSize = 20,          # Default batch size

    [Parameter(Mandatory = $false,
        HelpMessage = "Wait time in milliseconds between batches")]
    [ValidateRange(100,5000)]
    [int]$WaitTime = 1000,         # Default wait time

    [Parameter(Mandatory = $false,
        HelpMessage = "Maximum number of retry attempts for failed requests")]
    [ValidateRange(1,10)]
    [int]$MaxRetry = 3            # Default retry attempts

    #[Parameter(Mandatory = $false,
     #   HelpMessage = "Enable WhatIf mode to simulate changes")]
    #[switch]$WhatIf                 # Default to $false
    )
#endregion

#region ---------------------------------------------------[Set global script settings]--------------------------------------------
Set-StrictMode -Version Latest
if ($VerboseLogging) {$VerbosePreference = 'Continue'}
else {$VerbosePreference = 'SilentlyContinue'}
#endregion

#region ---------------------------------------------------[Import Modules and Extensions]-----------------------------------------
# Disable verbose logging and load required modules
$currentVerbosePreference = $VerbosePreference
$VerbosePreference = 'SilentlyContinue'
try {
    Import-Module Microsoft.Graph.Authentication
    if ($DeviceGroups){Import-Module Microsoft.Graph.Groups}
}
catch {
    Write-Error "$(([DateTime]::UtcNow).ToString('yyyy-MM-dd HH:mm:ss')),Error, Failed to import required modules: $_"
    throw
}
finally {
    # Restore original logging level
    $VerbosePreference = $currentVerbosePreference
}
#endregion

#region ---------------------------------------------------[Static Variables]------------------------------------------------------
[String]$ScriptAction                       = "Set Primary User"
$script:GetTimestamp = {([DateTime]::Now).ToString('yyyy-MM-dd HH:mm:ss')}
$WhatIfPreference = $true #For testing purposes only

# Use value types for report and logging
$script:Progress = @{
    Total   = [int]0
    Current = [int]0
    Success = [int]0
    Failed  = [int]0
    Skipped = [int]0
}

# variable for results
$script:ProcessResults = [System.Collections.Concurrent.ConcurrentQueue[PSCustomObject]]::new()

# Add garbage collection settings
[System.Runtime.GCSettings]::LargeObjectHeapCompactionMode = 'CompactOnce'
[System.GC]::WaitForPendingFinalizers()

# Required Graph API scopes
if($DeviceGroups){[System.Collections.ArrayList]$RequiredScopes      = "DeviceManagementManagedDevices.ReadWrite.All", "AuditLog.Read.All", "User.Read.All", "Group.Read.All","groupmember.read.all"}
else{[System.Collections.ArrayList]$RequiredScopes      = "DeviceManagementManagedDevices.ReadWrite.All", "AuditLog.Read.All", "User.Read.All"}

[datetime]$SignInsStartTime                 = (Get-Date).AddDays(-$SigninsTimeSpan )
$DevicesHash                           = @{} # Hash table for devices
$SignInLogs                             = @() # Array for sign-in logs
$devices                          = @() # Array for Intune devices
$AllPrimaryUsersHash                  = @{} # Hash table for primary users

#endregion

#region ---------------------------------------------------[Functions]------------------------------------------------------------
function Invoke-ConnectMgGraph {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, HelpMessage = "Send an arraylist of permission scopes required for the script")]
        [ValidateNotNull()]
        [System.Collections.ArrayList]$RequiredScopes = @("User.Read.All")
    )
    Begin {
        $ErrorActionPreference = 'Stop'
        $script:GetTimestamp = { ([DateTime]::Now).ToString('yyyy-MM-dd HH:mm:ss') }
        [string]$resourceURL = "https://graph.microsoft.com/"
        $GraphAccessToken = $null
        [bool]$ManagedIdentity = $false

        try {
            # Check for existing connection
            $context = Get-MgContext
            if ($context) {
                Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Using existing Graph connection for account: $($context.Account)"
                return $context # Return the existing context
            }
        }
        catch {
            Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Failed to check existing Graph connection: $_"
        }

        try {
            # Check execution context if managed identity
            $ManagedIdentity = [bool]$env:AUTOMATION_ASSET_ACCOUNTID
            Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Execution context: $($ManagedIdentity ? 'Managed Identity' : 'Interactive')"
        }
        catch {
            Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Failed to determine execution context: $_"
        }
    }

    Process {
        try {
            if ($ManagedIdentity) {
                # Check for required environment variables
                if (-not $env:IDENTITY_ENDPOINT -or -not $env:IDENTITY_HEADER) {
                    Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Required environment variables IDENTITY_ENDPOINT and IDENTITY_HEADER are not set."
                    throw
                }

                try {
                    # Get managed identity token
                    $headers = @{
                        'X-IDENTITY-HEADER' = "$env:IDENTITY_HEADER"
                        'Metadata' = 'True'
                    }
                    $response = Invoke-WebRequest -Uri "$($env:IDENTITY_ENDPOINT)?resource=$resourceURL" -Method GET -Headers $headers -TimeoutSec 30
                    $GraphAccessToken = ($response | ConvertFrom-Json).access_token
                    Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Retrieved managed identity token"
                }
                catch {
                    Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Failed to get managed identity token: $_"
                    throw
                }

                try {
                    # Get Graph module version
                    $GraphVersion = (Get-Module -Name 'Microsoft.Graph.Authentication').Version
                    Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Graph module version: $GraphVersion"
                }
                catch {
                    Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Failed to detect Graph module version: $_"
                    throw
                }

                try {
                    # Connect to Graph
                    $tokenParams = @{
                        NoWelcome = $true
                    }
                    if ($GraphVersion -ge '2.0.0') {
                        $tokenParams['Identity'] = $true
                    } else {
                        $tokenParams['AccessToken'] = $GraphAccessToken
                    }
                    Connect-MgGraph @tokenParams
                    Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Connected using Graph SDK $($GraphVersion)"
                }
                catch {
                    Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Failed to connect to Graph: $_"
                    throw
                }
            }
            else { # Connect manually
                try {
                    Connect-MgGraph -Scope $RequiredScopes -NoWelcome
                    Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Connected interactively to Graph"
                }
                catch {
                    Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Failed to connect interactively: $_"
                    throw
                }
            }

            try {
                # Validate permission scopes
                $CurrentPermissions = (Get-MgContext).Scopes
                foreach ($RequiredScope in $RequiredScopes) {
                    if ($RequiredScope -notin $CurrentPermissions) {
                        Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Missing required scope: $RequiredScope"
                        throw
                    }
                    Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Verified scope: $RequiredScope"
                }
            }
            catch {
                Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Failed to validate permissions: $_"
                throw
            }

            try {
                $GraphAccessToken = (Get-MgContext).Account
                Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Successfully authenticated as: $GraphAccessToken"
                return $GraphAccessToken # Return the account
            }
            catch {
                Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Failed to get account details: $_"
                throw
            }
        }
        catch {
            Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Script execution failed: $_"
            throw
        }
    }

    End {
        # Cleanup memory after executing a function
        try {
            $MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
            Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Memory usage before cleanup: $MemoryUsage MB"
            # Get all parameters of the function
            $params = $PSBoundParameters.Keys
            # Remove each parameter from the script scope
            foreach ($param in $params) {
                Remove-Variable -Name $param -Scope Local -ErrorAction SilentlyContinue |out-null
            }
            [System.GC]::Collect()
            $MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
            Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Memory usage after cleanup: $MemoryUsage MB"
        }
        catch {
            Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Failed to cleanup memory garbage: $_"
        }
    }
}
function invoke-mgGraphRequestBatch {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory,
            HelpMessage = "The Graph API version ('beta' or 'v1.0')")]
        [ValidateSet('beta', 'v1.0')]
        [string]$RunProfile = "v1.0",

        [Parameter(Mandatory,
            HelpMessage = "The HTTP method for the request")]
        [ValidateSet('GET', 'PATCH', 'POST', 'DELETE')]
        [String]$Method = "GET",
        
        [Parameter(Mandatory,
            HelpMessage = "The Graph API endpoint path")]
        [string]$Object,

        [Parameter(Mandatory,
            HelpMessage = "Array of objects to process in batches")]
        [System.Object[]]$Objects,

        [Parameter(Mandatory,
            HelpMessage = "The Graph API query on the objects")]
        [string]$query,

        [Parameter(HelpMessage = "Request body for POST/PATCH operations")]
        [object]$Body,
        
        [Parameter(HelpMessage = "Graph API properties to include (array)")]
        [string[]]$GraphProperties,

        [Parameter(HelpMessage = "Graph API filters to apply")]
        [string]$GraphFilters,

        [Parameter(HelpMessage = "Batch size (max 20 objects per batch)")]
        [ValidateRange(1,20)]
        [int]$BatchSize = 20,

        [Parameter(HelpMessage = "Delay between batches in milliseconds")]
        [ValidateRange(100,5000)]
        [int]$WaitTime = 1000,

        [Parameter(HelpMessage = "Maximum retry attempts for failed requests")]
        [ValidateRange(1,10)]
        [int]$MaxRetry = 3
    )
    
    Begin {
        $ErrorActionPreference = 'Stop'
        $script:GetTimestamp = {([DateTime]::Now).ToString('yyyy-MM-dd HH:mm:ss')}
        $starttime = $(&$script:GetTimestamp)
        try {
            $Retrycount = 0
            $CollectedObjects = [System.Collections.Generic.List[PSObject]]::new()
            $RetryObjects = [System.Collections.Generic.List[PSObject]]::new()
            $LookupHash = @{}
            
            # Check execution context
            if ($env:AUTOMATION_ASSET_ACCOUNTID) {
                [Bool]$ManagedIdentity = $true
                Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Rnning in Azure Automation context"
            }
            else {
                [Bool]$ManagedIdentity = $false
                Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Running in Local PowerShell context"
            }
            
            Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Start processing with $($Objects.Count) objects"
        }
        catch {
            Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Failed to initialize with error: $_"
            throw
        }
    }
    
    Process {
        try {
            do {
                try {
                    $TotalObjects = $Objects.Count
                    [int]$i = 0
                    $currentObject = 0
                    # Clear RetryObjects at the beginning of each retry loop
                    $RetryObjects.Clear()
                    
                    Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Processing started with $TotalObjects objects"                    
                    
                    # Start looping all objects and run batches
                    for($i = 0; $i -lt $TotalObjects; $i += $BatchSize) {
                        try {
                            # Create Requests of id, method and url
                            [System.Object[]]$req = @()
                            $batchStart = $i
                            $batchEnd = [Math]::Min($i + $BatchSize - 1, $TotalObjects - 1)
                            $batchObjects = $Objects[$batchStart..$batchEnd]
                            
                            $req = $batchObjects | ForEach-Object {
                                # Build URL with properties and filters
                                $url = "/$($Object)/$($_.id)$($query)"
                                $urlParams = @()

                                # Add properties if specified
                                if ($GraphProperties) {
                                    $select = $GraphProperties -join ','
                                    $urlParams += "`$select=$select"
                                }

                                # Add filters if specified
                                if ($GraphFilters) {
                                    $urlParams += "`$filter=$([System.Web.HttpUtility]::UrlEncode($GraphFilters))"
                                }

                                # Combine URL parameters
                                if ($urlParams) {
                                    $url += "?" + ($urlParams -join '&')
                                }
                                
                                @{
                                    'id' = $_.id
                                    'method' = $Method
                                    'url' = $url
                                    'body' = if ($Method -in 'PATCH','POST') { $Body } else { $null }
                                    'headers' = @{
                                        'Content-Type' = if ($Method -in 'PATCH','POST') { 
                                            'application/json' 
                                        } else { 
                                            $null 
                                        }
                                    }
                                }
                            Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Created batch for items $($i) to $([Math]::Min($i + $BatchSize, $TotalObjects)) of $TotalObjects total items"
                            }
                        }
                        catch {
                            Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Failed to create batch with error:$_"
                            throw
                        }

                        # Send the requests in a batch
                        try {
                            $batchRequest = @{'requests' = $req}
                            $batchBody = $batchRequest | ConvertTo-Json -Depth 10

                                $headers = @{
                                    'Content-Type' = 'application/json'
                                }
                                
                                $responses = Invoke-MgGraphRequest -Method POST `
                                    -Uri "https://graph.microsoft.com/$($RunProfile)/`$batch" `
                                    -Body $batchBody `
                                    -Headers $headers
                                
                                Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Successfully sent the request"
                            }
                            catch {
                                Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Failed to send batch request with error: $_"
                                throw
                            }

                            # Process the responses and verify status
                            foreach ($response in $responses.responses) {
                                $CurrentObject++
                                try {
                                    switch ($response.status) {
                                        200 {
                                            # GET success
                                            [void]$CollectedObjects.Add($response)
                                            Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Successfully processed GET for object $($response.id)" 
                                        }
                                        201 {
                                            # POST success
                                            [void]$CollectedObjects.Add($response)
                                            Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Successfully processed POST for object $($response.id)" 
                                        }
                                        204 {
                                            # PATCH/DELETE success
                                            [void]$CollectedObjects.Add($response)
                                            Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Successfully processed $Method for object $($response.id)" 
                                        }
                                        400 { 
                                            Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Bad request for object $($response.id) - Status: $($response.status)"
                                            [void]$RetryObjects.Add($response)
                                        }
                                        403 { 
                                            Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Access denied to object $($response.id) - Status: $($response.status)"
                                        }
                                        404 { 
                                            Write-Warning "$(&$script:GetTimestamp),Warning,$($MyInvocation.MyCommand.Name),Object $($response.id) not found - Status: $($response.status)"
                                        }
                                        429 {
                                            [void]$RetryObjects.Add($response)
                                            Write-Warning "$(&$script:GetTimestamp),Warning,$($MyInvocation.MyCommand.Name),Throttling occurred for object $($response.id) - Status: $($response.status)"
                                        }
                                        default {
                                            Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Unexpected status $($response.status) for object $($response.id)"
                                            [void]$RetryObjects.Add($response)
                                        }
                                    }
                                }
                                catch {
                                    Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Failed to process response: $_"
                                    continue
                                }
                            }

                            # Handle throttling and progress
                            try {
                                # Calculate progress and time estimates
                                $ElapsedTime = New-TimeSpan -Start $starttime -End (Get-Date)
                                $timeLeft = if ($CurrentObject -gt 0) {
                                    $timePerObject = $ElapsedTime.TotalMilliseconds / $CurrentObject
                                    $remainingObjects = $TotalObjects - $CurrentObject
                                    [TimeSpan]::FromMilliseconds($timePerObject * $remainingObjects)
                                } else {
                                    [TimeSpan]::Zero
                                }
                                
                                # Show progress if not running in automation
                                if (!$ManagedIdentity) {
                                    Write-Progress -Activity "$($MyInvocation.MyCommand.Name) processing Graph Requests" `
                                        -Status "Progress: $CurrentObject of $TotalObjects | Est. Time Left: $($timeLeft.ToString('hh\:mm\:ss')) | Throttled: $($RetryObjects.Count) | Retry: $($Retrycount)/$($MaxRetry)" `
                                        -PercentComplete ([math]::ceiling(($CurrentObject / $TotalObjects) * 100))
                                }
                            
                                # Handle throttling with exponential backoff
                                if ($RetryObjects.Count -gt 0) {
                                    $throttledResponses = $RetryObjects | Where-Object { $_.status -eq 429 }
                                    if ($throttledResponses) {
                                        $recommendedWait = ($throttledResponses.headers.'retry-after' | Measure-Object -Maximum).Maximum
                                        $backoffWait = [math]::Min($recommendedWait + ($Retrycount * 2), 30) # Max 30 second wait
                                        Write-Warning "$(&$script:GetTimestamp),Warning,$($MyInvocation.MyCommand.Name),Throttling detected, waiting $backoffWait seconds (Retry: $Retrycount)"
                                        Start-Sleep -Seconds $backoffWait
                                    }
                                }
                            }
                            catch {
                                Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Batch failed to handle throttling: $_"
                                throw
                            }
                        }

                        # Handle retries
                    if ($RetryObjects.Count -gt 0 -and $MaxRetry -gt 0) {
                        $Retrycount++
                        $MaxRetry--
                        Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Sarting retry $Retrycount with $($RetryObjects.Count) objects"
                        # The objects to retry are the ones that had errors
                        $Objects = $RetryObjects | ForEach-Object {$Objects | Where-Object {$_.id -eq $_.id}}
                    }
                }
            
            catch {
                Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Failed in retry loop: $_"
                throw
                }
            
            } while ($RetryObjects.Count -gt 0 -and $MaxRetry -gt 0)

            Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Successfully processed $($CollectedObjects.Count) objects"

            # Build return hashtable
            return $CollectedObjects   
        }
        catch {
            Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Failed in main process block with error: $_"
            throw
        }
    }
    
    End {
        # Cleanup memory after executing a function
        try {
            $MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
            Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Memory usage before cleanup: $MemoryUsage MB"
            # Get all parameters of the function
            $params = $PSBoundParameters.Keys
            # Remove each parameter from the script scope
            foreach ($param in $params) {
                Remove-Variable -Name $param -Scope Local -ErrorAction SilentlyContinue
            }
            [System.GC]::Collect()
            $MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
            Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Memory usage after cleanup: $MemoryUsage MB"
        }
        catch {
            Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Failed to cleanup memory garbage: $_"
        }
    }
}
function Invoke-MgGraphRequestSingle {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('v1.0', 'beta')]
        [string]$RunProfile,

        [Parameter(Mandatory)]
        [string]$Object,

        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string]$Method,

        [Parameter()]
        [string[]]$Properties,

        [Parameter()]
        [ValidateNotNull()]
        [object]$Filters,

        [Parameter()]
        [object]$Body,

        [Parameter()]
        [ValidateRange(1, 1000)]
        [int]$PageSize = 1000,

        [Parameter()]
        [ValidateRange(0, 10)]
        [int]$MaxRetry = 3,  # Default retry attempts

        [Parameter()]
        [ValidateRange(0, 300)]
        [int]$InitialDelaySeconds = 5 # Default initial delay in seconds
    )

    Begin {
        $PsobjectResults = [System.Collections.ArrayList]::new()
        # Build base URI
        $uri = "https://graph.microsoft.com/$RunProfile/$Object"
        $queryParams = [System.Collections.ArrayList]::new()

        # Add page size parameter
        [void]$queryParams.Add("`$top=$PageSize")

        # Add properties if specified
        if ($Properties) {
            $select = $Properties -join ','
            [void]$queryParams.Add("`$select=$select")
        }

        # Add filters if specified
        if ($Filters) {
            if ($Filters -is [string]) {
                [void]$queryParams.Add("`$filter=$([System.Web.HttpUtility]::UrlEncode($Filters))")
            }
            elseif ($Filters -is [hashtable]) {
                $filterParts = foreach ($key in $Filters.Keys) {
                    "$key eq '$($Filters[$key])'"
                }
                $filter = $filterParts -join ' and '
                [void]$queryParams.Add("`$filter=$([System.Web.HttpUtility]::UrlEncode($filter))")
            }
        }

        # combine query parameters into URI
        if ($queryParams.Count -gt 0) {
            $uri += "?" + ($queryParams -join '&')
        }
    }

    Process {
        $RetryCount = 0
        do {
            try {
                Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Making request to: $uri"
                $i = 1
                do {
                    Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Requesting page $i with $PageSize items"

                    $params = @{
                        Method      = $Method
                        Uri         = $uri
                        OutputType  = 'psobject'
                        ErrorAction = 'Stop'
                    }

                    if ($Body -and $Method -in 'PATCH', 'POST') {
                        $params['Body'] = $Body | ConvertTo-Json -Depth 10
                        $params['Headers'] = @{ 'Content-Type' = 'application/json' }
                    }

                    $response = Invoke-MgGraphRequest @params

                    if ($response.value) {
                        [void]$PsobjectResults.AddRange($response.value)
                    }
                    Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Retrieved page $i with $($response.Count) items, Now total: $($PsobjectResults.Count) items"

                    # Check for next page
                    if ($response.PSObject.Properties.Name -contains '@odata.nextLink') {
                        if ($response.'@odata.nextLink') {
                            $uri = $response.'@odata.nextLink'
                            Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Next page found: $uri"
                        }
                    }
                    else {
                        Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),No more pages found"
                        $uri = $null
                    }

                    $i++
                } while ($uri)
                Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Returning array with $($PsobjectResults.Count) items"
                return $PsobjectResults # Success, return results and exit retry loop
            }
            catch {
                $ErrorMessage = $_.Exception.Message
                Write-Warning "$(&$script:GetTimestamp),Warning,$($MyInvocation.MyCommand.Name),Request failed (Retry attempt $($RetryCount + 1)/$MaxRetry): $ErrorMessage"

                # Check for throttling
                if ($_.Exception.Response.StatusCode -eq 429) {
                    # Extract Retry-After header if present
                    $RetryAfter = ($_.Exception.Response.Headers | Where-Object {$_.Name -eq "Retry-After"}).Value
                    if ($RetryAfter) {
                        Write-Warning "$(&$script:GetTimestamp),Warning,$($MyInvocation.MyCommand.Name),Throttling detected. Waiting $($RetryAfter) seconds before retrying."
                        Start-Sleep -Seconds $RetryAfter
                    }
                    else {
                        # If no Retry-After header, use exponential backoff
                        $Delay = [math]::Min(($InitialDelaySeconds * ([math]::Pow(2, $RetryCount))), 60) #Exponential backoff, max 60 seconds
                        Write-Warning "$(&$script:GetTimestamp),Warning,$($MyInvocation.MyCommand.Name),Throttling detected. No Retry-After header found. Waiting $($Delay) seconds before retrying."
                        Start-Sleep -Seconds $Delay
                    }
                }
                else {
                    # For non-throttling errors, use exponential backoff with initial delay
                    $Delay = [math]::Min(($InitialDelaySeconds * ([math]::Pow(2, $RetryCount))), 60) #Exponential backoff, max 60 seconds
                    Write-Warning "$(&$script:GetTimestamp),Warning,$($MyInvocation.MyCommand.Name),Non-throttling error. Waiting $($Delay) seconds before retrying."
                    Start-Sleep -Seconds $Delay
                }

                $RetryCount++
            }
        } while ($RetryCount -le $MaxRetry)

        Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Request failed after $($MaxRetry) retries. Aborting."
        throw "Request failed after $($MaxRetry) retries." # Re-throw the exception after max retries
    }

    End {
        # Cleanup memory after executing a function
        try {
            $MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
            Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Memory usage before cleanup: $MemoryUsage MB"
            # Get all parameters of the function
            $params = $PSBoundParameters.Keys
            # Remove each parameter from the script scope
            foreach ($param in $params) {
                Remove-Variable -Name $param -Scope Local -ErrorAction SilentlyContinue
            }
            [System.GC]::Collect()
            $MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
            Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Memory usage after cleanup: $MemoryUsage MB"
        }
        catch {
            Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Failed to cleanup memory garbage: $_"
        }
    }
}
function Invoke-ScriptReport {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ReportTitle = "Script Report",
        [Parameter()]
        [string]$ScriptAction = "ScopeTagAssignment",
        [Parameter()]
        [bool]$DetailedReport = $script:DetailedReport
    )

    try {
        # Create report data structure using Progress values
        $reportData = @{
            Summary = @{
                StartTime = $script:StartTime
                Duration = "{0:hh\:mm\:ss}" -f ((Get-Date) - $script:StartTime)
                WhatIf = $WhatIfPreference
                TotalObjects = $script:Progress.Total
                ObjectsProcessed = $script:Progress.Current
                ObjectsChanged = $script:Progress.Success
                ObjectsSkipped = $script:Progress.Skipped
                ObjectsFailed = $script:Progress.Failed
            }
            Details = @()
        }

        # Display simple report
        Write-Output "`n$ReportTitle"
        Write-Output "====================="
        Write-Output "Start Time: $($reportData.Summary.StartTime)"
        Write-Output "Duration: $($reportData.Summary.Duration)"
        Write-Output "`nSummary Statistics:"
        Write-Output "-----------------"
        Write-Output "Total Objects Found:`t`t$($reportData.Summary.TotalObjects)"
        Write-Output "Processed:`t`t`t$($reportData.Summary.ObjectsProcessed)"
        Write-Output "Changed:`t`t`t$($reportData.Summary.ObjectsChanged)"
        Write-Output "Skipped Total:`t`t`t$($reportData.Summary.ObjectsSkipped)"
        Write-Output "Failed:`t`t`t`t$($reportData.Summary.ObjectsFailed)"
        if ($WhatIfPreference) {
            Write-Output "Would Have Changed:`t`t$($reportData.Summary.ObjectsChanged)"
        }

        # Generate detailed report if requested
        if ($DetailedReport) {
            Write-Output "`nDetailed Device Status:"
            Write-Output "---------------------"
            Write-Output "DeviceName`t`tValue`t`tStatus"
            Write-Output "----------`t`t--------`t`t------"
            
            # Use deviceResults queue for detailed status
            foreach ($deviceResult in $script:ProcessResults) {
                Write-Output "$($deviceResult.DeviceName)`t`t$($deviceResult.ScopeTag)`t`t$($deviceResult.Status)"
            }
            Write-Output ""
        }

        # Save report to disk if requested
        if ($script:ReportDisk) {
            $reportPath = Join-Path $script:ReportPath "ScopeTagReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            if (-not (Test-Path $script:ReportPath)) {
                New-Item -ItemType Directory -Path $script:ReportPath -Force | Out-Null
            }
            $reportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportPath -Force
            Write-Verbose "$(&$script:GetTimestamp),Info, Saved report to: $reportPath"
        }

        return $reportData
    }
    catch {
        Write-Error "$(&$script:GetTimestamp),Error, Failed to generate report: $_"
        throw
    }
}
function Convert-PSObjectArrayToHashTable {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject[]]$PSObjectArray,

        [Parameter(Mandatory)]
        [string]$IdProperty
    )

    Begin {
        $HashTable = @{}
    }
    Process {
        foreach ($PSObject in $PSObjectArray) {
            $IdValue = $PSObject.$IdProperty
            if ($IdValue) {
                $HashTable[$IdValue] = $PSObject
            }
            else {
                Write-Warning "Object $($PSObject) does not have a valid '$IdProperty' property. Skipping."
            }
        }
    }
    End {
        return $HashTable
    }
}

#endregion
#region ---------------------------------------------------[[Script Execution]------------------------------------------------------
$StartTime = $script:GetTimestamp

try {
    #Sign in to Graph
    try {$MgGraphAccessToken = Invoke-ConnectMgGraph -RequiredScopes $RequiredScopes
        Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Success to get Access Token to Graph"}
    catch {
        Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Failed to get Access Token to Graph, with error: $_"
        throw
    }

    #Prepare filter to get devices
    $GraphProperties = 'id,deviceName,operatingSystem,roleScopeTagIds,AzureAdDeviceId'
    if ($OperatingSystems -contains 'All') {$GraphFilters = $null} 
    else {
        $GraphFilters = ($OperatingSystems | ForEach-Object { 
        "operatingSystem eq '$_'" 
        }) -join ' or '
        }
    #Get devices with invoke-mggraphrequest
    $Devices = @()
    $Devices = Invoke-MgGraphRequestSingle `
        -RunProfile 'beta' `
        -Object 'deviceManagement/managedDevices' `
        -Method 'GET' `
        -Properties $GraphProperties `
        -Filters $GraphFilters 
    
    if ($Devices -and $Devices.Count -gt 0) {
        Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Retrieved total of $($Devices.Count) devices"
        $script:Progress.Total = $Devices.Count}
    else {
        Write-Warning "$(&$script:GetTimestamp),Warning,$($MyInvocation.MyCommand.Name),No devices found for the specified criteria"
        throw "No devices found for the specified criteria"
    }

    #Get sign-in logs
    try {
        $GraphProperties = 'deviceDetail,userPrincipalName,userId'
        $GraphFilters = "appDisplayName eq 'Windows Sign In' and status/errorCode eq 0 and isInteractive eq true and clientAppUsed eq 'Mobile Apps and Desktop clients' and createdDateTime gt $($SignInsStartTime.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
        $SignInLogs = @()
        $SignInLogs = Invoke-MgGraphRequestSingle `
            -RunProfile 'beta' `
            -Method 'GET' `
            -Object 'auditLogs/signIns' `
            -Properties $GraphProperties `
            -Filters $GraphFilters 

        if ($SignInLogs -and $SignInLogs.Count -gt 0) {
            Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Retrieved total of $($SignInLogs.Count) Sign In logs"}
        else {
            Write-Warning "$(&$script:GetTimestamp),Warning,$($MyInvocation.MyCommand.Name),No SignIn logs found for the specified criteria"
            throw "No devices found for the specified criteria"
        }
   }   
    catch {
        Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Failed to get SignIn logs: $_"
        throw
    }
    #Get primary users of all devices
    try {
        $GraphProperties = 'deviceDetail,userPrincipalName,userId'
        $GraphFilters = "" # Add your filter here if needed
        $AllPrimaryUsers = invoke-mggraphrequestbatch `
            -RunProfile 'beta' `
            -Method 'GET' `
            -Object 'deviceManagement/managedDevices' `
            -Objects $Devices `
            -Query '/users' `
            -GraphProperties $GraphProperties `
            -GraphFilters $GraphFilters `
            -BatchSize $BatchSize `
            -WaitTime $WaitTime `
            -MaxRetry $MaxRetry

        if ($AllPrimaryUsers -and $AllPrimaryUsers.Count -gt 0) {
            Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Retrieved total of $($AllPrimaryUsers.Count) Primary Users"
            $script:Progress.Total = $AllPrimaryUsers.Count}
        else {
            Write-Warning "$(&$script:GetTimestamp),Warning,$($MyInvocation.MyCommand.Name),No Primary Users found for the specified criteria"
            throw "No Primary Users found for the specified criteria"
        }
        #Convert Primary Users to hash table for faster lookups
        $AllPrimaryUsersHash = Convert-PSObjectArrayToHashTable -PSObjectArray $AllPrimaryUsers -IdProperty 'id'
    }
    catch {
        Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Failed to get primary users: $_"
        throw
    }
                    
        # Process results and update progress
        foreach ($device in $Devices) {
            #Get current Primary User
            $primaryuser = $null
            $SignInUsers = $null
            $MostFrequentUser = $null
            $script:Progress.Current++
            if ($AllPrimaryUsersHash.ContainsKey($device.id)) {
                $PrimaryuserHash = $AllPrimaryUsersHash[$device.id]
                if ($PrimaryuserHash.body.value.userprincipalname) {
                    $primaryuser = $PrimaryuserHash.body.value.userprincipalname
                    write-verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Success to get Primary User $($Primaryuser) for $($Device.DeviceName) from batch lookup"
                }
                else {
                    $primaryUser = ""
                    write-warning "$(&$script:GetTimestamp),Warning,$($MyInvocation.MyCommand.Name),Warning Primary user for device $($Device.DeviceName) is missing"
                }
            }
            else {
                $primaryUser = ""
                write-warning "$(&$script:GetTimestamp),Warning,$($MyInvocation.MyCommand.Name),Warning Primary user for device $($Device.DeviceName) is missing"
            }

            # Get sign in logs for the device
            $SignInLogsOnDevice = $SignInLogs | Where-Object {
                $_.deviceDetail.deviceid -eq $Device.AzureAdDeviceId -and (
                    $enrollmentaccounts.count -lt 1 -or $_.userprincipalname -notmatch $EnrollmentaccountsFilter
                )
            }
            if ($SignInLogsOnDevice){$SignInUsers = $SignInLogsOnDevice | Select-Object userprincipalname, UserId | Group-Object userprincipalname}
            else{write-warning "$(&$script:GetTimestamp),Warning,$($MyInvocation.MyCommand.Name),Device $($Device.DeviceName) is skipped due to missing Sign-In logs"}

            if($SignInUsers -and $SignInUsers.Count -gt 0) {
                Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Success to get Sign In logs for device $($Device.DeviceName)"
                $MostFrequentUser = $SignInUsers | Sort-Object count | Select-Object -Last 1
                $MostFrequentUserPrincipalname = $MostFrequentUser.group[0].UserPrincipalName
                $MostFrequentUserID = $MostFrequentUser.group[0].UserID

                if (($MostFrequentUserPrincipalname) -and ($MostFrequentUserid) -and ($MostFrequentUserPrincipalname -ne $PrimaryUser))
                {
                write-verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),to determine change needed on Device $($device.DeviceName) primaryuser from $($PrimaryUser) to $($MostFrequentUserPrincipalname)"
                $Body = @{ "@odata.id" = "https://graph.microsoft.com/beta/users/$MostFrequentUserid" } | ConvertTo-Json
                    if ($PSCmdlet.ShouldProcess) {
                        try {
                            invoke-mgGraphRequestSingle`
                            -RunProfile 'beta' `
                            -Method 'POST' `
                            -Object 'deviceManagement/managedDevices' `
                            -Query '/users/$ref' `
                            -body $Body

                            write-verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Success to set Primary User $($MostFrequentUserPrincipalname) for device $($device.DeviceName)"
                        }
                        catch {
                            write-Warning "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Failed to set Primary User $($MostFrequentUserPrincipalname) for device $($device.DeviceName) with error: $_"
                        }
                    }
                    else {
                        write-verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),WhatIf: Would set Primary User $($MostFrequentUserPrincipalname) for device $($device.DeviceName)"
                    }
                }
                else{
                    if (!$MostFrequentUserPrincipalname){
                        write-verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Success to determine that Device $($device.DeviceName) has no logins in collected logs"}
                    else {write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Success to determine that Device $($device.DeviceName) have correct Primary User $($PrimaryUser)"}
                    }
                }
            else {
                Write-Warning "$(&$script:GetTimestamp),Warning,$($MyInvocation.MyCommand.Name),No SignIn logs found for device $($Device.DeviceName)"
                continue
            }
        }
        Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Processing complete. Success: $($script:Progress.Success), Failed: $($script:Progress.Failed), Skipped: $($script:Progress.Skipped)"

}
catch {
    Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Script execution failed: $_"
}
finally {
    # Generate report if requested
 #   if ($ReturnReport) {
 #       if($DetailedReport) {
 #           Invoke-ScriptReport -DetailedReport $true -ScriptAction $ScriptAction
 #           Write-Verbose "$(&$script:GetTimestamp),Info, Generating detailed report"
 #       }
 #       else {
 #           Invoke-ScriptReport -DetailedReport $false -ScriptAction $ScriptAction
 #           Write-Verbose "$(&$script:GetTimestamp),Info, Generating summary report"
 #       }
 #   }

    # Disconnect and cleanup
    try {
        #Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Disconnected from Graph"
        
        # Clear essential variables
        $script:ProcessResults = $null
        $script:ProcessErrors = $null
        $script:Progress = $null
        $MgGraphAccessToken = $null
        
        # Cleanup memory after executing a function
        try {
            $MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
            Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Script memory usage before cleanup: $MemoryUsage MB"
            # Get all variables in the script scope
            $scriptVariables = Get-Variable -Scope Script | Where-Object {$_.Name -notin @("PSBoundParameters","MyInvocation","args","StackTrace","Error","ExecutionContext","Matches")}
            # Remove each variable from the script scope
            foreach ($variable in $scriptVariables) {
                try {
                    Remove-Variable -Name $variable.Name -Scope Script -ErrorAction SilentlyContinue
                    Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Removed variable '$($variable.Name)' from script scope"
                }
                catch {
                    Write-Warning "$(&$script:GetTimestamp),Warning,$($MyInvocation.MyCommand.Name),Failed to remove variable '$($variable.Name)': $_"
                }
            }
            [System.GC]::Collect()
            $MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
            Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Script memory usage after cleanup: $MemoryUsage MB"
        }
        catch {
            Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Script failed to cleanup memory garbage: $_"
        }
    }
    catch {
        Write-Error "$(&$script:GetTimestamp),Error,$($MyInvocation.MyCommand.Name),Failed to cleanup: $_"
    }
}
#endregion