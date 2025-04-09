<#PSScriptInfo
.SYNOPSIS
    Script for Intune to set Primary User on Device

.DESCRIPTION
    This script will get the Entra Sign in logs for Windows Sign ins
    The script then determine who has logged on to the device the most times in the last 30 days and set the Primary user to that user
    The script uses Ms Graph with MGGraph modules

.EXAMPLE
   .\Intune-Set-PrimaryUser.ps1
    Will set the primary user for devices in Intune with default settings

.EXAMPLE
    .\Intune-Set-PrimaryUser.ps1 -OperatingSystems All -DetailedReport $true -ReportDisk $true
    Will set the primary user for all devices in Intune and return a detailed report to disk

.NOTES
    Written by Mr-Tbone (Tbone Granheden) Coligo AB
    torbjorn.granheden@coligo.se

.VERSION
    5.0

.RELEASENOTES
    1.0 2023-02-14 Initial Build
    2.0 2021-03-01 Large update to use Graph batching and reduce runtime
    3.0 2024-07-19 Added support for Group filtering and some bug fixes
    4.0 2025-03-21 New functions and new structure for the script
    5.0 2025-04-09 Changed all requests to use invoke-mggraphrequets and support Powershell 5.1 and 7.4

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
    4.0.2503.1 - Added new functions and new structure for the script
    5.0.2504.1 - Changed all requests to use invoke-mggraphrequets
#>

#region ---------------------------------------------------[Set script requirements]-----------------------------------------------
#
#Requires -Modules Microsoft.Graph.Authentication
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
    [string]$ReportPath = ("c:\Reports"), # Default report path

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

    )
#endregion

#region ---------------------------------------------------[Set global script settings]--------------------------------------------
Set-StrictMode -Version Latest
$script:GetTimestamp    = { ([DateTime]::Now).ToString('yyyy-MM-dd HH:mm:ss') }
if ($VerboseLogging) {$VerbosePreference = 'Continue'}
else {$VerbosePreference = 'SilentlyContinue'}
# Exit if running as a managed identity in PowerShell 7.2 due to bugs connecting to MgGraph https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/3151
if ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER -and $PSVersionTable.PSVersion -eq [version]"7.2.0") {
    Write-Error "$($script:GetTimestamp.Invoke()),Error, This script cannot run as a managed identity in PowerShell 7.2. Please use a different version of PowerShell."
    exit 1}
# Add garbage collection settings to preserve memory
[System.Runtime.GCSettings]::LargeObjectHeapCompactionMode = 'CompactOnce'
[System.GC]::WaitForPendingFinalizers()
#endregion

#region ---------------------------------------------------[Import Modules and Extensions]-----------------------------------------
# Disable verbose logging when loding required modules
$currentVerbosePreference = $VerbosePreference
$VerbosePreference = 'SilentlyContinue'
try {Import-Module Microsoft.Graph.Authentication}
catch {Write-Error "$($script:GetTimestamp.Invoke()),Error, Failed to import required modules: $_"
    throw}
# Restore original logging level
finally {$VerbosePreference = $currentVerbosePreference}
#endregion

#region ---------------------------------------------------[Static Variables]------------------------------------------------------
[String]$ScriptAction   = "Set Primary User" # Report Title for the action performed by the script

# Reporting variable with values and types for reporting
$script:Progress = @{
    Total   = [int]0
    Current = [int]0
    Success = [int]0
    Failed  = [int]0
    Skipped = [int]0
}

# Reporting variable for results
$script:ProcessResults = [System.Collections.Queue]::new()

# Required Graph API scopes
[System.Collections.ArrayList]$RequiredScopes      = "DeviceManagementManagedDevices.ReadWrite.All", "AuditLog.Read.All", "User.Read.All"

[datetime]$SignInsStartTime     = (Get-Date).AddDays(-$SigninsTimeSpan )
$SignInLogs                     = @() # Array for sign-in logs
$devices                        = @() # Array for Intune devices
$AllPrimaryUsersHash            = @{} # Hash table for primary users
$GraphProperties                = $null # Graph API properties
$GraphFilters                   = $null # Graph API filters
$GraphBody                      = $null # Graph API body
$MgGraphAccessToken             = $null # Microsoft Graph access token
$script:EndTime                 = $null # Script end time

# Set the enrollment accounts filter for the Graph API request
$EnrollmentAccountsFilter = if ($EnrollmentAccounts) { $EnrollmentAccounts -join '|' } else { $null }
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

        # Check for existing connection
        try {
            $context = Get-MgContext
            if ($context) {
                Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Using existing Graph connection for account: $($context.Account)"
                $GraphAccessToken = (Get-MgContext).Account
                return $GraphAccessToken # Return the account
            }
        }
        catch {
            Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Failed to check existing Graph connection: $_"
        }
        # Detect execution context
        try {
            if ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER) {
                $ManagedIdentity = $true
                Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Execution context: Managed Identity"
            } else {
                Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Execution context: Interactive"
            }
        }
        catch {
            Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Failed to determine execution context: $_"
            throw
        }
    }
    Process {
        try {
            if ($ManagedIdentity) {
                # Check for required environment variables
                if (-not $env:IDENTITY_ENDPOINT -or -not $env:IDENTITY_HEADER) {
                    Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Required environment variables IDENTITY_ENDPOINT and IDENTITY_HEADER are not set."
                    throw
                }

                try {
                    # Get managed identity token
                    $headers = @{
                        'X-IDENTITY-HEADER' = "$env:IDENTITY_HEADER"
                        'Metadata' = 'True'
                    }
                    $response = Invoke-RestMethod -Uri "$($env:IDENTITY_ENDPOINT)?resource=$resourceURL" -Method GET -Headers $headers -TimeoutSec 30
                    $GraphAccessToken = $response.access_token
                    Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Retrieved managed identity token"
                }
                catch {
                    Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Failed to get managed identity token: $_"
                    throw
                }
                # Connect to Microsoft Graph using the token
                try {
                    $GraphVersion = (Get-Module -Name 'Microsoft.Graph.Authentication').Version
                    Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Graph module version: $GraphVersion"

                    $tokenParams = @{
                        NoWelcome = $true
                    }
                    if ($GraphVersion -ge [version]"2.0.0") {
                        $tokenParams['Identity'] = $true
                    } else {
                        $tokenParams['AccessToken'] = $GraphAccessToken
                    }
                    Connect-MgGraph @tokenParams
                    Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Connected using Graph SDK $GraphVersion"
                }
                catch {
                    Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Failed to connect to Microsoft Graph: $_"
                    throw
                }
            }
            else { # Interactive Authentication
                try {
                    Connect-MgGraph -Scope $RequiredScopes -NoWelcome
                    Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Connected interactively to Graph"
                }
                catch {
                    Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Failed to connect interactively: $_"
                    throw
                }
            }
            # Validate permission scopes
            try {
                $CurrentPermissions = (Get-MgContext).Scopes
                foreach ($RequiredScope in $RequiredScopes) {
                    if ($RequiredScope -notin $CurrentPermissions) {
                        Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Missing required scope: $RequiredScope"
                        throw
                    }
                    Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Verified scope: $RequiredScope"
                }
            }
            catch {
                Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Failed to validate permissions: $_"
                throw
            }
            # Return the access token or context
            if ($null -ne $GraphAccessToken -and $GraphAccessToken.getType() -eq 'System.String') {
                Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Successfully authenticated with access token"
                return $GraphAccessToken # Return the access token
            }
            else {
                try {
                    $GraphAccessToken = (Get-MgContext).Account
                    Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Successfully authenticated as: $GraphAccessToken"
                    return $GraphAccessToken # Return the account
                }
                catch {
                    Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Failed to get account details: $_"
                    throw
                }
            }
        }
        catch {
            Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Script execution failed: $_"
            throw
        }
    }

    End {
        # Cleanup memory after executing a function
        try {
            $MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
            Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Memory usage before cleanup: $MemoryUsage MB"
            # Get all parameters of the function
            $params = $PSBoundParameters.Keys
            # Remove each parameter from the script scope
            foreach ($param in $params) {
                Remove-Variable -Name $param -Scope Local -ErrorAction SilentlyContinue |out-null
            }
            [System.GC]::Collect()
            $MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
            Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Memory usage after cleanup: $MemoryUsage MB"
        }
        catch {
            Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Failed to cleanup memory garbage: $_"
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
            HelpMessage = "The HTTP method for the request(e.g., 'GET', 'PATCH', 'POST', 'DELETE')")]
        [ValidateSet('GET', 'PATCH', 'POST', 'DELETE')]
        [String]$Method = "GET",
        
        [Parameter(Mandatory,
            HelpMessage = "The Graph API endpoint path to target (e.g., 'me', 'users', 'groups')")]
        [string]$Object,
    
        [Parameter(Mandatory,
            HelpMessage = "Array of objects to process in batches")]
        [System.Object[]]$Objects,
    
        [Parameter(Mandatory,
            HelpMessage = "The Graph API query on the objects")]
        [string]$query,
    
        [Parameter(HelpMessage = "Request body for POST/PATCH operations")]
        [object]$Body,
        
        [Parameter(HelpMessage = "Graph API properties to include")]
        [string[]]$Properties,
    
        [Parameter(HelpMessage = "Graph API filters to apply")]
        [string]$Filters,
    
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
        $script:GetTimestamp = { ([DateTime]::Now).ToString('yyyy-MM-dd HH:mm:ss') }
        $starttime = $($script:GetTimestamp.Invoke())
        try {
            $Retrycount = 0
            $CollectedObjects = [System.Collections.Generic.List[PSObject]]::new()
            $RetryObjects = [System.Collections.Generic.List[PSObject]]::new()
            $LookupHash = @{}
            
            # Check execution context
            if ($env:AUTOMATION_ASSET_ACCOUNTID) {
                [Bool]$ManagedIdentity = $true
                Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Running in Azure Automation context"
            }
            else {
                [Bool]$ManagedIdentity = $false
                Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Running in Local PowerShell context"
            }
            
            Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Start processing with $($Objects.Count) objects"
        }
        catch {
            Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Failed to initialize with error: $_"
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
                    
                    Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Processing started with $TotalObjects objects"                    
                    
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
                                if ($Properties) {
                                    $select = $Properties -join ','
                                    $urlParams += "`$select=$select"
                                }

                                # Add filters if specified
                                if ($Filters) {
                                    $urlParams += "`$filter=$([System.Web.HttpUtility]::UrlEncode($Filters))"
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
                            Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Created batch for items $($i) to $([Math]::Min($i + $BatchSize, $TotalObjects)) of $TotalObjects total items"
                            }
                        }
                        catch {
                            Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Failed to create batch with error:$_"
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
                                
                                Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Successfully sent the request"
                            }
                            catch {
                                Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Failed to send batch request with error: $_"
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
                                            Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Successfully processed GET for object $($response.id)" 
                                        }
                                        201 {
                                            # POST success
                                            [void]$CollectedObjects.Add($response)
                                            Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Successfully processed POST for object $($response.id)" 
                                        }
                                        204 {
                                            # PATCH/DELETE success
                                            [void]$CollectedObjects.Add($response)
                                            Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Successfully processed $Method for object $($response.id)" 
                                        }
                                        400 { 
                                            Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Bad request for object $($response.id) - Status: $($response.status)"
                                            [void]$RetryObjects.Add($response)
                                        }
                                        403 { 
                                            Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Access denied to object $($response.id) - Status: $($response.status)"
                                        }
                                        404 { 
                                            Write-Warning "$($script:GetTimestamp.Invoke()),Warning,$($MyInvocation.MyCommand.Name),Object $($response.id) not found - Status: $($response.status)"
                                        }
                                        429 {
                                            [void]$RetryObjects.Add($response)
                                            Write-Warning "$($script:GetTimestamp.Invoke()),Warning,$($MyInvocation.MyCommand.Name),Throttling occurred for object $($response.id) - Status: $($response.status)"
                                        }
                                        default {
                                            Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Unexpected status $($response.status) for object $($response.id)"
                                            [void]$RetryObjects.Add($response)
                                        }
                                    }
                                }
                                catch {
                                    Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Failed to process response: $_"
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
                                        Write-Warning "$($script:GetTimestamp.Invoke()),Warning,$($MyInvocation.MyCommand.Name),Throttling detected, waiting $backoffWait seconds (Retry: $Retrycount)"
                                        Start-Sleep -Seconds $backoffWait
                                    }
                                }
                            }
                            catch {
                                Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Batch failed to handle throttling: $_"
                                throw
                            }
                        }

                        # Handle retries
                    if ($RetryObjects.Count -gt 0 -and $MaxRetry -gt 0) {
                        $Retrycount++
                        $MaxRetry--
                        Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Sarting retry $Retrycount with $($RetryObjects.Count) objects"
                        # The objects to retry are the ones that had errors
                        $Objects = $RetryObjects | ForEach-Object {$Objects | Where-Object {$_.id -eq $_.id}}
                    }
                }
            
            catch {
                Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Failed in retry loop: $_"
                throw
                }
            
            } while ($RetryObjects.Count -gt 0 -and $MaxRetry -gt 0)

            Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Successfully processed $($CollectedObjects.Count) objects"

            # Build return hashtable
            return $CollectedObjects   
        }
        catch {
            Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Failed in main process block with error: $_"
            throw
        }
    }
    
    End {
        # Cleanup memory after executing a function
        try {
            $MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
            Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Memory usage before cleanup: $MemoryUsage MB"
            # Get all parameters of the function
            $params = $PSBoundParameters.Keys
            # Remove each parameter from the script scope
            foreach ($param in $params) {
                Remove-Variable -Name $param -Scope Local -ErrorAction SilentlyContinue
            }
            [System.GC]::Collect()
            $MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
            Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Memory usage after cleanup: $MemoryUsage MB"
        }
        catch {
            Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Failed to cleanup memory garbage: $_"
        }
    }
}
function Invoke-MgGraphRequestSingle {
[CmdletBinding()]
    Param(
        [Parameter(Mandatory,
            HelpMessage = "The Graph API version ('beta' or 'v1.0')")]
        [ValidateSet('beta', 'v1.0')]
        [string]$RunProfile = "v1.0",
    
        [Parameter(Mandatory,
            HelpMessage = "The HTTP method for the request(e.g., 'GET', 'PATCH', 'POST', 'DELETE')")]
        [ValidateSet('GET', 'PATCH', 'POST', 'DELETE')]
        [String]$Method = "GET",
        
        [Parameter(Mandatory,
            HelpMessage = "The Graph API endpoint path to target (e.g., 'me', 'users', 'groups')")]
        [string]$Object,
    
        [Parameter(HelpMessage = "Request body for POST/PATCH operations")]
        [string[]]$Body,
        
        [Parameter(HelpMessage = "Graph API properties to include")]
        [string[]]$Properties,
    
        [Parameter(HelpMessage = "Graph API filters to apply")]
        [string]$Filters,
    
        [Parameter(HelpMessage = "Page size (max 1000 objects per page)")]
        [ValidateRange(1,1000)]
        [int]$PageSize = 1000,
    
        [Parameter(HelpMessage = "Delay between requests if throttled in milliseconds")]
        [ValidateRange(100,5000)]
        [int]$WaitTime = 1000,
    
        [Parameter(HelpMessage = "Maximum retry attempts for failed requests when throttled")]
        [ValidateRange(1,10)]
        [int]$MaxRetry = 3
    )
    Begin {
        $script:GetTimestamp = { ([DateTime]::Now).ToString('yyyy-MM-dd HH:mm:ss') }
        $PsobjectResults = [System.Collections.ArrayList]::new()
        $RetryCount = 0

        # Build base URI
        $uri = "https://graph.microsoft.com/$RunProfile/$Object"
        $queryParams = [System.Collections.ArrayList]::new()

        # Add page size parameter
        if ($Method -eq 'GET') {
            [void]$queryParams.Add("`$top=$PageSize")
        }

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

        # Combine query parameters into URI
        if ($queryParams.Count -gt 0) {
            $uri += "?" + ($queryParams -join '&')
        }
    }
    Process {
        do {
            try {
                Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Making request to: $uri"
                $i = 1
                do {
                    Write-Verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Requesting page $i with $PageSize items"
                    $params = @{
                        Method      = $Method
                        Uri         = $uri
                        ErrorAction = 'Stop'
                        OutputType  = 'PSObject'
                    }
                    
                    if ($Method -in 'POST', 'PATCH') {
                        $params['Body'] = $Body
                        $params['Headers'] = @{
                            'Content-Type' = 'application/json'
                        }
                    }
                    try {
                        $response = Invoke-MgGraphRequest @params
                        Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Request successful"
                    }
                    catch {Write-Verbose "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Request failed with error: $_"}
                    if ($Method -eq 'POST') {
                    return
                    }
                    if ($response.value) {
                        [void]$PsobjectResults.AddRange($response.value)
                    }
                    Write-verbose "$(&$script:GetTimestamp),Info,$($MyInvocation.MyCommand.Name),Retrieved page $i, Now total: $($PsobjectResults.Count) items"

                    # Check for next page
                    if ($response.PSObject.Properties.Name -contains '@odata.nextLink') {
                        if ($response.'@odata.nextLink') {
                            $uri = $response.'@odata.nextLink'
                            Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Next page found: $uri"
                        }
                    }
                    else {
                        Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),No more pages found"
                        $uri = $null
                    }

                    $i++
                } while ($uri)
                Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Returning array with $($PsobjectResults.Count) items"
                return $PsobjectResults # Success, return results and exit retry loop
            }
            catch {
                $ErrorMessage = $_.Exception.Message
                Write-Warning "$($script:GetTimestamp.Invoke()),Warning,$($MyInvocation.MyCommand.Name),Request failed (Retry attempt $($RetryCount + 1)/$MaxRetry): $ErrorMessage"

                # Handle throttling or retry logic
                if ($_.Exception.Response.StatusCode -eq 429) {
                    $RetryAfter = ($_.Exception.Response.Headers | Where-Object {$_.Name -eq "Retry-After"}).Value
                    if ($RetryAfter) {
                        Write-Warning "$($script:GetTimestamp.Invoke()),Warning,$($MyInvocation.MyCommand.Name),Throttling detected. Waiting $($RetryAfter * 1000) milliseconds before retrying."
                        Start-Sleep -Milliseconds ($RetryAfter * 1000) # Convert seconds to milliseconds
                    } else {
                        $Delay = [math]::Min(($WaitTime * ([math]::Pow(2, $RetryCount))), 60000) # Exponential backoff, max 60,000 milliseconds (60 seconds)
                        Write-Warning "$($script:GetTimestamp.Invoke()),Warning,$($MyInvocation.MyCommand.Name),Throttling detected. No Retry-After header found. Waiting $($Delay) milliseconds before retrying."
                        Start-Sleep -Milliseconds $Delay
                    }
                } else {
                    $Delay = [math]::Min(($WaitTime * ([math]::Pow(2, $RetryCount))), 60000) # Exponential backoff, max 60,000 milliseconds (60 seconds)
                    Write-Warning "$($script:GetTimestamp.Invoke()),Warning,$($MyInvocation.MyCommand.Name),Non-throttling error. Waiting $($Delay) milliseconds before retrying."
                    Start-Sleep -Milliseconds $Delay
                }

                $RetryCount++
            }
        } while ($RetryCount -le $MaxRetry)

        Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Request failed after $($MaxRetry) retries. Aborting."
        throw "Request failed after $($MaxRetry) retries." # Re-throw the exception after max retries
    }

    End {
        # Cleanup memory after executing a function
        try {
            $MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
            Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Memory usage before cleanup: $MemoryUsage MB"
            # Get all parameters of the function
            $params = $PSBoundParameters.Keys
            # Remove each parameter from the script scope
            foreach ($param in $params) {
                Remove-Variable -Name $param -Scope Local -ErrorAction SilentlyContinue
            }
            [System.GC]::Collect()
            $MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
            Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Memory usage after cleanup: $MemoryUsage MB"
        }
        catch {
            Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Failed to cleanup memory garbage: $_"
        }
    }
}
function Invoke-ScriptReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, HelpMessage = "Title of the report")]
        [ValidateNotNullOrEmpty()]
        [string]$ReportTitle = "Script Report",

        [Parameter(Mandatory = $false, HelpMessage = "Action performed by the script")]
        [ValidateNotNullOrEmpty()]
        [string]$ScriptAction = "Primary User Assignment",

        [Parameter(Mandatory = $false, HelpMessage = "Include detailed report")]
        [bool]$DetailedReport = $script:DetailedReport,

        [Parameter(Mandatory = $false, HelpMessage = "Script Start Time")]
        [ValidateNotNullOrEmpty()]
        [datetime]$ScriptStartTime = [DateTime]::Now,

        [Parameter(Mandatory = $false, HelpMessage = "Script End Time")]
        [ValidateNotNullOrEmpty()]
        [datetime]$ScriptEndTime = [DateTime]::Now
    )

    Begin {
        $script:GetTimestamp = { ([DateTime]::Now).ToString('yyyy-MM-dd HH:mm:ss') }
        Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Starting report generation"
    }

    Process {
        try {
            # Validate $script:StartTime
            if (-not $ScriptStartTime -or -not ($ScriptStartTime -is [datetime])) {
                $ScriptStartTime = [DateTime]::Now
                Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Start time not provided, using current time: $ScriptStartTime"
            }
            if ($ScriptEndTime -and -not ($ScriptEndTime -is [datetime])) {
                $ScriptEndTime = [DateTime]::Now
                Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),End time not provided, using current time: $ScriptEndTime"
            }

            # Create report data structure using Progress values
            $reportData = @{
                Summary = @(
                    @{
                        StartTime         = $ScriptStartTime
                        Duration          = "{0:hh\:mm\:ss}" -f ($ScriptEndTime - $ScriptStartTime)
                        TotalObjects      = $script:Progress.Total
                        ObjectsProcessed  = $script:Progress.Current
                        ObjectsChanged    = $script:Progress.Success
                        ObjectsSkipped    = $script:Progress.Skipped
                        ObjectsFailed     = $script:Progress.Failed
                    }
                )
                Details = @()
            }

            # Display simple report
            Write-Output "`n$ReportTitle - $ScriptAction"
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

            # Generate detailed report if requested
            if ($DetailedReport) {
                Write-Output "`nDetailed Device Status:"
                Write-Output "---------------------"
                Write-Output "Object`t`tValue`t`tStatus"
                Write-Output "----------`t`t--------`t`t------"

                # Use deviceResults queue for detailed status
                foreach ($deviceResult in $script:ProcessResults) {
                    Write-Output "$($deviceResult.Object)`t`t$($deviceResult.Value)`t`t$($deviceResult.Status)"
                }
                Write-Output ""
            }

            # Save report to disk if requested
            if ($script:ReportDisk) {
                $reportPath = Join-Path $script:ReportPath "Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
                if (-not (Test-Path $script:ReportPath)) {
                    New-Item -ItemType Directory -Path $script:ReportPath -Force | Out-Null
                }
                $reportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportPath -Force
                Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Saved report to: $reportPath"
            }

            Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Report generation completed successfully"
            return $null
        }
        catch {
            Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Failed to generate report: $_"
            throw
        }
    }

    End {
        # Cleanup memory after executing the function
        try {
            $MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
            Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Memory usage before cleanup: $MemoryUsage MB"
            [System.GC]::Collect()
            $MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
            Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Memory usage after cleanup: $MemoryUsage MB"
        }
        catch {
            Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Failed to cleanup memory: $_"
        }
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
        # Initialize the hashtable
        $HashTable = @{}
    }

    Process {
        foreach ($PSObject in $PSObjectArray) {
            try {
                # Retrieve the value of the specified property
                $IdValue = $PSObject.$IdProperty

                if ($IdValue) {
                    # Add the object to the hashtable
                    $HashTable[$IdValue] = $PSObject
                } else {
                    Write-Warning "Object does not have a valid '$IdProperty' property. Skipping: $($PSObject | Out-String)"
                }
            }
            catch {
                Write-Warning "Failed to process object: $($PSObject | Out-String). Error: $_"
            }
        }
    }

    End {
        # Return the constructed hashtable
        return $HashTable
    }
}
#endregion
#region ---------------------------------------------------[[Script Execution]------------------------------------------------------
$Script:StartTime = [datetime]::Now

try {
    #Sign in to Graph
    try {$MgGraphAccessToken = Invoke-ConnectMgGraph -RequiredScopes $RequiredScopes
        Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Success to get Access Token to Graph"}
    catch {
        Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Failed to get Access Token to Graph, with error: $_"
        throw
    }

#Get Devices
    try{
        #Prepare filter and properties to get devices
        $GraphProperties = 'id,deviceName,operatingSystem,roleScopeTagIds,AzureAdDeviceId'
        if ($OperatingSystems -contains 'All') {$GraphFilters = $null} 
        else {
            $GraphFilters = ($OperatingSystems | ForEach-Object { 
            "operatingSystem eq '$_'" 
            }) -join ' or '
            }
        #Get devices with invoke-mggraphrequest
        $Devices = Invoke-MgGraphRequestSingle `
            -RunProfile 'beta' `
            -Method 'GET' `
            -Object 'deviceManagement/managedDevices' `
            -Properties $GraphProperties `
            -Filters $GraphFilters
        #Verify if devices were found   
        if ($Devices -and $Devices.Count -gt 0) {
            Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Retrieved total of $($Devices.Count) devices"
            $script:Progress.Total = $Devices.Count}
        else {
            Write-Warning "$($script:GetTimestamp.Invoke()),Warning,$($MyInvocation.MyCommand.Name),No devices found for the specified criteria"
            throw "No devices found for the specified criteria"
        }
    }
    catch {
        Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Failed to get devices: $_"
        throw
    }

#Get sign-in logs
    try {
        #Prepare filter and properties to get sign-in logs
        $GraphProperties = 'deviceDetail,userPrincipalName,userId'
        $GraphFilters = "appDisplayName eq 'Windows Sign In' and status/errorCode eq 0 and isInteractive eq true and clientAppUsed eq 'Mobile Apps and Desktop clients' and createdDateTime gt $($SignInsStartTime.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
        #Get sign-in logs with invoke-mggraphrequest
        $SignInLogs = Invoke-MgGraphRequestSingle `
            -RunProfile 'beta' `
            -Method 'GET' `
            -Object 'auditLogs/signIns' `
            -Properties $GraphProperties `
            -Filters $GraphFilters 
        #Verify if sign-in logs were found
        if ($SignInLogs -and $SignInLogs.Count -gt 0) {
            Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Retrieved total of $($SignInLogs.Count) Sign In logs"}
        else {
            Write-Warning "$($script:GetTimestamp.Invoke()),Warning,$($MyInvocation.MyCommand.Name),No SignIn logs found for the specified criteria"
            throw "No devices found for the specified criteria"
        }
   }   
    catch {
        Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Failed to get SignIn logs: $_"
        throw
    }
    
#Get primary users for all devices
    try {
        #Prepare filter and properties to get primary users
        $GraphProperties = 'deviceDetail,userPrincipalName,userId'
        $GraphFilters = ""
        #Get primary users with invoke-mggraphrequestbatch
        $AllPrimaryUsers = invoke-mggraphrequestbatch `
            -RunProfile 'beta' `
            -Method 'GET' `
            -Object 'deviceManagement/managedDevices' `
            -Objects $Devices `
            -Query '/users' `
            -Properties $GraphProperties `
            -Filters $GraphFilters `
            -BatchSize $BatchSize `
            -WaitTime $WaitTime `
            -MaxRetry $MaxRetry

        #Verify if primary users were found
        if ($AllPrimaryUsers -and $AllPrimaryUsers.Count -gt 0) {
            Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Retrieved total of $($AllPrimaryUsers.Count) Primary Users"
            $script:Progress.Total = $AllPrimaryUsers.Count}
        else {
            Write-Warning "$($script:GetTimestamp.Invoke()),Warning,$($MyInvocation.MyCommand.Name),No Primary Users found for the specified criteria"
            throw "No Primary Users found for the specified criteria"
        }
        #Convert Primary Users to hash table for faster lookups
        $AllPrimaryUsersHash = Convert-PSObjectArrayToHashTable -PSObjectArray $AllPrimaryUsers -IdProperty 'id'
    }
    catch {
        Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Failed to get primary users: $_"
        throw
    }
      
# Process results and update progress
    foreach ($device in $Devices) {
        # Initialize variables used in the loop
        $PrimaryUser = $null
        $SignInUsers = $null
        $MostFrequentUser = $null
        $script:Progress.Current++
    
        try {
            # Get current Primary User
            if ($AllPrimaryUsersHash.ContainsKey($device.id)) {
                $PrimaryUserHash = $AllPrimaryUsersHash[$device.id]
                if ($PrimaryUserHash -and $PrimaryUserHash.body -and $PrimaryUserHash.body.value -and $PrimaryUserHash.body.value.userPrincipalName) {
                    $PrimaryUser = $PrimaryUserHash.body.value.userPrincipalName
                    Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Success to get Primary User $($PrimaryUser) for $($Device.DeviceName)"
                } else {
                    $PrimaryUser = ""
                    Write-Warning "$($script:GetTimestamp.Invoke()),Warning,$($MyInvocation.MyCommand.Name),Primary user for device $($Device.DeviceName) is missing or invalid"
                }
            }
            else {
                $PrimaryUser = ""
                Write-Warning "$($script:GetTimestamp.Invoke()),Warning,$($MyInvocation.MyCommand.Name),Primary user for device $($Device.DeviceName) is missing in the hash table"
            }
    
            # Get sign-in logs for the device
            $SignInLogsOnDevice = $SignInLogs | Where-Object {
                $_.deviceDetail.deviceId -eq $Device.AzureAdDeviceId -and (
                    $EnrollmentAccounts.Count -lt 1 -or $_.userPrincipalName -notmatch $EnrollmentAccountsFilter
                )
            }
    
            if ($SignInLogsOnDevice) {
                $SignInUsers = $SignInLogsOnDevice | Select-Object userPrincipalName, UserId | Group-Object userPrincipalName
            }
            else {
                Write-Warning "$($script:GetTimestamp.Invoke()),Warning,$($MyInvocation.MyCommand.Name),Device $($Device.DeviceName) is skipped due to missing Sign-In logs"
                $script:Progress.Skipped++
                $script:ProcessResults.Enqueue([PSCustomObject]@{
                    Object  = $Device.DeviceName
                    Value = $PrimaryUser
                    Status      = "Skipped due to missing Sign-In logs"
                })
                continue
            }
    
            # Get the most frequent user from sign-in logs
            if ($SignInUsers -and $SignInUsers.Count -gt 0) {
                Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Success to get Sign In logs for device $($Device.DeviceName)"
                
                # Sort users by count and select the most frequent one
                $MostFrequentUser = $SignInUsers | Sort-Object Count | Select-Object -Last 1
    
                # Check if the most frequent user and its properties exist
                if ($MostFrequentUser -and $MostFrequentUser.group -and $MostFrequentUser.group.Count -gt 0) {
                    if ($MostFrequentUser.group[0] -and $MostFrequentUser.group[0].PSObject.Properties['userPrincipalName']) {
                        $MostFrequentUserPrincipalName = $MostFrequentUser.group[0].PSObject.Properties['userPrincipalName'].Value
                    } else {
                        $MostFrequentUserPrincipalName = $null
                    }

                    if ($MostFrequentUser.group[0] -and $MostFrequentUser.group[0].PSObject.Properties['UserId']) {
                        $MostFrequentUserID = $MostFrequentUser.group[0].PSObject.Properties['UserId'].Value
                    } else {
                        $MostFrequentUserID = $null
                    }
    
                    if ($MostFrequentUserPrincipalName -and $MostFrequentUserID -and ($MostFrequentUserPrincipalName -ne $PrimaryUser)) {
                        Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Determined change needed on Device $($Device.DeviceName) primary user from $($PrimaryUser) to $($MostFrequentUserPrincipalName)"
                        
                        if ($PSCmdlet.ShouldProcess("Device $($Device.DeviceName)", "Set Primary User to $($MostFrequentUserPrincipalName)")) {
                                try {
                                    # Prepare the request body
                                    $JsonDepth = if ($PSVersionTable.PSVersion -ge [version]"6.0.0") { 10 } else { 2 }
                                    $GraphBody = @{
                                        "@odata.id" = "https://graph.microsoft.com/beta/users/$MostFrequentUserID"
                                    } | ConvertTo-Json -Depth $JsonDepth

                                    # Attempt to set the primary user
                                    Invoke-MgGraphRequestSingle `
                                        -RunProfile 'beta' `
                                        -Method 'POST' `
                                        -Body $GraphBody `
                                        -Object "deviceManagement/managedDevices/$($Device.id)/users/`$ref"

                                    Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Successfully set Primary User $($MostFrequentUserPrincipalName) for device $($Device.DeviceName)"
                                    $script:Progress.Success++
                                    $script:ProcessResults.Enqueue([PSCustomObject]@{
                                        Object = $Device.DeviceName
                                        Value   = $MostFrequentUserPrincipalName
                                        Status     = "Success: Set Primary User to $($MostFrequentUserPrincipalName)"
                                    })
                                }
                                catch {
                                    Write-Warning "$($script:GetTimestamp.Invoke()),Warning,$($MyInvocation.MyCommand.Name),Failed to set Primary User $($MostFrequentUserPrincipalName) for device $($Device.DeviceName) with error: $_"
                                    $script:Progress.Failed++
                                    $script:ProcessResults.Enqueue([PSCustomObject]@{
                                        Object = $Device.DeviceName
                                        Value   = $MostFrequentUserPrincipalName
                                        Status     = "Failed: error: $_"
                                    })
                                }
                            } else {
                                Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),WhatIf: Would set Primary User $($MostFrequentUserPrincipalName) for device $($Device.DeviceName)"
                                $script:Progress.Skipped++
                                $script:ProcessResults.Enqueue([PSCustomObject]@{
                                    Object = $Device.DeviceName
                                    Value   = $MostFrequentUserPrincipalName
                                    Status     = "WhatIf: Would set Primary User to $($MostFrequentUserPrincipalName)"
                                })
                            }
                    }
                    else {
                        Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Device $($Device.DeviceName) already has the correct Primary User $($PrimaryUser)"
                        $script:Progress.Skipped++
                        $script:ProcessResults.Enqueue([PSCustomObject]@{
                            Object = $Device.DeviceName
                            Value   = $PrimaryUser
                            Status     = "Skipped: Correct Primary User $($PrimaryUser)"
                        })
                    }
                }
                else {
                    Write-Warning "$($script:GetTimestamp.Invoke()),Warning,$($MyInvocation.MyCommand.Name),No valid user data found in sign-in logs for device $($Device.DeviceName)"
                    $script:Progress.Skipped++
                    $script:ProcessResults.Enqueue([PSCustomObject]@{
                        Object = $Device.DeviceName
                        Value   = $PrimaryUser
                        Status     = "Skipped: No valid user data found in sign-in logs"
                    })
                }
            }
            else {
                Write-Warning "$($script:GetTimestamp.Invoke()),Warning,$($MyInvocation.MyCommand.Name),No SignIn logs found for device $($Device.DeviceName)"
                $script:Progress.Skipped++
                $script:ProcessResults.Enqueue([PSCustomObject]@{
                    Object = $Device.DeviceName
                    Value   = $PrimaryUser
                    Status     = "Skipped: No SignIn logs found"
                })
            }
        }
        catch {
            Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Failed to process device $($Device.DeviceName): $_"
            $script:Progress.Failed++
            $script:ProcessResults.Enqueue([PSCustomObject]@{
                Object = $Device.DeviceName
                Value   = $PrimaryUser
                Status     = "Failed: error: $_"
            })
        }
    }
    Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Processing complete. Success: $($script:Progress.Success), Failed: $($script:Progress.Failed), Skipped: $($script:Progress.Skipped)"
    $script:EndTime = [datetime]::Now
}
catch {
    Write-Error "$($script:GetTimestamp.Invoke()),Error,$($MyInvocation.MyCommand.Name),Script execution failed: $_"
}
finally {
# Generate report if requested
    if ($ReturnReport) {
        if($DetailedReport) {
            Invoke-ScriptReport -DetailedReport $true -ScriptAction $ScriptAction -ScriptStartTime $Script:StartTime -ScriptEndTime $script:EndTime
            Write-Verbose "$($script:GetTimestamp.Invoke()),Info, Generating detailed report"
        }
        else {
            Invoke-ScriptReport -DetailedReport $false -ScriptAction $ScriptAction -ScriptStartTime $Script:StartTime -ScriptEndTime $script:EndTime
            Write-Verbose "$($script:GetTimestamp.Invoke()),Info, Generating summary report"
        }
    }

# Disconnect and cleanup
    try {
        # Disconnect from Graph
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue *>$null
            Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Disconnected from Graph"
        } catch {
            Write-Error "$(([DateTime]::Now).ToString('yyyy-MM-dd HH:mm:ss')),Error,$($MyInvocation.MyCommand.Name),Failed to disconnect from Graph: $_"
        }
        # Clear essential variables
        $script:ProcessResults = $null
        $script:ProcessErrors = $null
        $script:Progress = $null
        $MgGraphAccessToken = $null
        
        # Cleanup memory after executing a function
        try {
            $MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
            Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Script memory usage before cleanup: $MemoryUsage MB"
            [System.GC]::Collect()
            $MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
            Write-Verbose "$($script:GetTimestamp.Invoke()),Info,$($MyInvocation.MyCommand.Name),Script memory usage after cleanup: $MemoryUsage MB"
            # Get all variables in the script scope
            $scriptVariables = Get-Variable -Scope Script | Where-Object {$_.Name -notin @("PSBoundParameters","MyInvocation","args","StackTrace","Error","ExecutionContext","Matches")}
            # Remove each variable from the script scope
            foreach ($variable in $scriptVariables) {
                try {Remove-Variable -Name $variable.Name -Scope Script -ErrorAction SilentlyContinue}
                catch {Write-Warning "$($script:GetTimestamp.Invoke()),Warning,$($MyInvocation.MyCommand.Name),Failed to remove variable '$($variable.Name)': $_"}
            }
        }
        catch {
            Write-Error "$(([DateTime]::Now).ToString('yyyy-MM-dd HH:mm:ss')),Error,$($MyInvocation.MyCommand.Name),Script failed to cleanup memory garbage: $_"
        }
    }
    catch {
        Write-Error "$(([DateTime]::Now).ToString('yyyy-MM-dd HH:mm:ss')),Error,$($MyInvocation.MyCommand.Name),Failed to cleanup: $_"
    }

}
#endregion