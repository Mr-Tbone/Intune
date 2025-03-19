#>
<#PSScriptInfo
.SYNOPSIS
    Script for Intune to set Scope Tag on device based on the Country attribute of the Primary user for Devices

.DESCRIPTION
    This script will get all devices
    Then also get all users
    Get the device primary users
    It will then get the find the country of the primary user
    It will then set the scope tag on the device based on the country of the primary owner

 .EXAMPLE
    .\Intune-setScopeTagBasedOnPrimaryUser.ps1 -OperatingSystems @('Windows') -DetailedReport $true
    Retrieves all Windows devices and sets scope tags based on primary user's country. Includes detailed reporting of each device's status.

.EXAMPLE
    .\Intune-setScopeTagBasedOnPrimaryUser.ps1 -OperatingSystems @('Windows','iOS','Android') -EnableWhatIf -VerboseLogging $true
    Shows what changes would be made to all Windows, iOS, and Android devices without actually making changes. Includes verbose logging for troubleshooting.

.EXAMPLE
    .\Intune-setScopeTagBasedOnPrimaryUser.ps1 -OperatingSystems @('All') -ReturnReport $true -DetailedReport $true -ReportDisk $true -ReportPath "C:\Reports\Intune" -BatchSize 15 -WaitTime 2000
    Processes all devices regardless of OS type, generates detailed reports both to console and disk, and uses custom batch settings for performance tuning.

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
#
#endregion

#region ---------------------------------------------------[Script Parameters]-----------------------------------------------
#endregion

#region ---------------------------------------------------[Modifiable Parameters and defaults]------------------------------------
# You can make changes to the defaults directly in the script or assign them at execution
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [ValidateSet('All', 'Windows', 'Android', 'iOS', 'macOS')]
    [string[]]$OperatingSystems = @('Windows', 'Android', 'iOS'),                     # Operating systems to target
    [Parameter()]
    [ValidateRange(0,1)]
    [bool]$ReturnReport = $true,                                # Return report after execution
    [Parameter()]
    [bool]$DetailedReport = $True,                              # Detailed report with device status
    [Parameter()]
    [bool]$ReportDisk = $true,                                  # Save report to disk
    [Parameter()]
    [string]$ReportPath = (Join-Path $PSScriptRoot "Reports"),  # Path to save report
    [Parameter()]
    [bool]$VerboseLogging = $true,                              # Enable verbose logging
    [Parameter()]
    [ValidateRange(1,20)]
    [int]$Batchsize = 20,                                       # Batch size for processing devices
    [Parameter()]
    [ValidateRange(100,5000)]
    [int]$WaitTime = 1000,                                      # Wait time in milliseconds between batches
    [Parameter()]
    [ValidateRange(1,10)]
    [int]$MaxRetry = 3,                                         # Maximum number of retries for failed requests
    [Parameter()]
    [switch]$EnableWhatIf                                       # Enable WhatIf mode manually
)

# Mapping table for country value to scope tag
$ScopeTagMap = @{
    'Sweden'    = 'SE'
    'Usa'       = 'US'
    'France'    = 'FR'
    # Add more countries as needed
}
#endregion

#region ---------------------------------------------------[Set global script settings]--------------------------------------------
Set-StrictMode -Version Latest
if ($VerboseLogging) {$VerbosePreference = 'Continue'}
else {$VerbosePreference = 'SilentlyContinue'}
#endregion

#region ---------------------------------------------------[Import Modules and Extensions]-----------------------------------------
# Save current VerbosePreference and temporarily disable verbose output to skip when importing modules
$currentVerbosePreference = $VerbosePreference
$VerbosePreference = 'SilentlyContinue'
try {
    Import-Module Microsoft.Graph.Authentication
}
catch {
    Write-Error "$(([DateTime]::UtcNow).ToString('yyyy-MM-dd HH:mm:ss')),Error, Failed to import required modules: $_"
    throw
}
finally {
    # Restore original VerbosePreference
    $VerbosePreference = $currentVerbosePreference
}
#endregion

#region ---------------------------------------------------[Static Variables]------------------------------------------------------
$script:GetTimestamp = {([DateTime]::Now).ToString('yyyy-MM-dd HH:mm:ss')}

# If EnableWhatIf is specified, set WhatIfPreference to True
if ($EnableWhatIf) {
    $WhatIfPreference = $true
    Write-Verbose "$(&$script:GetTimestamp),Info, WhatIf mode enabled via parameter"
}

# Use value types for logging
$script:Progress = @{
    Total = [int]0
    Current = [int]0
    Success = [int]0
    Failed = [int]0
    Skipped = [int]0
    DevicesNoPrimaryUser = [int]0
}

# variables for device results and errors
$script:deviceResults = [System.Collections.Concurrent.ConcurrentQueue[PSCustomObject]]::new()
$script:errors = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()

# Add garbage collection settings
[System.Runtime.GCSettings]::LargeObjectHeapCompactionMode = 'CompactOnce'
[System.GC]::WaitForPendingFinalizers()

# Progress tracking
$script:DeviceStatus = [System.Collections.Concurrent.ConcurrentDictionary[string,object]]::new()

# Required Graph API scopes
$RequiredScopes = [System.Collections.ArrayList]@(
    'DeviceManagementManagedDevices.ReadWrite.All',
    'DeviceManagementRBAC.Read.All',
    'User.Read.All',
    'Directory.Read.All'
)
#endregion

#region ---------------------------------------------------[Functions]------------------------------------------------------------

function Invoke-ConnectMgGraph {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.Collections.ArrayList]$RequiredScopes
    )
    Begin {
        $ErrorActionPreference = 'Stop'
        [string]$resourceURL = "https://graph.microsoft.com/"
        $GraphAccessToken = $null
        [bool]$ManagedIdentity = $false
        try {
            # Check for existing connection
            $context = Get-MgContext
            if ($context) {
                Write-Verbose "$(&$script:GetTimestamp),Info, Using existing Graph connection for account: $($context.Account)"
                return $context.Account
            }
        }
        catch {
            Write-Error "$(&$script:GetTimestamp),Error, Failed to check existing Graph connection: $_"
        }

        try {
            # Check execution context
            [bool]$ManagedIdentity = [bool]$env:AUTOMATION_ASSET_ACCOUNTID
            Write-Verbose "$(&$script:GetTimestamp),Info, Execution context: $($ManagedIdentity ? 'Managed Identity' : 'Interactive')"
        }
        catch {
            Write-Error "$(&$script:GetTimestamp),Error, Failed to determine execution context: $_"
        }
    }

    Process {
        if ($ManagedIdentity) {
            try {
                # Get managed identity token
                $headers = @{
                    'X-IDENTITY-HEADER' = "$env:IDENTITY_HEADER"
                    'Metadata' = 'True'
                }
                $response = Invoke-WebRequest -UseBasicParsing -Uri "$($env:IDENTITY_ENDPOINT)?resource=$resourceURL" -Method GET -Headers $headers
                $GraphAccessToken = ([System.Text.Encoding]::Default.GetString($response.RawContentStream.ToArray()) | ConvertFrom-Json).access_token
                Write-Verbose "$(&$script:GetTimestamp),Info, Retrieved managed identity token"
            }
            catch {
                Write-Error "$(&$script:GetTimestamp),Error, Failed to get managed identity token: $_"
                throw
            }

            try {
                # Get Graph module version
                $GraphVersion = (Get-Module -Name 'Microsoft.Graph.Authentication' -ErrorAction Stop).Version | 
                    Sort-Object -Descending | 
                    Select-Object -First 1
                Write-Verbose "$(&$script:GetTimestamp),Info, Detected Graph module version: $GraphVersion"
            }
            catch {
                Write-Error "$(&$script:GetTimestamp),Error, Failed to detect Graph module version: $_"
                throw
            }

            try {
                # Connect based on version
                if ($GraphVersion -ge '2.0.0') {
                    Connect-MgGraph -Identity -NoWelcome
                    $GraphAccessToken = ConvertTo-SecureString $GraphAccessToken -AsPlainText -Force
                    Write-Verbose "$(&$script:GetTimestamp),Info, Connected using Graph SDK 2.x"
                }
                else {
                    Connect-MgGraph -AccessToken $GraphAccessToken -NoWelcome
                    Write-Verbose "$(&$script:GetTimestamp),Info, Connected using Graph SDK 1.x"
                }
            }
            catch {
                Write-Error "$(&$script:GetTimestamp),Error, Failed to connect to Graph: $_"
                throw
            }
        }
        else {
            try {
                Connect-MgGraph -Scope $RequiredScopes -NoWelcome
                Write-Verbose "$(&$script:GetTimestamp),Info, Connected interactively to Graph"
            }
            catch {
                Write-Error "$(&$script:GetTimestamp),Error, Failed to connect interactively: $_"
                throw
            }
        }

        try {
            # Validate permissions
            $CurrentPermissions = (Get-MgContext).Scopes
            foreach ($RequiredScope in $RequiredScopes) {
                if (-not ($CurrentPermissions -contains $RequiredScope)) {
                    Write-Error "$(&$script:GetTimestamp),Error, Missing required scope: $RequiredScope"
                    throw "Missing required scope: $RequiredScope"
                }
                Write-Verbose "$(&$script:GetTimestamp),Info, Verified scope: $RequiredScope"
            }
        }
        catch {
            Write-Error "$(&$script:GetTimestamp),Error, Failed to validate permissions: $_"
            throw
        }

        try {
            $GraphAccessToken = (Get-MgContext).Account
            Write-Verbose "$(&$script:GetTimestamp),Info, Successfully authenticated as: $GraphAccessToken"
            return $GraphAccessToken
        }
        catch {
            Write-Error "$(&$script:GetTimestamp),Error, Failed to get account details: $_"
            throw
        }
    }

    End {
        try {
            [System.GC]::Collect()
            $MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
            Write-Verbose "$(&$script:GetTimestamp),Info, Final memory usage: $MemoryUsage MB"
        }
        catch {
            Write-Error "$(&$script:GetTimestamp),Error, Failed to collect garbage: $_"
        }
    }
}
function invoke-mgGraphRequestBatch {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$RunProfile,
        [Parameter(Mandatory)]
        [string]$Object,
        [Parameter(Mandatory)]
        [String]$Method,
        [Parameter(Mandatory)]
        [system.object]$Objects,
        [Parameter()]
        [string]$Uri,
        [Parameter()]
        [object]$Body,
        [Parameter()]
        [int]$BatchSize = 20,
        [Parameter()]
        [int]$WaitTime = 1000,
        [Parameter()]
        [int]$MaxRetry = 3
    )
    
    Begin {
        $ErrorActionPreference = 'Stop'
        try {
            $Retrycount = 0
            $CollectedObjects = [System.Collections.ArrayList]@()
            $LookupHash = @{}
            
            # Check execution context
            if ($env:AUTOMATION_ASSET_ACCOUNTID) {
                [Bool]$ManagedIdentity = $true
                Write-Verbose "$(&$script:GetTimestamp),Info, Running in Azure Automation context"
            }
            else {
                [Bool]$ManagedIdentity = $false
                Write-Verbose "$(&$script:GetTimestamp),Info, Running in Local PowerShell context"
            }
            
            Write-Verbose "$(&$script:GetTimestamp),Info, Starting batch processing for $($Objects.Count) objects"
        }
        catch {
            Write-Error "$(&$script:GetTimestamp),Error, Failed to initialize batch processing: $_"
            throw
        }
    }
    
    Process {
        try {
            $starttime = Get-Date
            do {
                try {
                    $TotalObjects = $Objects.Count
                    [int]$i = 0
                    $currentObject = 0
                    $RetryObjects = [System.Collections.ArrayList]@()
                    
                    Write-Verbose "$(&$script:GetTimestamp),Info, Processing batch with $TotalObjects objects"                    
                    
                    # Start looping all objects and run batches
                    for($i = 0; $i -lt $TotalObjects; $i += $BatchSize) {
                        try {
                            # Create Requests of id, method and url
                            [System.Object]$req = @()
                            
                            try {
                                if($i + ($BatchSize-1) -lt $TotalObjects) {
                                    $req = ($Objects[$i..($i+($BatchSize-1))] | ForEach-Object {
                                        @{
                                            'id' = $_.id
                                            'method' = $Method
                                            'url' = "/$($Object)/$($_.id)$($Uri)"
                                            'body' = if ($Body) {$Body} else { $null }
                                            'headers' = @{
                                                'Content-Type' = 'application/json'
                                            }
                                        }
                                    })
                                }
                                elseif ($TotalObjects -eq 1) {
                                    $req = @(@{
                                        'id' = $Objects[$i].id
                                        'method' = $Method
                                        'url' = "/$($Object)/$($Objects[$i].id)$($Uri)"
                                        'body' = if ($Body) {$Body} else { $null }
                                        'headers' = @{
                                            'Content-Type' = 'application/json'
                                        }
                                    })
                                }
                                else {
                                    $req = ($Objects[$i..($TotalObjects-1)] | ForEach-Object {
                                        @{
                                            'id' = $_.id
                                            'method' = $Method
                                            'url' = "/$($Object)/$($_.id)$($Uri)"
                                            'body' = if ($Body) {$Body} else { $null }
                                            'headers' = @{
                                                'Content-Type' = 'application/json'
                                            }
                                        }
                                    })
                                }
                                
                                Write-Verbose "$(&$script:GetTimestamp),Info, Created batch request for items $($i) to $([Math]::Min($i + $BatchSize, $TotalObjects)) of $TotalObjects total items"
                            }
                            catch {
                                Write-Error "$(&$script:GetTimestamp),Error, Failed to create batch request: $_"
                                throw
                            }

                            # Send the requests in a batch
                            try {
                                $batchRequest = @{'requests' = $req}
                                $batchBody = $batchRequest | ConvertTo-Json -Depth 10
                                #enable verbose logging for batch request for troubleshooting
<#                              try {
                                    Write-Verbose "$(&$script:GetTimestamp),Info, Batch request content:$($req | ConvertTo-Json -Depth 10 | Format-List | Out-String)"
                                }
                                catch {
                                    Write-Error "$(&$script:GetTimestamp),Error, Failed to write batch request content: $_"
                                }
#>
                                # Add headers including Content-Type
                                $headers = @{
                                    'Content-Type' = 'application/json'
                                }
                                
                                $responses = Invoke-MgGraphRequest -Method POST `
                                    -Uri "https://graph.microsoft.com/$($RunProfile)/`$batch" `
                                    -Body $batchBody `
                                    -Headers $headers
                                
                                Write-Verbose "$(&$script:GetTimestamp),Info, Successfully sent batch request"
                            }
                            catch {
                                Write-Error "$(&$script:GetTimestamp),Error, Failed to send batch request: $_"
                                throw
                            }

                            # Process the responses and verify status
                            foreach ($response in $responses.responses) {
                                $CurrentObject++
                                try {
                                    switch ($response.status) {
                                        200 {
                                            [void]$CollectedObjects.Add($response)
                                            Write-Verbose "$(&$script:GetTimestamp),Info, Batch Successfully processed object $($response.id)" 
                                        }
                                        204 {
                                            [void]$CollectedObjects.Add($response)
                                            Write-Verbose "$(&$script:GetTimestamp),Info, Batch Successfully PATCH processed object $($response.id)" 
                                        }
                                        403 { 
                                            Write-Error "$(&$script:GetTimestamp),Error, Batch Access denied to object $($response.id) - Status: $($response.status)"
                                        }
                                        404 { 
                                            Write-Warning "$(&$script:GetTimestamp),Warning, Batch Object $($response.id) not found - Status: $($response.status)"
                                        }
                                        429 {
                                            [void]$RetryObjects.Add($response)
                                            Write-Warning "$(&$script:GetTimestamp),Warning, Batch Throttling occurred for object $($response.id) - Status: $($response.status)"
                                        }
                                        default {
                                            [void]$RetryObjects.Add($response)
                                            Write-Error "$(&$script:GetTimestamp),Error, Batch Unexpected error for object $($response.id) - Status: $($response.status)"
                                        }
                                    }
                                }
                                catch {
                                    Write-Error "$(&$script:GetTimestamp),Error, Batch Failed to process response: $_"
                                    continue
                                }
                            }

                            # Handle throttling and progress
                            try {
                                $Elapsedtime = (Get-Date) - $starttime
                                $timeLeft = [TimeSpan]::FromMilliseconds((($ElapsedTime.TotalMilliseconds / $CurrentObject) * ($TotalObjects - $CurrentObject)))
                                
                                if (!$ManagedIdentity) {
                                    Write-Progress -Activity "Processing Batch $($Uri) $($CurrentObject) of $($TotalObjects)" `
                                        -Status "Est Time Left: $($timeLeft.Hours)h $($timeLeft.Minutes)m $($timeLeft.Seconds)s - Throttled: $($RetryObjects.Count) - Retry: $($Retrycount)/$($MaxRetry)" `
                                        -PercentComplete ([math]::ceiling($($CurrentObject / $TotalObjects) * 100))
                                }

                                $throttledResponses = $responses.responses | Select-Object -Last 20 | Where-Object {$_.status -eq "429"}
                                if ($throttledResponses) {
                                    $recommendedWait = ($throttledResponses.headers.'retry-after' | Measure-Object -Maximum).Maximum
                                    Write-Warning "$(&$script:GetTimestamp),Warning, Batch Throttling detected, waiting $($recommendedWait + 1) seconds"
                                    Start-Sleep -Seconds ($recommendedWait + 1)
                                }
                                elseif($CurrentObject % ($BatchSize * 4) -eq 0) {
                                    Start-Sleep -Seconds $WaitTime
                                }
                                else {
                                    Start-Sleep -Milliseconds $WaitTime
                                }
                            }
                            catch {
                                Write-Error "$(&$script:GetTimestamp),Error, Batch Failed to handle throttling/progress: $_"
                                continue
                            }
                        }
                        catch {
                            Write-Error "$(&$script:GetTimestamp),Error, Batch Failed to process batch at index $i`: $_"
                            continue
                        }
                    }

                    # Handle retries
                    if ($RetryObjects.Count -gt 0 -and $MaxRetry -gt 0) {
                        $Retrycount++
                        $MaxRetry--
                        Write-Verbose "$(&$script:GetTimestamp),Info, Batch Starting retry $Retrycount with $($RetryObjects.Count) objects"
                        $Objects = $RetryObjects
                    }
                }
                catch {
                    Write-Error "$(&$script:GetTimestamp),Error, Batch Failed in retry loop: $_"
                    throw
                }
            } While ($RetryObjects.Count -gt 0 -and $MaxRetry -gt 0)

            Write-Progress -Completed -Activity "Completed"
            Write-Verbose "$(&$script:GetTimestamp),Info, Batch Successfully processed $($CollectedObjects.Count) objects"

            # Build return hashtable
            foreach ($CollectedObject in $CollectedObjects) {
                $LookupHash[$CollectedObject.id] = $CollectedObject
            }
            
            return $LookupHash
        }
        catch {
            Write-Error "$(&$script:GetTimestamp),Error, Batches Failed in main process block: $_"
            throw
        }
    }
    
    End {
        try {
            # Cleanup memory
            [System.GC]::Collect()
            $MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($true) / 1MB), 2)
            Write-Verbose "$(&$script:GetTimestamp),Info, Final memory usage: $MemoryUsage MB"
        }
        catch {
            Write-Error "$(&$script:GetTimestamp),Error, Failed to cleanup: $_"
        }
    }
}
function Invoke-MgGraphRequestSingle {
    [CmdletBinding()]
    param(
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
        [object]$Filters,  # Changed from [hashtable] to [object] to support both string and hashtable
        
        [Parameter()]
        [object]$Body
    )
    
    try {
        # Build base URI
        $uri = "https://graph.microsoft.com/$RunProfile/$Object"
        $queryParams = [System.Collections.ArrayList]@()
        
        # Add properties if specified
        if ($Properties) {
            $select = $Properties -join ','
            [void]$queryParams.Add("`$select=$select")
        }
        
        # Add filters if specified
        if ($Filters) {
            if ($Filters -is [string]) {
                # Direct filter string
                [void]$queryParams.Add("`$filter=$Filters")
            }
            elseif ($Filters -is [hashtable]) {
                # Build filter from hashtable
                $filterParts = foreach ($key in $Filters.Keys) {
                    "$key eq '$($Filters[$key])'"
                }
                $filter = $filterParts -join ' and '
                [void]$queryParams.Add("`$filter=$filter")
            }
        }
        
        # Combine URI with query parameters
        if ($queryParams.Count -gt 0) {
            $uri += "?" + ($queryParams -join '&')
        }
        
        Write-Verbose "$(&$script:GetTimestamp),Info, Making request to: $uri"
        
        # Initialize result collection
        $results = [System.Collections.ArrayList]@()
        
        # Make initial request
        $params = @{
            Method = $Method
            Uri = $uri
        }
        
        if ($Body) {
            $params['Body'] = $Body | ConvertTo-Json -Depth 10
            $params['Headers'] = @{ 'Content-Type' = 'application/json' }
        }
        
        $response = Invoke-MgGraphRequest @params
        
        if ($response.value) {
            [void]$results.AddRange($response.value)
        }
        
        # Handle pagination
        while ($deviceResponse.PSObject.Properties.Name -contains '@odata.nextLink' -and 
           -not [string]::IsNullOrEmpty($deviceResponse.'@odata.nextLink'))  {
            $response = Invoke-MgGraphRequest -Method $Method -Uri $response.'@odata.nextLink'
            if ($response.value) {
                [void]$results.AddRange($response.value)
            }
        }
        
        Write-Verbose "$(&$script:GetTimestamp),Info, Retrieved $($results.Count) items"
        return $results
    }
    catch {
        Write-Error "$(&$script:GetTimestamp),Error, Failed to execute Graph request: $_"
        throw
    }
}
function Invoke-ScopeTagAssignmentReport {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ReportTitle = "Scope Tag Assignment Report",
        [Parameter()]
        [bool]$DetailedReport = $script:DetailedReport
    )

    try {
        # Create report data structure using Progress values
        $reportData = @{
            Summary = @{
                StartTime = $script:StartTime
                EndTime = Get-Date
                Duration = "{0:hh\:mm\:ss}" -f ((Get-Date) - $script:StartTime)
                WhatIf = $WhatIfPreference
                TotalDevices = $script:Progress.Total
                DevicesNoPrimaryUser = $script:Progress.DevicesNoPrimaryUser
                DevicesProcessed = $script:Progress.Current
                DevicesChanged = $script:Progress.Success
                DevicesSkipped = $script:Progress.Skipped
                DevicesFailed = $script:Progress.Failed
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
        Write-Output "Total Devices Found:`t`t$($reportData.Summary.TotalDevices)"
        Write-Output "Processed:`t`t`t$($reportData.Summary.DevicesProcessed)"
        Write-Output "Changed:`t`t`t$($reportData.Summary.DevicesChanged)"
        Write-Output "Skipped No Primary User:`t$($reportData.Summary.DevicesNoPrimaryUser)"
        Write-Output "Skipped Total:`t`t`t$($reportData.Summary.DevicesSkipped)"
        Write-Output "Failed:`t`t`t`t$($reportData.Summary.DevicesFailed)"
        if ($WhatIfPreference) {
            Write-Output "Would Have Changed:`t`t$($reportData.Summary.DevicesChanged)"
        }

        # Generate detailed report if requested
        if ($DetailedReport) {
            Write-Output "`nDetailed Device Status:"
            Write-Output "---------------------"
            Write-Output "DeviceName`t`tScopeTag`t`tStatus"
            Write-Output "----------`t`t--------`t`t------"
            
            # Use deviceResults queue for detailed status
            foreach ($deviceResult in $script:deviceResults) {
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
#endregion

#region ---------------------------------------------------[[Script Execution]------------------------------------------------------
$StartTime = Get-Date  # Use DateTime object instead of string timestamp

try {
    #Sign in to Graph
    try {$MgGraphAccessToken = Invoke-ConnectMgGraph -RequiredScopes $RequiredScopes
        Write-Verbose "$(&$script:GetTimestamp),Info, Success to get Access Token to Graph"}
    catch {Write-Error "$(&$script:GetTimestamp),Error, Failed to get Access Token to Graph, with error: $_"
        throw}

    # garbage collection for memory
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()

    
   #get all scope tags
    try {
        # Get scope tags
        $scopeTagsProperties = 'id,displayName'
        $scopeTags = Invoke-MgGraphRequestSingle `
            -RunProfile 'beta' `
            -Object 'deviceManagement/roleScopeTags' `
            -Method 'GET' `
            -Properties $scopeTagsProperties
        Write-Verbose "$(&$script:GetTimestamp),Info, Successfully retrieved $($ScopeTags.Count) scope tags"
    }
    catch {
        Write-Error "$(&$script:GetTimestamp),Error, Failed to get scope tags: $_"
        throw
    }
    # garbage collection for memory to free up memory
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    write-verbose "$(&$script:GetTimestamp),Info, memory usage after scope tag retrieval: $([math]::round([System.GC]::GetTotalMemory($false) / 1MB, 2)) MB"

    # Get all devices
    $DeviceProperties = 'id,deviceName,operatingSystem,roleScopeTagIds'
    try {
        if ($OperatingSystems -contains 'All') {
            $Devices = Invoke-MgGraphRequestSingle `
                -RunProfile 'beta' `
                -Object 'deviceManagement/managedDevices' `
                -Method 'GET' `
                -Properties $DeviceProperties
        }
        else {
            # Create filter for all operating systems at once
            $filterString = ($OperatingSystems | ForEach-Object { 
                "operatingSystem eq '$_'" 
            }) -join ' or '
            
            $Devices = Invoke-MgGraphRequestSingle `
                -RunProfile 'beta' `
                -Object 'deviceManagement/managedDevices' `
                -Method 'GET' `
                -Properties $DeviceProperties `
                -Filters $filterString  # Pass filter string directly
        }
        
        Write-Verbose "$(&$script:GetTimestamp),Info, Retrieved total of $($Devices.Count) devices"
        $script:Progress.Total = $Devices.Count
    }
    catch {
        Write-Error "$(&$script:GetTimestamp),Error, Failed to get devices: $_"
        throw
    }
    
    # garbage collection for memory to free up memory
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    write-verbose "$(&$script:GetTimestamp),Info, memory usage after device retrieval: $([math]::round([System.GC]::GetTotalMemory($false) / 1MB, 2)) MB"

    # Get all devices with a primary user
    try {
        $primaryUsers = invoke-mggraphrequestbatch `
            -RunProfile 'beta' `
            -Object 'deviceManagement/managedDevices' `
            -Method 'GET' `
            -Objects $Devices `
            -Uri '/users?$select=id,userPrincipalName,country' `
            -BatchSize $BatchSize `
            -WaitTime $WaitTime `
            -MaxRetry $MaxRetry
        
        Write-Verbose "$(&$script:GetTimestamp),Info, Successfully retrieved $($primaryUsers.count) devices and their primary users"
    }
    catch {
        Write-Error "$(&$script:GetTimestamp),Error, Failed to get primary users: $_"
        throw
    }
    
    # Process primary user responses
    $devicesWithNoPrimaryUser = $primaryUsers.GetEnumerator() | 
        Where-Object { 
            -not ($_.Value.body.value) -or 
            $_.Value.body.value.Count -eq 0 
        } | 
        Select-Object -ExpandProperty Key

    $devicesWithPrimaryUser = $primaryUsers.GetEnumerator() | 
        Where-Object { 
            $_.Value.body.value -and 
            $_.Value.body.value.Count -gt 0 
        }

    # Update progress tracking
    foreach ($deviceId in $devicesWithNoPrimaryUser) {
        $device = $Devices | Where-Object { $_.id -eq $deviceId }
        if ($device) {
            [void]$script:deviceResults.Enqueue([PSCustomObject]@{
                DeviceName = $device.deviceName
                DeviceId = $device.id
                OperatingSystem = $device.operatingSystem
                ScopeTag = if ($device.roleScopeTagIds) { $device.roleScopeTagIds -join ',' } else { 'None' }
                Status = "Skipped - No Primary User"
            })
        }
    }
    $script:Progress.DevicesNoPrimaryUser = $devicesWithNoPrimaryUser.Count
    $script:Progress.Skipped = $script:Progress.DevicesNoPrimaryUser
    $script:Progress.Current = $Devices.Count - $script:Progress.DevicesNoPrimaryUser

    Write-Verbose "$(&$script:GetTimestamp),Info, Found $($devicesWithNoPrimaryUser.Count) devices without primary user"
    Write-Verbose "$(&$script:GetTimestamp),Info, Found $($devicesWithPrimaryUser.Count) devices with primary user"

    # garbage collection for memory to free up memory
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    write-verbose "$(&$script:GetTimestamp),Info, memory usage after device retrieval: $([math]::round([System.GC]::GetTotalMemory($false) / 1MB, 2)) MB"

    # Get unique countries from primary users
    $uniqueCountries = $devicesWithPrimaryUser | 
    ForEach-Object { 
        Write-Verbose "$(&$script:GetTimestamp),Info, Processing response for device $($_.Key)"
        if ($_.Value.body.value -and $_.Value.body.value.Count -gt 0) {
            $_.Value.body.value[0].country
        }
    } | 
    Where-Object { -not [string]::IsNullOrEmpty($_) } | 
    Select-Object -Unique | 
    Sort-Object

    Write-Verbose "$(&$script:GetTimestamp),Info, Found $($uniqueCountries.Count) unique countries"

        #Process each country and update scope tags
    try {       
        foreach ($country in $uniqueCountries) {
            # Find matching scope tag
            $scopeTag = $ScopeTagMap[$country]
            #verify if scope tag exist in $ScopeTags
            if ($scopeTag = $ScopeTags | Where-Object { $_.displayName -eq $scopeTag } | Select-Object -ExpandProperty id) {
                Write-verbose "$(&$script:GetTimestamp),info, Found scope tag mapping: $scopeTag for country: $country"
                            
            # Get devices for this country (with null checks)
            $devicesForCountry = @(
                $devicesWithPrimaryUser.GetEnumerator() | 
                    Where-Object { 
                        $_.Value.body.value -and 
                        $_.Value.body.value.Count -gt 0 -and 
                        $_.Value.body.value[0].country -eq $country 
                    } |
                    ForEach-Object { 
                        $deviceId = $_.Key
                        $Devices | Where-Object { 
                            $_.id -eq $deviceId -and 
                            (-not $_.roleScopeTagIds -or -not ($_.roleScopeTagIds -contains $scopeTag))
                        }
                    }
            )
            Write-Verbose "$(&$script:GetTimestamp),Info, Found $($devicesForCountry.Count) devices for country: $country"

            if ($devicesForCountry.Count -gt 0) {
                $updateMsg = "Update scope tag to '$scopeTag' for $($devicesForCountry.Count) devices in country: $country"
                
                if ($PSCmdlet.ShouldProcess($updateMsg, "Update Device Scope Tags")) {
                    # Create body content with an explicit array
                    $bodyContent = @{
                        roleScopeTagIds = @($scopeTag) 
                    }
                    $updatedDevices = invoke-mgGraphRequestBatch `
                        -RunProfile 'beta' `
                        -Object 'deviceManagement/managedDevices' `
                        -Method 'PATCH' `
                        -Objects $devicesForCountry `
                        -Uri '' `
                        -BatchSize $BatchSize `
                        -WaitTime $WaitTime `
                        -MaxRetry $MaxRetry `
                        -Body $bodyContent
                    Write-Verbose "$(&$script:GetTimestamp),Info, Successfully updated scope tag for $($updatedDevices.Count) devices"
                    
                    # Process updated devices for reporting
                    foreach ($device in $devicesForCountry) {
                        $status = if ($updatedDevices.ContainsKey($device.id)) { 
                            $script:Progress.Success++
                            "Updated" 
                        } else { 
                            $script:Progress.Failed++
                            "Failed" 
                        }
                        
                        [void]$script:deviceResults.Enqueue([PSCustomObject]@{
                            DeviceName = $device.deviceName
                            DeviceId = $device.id
                            OperatingSystem = $device.operatingSystem
                            Country = $country
                            ScopeTag = $scopeTag
                            Status = $status
                        })
                    }
                    $script:Progress.Success += ($updatedDevices.Keys).Count
                    $script:Progress.Failed += ($devicesForCountry.Count - ($updatedDevices.Keys).Count)
                    }
                else {
                    $devicesForCountry | ForEach-Object {
                        Write-Verbose "$(&$script:GetTimestamp),Info, WhatIf: Would update scope tag to '$scopeTag' for device: $($_.deviceName)"
                        $device = $_  # Store current device in variable
                        [void]$script:deviceResults.Enqueue([PSCustomObject]@{
                            DeviceName = $device.deviceName
                            DeviceId = $device.id
                            OperatingSystem = $device.operatingSystem
                            Country = $country
                            ScopeTag = $scopeTag
                            Status = "Would Update"
                        })
                        $script:Progress.Skipped++
                    }
                }
            }
            }
            else {
                Write-Warning "$(&$script:GetTimestamp),Warning, No scope tag mapping found for country: $country"
            }
        }
    }
    catch {
        Write-Error "$(&$script:GetTimestamp),Error, Failed to process countries: $_"
        throw
    }

}
catch {
    Write-Error "$(&$script:GetTimestamp),Error, Script execution failed: $_"
}
finally {
    # Generate report if requested
    if ($ReturnReport) {
        if($DetailedReport) {
            Invoke-ScopeTagAssignmentReport -DetailedReport $true
            Write-Verbose "$(&$script:GetTimestamp),Info, Generating detailed report"
        }
        else {
            Invoke-ScopeTagAssignmentReport -DetailedReport $false
            Write-Verbose "$(&$script:GetTimestamp),Info, Generating summary report"
        }
    }

    # Disconnect and cleanup
    try {
        #Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Verbose "$(&$script:GetTimestamp),Info, Disconnected from Graph"
        
        # Clear variables
        $devices = $null
        $primaryUsers = $null
        $devicesWithNoPrimaryUser = $null
        $devicesWithPrimaryUser = $null
        $scopeTag = $null
        $scopeTags = $null
        $uniqueCountries = $null
        $devicesForCountry = $null
        $reportData = $null
        $script:deviceResults = $null
        $script:errors = $null
        $script:DeviceStatus = $null
        $script:Progress = $null
        $MgGraphAccessToken = $null
        
        # Force garbage collection
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        
        $memoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
        Write-Verbose "$(&$script:GetTimestamp),Info, Final memory usage: $memoryUsage MB"
    }
    catch {
        Write-Error "$(&$script:GetTimestamp),Error, Failed to cleanup: $_"
    }
}
#endregion