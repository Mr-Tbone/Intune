<#PSScriptInfo
.SYNOPSIS
    Script for Intune to set Scope Tags on Device based on Primary Users and their attributes

.DESCRIPTION
    This script will get all devices and their current primary user and current scope tags
    Get all users and the significant attributes for scope tagging
    It will then set scope tags based on that attribute
    The script uses Ms Graph and only requires the Microsoft.Graph.Authentication module

.EXAMPLE
   .\Intune-Add-ScopeTagsBasedOnPrimaryUsers.ps1
    Will set the scope tags on devices in Intune based on primary users and their attributes with default settings

.EXAMPLE
    .\Intune-Add-ScopeTagsBasedOnPrimaryUsers.ps1 -ScopeTagAttribute country -OperatingSystems All -DetailedReport $true -ReportToDisk $true -ReportPath "C:\Reports"
    Will set the scope tags on devices in Intune based on primary users and their attribute country for all devices and return a detailed report to disk

.NOTES
    Written by Mr-Tbone (Tbone Granheden) Coligo AB
    torbjorn.granheden@coligo.se

.VERSION
    2.0

.RELEASENOTES
    1.0 2025-03-19 Initial Build
    2.0 2025-11-14 Large update to use Graph batching and reduce runtime

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
    1.0.2503.1 - Initial Version
    2.0.2511.1 - Large update to use Graph batching and reduce runtime
#>

#region ---------------------------------------------------[Set Script Requirements]-----------------------------------------------
#Requires -Modules Microsoft.Graph.Authentication
#Requires -Version 5.1
#endregion

#region ---------------------------------------------------[Modifiable Parameters and Defaults]------------------------------------
# Customizations
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false,          HelpMessage = "Name of the script action for logging. Default is 'Intune Primary User'")]
    [string]$ScriptActionName       = "Intune Set Scope Tags based on Primary User",

    [Parameter(Mandatory = $false,          HelpMessage = "Device operatingsystems to process ('All', 'Windows', 'Android', 'iOS', 'macOS'). Default is 'Windows'")]
    [ValidateSet('All', 'Windows', 'Android', 'iOS', 'macOS')]
    [string[]]$OperatingSystems     = @('Windows'),

    [Parameter(Mandatory = $false,          HelpMessage = "Attribute to use for the scope tag. Default is 'Country'")]
    [string]$ScopeTagAttribute      = "Country",

    [Parameter(Mandatory = $false,          HelpMessage = "Whether to keep the built-in scope tag (usually called Default). Default is true")]
    [bool]$KeepBuiltinTag           = $true,

    [Parameter(Mandatory = $false,          HelpMessage = "Filter to only include devicenames that starts with specific strings like ('Tbone', 'Desktop'). Default is blank")]
    [string[]]$IncludedDeviceNames  = @(),

    [Parameter(Mandatory = $false,          HelpMessage = "Filter to exclude devicenames that starts with specific strings like ('Tbone', 'Desktop'). Default is blank")]
    [string[]]$ExcludedDeviceNames  = @(),

    [Parameter(Mandatory = $false,          HelpMessage = "Return report with statistics on how many changed objects. Default is true")]
    [bool]$ReturnReport             = $true,

    [Parameter(Mandatory = $false,          HelpMessage = "Include detailed device changes in the report. Default is true")]
    [bool]$DetailedReport           = $true,

    [Parameter(Mandatory = $false,          HelpMessage = "Save report to disk. Default is false")]
    [bool]$ReportToDisk             = $false,    

    [Parameter(Mandatory = $false,          HelpMessage = "Path where to save the report. Default is TEMP directory for Azure Automation compatibility")]
    [string]$ReportPath             = "$env:TEMP",

    [Parameter(Mandatory = $false,          HelpMessage = "Enable verbose logging. Default is false")]
    [bool]$VerboseLogging           = $false,

    [Parameter(Mandatory = $false,          HelpMessage = "Wait time in milliseconds between throttled requests. Default is 1000")]
    [ValidateRange(100,5000)]
    [int]$WaitTime                  = 1000,

    [Parameter(Mandatory = $false,          HelpMessage = "Maximum number of retry attempts for failed requests. Default is 3")]
    [ValidateRange(1,10)]
    [int]$MaxRetry                  = 3,

    [Parameter(Mandatory = $false,          HelpMessage = "Maximum number of items to process in a single batch. Default is 20")]
    [ValidateRange(1,20)]
    [int]$BatchSize                  = 20,

    [Parameter(Mandatory = $false,          HelpMessage = "Testmode, same as -WhatIf. Default is false")]
    [bool]$Testmode                 = $false
    )
#endregion
#region ---------------------------------------------------[Modifiable Variables and defaults]------------------------------------
# Define User attribute to scope tags mapping by table
$ScopeTagMappings = @{
#   User attribute Value= Scope Tag Name    
    'Sweden'            = 'SE'
    'Germany'           = 'DE'
    'France'            = 'FR'
    'Poland'            = 'PL'
    'United States'     = 'US'
    'China'             = 'CN'
    'Republic of Korea' = 'KR'
    'Japan'             = 'JP'
    'India'             = 'IN'
}
#endregion

#region ---------------------------------------------------[Set global script settings]--------------------------------------------
# Exit if running as a managed identity in PowerShell 7.2 due to bugs connecting to MgGraph https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/3151
if ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER -and $PSVersionTable.PSVersion -eq [version]"7.2.0") {
    Write-Error "This script cannot run as a managed identity in PowerShell 7.2. Please use a different version of PowerShell."
    exit 1}
# set strict mode to latest version
Set-StrictMode -Version Latest

# Save original preference states at script scope for restoration in finally block
$script:OriginalErrorActionPreference   = $ErrorActionPreference
$script:OriginalVerbosePreference       = $VerbosePreference
$script:OriginalWhatIfPreference        = $WhatIfPreference

# Set verbose- and should-preference based on parameter instead of hardcoded values
if ($VerboseLogging)    {$VerbosePreference = 'Continue'}                   # Set verbose logging based on the parameter $VerbosePreference
else                    {$VerbosePreference = 'SilentlyContinue'}
if($Testmode)           {$WhatIfPreference = 1}                             # Manually enable whatif mode with parameter $Testmode for testing
#endregion

#region ---------------------------------------------------[Import Modules and Extensions]-----------------------------------------
# Check if Microsoft.Graph.Authentication module is already loaded, if not import it silently
$moduleName = 'Microsoft.Graph.Authentication'
if (-not (Get-Module -Name $moduleName)) {
    $savedVerbosePreference = $VerbosePreference
    $VerbosePreference = 'SilentlyContinue'
    try {Import-Module $moduleName -ErrorAction Stop}
    finally {$VerbosePreference = $savedVerbosePreference}
} else {Write-Verbose "Module '$moduleName' is already loaded"}
#endregion

#region ---------------------------------------------------[Static Variables]------------------------------------------------------
# Required Graph API scopes for Invoke-ConnectMgGraph function
[System.Collections.ArrayList]$requiredScopes = "DeviceManagementManagedDevices.ReadWrite.All", "AuditLog.Read.All", "User.Read.All", "DeviceManagementRBAC.Read.All"

# Script execution tracking
[datetime]$Script:StartTime                 = ([DateTime]::Now) # Script start time
#[datetime]$script:EndTime                   = ([DateTime]::Now) # Script end time

# Reporting variables for progress tracking
$script:ReportProgress = @{
    Total   = [int]0    # Total number of objects to process
    Success = [int]0    # Successfully updated objects
    Whatif  = [int]0    # Objects that would be changed (WhatIf mode)
    Failed  = [int]0    # Failed operations
    Skipped = [int]0    # Skipped objects (already correct or excluded)
}

# Reporting variable for detailed results
$script:ReportResults = [System.Collections.ArrayList]::new()
#endregion

#region ---------------------------------------------------[Functions]------------------------------------------------------------
function Invoke-TboneLog { 
<#
.SYNOPSIS
    Unified tiny logger for PowerShell 5.1–7.5 and Azure Automation; overrides Write-* cmdlets and stores all messages in-memory

.DESCRIPTION
    A lightweight, cross-platform logging solution that intercepts all Write-Host, Write-Output, Write-Verbose, 
    Write-Warning, and Write-Error calls. Stores messages in memory with timestamps and can optionally output to:
    -LogToGUI - Console (real-time during execution) -LogToDisk - Disk (log file at script completion) -LogToEventlog - Windows Event Log (Application log)
#>
    param(
        [Parameter(                                         HelpMessage='Start=Begin logging, Stop=End and output log array')]
        [ValidateSet('Start','Stop')][string]$Mode,
        [Parameter(                                         HelpMessage='Show output in console during execution')]
        [bool]$LogToGUI=$true,
        [Parameter(                                         HelpMessage='Write complete log array to Disk when script ends')]
        [bool]$LogToDisk=$true,
        [Parameter(                                         HelpMessage='Write complete log array to Windows Event when script ends')]
        [bool]$LogToEventlog=$true,
        [Parameter(                                         HelpMessage='Return complete log array as Host output when script ends (Good for Intune Remediations)')]
        [bool]$LogToHost=$false,
        [Parameter(                                         HelpMessage='Path where Disk logs are saved')]
        [string]$LogPath = "c:\temp"
    )
    # Auto-detect mode: if logger functions is already loaded in memory and no mode specified, assume Stop
    if(!$Mode){$Mode=if(Get-Variable -Name _l -Scope Global -EA 0){'Stop'}else{'Start'}}
    if(!$LogPath){$LogPath=if($global:_p){$global:_p}elseif($env:TEMP){$env:TEMP}else{'/tmp'}}

    # Stop mode: Save logs and cleanup
    if ($Mode -eq 'Stop') {
        if((Get-Variable -Name _l -Scope Global -EA 0) -and (Test-Path function:\global:_Save)){_Save;if($global:_r){,$global:_l.ToArray()}}
        Unregister-Event -SourceIdentifier PowerShell.Exiting -ea 0 -WhatIf:$false
        if(Test-Path function:\global:_Clean){_Clean}
        return
    }

    # Start mode: Initialize logging and proxy all Write-* functions
    if ($Mode -eq 'Start') {
        # Create helper functions and variables
        $c=(Get-PSCallStack)[1];$n=if($c.Command -and $c.Command -ne '<ScriptBlock>'){$c.Command}elseif($c.ScriptName){[IO.Path]::GetFileNameWithoutExtension($c.ScriptName)}else{'PowershellScript'}
        $global:_az=$env:AZUREPS_HOST_ENVIRONMENT -or $env:AUTOMATION_ASSET_ACCOUNTID # Detect Azure Automation environment
        $global:_l=[Collections.Generic.List[string]]::new();$global:_g=$LogToGUI;$global:_s=$n;$global:_n="{0}-{1:yyyyMMdd-HHmmss}"-f$n,(Get-Date);$global:_p=$LogPath;$global:_d=$LogToDisk;$global:_e=$LogToEventlog;$global:_r=$LogToHost;$global:_w=([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
        if(!(Test-Path function:\global:_Time)){function global:_Time{Get-Date -f 'yyyy-MM-dd,HH:mm:ss'}}
        if(!(Test-Path function:\global:_ID)){function global:_ID{$c=(Get-PSCallStack)[2];$n=if($c.Command -and $c.Command -ne '<ScriptBlock>'){$c.Command}elseif($c.FunctionName -and $c.FunctionName -ne '<ScriptBlock>'){$c.FunctionName}else{'Main-Script'};if($n -like '*.ps1'){'Main-Script'}else{$n}}}
        if(!(Test-Path function:\global:_Save)){function global:_Save{try{if($global:_d){[IO.Directory]::CreateDirectory($global:_p)|Out-Null;[IO.File]::WriteAllLines((Join-Path $global:_p "$($global:_n).log"),$global:_l.ToArray())};if($global:_e -and $global:_w){try{$id=[Security.Principal.WindowsIdentity]::GetCurrent();$isAdmin=([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)}catch{$isAdmin=$false};if([Diagnostics.EventLog]::SourceExists($global:_s) -or $isAdmin){if(-not [Diagnostics.EventLog]::SourceExists($global:_s)){try{New-EventLog -LogName Application -Source $global:_s -EA 0 -WhatIf:$false}catch{}};$la=$global:_l -join"`n";$h=$la -match ',ERROR,';Write-EventLog -LogName Application -Source $global:_s -EventId $(if($h){11003}elseif($la -match ',WARN,'){11002}else{11001}) -EntryType $(if($h){'Error'}elseif($la -match ',WARN,'){Warning}else{Information}) -Message $la -EA 0 -WhatIf:$false}}}catch{}}}
        if(!(Test-Path function:\global:_Clean)){function global:_Clean{$WhatIfPreference=$false;Remove-Item -Path function:\Write-Host,function:\Write-Output,function:\Write-Warning,function:\Write-Error,function:\Write-Verbose,function:\_Save,function:\_Clean,function:\_ID,function:\_Time -ea 0 -Force;Remove-Variable -Name _l,_g,_s,_n,_p,_d,_e,_r,_w,_az -Scope Global -ea 0}}
        # Register exit handler FIRST (before Write-* overrides)
        $null=Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action{if($global:_l){try{_Save}catch{}};if(Test-Path function:\_Clean){_Clean}} -MaxTriggerCount 1
        # Create Write-* proxy functions (skip in Azure Automation)
        function Script:Write-Host{$m="$args";$c=(Get-PSCallStack)[1];$r="Row$($c.ScriptLineNumber)";$e="$(_Time),INFO,$r,$(_ID),$m";$global:_l.Add($e);if($global:_g){if($global:_az){Microsoft.PowerShell.Utility\Write-Output $m}else{Microsoft.PowerShell.Utility\Write-Host $e -ForegroundColor Green}}}
        function Script:Write-Output{$m="$args";$c=(Get-PSCallStack)[1];$r="Row$($c.ScriptLineNumber)";$e="$(_Time),OUTPUT,$r,$(_ID),$m";$global:_l.Add($e);if($global:_g){if($global:_az){Microsoft.PowerShell.Utility\Write-Output $m}else{Microsoft.PowerShell.Utility\Write-Host $e -ForegroundColor Green}}}
        function Script:Write-Verbose{$m="$args";$c=(Get-PSCallStack)[1];$r="Row$($c.ScriptLineNumber)";$e="$(_Time),VERBOSE,$r,$(_ID),$m";$global:_l.Add($e);if($global:_g -and $VerbosePreference -ne 'SilentlyContinue'){if($global:_az){Microsoft.PowerShell.Utility\Write-Verbose $m}else{Microsoft.PowerShell.Utility\Write-Host $e -ForegroundColor cyan}}}
        function Script:Write-Warning{$m="$args";$c=(Get-PSCallStack)[1];$r="Row$($c.ScriptLineNumber)";$e="$(_Time),WARN,$r,$(_ID),$m";$global:_l.Add($e);if($global:_g){if($global:_az){Microsoft.PowerShell.Utility\Write-Warning $m}else{Microsoft.PowerShell.Utility\Write-Host $e -ForegroundColor Yellow}};if($WarningPreference -eq 'Stop'){_Save;_Clean;exit}}
        function Script:Write-Error{$m="$args";$c=(Get-PSCallStack)[1];$r="Row$($c.ScriptLineNumber)";$e="$(_Time),ERROR,$r,$(_ID),$m";$global:_l.Add($e);if($global:_g){if($global:_az){Microsoft.PowerShell.Utility\Write-Error $m}else{Microsoft.PowerShell.Utility\Write-Host $e -ForegroundColor Red}};if($ErrorActionPreference -eq 'Stop'){_Save;_Clean;exit}}
    }
}
function Invoke-ConnectMgGraph {
<#
.SYNOPSIS
    Connects to Microsoft Graph API with multiple authentication methods.

.DESCRIPTION
    Supports Managed Identity, Interactive, Client Secret, and Certificate authentication.
    Automatically detects the method from provided parameters and environment. 
    Validates required scopes for Interactive authentication and reuses an existing connection when possible. 
#>
    [CmdletBinding()]
    param (
        [Parameter(HelpMessage = "Array of required Microsoft Graph API permission scopes example:('User.Read.All','DeviceManagementManagedDevices.ReadWrite.All') ")]
        [string[]]$RequiredScopes,
        
        [Parameter(HelpMessage = "Entra ID Application ID (ClientID) (required for Client Secret or Certificate authentication)")]
        [ValidateNotNullOrEmpty()][string]$ClientId,

        [Parameter(HelpMessage = "Entra ID Tenant ID (directory ID) for app-only authentication (required for Client Secret or Certificate authentication)")]
        [ValidateNotNullOrEmpty()][string]$TenantId,
        
        [Parameter(HelpMessage = "Client Secret as SecureString for app-only authentication (use with ClientId and TenantId)")]
        [ValidateNotNull()][SecureString]$ClientSecret,
        
        [Parameter(HelpMessage = "Certificate thumbprint for certificate-based authentication (certificate must be in CurrentUser or LocalMachine store)")]
        [ValidateNotNullOrEmpty()][string]$CertificateThumbprint,

        [Parameter(HelpMessage = "Certificate subject name for certificate-based authentication (certificate must be in CurrentUser or LocalMachine store)")]
        [ValidateNotNullOrEmpty()][string]$CertificateName,
        
        [Parameter(HelpMessage = "File path to certificate (.pfx or .cer) for certificate-based authentication")]
        [ValidateNotNullOrEmpty()][string]$CertificatePath,
        
        [Parameter(HelpMessage = "Password for certificate file as SecureString (required if certificate file is password-protected)")]
        [SecureString]$CertificatePassword
    )
    
    Begin {
        $ErrorActionPreference = 'Stop'
        $timestamp = [DateTime]::Now.ToString('yy-MM-dd HH:mm:ss')
        $resourceURL = "https://graph.microsoft.com/"

        # Default scopes to sign in if not provided
        if (-not $RequiredScopes -or @($RequiredScopes).Count -eq 0) {
            $RequiredScopes = @("User.Read.All")
        }
        
        # Detect authentication method based on parameters and environment (priority: ClientSecret > Certificate > ManagedIdentity > Interactive)
        $hasClientId     = $PSBoundParameters.ContainsKey('ClientId') -and [string]::IsNullOrWhiteSpace($ClientId) -eq $false
        $hasTenantId     = $PSBoundParameters.ContainsKey('TenantId') -and [string]::IsNullOrWhiteSpace($TenantId) -eq $false
        $hasClientSecret = $PSBoundParameters.ContainsKey('ClientSecret') -and $null -ne $ClientSecret
        $hasCertInput    = $PSBoundParameters.ContainsKey('CertificateThumbprint') -or $PSBoundParameters.ContainsKey('CertificateName') -or $PSBoundParameters.ContainsKey('CertificatePath')

        if ($hasClientSecret -and $hasClientId -and $hasTenantId) {
            $authMethod = 'ClientSecret'
        }
        elseif ($hasCertInput -and $hasClientId -and $hasTenantId) {
            $authMethod = 'Certificate'
        }
        elseif ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER) {
            $authMethod = 'ManagedIdentity'
        }
        else {
            $authMethod = 'Interactive'
        }
        
        Write-Verbose "$timestamp,Info,Invoke-ConnectMgGraph,Authentication method: $authMethod"
    }
    
    Process {
        try {
            # Check for existing valid connection
            try {
                $context = Get-MgContext -ErrorAction SilentlyContinue
                if ($context) {
                    Write-Verbose "$timestamp,Info,Invoke-ConnectMgGraph,Existing connection found for: $($context.Account)"
                    
                    # Validate scopes only for Interactive auth (Managed Identity/app-only doesn't use delegated scopes)
                    if ($authMethod -eq 'Interactive' -and @($RequiredScopes).Count -gt 0) {
                        $currentScopes = @($context.Scopes)
                        $reqScopes = @($RequiredScopes)
                        $missingScopes = @($reqScopes | Where-Object { $_ -notin $currentScopes })
                        
                        if (@($missingScopes).Count -eq 0) {
                            Write-Verbose "$timestamp,Info,Invoke-ConnectMgGraph,Reusing existing connection with valid scopes"
                            return $context.Account
                        } else {
                            Write-Verbose "$timestamp,Warning,Invoke-ConnectMgGraph,Existing connection missing scopes: $($missingScopes -join ', ')"
                            Disconnect-MgGraph -ErrorAction SilentlyContinue
                        }
                    } else {
                        # For app-only auth, reuse existing connection
                        return $context.Account
                    }
                }
            }
            catch {
                Write-Verbose "$timestamp,Info,Invoke-ConnectMgGraph,No existing connection found"
            }
            
            # Build connection parameters
            $connectParams = @{ NoWelcome = $true }
            
            switch ($authMethod) {
                'ManagedIdentity' {
                    Write-Verbose "$timestamp,Info,Invoke-ConnectMgGraph,Connecting with Managed Identity"
                    
                    # Validate environment variables
                    if (-not $env:IDENTITY_ENDPOINT -or -not $env:IDENTITY_HEADER) {
                        throw "Managed Identity environment variables not set"
                    }
                    
                    # Get Graph SDK version for compatibility
                    $graphVersion = (Get-Module -Name 'Microsoft.Graph.Authentication' -ListAvailable | 
                        Sort-Object Version -Descending | Select-Object -First 1).Version
                    Write-Verbose "$timestamp,Info,Invoke-ConnectMgGraph,Graph SDK version: $graphVersion"
                    
                    if ($graphVersion -ge [version]"2.0.0") {
                        $connectParams['Identity'] = $true
                    } else {
                        # For older SDK versions, get token manually
                        $headers = @{
                            'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER
                            'Metadata' = 'True'
                        }
                        $response = Invoke-RestMethod -Uri "$($env:IDENTITY_ENDPOINT)?resource=$resourceURL" `
                            -Method GET -Headers $headers -TimeoutSec 30
                        $connectParams['AccessToken'] = $response.access_token
                        Write-Verbose "$timestamp,Info,Invoke-ConnectMgGraph,Retrieved managed identity token"
                    }
                }
                
                'ClientSecret' {
                    Write-Verbose "$timestamp,Info,Invoke-ConnectMgGraph,Connecting with Client Secret"
                    # Validate required inputs
                    if (-not $hasClientId -or -not $hasTenantId) {
                        throw "ClientSecret authentication requires both ClientId and TenantId."
                    }
                    # Prefer native parameters supported by the Graph SDK and convert SecureString to plain text
                    $plainSecret = $null
                    try {
                        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret)
                        $plainSecret = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                    } finally {
                        if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
                    }
                    $connectParams['ClientId']     = $ClientId
                    $connectParams['TenantId']     = $TenantId
                    $connectParams['ClientSecret'] = $plainSecret
                    Write-Verbose "$timestamp,Info,Invoke-ConnectMgGraph,Using ClientId: $ClientId, TenantId: $TenantId"
                }
                
                'Certificate' {
                    Write-Verbose "$timestamp,Info,Invoke-ConnectMgGraph,Connecting with Certificate"
                    # Validate required inputs
                    if (-not $hasClientId -or -not $hasTenantId) {
                        throw "Certificate authentication requires both ClientId and TenantId."
                    }
                    $connectParams['ClientId'] = $ClientId
                    $connectParams['TenantId'] = $TenantId
                    
                    # Handle different certificate input methods
                    if ($CertificateThumbprint) {
                        $connectParams['CertificateThumbprint'] = $CertificateThumbprint
                        Write-Verbose "$timestamp,Info,Invoke-ConnectMgGraph,Using certificate thumbprint: $CertificateThumbprint"
                    }
                    elseif ($CertificateName) {
                        $connectParams['CertificateName'] = $CertificateName
                        Write-Verbose "$timestamp,Info,Invoke-ConnectMgGraph,Using certificate name: $CertificateName"
                    }
                    elseif ($CertificatePath) {
                        # Load certificate from file
                        if (-not (Test-Path $CertificatePath)) {
                            throw "Certificate file not found: $CertificatePath"
                        }
                        
                        try {
                            if ($CertificatePassword) {
                                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                                    $CertificatePath, 
                                    $CertificatePassword
                                )
                            } else {
                                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath)
                            }
                            $connectParams['Certificate'] = $cert
                            Write-Verbose "$timestamp,Info,Invoke-ConnectMgGraph,Loaded certificate from: $CertificatePath"
                        }
                        catch {
                            throw "Failed to load certificate: $_"
                        }
                    }
                    else {
                        throw "No certificate specified. Use CertificateThumbprint, CertificateName, or CertificatePath"
                    }
                }
                
                'Interactive' {
                    Write-Verbose "$timestamp,Info,Invoke-ConnectMgGraph,Connecting interactively"
                    # Ensure scopes are a string array
                    $connectParams['Scopes'] = @($RequiredScopes)
                }
            }
            
            # Connect to Microsoft Graph
            try {
                Connect-MgGraph @connectParams -ErrorAction Stop
                Write-Verbose "$timestamp,Info,Invoke-ConnectMgGraph,Successfully connected to Microsoft Graph"
            }
            catch {
                throw "Failed to connect to Microsoft Graph: $_"
            }
            finally {
                # Clear sensitive value if used
                if ($connectParams.ContainsKey('ClientSecret')) { $connectParams['ClientSecret'] = $null }
            }
            
            # Validate permissions for delegated auth (Interactive only)
            if ($authMethod -eq 'Interactive' -and @($RequiredScopes).Count -gt 0) {
                try {
                    $context = Get-MgContext
                    $currentScopes = @($context.Scopes)
                    $reqScopes = @($RequiredScopes)
                    $missingScopes = @($reqScopes | Where-Object { $_ -notin $currentScopes })
                    if (@($missingScopes).Count -gt 0) {
                        throw "Missing required scopes: $($missingScopes -join ', ')"
                    }
                    
                    Write-Verbose "$timestamp,Info,Invoke-ConnectMgGraph,Validated all required scopes: $($RequiredScopes -join ', ')"
                }
                catch {
                    throw "Failed to validate permissions: $_"
                }
            }
            
            # Return account context
            $context = Get-MgContext
            $account = $context.Account
            Write-Verbose "$timestamp,Info,Invoke-ConnectMgGraph,Connected as: $account"
            return $account
        }
        catch {
            Write-Error "$timestamp,Error,Invoke-ConnectMgGraph,Connection failed: $_"
            throw
        }
    }
    
    End {
        $memoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
        Write-Verbose "$timestamp,Info,Invoke-ConnectMgGraph,Function finished. Memory: $memoryUsage MB"
    }
}
function Invoke-MgGraphRequestSingle {
    <#
    .SYNOPSIS
        Executes a single Graph API request with pagination and retry logic.

    .DESCRIPTION
        Makes Graph API calls with automatic pagination, throttling handling, and exponential backoff retry logic.
        Supports filtering, property selection, and count queries. Returns all pages of results automatically.
    #>
[CmdletBinding()]
    Param(
        [Parameter(HelpMessage = "The Graph API version ('beta' or 'v1.0')")]
        [ValidateSet('beta', 'v1.0')]
        [string]$RunProfile     = "v1.0",
    
        [Parameter(HelpMessage = "The HTTP method for the request(e.g., 'GET', 'PATCH', 'POST', 'DELETE')")]
        [ValidateSet('GET', 'PATCH', 'POST', 'DELETE')]
        [String]$Method         = "GET",
        
        [Parameter(HelpMessage = "The Graph API endpoint path to target (e.g., 'me', 'users', 'groups')")]
        [string]$Object,

        [Parameter(             HelpMessage = "Request body for POST/PATCH operations")]
        [string[]]$Body,
        
        [Parameter(             HelpMessage = "Graph API properties to include")]
        [string[]]$Properties,
    
        [Parameter(             HelpMessage = "Graph API filters to apply")]
        [string]$Filters,
    
        [Parameter(             HelpMessage = "Page size (max 1000 objects per page)")]
        [ValidateRange(1,1000)]
        [int]$PageSize          = 999,

        [Parameter(             HelpMessage = "Skip pagination and only get the first page. Default is false")]
        [bool]$SkipPagination   = $false,

        [Parameter(             HelpMessage = "Include count of total items. Adds ConsistencyLevel header. Default is false")]
        [bool]$Count            = $false,

        [Parameter(             HelpMessage = "Delay between requests if throttled in milliseconds")]
        [ValidateRange(100,5000)]
        [int]$WaitTime          = 1000,

        [Parameter(             HelpMessage = "Maximum retry attempts for failed requests when throttled")]
        [ValidateRange(1,10)]
        [int]$MaxRetry          = 3
    )
    Begin {
        $PsobjectResults = [System.Collections.ArrayList]::new()
        $RetryCount = 0
        $TotalCount = $null

        # Build base URI
        $uri = "https://graph.microsoft.com/$RunProfile/$Object"
        $queryParams = [System.Collections.ArrayList]::new()

        # Add count parameter if requested
        if ($Count) {[void]$queryParams.Add("`$count=true")}

        # Add page size parameter
        if ($Method -eq 'GET') {[void]$queryParams.Add("`$top=$PageSize")}

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
        if ($queryParams.Count -gt 0) {$uri += "?" + ($queryParams -join '&')}
    }
    Process {
        do {
            try {
                Write-Verbose "Making request to: $uri"
                $i = 1
                do {
                    $response = $null
                    Write-Verbose "Requesting page $i with $PageSize items"
                    # Set default parameters for Invoke-MgGraphRequest
                    $params = @{
                        Method      = $Method
                        Uri         = $uri
                        ErrorAction = 'Stop'
                        OutputType  = 'PSObject'
                        Verbose     = $false
                    }
                    # Add ConsistencyLevel header if Count is requested
                    if ($Count) { $params['Headers'] = @{ 'ConsistencyLevel' = 'eventual' } }

                    # Add additional parameters based on method
                    if ($Method -in 'POST', 'PATCH') {
                        $params['Body'] = $Body
                        if (-not $params.ContainsKey('Headers')) {
                            $params['Headers'] = @{}
                        }
                        $params['Headers']['Content-Type'] = 'application/json'
                        write-verbose "Request body: $($Body | ConvertTo-Json -Depth 10)"
                    }
                    # Send request to Graph API
                    try {
                        $response = Invoke-MgGraphRequest @params
                        Write-Verbose "Request successful"
                    }
                    catch {
                        # Check if this is an expired skip token error
                        if ($_.Exception.Message -match "Skip token.*expired|Skip token is null") {
                            Write-Warning "Skip token has expired on page $i after collecting $($PsobjectResults.Count) items. Returning collected data."
                            # Exit pagination loop and return what we have
                            $uri = $null
                            break
                        }
                        # For other errors, log and re-throw to outer catch
                        Write-Verbose "Request failed with error: $_"
                        throw
                    }
                    if ($Method -in 'POST', 'PATCH', 'DELETE') {return $response}
                    if ($response.value) {[void]$PsobjectResults.AddRange($response.value)}
                    # Capture count from first response if requested
                    if ($Count -and $null -eq $TotalCount -and $response.'@odata.count') {
                        $TotalCount = $response.'@odata.count'
                        Write-Verbose "Total count available: $TotalCount items"
                    }
                    Write-Verbose "Retrieved page $i, Now total: $($PsobjectResults.Count) items"

                    # Check for next page
                    if ($SkipPagination) {
                        Write-Verbose "SkipPagination enabled, stopping after first page"
                        $uri = $null
                    }
                    elseif ($response.PSObject.Properties.Name -contains '@odata.nextLink') {
                        if ($response.'@odata.nextLink') {
                            $uri = $response.'@odata.nextLink'
                            Write-Verbose "Next page found: $uri"
                        }
                        else {
                            Write-Verbose "No @odata.nextLink value, stopping pagination"
                            $uri = $null
                        }
                    }
                    else {
                        Write-Verbose "No more pages found"
                        $uri = $null
                    }

                    $i++
                } while ($uri)
                Write-Verbose "Completed pagination. Returning array with $($PsobjectResults.Count) items"
                
                # Return results with count if requested
                if ($Count -and $null -ne $TotalCount) {
                    return [PSCustomObject]@{
                        Items = $PsobjectResults
                        Count = $TotalCount
                    }
                }
                return $PsobjectResults # Success, return results and exit retry loop
            }
            catch {
                $ErrorMessage = $_.Exception.Message
                # Get full error string including nested JSON messages for better pattern matching
                $FullErrorString = $_ | Out-String
                Write-Warning "Request failed (Retry attempt $($RetryCount + 1)/$MaxRetry): $ErrorMessage"

                # Check if the exception has response details (it should for HTTP errors)
                if ($_.Exception.Response) {
                    $StatusCode = $_.Exception.Response.StatusCode

                    # Use switch to handle specific status codes (handle both enum names and numeric values)
                    switch ($StatusCode) {
                        {$_ -eq 429 -or $_ -eq 'TooManyRequests'} { # Throttling
                            $RetryAfter = ($_.Exception.Response.Headers | Where-Object {$_.Name -eq "Retry-After"}).Value
                            if ($RetryAfter) {
                                Write-Warning "Throttling detected (429). Waiting $($RetryAfter * 1000) milliseconds before retrying."
                                Start-Sleep -Milliseconds ($RetryAfter * 1000) # Convert seconds to milliseconds
                            } else {
                                $Delay = [math]::Min(($WaitTime * ([math]::Pow(2, $RetryCount))), 60000) # Exponential backoff, max 60 seconds
                                Write-Warning "Throttling detected (429). No Retry-After header found. Waiting $($Delay) milliseconds before retrying."
                                Start-Sleep -Milliseconds $Delay
                            }
                            # Break not needed, will fall through to retry logic below
                        }
                        {$_ -eq 404 -or $_ -eq 'NotFound'} { # Not Found
                            Write-Warning "Resource not found (404). Error: $ErrorMessage"
                            # Re-throw the original exception to signal failure to the caller immediately
                            throw "$_ (Object Deleted/No User License)"
                        }
                        {$_ -eq 400 -or $_ -eq 'BadRequest'} { # Bad Request                            
                            if ($ErrorMessage -match "Skip token.*expired|Skip token is null" -or $FullErrorString -match "Skip token.*expired|Skip token is null") {# Check if this is an expired skip token error
                                Write-Warning "Skip token has expired after collecting $($PsobjectResults.Count) items. Returning collected data."
                                return $PsobjectResults
                            }
                            if ($ErrorMessage -match "does not have intune license or is deleted" -or $FullErrorString -match "does not have intune license or is deleted") { # Check if no license, common for Intune queries
                                Write-Warning "Object Deleted or User has no Intune license"
                                return "$_ (Object Deleted/No User License)"
                            }
                            else {
                                Write-Error "Bad request (400). Error: $ErrorMessage"
                                throw $_
                            }
                        }
                        {$_ -eq 403 -or $_ -eq 'Forbidden'} { # Forbidden / Access Denied
                             Write-Error "Access denied (403). Error: $ErrorMessage"
                             throw $_
                        }
                        default { # Other HTTP errors - Use generic retry
                            $Delay = [math]::Min(($WaitTime * ([math]::Pow(2, $RetryCount))), 60000) # Exponential backoff, max 60 seconds
                            Write-Warning "HTTP error $($StatusCode). Waiting $($Delay) milliseconds before retrying."
                            Start-Sleep -Milliseconds $Delay
                            # Break not needed, will fall through to retry logic below
                        }
                    }
                } else {
                    # Non-HTTP errors (e.g., network issues, DNS resolution) - Use generic retry
                    $Delay = [math]::Min(($WaitTime * ([math]::Pow(2, $RetryCount))), 60000) # Exponential backoff, max 60 seconds
                    Write-Warning "Non-HTTP error. Waiting $($Delay) milliseconds before retrying. Error: $ErrorMessage"
                    Start-Sleep -Milliseconds $Delay
                }

                # Increment retry count and check if max retries exceeded ONLY if not already thrown
                $RetryCount++
                if ($RetryCount -gt $MaxRetry) {
                     Write-Error "Request failed after $($MaxRetry) retries. Aborting."
                     throw "Request failed after $($MaxRetry) retries. Last error: $ErrorMessage"
                }
                # If retries not exceeded and error was potentially retryable (e.g., 429, other HTTP, non-HTTP), the loop will continue
            }
        } while ($RetryCount -le $MaxRetry)

        Write-Error "Request failed after $($MaxRetry) retries. Aborting."
        throw "Request failed after $($MaxRetry) retries." # Re-throw the exception after max retries
    }

    End {
        # End function and report memory usage 
        $MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
        Write-Verbose "Function finished. Memory usage: $MemoryUsage MB"
    }
}
function invoke-mgGraphRequestBatch {
    <#
    .SYNOPSIS
        Processes multiple Graph API requests in batches for improved performance.

    .DESCRIPTION
        Sends Graph API requests in batches (up to 20 per batch) to efficiently process large numbers of objects.
        Handles throttling, retries, and provides progress tracking. Supports GET, PATCH, POST, and DELETE operations.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(
            HelpMessage = "The Graph API version ('beta' or 'v1.0')")]
        [ValidateSet('beta', 'v1.0')]
        [string]$RunProfile = "v1.0",
    
        [Parameter(
            HelpMessage = "The HTTP method for the request(e.g., 'GET', 'PATCH', 'POST', 'DELETE')")]
        [ValidateSet('GET', 'PATCH', 'POST', 'DELETE')]
        [String]$Method = "GET",
        
        [Parameter(
            HelpMessage = "The Graph API endpoint path to target (e.g., 'me', 'users', 'groups')")]
        [string]$Object,
    
        [Parameter(
            HelpMessage = "Array of objects to process in batches")]
        [System.Object[]]$Objects,
    
        [Parameter(
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
        $starttime = Get-Date
        $Retrycount = 0
        $TotalObjects = $Objects.Count
        
        # Pre-allocate collections with capacity for better performance
        $CollectedObjects = [System.Collections.Generic.List[PSObject]]::new($TotalObjects)
        $RetryObjects = [System.Collections.Generic.List[PSObject]]::new()
        
        # Check execution context once
        [Bool]$ManagedIdentity = [bool]$env:AUTOMATION_ASSET_ACCOUNTID
        Write-Verbose "Running in $(if ($ManagedIdentity) { 'Azure Automation' } else { 'interactive PowerShell' }) context"
        
        # Pre-calculate common values to avoid repeated work
        $batchUri = "https://graph.microsoft.com/$RunProfile/`$batch"
        $batchHeaders = @{'Content-Type' = 'application/json'}
        
        # Build URL query parameters once (they're the same for all requests)
        $urlQueryString = $null
        if ($Properties -or $Filters) {
            $urlParams = [System.Collections.Generic.List[string]]::new()
            if ($Properties) {
                $urlParams.Add("`$select=$($Properties -join ',')")
            }
            if ($Filters) {
                $urlParams.Add("`$filter=$([System.Web.HttpUtility]::UrlEncode($Filters))")
            }
            $urlQueryString = "?" + ($urlParams -join '&')
        }
        
        # Pre-determine if method needs body/headers (avoid repeated checks)
        $needsBody = $Method -in 'PATCH','POST'
        $contentTypeHeader = if ($needsBody) { 'application/json' } else { $null }
        
        Write-Verbose "Graph batch processing initialized for $TotalObjects objects"
    }
    
    Process {
        try {
            do {
                $currentObject = 0
                $RetryObjects.Clear()
                
                # Process objects in batches
                for($i = 0; $i -lt $Objects.Count; $i += $BatchSize) {
                    # Calculate batch boundaries
                    $batchEnd = [Math]::Min($i + $BatchSize, $Objects.Count)
                    $batchCount = $batchEnd - $i
                    
                    # Pre-allocate request array with exact size
                    $req = [System.Collections.ArrayList]::new($batchCount)
                    
                    # Build batch requests (optimized loop)
                    for ($j = $i; $j -lt $batchEnd; $j++) {
                        $obj = $Objects[$j]
                        $url = "/$Object/$($obj.id)$query"
                        if ($urlQueryString) { $url += $urlQueryString }
                        
                        # Use object's body if available, otherwise use the global Body parameter
                        $requestBody = if ($obj.PSObject.Properties.Name -contains 'body' -and $obj.body) {
                            $obj.body
                        } elseif ($needsBody) {
                            $Body
                        } else {
                            $null
                        }
                        
                        [void]$req.Add(@{
                            'id' = $obj.id
                            'method' = $Method
                            'url' = $url
                            'body' = $requestBody
                            'headers' = @{ 'Content-Type' = $contentTypeHeader }
                        })
                    }
                    
                    Write-Verbose "Sending batch $([Math]::Floor($i/$BatchSize) + 1): items $($i+1) to $batchEnd of $($Objects.Count)"
                    
                    # Send batch request
                    try {
                        $batchBody = @{'requests' = $req} | ConvertTo-Json -Depth 10 -Compress
                        $responses = Invoke-MgGraphRequest -Method POST -Uri $batchUri -Body $batchBody -Headers $batchHeaders -Verbose:$false
                        Write-Verbose "Batch request successful with $($req.Count) requests"
                    }
                    catch {
                        Write-Error "Failed to send batch request: $_"
                        throw
                    }
                    
                    # Process responses (optimized with direct property access)
                    $throttledCount = 0
                    foreach ($response in $responses.responses) {
                        $currentObject++
                        
                        # Handle response by status code
                        switch ($response.status) {
                            {$_ -in 200,201,204} { # Success cases
                                # Extract the actual device object from response.body
                                if ($response.body) {
                                    # Convert hashtable to PSCustomObject if needed
                                    $bodyObject = if ($response.body -is [hashtable]) {
                                        [PSCustomObject]$response.body
                                    } else {
                                        $response.body
                                    }
                                    [void]$CollectedObjects.Add($bodyObject)
                                    Write-Verbose "Success ($($response.status)) for request $($response.id) with body"
                                } else {
                                    # For 204 No Content (PATCH/DELETE), return a success indicator with the request ID
                                    $successObject = [PSCustomObject]@{
                                        id = $response.id
                                        status = $response.status
                                    }
                                    [void]$CollectedObjects.Add($successObject)
                                    Write-Verbose "Success ($($response.status)) for request $($response.id) - no body returned"
                                }
                            }
                            400 { # Bad request - retry
                                Write-Error "Bad request (400) for object $($response.id)"
                                [void]$RetryObjects.Add($response)
                            }
                            403 { # Access denied - don't retry
                                Write-Error "Access denied (403) for object $($response.id) - Check permissions"
                            }
                            404 { # Not found - fatal error
                                Write-Warning "Resource not found (404) for object $($response.id)"
                                throw "Object $($response.id) does not exist in Graph API"
                            }
                            429 { # Throttling - retry with backoff
                                Write-Warning "Throttling (429) for object $($response.id)"
                                [void]$RetryObjects.Add($response)
                                $throttledCount++
                            }
                            default { # Other errors - retry
                                Write-Error "Unexpected status ($($response.status)) for object $($response.id)"
                                [void]$RetryObjects.Add($response)
                            }
                        }
                    }
                    
                    # Show progress (only in interactive mode)
                    if (-not $ManagedIdentity) {
                        $percentComplete = ($currentObject / $TotalObjects) * 100
                        $elapsed = (Get-Date) - $starttime
                        $timeLeft = if ($currentObject -gt 0) {
                            [TimeSpan]::FromMilliseconds(($elapsed.TotalMilliseconds / $currentObject) * ($TotalObjects - $currentObject))
                        } else { [TimeSpan]::Zero }
                        
                        Write-Progress -Activity "Processing Graph Batch Requests" `
                            -Status "Progress: $currentObject/$TotalObjects | Estimated Time Left: $($timeLeft.ToString('hh\:mm\:ss')) | Throttled: $throttledCount | Retry: $Retrycount/$MaxRetry" `
                            -PercentComplete $percentComplete
                    }
                    
                    # Handle throttling with exponential backoff (only if throttled responses exist)
                    if ($throttledCount -gt 0) {
                        # Extract retry-after values efficiently
                        $retryAfterValues = $RetryObjects | 
                            Where-Object { $_.status -eq 429 -and $_.headers.'retry-after' } | 
                            Select-Object -ExpandProperty headers | 
                            Select-Object -ExpandProperty 'retry-after'
                        
                        $waitSeconds = if ($retryAfterValues) {
                            [Math]::Min(($retryAfterValues | Measure-Object -Maximum).Maximum + ($Retrycount * 2), 30)
                        } else {
                            [Math]::Min(1 + ($Retrycount * 2), 30)
                        }
                        
                        Write-Warning "Throttling detected, waiting $waitSeconds seconds (Retry: $Retrycount)"
                        Start-Sleep -Seconds $waitSeconds
                    }
                }
                
                # Prepare for retry if needed
                if ($RetryObjects.Count -gt 0 -and $Retrycount -lt $MaxRetry) {
                    $Retrycount++
                    Write-Verbose "Starting retry $Retrycount with $($RetryObjects.Count) objects"
                    
                    # Create lookup hashtable for faster filtering
                    $retryIdHash = @{}
                    foreach ($r in $RetryObjects) { $retryIdHash[$r.id] = $true }
                    
                    # Filter objects to retry
                    $Objects = $Objects | Where-Object { $retryIdHash.ContainsKey($_.id) }
                }
                
            } while ($RetryObjects.Count -gt 0 -and $Retrycount -lt $MaxRetry)
            
            # Clear progress bar if used
            if (-not $ManagedIdentity) {
                Write-Progress -Activity "Processing Graph Batch Requests" -Completed
            }
            
            Write-Verbose "Successfully processed $($CollectedObjects.Count) of $TotalObjects objects"
            return $CollectedObjects
        }
        catch {
            Write-Error "Function failed in main process block: $_"
            throw
        }
    }
    
    End {
        # Report memory usage
        $MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
        $duration = (Get-Date) - $starttime
        Write-Verbose "Function $($MyInvocation.MyCommand.Name) finished in $($duration.ToString('mm\:ss')) | Memory: $MemoryUsage MB"
    }
}
function Invoke-ScriptReport {
    <#
    .SYNOPSIS
        Generates execution report with summary statistics and optional detailed results.

    .DESCRIPTION
        Creates formatted reports showing script execution outcomes including success/failure statistics,
        execution duration, and per-object results if detailed reporting is enabled. Can output to console
        and optionally save to disk in JSON format.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false,  HelpMessage = "Action performed by the script")]
        [ValidateNotNullOrEmpty()]
        [string]$ScriptAction           = "Generic Report",

        [Parameter(Mandatory = $false,  HelpMessage = "Include detailed report")]
        [bool]$DetailedReport           = $script:DetailedReport,

        [Parameter(Mandatory = $false,  HelpMessage = "Save report to disk")]
        [bool]$ReportToDisk             = $script:ReportToDisk,

        [Parameter(Mandatory = $false,  HelpMessage = "Path where to save the report")]
        [ValidateNotNullOrEmpty()]
        [string]$ReportPath             = $script:ReportPath,

        [Parameter(Mandatory = $false,  HelpMessage = "Script Start Time")]
        [ValidateNotNullOrEmpty()]
        [datetime]$ScriptStartTime      = [DateTime]::Now,

        [Parameter(Mandatory = $false,  HelpMessage = "Script End Time")]
        [ValidateNotNullOrEmpty()]
        [datetime]$ScriptEndTime        = [DateTime]::Now
    )

    Begin {
        Write-Verbose "Starting report generation"
    }

    Process {
        try {
            # Validate timestamps (simplified check)
            if (-not ($ScriptStartTime -is [datetime])) { $ScriptStartTime = [DateTime]::Now }
            if (-not ($ScriptEndTime -is [datetime])) { $ScriptEndTime = [DateTime]::Now }
            $RunsInAzure = $env:AZUREPS_HOST_ENVIRONMENT -or $env:AUTOMATION_ASSET_ACCOUNTID # Detect Azure Automation environment
            # Pre-calculate summary values once
            $duration = "{0:hh\:mm\:ss}" -f ($ScriptEndTime - $ScriptStartTime)
            $totalObjects = $script:ReportProgress.Total
            $wouldChange = $script:ReportProgress.Whatif
            $objectsChanged = $script:ReportProgress.Success
            $objectsSkipped = $script:ReportProgress.Skipped
            $objectsFailed = $script:ReportProgress.Failed

            # Generate detailed report if requested
            if ($DetailedReport -and $script:ReportResults.Count -gt 0) {
                @($script:ReportResults) | Sort-Object -Property Status, Object | Format-Table -Property `
                    @{Name='Object';Expression={$_.Object};Alignment='Left'},
                    @{Name='OldValue';Expression={$_.OldValue};Alignment='Left'},
                    @{Name='NewValue';Expression={$_.NewValue};Alignment='Left'},
                    @{Name='Status';Expression={$_.Status};Alignment='Left'} -AutoSize | Out-String -Width 200
            }

            # Display summary report
            Write-Output "`nScript Report - $ScriptAction"
            Write-Output "====================="
            Write-Output "Start Time: $ScriptStartTime"
            Write-Output "Duration: $duration"
            Write-Output "`nSummary Statistics:"
            Write-Output "-----------------"
            Write-Output "Total Objects Found:`t`t$totalObjects"
            Write-Output "Would Change:`t`t`t$wouldChange"
            Write-Output "Changed:`t`t`t$objectsChanged"
            Write-Output "Skipped Total:`t`t`t$objectsSkipped"
            Write-Output "Failed:`t`t`t`t$objectsFailed"

            # Save report to disk if requested
            if ($ReportToDisk) {
                $reportFilePath = Join-Path $ReportPath "Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
                if (-not (Test-Path $ReportPath)) {
                    New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null
                }
                
                # Build report data only if saving to disk
                $reportData = @{
                    Summary = @{
                        StartTime = $ScriptStartTime
                        Duration = $duration
                        TotalObjects = $totalObjects
                        ObjectsChanged = $objectsChanged
                        WouldChange = $wouldChange
                        ObjectsSkipped = $objectsSkipped
                        ObjectsFailed = $objectsFailed
                    }
                }
                
                $reportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportFilePath -Force
                Write-Verbose "Saved report to: $reportFilePath"
            }

            Write-Verbose "Report generation completed successfully"
        }
        catch {
            Write-Error "Failed to generate report: $_"
            throw
        }
    }

    End {
        # End function and report memory usage 
        $MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
        Write-Verbose "Function finished. Memory usage: $MemoryUsage MB"
    }
}
function Convert-PSObjectArrayToHashTables {
    <#
    .SYNOPSIS
        Converts PSObject arrays to optimized hashtables for fast O(1) lookups.
    .DESCRIPTION
        Creates Generic.Dictionary hashtables from PSObject arrays using specified properties as keys.
        Returns single or multiple hashtables indexed by property values for efficient data retrieval.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject[]]$PSObjectArray,

        [Parameter(Mandatory)]
        [string[]]$IdProperties  # Array of property names to create hashtables for
    )

    Begin {
        # Initialize hashtables with estimated capacity
        $HashTables = @{}
        foreach ($prop in $IdProperties) {
            $HashTables[$prop] = [System.Collections.Generic.Dictionary[string,object]]::new($PSObjectArray.Count)
        }
    }

    Process {
        foreach ($PSObject in $PSObjectArray) {
            foreach ($IdProperty in $IdProperties) {
                # DEBUG: Show what we're looking for and what's available
                $availableProps = $PSObject.PSObject.Properties.Name -join ', '
                # Use case-insensitive comparison to find the property
                $actualProperty = $PSObject.PSObject.Properties.Name | Where-Object { $_ -eq $IdProperty }
                if ($actualProperty) {
                    $IdValue = $PSObject.$actualProperty
                    if ($null -ne $IdValue -and $IdValue -ne '') {
                        # Add to hashtable (overwrite if duplicate key exists)
                        $HashTables[$IdProperty][$IdValue] = $PSObject
                    } else {
                        Write-Warning "Property '$actualProperty' is null or empty"
                    }
                } else {
                    Write-Warning "Property '$IdProperty' not found in object"
                }
            }
        }
    }
    
    End {
        foreach ($prop in $IdProperties) {
            Write-Verbose "Converted $($HashTables[$prop].Count) objects to hashtable using property '$prop'"
        }
        # Return single hashtable if only one property, otherwise return all by property name
        if ($IdProperties.Count -eq 1) {
            return $HashTables[$IdProperties[0]]
        }
        else {
            return $HashTables
        }
    }
}
#endregion

#region ---------------------------------------------------[[Script Execution]------------------------------------------------------
$Script:StartTime = [datetime]::Now

# Start custom logging
if ($ReportToDisk) { Invoke-TboneLog -Mode Start -LogToGUI $true -LogToDisk $true -LogPath $ReportPath }
else{ Invoke-TboneLog -Mode Start -LogToGUI $true -LogToDisk $false }

try {
    #Sign in to Graph
    try {Invoke-ConnectMgGraph -RequiredScopes $RequiredScopes
        Write-Verbose "Success to get Access Token to Graph"}
    catch {
        Write-Error "Failed to get Access Token to Graph, with error: $_"
        throw
    }

# Get all devices
    try {
        # List properties to retrieve
        $GraphProperties = 'id,deviceName,operatingSystem,AzureAdDeviceId,userid'
        # Prepare graph filters if needed
        $GraphFilterString = $null
        if ($OperatingSystems -notcontains 'All' -and $OperatingSystems.Count -gt 0) {
            $osFilterParts = $OperatingSystems | ForEach-Object { "operatingSystem eq '$_'" }
            $GraphFilterString = "($($osFilterParts -join ' or '))"
        }
        # Add filter for Intune managed devices only in co-managed environment
        if ($GraphFilterString) {$GraphFilterString = "managementAgent eq 'mdm' and " + $GraphFilterString}
        else {$GraphFilterString = "managementAgent eq 'mdm' "}
        # Verbose logging of the filter used
        if($GraphFilterString){Write-Verbose "Using filter: $GraphFilterString"}
        $AllDevices = Invoke-MgGraphRequestSingle `
            -RunProfile 'beta' `
            -Method 'GET' `
            -Object 'deviceManagement/managedDevices' `
            -Properties $GraphProperties `
            -Filters $GraphFilterString `
            -MaxRetry $MaxRetry `
            -WaitTime $WaitTime

        # Verify if devices were found   
        if ($AllDevices -and $AllDevices.Count -gt 0) {
            Write-Verbose "Retrieved $($AllDevices.Count) devices from Graph API"
            
            # Apply client-side name filters
            if (($IncludedDeviceNames -and $IncludedDeviceNames.Count -gt 0) -or ($ExcludedDeviceNames -and $ExcludedDeviceNames.Count -gt 0)) {
                $includePattern = if ($IncludedDeviceNames -and $IncludedDeviceNames.Count -gt 0) {
                    '^(' + (($IncludedDeviceNames | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')'
                } else { $null }
                $excludePattern = if ($ExcludedDeviceNames -and $ExcludedDeviceNames.Count -gt 0) {
                    '^(' + (($ExcludedDeviceNames | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')'
                } else { $null }
                $AllDevices = $AllDevices | Where-Object {
                    $device = $_
                    $includeMatch = if ($includePattern) { $device.deviceName -imatch $includePattern } else { $true }
                    $excludeMatch = if ($excludePattern) { $device.deviceName -notmatch $excludePattern } else { $true }
                    $includeMatch -and $excludeMatch
                }
                if ($includePattern) { Write-Verbose "Applied inclusion filter for $($IncludedDeviceNames.Count) patterns" }
                if ($excludePattern) { Write-Verbose "Applied exclusion filter for $($ExcludedDeviceNames.Count) patterns" }
                Write-Verbose "Remaining after filters: $($AllDevices.Count) devices"
            }
        }
        else {Write-Warning "No devices found in tenant"}
    }
    catch {
        Write-Error "Failed to get devices: $_"
        throw
    }

#Get all devices one by one to get their scope tags, in batch to avoid throttling
    try {
        # List properties to retrieve
        $GraphProperties = 'id,deviceName,operatingSystem,AzureAdDeviceId,userId,roleScopeTagIds'
        # Prepare graph filters if needed
        $GraphFilterString = $null
        # Verbose logging of the filter used
        if($GraphFilterString){Write-Verbose "Using filter: $GraphFilterString"}
        # Get graph objects using batch
        $AllDevicesWithTags = invoke-mggraphrequestbatch `
            -RunProfile 'beta' `
            -Method 'GET' `
            -Object 'deviceManagement/managedDevices' `
            -Objects $AllDevices `
            -Query  ''`
            -Properties $GraphProperties `
            -Filters $GraphFilterString `
            -BatchSize $BatchSize `
            -WaitTime $WaitTime `
            -MaxRetry $MaxRetry 

        # Verify if objects were found
        if ($AllDevicesWithTags -and $AllDevicesWithTags.Count -gt 0) {
            Write-Verbose "Successfully retrieved $($AllDevicesWithTags.Count) devices with scope tags from Graph API Batching"
            # Create hashtable for fast lookups
            $AllDevicesWithTagsHash = Convert-PSObjectArrayToHashTables -PSObjectArray $AllDevicesWithTags -IdProperties @('id','userId')
            $AllDevicesWithTagsByDeviceIdHash = $AllDevicesWithTagsHash['id']
            $AllDevicesWithTagsByUserIdHash = $AllDevicesWithTagsHash['userId']
            Write-Verbose "Created device lookup hashtables: Id=$($AllDevicesWithTagsByDeviceIdHash.Count) entries, userId=$($AllDevicesWithTagsByUserIdHash.Count) entries"
        }
        else {
            Write-Warning "No devices with scope tags found in tenant"
        }
    }
    catch {
        Write-Error "Failed to get devices and their scope tags: $_"
        throw
    }
#cleanup unused variable to save memory
Remove-Variable -Name AllDevices

# Get all users 
    try {
        # List properties to retrieve
        $GraphProperties = "id,userPrincipalName,$ScopeTagAttribute"
        # Prepare graph filters if needed
        $GraphFilterString = $null
        # Verbose logging of the filter used
        if($GraphFilterString){Write-Verbose "Using filter: $GraphFilterString"}
        # Get graph objects
        $AllUsers = Invoke-MgGraphRequestSingle `
            -RunProfile 'v1.0' `
            -Method 'GET' `
            -Object 'users' `
            -Properties $GraphProperties `
            -Filters $GraphFilterString `
            -MaxRetry $MaxRetry `
            -WaitTime $WaitTime

        # Verify if objects were found
        if ($AllUsers -and $AllUsers.Count -gt 0) {
            Write-Verbose "Successfully retrieved $($AllUsers.Count) users from Graph API"
            # Create hashtable for fast lookups
            $userHashTables = Convert-PSObjectArrayToHashTables -PSObjectArray $AllUsers -IdProperties @('id', 'userPrincipalName')
            $AllUserByIdHash = $userHashTables['id']
            $UserByUPNHash = $userHashTables['userPrincipalName']
            Write-Verbose "Created user lookup hashtables: ID=$($AllUserByIdHash.Count) entries, UPN=$($UserByUPNHash.Count) entries"
        }
        else {Write-Warning "No users found in tenant"}
    }
    catch {
        Write-Error "Failed to get users: $_"
        throw
    }

# Get all scope tags 
    try {
        # List properties to retrieve
        $GraphProperties = 'id,displayName,description,isBuiltIn'
        # Prepare filters if needed
        $GraphFilterString = $null
        # Verbose logging of the filter used
        if($GraphFilterString){Write-Verbose "Using filter: $GraphFilterString"}
        # Get graph objects
        $AllScopeTags = Invoke-MgGraphRequestSingle `
            -RunProfile 'beta' `
            -Method 'GET' `
            -Object 'deviceManagement/roleScopeTags' `
            -Properties $GraphProperties `
            -Filters $GraphFilterString `
            -MaxRetry $MaxRetry `
            -WaitTime $WaitTime

        # Verify if objects were found
        if ($AllScopeTags -and $AllScopeTags.Count -gt 0) {
            Write-Verbose "Successfully retrieved $($AllScopeTags.Count) scope tags from Graph API"
            # Create hashtable for fast lookups
            $AllScopeTagHash = Convert-PSObjectArrayToHashTables -PSObjectArray $AllScopeTags -IdProperties @('id','displayName')
            $AllScopeTagByIdHash = $AllScopeTagHash['id']
            $AllScopeTagByDisplayNameHash = $AllScopeTagHash['displayName']
            Write-Verbose "Created scope tag lookup hashtable: ID=$($AllScopeTagByIdHash.Count) entries, DisplayName=$($AllScopeTagByDisplayNameHash.Count) entries"
        }
        else {Write-Warning "No scope tags found in tenant"}
    }
    catch {
        Write-Error "Failed to get scope tags: $_"
        throw
    }

# Process all devices and set the scope tag to match info on the primary user
    $script:ReportProgress.Total = $AllDevicesWithTags.Count
    # Initialize collection for devices that need updates
    $devicesToUpdate = [System.Collections.ArrayList]::new()
    # Helper function to add report result
    $addReport = {
        param($Device, $Old, $New, $Status, $Counter)
        $script:ReportProgress.$Counter++
        [void]$script:ReportResults.Add([PSCustomObject]@{
            Object = $Device; OldValue = $Old; NewValue = $New; Status = $Status
        })
    }.GetNewClosure()
    # Process each device
    foreach ($device in $AllDevicesWithTags) {
        # Cache device properties for faster access
        $deviceName = $device.DeviceName
        $deviceId = $device.id

        # Get current Primary User
        $currentPrimaryUser = $null
        if (-not ($device.userid -and $AllUserByIdHash.TryGetValue($device.userid, [ref]$currentPrimaryUser))) {
            # Skip this device if no current primary user was found
            & $addReport $deviceName 'No.CurrentPrimaryUser' 'N/A' 'Skipped: Missing Current Primary User' 'Skipped'
            Write-Warning "Device: $($deviceName) Primary user is missing or invalid - skipping"
            continue
        }
        $currentPrimaryUserUPN = $currentPrimaryUser.userPrincipalName

        # Get desired Scope Tag based on Primary User attributes
        $ScopeTagAttributeValue = $currentPrimaryUser.$ScopeTagAttribute
        if (-not $ScopeTagMappings.ContainsKey($ScopeTagAttributeValue)) {
            # Skip this device if no mapping was found
            & $addReport $deviceName $ScopeTagAttributeValue 'N/A' 'Skipped: No Mapping Found' 'Skipped'
            write-warning "Device: $($deviceName) Primary user: $($currentPrimaryUserUPN) No Attribute Mapping for $($ScopeTagAttribute): '$($ScopeTagAttributeValue)' - skipping"
            continue
        }

        # Get desired scope tag object (has both id and displayName)
        $desiredScopeTagName = $ScopeTagMappings[$ScopeTagAttributeValue]
        $desiredScopeTag = $null
        if (-not $AllScopeTagBydisplayNameHash.TryGetValue($desiredScopeTagName, [ref]$desiredScopeTag)) {
            & $addReport $deviceName $ScopeTagAttributeValue $desiredScopeTagName 'Skipped: Scope Tag Not Found' 'Skipped'
            Write-Warning "Device: $($deviceName) Primary user: $($currentPrimaryUserUPN) Attribute $($ScopeTagAttribute): '$($ScopeTagAttributeValue)' Scope Tag missing in tenant - skipping"
            continue
        }
        
        # Add builtin "Default" scope tag if requested
        [array]$newScopeTagIds = if ($KeepBuiltinTag) { $desiredScopeTag.id, "0" } else { $desiredScopeTag.id }
        $newScopeTagIds = @($newScopeTagIds | Select-Object -Unique | Sort-Object)
        
        # Get current scope tag IDs from device
        $deviceWithTags = $null
        [array]$currentScopeTagIds = if ($AllDevicesWithTagsByDeviceIdHash.TryGetValue($deviceId, [ref]$deviceWithTags) -and $deviceWithTags.roleScopeTagIds) {
            @($deviceWithTags.roleScopeTagIds) | Sort-Object
        } else {
            @()
        }
        
        # Compare if current tags match desired tags
        $tagsMatch =    if (@($currentScopeTagIds).Count -ne @($newScopeTagIds).Count) {$false}
                        else {
                            $diff = Compare-Object $currentScopeTagIds $newScopeTagIds
                            $null -eq $diff
                        }
        
        # Convert to names for reporting
        if (-not $tagsMatch) {
            $currentNames = ($currentScopeTagIds | ForEach-Object { 
                if ($_ -eq "0") { "Default" } else { 
                    $t = $null; if ($AllScopeTagByIdHash.TryGetValue($_, [ref]$t)) { $t.displayName } else { $_ }
                }
            }) -join ','
            $newNames = ($newScopeTagIds | ForEach-Object { 
                if ($_ -eq "0") { "Default" } else { $desiredScopeTag.displayName }
            }) -join ','
        } else {
            $currentNames = $newNames = ($newScopeTagIds | ForEach-Object { 
                if ($_ -eq "0") { "Default" } else { $desiredScopeTag.displayName }
            }) -join ','
        }
        
        if ($tagsMatch) {
            & $addReport $deviceName $currentNames $newNames 'Skipped: Tags Already Correct' 'Skipped'
            Write-Verbose "Device: $($deviceName) Primary user: $($currentPrimaryUserUPN) Attribute $($ScopeTagAttribute): '$($ScopeTagAttributeValue)' already has correct scope tags: $newNames"
        }
        else {
            # Add device to batch update queue
            $devicesToUpdate.Add([PSCustomObject]@{
                id = $deviceId
                deviceName = $deviceName
                currentScopeTagNames = $currentNames
                newScopeTagNames = $newNames
                body = @{ roleScopeTagIds = $newScopeTagIds }
            }) | Out-Null
            Write-verbose "Device: $($deviceName) Primary user: $($currentPrimaryUserUPN) Attribute $($ScopeTagAttribute): '$($ScopeTagAttributeValue)' Scope Tag change needed $currentNames → $newNames"
        }
    }
    
    # Process batch updates for devices that need changes
    if ($devicesToUpdate.Count -gt 0) {
        Write-Verbose "Starting batch update for $($devicesToUpdate.Count) devices"
        if ($WhatIfPreference) {
            # WhatIf mode - just report what would change
            foreach ($dev in $devicesToUpdate) {
                & $addReport $dev.deviceName ($dev.currentScopeTagNames -join ',') ($dev.newScopeTagNames -join ',') 'Would Change' 'Whatif'
                Write-Verbose "WhatIf: Device $($dev.deviceName) would be updated from [$($dev.currentScopeTagNames -join ', ')] to [$($dev.newScopeTagNames -join ', ')]"
            }
        }
        else {
            # Perform batch updates
            try {
                $batchResults = invoke-mggraphrequestbatch `
                    -RunProfile 'beta' `
                    -Method 'PATCH' `
                    -Object 'deviceManagement/managedDevices' `
                    -Objects $devicesToUpdate `
                    -Query '' `
                    -BatchSize 20 `
                    -WaitTime $WaitTime `
                    -MaxRetry $MaxRetry
                
                Write-Verbose "Batch update completed with $($batchResults.Count) results. Processing reports..."
                # Process batch results and update reports
                foreach ($result in $batchResults) {
                    $resultId = if ($result.id) { $result.id } elseif ($result.'@odata.id') { ($result.'@odata.id' -split '/')[-1] } else { $null }
                    if ($resultId) {
                        # Find the matching device
                        $deviceInfo = $devicesToUpdate | Where-Object { $_.id -eq $resultId } | Select-Object -First 1
                        if ($deviceInfo) {
                            & $addReport $deviceInfo.deviceName ($deviceInfo.currentScopeTagNames -join ',') ($deviceInfo.newScopeTagNames -join ',') 'Success to change' 'Success'
                            Write-Verbose "Successfully updated device $($deviceInfo.deviceName) from [$($deviceInfo.currentScopeTagNames -join ', ')] to [$($deviceInfo.newScopeTagNames -join ', ')]"
                        } else {
                            Write-Warning "Batch result with ID $resultId not found in update list"
                        }
                    } else {
                        Write-Warning "Batch result has no ID: $($result | ConvertTo-Json -Depth 1)"
                    }
                }
            }
            catch {
                Write-Error "Batch update failed: $_"
                # Mark all devices as failed
                foreach ($dev in $devicesToUpdate) {
                    & $addReport $dev.deviceName ($dev.currentScopeTagNames -join ',') 'N/A' "Failed: $_" 'Failed'
                }
            }
        }
    }
    else {
        Write-Verbose "No devices need updating"
    }
    
    Write-Verbose "Processing complete. Success: $($script:ReportProgress.Success), Failed: $($script:ReportProgress.Failed), Skipped: $($script:ReportProgress.Skipped)"
    $script:EndTime = [datetime]::Now
}
catch {
    Write-Error "Script execution failed: $_"
}
finally {
    # Disconnect from Graph
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue *>$null
        Write-Verbose "Disconnected from Graph"
    } catch {Write-Error "Failed to disconnect from Graph: $_"}
    Invoke-TboneLog -Mode Stop
    
    # Restore original preference settings to user's console
    $ErrorActionPreference = $script:OriginalErrorActionPreference
    $VerbosePreference = $script:OriginalVerbosePreference
    $WhatIfPreference = $script:OriginalWhatIfPreference
    
    # End script and report memory usage 
    $MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
    Write-Verbose "Script finished. Memory usage: $MemoryUsage MB"
# Generate report if requested
    if ($ReturnReport -and $DetailedReport -and $script:ReportResults.Count -gt 0) {
        Invoke-ScriptReport -DetailedReport $true -ReportToDisk $ReportToDisk -ReportPath $ReportPath -ScriptAction $ScriptActionName -ScriptStartTime $Script:StartTime -ScriptEndTime $script:EndTime
        Write-Verbose "Generated detailed report"
    } elseif ($ReturnReport -and $script:ReportResults.Count -gt 0) {
        Invoke-ScriptReport -DetailedReport $false -ReportToDisk $ReportToDisk -ReportPath $ReportPath -ScriptAction $ScriptActionName -ScriptStartTime $Script:StartTime -ScriptEndTime $script:EndTime
        Write-Verbose "Generated summary report"
    } else {Write-Verbose "Report generation not requested or no results to report"}
}

#endregion
