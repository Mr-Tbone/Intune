<#PSScriptInfo
.VERSION        4.0.0
.GUID           feedbeef-beef-4dad-beef-000000000003
.AUTHOR         @MrTbone_se (T-bone Granheden)
.COPYRIGHT      (c) 2026 T-bone Granheden. MIT License - free to use with attribution.
.TAGS           Intune Graph PrimaryUser DeviceManagement MicrosoftGraph Azure
.LICENSEURI     https://opensource.org/licenses/MIT
.PROJECTURI     https://github.com/Mr-Tbone/Intune
.RELEASENOTES
    1.0 2025-03-19 Initial Build
    2.0 2025-11-14 Large update to use Graph batching and reduce runtime
    3.0 2025-12-19 Added versions on functions to keep track of changes, changed name to Add-IntuneScopeTagsBasedOnPrimaryUser, comments and fixed minor bugs
    4.0.0 2025-12-23 Major update to allign all primary user scripts. Many small changes to improve performance and reliability.
#>

<#
.SYNOPSIS
    Script for Intune to set Scope Tags on Device based on Primary Users and their attributes

.DESCRIPTION
    This script will get all devices and their current primary user and current scope tags
    Get all users and the significant attribute for scope tagging
    It will then set scope tags based on that attribute
    The script uses Ms Graph and only requires the Microsoft.Graph.Authentication module

.EXAMPLE
   .\Add-IntuneScopeTagsBasedOnPrimaryUser.ps1
    Will set the scope tags on devices in Intune based on primary users and their attributes with default settings

.EXAMPLE
    .\Add-IntuneScopeTagsBasedOnPrimaryUser.ps1 -MappingAttribute country -OperatingSystems All -ReportDetailed $true -ReportToDisk $true -ReportToDiskPath "C:\Reports"
    Will set the scope tags on devices in Intune based on primary users and their attribute country for all devices and return a detailed report to disk

.EXAMPLE
    .\Add-IntuneScopeTagsBasedOnPrimaryUser.ps1 -OperatingSystems Windows -MappingAttribute "Country"
    Will set the scope tags on devices in Intune based on primary user attribute "country" for Windows devices.

.NOTES
    Please feel free to use this, but make sure to credit @MrTbone_se as the original author

.LINK
    https://tbone.se
#>

#region ---------------------------------------------------[Set Script Requirements]-----------------------------------------------
#Requires -Modules Microsoft.Graph.Authentication
#Requires -Version 5.1
#endregion

#region ---------------------------------------------------[Modifiable Parameters and Defaults]------------------------------------
# Customizations
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false,          HelpMessage = "Name of the script action for logging.")]
    [string]$ScriptActionName       = "Intune Set Scope Tags based on Primary User",

    [Parameter(Mandatory = $false,          HelpMessage = "Device operatingsystems to process ('All', 'Windows', 'Android', 'iOS', 'macOS'). Default is 'Windows'")]
    [ValidateSet('All', 'Windows', 'Android', 'iOS', 'macOS')]
    [string[]]$OperatingSystems     = @('Windows'),

    [Parameter(Mandatory = $false,          HelpMessage = "Attribute to use for the scope tag. Default is 'Country'")]
    [string]$MappingAttribute      = "Country",

    [Parameter(Mandatory = $false,          HelpMessage = "Whether to keep the built-in scope tag (usually called Default). Default is true")]
    [bool]$KeepBuiltinTag           = $true,
            
    [Parameter(Mandatory = $false,          HelpMessage = "Filter Intune only managed devices (true) or also include Co-managed devices (false). Default is true")]
    [bool]$IntuneOnly               = $true,

    [Parameter(Mandatory = $false,          HelpMessage = "Filter to only include devicenames that starts with specific strings like ('Tbone', 'Desktop'). Default is blank")]
    [string[]]$IncludedDeviceNames  = @(),

    [Parameter(Mandatory = $false,          HelpMessage = "Filter to exclude devicenames that starts with specific strings like ('Tbone', 'Desktop'). Default is blank")]
    [string[]]$ExcludedDeviceNames  = @(),
    
    [Parameter(Mandatory = $false,          HelpMessage = "Testmode, same as -WhatIf. Default is false")]
    [bool]$Testmode                 = $false,
    # ---------------------------------- Authentication (Invoke-ConnectMgGraph) Leave blank if use Interactive or Managed Identity-------------------------
    [Parameter(                             HelpMessage = "Entra ID Tenant ID (directory ID) (required for Client Secret or Certificate authentication)")]
    [ValidateNotNullOrEmpty()]
    [string]$AuthTenantId,

    [Parameter(                             HelpMessage = "Entra ID Application ID (ClientID) (required for Client Secret or Certificate authentication)")]
    [ValidateNotNullOrEmpty()]
    [string]$AuthClientId,
    
    [Parameter(                             HelpMessage = "Client Secret as SecureString for app-only authentication (require also ClientId and TenantId)")]
    [ValidateNotNull()]
    [SecureString]$AuthClientSecret,
    
    [Parameter(                             HelpMessage = "Certificate thumbprint for certificate-based authentication (if certificate is stored in CurrentUser or LocalMachine store)")]
    [ValidateNotNullOrEmpty()]
    [string]$AuthCertThumbprint,

    [Parameter(                             HelpMessage = "Certificate subject name for certificate-based authentication (if certificate is stored in CurrentUser or LocalMachine store)")]
    [ValidateNotNullOrEmpty()]
    [string]$AuthCertName,
    
    [Parameter(                             HelpMessage = "File path to certificate (.pfx or .cer) for certificate-based authentication (if certificate is stored as a file)")]
    [ValidateNotNullOrEmpty()]
    [string]$AuthCertPath,
    
    [Parameter(                             HelpMessage = "Password for certificate file as SecureString (required if certificate is stored as a file and password-protected)")]
    [SecureString]$AuthCertPassword,
# ---------------------------------- Logging (Invoke-TboneLog)-------------------------------------------------------
    [Parameter(Mandatory = $false,          HelpMessage='Show output in console during execution')]
    [bool]$LogToGUI                 = $true,

    [Parameter(Mandatory = $false,          HelpMessage='Write complete log array to Windows Event when script ends')]
    [bool]$LogToEventlog            = $false,

    [Parameter(Mandatory = $false,          HelpMessage='Return complete log array as Host output when script ends (Good for Intune Remediations)')]
    [bool]$LogToHost                = $false,

    [Parameter(Mandatory = $false,          HelpMessage='Write complete log array to Disk when script ends')]
    [bool]$LogToDisk                = $false,

    [Parameter(Mandatory = $false,          HelpMessage='Path where Disk logs are saved (if LogToDisk is enabled)')]
    [string]$LogToDiskPath          = "$env:TEMP",

    [Parameter(Mandatory = $false,          HelpMessage = "Enable verbose logging. Default is false")]
    [bool]$LogVerboseEnabled        = $false,
# ---------------------------------- Reporting (Invoke-ScriptReport)---------------------------------------------------
    [Parameter(Mandatory = $false,          HelpMessage = "Return report with statistics on how many changed objects. Default is true")]
    [bool]$ReportEnabled            = $true,

    [Parameter(Mandatory = $false,          HelpMessage = "Include detailed device changes in the report. Default is true")]
    [bool]$ReportDetailed           = $true,

    [Parameter(Mandatory = $false,          HelpMessage = "Save report to disk. Default is false")]
    [bool]$ReportToDisk             = $false,    

    [Parameter(Mandatory = $false,          HelpMessage = "Path where to save the report. Default is TEMP directory for Azure Automation compatibility")]
    [string]$ReportToDiskPath       = "$env:TEMP",
# ---------------------------------- Throttling and Retry (Invoke-MgGraphRequestSingle and Invoke-MgGraphRequestBatch)--
    [Parameter(Mandatory = $false,          HelpMessage = "Wait time in milliseconds between throttled requests. Default is 1000")]
    [ValidateRange(100,5000)]
    [int]$GraphWaitTime                  = 1000,

    [Parameter(Mandatory = $false,          HelpMessage = "Maximum number of retry attempts for failed requests. Default is 3")]
    [ValidateRange(1,10)]
    [int]$GraphMaxRetry                  = 3,

    [Parameter(Mandatory = $false,          HelpMessage = "Maximum number of items to process in a single batch. Default is 20")]
    [ValidateRange(1,20)]
    [int]$GraphBatchSize                  = 20
    )
#endregion

#region ---------------------------------------------------[Modifiable Variables and defaults]------------------------------------
# Define User attribute to scope tags mapping by table
$MappingAttributeTable = @{
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
# Required Graph API scopes for Invoke-ConnectMgGraph functions
[System.Collections.ArrayList]$requiredScopes = @(
    "DeviceManagementManagedDevices.ReadWrite.All",  # Read/write Intune device to set scope tags
    "DeviceManagementRBAC.Read.All",                 # Read scope tags
    "User.Read.All"                                  # Read users
)
#endregion

#region ---------------------------------------------------[Set global script settings]--------------------------------------------
# Exit if running as a managed identity in PowerShell 7.2 due to bugs connecting to MgGraph https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/3151
if ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER -and $PSVersionTable.PSVersion -eq [version]"7.2.0") {
    Write-Error "This script cannot run as a managed identity in PowerShell 7.2. Please use a different version of PowerShell."
    exit 1}
# set strict mode to latest version
Set-StrictMode -Version Latest

# Save original preference states at script scope for restoration in finally block
[System.Management.Automation.ActionPreference]$script:OriginalErrorActionPreference    = $ErrorActionPreference
[System.Management.Automation.ActionPreference]$script:OriginalVerbosePreference        = $VerbosePreference
[bool]$script:OriginalWhatIfPreference                                                  = $WhatIfPreference

# Set verbose- and whatif- preference based on parameter instead of hardcoded values
if ($LogVerboseEnabled)     {$VerbosePreference = 'Continue'}                   # Set verbose logging based on the parameter $LogVerboseEnabled
else                        {$VerbosePreference = 'SilentlyContinue'}
if($Testmode)               {$WhatIfPreference = 1}                             # Manually enable whatif mode with parameter $Testmode for testing
#endregion

#region ---------------------------------------------------[Import Modules and Extensions]-----------------------------------------
# Check if Microsoft.Graph.Authentication module is already loaded, if not import it silently by suppressing verbose output
[string]$moduleName = 'Microsoft.Graph.Authentication'
if (-not (Get-Module -Name $moduleName)) {
    & {$VerbosePreference = 'SilentlyContinue'; Import-Module $moduleName -ErrorAction Stop}
} else {Write-Verbose "Module '$moduleName' is already loaded"}
#endregion

#region ---------------------------------------------------[Static Variables]------------------------------------------------------
# Script execution tracking for reporting
[datetime]$Script:StartTime = ([DateTime]::Now) # Script start time

# Initialize hashtable and helper for reporting (used by invoke-scriptreport)
[hashtable]$ReportResults = @{}
[scriptblock]$addReport = {param($Target,$OldValue,$NewValue,$Action,$Details)
    if(-not $ReportResults.ContainsKey($Action)){$ReportResults[$Action]=[System.Collections.ArrayList]::new()}
    $null=$ReportResults[$Action].Add([PSCustomObject]@{Target=$Target;OldValue=$OldValue;NewValue=$NewValue;Action=$Action;Details=$Details})}
#endregion

#region ---------------------------------------------------[Functions]------------------------------------------------------------
function Invoke-ConnectMgGraph {
<#
.SYNOPSIS
    Connects to Microsoft Graph API with multiple authentication methods.
.DESCRIPTION
    Supports Managed Identity, Interactive, Client Secret, and Certificate authentication...
.NOTES
    Author:  @MrTbone_se (T-bone Granheden)
    Version: 2.0
    
    Version History:
    1.0 - Initial version
    2.0 - 2026-01-09 - Changed parameter names and fixed minor bugs on certificate authentication
#>
    [CmdletBinding()]
    param (
        [Parameter(             HelpMessage = "Array of required Microsoft Graph API permission scopes example:('User.Read.All','DeviceManagementManagedDevices.ReadWrite.All') ")]
        [string[]]$RequiredScopes = @("User.Read.All"),

        [Parameter(             HelpMessage = "Entra ID Tenant ID (directory ID) (required for Client Secret or Certificate authentication)")]
        [ValidateNotNullOrEmpty()]
        [string]$AuthTenantId,
        
        [Parameter(             HelpMessage = "Entra ID Application ID (ClientID) (required for Client Secret or Certificate authentication)")]
        [ValidateNotNullOrEmpty()]
        [string]$AuthClientId, 

        [Parameter(             HelpMessage = "Client Secret as SecureString for app-only authentication (require also ClientId and TenantId)")]
        [ValidateNotNull()]
        [SecureString]$AuthClientSecret,

        [Parameter(             HelpMessage = "Certificate subject name for certificate-based authentication (if certificate is stored in CurrentUser or LocalMachine store)")]
        [ValidateNotNullOrEmpty()]
        [string]$AuthCertName,

        [Parameter(             HelpMessage = "Certificate thumbprint for certificate-based authentication (if certificate is stored in CurrentUser or LocalMachine store)")]
        [ValidateNotNullOrEmpty()]
        [string]$AuthCertThumbprint,
        
        [Parameter(             HelpMessage = "File path to certificate (.pfx or .cer) for certificate-based authentication (if certificate is stored as a file)")]
        [ValidateNotNullOrEmpty()]
        [string]$AuthCertPath,
        
        [Parameter(             HelpMessage = "Password for certificate file as SecureString (required if certificate is stored as a file and password-protected)")]
        [SecureString]$AuthCertPassword
    )

    Begin {
        $ErrorActionPreference = 'Stop'
        [string]$resourceURL = "https://graph.microsoft.com/"
        
        # Detect authentication method based on parameters and environment (priority: ClientSecret > Certificate > ManagedIdentity > Interactive)
        [bool]$hasClientId     = -not [string]::IsNullOrWhiteSpace($AuthClientId)
        [bool]$hasTenantId     = -not [string]::IsNullOrWhiteSpace($AuthTenantId)
        [bool]$hasClientSecret = $null -ne $AuthClientSecret
        [bool]$hasCertInput    = -not [string]::IsNullOrWhiteSpace($AuthCertThumbprint) -or -not [string]::IsNullOrWhiteSpace($AuthCertName) -or -not [string]::IsNullOrWhiteSpace($AuthCertPath)

        [string]$authMethod = if ($hasClientSecret -and $hasClientId -and $hasTenantId) {'ClientSecret'}
        elseif ($hasCertInput -and $hasClientId -and $hasTenantId)                      {'Certificate'}
        elseif ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER)                       {'ManagedIdentity'}
        else                                                                            {'Interactive'}
        Write-Verbose "Using authentication method: $authMethod"
    }

    Process {
        try {
            # Check for existing valid connection and required scopes
            try {
                $context = Get-MgContext -ErrorAction SilentlyContinue
                if ($context) {
                    Write-Verbose "Existing connection found for: $($context.Account)"
                    # Validate scopes only for Interactive auth (Managed Identity/app-only doesn't use delegated scopes)
                    if ($authMethod -eq 'Interactive') {
                        [string[]]$currentScopes = @($context.Scopes)
                        [string[]]$missingScopes = @($RequiredScopes | Where-Object { $_ -notin $currentScopes })
                        
                        if ($missingScopes.Count -eq 0) {
                            Write-Verbose "Reusing existing connection with valid scopes"
                            return $context.Account
                        }
                        Write-Verbose "Existing connection missing scopes: $($missingScopes -join ', ')"
                        Disconnect-MgGraph -ErrorAction SilentlyContinue
                    } else {
                        # For app-only auth, reuse existing connection
                        return $context.Account
                    }
                }
            }
            catch {
                Write-Verbose "No existing connection found"
            }
            
            # Build connection parameters
            $connectParams = @{ NoWelcome = $true }
            
            switch ($authMethod) {
                'ManagedIdentity' {
                    Write-Verbose "Connecting with Managed Identity"
                    
                    # Validate environment variables
                    if (-not $env:IDENTITY_ENDPOINT -or -not $env:IDENTITY_HEADER) {
                        throw "Managed Identity environment variables not set"
                    }
                    
                    # Get Graph SDK version for compatibility
                    [version]$graphVersion = (Get-Module -Name 'Microsoft.Graph.Authentication' -ListAvailable | 
                        Sort-Object Version -Descending | Select-Object -First 1).Version
                    Write-Verbose "Graph SDK version: $graphVersion"
                    
                    if ($graphVersion -ge [version]"2.0.0") {
                        $connectParams['Identity'] = $true
                    } else {
                        # For older SDK versions, get token manually from managed identity endpoint
                        [hashtable]$Headers = @{
                            'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER
                            'Metadata' = 'True'
                        }
                        $response = Invoke-RestMethod -Uri "$($env:IDENTITY_ENDPOINT)?resource=$resourceURL" -Method GET -Headers $Headers -TimeoutSec 30 -ErrorAction Stop
                        if (-not $response -or [string]::IsNullOrWhiteSpace($response.access_token)) {
                            throw "Failed to retrieve access token from managed identity endpoint"
                        }
                        $connectParams['AccessToken'] = $response.access_token
                        Write-Verbose "Retrieved managed identity token"
                    }
                }
                
                'ClientSecret' {
                    Write-Verbose "Connecting with Client Secret"
                    # Validate required inputs
                    if (-not $hasClientId -or -not $hasTenantId) {
                        throw "ClientSecret authentication requires both ClientId and TenantId."
                    }
                    # Convert SecureString to PSCredential to build ClientCredential
                    [System.Management.Automation.PSCredential]$clientCredential = [System.Management.Automation.PSCredential]::new($AuthClientId, $AuthClientSecret)
                    $connectParams['ClientId']               = $AuthClientId
                    $connectParams['TenantId']               = $AuthTenantId
                    $connectParams['ClientSecretCredential'] = $clientCredential
                    Write-Verbose "Using ClientId: $AuthClientId, TenantId: $AuthTenantId"
                }
                
                'Certificate' {
                    Write-Verbose "Connecting with Certificate"
                    # Validate required inputs
                    if (-not $hasClientId -or -not $hasTenantId) {
                        throw "Certificate authentication requires both ClientId and TenantId."
                    }
                    $connectParams['ClientId'] = $AuthClientId
                    $connectParams['TenantId'] = $AuthTenantId
                    
                    # Handle different certificate input methods
                    if ($AuthCertThumbprint) {
                        $connectParams['CertificateThumbprint'] = $AuthCertThumbprint
                        Write-Verbose "Using certificate thumbprint: $AuthCertThumbprint"
                    }
                    elseif ($AuthCertName) {
                        $connectParams['CertificateName'] = $AuthCertName
                        Write-Verbose "Using certificate name: $AuthCertName"
                    }
                    elseif ($AuthCertPath) {
                        # Load certificate from file
                        if (-not (Test-Path $AuthCertPath)) {
                            throw "Certificate file not found: $AuthCertPath"
                        }
                        
                        try {
                            # Declare variable for StrictMode compliance
                            [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert = $null
                            # Use MachineKeySet flag for Azure Automation compatibility
                            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]$keyFlags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet
                            
                            if ($AuthCertPassword) {
                                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                                    $AuthCertPath, 
                                    $AuthCertPassword,
                                    $keyFlags
                                )
                            } else {
                                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($AuthCertPath, [string]::Empty, $keyFlags)
                            }
                            
                            # Validate certificate has private key (required for auth)
                            if (-not $cert.HasPrivateKey) {
                                throw "Certificate does not contain a private key, which is required for authentication"
                            }
                            
                            $connectParams['Certificate'] = $cert
                            Write-Verbose "Loaded certificate from: $AuthCertPath (Subject: $($cert.Subject), Expires: $($cert.NotAfter))"
                        }
                        catch {
                            throw "Failed to load certificate: $($_.Exception.Message)"
                        }
                    }
                    else {
                        throw "No certificate specified. Use CertificateThumbprint, CertificateName, or CertificatePath"
                    }
                }
                
                'Interactive' {
                    Write-Verbose "Connecting interactively"
                    # Ensure scopes are a string array
                    $connectParams['Scopes'] = @($RequiredScopes)
                }
            }
            
            # Connect to Microsoft Graph
            try {
                Connect-MgGraph @connectParams -ErrorAction Stop
                Write-Verbose "Successfully connected to Microsoft Graph"
            }
            catch {
                throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
            }
            finally {
                # Clear sensitive credentials if used (PSCredential object)
                if ($connectParams.ContainsKey('ClientSecretCredential')) { 
                    $connectParams['ClientSecretCredential'] = $null 
                }
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
                    
                    Write-Verbose "Validated all required scopes: $($RequiredScopes -join ', ')"
                }
                catch {
                    throw "Failed to validate permissions: $($_.Exception.Message)"
                }
            }
            
            # Return account context
            $context = Get-MgContext
            $account = $context.Account
            Write-Verbose "Connected as: $account"
            return $account
        }
        catch {
            Write-Error "Connection failed: $($_.Exception.Message)"
            throw
        }
    }

    End {
        # End function and report memory usage 
        [double]$MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
        Write-Verbose "Function finished. Memory usage: $MemoryUsage MB"
    }
}
function Invoke-TboneLog { 
<#
.SYNOPSIS
    Unified tiny logger for PowerShell 5.1–7.5 and Azure Automation; overrides Write-* cmdlets and stores all messages in-memory
.DESCRIPTION
    A lightweight, cross-platform logging solution that intercepts all Write-Host, Write-Output, Write-Verbose, 
    Write-Warning, and Write-Error calls. Stores messages in memory with timestamps and can optionally output to:
    -LogToGUI - Console (real-time during execution) -LogToDisk - Disk (log file at script completion) -LogToEventlog - Windows Event Log (Application log)
.NOTES
    Author:  @MrTbone_se (T-bone Granheden)
    Version: 1.0
    
    Version History:
    1.0 - Initial version
#>
    [CmdletBinding()]
    param(
        [Parameter(                     HelpMessage='Start=Begin logging, Stop=End and output log array')]
        [ValidateSet('Start','Stop')]
        [string]$Mode,
        [Parameter(                     HelpMessage='Show output in console during execution')]
        [bool]$LogToGUI         =$true,
        [Parameter(                     HelpMessage='Write complete log array to Windows Event when script ends')]
        [bool]$LogToEventlog    =$true,
        [Parameter(                     HelpMessage='Return complete log array as Host output when script ends (Good for Intune Remediations)')]
        [bool]$LogToHost        =$false,
        [Parameter(                     HelpMessage='Write complete log array to Disk when script ends')]
        [bool]$LogToDisk        =$true,
        [Parameter(                     HelpMessage='Path where Disk logs are saved (if LogToDisk is enabled)')]
        [string]$LogPath        = "$env:TEMP"
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
function Invoke-MgGraphRequestSingle {
<#
.SYNOPSIS
    Makes a single Graph API call with Invoke-MgGraphRequest and support for filtering, property selection, and count queries.
.DESCRIPTION
    Makes Graph API calls using Invoke-MgGraphRequest but add automatic pagination, throttling handling, and exponential backoff retry logic.
    Supports filtering, property selection, and count queries. Returns all pages of results automatically.
.NOTES
    Author:  @MrTbone_se (T-bone Granheden)
    Version: 2.1
    
    Version History:
    1.0 - Initial version
    2.0 - Fixed some small bugs with throttling handling
    2.1 - Added more error handling for Post/Patch methods
#>
[CmdletBinding()]
    Param(
        [Parameter(                 HelpMessage = "The Graph API version ('beta' or 'v1.0')")]
        [ValidateSet('beta', 'v1.0')]
        [string]$GraphRunProfile     = "v1.0",
    
        [Parameter(                 HelpMessage = "The HTTP method for the request(e.g., 'GET', 'PATCH', 'POST', 'DELETE')")]
        [ValidateSet('GET', 'PATCH', 'POST', 'DELETE')]
        [String]$GraphMethod         = "GET",
        
        [Parameter(Mandatory=$true, HelpMessage = "The Graph API endpoint path to target (e.g., 'me', 'users', 'groups')")]
        [ValidateNotNullOrEmpty()]
        [string]$GraphObject,

        [Parameter(                 HelpMessage = "Request body for POST/PATCH operations")]
        [string[]]$GraphBody,
        
        [Parameter(                 HelpMessage = "Graph API properties to include")]
        [string[]]$GraphProperties,
    
        [Parameter(                 HelpMessage = "Graph API filters to apply")]
        [string]$GraphFilters,
    
        [Parameter(                 HelpMessage = "Page size (Default is the maximum 1000 objects per page)")]
        [ValidateRange(1,1000)]
        [int]$GraphPageSize          = 999,

        [Parameter(                 HelpMessage = "Skip pagination and only get the first page. (Default is false)")]
        [bool]$GraphSkipPagination   = $false,

        [Parameter(                 HelpMessage = "Include count of total items. Adds ConsistencyLevel header. (Default is false)")]
        [bool]$GraphCount            = $false,

        [Parameter(                 HelpMessage = "Delay in milliseconds between requests if throttled")]
        [ValidateRange(100,5000)]
        [int]$GraphWaitTime         = 1000,

        [Parameter(                 HelpMessage = "Maximum retry attempts for failed requests when throttled")]
        [ValidateRange(1,10)]
        [int]$GraphMaxRetry         = 3
    )

    Begin {
        # Initialize variables
        [nullable[int]]$TotalCount = $null
        [System.Collections.ArrayList]$PsobjectResults = [System.Collections.ArrayList]::new()
        [int]$RetryCount = 0
        [string]$uri = "https://graph.microsoft.com/$GraphRunProfile/$GraphObject"
        [System.Collections.ArrayList]$GraphQueryParams = [System.Collections.ArrayList]::new()

        # Add Count parameter to Query if requested
        if ($GraphCount) {[void]$GraphQueryParams.Add("`$count=true")}

        # Add page size parameter to Query if specified
        if ($GraphMethod -eq 'GET') {[void]$GraphQueryParams.Add("`$top=$GraphPageSize")}

        # Add properties to Query if specified
        if ($GraphProperties) {
            [string]$select = $GraphProperties -join ','
            [void]$GraphQueryParams.Add("`$select=$select")
        }

        # Add filters to Query if specified
        if ($GraphFilters) {
            [void]$GraphQueryParams.Add("`$filter=$([System.Web.HttpUtility]::UrlEncode($GraphFilters))")
        }

        # Combine query parameters into URI
        if ($GraphQueryParams.Count -gt 0) {$uri += "?" + ($GraphQueryParams -join '&')}
    }

    Process {
        do {
            try {
                Write-Verbose "Making request to: $uri"
                $i = 1
                do {
                    $response = $null
                    Write-Verbose "Requesting page $i with $GraphPageSize items"
                    # Set default parameters for Invoke-MgGraphRequest
                    $params = @{
                        Method      = $GraphMethod
                        Uri         = $uri
                        ErrorAction = 'Stop'
                        OutputType  = 'PSObject'
                        Verbose     = $false
                    }
                    # Add ConsistencyLevel header if Count is requested
                    if ($GraphCount) { $params['Headers'] = @{ 'ConsistencyLevel' = 'eventual' } }

                    # Add additional parameters based on method
                    if ($GraphMethod -in 'POST', 'PATCH') {
                        $params['Body'] = $GraphBody
                        if (-not $params.ContainsKey('Headers')) {
                            $params['Headers'] = @{}
                        }
                        $params['Headers']['Content-Type'] = 'application/json'
                        write-verbose "Request body: $($GraphBody | ConvertTo-Json -Depth 10)"
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
                        Write-Verbose "Request failed with error: $($_.Exception.Message)"
                        throw
                    }
                    if ($GraphMethod -in 'POST', 'PATCH', 'DELETE') {return $response}
                    if ($response.value) {[void]$PsobjectResults.AddRange($response.value)}
                    # Capture count from first response if requested
                    if ($GraphCount -and $null -eq $TotalCount -and $response.'@odata.count') {
                        $TotalCount = $response.'@odata.count'
                        Write-Verbose "Total count available: $TotalCount items"
                    }
                    Write-Verbose "Retrieved page $i, Now total: $($PsobjectResults.Count) items"

                    # Check for next page
                    if ($GraphSkipPagination) {
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
                if ($GraphCount -and $null -ne $TotalCount) {
                    return [PSCustomObject]@{
                        Items = $PsobjectResults
                        Count = $TotalCount
                    }
                }
                return $PsobjectResults # Success, return results and exit retry loop
            }
            catch {
                [string]$ErrorMessage = $_.Exception.Message
                # Get full error string including nested JSON messages for better pattern matching
                [string]$FullErrorString = $_ | Out-String
                Write-Warning "Request failed (Retry attempt $($RetryCount + 1)/$GraphMaxRetry): $ErrorMessage"

                # First check for throttling in error message (Invoke-MgGraphRequest may internally retry and throw with embedded 429 info)
                if ($ErrorMessage -match "TooManyRequests|Too Many Requests|429" -or $FullErrorString -match "TooManyRequests|Too Many Requests|429") {
                    # Throttling detected from error message - use exponential backoff
                    [int]$Delay = [math]::Min(($GraphWaitTime * ([math]::Pow(2, $RetryCount + 1))), 60000)
                    Write-Warning "Throttling detected from error message. Waiting $Delay milliseconds before retrying."
                    Start-Sleep -Milliseconds $Delay
                }
                # Check if the exception has response details (standard HTTP errors)
                elseif ($_.Exception.PSObject.Properties.Name -contains 'Response' -and $_.Exception.Response) {
                    [object]$StatusCode = $_.Exception.Response.StatusCode

                    # Use switch to handle specific status codes (handle both enum names and numeric values)
                    switch ($StatusCode) {
                        {$_ -eq 429 -or $_ -eq 'TooManyRequests'} { # Throttling
                            $RetryAfter = $_.Exception.Response.Headers["Retry-After"]
                            if ($RetryAfter) {
                                Write-Warning "Throttling detected (429). Waiting $($RetryAfter * 1000) milliseconds before retrying."
                                Start-Sleep -Milliseconds ($RetryAfter * 1000)
                            } else {
                                [int]$Delay = [math]::Min(($GraphWaitTime * ([math]::Pow(2, $RetryCount))), 60000)
                                Write-Warning "Throttling detected (429). No Retry-After header found. Waiting $Delay milliseconds before retrying."
                                Start-Sleep -Milliseconds $Delay
                            }
                            # Break not needed, will fall through to retry logic below
                        }
                        {$_ -eq 404 -or $_ -eq 'NotFound'} { # Not Found
                            # For DELETE operations, 404 means already deleted - treat as success
                            if ($GraphMethod -eq 'DELETE') {
                                Write-Verbose "Resource not found (404) - treating as already deleted"
                                return [PSCustomObject]@{ id = $GraphObject; status = 204; note = 'Already deleted' }
                            }
                            Write-Warning "Resource not found (404). Error: $ErrorMessage"
                            throw "$ErrorMessage (Object Deleted/No User License)"
                        }
                        {$_ -eq 400 -or $_ -eq 'BadRequest'} { # Bad Request                            
                            if ($ErrorMessage -match "Skip token.*expired|Skip token is null" -or $FullErrorString -match "Skip token.*expired|Skip token is null") {# Check if this is an expired skip token error
                                Write-Warning "Skip token has expired after collecting $($PsobjectResults.Count) items. Returning collected data."
                                return $PsobjectResults
                            }
                            if ($ErrorMessage -match "does not have intune license or is deleted" -or $FullErrorString -match "does not have intune license or is deleted") { # Check if no license, common for Intune queries
                                Write-Warning "Object Deleted or User has no Intune license"
                                return "$ErrorMessage (Object Deleted/No User License)"
                            }
                            # For DELETE operations, "not found" patterns mean already removed - treat as success
                            if ($GraphMethod -eq 'DELETE' -and ($ErrorMessage -imatch 'does not exist|not found|cannot be found|no longer exists|was not found|resource .+ not found' -or $FullErrorString -imatch 'does not exist|not found|cannot be found|no longer exists')) {
                                Write-Verbose "Object already removed or not found (400) - treating as success"
                                return [PSCustomObject]@{ id = $GraphObject; status = 204; note = 'Already removed' }
                            }
                            # For POST operations, "already exists" patterns mean already created - treat as success
                            if ($GraphMethod -eq 'POST' -and ($ErrorMessage -imatch 'already exist|duplicate|conflict|references already exist|object reference already exist' -or $FullErrorString -imatch 'already exist|duplicate|conflict')) {
                                Write-Verbose "Object already exists (400) - treating as success"
                                return [PSCustomObject]@{ id = $GraphObject; status = 200; note = 'Already exists' }
                            }
                            Write-Error "Bad request (400). Error: $ErrorMessage"
                            throw $_
                        }
                        {$_ -eq 403 -or $_ -eq 'Forbidden'} { # Forbidden / Access Denied
                             Write-Error "Access denied (403). Error: $ErrorMessage"
                             throw $_
                        }
                        default { # Other HTTP errors - Use generic retry
                            [int]$Delay = [math]::Min(($GraphWaitTime * ([math]::Pow(2, $RetryCount))), 60000)
                            Write-Warning "HTTP error $StatusCode. Waiting $Delay milliseconds before retrying."
                            Start-Sleep -Milliseconds $Delay
                            # Break not needed, will fall through to retry logic below
                        }
                    }
                } else {
                    # Non-HTTP errors (e.g., network issues, DNS resolution) - Use generic retry
                    [int]$Delay = [math]::Min(($GraphWaitTime * ([math]::Pow(2, $RetryCount))), 60000)
                    Write-Warning "Non-HTTP error. Waiting $Delay milliseconds before retrying. Error: $ErrorMessage"
                    Start-Sleep -Milliseconds $Delay
                }

                # Increment retry count and check if max retries exceeded ONLY if not already thrown
                $RetryCount++
                if ($RetryCount -gt $GraphMaxRetry) {
                     Write-Error "Request failed after $($GraphMaxRetry) retries. Aborting."
                     throw "Request failed after $($GraphMaxRetry) retries. Last error: $ErrorMessage"
                }
                # If retries not exceeded and error was potentially retryable (e.g., 429, other HTTP, non-HTTP), the loop will continue
            }
        } while ($RetryCount -le $GraphMaxRetry)

        Write-Error "Request failed after $($GraphMaxRetry) retries. Aborting."
        throw "Request failed after $($GraphMaxRetry) retries." # Re-throw the exception after max retries
    }

    End {
        # End function and report memory usage 
        [double]$MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
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
.NOTES
    Author:  @MrTbone_se (T-bone Granheden)
    Version: 1.3
    
    Version History:
    1.0 - Initial version
    1.1 - Added version on function to keep track of changes, minor bug fixes
    1.2 - Added more error handling for Post/Patch methods
    1.3 - Added a new parameter GraphNoObjectIdInUrl to allow requests where objectId should not be appended to the URL
#>
    [CmdletBinding()]
    Param(
        [Parameter(
            HelpMessage = "The Graph API version ('beta' or 'v1.0')")]
        [ValidateSet('beta', 'v1.0')]
        [string]$GraphRunProfile = "v1.0",
    
        [Parameter(
            HelpMessage = "The HTTP method for the request(e.g., 'GET', 'PATCH', 'POST', 'DELETE')")]
        [ValidateSet('GET', 'PATCH', 'POST', 'DELETE')]
        [String]$GraphMethod = "GET",
        
        [Parameter(
            HelpMessage = "The Graph API endpoint path to target (e.g., 'me', 'users', 'groups')")]
        [string]$GraphObject,
    
        [Parameter(
            HelpMessage = "Array of objects to process in batches")]
        [System.Object[]]$GraphObjects,

        [Parameter(HelpMessage = "Do not append objectId to the request URL (useful for endpoints like POST groups/id/members)")]
        [bool]$GraphNoObjectIdInUrl = $false,
    
        [Parameter(
            HelpMessage = "The Graph API query on the objects")]
        [string]$GraphQuery,
    
        [Parameter(HelpMessage = "Request body for POST/PATCH operations")]
        [object]$GraphBody,
        
        [Parameter(HelpMessage = "Graph API properties to include")]
        [string[]]$GraphProperties,
    
        [Parameter(HelpMessage = "Graph API filters to apply")]
        [string]$GraphFilters,
    
        [Parameter(HelpMessage = "Batch size (max 20 objects per batch)")]
        [ValidateRange(1,20)]
        [int]$GraphBatchSize = 20,
    
        [Parameter(HelpMessage = "Delay between batches in milliseconds")]
        [ValidateRange(100,5000)]
        [int]$GraphWaitTime = 1000,
    
        [Parameter(HelpMessage = "Maximum retry attempts for failed requests")]
        [ValidateRange(1,10)]
        [int]$GraphMaxRetry = 3
    )
    
    Begin {
        $ErrorActionPreference = 'Stop'
        [scriptblock]$script:GetTimestamp = { ([DateTime]::Now).ToString('yyyy-MM-dd HH:mm:ss') }
        [datetime]$starttime = Get-Date
        [int]$Retrycount = 0
        [int]$TotalObjects = $GraphObjects.Count
        
        # Pre-allocate collections with capacity for better performance
        [System.Collections.Generic.List[PSObject]]$CollectedObjects = [System.Collections.Generic.List[PSObject]]::new($TotalObjects)
        [System.Collections.Generic.List[PSObject]]$RetryObjects = [System.Collections.Generic.List[PSObject]]::new()
        
        # Check execution context once
        [bool]$ManagedIdentity = [bool]$env:AUTOMATION_ASSET_ACCOUNTID
        Write-Verbose "Running in $(if ($ManagedIdentity) { 'Azure Automation' } else { 'interactive PowerShell' }) context"
        
        # Pre-calculate common values to avoid repeated work
        [string]$batchUri = "https://graph.microsoft.com/$GraphRunProfile/`$batch"
        [hashtable]$batchHeaders = @{'Content-Type' = 'application/json'}
        
        # Build URL query parameters once (they're the same for all requests)
        [string]$urlQueryString = $null
        if ($GraphProperties -or $GraphFilters) {
            [System.Collections.Generic.List[string]]$urlParams = [System.Collections.Generic.List[string]]::new()
            if ($GraphProperties) {
                $urlParams.Add("`$select=$($GraphProperties -join ',')")
            }
            if ($GraphFilters) {
                $urlParams.Add("`$filter=$([System.Web.HttpUtility]::UrlEncode($GraphFilters))")
            }
            $urlQueryString = "?" + ($urlParams -join '&')
        }
        
        # Pre-determine if method needs body/headers (avoid repeated checks)
        [bool]$needsBody = $GraphMethod -in 'PATCH','POST'
        [string]$contentTypeHeader = if ($needsBody) { 'application/json' } else { $null }
        
        Write-Verbose "Graph batch processing initialized for $TotalObjects objects"
    }
    
    Process {
        try {
            do {
                [int]$currentObject = 0
                $RetryObjects.Clear()
                
                # Process objects in batches
                for($i = 0; $i -lt $GraphObjects.Count; $i += $GraphBatchSize) {
                    # Calculate batch boundaries
                    [int]$batchEnd = [Math]::Min($i + $GraphBatchSize, $GraphObjects.Count)
                    [int]$batchCount = $batchEnd - $i
                    
                    # Pre-allocate request array with exact size
                    [System.Collections.ArrayList]$req = [System.Collections.ArrayList]::new($batchCount)
                    
                    # Build batch requests (optimized loop)
                    for ($j = $i; $j -lt $batchEnd; $j++) {
                        [object]$obj = $GraphObjects[$j]
                        [string]$url = if ($GraphNoObjectIdInUrl) { "/$GraphObject$GraphQuery" } else { "/$GraphObject/$($obj.id)$GraphQuery" }
                        if ($urlQueryString) { $url += $urlQueryString }
                        
                        # Use object's body if available, otherwise use the global Body parameter
                        [object]$requestBody = if ($obj.PSObject.Properties.Name -contains 'body' -and $obj.body) {
                            $obj.body
                        } elseif ($needsBody) {
                            $GraphBody
                        } else {
                            $null
                        }
                        
                        [void]$req.Add(@{
                            'id' = $obj.id
                            'method' = $GraphMethod
                            'url' = $url
                            'body' = $requestBody
                            'headers' = @{ 'Content-Type' = $contentTypeHeader }
                        })
                    }
                    
                    Write-Verbose "Sending batch $([Math]::Floor($i/$GraphBatchSize) + 1): items $($i+1) to $batchEnd of $($GraphObjects.Count)"
                    
                    # Send batch request
                    try {
                        [string]$batchBody = @{'requests' = $req} | ConvertTo-Json -Depth 10 -Compress
                        [object]$responses = Invoke-MgGraphRequest -Method POST -Uri $batchUri -Body $batchBody -Headers $batchHeaders -Verbose:$false
                        Write-Verbose "Batch request successful with $($req.Count) requests"
                    }
                    catch {
                        Write-Error "Failed to send batch request: $($_.Exception.Message)"
                        throw
                    }
                    
                    # Process responses (optimized with direct property access)
                    [int]$throttledCount = 0
                    foreach ($response in $responses.responses) {
                        $currentObject++
                        
                        # Handle response by status code
                        switch ($response.status) {
                            {$_ -in 200,201,204} { # Success cases
                                # Extract the actual device object from response.body
                                if ($response.body) {
                                    # Convert hashtable to PSCustomObject if needed
                                    [object]$GraphBodyObject = if ($response.body -is [hashtable]) {
                                        [PSCustomObject]$response.body
                                    } else {
                                        $response.body
                                    }
                                    [void]$CollectedObjects.Add($GraphBodyObject)
                                    Write-Verbose "Success ($($response.status)) for request $($response.id) with body"
                                } else {
                                    # For 204 No Content (PATCH/DELETE), return a success indicator with the request ID
                                    [PSCustomObject]$successObject = [PSCustomObject]@{
                                        id = $response.id
                                        status = $response.status
                                    }
                                    [void]$CollectedObjects.Add($successObject)
                                    Write-Verbose "Success ($($response.status)) for request $($response.id) - no body returned"
                                }
                            }
                            400 { # Bad request - check error details for expected failures
                                # Extract error message from response body
                                [string]$errorCode = $null
                                [string]$errorMessage = $null
                                if ($response.body -and $response.body.error) {
                                    $errorCode = $response.body.error.code
                                    $errorMessage = $response.body.error.message
                                }
                                
                                # For DELETE operations, common "not found" patterns mean already removed - treat as success
                                if ($GraphMethod -eq 'DELETE' -and ($errorMessage -imatch 'does not exist|not found|cannot be found|no longer exists|was not found|resource .+ not found')) {
                                    Write-Verbose "Object $($response.id) already removed or not found (400: $errorCode)"
                                    [PSCustomObject]$successObject = [PSCustomObject]@{
                                        id = $response.id
                                        status = 204  # Treat as successful removal
                                        note = 'Already removed'
                                    }
                                    [void]$CollectedObjects.Add($successObject)
                                }
                                # For POST operations, "already exists" patterns mean already created - treat as success
                                elseif ($GraphMethod -eq 'POST' -and ($errorMessage -imatch 'already exist|duplicate|conflict|references already exist|object reference already exist')) {
                                    Write-Verbose "Object $($response.id) already exists (400: $errorCode)"
                                    [PSCustomObject]$successObject = [PSCustomObject]@{
                                        id = $response.id
                                        status = 200  # Treat as successful (already exists)
                                        note = 'Already exists'
                                    }
                                    [void]$CollectedObjects.Add($successObject)
                                }
                                else {
                                    # Unexpected 400 error - log and add to retry
                                    Write-Error "Bad request (400) for object $($response.id): $errorCode - $errorMessage"
                                    [void]$RetryObjects.Add($response)
                                }
                            }
                            403 { # Access denied - don't retry
                                Write-Error "Access denied (403) for object $($response.id) - Check permissions"
                            }
                            404 { # Not found - for DELETE treat as success, for others log warning
                                if ($GraphMethod -eq 'DELETE') {
                                    Write-Verbose "Object $($response.id) not found (404) - treating as already removed"
                                    [PSCustomObject]$successObject = [PSCustomObject]@{
                                        id = $response.id
                                        status = 204
                                        note = 'Not found - already removed'
                                    }
                                    [void]$CollectedObjects.Add($successObject)
                                } else {
                                    Write-Warning "Resource not found (404) for object $($response.id)"
                                }
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
                        [double]$percentComplete = ($currentObject / $TotalObjects) * 100
                        [timespan]$elapsed = (Get-Date) - $starttime
                        [timespan]$timeLeft = if ($currentObject -gt 0) {
                            [TimeSpan]::FromMilliseconds(($elapsed.TotalMilliseconds / $currentObject) * ($TotalObjects - $currentObject))
                        } else { [TimeSpan]::Zero }
                        
                        Write-Progress -Activity "Processing Graph Batch Requests" `
                            -Status "Progress: $currentObject/$TotalObjects | Estimated Time Left: $($timeLeft.ToString('hh\:mm\:ss')) | Throttled: $throttledCount | Retry: $Retrycount/$GraphMaxRetry" `
                            -PercentComplete $percentComplete
                    }
                    
                    # Handle throttling with exponential backoff (only if throttled responses exist)
                    if ($throttledCount -gt 0) {
                        # Extract retry-after values efficiently
                        [array]$retryAfterValues = @($RetryObjects | 
                            Where-Object { $_.status -eq 429 -and $_.headers.'retry-after' } | 
                            Select-Object -ExpandProperty headers | 
                            Select-Object -ExpandProperty 'retry-after')
                        
                        [int]$waitSeconds = if ($retryAfterValues -and $retryAfterValues.Count -gt 0) {
                            [Math]::Min(($retryAfterValues | Measure-Object -Maximum).Maximum + ($Retrycount * 2), 30)
                        } else {
                            [Math]::Min(1 + ($Retrycount * 2), 30)
                        }
                        
                        Write-Warning "Throttling detected, waiting $waitSeconds seconds (Retry: $Retrycount)"
                        Start-Sleep -Seconds $waitSeconds
                    }
                }
                
                # Prepare for retry if needed
                if ($RetryObjects.Count -gt 0 -and $Retrycount -lt $GraphMaxRetry) {
                    $Retrycount++
                    Write-Verbose "Starting retry $Retrycount with $($RetryObjects.Count) objects"
                    
                    # Create lookup hashtable for faster filtering
                    [hashtable]$retryIdHash = @{}
                    foreach ($r in $RetryObjects) { $retryIdHash[$r.id] = $true }
                    
                    # Filter objects to retry
                    $Objects = $Objects | Where-Object { $retryIdHash.ContainsKey($_.id) }
                }
                
            } while ($RetryObjects.Count -gt 0 -and $Retrycount -lt $GraphMaxRetry)
            
            # Clear progress bar if used
            if (-not $ManagedIdentity) {
                Write-Progress -Activity "Processing Graph Batch Requests" -Completed
            }
            
            Write-Verbose "Successfully processed $($CollectedObjects.Count) of $TotalObjects objects"
            return $CollectedObjects
        }
        catch {
            Write-Error "Function failed in main process block: $($_.Exception.Message)"
            throw
        }
    }
    
    End {
        # Report memory usage
        [double]$MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
        [timespan]$duration = (Get-Date) - $starttime
        Write-Verbose "Function $($MyInvocation.MyCommand.Name) finished in $($duration.ToString('mm\:ss')) | Memory: $MemoryUsage MB"
    }
}
function Convert-PSObjectArrayToHashTables {
<#
.SYNOPSIS
    Converts PSObject arrays to optimized hashtables for fast O(1) lookups.
.DESCRIPTION
    Creates Generic.Dictionary hashtables from PSObject arrays using specified properties as keys.
    Returns single or multiple hashtables indexed by property values for efficient data retrieval.
.NOTES
    Author:  @MrTbone_se (T-bone Granheden)
    Version: 1.2
    
    Version History:
    1.0 - Initial version
    1.1 - Removed pipeline support, optimized property checks, added capacity pre-allocation
    1.2 - Added StringComparer.OrdinalIgnoreCase for correct UPN/ID lookups and improved error handling
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,  HelpMessage = "Array of PSObjects to convert to hashtables")]
        [PSObject[]]$PSObjectArray,

        [Parameter(Mandatory = $true,  HelpMessage = "Property names to use as keys for hashtables")]
        [string[]]$IdProperties
    )

    Begin {
        $ErrorActionPreference = 'Stop'
        Write-Verbose "Starting conversion of $($PSObjectArray.Count) objects using $($IdProperties.Count) index propert$(if($IdProperties.Count -eq 1){'y'}else{'ies'})"
        
        # Validate inputs
        try {
            if ($null -eq $PSObjectArray -or $PSObjectArray.Count -eq 0) {
                throw "PSObjectArray is null or empty"
            }
            if ($null -eq $IdProperties -or $IdProperties.Count -eq 0) {
                throw "IdProperties is null or empty"
            }
        }
        catch {
            Write-Error "Input validation failed: $($_.Exception.Message)"
            throw
        }
    }

    Process {
        try {
            # Pre-calculate capacity for better memory allocation
            [int]$capacity = $PSObjectArray.Count

            # Single index requested (most common)
            if ($IdProperties.Count -eq 1) {
                try {
                    [string]$IdProperty = $IdProperties[0]
                    [System.Collections.Generic.Dictionary[string,object]]$HashTable = [System.Collections.Generic.Dictionary[string,object]]::new($capacity, [System.StringComparer]::OrdinalIgnoreCase)

                    foreach ($PSObject in $PSObjectArray) {
                        try {
                            [object]$IdValue = $PSObject.$IdProperty
                            if ($null -eq $IdValue) { continue }

                            # Convert to string for dictionary key (handles int/guid IDs etc)
                            [string]$key = $IdValue.ToString()
                            if ($key.Length -eq 0) { continue }

                            # Add to hashtable (overwrite if duplicate key exists)
                            $HashTable[$key] = $PSObject
                        }
                        catch {
                            Write-Warning "Failed to process object for property '$IdProperty': $($_.Exception.Message)"
                            continue
                        }
                    }

                    Write-Verbose "Converted $($HashTable.Count) objects to hashtable using property '$IdProperty'"
                    return $HashTable
                }
                catch {
                    Write-Error "Failed to create single-index hashtable for property '$IdProperty': $($_.Exception.Message)"
                    throw
                }
            }

            # Create hashtable collections for multiple indexes
            try {
                [hashtable]$HashTables = [hashtable]::new($IdProperties.Count)
                foreach ($prop in $IdProperties) {
                    try {
                        $HashTables[$prop] = [System.Collections.Generic.Dictionary[string,object]]::new($capacity, [System.StringComparer]::OrdinalIgnoreCase)
                    }
                    catch {
                        Write-Error "Failed to create dictionary for property '$prop': $($_.Exception.Message)"
                        throw
                    }
                }
            }
            catch {
                Write-Error "Failed to initialize hashtable collection: $($_.Exception.Message)"
                throw
            }

            # Process all objects and populate hashtables
            foreach ($PSObject in $PSObjectArray) {
                foreach ($IdProperty in $IdProperties) {
                    try {
                        $IdValue = $PSObject.$IdProperty
                        if ($null -eq $IdValue) { continue }

                        $key = $IdValue.ToString()
                        if ($key.Length -eq 0) { continue }

                        $HashTables[$IdProperty][$key] = $PSObject
                    }
                    catch {
                        Write-Warning "Failed to process object for property '$IdProperty': $($_.Exception.Message)"
                        continue
                    }
                }
            }
            # Log conversion summary
            foreach ($prop in $IdProperties) {
                Write-Verbose "Converted $($HashTables[$prop].Count) objects to hashtable using property '$prop'"
            }
            return $HashTables
        }
        catch {
            Write-Error "Failed to convert objects to hashtables: $($_.Exception.Message)"
            throw
        }
    }

    End {
        # End function and report memory usage 
        [double]$MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
        Write-Verbose "Function finished. Memory usage: $MemoryUsage MB"
    }
}
function Invoke-ScriptReport {
<#
.SYNOPSIS
    A reporting function with dynamic action tracking that generates a summary and detailed report.
.DESCRIPTION
    Generates comprehensive reports with dynamic action counters. Tracks Target, OldValue, NewValue, 
    and Action for each processed object. Compatible with PS 5.1-7.5 and Azure Automation.
    Initialize hashtable and a small helper inline function for reporting function (invoke-scriptreport)
        [hashtable]$ReportResults = @{}
        [scriptblock]$addReport = {param($Target,$OldValue,$NewValue,$Action,$Details)
            if(-not $ReportResults.ContainsKey($Action)){$ReportResults[$Action]=[System.Collections.ArrayList]::new()}
            $null=$ReportResults[$Action].Add([PSCustomObject]@{Target=$Target;OldValue=$OldValue;NewValue=$NewValue;Action=$Action;Details=$Details})}
    Then use this to log report actions during processing:
        & $addReport -Target "Device001" -OldValue "Enabled" -NewValue "Disabled" -Action "Disabled" -Details "Optional info"
.NOTES
    Author:  @MrTbone_se (T-bone Granheden)
    Version: 2.0
    
    Version History:
    1.0 - Initial version
    2.0 - Added dynamic reporting object with dynamic action counters
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false,                  HelpMessage = "Description of the action performed by the script")]
        [string]$ScriptAction           = "Script Execution",
        
        [Parameter(Mandatory = $true,                   HelpMessage = "Hashtable of ArrayLists grouped by Action containing report entries")]
        [hashtable]$ReportResults,
        
        [Parameter(Mandatory = $true,                   HelpMessage = "Start time of the report execution")]
        [datetime]$ReportStartTime,

        [Parameter(Mandatory = $false,                  HelpMessage = "Include detailed per-object results in console output")]
        [bool]$ReportDetailed           = $false,

        [Parameter(Mandatory = $false,                  HelpMessage = "Save report to disk in JSON/CSV format")]
        [bool]$ReportToDisk             = $false,

        [Parameter(Mandatory = $false,                  HelpMessage = "Directory path where report files will be saved")]
        [ValidateScript({Test-Path $_ -IsValid})]
        [string]$ReportToDiskPath       = "$env:TEMP\Reports",
        
        [Parameter(Mandatory = $false,                  HelpMessage = "Format for report export (JSON or CSV)")]
        [ValidateSet('JSON', 'CSV')]
        [string]$ReportFormat           = 'CSV'
    )

    Begin {
        Write-Verbose "Starting report generation"
        [datetime]$reportEndTime = [DateTime]::Now
    }

    Process {
        try {
            # Calculate duration
            [timespan]$duration = $reportEndTime - $ReportStartTime
            [string]$durationFormatted = $duration.ToString("hh\:mm\:ss")
            
            # Cache sorted action keys
            [array]$sortedActions = @($ReportResults.Keys | Sort-Object)
            
            # Build action summary and count total objects
            [int]$totalObjects = 0
            [System.Collections.Specialized.OrderedDictionary]$actionSummary = [ordered]@{}
            foreach ($action in $sortedActions) {
                [int]$count = $ReportResults[$action].Count
                $actionSummary[$action] = $count
                $totalObjects += $count
            }
            # Output detailed report if requested
            if ($ReportDetailed -and $totalObjects -gt 0) {
                # Flatten all entries from all action groups into a single array
                [System.Collections.ArrayList]$allEntries = [System.Collections.ArrayList]::new($totalObjects)
                foreach ($action in $sortedActions) {
                    [void]$allEntries.AddRange(@($ReportResults[$action]))
                }
                # Sort entries and output each line to avoid truncation
                [array]$sortedEntries = @($allEntries | Sort-Object -Property Action, Target)
                [object]$tableOutput = $sortedEntries | Format-Table -Property `
                    @{Name='Target';Expression={$_.Target};Alignment='Left'},
                    @{Name='OldValue';Expression={$_.OldValue};Alignment='Left'},
                    @{Name='NewValue';Expression={$_.NewValue};Alignment='Left'},
                    @{Name='Action';Expression={$_.Action};Alignment='Left'},
                    @{Name='Details';Expression={$_.Details};Alignment='Left'} -AutoSize -Wrap
                # Use Out-String with -Stream to output each line separately (no truncation)
                $tableOutput | Out-String -Stream -Width 250 | ForEach-Object { Write-Output $_ }
            }
            #Output summary report
            Write-Output "═══════════════════════════════════════════════════════════"
            Write-Output "  $ScriptAction"
            Write-Output "═══════════════════════════════════════════════════════════"
            Write-Output "  Start:    $($ReportStartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
            Write-Output "  End:      $($reportEndTime.ToString('yyyy-MM-dd HH:mm:ss'))"
            Write-Output "  Duration: $durationFormatted"
            Write-Output "───────────────────────────────────────────────────────────"
            Write-Output "  Summary"
            
            # Display actions breakdown dynamically and their percentages
            if ($actionSummary.Count -gt 0) {
                if ($totalObjects -gt 0) {
                    foreach ($action in $actionSummary.Keys) {
                        [int]$count = $actionSummary[$action]
                        [double]$percentage = [math]::Round(($count / $totalObjects) * 100, 1)
                        Write-Output ("    {0,-30}: {1,6} ({2,5}%)" -f $action, $count, $percentage)
                    }
                } else {
                    foreach ($action in $actionSummary.Keys) {
                        Write-Output ("    {0,-20}: {1,6} (  0.0%)" -f $action, $actionSummary[$action])
                    }
                }
            }
            Write-Output ("    {0,-30}: {1,6}" -f "Total Objects", $totalObjects)
            Write-Output "═══════════════════════════════════════════════════════════"

            if ($ReportToDisk) {
                # Ensure directory exists or create it
                if (-not (Test-Path $ReportToDiskPath)) {
                    try {New-Item -ItemType Directory -Path $ReportToDiskPath -Force -ErrorAction Stop | Out-Null}
                    catch {
                        Write-Warning "Failed to create report directory '$ReportToDiskPath': $($_.Exception.Message)"
                        Write-Warning "Report will not be saved to disk."
                        return
                    }
                }
                # Build base filename
                [string]$timestamp = $reportEndTime.ToString('yyyyMMdd_HHmmss')
                [string]$cleanAction = $ScriptAction -replace '[^\w\-]', '_'
                [string]$baseFileName = "Report_$($cleanAction)_$timestamp"
                
                # Save report based on format parameter
                if ($ReportFormat -eq 'JSON') {
                    # Flatten results for JSON export
                    $allResults = [System.Collections.ArrayList]::new()
                    foreach ($list in $ReportResults.Values) {
                        [void]$allResults.AddRange($list)
                    }
                    
                    # Build report object
                    $reportData = [PSCustomObject]@{
                        ScriptAction    = $ScriptAction
                        StartTime       = $ReportStartTime.ToString('yyyy-MM-dd HH:mm:ss')
                        EndTime         = $reportEndTime.ToString('yyyy-MM-dd HH:mm:ss')
                        Duration        = $durationFormatted
                        TotalProcessed  = $totalObjects
                        ActionSummary   = $actionSummary
                        DetailedResults = $allResults
                    }
                    
                    # Save as JSON
                    try {
                        $ReportToDiskPath = Join-Path $ReportToDiskPath "$baseFileName.json"
                        $reportData | ConvertTo-Json -Depth 10 -Compress:$false | Out-File -FilePath $ReportToDiskPath -Force -Encoding utf8 -ErrorAction Stop
                        Write-Output "Report saved: $ReportToDiskPath"
                    }
                    catch {
                        Write-Warning "Failed to save JSON report: $($_.Exception.Message)"
                    }
                }
                else {
                    # Save as CSV
                    if ($ReportResults.Count -gt 0) {
                        # Flatten results for CSV export
                        $allResults = [System.Collections.ArrayList]::new()
                        foreach ($list in $ReportResults.Values) {
                            [void]$allResults.AddRange($list)
                        }
                        
                        try {
                            $ReportToDiskPath = Join-Path $ReportToDiskPath "$baseFileName.csv"
                            $allResults | Export-Csv -Path $ReportToDiskPath -NoTypeInformation -Force -Encoding UTF8 -ErrorAction Stop
                            Write-Output "Report saved: $ReportToDiskPath"
                        }
                        catch {
                            Write-Warning "Failed to save CSV report: $($_.Exception.Message)"
                        }
                    }
                    else {
                        Write-Warning "No results to save in CSV format."
                    }
                }
            }
            Write-Verbose "Report completed successfully"
        }
        catch {
            Write-Error "Failed to generate report: $($_.Exception.Message)"
            throw
        }
    }

    End {
        # End function and report memory usage 
        [double]$MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
        Write-Verbose "Function finished. Memory usage: $MemoryUsage MB"
    }
}
#endregion

#region ---------------------------------------------------[[Script Execution]------------------------------------------------------
# Start T-Bone custom logging (can be removed if you don't want to use T-Bone logging)
Invoke-TboneLog -Mode Start -LogToGUI $LogToGUI -LogToEventlog $LogToEventlog -LogToDisk $LogToDisk -LogPath $LogToDiskPath -LogToHost $LogToHost

try {
    #Sign in to Graph
    try {
        # Build authentication parameters to pass only non-empty values. If no values are provided, default interactive auth or managed identity auth will be used.
        [hashtable]$authParams = @{}
        @{AuthTenantId = $AuthTenantId; AuthClientId = $AuthClientId; AuthCertThumbprint = $AuthCertThumbprint; AuthCertName = $AuthCertName; AuthCertPath = $AuthCertPath}.GetEnumerator() `
            | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Value) } `
            | ForEach-Object { $authParams[$_.Key] = $_.Value }
        # Add SecureString parameters that require different null checks
        if ($AuthClientSecret -and $AuthClientSecret.Length -gt 0) { $authParams['AuthClientSecret'] = $AuthClientSecret }
        if ($AuthCertPassword -and $AuthCertPassword.Length -gt 0) { $authParams['AuthCertPassword'] = $AuthCertPassword }
        # Invoke connection to Microsoft Graph with specified authentication parameters
        Invoke-ConnectMgGraph @authParams -RequiredScopes $RequiredScopes
        Write-Verbose "Success to get Access Token to Graph"
    }
    catch {
        Write-Error "Failed to get Access Token to Graph: $($_.Exception.Message)"
        throw
    }

    # Get all devices
    try {
        # List properties to retrieve
        [string]$GraphProperties = 'id,deviceName,operatingSystem,AzureAdDeviceId,userId'
        # Prepare filters
        [string]$GraphFilterString = $null
        # Add filter for Operating Systems
        if ($OperatingSystems -notcontains 'All' -and $OperatingSystems.Count -gt 0) {
            [array]$osFilterParts = $OperatingSystems | ForEach-Object { "operatingSystem eq '$_'" }
            $GraphFilterString = "($($osFilterParts -join ' or '))"
            Write-Verbose "Using OS filter: $GraphFilterString"
        }
        else {Write-Verbose "No OS filter applied (retrieving all operating systems)"}
        # Add filter for Intune managed devices or also include co-managed environment
        if ($IntuneOnly) {
            if ($GraphFilterString) {$GraphFilterString = "managementAgent eq 'mdm' and " + $GraphFilterString}
            else {$GraphFilterString = "managementAgent eq 'mdm' "}
        }
        else {Write-Verbose "No management agent filter applied"}
        # Get graph objects with single call
        $AllDevices = Invoke-MgGraphRequestSingle `
            -GraphRunProfile 'beta' `
            -GraphMethod 'GET' `
            -GraphObject 'deviceManagement/managedDevices' `
            -GraphProperties $GraphProperties `
            -GraphFilters $GraphFilterString `
            -GraphMaxRetry $GraphMaxRetry `
            -GraphWaitTime $GraphWaitTime

        # Verify if objects were found   
        if ($AllDevices -and $AllDevices.Count -gt 0) {
            Write-Verbose "Retrieved $($AllDevices.Count) devices from Graph API"
            
            # Apply client-side name filters
            if (($IncludedDeviceNames -and $IncludedDeviceNames.Count -gt 0) -or ($ExcludedDeviceNames -and $ExcludedDeviceNames.Count -gt 0)) {
                [string]$includePattern = if ($IncludedDeviceNames -and $IncludedDeviceNames.Count -gt 0) {
                    '^(' + (($IncludedDeviceNames | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')'
                } else { $null }
                [string]$excludePattern = if ($ExcludedDeviceNames -and $ExcludedDeviceNames.Count -gt 0) {
                    '^(' + (($ExcludedDeviceNames | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')'
                } else { $null }
                $AllDevices = $AllDevices | Where-Object {
                    $includeMatch = if ($includePattern) { $_.deviceName -imatch $includePattern } else { $true }
                    $excludeMatch = if ($excludePattern) { $_.deviceName -notmatch $excludePattern } else { $true }
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
        Write-Error "Failed to get devices: $($_.Exception.Message)"
        throw
    }

    # Get all users from Graph
    try {
        # List properties to retrieve
        [string]$GraphProperties = "id,userPrincipalName,$MappingAttribute"
        # Prepare filters
        [string]$GraphFilterString = $null
        # Get graph objects with single call
        $AllUsers = Invoke-MgGraphRequestSingle `
            -GraphRunProfile 'v1.0' `
            -GraphMethod 'GET' `
            -GraphObject 'users' `
            -GraphProperties $GraphProperties `
            -GraphFilters $GraphFilterString `
            -GraphMaxRetry $GraphMaxRetry `
            -GraphWaitTime $GraphWaitTime

        # Initialize hashtables
        $AllUsersByIdHash = [System.Collections.Generic.Dictionary[string,object]]::new(0, [System.StringComparer]::OrdinalIgnoreCase)
        $AllUsersByUPNHash = [System.Collections.Generic.Dictionary[string,object]]::new(0, [System.StringComparer]::OrdinalIgnoreCase)
        # Verify if objects were found
        if ($AllUsers -and $AllUsers.Count -gt 0) {
            Write-Verbose "Successfully retrieved $($AllUsers.Count) users from Graph API"
            # Create hashtable for fast lookups
            $AllUserHashTables = Convert-PSObjectArrayToHashTables -PSObjectArray $AllUsers -IdProperties @('id', 'userPrincipalName')
            $AllUsersByIdHash = $AllUserHashTables['id']
            $AllUsersByUPNHash = $AllUserHashTables['userPrincipalName']
            Write-Verbose "Created user lookup hashtables: ID=$($AllUsersByIdHash.Count) entries, UPN=$($AllUsersByUPNHash.Count) entries"
        }
        else {Write-Warning "No users found in tenant"}
    }
    catch {
        Write-Error "Failed to get users: $($_.Exception.Message)"
        throw
    }

    # Get all devices one by one in batch to get their scope tags
    try {
        # List properties to retrieve
        [string]$GraphProperties = 'id,deviceName,operatingSystem,AzureAdDeviceId,userId,roleScopeTagIds'
        # Prepare filters
        [string]$GraphFilterString = $null
        # Get graph objects using batch
        $AllDevicesWithTags = invoke-mggraphrequestbatch `
            -GraphRunProfile 'beta' `
            -GraphMethod 'GET' `
            -GraphObject 'deviceManagement/managedDevices' `
            -GraphObjects $AllDevices `
            -GraphQuery  ''`
            -GraphProperties $GraphProperties `
            -GraphFilters $GraphFilterString `
            -GraphBatchSize $GraphBatchSize `
            -GraphWaitTime $GraphWaitTime `
            -GraphMaxRetry $GraphMaxRetry 

        # Initialize hashtables
        $AllDevicesWithTagsByDeviceIdHash = [System.Collections.Generic.Dictionary[string,object]]::new(0, [System.StringComparer]::OrdinalIgnoreCase)
        $AllDevicesWithTagsByUserIdHash = [System.Collections.Generic.Dictionary[string,object]]::new(0, [System.StringComparer]::OrdinalIgnoreCase)
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
        Write-Error "Failed to get devices and their scope tags: $($_.Exception.Message)"
        throw
    }
    # Cleanup unused variable to save memory
    Remove-Variable -Name AllDevices

    # Get all scope tags 
    try {
        # List properties to retrieve
        [string]$GraphProperties = 'id,displayName,description,isBuiltIn'
        # Prepare filters
        [string]$GraphFilterString = $null
        # Get graph objects
        $AllScopeTags = Invoke-MgGraphRequestSingle `
            -GraphRunProfile 'beta' `
            -GraphMethod 'GET' `
            -GraphObject 'deviceManagement/roleScopeTags' `
            -GraphProperties $GraphProperties `
            -GraphFilters $GraphFilterString `
            -GraphMaxRetry $GraphMaxRetry `
            -GraphWaitTime $GraphWaitTime

        # Initialize hashtables
        $AllScopeTagByIdHash = [System.Collections.Generic.Dictionary[string,object]]::new(0, [System.StringComparer]::OrdinalIgnoreCase)
        $AllScopeTagByDisplayNameHash = [System.Collections.Generic.Dictionary[string,object]]::new(0, [System.StringComparer]::OrdinalIgnoreCase)
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
        Write-Error "Failed to get scope tags: $($_.Exception.Message)"
        throw
    }

    # Process all devices and set the scope tag to match info on the primary user
    [System.Collections.Generic.List[PSObject]]$devicesToUpdate = [System.Collections.Generic.List[PSObject]]::new()
    $deviceState = [System.Collections.Generic.Dictionary[string,hashtable]]::new([StringComparer]::OrdinalIgnoreCase)
    
    # Process each device
    foreach ($device in $AllDevicesWithTags) {
        # Cache device properties for faster access
        $deviceName = $device.DeviceName
        $deviceId = $device.id

        # Get current Primary User, if missing early exit
        $currentPrimaryUser = $null
        if (-not ($device.userId -and $AllUsersByIdHash.TryGetValue($device.userId, [ref]$currentPrimaryUser))) {
            & $addReport -Target $deviceName -OldValue 'No.CurrentPrimaryUser' -NewValue 'N/A' -Action 'Skipped-NoPrimaryUser' -Details 'Missing Current Primary User'
            continue
        }
        $currentPrimaryUserUPN = $currentPrimaryUser.userPrincipalName

        # Get mapping attribute value, if missing early exit
        $mappingAttributeValue = $currentPrimaryUser.$MappingAttribute
        if ([string]::IsNullOrWhiteSpace($mappingAttributeValue)) {
            & $addReport -Target $deviceName -OldValue 'N/A' -NewValue 'N/A' -Action 'Skipped-NoAttribute' -Details "Primary user missing $MappingAttribute"
            continue
        }
        # Check if mapping exists, if missing early exit
        if (-not $MappingAttributeTable.ContainsKey($mappingAttributeValue)) {
            & $addReport -Target $deviceName -OldValue $mappingAttributeValue -NewValue 'N/A' -Action 'Skipped-NoMapping' -Details 'No Attribute Mapping Found'
            continue
        }
        # Get desired scope tag object, if missing early exit
        $desiredScopeTagName = $MappingAttributeTable[$mappingAttributeValue]
        $desiredScopeTag = $null
        if (-not $AllScopeTagByDisplayNameHash.TryGetValue($desiredScopeTagName, [ref]$desiredScopeTag)) {
            & $addReport -Target $deviceName -OldValue $mappingAttributeValue -NewValue $desiredScopeTagName -Action 'Skipped-ScopeTagNotFound' -Details 'Scope Tag not found in tenant'
            continue
        }
        
        # Add builtin "Default" scope tag if requested
        [array]$newScopeTagIds = if ($KeepBuiltinTag) { $desiredScopeTag.id, "0" } else { $desiredScopeTag.id }
        $newScopeTagIds = @($newScopeTagIds | Select-Object -Unique | Sort-Object)
        
        # Get current scope tag IDs from device
        $deviceWithTags = $null
        [array]$currentScopeTagIds = if ($AllDevicesWithTagsByDeviceIdHash.TryGetValue($deviceId, [ref]$deviceWithTags) -and $deviceWithTags.roleScopeTagIds) {
            @($deviceWithTags.roleScopeTagIds) | Sort-Object
        } else { @() }
        
        # Compare if current tags match desired tags (fast string comparison on sorted arrays)
        [bool]$tagsMatch = (@($currentScopeTagIds).Count -eq @($newScopeTagIds).Count) -and (($currentScopeTagIds -join ',') -eq ($newScopeTagIds -join ','))
        
        # Convert to names for reporting
        $currentNames = ($currentScopeTagIds | ForEach-Object { 
            if ($_ -eq "0") { "Default" } else { 
                $t = $null; if ($AllScopeTagByIdHash.TryGetValue($_, [ref]$t)) { $t.displayName } else { $_ }
            }
        }) -join ','
        $newNames = ($newScopeTagIds | ForEach-Object { 
            if ($_ -eq "0") { "Default" } else { $desiredScopeTag.displayName }
        }) -join ','
        
        if ($tagsMatch) {
            & $addReport -Target $deviceName -OldValue $currentNames -NewValue $newNames -Action 'Correct' -Details 'Scope Tags already correct'
            Write-Verbose "Device: $deviceName already has correct scope tags: $newNames"
        }
        else {
            # Add device to batch update queue
            $devicesToUpdate.Add([PSCustomObject]@{
                id = $deviceId
                deviceName = $deviceName
                body = @{ roleScopeTagIds = $newScopeTagIds }
            })
            # Cache state - report will be generated after batch operations complete
            $deviceState[$deviceName] = @{
                oldValue = $currentNames; newValue = $newNames
                updateOk = $true; errorMsg = $null
            }
            Write-Verbose "Device: $deviceName Scope Tag change needed: $currentNames → $newNames"
        }
    }
    
    # Process batch updates for devices that need changes
    if ($devicesToUpdate.Count -gt 0) {
        Write-Verbose "Starting batch update for $($devicesToUpdate.Count) devices"
        
        if (-not $WhatIfPreference) {
            try {
                $batchResults = invoke-mggraphrequestbatch `
                    -GraphRunProfile 'beta' `
                    -GraphMethod 'PATCH' `
                    -GraphObject 'deviceManagement/managedDevices' `
                    -GraphObjects $devicesToUpdate `
                    -GraphQuery '' `
                    -GraphBatchSize $GraphBatchSize `
                    -GraphWaitTime $GraphWaitTime `
                    -GraphMaxRetry $GraphMaxRetry
                
                Write-Verbose "Batch update completed with $($batchResults.Count) results"
                
                # Create lookup hash and track processed IDs
                $devicesToUpdateHash = [System.Collections.Generic.Dictionary[string,object]]::new($devicesToUpdate.Count, [System.StringComparer]::OrdinalIgnoreCase)
                foreach ($d in $devicesToUpdate) { $devicesToUpdateHash[$d.id] = $d }
                $processedIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                
                # Process batch results
                foreach ($result in $batchResults) {
                    $resultId = if ($result.id) { $result.id } elseif ($result.'@odata.id') { ($result.'@odata.id' -split '/')[-1] } else { $null }
                    if ($resultId) {
                        [void]$processedIds.Add($resultId)
                        $deviceInfo = $null
                        if ($devicesToUpdateHash.TryGetValue($resultId, [ref]$deviceInfo)) {
                            Write-Verbose "Successfully updated device $($deviceInfo.deviceName)"
                        }
                    }
                }
                
                # Mark devices not in results as failed
                foreach ($dev in $devicesToUpdate) {
                    if (-not $processedIds.Contains($dev.id)) {
                        $state = $null
                        if ($deviceState.TryGetValue($dev.deviceName, [ref]$state)) {
                            $state.updateOk = $false
                            $state.errorMsg = 'No response received from batch'
                        }
                    }
                }
            }
            catch {
                $batchErrorMessage = $_.Exception.Message
                Write-Error "Batch update failed: $batchErrorMessage"
                # Mark all devices as failed
                foreach ($dev in $devicesToUpdate) {
                    $state = $null
                    if ($deviceState.TryGetValue($dev.deviceName, [ref]$state)) {
                        $state.updateOk = $false
                        $state.errorMsg = $batchErrorMessage
                    }
                }
            }
        }
        
        # Generate final reports for all devices that needed changes
        foreach ($deviceName in $deviceState.Keys) {
            $state = $deviceState[$deviceName]
            if ($WhatIfPreference) {
                & $addReport -Target $deviceName -OldValue $state.oldValue -NewValue $state.newValue -Action 'WhatIf' -Details 'Would update scope tags'
                Write-Verbose "WhatIf: Device $deviceName would be updated from [$($state.oldValue)] to [$($state.newValue)]"
            }
            elseif (-not $state.updateOk) {
                & $addReport -Target $deviceName -OldValue $state.oldValue -NewValue $state.newValue -Action 'Failed' -Details $state.errorMsg
                Write-Warning "Device $deviceName failed: $($state.errorMsg)"
            }
            else {
                & $addReport -Target $deviceName -OldValue $state.oldValue -NewValue $state.newValue -Action 'Success-Updated' -Details 'Scope tags updated'
                Write-Verbose "Successfully updated device $deviceName from [$($state.oldValue)] to [$($state.newValue)]"
            }
        }
    }
    else {
        Write-Verbose "No devices need scope tag updates"
    }
}
catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
}
finally { #End Script and restore preferences
    # Disconnect from Graph
    try {
        Disconnect-MgGraph -ErrorAction Stop *>$null
        Write-Verbose "Disconnected from Graph"
    } 
    catch {Write-Warning "Failed to disconnect from Graph: $($_.Exception.Message)"}
    # Restore original preference settings to user's console
    $ErrorActionPreference  = $script:OriginalErrorActionPreference
    $VerbosePreference      = $script:OriginalVerbosePreference
    $WhatIfPreference       = $script:OriginalWhatIfPreference
    # End T-Bone custom logging
    Invoke-TboneLog -Mode Stop
    # Generate report if requested
    if ($ReportEnabled) {
        Invoke-ScriptReport -ScriptAction $ScriptActionName -ReportResults $ReportResults -ReportStartTime $Script:StartTime -ReportDetailed $ReportDetailed -ReportToDisk $ReportToDisk -ReportToDiskPath $ReportToDiskPath
    } else {Write-Verbose "Report generation not requested"}
    # End script and report memory usage 
    [double]$MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
    Write-Verbose "Script finished. Memory usage: $MemoryUsage MB"
}
#endregion

