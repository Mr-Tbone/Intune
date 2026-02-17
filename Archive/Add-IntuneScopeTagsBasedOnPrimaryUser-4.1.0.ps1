<#PSScriptInfo
.VERSION        4.1.0
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
    4.0.1 2026-01-09 Fixed Header and renamed script for clarity
    4.0.2 2026-01-09 Fixed an unused variable
    4.1.0 2026-01-21 Minor update to logging module and a lot of variable naming changes
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
# ==========> Authentication (Invoke-ConnectMgGraph) Leave blank if use Interactive or Managed Identity <==============
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
# ==========> Logging (Invoke-TboneLog) <==============================================================================
    [Parameter(Mandatory = $false,          HelpMessage='Name of Log, to set name for Eventlog and Filelog')]
    [string]$LogName                = "",

    [Parameter(Mandatory = $false,          HelpMessage='Show output in console during execution')]
    [bool]$LogToGUI                 = $true,

    [Parameter(Mandatory = $false,          HelpMessage='Write complete log array to Windows Event when script ends')]
    [bool]$LogToEventlog            = $false,

    [Parameter(Mandatory = $false,          HelpMessage='EventLog IDs as hashtable: @{Info=11001; Warn=11002; Error=11003}')]
    [hashtable]$LogEventIds         = @{Info=11001; Warn=11002; Error=11003},

    [Parameter(Mandatory = $false,          HelpMessage='Return complete log array as Host output when script ends (Good for Intune Remediations)')]
    [bool]$LogToHost                = $false,

    [Parameter(Mandatory = $false,          HelpMessage='Write complete log array to Disk when script ends')]
    [bool]$LogToDisk                = $false,

    [Parameter(Mandatory = $false,          HelpMessage='Path where Disk logs are saved (if LogToDisk is enabled)')]
    [string]$LogToDiskPath          = "$env:TEMP",

    [Parameter(Mandatory = $false,          HelpMessage = "Enable verbose logging. Default is false")]
    [bool]$LogVerboseEnabled        = $false,
# ==========> Reporting (Invoke-ScriptReport) <========================================================================
    [Parameter(Mandatory = $false,          HelpMessage = "Title of the report")]
    [string]$ReportTitle            = "",

    [Parameter(Mandatory = $false,          HelpMessage = "Return report with statistics on how many changed objects. Default is true")]
    [bool]$ReportEnabled            = $true,

    [Parameter(Mandatory = $false,          HelpMessage = "Include detailed device changes in the report. Default is true")]
    [bool]$ReportDetailed           = $true,

    [Parameter(Mandatory = $false,          HelpMessage = "Save report to disk. Default is false")]
    [bool]$ReportToDisk             = $false,    

    [Parameter(Mandatory = $false,          HelpMessage = "Path where to save the report. Default is TEMP directory for Azure Automation compatibility")]
    [string]$ReportToDiskPath       = "$env:TEMP",
# ==========> Throttling and Retry (Invoke-MgGraphRequestSingle and Invoke-MgGraphRequestBatch) <======================
    [Parameter(Mandatory = $false,          HelpMessage = "Wait time in milliseconds between throttled requests. Default is 1000")]
    [ValidateRange(100,5000)]
    [int]$GraphWaitTime              = 1000,

    [Parameter(Mandatory = $false,          HelpMessage = "Maximum number of retry attempts for failed requests. Default is 3")]
    [ValidateRange(1,10)]
    [int]$GraphMaxRetry              = 3,

    [Parameter(Mandatory = $false,          HelpMessage = "Maximum number of items to process in a single batch. Default is 20")]
    [ValidateRange(1,20)]
    [int]$GraphBatchSize             = 20
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
# ==========> Authentication (Invoke-ConnectMgGraph) <=================================================================
[System.Collections.ArrayList]$RequiredScopes = @(  # Required Graph API permission scopes used in function Invoke-ConnectMgGraph
    "DeviceManagementManagedDevices.ReadWrite.All", # Read/write Intune device to set scope tags
    "DeviceManagementRBAC.Read.All",                # Read scope tags
    "User.Read.All"                                 # Read users
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
# Import Microsoft.Graph.Authentication with automatic version conflict resolution
[string]$ModuleName = 'Microsoft.Graph.Authentication'
if (-not (Get-Module -Name $ModuleName)) {
    try { # Try normal import first
        & {$VerbosePreference = 'SilentlyContinue'; Import-Module $ModuleName -ErrorAction Stop}
        Write-Verbose "Imported $ModuleName v$((Get-Module -Name $ModuleName).Version)"
    }
    catch { # Reported bug with missmatch version. This will catch the error and try to clean up and retry the import
        if ($_.Exception -is [System.TypeLoadException] -or $_.Exception.Message -match 'does not have an implementation') {
            Write-Warning "Module version conflict detected - cleaning up and retrying"
            & {$VerbosePreference = 'SilentlyContinue'; Get-Module Microsoft.Graph.* | Remove-Module -Force -ErrorAction SilentlyContinue}
            [version]$LatestVersion = (Get-Module -Name $ModuleName -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1).Version
            & {$VerbosePreference = 'SilentlyContinue'; Import-Module $ModuleName -RequiredVersion $LatestVersion -Force -ErrorAction Stop}
            Write-Verbose "Resolved conflict - imported $ModuleName v$LatestVersion"
        } else {throw}
    }
} else {Write-Verbose "Module '$ModuleName' already loaded v$((Get-Module -Name $ModuleName).Version)"}
#endregion

#region ---------------------------------------------------[Static Variables]------------------------------------------------------
# ==========> Logging (Invoke-TboneLog) <==============================================================================
if([string]::IsNullOrWhiteSpace($LogName)) {[string]$LogName = $ScriptActionName}           # Logname defaults to script action name
# ==========> Reporting (Invoke-ScriptReport) <========================================================================
if([string]::IsNullOrWhiteSpace($ReportTitle)) {[string]$ReportTitle = $ScriptActionName}   # Report title defaults to script action name
[datetime]$ReportStartTime = ([DateTime]::Now)                                              # Script start time for reporting
[hashtable]$ReportResults = @{}                                                             # Initialize empty hashtable for report results
[scriptblock]$AddReport = {param($Target,$OldValue,$NewValue,$Action,$Details)              # Small inline function to add report entries
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
        [string]$ResourceURL = "https://graph.microsoft.com/"
        
        # Detect authentication method based on parameters and environment (priority: ClientSecret > Certificate > ManagedIdentity > Interactive)
        [bool]$HasClientId     = -not [string]::IsNullOrWhiteSpace($AuthClientId)
        [bool]$HasTenantId     = -not [string]::IsNullOrWhiteSpace($AuthTenantId)
        [bool]$HasClientSecret = $null -ne $AuthClientSecret
        [bool]$HasCertInput    = -not [string]::IsNullOrWhiteSpace($AuthCertThumbprint) -or -not [string]::IsNullOrWhiteSpace($AuthCertName) -or -not [string]::IsNullOrWhiteSpace($AuthCertPath)

        [string]$AuthMethod = if ($HasClientSecret -and $HasClientId -and $HasTenantId) {'ClientSecret'}
        elseif ($HasCertInput -and $HasClientId -and $HasTenantId)                      {'Certificate'}
        elseif ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER)                       {'ManagedIdentity'}
        else                                                                            {'Interactive'}
        Write-Verbose "Using authentication method: $AuthMethod"
    }

    Process {
        try {
            # Check for existing valid connection and required scopes
            try {
                $Context = Get-MgContext -ErrorAction SilentlyContinue
                if ($Context) {
                    Write-Verbose "Existing connection found for: $($Context.Account)"
                    # Validate scopes only for Interactive auth (Managed Identity/app-only doesn't use delegated scopes)
                    if ($AuthMethod -eq 'Interactive') {
                        [string[]]$CurrentScopes = @($Context.Scopes)
                        [string[]]$MissingScopes = @($RequiredScopes | Where-Object { $_ -notin $CurrentScopes })
                        
                        if ($MissingScopes.Count -eq 0) {
                            Write-Verbose "Reusing existing connection with valid scopes"
                            return $Context.Account
                        }
                        Write-Verbose "Existing connection missing scopes: $($MissingScopes -join ', ')"
                        Disconnect-MgGraph -ErrorAction SilentlyContinue
                    } else {
                        # For app-only auth, reuse existing connection
                        return $Context.Account
                    }
                }
            }
            catch {
                Write-Verbose "No existing connection found"
            }
            
            # Build connection parameters
            $ConnectParams = @{ NoWelcome = $true }
            
            switch ($AuthMethod) {
                'ManagedIdentity' {
                    Write-Verbose "Connecting with Managed Identity"
                    
                    # Validate environment variables
                    if (-not $env:IDENTITY_ENDPOINT -or -not $env:IDENTITY_HEADER) {
                        throw "Managed Identity environment variables not set"
                    }
                    
                    # Get Graph SDK version for compatibility
                    [version]$GraphVersion = (Get-Module -Name 'Microsoft.Graph.Authentication' -ListAvailable | 
                        Sort-Object Version -Descending | Select-Object -First 1).Version
                    Write-Verbose "Graph SDK version: $GraphVersion"
                    
                    if ($GraphVersion -ge [version]"2.0.0") {
                        $ConnectParams['Identity'] = $true
                    } else {
                        # For older SDK versions, get token manually from managed identity endpoint
                        [hashtable]$Headers = @{
                            'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER
                            'Metadata' = 'True'
                        }
                        $Response = Invoke-RestMethod -Uri "$($env:IDENTITY_ENDPOINT)?resource=$ResourceURL" -Method GET -Headers $Headers -TimeoutSec 30 -ErrorAction Stop
                        if (-not $Response -or [string]::IsNullOrWhiteSpace($Response.access_token)) {
                            throw "Failed to retrieve access token from managed identity endpoint"
                        }
                        $ConnectParams['AccessToken'] = $Response.access_token
                        Write-Verbose "Retrieved managed identity token"
                    }
                }
                
                'ClientSecret' {
                    Write-Verbose "Connecting with Client Secret"
                    # Validate required inputs
                    if (-not $HasClientId -or -not $HasTenantId) {
                        throw "ClientSecret authentication requires both ClientId and TenantId."
                    }
                    # Convert SecureString to PSCredential to build ClientCredential
                    [System.Management.Automation.PSCredential]$ClientCredential = [System.Management.Automation.PSCredential]::new($AuthClientId, $AuthClientSecret)
                    $ConnectParams['ClientId']               = $AuthClientId
                    $ConnectParams['TenantId']               = $AuthTenantId
                    $ConnectParams['ClientSecretCredential'] = $ClientCredential
                    Write-Verbose "Using ClientId: $AuthClientId, TenantId: $AuthTenantId"
                }
                
                'Certificate' {
                    Write-Verbose "Connecting with Certificate"
                    # Validate required inputs
                    if (-not $HasClientId -or -not $HasTenantId) {
                        throw "Certificate authentication requires both ClientId and TenantId."
                    }
                    $ConnectParams['ClientId'] = $AuthClientId
                    $ConnectParams['TenantId'] = $AuthTenantId
                    
                    # Handle different certificate input methods
                    if ($AuthCertThumbprint) {
                        $ConnectParams['CertificateThumbprint'] = $AuthCertThumbprint
                        Write-Verbose "Using certificate thumbprint: $AuthCertThumbprint"
                    }
                    elseif ($AuthCertName) {
                        $ConnectParams['CertificateName'] = $AuthCertName
                        Write-Verbose "Using certificate name: $AuthCertName"
                    }
                    elseif ($AuthCertPath) {
                        # Load certificate from file
                        if (-not (Test-Path $AuthCertPath)) {
                            throw "Certificate file not found: $AuthCertPath"
                        }
                        
                        try {
                            # Declare variable for StrictMode compliance
                            [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert = $null
                            # Use MachineKeySet flag for Azure Automation compatibility
                            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]$KeyFlags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet
                            
                            if ($AuthCertPassword) {
                                $Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                                    $AuthCertPath, 
                                    $AuthCertPassword,
                                    $KeyFlags
                                )
                            } else {
                                $Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($AuthCertPath, [string]::Empty, $KeyFlags)
                            }
                            
                            # Validate certificate has private key (required for auth)
                            if (-not $Cert.HasPrivateKey) {
                                throw "Certificate does not contain a private key, which is required for authentication"
                            }
                            
                            $ConnectParams['Certificate'] = $Cert
                            Write-Verbose "Loaded certificate from: $AuthCertPath (Subject: $($Cert.Subject), Expires: $($Cert.NotAfter))"
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
                    $ConnectParams['Scopes'] = @($RequiredScopes)
                }
            }
            
            # Connect to Microsoft Graph
            try {
                Connect-MgGraph @ConnectParams -ErrorAction Stop
                Write-Verbose "Successfully connected to Microsoft Graph"
            }
            catch {
                throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
            }
            finally {
                # Clear sensitive credentials if used (PSCredential object)
                if ($ConnectParams.ContainsKey('ClientSecretCredential')) { 
                    $ConnectParams['ClientSecretCredential'] = $null 
                }
            }
            
            # Validate permissions for delegated auth (Interactive only)
            if ($AuthMethod -eq 'Interactive' -and @($RequiredScopes).Count -gt 0) {
                try {
                    $Context = Get-MgContext
                    $CurrentScopes = @($Context.Scopes)
                    $ReqScopes = @($RequiredScopes)
                    $MissingScopes = @($ReqScopes | Where-Object { $_ -notin $CurrentScopes })
                    if (@($MissingScopes).Count -gt 0) {
                        throw "Missing required scopes: $($MissingScopes -join ', ')"
                    }
                    
                    Write-Verbose "Validated all required scopes: $($RequiredScopes -join ', ')"
                }
                catch {
                    throw "Failed to validate permissions: $($_.Exception.Message)"
                }
            }
            
            # Return account context
            $Context = Get-MgContext
            $Account = $Context.Account
            Write-Verbose "Connected as: $Account"
            return $Account
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
    Version: 1.1.0
    
    Version History:
    1.0 - Initial version
    1.0.1 - Fixed event log source creation for first-time runs
    1.1.0 - Added parameter logName and logEventIds to customize event log source and file log name
#>
    [CmdletBinding()]
    param(
        [Parameter(                     HelpMessage='Start=Begin logging, Stop=End and output log array')]
        [ValidateSet('Start','Stop')]
        [string]$LogMode,
        [Parameter(                     HelpMessage='Name of Log, to set name for Eventlog and Filelog')]
        [string]$LogName        = "PowerShellScript",
        [Parameter(                     HelpMessage='Show output in console during execution')]
        [bool]$LogToGUI         = $true,
        [Parameter(                     HelpMessage='Write complete log array to Windows Eventlog when script ends')]
        [bool]$LogToEventlog    = $true,
        [Parameter(                     HelpMessage='EventLog IDs as hashtable: @{Info=11001; Warn=11002; Error=11003}')]
        [hashtable]$LogEventIds = @{Info=11001; Warn=11002; Error=11003},
        [Parameter(                     HelpMessage='Return complete log array as Host output when script ends (Good for Intune Remediations)')]
        [bool]$LogToHost        = $True,
        [Parameter(                     HelpMessage='Write complete log array to filelog on disk when script ends')]
        [bool]$LogToDisk        = $true,
        [Parameter(                     HelpMessage='Path where Disk logs are saved (if LogToDisk is enabled)')]
        [string]$LogPath        = "$env:TEMP"
    )
    # Auto-detect mode: if logger functions is already loaded in memory and no mode specified, assume Stop
    if(!$LogMode){$LogMode=if(Get-Variable -Name _l -Scope Global -EA 0){'Stop'}else{'Start'}}
    if(!$LogPath){$LogPath=if($global:_p){$global:_p}elseif($env:TEMP){$env:TEMP}else{'/tmp'}}
    # Stop mode: Save logs and cleanup
    if ($LogMode -eq 'Stop') {
        if((Get-Variable -Name _l -Scope Global -EA 0) -and (Test-Path function:\global:_Save)){_Save;if($global:_r){,$global:_l.ToArray()}}
        Unregister-Event -SourceIdentifier PowerShell.Exiting -ea 0 -WhatIf:$false
        if(Test-Path function:\global:_Clean){_Clean}
        return
    }
    # Start mode: Initialize logging and proxy all Write-* functions
    if ($LogMode -eq 'Start') {
        # Create helper functions and variables
        $global:_az=$env:AZUREPS_HOST_ENVIRONMENT -or $env:AUTOMATION_ASSET_ACCOUNTID # Detect Azure Automation environment
        $global:_l=[Collections.Generic.List[string]]::new();$global:_g=$LogToGUI;$global:_s=$Logname;$global:_n="{0}-{1:yyyyMMdd-HHmmss}"-f$Logname,(Get-Date);$global:_p=$LogPath;$global:_d=$LogToDisk;$global:_e=$LogToEventlog;$global:_i=$LogEventIds;$global:_r=$LogToHost;$global:_w=([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
        if(!(Test-Path function:\global:_Time)){function global:_Time{Get-Date -f 'yyyy-MM-dd,HH:mm:ss'}}
        if(!(Test-Path function:\global:_ID)){function global:_ID{$c=(Get-PSCallStack)[2];$n=if($c.Command -and $c.Command -ne '<ScriptBlock>'){$c.Command}elseif($c.FunctionName -and $c.FunctionName -ne '<ScriptBlock>'){$c.FunctionName}else{'Main-Script'};if($n -like '*.ps1'){'Main-Script'}else{$n}}}
        if(!(Test-Path function:\global:_Save)){function global:_Save{try{if($global:_d){[IO.Directory]::CreateDirectory($global:_p)|Out-Null;[IO.File]::WriteAllLines((Join-Path $global:_p "$($global:_n).log"),$global:_l.ToArray())};if($global:_e -and $global:_w){$isAdmin=$false;try{$id=[Security.Principal.WindowsIdentity]::GetCurrent();$isAdmin=([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)}catch{};$la=$global:_l -join"`n";$h=$la -match ',ERROR,';$et=if($h){'Error'}elseif($la -match ',WARN,'){'Warning'}else{'Information'};$eid=if($h){$global:_i.Error}elseif($la -match ',WARN,'){$global:_i.Warn}else{$global:_i.Info};$ok=$false;try{Write-EventLog -LogName Application -Source $global:_s -EventId $eid -EntryType $et -Message $la -EA Stop;$ok=$true}catch{};if(-not $ok -and $isAdmin){try{[Diagnostics.EventLog]::CreateEventSource($global:_s,'Application')}catch{};try{Write-EventLog -LogName Application -Source $global:_s -EventId $eid -EntryType $et -Message $la}catch{}}}}catch{}}}
        if(!(Test-Path function:\global:_Clean)){function global:_Clean{$WhatIfPreference=$false;Remove-Item -Path function:\Write-Host,function:\Write-Output,function:\Write-Warning,function:\Write-Error,function:\Write-Verbose,function:\_Save,function:\_Clean,function:\_ID,function:\_Time -ea 0 -Force;Remove-Variable -Name _l,_g,_s,_n,_p,_d,_e,_i,_r,_w,_az -Scope Global -ea 0}}
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
        [string]$Uri = "https://graph.microsoft.com/$GraphRunProfile/$GraphObject"
        [System.Collections.ArrayList]$GraphQueryParams = [System.Collections.ArrayList]::new()

        # Add Count parameter to Query if requested
        if ($GraphCount) {[void]$GraphQueryParams.Add("`$count=true")}

        # Add page size parameter to Query if specified
        if ($GraphMethod -eq 'GET') {[void]$GraphQueryParams.Add("`$top=$GraphPageSize")}

        # Add properties to Query if specified
        if ($GraphProperties) {
            [string]$Select = $GraphProperties -join ','
            [void]$GraphQueryParams.Add("`$select=$Select")
        }

        # Add filters to Query if specified
        if ($GraphFilters) {
            [void]$GraphQueryParams.Add("`$filter=$([System.Web.HttpUtility]::UrlEncode($GraphFilters))")
        }

        # Combine query parameters into URI
        if ($GraphQueryParams.Count -gt 0) {$Uri += "?" + ($GraphQueryParams -join '&')}
    }

    Process {
        do {
            try {
                Write-Verbose "Making request to: $Uri"
                $I = 1
                do {
                    $Response = $null
                    Write-Verbose "Requesting page $I with $GraphPageSize items"
                    # Set default parameters for Invoke-MgGraphRequest
                    $Params = @{
                        Method      = $GraphMethod
                        Uri         = $Uri
                        ErrorAction = 'Stop'
                        OutputType  = 'PSObject'
                        Verbose     = $false
                    }
                    # Add ConsistencyLevel header if Count is requested
                    if ($GraphCount) { $Params['Headers'] = @{ 'ConsistencyLevel' = 'eventual' } }

                    # Add additional parameters based on method
                    if ($GraphMethod -in 'POST', 'PATCH') {
                        $Params['Body'] = $GraphBody
                        if (-not $Params.ContainsKey('Headers')) {
                            $Params['Headers'] = @{}
                        }
                        $Params['Headers']['Content-Type'] = 'application/json'
                        Write-Verbose "Request body: $($GraphBody | ConvertTo-Json -Depth 10)"
                    }
                    # Send request to Graph API
                    try {
                        $Response = Invoke-MgGraphRequest @Params
                        Write-Verbose "Request successful"
                    }
                    catch {
                        # Check if this is an expired skip token error
                        if ($_.Exception.Message -match "Skip token.*expired|Skip token is null") {
                            Write-Warning "Skip token has expired on page $I after collecting $($PsobjectResults.Count) items. Returning collected data."
                            # Exit pagination loop and return what we have
                            $Uri = $null
                            break
                        }
                        # For other errors, log and re-throw to outer catch
                        Write-Verbose "Request failed with error: $($_.Exception.Message)"
                        throw
                    }
                    if ($GraphMethod -in 'POST', 'PATCH', 'DELETE') {return $Response}
                    if ($Response.value) {[void]$PsobjectResults.AddRange($Response.value)}
                    # Capture count from first response if requested
                    if ($GraphCount -and $null -eq $TotalCount -and $Response.'@odata.count') {
                        $TotalCount = $Response.'@odata.count'
                        Write-Verbose "Total count available: $TotalCount items"
                    }
                    Write-Verbose "Retrieved page $I, Now total: $($PsobjectResults.Count) items"

                    # Check for next page
                    if ($GraphSkipPagination) {
                        Write-Verbose "SkipPagination enabled, stopping after first page"
                        $Uri = $null
                    }
                    elseif ($Response.PSObject.Properties.Name -contains '@odata.nextLink') {
                        if ($Response.'@odata.nextLink') {
                            $Uri = $Response.'@odata.nextLink'
                            Write-Verbose "Next page found: $Uri"
                        }
                        else {
                            Write-Verbose "No @odata.nextLink value, stopping pagination"
                            $Uri = $null
                        }
                    }
                    else {
                        Write-Verbose "No more pages found"
                        $Uri = $null
                    }

                    $I++
                } while ($Uri)
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
function Invoke-MgGraphRequestBatch {
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
        [datetime]$StartTime = Get-Date
        [int]$RetryCount = 0
        [int]$TotalObjects = $GraphObjects.Count
        
        # Pre-allocate collections with capacity for better performance
        [System.Collections.Generic.List[PSObject]]$CollectedObjects = [System.Collections.Generic.List[PSObject]]::new($TotalObjects)
        [System.Collections.Generic.List[PSObject]]$RetryObjects = [System.Collections.Generic.List[PSObject]]::new()
        
        # Check execution context once
        [bool]$ManagedIdentity = [bool]$env:AUTOMATION_ASSET_ACCOUNTID
        Write-Verbose "Running in $(if ($ManagedIdentity) { 'Azure Automation' } else { 'interactive PowerShell' }) context"
        
        # Pre-calculate common values to avoid repeated work
        [string]$BatchUri = "https://graph.microsoft.com/$GraphRunProfile/`$batch"
        [hashtable]$BatchHeaders = @{'Content-Type' = 'application/json'}
        
        # Build URL query parameters once (they're the same for all requests)
        [string]$UrlQueryString = $null
        if ($GraphProperties -or $GraphFilters) {
            [System.Collections.Generic.List[string]]$UrlParams = [System.Collections.Generic.List[string]]::new()
            if ($GraphProperties) {
                $UrlParams.Add("`$select=$($GraphProperties -join ',')")
            }
            if ($GraphFilters) {
                $UrlParams.Add("`$filter=$([System.Web.HttpUtility]::UrlEncode($GraphFilters))")
            }
            $UrlQueryString = "?" + ($UrlParams -join '&')
        }
        
        # Pre-determine if method needs body/headers (avoid repeated checks)
        [bool]$NeedsBody = $GraphMethod -in 'PATCH','POST'
        [string]$ContentTypeHeader = if ($NeedsBody) { 'application/json' } else { $null }
        
        Write-Verbose "Graph batch processing initialized for $TotalObjects objects"
    }
    
    Process {
        try {
            do {
                [int]$CurrentObject = 0
                $RetryObjects.Clear()
                
                # Process objects in batches
                for($i = 0; $i -lt $GraphObjects.Count; $i += $GraphBatchSize) {
                    # Calculate batch boundaries
                    [int]$BatchEnd = [Math]::Min($i + $GraphBatchSize, $GraphObjects.Count)
                    [int]$BatchCount = $BatchEnd - $i
                    
                    # Pre-allocate request array with exact size
                    [System.Collections.ArrayList]$Req = [System.Collections.ArrayList]::new($BatchCount)
                    
                    # Build batch requests (optimized loop)
                    for ($j = $i; $j -lt $BatchEnd; $j++) {
                        [object]$Obj = $GraphObjects[$j]
                        [string]$Url = if ($GraphNoObjectIdInUrl) { "/$GraphObject$GraphQuery" } else { "/$GraphObject/$($Obj.id)$GraphQuery" }
                        if ($UrlQueryString) { $Url += $UrlQueryString }
                        
                        # Use object's body if available, otherwise use the global Body parameter
                        [object]$RequestBody = if ($Obj.PSObject.Properties.Name -contains 'body' -and $Obj.body) {
                            $Obj.body
                        } elseif ($NeedsBody) {
                            $GraphBody
                        } else {
                            $null
                        }
                        
                        [void]$Req.Add(@{
                            'id' = $Obj.id
                            'method' = $GraphMethod
                            'url' = $Url
                            'body' = $RequestBody
                            'headers' = @{ 'Content-Type' = $ContentTypeHeader }
                        })
                    }
                    
                    Write-Verbose "Sending batch $([Math]::Floor($i/$GraphBatchSize) + 1): items $($i+1) to $BatchEnd of $($GraphObjects.Count)"
                    
                    # Send batch request
                    try {
                        [string]$BatchBody = @{'requests' = $Req} | ConvertTo-Json -Depth 10 -Compress
                        [object]$Responses = Invoke-MgGraphRequest -Method POST -Uri $BatchUri -Body $BatchBody -Headers $BatchHeaders -Verbose:$false
                        Write-Verbose "Batch request successful with $($Req.Count) requests"
                    }
                    catch {
                        Write-Error "Failed to send batch request: $($_.Exception.Message)"
                        throw
                    }
                    
                    # Process responses (optimized with direct property access)
                    [int]$ThrottledCount = 0
                    foreach ($Response in $Responses.responses) {
                        $CurrentObject++
                        
                        # Handle response by status code
                        switch ($Response.status) {
                            {$_ -in 200,201,204} { # Success cases
                                # Extract the actual device object from response.body
                                if ($Response.body) {
                                    # Convert hashtable to PSCustomObject if needed
                                    [object]$GraphBodyObject = if ($Response.body -is [hashtable]) {
                                        [PSCustomObject]$Response.body
                                    } else {
                                        $Response.body
                                    }
                                    [void]$CollectedObjects.Add($GraphBodyObject)
                                    Write-Verbose "Success ($($Response.status)) for request $($Response.id) with body"
                                } else {
                                    # For 204 No Content (PATCH/DELETE), return a success indicator with the request ID
                                    [PSCustomObject]$SuccessObject = [PSCustomObject]@{
                                        id = $Response.id
                                        status = $Response.status
                                    }
                                    [void]$CollectedObjects.Add($SuccessObject)
                                    Write-Verbose "Success ($($Response.status)) for request $($Response.id) - no body returned"
                                }
                            }
                            400 { # Bad request - check error details for expected failures
                                # Extract error message from response body
                                [string]$ErrorCode = $null
                                [string]$ErrorMsg = $null
                                if ($Response.body -and $Response.body.error) {
                                    $ErrorCode = $Response.body.error.code
                                    $ErrorMsg = $Response.body.error.message
                                }
                                
                                # For DELETE operations, common "not found" patterns mean already removed - treat as success
                                if ($GraphMethod -eq 'DELETE' -and ($ErrorMsg -imatch 'does not exist|not found|cannot be found|no longer exists|was not found|resource .+ not found')) {
                                    Write-Verbose "Object $($Response.id) already removed or not found (400: $ErrorCode)"
                                    [PSCustomObject]$SuccessObject = [PSCustomObject]@{
                                        id = $Response.id
                                        status = 204  # Treat as successful removal
                                        note = 'Already removed'
                                    }
                                    [void]$CollectedObjects.Add($SuccessObject)
                                }
                                # For POST operations, "already exists" patterns mean already created - treat as success
                                elseif ($GraphMethod -eq 'POST' -and ($ErrorMsg -imatch 'already exist|duplicate|conflict|references already exist|object reference already exist')) {
                                    Write-Verbose "Object $($Response.id) already exists (400: $ErrorCode)"
                                    [PSCustomObject]$SuccessObject = [PSCustomObject]@{
                                        id = $Response.id
                                        status = 200  # Treat as successful (already exists)
                                        note = 'Already exists'
                                    }
                                    [void]$CollectedObjects.Add($SuccessObject)
                                }
                                else {
                                    # Unexpected 400 error - log and add to retry
                                    Write-Error "Bad request (400) for object $($Response.id): $ErrorCode - $ErrorMsg"
                                    [void]$RetryObjects.Add($Response)
                                }
                            }
                            403 { # Access denied - don't retry
                                Write-Error "Access denied (403) for object $($Response.id) - Check permissions"
                            }
                            404 { # Not found - for DELETE treat as success, for others log warning
                                if ($GraphMethod -eq 'DELETE') {
                                    Write-Verbose "Object $($Response.id) not found (404) - treating as already removed"
                                    [PSCustomObject]$SuccessObject = [PSCustomObject]@{
                                        id = $Response.id
                                        status = 204
                                        note = 'Not found - already removed'
                                    }
                                    [void]$CollectedObjects.Add($SuccessObject)
                                } else {
                                    Write-Warning "Resource not found (404) for object $($Response.id)"
                                }
                            }
                            429 { # Throttling - retry with backoff
                                Write-Warning "Throttling (429) for object $($Response.id)"
                                [void]$RetryObjects.Add($Response)
                                $ThrottledCount++
                            }
                            default { # Other errors - retry
                                Write-Error "Unexpected status ($($Response.status)) for object $($Response.id)"
                                [void]$RetryObjects.Add($Response)
                            }
                        }
                    }
                    
                    # Show progress (only in interactive mode)
                    if (-not $ManagedIdentity) {
                        [double]$PercentComplete = ($CurrentObject / $TotalObjects) * 100
                        [timespan]$Elapsed = (Get-Date) - $StartTime
                        [timespan]$TimeLeft = if ($CurrentObject -gt 0) {
                            [TimeSpan]::FromMilliseconds(($Elapsed.TotalMilliseconds / $CurrentObject) * ($TotalObjects - $CurrentObject))
                        } else { [TimeSpan]::Zero }
                        
                        Write-Progress -Activity "Processing Graph Batch Requests" `
                            -Status "Progress: $CurrentObject/$TotalObjects | Estimated Time Left: $($TimeLeft.ToString('hh\:mm\:ss')) | Throttled: $ThrottledCount | Retry: $RetryCount/$GraphMaxRetry" `
                            -PercentComplete $PercentComplete
                    }
                    
                    # Handle throttling with exponential backoff (only if throttled responses exist)
                    if ($ThrottledCount -gt 0) {
                        # Extract retry-after values efficiently
                        [array]$RetryAfterValues = @($RetryObjects | 
                            Where-Object { $_.status -eq 429 -and $_.headers.'retry-after' } | 
                            Select-Object -ExpandProperty headers | 
                            Select-Object -ExpandProperty 'retry-after')
                        
                        [int]$WaitSeconds = if ($RetryAfterValues -and $RetryAfterValues.Count -gt 0) {
                            [Math]::Min(($RetryAfterValues | Measure-Object -Maximum).Maximum + ($RetryCount * 2), 30)
                        } else {
                            [Math]::Min(1 + ($RetryCount * 2), 30)
                        }
                        
                        Write-Warning "Throttling detected, waiting $WaitSeconds seconds (Retry: $RetryCount)"
                        Start-Sleep -Seconds $WaitSeconds
                    }
                }
                
                # Prepare for retry if needed
                if ($RetryObjects.Count -gt 0 -and $RetryCount -lt $GraphMaxRetry) {
                    $RetryCount++
                    Write-Verbose "Starting retry $RetryCount with $($RetryObjects.Count) objects"
                    
                    # Create lookup hashtable for faster filtering
                    [hashtable]$RetryIdHash = @{}
                    foreach ($R in $RetryObjects) { $RetryIdHash[$R.id] = $true }
                    
                    # Filter objects to retry
                    $Objects = $Objects | Where-Object { $RetryIdHash.ContainsKey($_.id) }
                }
                
            } while ($RetryObjects.Count -gt 0 -and $RetryCount -lt $GraphMaxRetry)
            
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
        [timespan]$Duration = (Get-Date) - $StartTime
        Write-Verbose "Function $($MyInvocation.MyCommand.Name) finished in $($Duration.ToString('mm\:ss')) | Memory: $MemoryUsage MB"
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
    2.1 - renamed parameter ActionName to ReportTitle for clarity
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false,                  HelpMessage = "Description of the action performed by the script")]
        [string]$ReportTitle           = "Script Execution Report",
        
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
        [datetime]$ReportEndTime = [DateTime]::Now
    }

    Process {
        try {
            # Calculate duration
            [timespan]$Duration = $ReportEndTime - $ReportStartTime
            [string]$DurationFormatted = $Duration.ToString("hh\:mm\:ss")
            
            # Cache sorted action keys
            [array]$SortedActions = @($ReportResults.Keys | Sort-Object)
            
            # Build action summary and count total objects
            [int]$TotalObjects = 0
            [System.Collections.Specialized.OrderedDictionary]$ActionSummary = [ordered]@{}
            foreach ($Action in $SortedActions) {
                [int]$Count = $ReportResults[$Action].Count
                $ActionSummary[$Action] = $Count
                $TotalObjects += $Count
            }
            # Output detailed report if requested
            if ($ReportDetailed -and $TotalObjects -gt 0) {
                # Flatten all entries from all action groups into a single array
                [System.Collections.ArrayList]$AllEntries = [System.Collections.ArrayList]::new($TotalObjects)
                foreach ($Action in $SortedActions) {
                    [void]$AllEntries.AddRange(@($ReportResults[$Action]))
                }
                # Sort entries and output each line to avoid truncation
                [array]$SortedEntries = @($AllEntries | Sort-Object -Property Action, Target)
                [object]$TableOutput = $SortedEntries | Format-Table -Property `
                    @{Name='Target';Expression={$_.Target};Alignment='Left'},
                    @{Name='OldValue';Expression={$_.OldValue};Alignment='Left'},
                    @{Name='NewValue';Expression={$_.NewValue};Alignment='Left'},
                    @{Name='Action';Expression={$_.Action};Alignment='Left'},
                    @{Name='Details';Expression={$_.Details};Alignment='Left'} -AutoSize -Wrap
                # Use Out-String with -Stream to output each line separately (no truncation)
                $TableOutput | Out-String -Stream -Width 250 | ForEach-Object { Write-Output $_ }
            }
            #Output summary report
            Write-Output "═══════════════════════════════════════════════════════════"
            Write-Output "  $ReportTitle"
            Write-Output "═══════════════════════════════════════════════════════════"
            Write-Output "  Start:    $($ReportStartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
            Write-Output "  End:      $($ReportEndTime.ToString('yyyy-MM-dd HH:mm:ss'))"
            Write-Output "  Duration: $DurationFormatted"
            Write-Output "───────────────────────────────────────────────────────────"
            Write-Output "  Summary"
            
            # Display actions breakdown dynamically and their percentages
            if ($ActionSummary.Count -gt 0) {
                if ($TotalObjects -gt 0) {
                    foreach ($Action in $ActionSummary.Keys) {
                        [int]$Count = $ActionSummary[$Action]
                        [double]$Percentage = [math]::Round(($Count / $TotalObjects) * 100, 1)
                        Write-Output ("    {0,-30}: {1,6} ({2,5}%)" -f $Action, $Count, $Percentage)
                    }
                } else {
                    foreach ($Action in $ActionSummary.Keys) {
                        Write-Output ("    {0,-20}: {1,6} (  0.0%)" -f $Action, $ActionSummary[$Action])
                    }
                }
            }
            Write-Output ("    {0,-30}: {1,6}" -f "Total Objects", $TotalObjects)
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
                [string]$Timestamp = $ReportEndTime.ToString('yyyyMMdd_HHmmss')
                [string]$CleanAction = $ReportTitle -replace '[^\w\-]', '_'
                [string]$BaseFileName = "Report_$($CleanAction)_$Timestamp"
                
                # Save report based on format parameter
                if ($ReportFormat -eq 'JSON') {
                    # Flatten results for JSON export
                    $AllResults = [System.Collections.ArrayList]::new()
                    foreach ($List in $ReportResults.Values) {
                        [void]$AllResults.AddRange($List)
                    }
                    
                    # Build report object
                    $ReportData = [PSCustomObject]@{
                        ReportTitle    = $ReportTitle
                        StartTime       = $ReportStartTime.ToString('yyyy-MM-dd HH:mm:ss')
                        EndTime         = $ReportEndTime.ToString('yyyy-MM-dd HH:mm:ss')
                        Duration        = $DurationFormatted
                        TotalProcessed  = $TotalObjects
                        ActionSummary   = $ActionSummary
                        DetailedResults = $AllResults
                    }
                    
                    # Save as JSON
                    try {
                        $ReportToDiskPath = Join-Path $ReportToDiskPath "$BaseFileName.json"
                        $ReportData | ConvertTo-Json -Depth 10 -Compress:$false | Out-File -FilePath $ReportToDiskPath -Force -Encoding utf8 -ErrorAction Stop
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
                        $AllResults = [System.Collections.ArrayList]::new()
                        foreach ($List in $ReportResults.Values) {
                            [void]$AllResults.AddRange($List)
                        }
                        
                        try {
                            $ReportToDiskPath = Join-Path $ReportToDiskPath "$BaseFileName.csv"
                            $AllResults | Export-Csv -Path $ReportToDiskPath -NoTypeInformation -Force -Encoding UTF8 -ErrorAction Stop
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
Invoke-TboneLog -LogMode Start -Logname $LogName -LogToGUI $LogToGUI -LogToEventlog $LogToEventlog -LogEventIds $LogEventIds -LogToDisk $LogToDisk -LogPath $LogToDiskPath -LogToHost $LogToHost

try {
    #Sign in to Graph
    try {
        # Build authentication parameters to pass only non-empty values. If no values are provided, default interactive auth or managed identity auth will be used.
        [hashtable]$AuthParams = @{}
        @{AuthTenantId = $AuthTenantId; AuthClientId = $AuthClientId; AuthCertThumbprint = $AuthCertThumbprint; AuthCertName = $AuthCertName; AuthCertPath = $AuthCertPath}.GetEnumerator() `
            | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Value) } `
            | ForEach-Object { $AuthParams[$_.Key] = $_.Value }
        # Add SecureString parameters that require different null checks
        if ($AuthClientSecret -and $AuthClientSecret.Length -gt 0) { $AuthParams['AuthClientSecret'] = $AuthClientSecret }
        if ($AuthCertPassword -and $AuthCertPassword.Length -gt 0) { $AuthParams['AuthCertPassword'] = $AuthCertPassword }
        # Invoke connection to Microsoft Graph with specified authentication parameters
        Invoke-ConnectMgGraph @AuthParams -RequiredScopes $RequiredScopes
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
            [array]$OsFilterParts = $OperatingSystems | ForEach-Object { "operatingSystem eq '$_'" }
            $GraphFilterString = "($($OsFilterParts -join ' or '))"
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
                [string]$IncludePattern = if ($IncludedDeviceNames -and $IncludedDeviceNames.Count -gt 0) {
                    '^(' + (($IncludedDeviceNames | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')'
                } else { $null }
                [string]$ExcludePattern = if ($ExcludedDeviceNames -and $ExcludedDeviceNames.Count -gt 0) {
                    '^(' + (($ExcludedDeviceNames | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')'
                } else { $null }
                $AllDevices = $AllDevices | Where-Object {
                    $IncludeMatch = if ($IncludePattern) { $_.deviceName -imatch $IncludePattern } else { $true }
                    $ExcludeMatch = if ($ExcludePattern) { $_.deviceName -notmatch $ExcludePattern } else { $true }
                    $IncludeMatch -and $ExcludeMatch
                }
                if ($IncludePattern) { Write-Verbose "Applied inclusion filter for $($IncludedDeviceNames.Count) patterns" }
                if ($ExcludePattern) { Write-Verbose "Applied exclusion filter for $($ExcludedDeviceNames.Count) patterns" }
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
        $AllDevicesWithTags = Invoke-MgGraphRequestBatch `
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
    [System.Collections.Generic.List[PSObject]]$DevicesToUpdate = [System.Collections.Generic.List[PSObject]]::new()
    $DeviceState = [System.Collections.Generic.Dictionary[string,hashtable]]::new([StringComparer]::OrdinalIgnoreCase)
    
    # Process each device
    foreach ($Device in $AllDevicesWithTags) {
        # Cache device properties for faster access
        $DeviceName = $Device.DeviceName
        $DeviceId = $Device.id

        # Get current Primary User, if missing early exit
        $CurrentPrimaryUser = $null
        if (-not ($Device.userId -and $AllUsersByIdHash.TryGetValue($Device.userId, [ref]$CurrentPrimaryUser))) {
            & $AddReport -Target $DeviceName -OldValue 'No.CurrentPrimaryUser' -NewValue 'N/A' -Action 'Skipped-NoPrimaryUser' -Details 'Missing Current Primary User'
            continue
        }

        # Get mapping attribute value, if missing early exit
        $MappingAttributeValue = $CurrentPrimaryUser.$MappingAttribute
        if ([string]::IsNullOrWhiteSpace($MappingAttributeValue)) {
            & $AddReport -Target $DeviceName -OldValue 'N/A' -NewValue 'N/A' -Action 'Skipped-NoAttribute' -Details "Primary user missing $MappingAttribute"
            continue
        }
        # Check if mapping exists, if missing early exit
        if (-not $MappingAttributeTable.ContainsKey($MappingAttributeValue)) {
            & $AddReport -Target $DeviceName -OldValue $MappingAttributeValue -NewValue 'N/A' -Action 'Skipped-NoMapping' -Details 'No Attribute Mapping Found'
            continue
        }
        # Get desired scope tag object, if missing early exit
        $DesiredScopeTagName = $MappingAttributeTable[$MappingAttributeValue]
        $DesiredScopeTag = $null
        if (-not $AllScopeTagByDisplayNameHash.TryGetValue($DesiredScopeTagName, [ref]$DesiredScopeTag)) {
            & $AddReport -Target $DeviceName -OldValue $MappingAttributeValue -NewValue $DesiredScopeTagName -Action 'Skipped-ScopeTagNotFound' -Details 'Scope Tag not found in tenant'
            continue
        }
        
        # Add builtin "Default" scope tag if requested
        [array]$NewScopeTagIds = if ($KeepBuiltinTag) { $DesiredScopeTag.id, "0" } else { $DesiredScopeTag.id }
        $NewScopeTagIds = @($NewScopeTagIds | Select-Object -Unique | Sort-Object)
        
        # Get current scope tag IDs from device
        $DeviceWithTags = $null
        [array]$CurrentScopeTagIds = if ($AllDevicesWithTagsByDeviceIdHash.TryGetValue($DeviceId, [ref]$DeviceWithTags) -and $DeviceWithTags.roleScopeTagIds) {
            @($DeviceWithTags.roleScopeTagIds) | Sort-Object
        } else { @() }
        
        # Compare if current tags match desired tags (fast string comparison on sorted arrays)
        [bool]$TagsMatch = (@($CurrentScopeTagIds).Count -eq @($NewScopeTagIds).Count) -and (($CurrentScopeTagIds -join ',') -eq ($NewScopeTagIds -join ','))
        
        # Convert to names for reporting
        $CurrentNames = ($CurrentScopeTagIds | ForEach-Object { 
            if ($_ -eq "0") { "Default" } else { 
                $T = $null; if ($AllScopeTagByIdHash.TryGetValue($_, [ref]$T)) { $T.displayName } else { $_ }
            }
        }) -join ','
        $NewNames = ($NewScopeTagIds | ForEach-Object { 
            if ($_ -eq "0") { "Default" } else { $DesiredScopeTag.displayName }
        }) -join ','
        
        if ($TagsMatch) {
            & $AddReport -Target $DeviceName -OldValue $CurrentNames -NewValue $NewNames -Action 'Correct' -Details 'Scope Tags already correct'
            Write-Verbose "Device: $DeviceName already has correct scope tags: $NewNames"
        }
        else {
            # Add device to batch update queue
            $DevicesToUpdate.Add([PSCustomObject]@{
                id = $DeviceId
                deviceName = $DeviceName
                body = @{ roleScopeTagIds = $NewScopeTagIds }
            })
            # Cache state - report will be generated after batch operations complete
            $DeviceState[$DeviceName] = @{
                oldValue = $CurrentNames; newValue = $NewNames
                updateOk = $true; errorMsg = $null
            }
            Write-Verbose "Device: $DeviceName Scope Tag change needed: $CurrentNames → $NewNames"
        }
    }
    
    # Process batch updates for devices that need changes
    if ($DevicesToUpdate.Count -gt 0) {
        Write-Verbose "Starting batch update for $($DevicesToUpdate.Count) devices"
        
        if (-not $WhatIfPreference) {
            try {
                $BatchResults = Invoke-MgGraphRequestBatch `
                    -GraphRunProfile 'beta' `
                    -GraphMethod 'PATCH' `
                    -GraphObject 'deviceManagement/managedDevices' `
                    -GraphObjects $DevicesToUpdate `
                    -GraphQuery '' `
                    -GraphBatchSize $GraphBatchSize `
                    -GraphWaitTime $GraphWaitTime `
                    -GraphMaxRetry $GraphMaxRetry
                
                Write-Verbose "Batch update completed with $($BatchResults.Count) results"
                
                # Create lookup hash and track processed IDs
                $DevicesToUpdateHash = [System.Collections.Generic.Dictionary[string,object]]::new($DevicesToUpdate.Count, [System.StringComparer]::OrdinalIgnoreCase)
                foreach ($D in $DevicesToUpdate) { $DevicesToUpdateHash[$D.id] = $D }
                $ProcessedIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                
                # Process batch results
                foreach ($Result in $BatchResults) {
                    $ResultId = if ($Result.id) { $Result.id } elseif ($Result.'@odata.id') { ($Result.'@odata.id' -split '/')[-1] } else { $null }
                    if ($ResultId) {
                        [void]$ProcessedIds.Add($ResultId)
                        $DeviceInfo = $null
                        if ($DevicesToUpdateHash.TryGetValue($ResultId, [ref]$DeviceInfo)) {
                            Write-Verbose "Successfully updated device $($DeviceInfo.deviceName)"
                        }
                    }
                }
                
                # Mark devices not in results as failed
                foreach ($Dev in $DevicesToUpdate) {
                    if (-not $ProcessedIds.Contains($Dev.id)) {
                        $State = $null
                        if ($DeviceState.TryGetValue($Dev.deviceName, [ref]$State)) {
                            $State.updateOk = $false
                            $State.errorMsg = 'No response received from batch'
                        }
                    }
                }
            }
            catch {
                $BatchErrorMessage = $_.Exception.Message
                Write-Error "Batch update failed: $BatchErrorMessage"
                # Mark all devices as failed
                foreach ($Dev in $DevicesToUpdate) {
                    $State = $null
                    if ($DeviceState.TryGetValue($Dev.deviceName, [ref]$State)) {
                        $State.updateOk = $false
                        $State.errorMsg = $BatchErrorMessage
                    }
                }
            }
        }
        
        # Generate final reports for all devices that needed changes
        foreach ($DeviceName in $DeviceState.Keys) {
            $State = $DeviceState[$DeviceName]
            if ($WhatIfPreference) {
                & $AddReport -Target $DeviceName -OldValue $State.oldValue -NewValue $State.newValue -Action 'WhatIf' -Details 'Would update scope tags'
                Write-Verbose "WhatIf: Device $DeviceName would be updated from [$($State.oldValue)] to [$($State.newValue)]"
            }
            elseif (-not $State.updateOk) {
                & $AddReport -Target $DeviceName -OldValue $State.oldValue -NewValue $State.newValue -Action 'Failed' -Details $State.errorMsg
                Write-Warning "Device $DeviceName failed: $($State.errorMsg)"
            }
            else {
                & $AddReport -Target $DeviceName -OldValue $State.oldValue -NewValue $State.newValue -Action 'Success-Updated' -Details 'Scope tags updated'
                Write-Verbose "Successfully updated device $DeviceName from [$($State.oldValue)] to [$($State.newValue)]"
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
    Invoke-TboneLog -LogMode Stop
    # Generate report if requested
    if ($ReportEnabled) {
        Invoke-ScriptReport -ReportTitle $ReportTitle -ReportResults $ReportResults -ReportStartTime $ReportStartTime -ReportDetailed $ReportDetailed -ReportToDisk $ReportToDisk -ReportToDiskPath $ReportToDiskPath
    } else {Write-Verbose "Report generation not requested"}
    # End script and report memory usage 
    [double]$MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
    Write-Verbose "Script finished. Memory usage: $MemoryUsage MB"
}
#endregion

