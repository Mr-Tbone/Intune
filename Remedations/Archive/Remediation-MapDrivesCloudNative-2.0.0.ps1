<#PSScriptInfo
.VERSION        2.0.0
.AUTHOR         @MrTbone_se (T-bone Granheden)
.GUID           feedbeef-beef-4dad-beef-b628ccca16bd
.COPYRIGHT      (c) 2026 T-bone Granheden. MIT License - free to use with attribution.
.TAGS           Intune Graph PrimaryUser DeviceManagement MicrosoftGraph Azure
.LICENSEURI     https://opensource.org/licenses/MIT
.PROJECTURI     https://github.com/Mr-Tbone/Intune
.RELEASENOTES
    1.0 2023-10-02 Initial Build
    1.1 2021-10-04 Added logging to eventlog
    1.2 2021-10-05 Added detection mode to run as remediation script
    2.0.0 2026-01-20 Major update with updated functions, logic and error handling
#>

<#
.SYNOPSIS
    This script will map drives and printers for cloud native devices
    It can be used as both script and remediation script in Intune. 
    I prefer to use it as a remediation script to be able to update with new versions.

.DESCRIPTION
    This script maps network drives or printers for cloud-native (Entra ID joined) Windows devices.
    When run as SYSTEM (via Intune), it creates a scheduled task that runs as the logged-in user.
    The scheduled task executes on logon and network connection events to map drives/printers.
    Group memberships are queried via LDAP to determine which mappings apply to the user.

.EXAMPLE
    .\Remediation-MapDrivesCloudNative.ps1
    When deployed via Intune as SYSTEM, creates scheduled task and scripts for drive mapping.

.EXAMPLE
    .\Remediation-MapDrivesCloudNative.ps1 -LogVerboseEnabled $true -LogToDisk $true
    Runs with verbose logging enabled and saves logs to disk.

.NOTES
    Please feel free to use this, but make sure to credit @MrTbone_se as the original author

.LINK
    https://tbone.se
#>

#region ---------------------------------------------------[Modifiable Parameters and Defaults]------------------------------------
# Customizations
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Path where script will be stored")]
    [String]$CorpDataPath           = "C:\ProgramData\CorpData",

    [Parameter(Mandatory = $false, HelpMessage = "Domain to search for AD group memberships (e.g., 'contoso.com')")]
    [String]$DomainName             = "tbone.se",

    [Parameter(Mandatory = $false, HelpMessage = "Mapping configuration version, increment when adding new or changing drive or printer mappings")]
    [version]$MappingVersion        = "1.1",

    [Parameter(Mandatory = $false, HelpMessage = "Remove stale drive/printer mappings that are no longer in the configuration")]
    [Bool]$RemoveStaleObjects       = $false,

    [Parameter(Mandatory = $false, HelpMessage = "Force replace all scripts and scheduled tasks even if version is the same")]
    [Bool]$ForceReplaceAll          = $false,
# ==========> Logging (Invoke-TboneLog) <==============================================================================
    [Parameter(Mandatory = $false,          HelpMessage='Name of Log, to set name for Eventlog and Filelog')]
    [string]$LogName                = "",

    [Parameter(Mandatory = $false,          HelpMessage='Show output in console during execution')]
    [bool]$LogToGUI                 = $false,

    [Parameter(Mandatory = $false,          HelpMessage='Write complete log array to Windows Event when script ends')]
    [bool]$LogToEventlog            = $true,

    [Parameter(Mandatory = $false,          HelpMessage='EventLog IDs as hashtable: @{Info=11001; Warn=11002; Error=11003}')]
    [hashtable]$LogEventIds         = @{Info=11001; Warn=11002; Error=11003},

    [Parameter(Mandatory = $false,          HelpMessage='Return complete log array as Host output when script ends (Good for Intune Remediations)')]
    [bool]$LogToHost                = $true,

    [Parameter(Mandatory = $false,          HelpMessage='Write complete log array to Disk when script ends')]
    [bool]$LogToDisk                = $false,

    [Parameter(Mandatory = $false,          HelpMessage='Path where Disk logs are saved (if LogToDisk is enabled)')]
    [string]$LogToDiskPath          = "$env:TEMP",

    [Parameter(Mandatory = $false,          HelpMessage = "Enable verbose logging. Default is false")]
    [bool]$LogVerboseEnabled        = $false
)
#endregion

#region ---------------------------------------------------[Modifiable Parameters and defaults]------------------------------------
#IMPORTANT! When adding new Drivers make sure to also increment Version in Psscriptinfo above. 
# Add Objects to Map here either Printers or Drives (Not Both) with the following syntax
#Printers:  $MapObjects += @{PrinterName="PrinterName"  ;Default=$true      ;Path="\\printserver\printerName"   ;ADGroups="My Group"}
#Drives:    $MapObjects += @{Letter="X"                 ;Persistent=$true   ;Path="\\fileserver\fileshare"      ;ADGroups="My Group"    ;Label="My drive"}
$MapObjects = @()
$MapObjects+=@{Letter="S";Persistent=$true;Path="\\fileserver.tbone.se\Sales"	    ;ADGroups=	"Sales"	        ;Label="Sales"      }
$MapObjects+=@{Letter="D";Persistent=$true;Path="\\fileserver.tbone.se\Consult"     ;ADGroups=	"Consultants"   ;Label="Consultants"}
$MapObjects+=@{Letter="W";Persistent=$true;Path="\\fileserver.tbone.se\Common"	    ;ADGroups=	"Loc_ESC"       ;Label=""           }
#endregion

#region ---------------------------------------------------[Set global script settings]--------------------------------------------
# set strict mode to latest version
Set-StrictMode -Version Latest

# Save original preference states at script scope for restoration in finally block
[System.Management.Automation.ActionPreference]$script:OriginalErrorActionPreference    = $ErrorActionPreference
[System.Management.Automation.ActionPreference]$script:OriginalVerbosePreference        = $VerbosePreference
[bool]$script:OriginalWhatIfPreference                                                  = $WhatIfPreference

# Set verbose- and whatif- preference based on parameter instead of hardcoded values
if ($LogVerboseEnabled)     {$VerbosePreference = 'Continue'}                   # Set verbose logging based on the parameter $LogVerboseEnabled
else                        {$VerbosePreference = 'SilentlyContinue'}
#endregion

#region ---------------------------------------------------[Static Variables]------------------------------------------------------
# Constants
[string]$UsersGroupSid  = "S-1-5-32-545"    # Built-in Users group, used for scheduled task
[string]$SystemUserSid  = "S-1-5-18"        # SYSTEM account, used for creating scheduled task
[int]$LdapPort          = 389               # LDAP port for AD queries
[int]$LdapTimeoutMs     = 2000              # Timeout for LDAP connectivity test in milliseconds

# Determine execution mode based on script filename only
[string]$ExecutionMode = switch -Wildcard (Split-Path $PSCommandPath -Leaf) {
    "*detect*"    { "Detection"; break }   # Stops searching after match
    "*remediat*"  { "Remediation"; break } 
    default       { "Standalone" }
}
# Determine object type based on first mapping object and set namings accordingly
if (-not $MapObjects) { throw "MapObjects array is empty or not defined" }
$ObjectType = switch ($MapObjects[0]) {
    { $_.ContainsKey('Letter') }      { 'Drive'; break }
    { $_.ContainsKey('PrinterName') } { 'Printer'; break }
    default { throw "Unknown MapObject type: First object must contain 'Letter' or 'PrinterName' key" }
}
# Set Names and Paths based on ObjectType for scripts and scheduled task
[string]$TaskName           = "Intune$($ObjectType)Mapping"
[string]$TaskDescription    = "Map $($ObjectType) with script from Intune"
[string]$ScriptSavePath     = $(Join-Path -Path $CorpDataPath -ChildPath "scripts\$($TaskName).ps1")
[string]$vbsSavePath        = $(Join-Path -Path $CorpDataPath -ChildPath "scripts\$($TaskName).vbs")
[string]$VersionFilePath    = $(Join-Path -Path $CorpDataPath -ChildPath "scripts\$($TaskName).version")
# ==========> Logging (Invoke-TboneLog) <==============================================================================
if ([string]::IsNullOrWhiteSpace($LogName)) { $LogName = $TaskName }
#endregion

#region ---------------------------------------------------[Import Modules and Extensions]-----------------------------------------
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
function Test-MapObjectValidation {
<#
.SYNOPSIS
    Validates custom mapping objects (Drives/Printers) for required properties and syntax.
.DESCRIPTION
    Throws on first invalid object to ensure configuration errors are caught early.
.NOTES
    Author:  @MrTbone_se (T-bone Granheden)
    Version: 1.0
    
    Version History:
    1.0 - Initial version
#>
    [CmdletBinding()]
    param ([Parameter(Mandatory)][array]$MapObjects)

    # Regex patterns for validation
    $NameRegex      = '[<>:"/\\|?*]'
    $PathRegex      = '^\\\\[\w.\-]+\\[\w.\-$]+(?:\\[\w.\-$ ]+)*$'
    $LetterRegex    = '^[A-Za-z]$'
    
    $i = 0
    foreach ($o in $MapObjects) {
        $i++; $e = @()
        $p = $o['Path']
        $validPath = $p -and $p -match $PathRegex
        
        if ($o.ContainsKey('Letter')) {
            if ($o['Letter'] -is [string]) { $o['Letter'] = $o['Letter'].TrimEnd(':') }
            if ($o['Letter'] -notmatch $LetterRegex)            { $e += "Invalid Letter '$($o['Letter'])'" }
            if ($o['Persistent'] -isnot [bool])                 { $e += "Persistent must be `$true or `$false" }
            if (-not $validPath)                                { $e += "Invalid/Missing Path '$p'" }
            if ($o['Label'] -and $o['Label'] -match $NameRegex) { $e += "Label contains illegal characters" }
        }
        elseif ($o.ContainsKey('PrinterName')) {
            if ([string]::IsNullOrWhiteSpace($o['PrinterName'])) { $e += "Missing/Empty PrinterName" }
            elseif ($o['PrinterName'] -match $NameRegex)         { $e += "PrinterName contains illegal characters" }
            if ($o['Default'] -isnot [bool])                     { $e += "Default must be `$true or `$false" }
            if (-not $validPath)                                 { $e += "Invalid/Missing Path '$p'" }
        }
        else { $e += "Unknown Type: Must have 'Letter' or 'PrinterName'" }
        if ($o['ADGroups'] -and $o['ADGroups'] -match $NameRegex) { $e += "ADGroups contains illegal characters" }
        if ($e.Count -gt 0) { throw "MapObject[$i] validation failed: $($e -join ', ')" }
    }
    return $MapObjects
}
function Get-ADGroupMemberships {
<#
.SYNOPSIS
    Gets the AD group memberships for the current user using LDAP.
.DESCRIPTION
    Queries Active Directory via LDAP to get all group memberships (including nested) for the currently logged-in user.
    This is due to the fact that in Windows there is no list of group memberships available locally on a cloud native device
    It assumes domain connectivity, therwise it will not be able to map drives and printers based on group membership.
.NOTES
    Author:  @MrTbone_se (T-bone Granheden)
    Version: 2.0

    Version History:
    1.0 - Initial version
    2.0 - Modified connectivity test, added primary group and improved error handling
#>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[String]])]
    param(
        [Parameter(Mandatory = $false,          HelpMessage='Domain to search for AD group memberships (e.g., ''contoso.com'')')]
        [string]$Domain = $env:USERDNSDOMAIN
    )
    
    begin {
        $TCPClient           = $null
        $ADsearcher          = $null
        $UserResult          = $null
        $GroupsResults       = $null
        $PrimaryGroupResult  = $null
        $GroupMembershipList = [System.Collections.Generic.List[String]]::new()
    }
    
    process {
        try {
            # Validate and set domain - use fallback if empty
            if ([string]::IsNullOrEmpty($Domain)) {
                $Domain = $env:USERDNSDOMAIN
                if ([string]::IsNullOrEmpty($Domain)) {
                    Write-Error "No domain specified and USERDNSDOMAIN environment variable is empty"
                    return $GroupMembershipList
                }
            }
            Write-Verbose "Using domain: $Domain"
            
            # Get current user's UPN - with fallback for hybrid scenarios
            $UserPrincipalName = try { whoami /upn 2>$null } catch { $null }
            if (-not $UserPrincipalName -or $UserPrincipalName -notlike "*@*") {
                Write-Error "Failed to enumerate UserPrincipalName - user may not be domain-joined"
                return $GroupMembershipList
            }
            Write-Verbose "Success to enumerate UserPrincipalName: $UserPrincipalName"
            
            # Test LDAP connectivity with fast TCP test (timeout after 2 seconds)
            try {
                $TCPClient = [System.Net.Sockets.TcpClient]::new()
                $connectTask = $TCPClient.ConnectAsync($Domain, $LdapPort)
                $waitResult = $connectTask.Wait($LdapTimeoutMs)
                if (-not $waitResult) {
                    Write-Error "Failed to connect to domain controller for $Domain (timeout after $LdapTimeoutMs ms)"
                    return $GroupMembershipList
                }
                if ($connectTask.IsFaulted) {
                    Write-Error "Failed to connect to domain controller for $Domain with error: $($connectTask.Exception.GetBaseException().Message)"
                    return $GroupMembershipList
                }
                Write-Verbose "Success to connect to domain controller for $Domain"
            }
            catch {
                Write-Error "Failed to connect to domain controller for $Domain with error: $_"
                return $GroupMembershipList
            }
            finally {
                if ($TCPClient) { 
                    try { $TCPClient.Dispose() } catch { }
                }
            }
            
            # Create DirectorySearcher and find user
            $ADsearcher = [System.DirectoryServices.DirectorySearcher]::new()
            $ADsearcher.SearchRoot = [ADSI]"LDAP://$Domain"
            $ADsearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
            $ADsearcher.ServerTimeLimit = [TimeSpan]::FromSeconds(30)
            $escapedUPN = $UserPrincipalName -replace '([\\*\(\)\x00/])','\\$1' # Escape LDAP special characters
            $ADsearcher.Filter = "(userprincipalname=$escapedUPN)"
            $null = $ADsearcher.PropertiesToLoad.Add("distinguishedname")
            $null = $ADsearcher.PropertiesToLoad.Add("primarygroupid")
            $UserResult = $ADsearcher.FindOne()
            if (-not $UserResult -or -not $UserResult.Properties["distinguishedname"]) {
                Write-Error "Failed to find user $UserPrincipalName in directory"
                return $GroupMembershipList
            }
            
            # Query nested group memberships using LDAP_MATCHING_RULE_IN_CHAIN
            $distinguishedName = $UserResult.Properties["distinguishedname"][0]
            $escapedDN = $distinguishedName -replace '([\\*\(\)\x00/])','\\$1' # Escape LDAP special characters
            $ADsearcher.Filter = "(member:1.2.840.113556.1.4.1941:=$escapedDN)"
            $ADsearcher.PropertiesToLoad.Clear()
            $null = $ADsearcher.PropertiesToLoad.Add("name")
            $GroupsResults = $ADsearcher.FindAll()
            if ($GroupsResults.Count -gt 0) {
                foreach ($result in $GroupsResults) {
                    $groupName = $result.Properties["name"]
                    if ($groupName.Count -gt 0) { $GroupMembershipList.Add($groupName[0]) }
                }
            }
            
            # Add primary group (e.g., "Domain Users") - not returned by LDAP_MATCHING_RULE_IN_CHAIN
            $primaryGroupID = $UserResult.Properties["primarygroupid"]
            if ($primaryGroupID.Count -gt 0) {
                $domainSID = ([ADSI]"LDAP://$Domain").objectSid[0]
                $domainSIDString = (New-Object System.Security.Principal.SecurityIdentifier($domainSID, 0)).Value
                $primaryGroupSID = "$domainSIDString-$($primaryGroupID[0])"
                $ADsearcher.Filter = "(objectSid=$primaryGroupSID)"
                $ADsearcher.PropertiesToLoad.Clear()
                $null = $ADsearcher.PropertiesToLoad.Add("name")
                $PrimaryGroupResult = $ADsearcher.FindOne()
                if ($PrimaryGroupResult -and $PrimaryGroupResult.Properties["name"].Count -gt 0) {
                    $GroupMembershipList.Add($PrimaryGroupResult.Properties["name"][0])
                }
            }
            
            if ($GroupMembershipList.Count -gt 0) {
                Write-Verbose "Success to collect user group memberships, found $($GroupMembershipList.Count) groups"
            }
            else {
                Write-Verbose "No group memberships found for user $UserPrincipalName"
            }
            return $GroupMembershipList
        }
        catch {
            Write-Error "Failed to collect user group memberships with error: $_"
            return $GroupMembershipList
        }
    }
    
    end {
        # Dispose of COM objects to prevent memory leaks
        if ($PrimaryGroupResult) { $PrimaryGroupResult.Dispose() }
        if ($UserResult) { $UserResult.Dispose() }
        if ($GroupsResults) { $GroupsResults.Dispose() }
        if ($ADsearcher) { $ADsearcher.Dispose() }
    }
}
function New-PrinterMapping {
<#
.SYNOPSIS
    Maps a network printers for the current user.
.DESCRIPTION
    Maps a network printer for the current user. If the printer already exists,
    it verifies if the default state matches the desired state.
    If not, it removes and remaps the printer with the correct default state.
.NOTES
    Author:  @MrTbone_se (T-bone Granheden)
    Version: 2.0

    Version History:
    1.0 - Initial version
    2.0 - Modified structure and improved error handling
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Friendly name of the printer for logging purposes")]
        [string]$PrinterName,
        
        [Parameter(Mandatory = $true, HelpMessage = "UNC path to the network printer (e.g., '\\\\printserver\\printername')")]
        [string]$PrinterPath,
        
        [Parameter(Mandatory = $false, HelpMessage = "Set this printer as the default printer. Default is false")]
        [bool]$PrinterDefault = $false
    )
    
    begin {
        $ExistingPrinter = $null
        $PrinterCim      = $null
    }
    
    process {
        Write-Verbose "Processing printer: $PrinterName ($PrinterPath)"
        
        # Helper function to set default printer
        $SetDefaultPrinter = {
            if (-not $PrinterDefault) { return $true }
            $DefaultPrinterCim = $null
            try {
                $DefaultPrinterCim = Get-CimInstance -Class Win32_Printer -Filter "Name='$($PrinterPath -replace '\\','\\\\')' " -EA Stop
                $null = Invoke-CimMethod -InputObject $DefaultPrinterCim -MethodName SetDefaultPrinter -EA Stop
                Write-Verbose "Success to set printer '$PrinterName' as default"
                return $true
            }
            catch {
                Write-Warning "Failed to set printer '$PrinterName' as default with error: $_"
                return $false
            }
            finally {
                if ($DefaultPrinterCim) {
                    Remove-Variable -Name DefaultPrinterCim -ErrorAction SilentlyContinue
                }
            }
        }
        
        # Check if printer already exists
        $ExistingPrinter = Get-Printer -Name $PrinterPath -EA SilentlyContinue
        
        if ($ExistingPrinter) {
            Write-Verbose "Found existing printer '$PrinterName' with path $PrinterPath"
            
            # Verify default state matches desired state
            try {
                $PrinterCim = Get-CimInstance -Class Win32_Printer -Filter "Name='$($PrinterPath -replace '\\','\\\\')' " -EA Stop
                if ($PrinterCim -and $PrinterCim.Default -eq $PrinterDefault) {
                    Write-Verbose "Printer '$PrinterName' already correctly mapped with default=$PrinterDefault"
                    return
                }
            }
            catch {
                Write-Warning "Failed to query existing printer state: $_"
            }
            finally {
                if ($PrinterCim) {
                    Remove-Variable -Name PrinterCim -ErrorAction SilentlyContinue
                }
            }
            
            # Need to remap - remove existing first
            $null = Remove-Printer -Name $PrinterPath -EA SilentlyContinue -EV ErrorVar
            if ($ErrorVar.Count -gt 0) {
                Write-Error "Failed to remove existing printer '$PrinterName' with error: $ErrorVar"
                return
            }
            Write-Verbose "Removed existing printer '$PrinterName' to remap with correct default state"
        }
        
        # Add the printer
        $null = Add-Printer -ConnectionName $PrinterPath -EA SilentlyContinue -EV ErrorVar
        if ($ErrorVar.Count -gt 0) {
            Write-Error "Failed to add printer '$PrinterName' ($PrinterPath) with error: $ErrorVar"
            return
        }
        Write-Verbose "Success to add printer '$PrinterName' ($PrinterPath)"
        
        # Set as default if requested
        $null = & $SetDefaultPrinter
    }
    
    end {}
}
function New-DriveMapping {
<#
.SYNOPSIS
    Maps a network drive for the current user.
.DESCRIPTION
    Maps a network drive for the current user. If the drive already exists,
    it verifies if the path matches the desired path.
    If not, it removes and remaps the drive with the correct path.
.NOTES
    Author:  @MrTbone_se (T-bone Granheden)
    Version: 2.0

    Version History:
    1.0 - Initial version
    2.0 - Modified structure and improved error handling
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Drive letter to map (e.g., 'S' for S:)")]
        [ValidatePattern('^[A-Z]$')]
        [string]$DriveLetter,
        
        [Parameter(Mandatory = $true, HelpMessage = "UNC path to the network share (e.g., '\\\\fileserver\\share')")]
        [string]$DrivePath,
        
        [Parameter(Mandatory = $false, HelpMessage = "Friendly label for the drive shown in Explorer")]
        [string]$DriveLabel = "",
        
        [Parameter(Mandatory = $false, HelpMessage = "Make the drive mapping persistent across reboots. Default is true")]
        [bool]$DrivePersistent = $true
    )
    
    begin {
        $ExistingDrive = $null
    }
    
    process {
        Write-Verbose "Processing drive: $DriveLetter`: ($DrivePath)"
        
        # Helper scriptblock to create drive and set label
        $CreateDriveAndSetLabel = {
            $null = New-PSDrive -PSProvider FileSystem -Name $DriveLetter -Root $DrivePath -Description $DriveLabel -Persist:$DrivePersistent -Scope Global -EA SilentlyContinue -EV ErrorVar
            if ($ErrorVar.Count -gt 0) {
                Write-Error "Failed to add drive '$DriveLetter`:' ($DrivePath) with error: $ErrorVar"
                return $false
            }
            Write-Verbose "Success to add drive '$DriveLetter`:' ($DrivePath)"
            
            # Set the drive label in Explorer if specified
            if (-not [string]::IsNullOrEmpty($DriveLabel)) {
                $ShellApp = $null
                try {
                    $ShellApp = New-Object -ComObject Shell.Application
                    $DriveNamespace = $ShellApp.NameSpace("$DriveLetter`:")
                    if ($DriveNamespace) {
                        $DriveNamespace.Self.Name = $DriveLabel
                        Write-Verbose "Success to set drive '$DriveLetter`:' label to '$DriveLabel'"
                    }
                    else {
                        Write-Warning "Failed to get namespace for drive '$DriveLetter`:' to set label"
                    }
                }
                catch {
                    Write-Warning "Failed to set drive '$DriveLetter`:' label to '$DriveLabel' with error: $_"
                }
                finally {
                    if ($ShellApp) { 
                        try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($ShellApp) | Out-Null } 
                        catch { }
                    }
                }
            }
            return $true
        }
        
        # Check if drive already exists
        $ExistingDrive = Get-PSDrive -Name $DriveLetter -EA SilentlyContinue
        if (-not $ExistingDrive) {
            $null = & $CreateDriveAndSetLabel
            return
        }
        
        # Drive exists - check if path matches
        Write-Verbose "Found existing drive '$DriveLetter`:'"
        $ExistingRoot = $ExistingDrive.DisplayRoot
        if (-not $ExistingRoot) { $ExistingRoot = $ExistingDrive.Root }
        if ($ExistingRoot -eq $DrivePath) {
            Write-Verbose "Drive '$DriveLetter`:' already correctly mapped to '$DrivePath'"
            return
        }
        
        # Path differs - need to remap
        Write-Verbose "Drive '$DriveLetter`:' mapped to '$ExistingRoot' but should be '$DrivePath' - remapping"
        # Remove existing drive using net use (handles persistent mappings better than Remove-PSDrive)
        $null = net use "$DriveLetter`:" /delete 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to remove existing drive '$DriveLetter`:' (exit code: $LASTEXITCODE)"
            return
        }
        Write-Verbose "Success to remove existing drive '$DriveLetter`:'"
        
        # Create the new drive
        $null = & $CreateDriveAndSetLabel
    }
    
    end {}
}
#endregion

#region ---------------------------------------------------[[Script Execution]------------------------------------------------------
# Start T-Bone custom logging (can be removed if you don't want to use T-Bone logging)
Invoke-TboneLog -LogMode Start -Logname $LogName -LogToGUI $LogToGUI -LogToEventlog $LogToEventlog -LogEventIds $LogEventIds -LogToDisk $LogToDisk -LogPath $LogToDiskPath -LogToHost $LogToHost

# Check if running as SYSTEM - needed in finally block for exit handling
$RunningAsSystem = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq $SystemUserSid
[bool]$IsCompliant = $true

try {
    # Validate mapping objects and throw on first error
    if (-not $MapObjects -or $MapObjects.Count -eq 0) { throw "MapObjects array is empty or not defined" }
    $MapObjects = Test-MapObjectValidation -MapObjects $MapObjects
    
    # If running as system, create scheduled task to run the powershell script as user
    if ($RunningAsSystem) {
        if ($ExecutionMode -eq "Detection") { Write-Verbose "Running in detection mode - will check compliance only" }
        
        # Check and create scripts folder
        $ScriptsFolder = Join-Path -Path $CorpDataPath -ChildPath 'scripts'
        $NeedsFolderCreation = -not (Test-Path $ScriptsFolder)
        if ($NeedsFolderCreation) {
            Write-Verbose "Scripts folder does not exist: $ScriptsFolder"
            if ($ExecutionMode -eq "Detection") { $IsCompliant = $false }
            else {
                try {
                    [System.IO.Directory]::CreateDirectory($ScriptsFolder) | Out-Null
                    Write-Verbose "Success to create folder: $ScriptsFolder"
                }
                catch { Write-Error "Failed to create folder with error: $_" }
            }
        }
        
        # Check PowerShell script
        $NeedsScriptUpdate = $true
        if (-not $ForceReplaceAll -and (Test-Path $VersionFilePath)) {
            try {
                $SavedVersion = [version](Get-Content -Path $VersionFilePath -Raw -ErrorAction Stop).Trim()
                if ($SavedVersion -ge $MappingVersion) {
                    $NeedsScriptUpdate = $false
                    Write-Verbose "Script version ($SavedVersion) is current or newer than ($MappingVersion)"
                }
                else { Write-Verbose "Script version ($SavedVersion) is older than ($MappingVersion)" }
            }
            catch { Write-Warning "Failed to read version file: $_" }
        }
        elseif ($ForceReplaceAll) { Write-Verbose "ForceReplaceAll enabled - will update script" }
        else { Write-Verbose "No version file found - will create script" }

        # Update script if needed
        if ($NeedsScriptUpdate) {
            if ($ExecutionMode -eq "Detection") { $IsCompliant = $false }
            else {
                try {
                    Get-Content -Path $PSCommandPath | Out-File -FilePath $ScriptSavePath -Force -ErrorAction Stop
                    $MappingVersion.ToString() | Out-File -FilePath $VersionFilePath -Force -ErrorAction Stop
                    Write-Verbose "Success to save script and version ($MappingVersion)"
                }
                catch { Write-Error "Failed to save script or version file with error: $_" }
            }
        }
        
        # Check and update VBScript helper file (to run PowerShell script silently in task scheduler)
        $NeedsVbsUpdate = $ForceReplaceAll -or -not (Test-Path $vbsSavePath)
        if ($NeedsVbsUpdate) {
            Write-Verbose "VBScript needs to be created or updated"
            if ($ExecutionMode -eq "Detection") { $IsCompliant = $false }
            else {
                try {
                    $vbsScript = @(
                        'Dim shell,fso,file'
                        'Set shell=CreateObject("WScript.Shell")'
                        'Set fso=CreateObject("Scripting.FileSystemObject")'
                        'strPath=WScript.Arguments.Item(0)'
                        'If fso.FileExists(strPath) Then'
                        '    set file=fso.GetFile(strPath)'
                        '    strCMD="powershell -nologo -executionpolicy ByPass -command " & Chr(34) & "&{" & file.ShortPath & "}" & Chr(34)'
                        '    shell.Run strCMD,0'
                        'End If'
                    ) -join [Environment]::NewLine
                    $vbsScript | Out-File -FilePath $vbsSavePath -Force -ErrorAction Stop
                    
                    # Validate file was created
                    if (-not (Test-Path $vbsSavePath)) {
                        throw "VBScript file was not created at $vbsSavePath"
                    }
                    Write-Verbose "Success to save VBScript"
                }
                catch { 
                    Write-Error "Failed to save VBScript with error: $_"
                    if ($ExecutionMode -eq "Remediation") { $IsCompliant = $false }
                }
            }
        }
        else { Write-Verbose "VBScript already exists" }
        
        # Check and update scheduled task
        $NeedsTaskCreation = $ForceReplaceAll -or -not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
        if ($NeedsTaskCreation) {
            Write-Verbose "Scheduled task needs to be created or updated"
            if ($ExecutionMode -eq "Detection") { $IsCompliant = $false }
            else {
                try {
                    # Create event trigger for network connection
                    $class = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace root/Microsoft/Windows/TaskScheduler
                    $Trigger_onEvent = $class | New-CimInstance -ClientOnly
                    $Trigger_onEvent.Enabled = $true
                    $Trigger_onEvent.Subscription = @(
                        '<QueryList>'
                        '  <Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational">'
                        '    <Select Path="Microsoft-Windows-NetworkProfile/Operational">*[System[EventID=10000]]</Select>'
                        '  </Query>'
                        '</QueryList>'
                    ) -join [Environment]::NewLine
                    # Create logon trigger
                    $Trigger_atLogon = New-ScheduledTaskTrigger -AtLogOn
                    # Set task to execute in users context
                    $principal = New-ScheduledTaskPrincipal -GroupId $UsersGroupSid -Id "Author"
                    # Set task to call the vbscript helper and pass the PowerShell script as argument
                    $wscriptPath = Join-Path -Path $env:SystemRoot -ChildPath "System32\wscript.exe"
                    $action = New-ScheduledTaskAction -Execute $wscriptPath -Argument "`"$vbsSavePath`" `"$ScriptSavePath`""
                    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
                    
                    # Register scheduled task
                    $null = Register-ScheduledTask -TaskName $TaskName -Trigger $Trigger_atLogon, $Trigger_onEvent -Action $action -Principal $principal -Settings $settings -Description $TaskDescription -Force -ErrorAction Stop
                    Write-Verbose "Success to register scheduled task"
                    
                    # Start the scheduled task immediately to map drive now
                    Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
                    Write-Verbose "Success to start scheduled task"
                }
                catch { 
                    Write-Error "Failed to create or start scheduled task with error: $_"
                    if ($ExecutionMode -eq "Remediation") { $IsCompliant = $false }
                }
            }
        }
        else { Write-Verbose "Scheduled task already exists" }
    }
    # If running as user (as a scheduled task), map objects
    else {
        Write-Host "Start to map $ObjectType as user"
        
        # Get user group memberships - required for mapping
        try {
            $groupMemberships = Get-ADGroupMemberships -Domain $DomainName
            if (-not $groupMemberships -or $groupMemberships.Count -eq 0) {
                Write-Warning "Failed to get user group memberships - cannot map $ObjectType"
                Write-Host "Task completed - $TaskName (no group memberships)"
                throw "NoGroupMemberships"
            }
            Write-Verbose "Success to collect $($groupMemberships.Count) group memberships"
        }
        catch [System.Management.Automation.RuntimeException] {
            if ($_.Exception.Message -eq "NoGroupMemberships") { return }
            Write-Error "Failed to retrieve group memberships: $_"
            Write-Host "Task failed - $TaskName (group membership query error)"
            return
        }
        
        # Filter mappings based on user's group memberships
        $TargetUserMappings = @($MapObjects | Where-Object {
            if ($null -eq $_.ADGroups -or $_.ADGroups -eq "") { return $true }
            foreach ($ADGroup in $_.ADGroups -split ";") {
                if ($groupMemberships -contains $ADGroup) { return $true }
            }
            return $false
        })
        
        if ($TargetUserMappings.Count -eq 0) {
            Write-Verbose "No $ObjectType to map for current user's groups"
            Write-Host "Task completed - $TaskName (no mappings for user)"
        }
        else {
            Write-Verbose "Found $($TargetUserMappings.Count) $ObjectType to map"
        }
        
        # Map each drive/printer with error handling (skip if no mappings)
        $successCount = 0
        $failureCount = 0
        if ($TargetUserMappings.Count -gt 0) {
            foreach ($mapping in $TargetUserMappings) {
                try {
                    if ($ObjectType -eq "Drive") {
                        New-DriveMapping -Letter $mapping.Letter -DrivePath $mapping.Path -Label $mapping.Label -Persistent $mapping.Persistent
                        $successCount++
                    }
                    else {
                        New-PrinterMapping -PrinterName $mapping.PrinterName -PrinterPath $mapping.Path -PrinterDefault $mapping.Default
                        $successCount++
                    }
                }
                catch {
                    $failureCount++
                    Write-Warning "Failed to map $ObjectType '$($mapping.Letter)$($mapping.PrinterName)': $_"
                }
            }
        }
        if ($successCount -gt 0 -or $failureCount -gt 0) {
            Write-Verbose "Mapping results: $successCount succeeded, $failureCount failed"
        }
        
        # Remove stale mappings (drives/printers not in current configuration)
        if ($RemoveStaleObjects -and $TargetUserMappings.Count -gt 0) {
            if ($ObjectType -eq "Drive") {
                # Get only network-mapped drives that have DisplayRoot starting with \\
                $NetworkDrives = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | 
                    Where-Object { $_.DisplayRoot -like "\\*" }
                
                foreach ($drive in $NetworkDrives) {
                    if ($drive.Name -notin $TargetUserMappings.Letter) {
                        Write-Verbose "Removing stale drive $($drive.Name): ($($drive.DisplayRoot))"
                        $null = net use "$($drive.Name):" /delete 2>&1
                        if ($LASTEXITCODE -eq 0) { Write-Verbose "Success to remove stale drive $($drive.Name):" }
                        else { Write-Warning "Failed to remove stale drive $($drive.Name): (exit code: $LASTEXITCODE)" }
                    }
                }
            }
            else {
                # Get only network printers that have a name starting with \\
                $NetworkPrinters = Get-Printer -ErrorAction SilentlyContinue | 
                    Where-Object { $_.Name -like "\\*" }
                
                foreach ($printer in $NetworkPrinters) {
                    if ($printer.Name -notin $TargetUserMappings.Path) {
                        Write-Verbose "Removing stale printer $($printer.Name)"
                        try {
                            Remove-Printer -Name $printer.Name -ErrorAction Stop
                            Write-Verbose "Success to remove stale printer $($printer.Name)"
                        }
                        catch { Write-Warning "Failed to remove stale printer $($printer.Name): $_" }
                    }
                }
            }
        }
        
        # Ensure mapped drives have persistent flag set in registry
        if ($ObjectType -eq "Drive" -and $TargetUserMappings.Count -gt 0) {
            foreach ($DriveLetter in $TargetUserMappings.Letter) {
                $regPath = "HKCU:\Network\$DriveLetter"
                if (Test-Path $regPath) {
                    $null = New-ItemProperty -Path $regPath -Name ConnectionType -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue
                }
            }
        }
        
        if ($TargetUserMappings.Count -gt 0) {
            Write-Host "Task completed - $TaskName mapped $($TargetUserMappings.Count) $ObjectType for user"
        }
    }
}
catch {
    Write-Error "Script execution failed with error: $_"
    $IsCompliant = $false
}
finally {
    # Always restore original preferences
    $ErrorActionPreference = $script:OriginalErrorActionPreference
    $VerbosePreference = $script:OriginalVerbosePreference
    $WhatIfPreference = $script:OriginalWhatIfPreference
    
    # End logging and collect logs from memory
    $Log = Invoke-TboneLog -LogMode Stop
    
    # Return results and exit code (only for SYSTEM context running as Intune remediation)
    if ($RunningAsSystem) {
        switch ($ExecutionMode) {
            "Detection" {
                if ($IsCompliant) { Write-Output "Compliant - $Log"; Exit 0 }
                else { Write-Output "Non-Compliant - $Log"; Exit 1 }
            }
            "Remediation" {
                if ($IsCompliant) { Write-Output "Remediated - $Log"; Exit 0 }
                else { Write-Output "Remediation failed - $Log"; Exit 1 }
            }
            "Standalone" {
                Write-Output "Completed - $Log"; Exit 0
            }
        }
    }
}
#endregion
