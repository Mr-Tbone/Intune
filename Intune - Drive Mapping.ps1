<#PSScriptInfo
.VERSION        1.2.1
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
    1.2.1 2026-01-19 Fixed small bugs and syntax errors
#>

<#
.SYNOPSIS
    This script will map drives and printers for cloud native devices
    It can be used as both script and remediation script in Intune. 
    I prefer to use it as a remediation script to be able to update with new versions.

.DESCRIPTION
    This script connects to Azure AD with the old AzureAD module
    Then assign the listed Microsoft Graph API permissions to the specified Managed Identity.

.EXAMPLE
    .\Set-AzureADManagedIdentityPermissions.ps1
    Will set the required Microsoft Graph API permissions on the specified Managed Identity that is specified in the script parameters defaults.

.EXAMPLE
    .\Set-AzureADManagedIdentityPermissions.ps1 -tenantID "your-tenant-id" -ManagedIdentity "Your-Managed-Identity-Name" -Permissions @("User.Read.All", "DeviceManagementManagedDevices.Read.All")
    Will set the specified Microsoft Graph API permissions on the specified Managed Identity.

.NOTES
    Please feel free to use this, but make sure to credit @MrTbone_se as the original author

.LINK
    https://tbone.se
#>

#region ---------------------------------------------------[Set Script Requirements]-----------------------------------------------
Set-StrictMode -Version Latest
#endregion

#region ---------------------------------------------------[Modifiable Parameters and Defaults]------------------------------------
# Customizations
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Path where script and logs will be stored")]
    [String]$CorpDataPath = "C:\ProgramData\CorpData",

    [Parameter(Mandatory = $false, HelpMessage = "Domain to search for AD group memberships (e.g., 'contoso.com')")]
    [String]$SearchRoot = "tbone.se",

    [Parameter(Mandatory = $false, HelpMessage = "Remove stale drive/printer mappings that are no longer in the configuration")]
    [Bool]$RemoveStaleObjects = $false,

    [Parameter(Mandatory = $false, HelpMessage = "Force replace all scripts and scheduled tasks even if version is the same")]
    [Bool]$ForceReplaceAll = $false,

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
$MapObjects+=@{Letter="C";Persistent=$true;Path="\\fileserver.tbone.se\Consult"     ;ADGroups=	"Consultants"   ;Label="Consultants"}
$MapObjects+=@{Letter="W";Persistent=$true;Path="\\fileserver.tbone.se\Common"	    ;ADGroups=	"Loc_ESC"       ;Label=""           }
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

#region ---------------------------------------------------[Static Variables]------------------------------------------------------

$global:searchRoot = $SearchRoot    # Set global search root for AD group membership lookups
$groupMemberships = $null
$compliance = @()
$compliance += $true
[string]$Global:EventType  = "information"
[int32]$Global:EventId     = 10
if ($PSCommandPath -like "*detect*"){[Bool]$Remediation = $false}
else{[Bool]$Remediation = $true}
if ($MapObjects -and $MapObjects[0] -and $MapObjects[0].Keys -contains 'Letter') {[string]$ObjectType = "Drive"}
else {[string]$ObjectType = "Printer"}
[string]$TaskName 		    = "Intune$($ObjectType)Mapping"
[string]$TaskDescription    = "Map $($ObjectType) with script from Intune"
[string]$ScriptSavePath     = $(Join-Path -Path $CorpDataPath -ChildPath "scripts\$($TaskName).ps1")
[string]$vbsSavePath        = $(Join-Path -Path $CorpDataPath -ChildPath "scripts\$($TaskName).vbs")
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
function Get-ADGroupMembership {
    <#
    .SYNOPSIS
        Gets the AD group memberships for the current user using LDAP.
    .DESCRIPTION
        Queries Active Directory via LDAP to get all group memberships (including nested)
        for the currently logged-in user. Compatible with PowerShell 5.1 - 7.x.
    .OUTPUTS
        System.Collections.Generic.List[String] - List of group names, or $null on failure
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[String]])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Domain = $global:searchRoot
    )
    
    begin {
        $searcher = $null
        $results = $null
        # Helper function for consistent logging
        function Write-Log {
            param([string]$Level, [string]$Message)
            Write-Verbose -Verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -Format 'HH:mm:ss'),$Level,$Message"
        }
    }
    
    process {
        try {
            # Validate and set domain - use fallback if empty
            if ([string]::IsNullOrEmpty($Domain)) {
                $Domain = $env:USERDNSDOMAIN
                if ([string]::IsNullOrEmpty($Domain)) {
                    Write-Log "error" "No domain specified and USERDNSDOMAIN environment variable is empty"
                    $Global:EventId = 12; $Global:EventType = "Error"
                    return $null
                }
            }
            
            # Get current user's UPN
            $UserPrincipalName = try { whoami /upn 2>$null } catch { $null }
            if (-not $UserPrincipalName -or $UserPrincipalName -notlike "*@*") {
                Write-Log "error" "Failed to enumerate UserPrincipalName - user may not be domain-joined"
                $Global:EventId = 12; $Global:EventType = "Error"
                return $null
            }
            Write-Log "info" "Success to enumerate UserPrincipalName: $UserPrincipalName"
            
            # Test LDAP connectivity with faster TCP test (timeout 2 seconds)
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            try {
                $connectTask = $tcpClient.ConnectAsync($Domain, 389)
                if (-not $connectTask.Wait(2000)) {
                    Write-Log "error" "Failed to connect to domain controller for $Domain (timeout)"
                    $Global:EventId = 12; $Global:EventType = "Error"
                    return $null
                }
                Write-Log "info" "Success to connect to domain controller for $Domain"
            }
            catch {
                Write-Log "error" "Failed to connect to domain controller for $Domain with error: $_"
                $Global:EventId = 12; $Global:EventType = "Error"
                return $null
            }
            finally {
                $tcpClient.Dispose()
            }
            
            # Create DirectorySearcher and find user
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = [ADSI]"LDAP://$Domain"
            $searcher.Filter = "(userprincipalname=$UserPrincipalName)"
            $searcher.PropertiesToLoad.Add("distinguishedname") | Out-Null
            
            $userResult = $searcher.FindOne()
            if (-not $userResult) {
                Write-Log "error" "Failed to find user $UserPrincipalName in directory"
                $Global:EventId = 12; $Global:EventType = "Error"
                return $null
            }
            
            $distinguishedName = $userResult.Properties["distinguishedname"][0]
            
            # Query nested group memberships using LDAP_MATCHING_RULE_IN_CHAIN
            $searcher.Filter = "(member:1.2.840.113556.1.4.1941:=$distinguishedName)"
            $searcher.PropertiesToLoad.Clear()
            $searcher.PropertiesToLoad.Add("name") | Out-Null
            
            $results = $searcher.FindAll()
            
            if ($results -and $results.Count -gt 0) {
                $list = [System.Collections.Generic.List[String]]::new()
                foreach ($result in $results) {
                    $groupName = $result.Properties["name"][0]
                    if ($groupName) { $list.Add($groupName) }
                }
                Write-Log "info" "Success to collect user group memberships, found $($list.Count) groups"
                return $list
            }
            else {
                Write-Log "info" "No group memberships found for user $UserPrincipalName"
                return $null
            }
        }
        catch {
            Write-Log "error" "Failed to collect user group memberships with error: $_"
            $Global:EventId = 12; $Global:EventType = "Error"
            return $null
        }
    }
    
    end {
        # Dispose of COM objects to prevent memory leaks
        if ($results) { $results.Dispose() }
        if ($searcher) { $searcher.Dispose() }
    }
}
function Map-Printer {
    Param(
        [string]$PrinterName,
        [string]$Printerpath,
        [bool]$Default
    )
    Begin {}
    Process {
        $existingPrinter = $null
        # Get the existing printer
        $null = $existingPrinter = Get-Printer -Name $Printerpath -ErrorAction SilentlyContinue -ErrorVariable errorvar
        if ($errorvar.count -eq 0){
            write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,success to find existing printer already mapped with same path as $($PrinterPath)"
            # Check if the printer exists and has the correct properties
            $printer = Get-CimInstance -Class win32_printer -filter "Name='$($Printerpath -replace '\\','\\')'" -ErrorAction SilentlyContinue -ErrorVariable errorvar
            if ($existingPrinter -and $printer.default -eq $Default){
                # If it does, no need to do anything
                write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to verify existing printer $($PrinterPath) already correctly mapped"
                }
            else {
                # If it doesn't, remove it if exists
                $null = Remove-Printer -Name $Printerpath -ErrorAction SilentlyContinue -ErrorVariable errorvar
                if ($errorvar.count -eq 0){
                    write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to remove existing printer map with same path as $($PrinterPath)"
                    $null = Add-Printer -ConnectionName $PrinterPath -ErrorAction silentlycontinue -ErrorVariable errorvar
                    if ($errorvar.count -eq 0){
                        write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to add printer $($PrinterPath)"
                        # Set the new printer as the default printer if specified
                        if ($Default) {
                            $printer = Get-CimInstance -Class win32_printer -filter "Name='$($Printerpath -replace '\\','\\')'" -ErrorAction SilentlyContinue -ErrorVariable errorvar
                            if ($errorvar.count -eq 0){
                                write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to get printer to set as default on $($PrinterPath)"
                                $null = Invoke-CimMethod -InputObject $printer -MethodName SetDefaultPrinter -ErrorAction silentlycontinue -ErrorVariable errorvar
                                if ($errorvar.count -eq 0){
                                    write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to set printer $($PrinterPath) as default"
                                }
                                else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Warning,Failed to set printer $($PrinterPath) as default with error: $($errorvar)";$errorvar=$null;$Global:EventId=11;$Global:EventType="Warning"}
                            }
                            else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Warning,Failed to get printer to set as default on $($PrinterPath) with error: $($errorvar)";$errorvar=$null;$Global:EventId=11;$Global:EventType="Warning"}
                        }
                    }
                    else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Error,Failed to add printer $($PrinterPath) with error: $($errorvar)";$errorvar=$null;$Global:EventId=12;$Global:EventType="Error"}
                }
                else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Error,Failed to remove existing printer map with same path as $($PrinterPath) with error: $($errorvar)";$errorvar=$null;$Global:EventId=12;$Global:EventType="Error"}
                }
            }
        else{
            $null = Add-Printer -ConnectionName $PrinterPath -ErrorAction silentlycontinue -ErrorVariable errorvar
            if ($errorvar.count -eq 0){
                write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to add printer $($PrinterPath)"
                # Set the new printer as the default printer if specified
                if ($Default) {
                    $printer = Get-CimInstance -Class win32_printer -filter "Name='$($Printerpath -replace '\\','\\')'" -ErrorAction SilentlyContinue -ErrorVariable errorvar
                    if ($errorvar.count -eq 0){
                        write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to get printer to set as default on $($PrinterPath)"
                        $null = Invoke-CimMethod -InputObject $printer -MethodName SetDefaultPrinter -ErrorAction silentlycontinue -ErrorVariable errorvar
                        if ($errorvar.count -eq 0){
                            write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to set printer $($PrinterPath) as default"
                        }
                        else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Warning,Failed to set printer $($PrinterPath) as default with error: $($errorvar)";$errorvar=$null;$Global:EventId=11;$Global:EventType="Warning"}
                    }
                    else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Warning,Failed to get printer to set as default on $($PrinterPath) with error: $($errorvar)";$errorvar=$null;$Global:EventId=11;$Global:EventType="Warning"}
                }
            }
            else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Error,Failed to add printer $($PrinterPath) with error: $($errorvar)";$errorvar=$null;$Global:EventId=12;$Global:EventType="Error"}
        }
    }
    End {}
}
function Map-Drive {
    Param(
        [string]$Letter,
        [string]$DrivePath,
        [string]$Label,
        [bool]$Persistant
    )
    Begin {}
    Process {
        $existingDrive = $null
        # Get the existing Drive
        $existingDrive = Get-PSDrive -Name $Letter -ErrorAction SilentlyContinue -ErrorVariable errorvar
        if ($errorvar.count -eq 0){
            write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to find existing drive map with same path as $($DrivePath)"
            #Fix psDrive values to get correct compare results 
            if($existingDrive.Root -match '\$env:') {$existingDrive.Root = $ExecutionContext.InvokeCommand.ExpandString($existingDrive.Root)}
            if($existingDrive -and ($null -eq $existingDrive.Description)) {$existingDrive.Description = ""}
            #Check if the PSDrive exists and has the correct path
            if ($existingDrive.displayroot -eq $DrivePath) {
                # If it does, no need to do anything
                write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to verify existing drive $($Letter) already correctly mapped"
            }
            else {
                #If it doesn't, remove it and remap it
                Try{net use "$($Letter):" /delete #Remove-PSDrive -Name $Letter -ErrorAction silentlycontinue
                    write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success,Removed $($Letter):"}
                catch{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Error,Failed to remove $($Letter): with error: $($_.Exception.Message)";$errorvar=$null;$Global:EventId=12;$Global:EventType="error"}
                #Map the drive
                $null = New-PSDrive -PSProvider FileSystem -Name $Letter -Root $DrivePath -Description $Label -Persist:$Persistant -Scope global -ErrorAction silentlyContinue -ErrorVariable errorvar
                if ($errorvar.count -eq 0){
                    write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to add drive $($Letter):"
                    #Set the drive Label
                    (New-Object -ComObject Shell.Application -ErrorAction SilentlyContinue -ErrorVariable errorvar).NameSpace("$($Letter):").Self.Name = $Label
                    if ($errorvar.count -eq 0){write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to set drive $($Letter): Label to $($Label)"}
                    else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Warning,Failed to set drive $($Letter): Label to $($Label) with error: $($errorvar)";$errorvar=$null;$Global:EventId=11;$Global:EventType="Warning"}
                    }
                else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Error,Failed to add drive $($Letter): with error: $($errorvar)";$errorvar=$null;$Global:EventId=12;$Global:EventType="Error"}
            }
        }
        else{
            # Create the new PSDrive
            $null = New-PSDrive -PSProvider FileSystem -Name $Letter -Root $DrivePath -Description $Label -Persist:$Persistant -Scope global -ErrorAction silentlyContinue -ErrorVariable errorvar
            if ($errorvar.count -eq 0){
                write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to add drive $($Letter):"
                #Set the drive Label
                (New-Object -ComObject Shell.Application -ErrorAction SilentlyContinue -ErrorVariable errorvar).NameSpace("$($Letter):").Self.Name = $Label
                if ($errorvar.count -eq 0){write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to set drive $($Letter): Label to $($Label)"}
                else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Warning,Failed to set drive $($Letter): Label to $($Label) with error: $($errorvar)";$errorvar=$null;$Global:EventId=11;$Global:EventType="Warning"}
                }
            else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Error,Failed to add drive $($Letter): with error: $($errorvar)";$errorvar=$null;$Global:EventId=12;$Global:EventType="Error"}
        }
    }
    End {}
}
#endregion

#region ---------------------------------------------------[[Script Execution]------------------------------------------------------
# Start T-Bone custom logging (can be removed if you don't want to use T-Bone logging)
Invoke-TboneLog -Mode Start -LogToGUI $LogToGUI -LogToEventlog $LogToEventlog -LogToDisk $LogToDisk -LogPath $LogToDiskPath -LogToHost $LogToHost

# Set verbose preference if enabled
if ($LogVerboseEnabled) { $VerbosePreference = 'Continue' }

try {
    #check if running as system
    $RunningAsSystem = [bool]($(whoami -user) -match "S-1-5-18")

#If running as system, create scheduled task to run the powershell script as user
if ($RunningAsSystem) {
	#Create corpdata folder if it doesn't exist
	if (-not (Test-Path $CorpDataPath)) {
        if ($Remediation){
            $null = New-Item -ItemType Directory -Path $CorpDataPath -Force -ErrorAction silentlycontinue -ErrorVariable errorvar
            if ($errorvar.count -eq 0){write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success,Created corpdata folder"}
            else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Error,Failed to create corpdata folder with error: $($errorvar)";$errorvar=$null;$Global:EventId=12;$Global:EventType="Error"}
        }
        else {$compliance += $false}
    }
    #Create scripts and logs folder if it doesn't exist
	if (-not (Test-Path $CorpDataPath\scripts)) {
        if ($Remediation){
            $null = New-Item -ItemType Directory -Path $CorpDataPath\scripts -Force -ErrorAction silentlycontinue -ErrorVariable errorvar
            if ($errorvar.count -eq 0){write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success,Created corpdata scripts folder"}
            else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Error,Failed to create corpdata scripts folder with error: $($errorvar)";$errorvar=$null;$Global:EventId=12;$Global:EventType="Error"}
        }
        else {$compliance += $false}
    }

	Write-Host "Start to create scheduled task as system for the users"
    if (!$Remediation){write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Running in detection mode, will NOT remediate and create scheduled task"}
	# load current script and check if current script exists in corpdata folder
	$currentScript = Get-Content -Path $($PSCommandPath)
    if (!$forceReplaceAll){
        if(Test-Path $ScriptSavePath){
            $ScriptSavedVersion = Test-ScriptFileInfo -Path $ScriptSavePath -ErrorAction SilentlyContinue -ErrorVariable errorvar | Select-Object version 
            if ($errorvar.count -eq 2){write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to read saved script info in corpdata folder"}
            else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,warning,Failed to read saved script info in corpdata folder with error: $($errorvar)";$errorvar=$null;$Global:EventId=11;$Global:EventType="warning"}
            $ScriptCurrentVersion = Test-ScriptFileInfo -path $MyInvocation.MyCommand.Path -ErrorAction SilentlyContinue -ErrorVariable errorvar | Select-Object version
            if ($errorvar.count -eq 2){write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to read current script info"}
            else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,warning,Failed to read current script info with error: $($errorvar)";$errorvar=$null;$Global:EventId=11;$Global:EventType="warning"}
            #Check if current script is the same as saved script
            if([version]$ScriptSavedVersion.version -ge [version]$ScriptCurrentVersion.version){
                $ReplaceScript = $False
                write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,ScriptSavedVersion = $($ScriptSavedVersion.version) is the same or newer than ScriptCurrentVersion = $($ScriptCurrentVersion.version)"
                }
            else{$ReplaceScript = $True
                write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),System,ScriptSavedVersion = $($ScriptSavedVersion.version) differ from ScriptCurrentVersion = $($ScriptCurrentVersion.version)"
            }
        }
        else {
            $ReplaceScript = $True
            write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,No existing saved script found"
        }
    }
    else {$ReplaceScript = $true
        write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,ForceReplaceScript is set to true, will replace existing script in corpdata folder"
    }
    if ($ReplaceScript){
        if ($Remediation){
            #Save current script to corpdata folder
            $currentScript | Out-File -FilePath $ScriptSavePath -Force -ErrorAction SilentlyContinue -ErrorVariable errorvar
            if ($errorvar.count -eq 0){
                write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to save the script in corpdata folder"
            
            }
            else{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),error,Failed to save the script in corpdata folder with error: $($errorvar)";$errorvar=$null;$Global:EventId=11;$Global:EventType="warning"}
        }
            else {
            write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Running in detection mode, Script needs to be replaced but will NOT remediate"
            $compliance += $false}
    }
    #Check if vbscript already exist
    if(!(Test-Path $vbsSavePath) -or $forceReplaceAll){
        if ($Remediation){ 
    # Create dummy vbscript to hide PowerShell Window popping up at logon
            $vbsScript = "
                Dim shell,fso,file
                Set shell=CreateObject(`"WScript.Shell`")
                Set fso=CreateObject(`"Scripting.FileSystemObject`")
                strPath=WScript.Arguments.Item(0)
                If fso.FileExists(strPath) Then
                set file=fso.GetFile(strPath)
                strCMD=`"powershell -nologo -executionpolicy ByPass -command `" & Chr(34) & `"&{`" &_
                file.ShortPath & `"}`" & Chr(34)
                shell.Run strCMD,0
                End If
                "
	        $vbsScript | Out-File -FilePath $vbsSavePath -Force -ErrorAction SilentlyContinue -ErrorVariable errorvar
            if ($errorvar.count -eq 0){write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to save the vbscript in corpdata folder"}
            else{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Error,Failed to save vbscript in corpdata folder with error: $($errorvar)";$errorvar=$null;$Global:EventId=12;$Global:EventType="error"}
            }
        else {
            write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Running in detection mode, vbscript needs to be replaced but will NOT remediate"
            $compliance += $false}
        }
    else{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to verify vbscript already exist in corpdata folder"}

    #Check if scheduled task already exist
    if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) -or $forceReplaceAll) {
        if ($Remediation){ 
            #Create Task Trigger
            $class = Get-cimclass MSFT_TaskEventTrigger root/Microsoft/Windows/TaskScheduler
            $Trigger_onEvent = $class | New-CimInstance -ClientOnly
            $trigger_onEvent.Enabled = $true
            $trigger_onEvent.Subscription = @"
                <QueryList>
                    <Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational">
                        <Select Path="Microsoft-Windows-NetworkProfile/Operational">
                            *[System[EventID=10000]]
                        </Select>
                    </Query>
                </QueryList>
"@
            $Trigger_atLogon = New-ScheduledTaskTrigger -AtLogOn
            #Execute task in users context
            $principal = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-545" -Id "Author"
            # Set path to wscript.exe
            $wscriptPath = Join-Path $env:SystemRoot -ChildPath "System32\wscript.exe"
            # Set task to call the vbscript helper and pass the Powershell script as argument
            $action = New-ScheduledTaskAction -Execute $wscriptPath -Argument "`"$vbsSavePath`" `"$scriptSavePath`""
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

            # Register scheduled task
            $null = Register-ScheduledTask -TaskName $TaskName -Trigger $Trigger_atLogon, $Trigger_onEvent -Action $action  -Principal $principal -Settings $settings -Description $TaskDescription -Force -ErrorAction SilentlyContinue -ErrorVariable errorvar
            if ($errorvar.count -eq 0){write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to register scheduled task"}
            else{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Error,Failed to register scheduled task with error: $($errorvar)";$errorvar=$null;$Global:EventId=12;$Global:EventType="error"}

            #Start scheduled task
            Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue -ErrorVariable errorvar
            if ($errorvar.count -eq 0){write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to start scheduled task"}
            else{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Error,Failed to start scheduled task with error: $($errorvar)";$errorvar=$null;$Global:EventId=12;$Global:EventType="error"}
            }
        else {
            write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Running in detection mode, scheduled task needs to be created but will NOT remediate"
            $compliance += $false}
        }
    else{Write-Host "Script and scheduled task already exist in corpdata folder"}

#region ----------------------------------------------------[Remediation]--------------------------------------------------------
    #Detection Compliant
    if (!($Remediation) -and !($compliance -contains $false)){
        Write-Host "Compliant - $TaskName completed successfully"
        Exit 0
    }
    #Detection Non compliant
    Elseif(!($Remediation) -and ($compliance -contains $false)){
        Write-Warning "NON Compliant or Failed Remediate - $TaskName"
        Exit 1
    }
    Else{
        Write-Host "Remediated - $TaskName completed successfully"
        Exit 0
    }
#endregion
}

# If running as user (as a scheduled task), run scheduled task to map objects
else{
    Write-Host "Start to map $ObjectType as user"
    
    # Get user group memberships
	$groupMemberships = Get-ADGroupMembership
	if ($groupMemberships){
        write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to collect user group memberships collected $($groupMemberships.count) groups"
		#Get target user mappings list based on groupmembeships
        $TargetUserMappings = $MapObjects | Where-Object {
            if ($_.ADGroups -ne $null) {
                foreach ($ADGroup in $_.ADGroups -split ";") {
                    if ($ADGroup -eq "" -or $groupMemberships -contains $ADGroup) {return $true}
                }
            }
            return $false
        }
        if ($TargetUserMappings){
            write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to find $($TargetUserMappings.count) $($ObjectType) to map"
            #Iterate through all Target Objects to Map and check if they already exist
            foreach ($TargetUserMap in $TargetUserMappings) {
                if ($ObjectType -eq "Drive"){Map-Drive -Letter $TargetUserMap.Letter -DrivePath $TargetUserMap.Path -Label $TargetUserMap.Label -Persistant $TargetUserMap.Persistent}
                else{Map-Printer -PrinterName $TargetUserMap.PrinterName -PrinterPath $TargetUserMap.Path -Default $TargetUserMap.default}
            }

            # Remove unassigned Mapped Objects
            if ($removeStaleObjects) {
                if ($ObjectType -eq "Drive"){
                    $ExistingMappings = Get-PSDrive -ErrorAction SilentlyContinue -ErrorVariable errorvar | Where-Object { $_.Provider.Name -eq "FileSystem" -and $_.Root -notin @("$env:SystemDrive\", "D:\")}
                    if ($ExistingMappings){
                        foreach ($psdrive in $ExistingMappings){
                            if ($psdrive.name -notin $TargetUserMappings.Letter){
                                write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,found mapped drive $($psdrive.name) that has not been assigned will try to remove"
                                Try{net use "$($Letter):" /delete #Remove-PSDrive -Name $Letter -ErrorAction silentlycontinue
                                write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success,Removed unassigned drive $($Letter):"}
                            catch{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Error,Failed to remove unassigned drive $($Letter): with error: $($_.Exception.Message)";$errorvar=$null;$Global:EventId=12;$Global:EventType="error"}
                            }
                        }
                    }
                    else{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,No existing unassigned drives to be removed."}
                }
                else{
                    $ExistingMappings = Get-Printer  -ErrorAction SilentlyContinue -ErrorVariable errorvar| Where-Object {($_.shared -eq $true) -and ($_.Name -like "\\*")}
                    if ($ExistingMappings){
                        foreach ($printer in $ExistingMappings){
                            if ($printer.Name -notin $TargetUserMappings.Path){
                                write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,found mapped printer $($printer.Name) that has not been assigned will try to remove"
                                remove-printer -Name $printer.Name -Force -ErrorAction SilentlyContinue -ErrorVariable errorvar
                                if ($errorvar.count -eq 0){write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success,Removed unassigned printer $($printer.Name)"}
                                else{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Error,Failed to remove unassigned printer $($printer.Name) with error: $($_.Exception.Message)";$errorvar=$null;$Global:EventId=12;$Global:EventType="error"}
                            }
                        }
                    }
                    else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,No existing unassigned printers to be removed."}
                }
            }
            # Fix to ensure Mapped Drives are mapped as persistent!
            if ($ObjectType -eq "Drive"){
                $null = Get-ChildItem -Path HKCU:\Network -ErrorAction SilentlyContinue | ForEach-Object {New-ItemProperty -Name ConnectionType -Value 1 -Path $_.PSPath -Force -ErrorAction SilentlyContinue}
            }
        }
        else{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Error,Failed to find any $($ObjectType) to map"}
        }
    else{Write-Warning "Failed to get user group memberships - script cannot continue"}

    Write-Host "Task completed - $TaskName mapped $ObjectType for user"
}
}
catch {
    Write-Error "Script execution failed with error: $_"
}
finally {
    # Always restore original preferences and stop logging
    $ErrorActionPreference = $script:OriginalErrorActionPreference
    $VerbosePreference = $script:OriginalVerbosePreference
    $WhatIfPreference = $script:OriginalWhatIfPreference
    # End T-Bone custom logging (writes to eventlog/disk/host based on settings)
    Invoke-TboneLog -Mode Stop
}
#endregion
