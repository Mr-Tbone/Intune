<#PSScriptInfo
.VERSION        3.5.0
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
    2.0.1 2026-01-21 Fix some syntax and added script parameters logname and logeventids
    3.0.0 2026-06-01 Major update with new parameters and functions for Add Remove Programs and Context controls, as well as some refactoring and code cleanup.
    3.1.0 2026-06-05 Default to x64 execution: auto-relaunch from x86, ProgramW6432-based install path, x64 ARP/Uninstall registry hive
    3.1.1 2026-06-05 Fix Remove-AddRemovePrograms packed-GUID converter (was leaving HKCR\Installer\Products\<wrong-id> orphaned, causing Intune detection to keep finding the app after uninstall -> 0x87D1041D)
    3.2.0 2026-06-05 Minor update with new name on scripts
    3.3.0 2026-06-14 Minor update to not overload Domain Controllers
    3.4.0 2026-06-15 Minor update with a function to remove legacy Mr T-Bone scripts to migrate to the new version
    3.5.0 2026-06-16 Minor update to move redundant tasks to scriptblocks
#>

<#
.SYNOPSIS
    Maps Intune-managed cloud-native drives or printers.

.DESCRIPTION
    Deploys and runs a drive or printer mapping solution for Entra ID joined / cloud-native Windows devices.
    Supports Intune Win32 app install, Intune remediation, manual install/repair, normal user execution, and uninstall.

    During install or remediation, the script stages itself, registers a hidden user-context scheduled task, writes a launcher,
    stores a version marker, and can register Add/Remove Programs entries, shortcuts, uninstall, and modify support.

    During user execution, it can start the deployed worker with a one-shot GUI override or run mapping directly.
    Mapping is filtered by configured AD groups resolved through LDAP after a DC Locator check.

.EXAMPLE
    .\Map-DrivesCloudNative.ps1
    Runs with default settings. As SYSTEM/Admin it installs or repairs the worker and scheduled task; as a normal user it starts the existing worker or runs mapping for the current session.

.EXAMPLE
    .\Map-DrivesCloudNative.ps1 -LogVerboseEnabled $true -LogToDisk $true
    Runs with verbose logging enabled and writes the log to disk at script end.

.EXAMPLE
    .\Map-DrivesCloudNative.ps1 -InstallType UnInstall
    Removes the scheduled task, staged worker files, version marker, and Add/Remove Programs registration.

.NOTES
    Please feel free to use this, but make sure to credit @MrTbone_se as the original author

.LINK
    https://tbone.se
#>

#region ---------------------------------------------------[Modifiable Parameters and Defaults]------------------------------------
# Customizations
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Domain to search for AD group memberships (e.g., 'contoso.com')")]
    [String]$DomainName             = "tbone.se",

    [Parameter(Mandatory = $false, HelpMessage = "Mapping configuration version, increment when adding new or changing drive or printer mappings")]
    [version]$MappingVersion        = "3.2.0",

    [Parameter(Mandatory = $false, HelpMessage = "Enable a GUI with mapping results when the user manually executes the script. Default is true.")]
    [Bool]$EndUserGUI               = $true,

    [Parameter(Mandatory = $false, HelpMessage = "Remove stale drive/printer mappings that are no longer in the configuration")]
    [Bool]$RemoveStaleObjects       = $true,

    [Parameter(Mandatory = $false,          HelpMessage = 'Specify how to run the script: Install, Repair or UnInstall')]
    [validateset("Install", "Repair", "UnInstall")]
    [string]$InstallType            = "Install",

    [Parameter(Mandatory = $false, HelpMessage = "Force replace all scripts and scheduled tasks even if version is the same")]
    [Bool]$ForceReplaceAll          = $false,

    [Parameter(Mandatory = $false, HelpMessage = "Detect and remove legacy mapping deployments from earlier generations before installing or repairing the current deployment")]
    [Bool]$ReplaceOldV1andV2        = $true,

    # ==========> ScheduleTask Triggers (Add-NewScheduledTask) <===========================================================
    [Parameter(Mandatory = $false, HelpMessage = "Run the script at user logon")]
    [Bool]$RunAtLogon               = $true,

    [Parameter(Mandatory = $false, HelpMessage = "Run the script when network connection is established")]
    [Bool]$RunAtNetConnect          = $false,

    # ==========> Add Application to Add Remove Program (Add-AddRemoveProgram) <===========================================
    [Parameter(Mandatory = $false,          HelpMessage = 'Name of the application/script being wrapped')]
    [String]$ARPAppName             = "Map Drives",

    [Parameter(Mandatory = $false,          HelpMessage = 'Company name used for naming of folders and registry keys')]
    [String]$ARPAppPublisher        = "T-Bone Consulting",

    [Parameter(Mandatory = $false,          HelpMessage = 'Enable an uninstall option in Add Remove Programs, require administrator privileges to uninstall')]
    [bool]$ARPAppEnableUninstall    = $True,

    [Parameter(Mandatory = $false,          HelpMessage = 'Enable a modify option in Add Remove Programs (typically for repair/reinstall), require administrator privileges to modify')]
    [bool]$ARPAppEnableModify       = $True,

    [Parameter(Mandatory = $false,          HelpMessage = 'Optional path to an external .ico file to use as the icon of the app')]
    [string]$ARPAppIconPath         = "",

    [Parameter(Mandatory = $false,          HelpMessage = 'Optional Base64-encoded .ico content to use as the icon of the app. if not specified, a default icon will be used')]
    [string]$ARPAppIcon             = "",

    [Parameter(Mandatory = $false,          HelpMessage = 'Create an All-Users Desktop shortcut (targets ARPAppUserStartFile when set, otherwise the deployed wrapper script)')]
    [bool]$ARPAppShortcutOnDesktop  = $true,

    [Parameter(Mandatory = $false,          HelpMessage = 'Create an All-Users Start Menu shortcut (targets ARPAppUserStartFile when set, otherwise the deployed wrapper script)')]
    [bool]$ARPAppShortcutInStart    = $true,

    [Parameter(Mandatory = $false,          HelpMessage = 'GUID of the application/script being wrapped. NOTE: This needs to be unique for each wrapped app')]
    [ValidatePattern('^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$')]
    [String]$ARPAppGuid             = "{feedbeef-beef-4dad-beef-b628ccca16bd}",

    [Parameter(Mandatory = $false,          HelpMessage = "Application folder path, if not specified, it will use the native 64-bit %ProgramFiles%\ARPPublisher\ARPAppName (via %ProgramW6432% so a 32-bit host does not get redirected to 'Program Files (x86)'). Falls back to %ProgramFiles% on a 32-bit OS where ProgramW6432 is unset.")]
    [string]$ARPAppFolder           = "$(if (${env:ProgramW6432}) { ${env:ProgramW6432} } else { $env:ProgramFiles })\$ARPAppPublisher\$ARPAppName",

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
#IMPORTANT! When adding new Drivers make sure to also increment Version in $MappingVersion above.
# Add Objects to Map here either Printers or Drives (Not Both) with the following syntax
#Printers:  $MapObjects += @{PrinterName="PrinterName"  ;Default=$true      ;Path="\\printserver\printerName"   ;ADGroups="My Group"}
#Drives:    $MapObjects += @{Letter="X"                 ;Persistent=$true   ;Path="\\fileserver\fileshare"      ;ADGroups="My Group"    ;Label="My drive"}
$MapObjects = @()
$MapObjects+=@{Letter="S";Persistent=$true;Path="\\t-bone-file.tbone.se\Sales"	        ;ADGroups=	"Sales"	        ;Label="Sales folder"   }
$MapObjects+=@{Letter="H";Persistent=$true;Path="\\t-bone-file.tbone.se\HR"             ;ADGroups=	"HR"            ;Label="HR"             }
$MapObjects+=@{Letter="W";Persistent=$true;Path="\\t-bone-file.tbone.se\Consultants"	;ADGroups=	"Consultants"   ;Label="Consult"        }
$MapObjects+=@{Letter="G";Persistent=$true;Path="\\t-bone-file.tbone.se\Common" 	    ;ADGroups=	""              ;Label="Common"         }
$MapObjects+=@{Letter="V";Persistent=$true;Path="\\t-bone-dc1.tbone.se\netlogon"	    ;ADGroups=	""              ;Label="Netlogon"       }
#endregion

#region ---------------------------------------------------[Set global script settings]--------------------------------------------
# set strict mode to latest version
Set-StrictMode -Version Latest

# Save original preference states at script scope for restoration in finally block
[System.Management.Automation.ActionPreference]$script:OriginalErrorActionPreference    = $ErrorActionPreference
[System.Management.Automation.ActionPreference]$script:OriginalVerbosePreference        = $VerbosePreference
[bool]$script:OriginalWhatIfPreference                                                  = $WhatIfPreference

# Set verbose- and whatif- preference based on parameter instead of hardcoded values
if ($LogVerboseEnabled)     {$VerbosePreference = 'Continue'}
else                        {$VerbosePreference = 'SilentlyContinue'}
#endregion

#region ---------------------------------------------------[Static Variables]------------------------------------------------------
# Determine object type based on first mapping object and set namings accordingly
if (-not $MapObjects -or $MapObjects.Count -eq 0) {throw "MapObjects array is empty or not defined"}
$firstMapObject = $MapObjects[0]
if ($firstMapObject.ContainsKey('Letter'))          {$ObjectType = 'Drive'}
elseif ($firstMapObject.ContainsKey('PrinterName')) {$ObjectType = 'Printer'}
else {throw "Unknown MapObject type: First object must contain 'Letter' or 'PrinterName' key"}

# Build the unique list of AD group names referenced in $MapObjects. Used to scope LDAP queries to only those groups
[string[]]$RequiredGroups       = @($MapObjects | ForEach-Object { $_['ADGroups'] } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)

# Static ARP wrapper options for this script usage pattern.
[string]$ARPAppInstallScript   = ""
[string]$ARPAppUnInstallScript = ""
[bool]$ARPAppIncludeFolder     = $false
[string]$ARPAppUserStartFile   = ""
[bool]$ARPAppForce             = $false
[version]$ARPAppVersion        = $MappingVersion

# Static script context requirements for this script usage pattern.
[string[]]$CTXReqIdentity      = @()
[version]$CTXReqPSVersion      = $null
[int]$CTXReqOSBuild            = 0
[string]$CTXReqArchitecture    = ""
[bool]$CTXAutoRelaunchToX64    = $true
[bool]$CTXAbortIfPendingReboot = $false

# Set Names and Paths based on ObjectType for scripts and scheduled task
[string]$UsersGroupSid          = "S-1-5-32-545"    # Built-in Users group, used for scheduled task
[string]$TaskName               = "Intune$($ObjectType)Mapping"
[string]$TaskDescription        = "Map $($ObjectType) with script from Intune"
[string]$ScriptSavePath         = $(Join-Path -Path $ARPAppFolder -ChildPath "scripts\$($TaskName).ps1")
[string]$JSSavePath             = $(Join-Path -Path $ARPAppFolder -ChildPath "scripts\$($TaskName).js")
[string]$VersionFilePath        = $(Join-Path -Path $ARPAppFolder -ChildPath "scripts\$($TaskName).version")
[string]$ShortcutLauncherPath   = $(Join-Path -Path $ARPAppFolder -ChildPath "$($TaskName)-Run.js")

# JS launcher content used by wscript that hides the console window and sets MapperCTXSource when the scheduled task fires the task in user context
[string]$JSLauncherContent = @'
var shell = new ActiveXObject("WScript.Shell");
shell.Environment("Process")("MapperCTXSource") = "ScheduledTask";
var cmd = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File \"" + WScript.Arguments(0) + "\"";
shell.Run(cmd, 0, false);
'@

# JS launcher content used by user-facing shortcuts: silently sets MapperShowGUI in HKCU\Environment and triggers the scheduled task via Schedule.Service COM
[string]$ShortcutLauncherContent = @"
var shell = new ActiveXObject("WScript.Shell");
try { shell.RegWrite("HKCU\\Environment\\MapperShowGUI", "1", "REG_SZ"); } catch (e) {}
try {
    var svc = new ActiveXObject("Schedule.Service");
    svc.Connect();
    var folder = svc.GetFolder("\\");
    var task = folder.GetTask("$TaskName");
    task.Run(null);
} catch (e) {}
"@

# ==========> Logging (Invoke-TboneLog) <==============================================================================
if ([string]::IsNullOrWhiteSpace($LogName)) { $LogName = $TaskName }
#endregion

#region ---------------------------------------------------[Import Modules and Extensions]-----------------------------------------
#endregion

#region ---------------------------------------------------[Functions]------------------------------------------------------------
function Invoke-TboneLog { 
<#
.SYNOPSIS
    Unified tiny logger for PowerShell 5.1-7.5 and Azure Automation; overrides Write-* cmdlets and stores all messages in-memory
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
        if(!(Test-Path function:\global:_Save)){function global:_Save{try{if($global:_d){[IO.Directory]::CreateDirectory($global:_p)|Out-Null;[IO.File]::WriteAllLines((Join-Path $global:_p "$($global:_n).log"),$global:_l.ToArray())};if($global:_e -and $global:_w){$isAdmin=$false;try{$id=[Security.Principal.WindowsIdentity]::GetCurrent();$isAdmin=([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)}catch{};$la=$global:_l -join"`n";$h=$la -match ',ERROR,';$w=$la -match ',WARN,';$eid=if($h){$global:_i.Error}elseif($w){$global:_i.Warn}else{$global:_i.Info};$et=if($h){'Error'}elseif($w){'Warning'}else{'Information'};$ok=$false;try{Write-EventLog -LogName Application -Source $global:_s -EventId $eid -EntryType $et -Message $la -EA Stop;$ok=$true}catch{};if(-not $ok -and $isAdmin){try{[Diagnostics.EventLog]::CreateEventSource($global:_s,'Application')}catch{};try{Write-EventLog -LogName Application -Source $global:_s -EventId $eid -EntryType $et -Message $la}catch{}}}}catch{}}}
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
Function Get-RuntimeContext {
<#
.SYNOPSIS
    Detects how the script is being executed and (optionally) validates it against requirements; can auto-relaunch in 64-bit.
.DESCRIPTION
    Inspects environment variables, the script path, parent/ancestor processes, identity, and architecture and returns a PSCustomObject with the following properties:
    - CTXMode           : WinPE, AzureAutomation, AzureFunction, GitHubActions, GitLabCI, AzureDevOps, TaskSequence, Remediation, Detection, PlatformScript, Intunewin, SCCM, GPO, or Standalone
    - CTXPath           : ProgramFiles, ProgramFilesX86, IMEContent, ProgramData, AppDataRoaming, AppDataLocal, IMECache, CCMCache, SystemRoot, or Other
    - CTXSource         : Managed (set for any non-Standalone CTXMode), or one of Manual, ScheduledTask, RemoteSession, VSCodeDebug, ISE, Explorer, Batch, Interactive
    - CTXIdentity       : System, LocalService, NetworkService, ServiceAccount, Admin, or User
    - CTXArchitecture   : x64 or x86
    - CTXPSVersion      : Version object from $PSVersionTable.PSVersion (e.g. 5.1.19041.0)
    - CTXOSBuild        : Integer Windows OS build number (0 on non-Windows)
    - CTXPendingReboot  : Boolean; $true when a reboot is pending (CBS / Windows Update / PendingFileRenameOperations)
    - CTXNoGUISupport   : Boolean; $true when a GUI (WinForms) cannot be shown - non-Windows or non-interactive session
.NOTES
    Version: 1.1.0
    
    Version History:
    1.0 - Initial version
    1.0.1 - Fixed some edge cases in detection logic
    1.1.0 - Added reqirements parameters and validation logic, and auto-relaunch to x64 if required and running x86
#>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(HelpMessage = 'Required execution identity. Valid: System, LocalService, NetworkService, ServiceAccount, Admin, User')]
        [ValidateSet('System','LocalService','NetworkService','ServiceAccount','Admin','User')]
        [string[]]$CTXReqIdentity           = @(),

        [Parameter(HelpMessage = 'Required process architecture. Valid: x64, x86 (empty = no requirement)')]
        [ValidateSet('x64','x86','')]
        [string]$CTXReqArchitecture         = '',

        [Parameter(HelpMessage = 'Required execution mode (any value returned in CTXMode).')]
        [string[]]$CTXReqMode               = @(),

        [Parameter(HelpMessage = 'Minimum required PowerShell version (e.g. 5.1). Fails if PSVersionTable.PSVersion is lower.')]
        [version]$CTXReqPSVersion           = $null,

        [Parameter(HelpMessage = 'Minimum required OS build number (e.g. 19041 for Win10 2004). Fails if OS build is lower.')]
        [int]$CTXReqOSBuild                 = 0,

        [Parameter(HelpMessage = 'If set, abort when a reboot is pending (CBS, Windows Update, or file rename pending).')]
        [switch]$CTXAbortIfPendingReboot,

        [Parameter(HelpMessage = 'If set and process is x86 while x64 is required, relaunch via SysNative.')]
        [switch]$CTXAutoRelaunchToX64,

        [Parameter(HelpMessage = 'Caller bound parameters to forward on relaunch (pass $PSBoundParameters from the caller).')]
        [hashtable]$CTXForwardParameters    = @{}
    )
    Write-Verbose "Start function Get-RuntimeContext"
    # Initialize variables
    [string]$CTXMode    = 'Standalone'
    [string]$CTXPath    = 'Other'
    [string]$CTXSource  = 'Managed'
    [string]$CTXIdentity= 'User'
    [string]$scriptPath = $script:PSCommandPath
    [string]$scriptRoot = $script:PSScriptRoot
    # PS5.1 Desktop is always Windows; PS6+ exposes $IsWindows
    [bool]$isWin = ($PSVersionTable.PSEdition -eq 'Desktop') -or $IsWindows

    # Helper: walk parent processes from $PID up to 8 levels using a PID->Win32_Process hashtable
    $getAncestors = {
        param([hashtable]$Table)
        $list = [System.Collections.Generic.List[int]]::new()
        $cur  = $PID
        while ($list.Count -lt 8 -and $Table.ContainsKey($cur)) {
            $parent = [int]$Table[$cur].ParentProcessId
            if ($parent -eq 0 -or $parent -eq $cur) { break }
            $list.Add($parent)
            $cur = $parent
        }
        ,$list
    }

    # ---- Execution Mode detection -------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Cross-platform managed-host signals first (env vars and PSPrivateMetadata work on every platform)
    if     ((Test-Path variable:PSPrivateMetadata) -and $PSPrivateMetadata.JobId)           { $CTXMode = 'AzureAutomation' }
    elseif ($env:FUNCTIONS_WORKER_RUNTIME -or $env:AZURE_FUNCTIONS_ENVIRONMENT)             { $CTXMode = 'AzureFunction'   }
    elseif ($env:GITHUB_ACTIONS -eq 'true')                                                 { $CTXMode = 'GitHubActions'   }
    elseif ($env:GITLAB_CI -eq 'true')                                                      { $CTXMode = 'GitLabCI'        }
    elseif ($env:TF_BUILD -eq 'True')                                                       { $CTXMode = 'AzureDevOps'     }
    elseif ($env:_SMSTSType -or $env:_SMSTSPackageID -or $env:SMSTSLogPath)                 { $CTXMode = 'TaskSequence'    }
    # Windows-only: WinPE detection requires HKLM provider
    if ($CTXMode -eq 'Standalone' -and $isWin) {
        try { if (Test-Path 'HKLM:\SYSTEM\ControlSet001\Control\MiniNT' -ErrorAction Stop) { $CTXMode = 'WinPE' } } catch {}
    }
    Write-Verbose "Enumerated CTXMode = $CTXMode after environment variable check"

    # If still standalone, get execution mode from script path (Remediation, Detection, PlatformScript, Intunewin, TaskSequence, SCCM)
    if ($CTXMode -eq 'Standalone' -and $scriptPath) {
        if     ($scriptPath -match 'IMECache\\HealthScripts\\.*\\remediate\.ps1$')          { $CTXMode = 'Remediation'    }
        elseif ($scriptPath -match 'IMECache\\HealthScripts\\.*\\detect\.ps1$')             { $CTXMode = 'Detection'      }
        elseif ($scriptPath -match 'IMECache\\Scripts\\')                                   { $CTXMode = 'PlatformScript' }
        elseif ($scriptPath -match 'Microsoft Intune Management Extension\\Content\\')      { $CTXMode = 'Intunewin'      }
        elseif ($scriptPath -match '_SMSTaskSequence\\')                                    { $CTXMode = 'TaskSequence'   }
        elseif ($scriptPath -match '\\ccmcache\\')                                          { $CTXMode = 'SCCM'           }
    }
    Write-Verbose "Enumerated CTXMode = $CTXMode after script path check"

    # If still standalone, walk parent processes via CIM (Windows-only) to detect Intunewin / GPO / SCCM / TaskSequence
    [hashtable]$procTable = @{}
    [System.Collections.Generic.List[int]]$ancestorPids = [System.Collections.Generic.List[int]]::new()
    if ($CTXMode -eq 'Standalone' -and $isWin) {
        try {
            Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId, Name -ErrorAction Stop -Verbose:$false |
                ForEach-Object { $procTable[[int]$_.ProcessId] = $_ }
        } catch { Write-Verbose "Failed to build process table with CIM: $_" }
        if ($procTable.Count -gt 0) {
            $ancestorPids = & $getAncestors $procTable
            foreach ($aPid in $ancestorPids) {
                if (-not $procTable.ContainsKey($aPid)) { continue }
                $procName = $procTable[$aPid].Name
                if     ($procName -in 'AgentExecutor.exe','IntuneManagementExtension.exe')  { $CTXMode = 'Intunewin';    break }
                elseif ($procName -eq 'gpscript.exe')                                       { $CTXMode = 'GPO';          break }
                elseif ($procName -in 'CcmExec.exe','ccmsetup.exe')                         { $CTXMode = 'SCCM';         break }
                elseif ($procName -in 'TSManager.exe','smstsbootstrap.exe')                 { $CTXMode = 'TaskSequence'; break }
            }
        }
    }
    Write-Verbose "Enumerated CTXMode = $CTXMode after CIM process detection"

    # ---- Execution path detection -------------------------------------------------------------------------------------------------------------------------------------------------------------------
    if ($scriptRoot) {
        $root = $scriptRoot.TrimEnd('\')
        $sc   = [StringComparison]::OrdinalIgnoreCase
        if     ($env:ProgramFiles        -and $root.StartsWith($env:ProgramFiles.TrimEnd('\'),                                                   $sc)) { $CTXPath = 'ProgramFiles'    }
        elseif (${env:ProgramFiles(x86)} -and $root.StartsWith(${env:ProgramFiles(x86)}.TrimEnd('\') + '\Microsoft Intune Management Extension', $sc)) { $CTXPath = 'IMEContent'      }
        elseif (${env:ProgramFiles(x86)} -and $root.StartsWith(${env:ProgramFiles(x86)}.TrimEnd('\'),                                            $sc)) { $CTXPath = 'ProgramFilesX86' }
        elseif ($env:ProgramData         -and $root.StartsWith($env:ProgramData.TrimEnd('\'),                                                    $sc)) { $CTXPath = 'ProgramData'     }
        elseif ($env:APPDATA             -and $root.StartsWith($env:APPDATA.TrimEnd('\'),                                                        $sc)) { $CTXPath = 'AppDataRoaming'  }
        elseif ($env:LOCALAPPDATA        -and $root.StartsWith($env:LOCALAPPDATA.TrimEnd('\'),                                                   $sc)) { $CTXPath = 'AppDataLocal'    }
        elseif ($env:SystemRoot          -and $root.StartsWith($env:SystemRoot.TrimEnd('\') + '\IMECache',                                       $sc)) { $CTXPath = 'IMECache'        }
        elseif ($env:SystemRoot          -and $root.StartsWith($env:SystemRoot.TrimEnd('\') + '\ccmcache',                                       $sc)) { $CTXPath = 'CCMCache'        }
        elseif ($env:SystemRoot          -and $root.StartsWith($env:SystemRoot.TrimEnd('\'),                                                     $sc)) { $CTXPath = 'SystemRoot'      }
    }
    Write-Verbose "Enumerated CTXPath = $CTXPath after path detection"

    # ---- Source detection (Windows-only; relies on CIM and Windows hosts) ---------------------------------------------------------------------------------------------------------------------------
    if ($CTXMode -eq 'Standalone') {
        $CTXSource = 'Manual'
        if ($isWin) {
            try {
                if ([System.Environment]::GetEnvironmentVariable('MapperCTXSource', 'Process') -eq 'ScheduledTask') {
                    $CTXSource = 'ScheduledTask'
                }
                elseif ($procTable.Count -eq 0) {
                    Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId, Name -ErrorAction Stop -Verbose:$false |
                        ForEach-Object { $procTable[[int]$_.ProcessId] = $_ }
                    $ancestorPids = & $getAncestors $procTable
                }
                if ($CTXSource -ne 'ScheduledTask') {
                    $parentName    = if ($ancestorPids.Count -gt 0 -and $procTable.ContainsKey($ancestorPids[0])) { $procTable[$ancestorPids[0]].Name } else { '' }
                    $ancestorNames = $ancestorPids | Where-Object { $procTable.ContainsKey($_) } | ForEach-Object { $procTable[$_].Name }
                    $svchostPid    = $ancestorPids | Where-Object { $procTable.ContainsKey($_) -and $procTable[$_].Name -eq 'svchost.exe' } | Select-Object -First 1
                    $svcNames      = if ($svchostPid) { @(Get-CimInstance Win32_Service -Filter "ProcessId=$svchostPid" -Property Name -ErrorAction SilentlyContinue | ForEach-Object Name) } else { @() }
                    if     ($svcNames -contains 'Schedule')                                                                         { $CTXSource = 'ScheduledTask' }
                    elseif ($parentName -eq 'wsmprovhost.exe')                                                                      { $CTXSource = 'RemoteSession' }
                    elseif ($Host.Name -eq 'Visual Studio Code Host' -or [bool]($ancestorNames -match '^Code( - Insiders)?\.exe$')) { $CTXSource = 'VSCodeDebug'   }
                    elseif ($Host.Name -eq 'Windows PowerShell ISE Host')                                                           { $CTXSource = 'ISE'           }
                    elseif ($parentName -eq 'explorer.exe')                                                                         { $CTXSource = 'Explorer'      }
                    elseif ($parentName -eq 'cmd.exe')                                                                              { $CTXSource = 'Batch'         }
                    elseif ($parentName -in 'powershell.exe','pwsh.exe')                                                            { $CTXSource = 'Interactive'   }
                }} catch                                                                                                            { $CTXSource = 'Manual'        }
        }
    }
    Write-Verbose "Enumerated CTXSource = $CTXSource after source detection"

    # ---- Identity detection (Windows-only; WindowsIdentity throws on Linux/macOS pwsh) --------------------------------------------------------------------------------------------------------------
    if ($isWin) {
        try {
            $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $principal       = [System.Security.Principal.WindowsPrincipal]$currentIdentity
            if     ($currentIdentity.IsSystem)                                                                      { $CTXIdentity = 'System'         }
            elseif ($currentIdentity.User.Value -eq 'S-1-5-19')                                                     { $CTXIdentity = 'LocalService'   }
            elseif ($currentIdentity.User.Value -eq 'S-1-5-20')                                                     { $CTXIdentity = 'NetworkService' }
            elseif ($currentIdentity.Name -like 'NT SERVICE\*' -or $currentIdentity.Name -like 'NT AUTHORITY\*')    { $CTXIdentity = 'ServiceAccount' }
            elseif ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))             { $CTXIdentity = 'Admin'          }
            else                                                                                                    { $CTXIdentity = 'User'           }
        } catch { Write-Verbose "Failed to detect CTXIdentity, defaulting to 'User'. Error: $_" }
    }
    Write-Verbose "Enumerated CTXIdentity = $CTXIdentity after identity detection"

    # ---- Architecture / PS version / OS build / pending reboot --------------------------------------------------------------------------------------------------------------------------------------
    [string]$CTXArchitecture = if ([Environment]::Is64BitProcess) { 'x64' } else { 'x86' }
    [version]$CTXPSVersion   = $PSVersionTable.PSVersion
    [int]$CTXOSBuild         = if ($isWin) { [Environment]::OSVersion.Version.Build } else { 0 }
    [bool]$CTXPendingReboot  = $false
    if ($isWin) {
        try {
            if     (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')                                              { $CTXPendingReboot = $true }
            elseif (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')                                             { $CTXPendingReboot = $true }
            else {
                $pfro = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
                if ($pfro -and $pfro.PendingFileRenameOperations)                                                                                                     { $CTXPendingReboot = $true }
            }
        } catch { Write-Verbose "Failed to detect pending reboot state. Error: $_" }
    }
    # GUI availability: $true = GUI cannot be shown (non-Windows or non-interactive session)
    [bool]$CTXNoGUISupport = (-not [System.Environment]::UserInteractive) -or
                      ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows)

    Write-Verbose "Enumerated CTXArchitecture=$CTXArchitecture, CTXPSVersion=$CTXPSVersion, CTXOSBuild=$CTXOSBuild, CTXPendingReboot=$CTXPendingReboot, CTXNoGUISupport=$CTXNoGUISupport"

    [PSCustomObject]$CTX = [PSCustomObject]@{
        CTXMode          = $CTXMode
        CTXPath          = $CTXPath
        CTXSource        = $CTXSource
        CTXIdentity      = $CTXIdentity
        CTXArchitecture  = $CTXArchitecture
        CTXPSVersion     = $CTXPSVersion
        CTXOSBuild       = $CTXOSBuild
        CTXPendingReboot = $CTXPendingReboot
        CTXNoGUISupport         = $CTXNoGUISupport
    }

    # ---- Requirement validation (only runs if any requirement parameter is provided) ---------------------------------------------------------------------------------------------------------------
    [bool]$ok = $true
    if ($CTXReqIdentity.Count -gt 0 -and $CTX.CTXIdentity -notin $CTXReqIdentity) {
        Write-Error "Required identity: $($CTXReqIdentity -join '/'), actual: $($CTX.CTXIdentity)."
        $ok = $false
    }
    if ($CTXReqMode.Count -gt 0 -and $CTX.CTXMode -notin $CTXReqMode) {
        Write-Error "Required execution mode: $($CTXReqMode -join '/'), actual: $($CTX.CTXMode)."
        $ok = $false
    }
    if ($CTXReqArchitecture -and $CTX.CTXArchitecture -ne $CTXReqArchitecture) {
        if ($CTXAutoRelaunchToX64 -and $CTXReqArchitecture -eq 'x64' -and [Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
            # Resolve caller script path: prefer $script:PSCommandPath, else first call-stack frame with a ScriptName
            [string]$callerScript = $scriptPath
            if (-not $callerScript) {
                foreach ($frame in (Get-PSCallStack)) {
                    if ($frame.ScriptName) { $callerScript = $frame.ScriptName; break }
                }
            }
            [string]$sysNative = "$env:SystemRoot\SysNative\WindowsPowerShell\v1.0\powershell.exe"
            if (-not $callerScript -or -not (Test-Path -LiteralPath $callerScript)) {
                Write-Error "CTXAutoRelaunchToX64 requires a file-based script (caller path '$callerScript' not resolvable). Architecture requirement failed."
                return $null
            }
            if (-not (Test-Path -LiteralPath $sysNative)) {
                Write-Error "CTXAutoRelaunchToX64 failed: '$sysNative' not found. Architecture requirement failed."
                return $null
            }
            # Build a single -Command line that re-invokes the caller script with forwarded parameters
            [string]$cmdLine = "& '" + ($callerScript -replace "'","''") + "'"
            foreach ($k in $CTXForwardParameters.Keys) {
                $v = $CTXForwardParameters[$k]
                if     ($v -is [switch])  { if ($v.IsPresent) { $cmdLine += " -$k" } }
                elseif ($v -is [bool])    { $cmdLine += " -${k}:`$$($v.ToString().ToLower())" }
                elseif ($v -is [array])   { $cmdLine += " -$k '" + (($v | ForEach-Object { $_ -replace "'","''" }) -join "','") + "'" }
                else                      { $cmdLine += " -$k '" + ($v.ToString() -replace "'","''") + "'" }
            }
            Write-Warning "Process is x86; relaunching as x64 via SysNative: $sysNative"
            $proc = Start-Process -FilePath $sysNative -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-Command', $cmdLine) -Wait -NoNewWindow -PassThru
            exit $proc.ExitCode  # exits the current script/host after the relaunched x64 process completes
        }
        Write-Error "Required architecture: $CTXReqArchitecture, actual: $($CTX.CTXArchitecture)."
        $ok = $false
    }
    if ($CTXReqPSVersion -and $CTX.CTXPSVersion -lt $CTXReqPSVersion) {
        Write-Error "Required minimum PowerShell version: $CTXReqPSVersion, actual: $($CTX.CTXPSVersion)."
        $ok = $false
    }
    if ($CTXReqOSBuild -gt 0 -and $CTX.CTXOSBuild -lt $CTXReqOSBuild) {
        Write-Error "Required minimum OS build: $CTXReqOSBuild, actual: $($CTX.CTXOSBuild)."
        $ok = $false
    }
    if ($CTXAbortIfPendingReboot -and $CTX.CTXPendingReboot) {
        Write-Error "A reboot is pending on this machine. Aborting as -CTXAbortIfPendingReboot is set."
        $ok = $false
    }
    if (-not $ok) { return $null }
    return $CTX
}
Function Add-AddRemovePrograms {
    <#
    .SYNOPSIS
        Adds an application entry to Add Remove Programs (ARP) in Windows, allowing it to be displayed and optionally uninstalled or modified from there.
    .DESCRIPTION
        This function creates the necessary registry entries and files to make a script or application appear in the Add Remove Programs list in Windows Settings.
        It supports custom uninstall and modify scripts, as well as an application icon. 
        The function is designed to be flexible and can be used for various types of applications or scripts that need to be managed through ARP.
    .NOTES
        Author:  @MrTbone_se (T-bone Granheden)
        Version: 1.2.0
        
        Version History:
        1.0 - Initial version
        1.0.1 - Changed parameter names end improved error handling
        1.1.0 - Major refactor to support more features, better logging and error handling, and to be more modular and maintainable. Added parameters for shortcuts and folder copying.
        1.2.0 - Added icon handling improvements and adding program name to the icon for better UX in ARP and shortcuts.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [Parameter(Mandatory = $false,          HelpMessage = 'Name of the application/script being wrapped')]
        [String]$ARPAppName             = "App Name",

        [Parameter(Mandatory = $false,          HelpMessage = 'Version of the application. Increment when changing config')]
        [ValidatePattern("^\d+\.\d+\.\d+$")]
        [version]$ARPAppVersion         = "1.0.0",

        [Parameter(Mandatory = $false,          HelpMessage = 'GUID of the application/script being wrapped. NOTE: This needs to be unique for each wrapped app')]
        [ValidatePattern('^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$')]
        [String]$ARPAppGuid             = "{feedbeef-beef-4dad-beef-b628ccca16e0}",

        [Parameter(Mandatory = $false,          HelpMessage = 'Company name used for naming of folders and registry keys')]
        [String]$ARPAppPublisher        = "Coligo",
        
        [Parameter(Mandatory = $false,          HelpMessage = "Application folder path, if not specified, it will use %ProgramFiles%\ARPPublisher\ARPAppName ")]
        [string]$ARPAppFolder           = "$Env:Programfiles\$ARPAppPublisher\$ARPAppName",
        
        [Parameter(Mandatory = $false,          HelpMessage = 'Enable an uninstall option in Add Remove Programs')]
        [bool]$ARPAppEnableUninstall    = $True,

        [Parameter(Mandatory = $false,          HelpMessage = 'Enable a modify option in Add Remove Programs (typically for repair/reinstall)')]
        [bool]$ARPAppEnableModify       = $True,

        [Parameter(Mandatory = $false,          HelpMessage = 'Optional Base64-encoded .ico content to use as the icon of the app')]
        [string]$ARPAppIcon,
        
        [Parameter(Mandatory = $false,          HelpMessage = 'Optional path to a .ps1 file to use as the installer script')]
        [string]$ARPAppInstallScript    = "",

        [Parameter(Mandatory = $false,          HelpMessage = 'Optional path to a .ps1 file to use as the uninstaller script')]
        [string]$ARPAppUnInstallScript  = "",

        [Parameter(Mandatory = $false,          HelpMessage = 'Optional path to a .ico file to use as the icon of the app')]
        [string]$ARPAppIconPath         = "",

        [Parameter(Mandatory = $false,          HelpMessage = 'If $true, copy every file in the wrapper''s source folder into the app folder (excluding the wrapper itself, the install/uninstall scripts and the icon, which are deployed under standardized names).')]
        [bool]$ARPAppIncludeFolder      = $false,

        [Parameter(Mandatory = $false,          HelpMessage = 'Optional name of a companion file inside the app folder to launch (t-bone.exe). If blank, shortcuts default to launching the deployed wrapper script.')]
        [string]$ARPAppUserStartFile    = "",

        [Parameter(Mandatory = $false,          HelpMessage = 'Create an All-Users Desktop shortcut (targets ARPAppUserStartFile when set, otherwise the deployed wrapper script)')]
        [bool]$ARPAppShortcutOnDesktop  = $false,

        [Parameter(Mandatory = $false,          HelpMessage = 'Create an All-Users Start Menu shortcut (targets ARPAppUserStartFile when set, otherwise the deployed wrapper script)')]
        [bool]$ARPAppShortcutInStart    = $false,

        [Parameter(Mandatory = $false,          HelpMessage = 'Force the action to reregister the application in ARP even if it is already present. This can be useful to update the icon or other metadata.')]
        [bool]$ARPAppForce              = $False
    )
    Begin {
        $ErrorActionPreference = 'Stop'
        Write-Verbose "Start Function Add-AddRemovePrograms"
        $private:HKCRDrive = $false
        # Ensure System.Drawing is loaded - it is not auto-loaded in SYSTEM / headless / PS7 sessions
        try   { Add-Type -AssemblyName System.Drawing -ErrorAction Stop }
        catch { Write-Warning "Failed to load System.Drawing assembly. Icon generation will be skipped. Error: $_" }
        # ARP app icon settings (used for dynamic icon generation when Base64 or file path is provided, or as defaults for the demo icon)
        $ARPAppIcoHorizontal  = 20    # 0 = center
        $ARPAppIcoVertical    = 28    # 0 = center
        $ARPAppIcoRotation    = -17   # degrees
        $ARPAppIcoFontSize    = 0     # 0 = auto-fit
        $ARPAppIcoFontFamily  = 'Arial'
        $ARPAppIcoFontWeight  = [System.Drawing.FontStyle]::Bold  # Regular, Bold, Italic, or Bold -bor Italic
        $ARPAppIcoColor       = [System.Drawing.Color]::FromArgb(246, 146, 30)
        $ARPAppIcoSize        = 256
        # Default demo app icon, used when no icon path or Base64 is provided.
        $ARPAppDefaultIconBase64  = "iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAMAAAD04JH5AAAAtFBMVEX///80LCcwIhwmGRYZFBEFAgEXCAUmCwYqEgs4FAt
        GGQs3FA1YJhdTIg9oNidNFwtlKhh2OyeMTDNxLhZpOi14RzZyQjKoa02QWUVpHAmTNQ7apWT+jwT3cwHCPwDTUgH+qBKtVB30xpDPnoPa49+CSDKQdGPz6tzk3M/
        FvK3y7uXr5dn89un//vvQx7nZ08e4sqexqJqThnifl4tzbGFORDxpV0xWT0YnGxYwHhdJIxhRMSkmJKzTAAAAAXRSTlMAQObYZgAADvpJREFUeNrt2u1zVMeVgPH
        nnO6+d0YSwgbHuOJkN3YCBCT0BgKN/PeHGbDeBTYg26lK7cZO4tgYIWnmdvc5yxYux5WKU8RBSe2Wfp/mWz91bn+Y2305c+bMmTNnzvzfsbYuevsCAFy8+ObszAc
        fzM5cHPBP0ldcXcPGPSXxLsDF2da1d7B/Q8PjS3D63pj94ANdb5pmevadd2Hw5k8vvHnhhdlLFy69e/n0R//2W+tvzc689c6lC/03z7/97jv95vylSxcuvHPhxfL
        vvnmBf4rw9wzu4esjW/cHWlWU1hgzwzd1Nl7679jDJ27dxYPXHzD48gAGB53O3VWDFFssOu0kMaFORXrPI2V6ctJOUubq8HUGvGWUQ7V1wEdrCIyaPiAO4j0X56n
        0EtJBxYKKvyh4bQGD/Sbla+AyHGwvyajfu/KgtURH25GESe69x1POGTg4R/TDp4nmi9cVMBNyaOQqcHA5P8rLBxNL4oq3x3XqjRl3pwp8X/2jBfQPryngnI5d1FS
        oTUoTi+IgXpoLU54DLznGd4L9IdhJ1K9eT8AbhK7EmiSYkJj4dPusXqnlqA/gBn8t1N81yY+5MXwdAVNp7mNpOndEMI8lNvkX9bAnuAkvlQCg4hiVKPbHLMxtxcP
        XEDDYY/Ej+idStUZ1wcfXc1ZMKgFKAhMKBNRLQgDofWZWxedH/BiRv9C9xRFzn1aKmos7zWFHNKvthIArQXXsEkHCQ83cUjczlyLeNM8/gm8N/N4tQUf/YMBAdsc
        y4ImMw/Qv95K3nb//IULXiwQv0osPk3Ojc0Bw6ek+FKSsxs69Q9ZGAMlXujI/BhbD1j/yCAbCVnGTNbbbxn0csPaoyHI9AWKUzeSi3S0bO5REsy8CIu7eJikopfc
        nWNtcGRvkWalHkdAfvvIEetviE0VEdsWUKvlnXx86GKUXw0YgIV4jIQcBC4I7AOjMxJRxKycgW+VpU0XObwE3ujp+5f8Da7lbDq0joKF5fnxS9CdXVgQaPb+3tx1
        FcAdP1gNipfKSxOmpRmhDJ/OApymE7IDvBc93XjXgPg2LllwcW4iNMR32Huw4kHaSKu7OS6JAxCsaQkz9PkfueJPkMQOB/QlEw1GNkF8xQCWAVI8uLO6OO+mNc5p
        3YHMomDkgQeCuBgAoA01t2zTiyYv2ctIuMhSQ3waJIStuh+ADftDgewEDjOFdL6TELkX1mCk7WEG8BnMQkVABBAHAfUJAY9A240xqaZjAbXEs44YJDpkfMkg6WVw
        agAKs4+5TqKr4LhrMm/77aewqAKHeXl1arcEcaTxkAFMjt02MdL2Cp94kx+swvOlYIm+wavg50L+xstyGtY2lX+dSjkEBBKi518YAC1YyU3H8mcxvL99cXW2bmwP
        84VYjAIb1vL4cSS+TvRFvWgmlqQgwdNaFFnDcDOH7ktxJGyvXTtYGm+UoxCeP6ioKrLuDW61qyNbJsspEWsafTMP+w8Xpg8e7TxZDuKUKgCgVqFM0zw9/9s5//PT
        nP5dDI8pjYADdBBGA22PttUOgaa4sXQFNi9ePl+04YBssBdtFUCKsMVpbu4dXBK0l3F3furEXjY59QvNRDsZ4r3fVQSB1oQBVXXqTzqkAb3fTgn4OABrQ2yMXqko
        YAdHmrLa//swXjwOHc65FcKMNGKCg9AF3V6dKUL27zMJ1a5viIY29d1X66HiXFXdwFVqA8p4fo6pu1bVntT47BhAcd+GeWNGyextU5k0+/ijNr3TJNHY9KcbN7Al
        ucR8FGQGp329ydpcohI17o9HCe9qPnrHyJIAH29sVYITmCZUqdmzAhCru3nWc7wbgYM7z4SCxWOWJDlkLK8X3RZsJ+w9DlYMd2CCrbkAJAQVgl1ihl8xrlUYJgjw
        aH3U1tVSppVEJvb6Ik9x7ACKeQZ851BiCTjWxAVCgzqYNX5w0jzTDh3TSCohsRVGJiklAJCllHFaJ4FTQlb1gKxtag1Yg2H1NsYHQchK9auKK7Bi4pBzihKrVDGY
        D8S4iiNgsAELteV09mfhWzLC2WTsVBSjRzBO1NkJ2gaVu21HYJfvu/EegKBgOiq/IQk8ouTtppFOQB74IYARo2xa/Cba5uX0vtE2MypQL3AfDx9e+EYnX5gZwj1X
        NrQJyG6vhQ1YlYOLCQp65Awo4sF0WsO2AYGBIuN+JIWXSpM41vQ2NSAGaIgD4JAMpoGov+G2bOIBBnn70ycf7TSxHl1Ey/bsIONwSiVQRjGjXTqa3RqBwQ6AuL+w
        tqi4KCTN1IcZ7J6E2TZ3Edka+kni86w0wRCuAh6fgbv6/4PbjRRmCOxJbUbG0E3UyJYq53FkxnhERguOu3MJt/GgrAwqjvjt7e1BsD82o4qgQj7/Ok86WTo6OXbo
        8tbALToM3ANXPiYqK1tqsrkaO9gIADlQXcba1LSuYu46AmXwX4xAMwNn57Z2c4k0UAMPhYWBBDTcMuiKmNfcWTS5cuFiKSN1bCgJGEyYOrRJeaNPFC3M7nHu8bHM
        AYBDKikNQ4jE2iQrgojizMHZlQyEPlZtHKHDU93KysFBZxjTFoBGL6h7flivM7zQqM0WEmd0lAQwFx60GT3pj4b2riQNH4ggQnCrGyBGPOBVc2FDGjVI94Ckacsw
        dNDCeQQGq02whvr0TV6gCmKpPvd27uPvpvWLFVIFJcP9uFzrVrzUSnuw92PYojAkA4N6isOq4QOu3yGDuTQCrRs3+jHCekgLzvosCjBsvtlMF6o4EcVPM9bx30d7
        Xiw5e8WqG4AwJDYDgMeTjZibstZfF9q/yLVeDkeOA0ABArYJLswFtnmaliScr9Vf5QUYBGIeIOO5BAQmi0AMpb+xqAAKiiu0CNFgmQ1uwX5xzU+mz/6vlG7y0Dmw
        ADoBwt0kG3CRRyaCB8a/H97ebo+v+MIACQIdmc/EqUSKKwpQA33QXHZjkX+c5LvQQcGt6AF68flFmfNK8GXp7vrsPIHQTnJcqWUUUXVNq2OAWPSFE2mYf3en3P40
        ZlJfG487N8UpEcEMwiE5CBOz3F++fT+cAvOmEFohmuPZ64z89/6buyAIAKPk5Lz2jh2qQuimeg6ITd3xjOm4HJOzukgHlO507UEoVCTiCKFErFY6nvHvLOnrguCp
        koM6NU8ljH9u5c20d8q12FhgIt6ezBtFDHN7P23B/6hg87OyE+kLuMoDy/QIDIi6uSHTNzFyIcgQn1NSaEEVgl5An5BzFJUfamX6EsMRLngC4F6TWViJ+vjsqK+0
        5hbB3IGbFb2Uzd4e/DqDDkBKoYYWe4F4kUbPjU14Ov1TvbgLF6NGCF6tNbhxrjo7HmwAIloU74F5ctL0L27MydzzZFjOrd+z24E4d/fBJaedWBGBHpogZ1Mqfz1N
        c4NB///kCjjsotOTqVTxHXIItRL5vTVktXbobgM1HUw8+u11s7Y6PGP5mCD8cQGfU2qAiGE+PBcQEiIjrarO/HYDGDlsB2tqOYz0qHvrL2wsAAwRAuKc24dx9SjU
        07aRbQ/y7pf9eAJ1BpqtBvBQQlAgIou3HPWuCwFDfEGhb/P2+aa96Zp+/7EHlfhN9oaQPccxqzrUbvfph9aQCQopABp4jiEC52dbMHA59BAQcc6+diAnh+y9a6it
        zubeldwB/ocKrB7Bs4EwJAjjPAcRiK5nEXhUojoKg2ImIeyDP48Bg092gzF057h7uyOroRx3Xj6y6uRgKIJbAEX+641oQARwcEEHMW/QnMe8poJvLv7pWgwdrH3y
        SuD3iRwXQOWgEJ4kI5wH7/Ivri/MkykoCHFUFPN9o0fbLn8+o7YM4KbRb2zsf7ydfKUN+ZACd8wbOkeRcvkAcpjTtfvKYzLKf4DQoKBDKN52fjD+rJQgDYfOjh1s
        hiNtKGfFqIn/D8qYgfkx4WuBoGuZka2Xf1PoHl/vZGd4SAOnf5w1HQ2etwTDgwXC/PWIE/0zAcPDRNG5CY/jJifPl4orP86B/lLYBGnA5PL/pqS9NFklmc3uweg9
        jbcjodVxYNOJtQYIXw11teWOd/FnH/G6tyJJ8/caGS0g9kNzPNiE8f72XVp1rNfEaUxAB2V7n4NEVkU8WAYSDDz3FtsWbaCchrXDjtV/ZNIg6SqiYQZa1J+I6vrH
        hLqv5w7ZqvwVyshNY2Jsfve4AaN1VI1TNjrsNvPDZ1S0zwYRWtedZHMLELISnrz+A1oV+RxIfO4bbOVOyZofVB0yNXbWZpO64l5f3TiWARggqDlYdqGuPjwQ3ZGV
        PVcSkEencujZb0//8FAJoXXpZiR1F3UnJbHFLlvbQ6OpNdiDh3XV5EP98GgH0XAWaWtBq1EhbgtRobjtxACRmwuT5zcdzw9O4O14WgOJiWRJSbjaIAYJAgkRT8KJ
        x48YTTiNgiId+iAGNeFDPV+r81Li6Z9yLuDTj54Wqq4qfSgDL3nVec4JaCGmfm5uXFZWcRJzeuGuaSU99f+0xp7IHoIWQMsELCFbW2DhXel2Z6kiZtqtybQcP19P
        Dp6cyASaCdzgI7i4yJF8px6UleYFJKdceLMcVT5TLpzMBBpvJAHEqATPJ63uhRnFxgYBcPjhagtHU4elMgOFKBpFmqhHMCRIcoruWaNlLNv5zibuj1L9wSgGMxAT
        oCCKCo6PSXY54zLSVpGwyXF/r5a9OK4CJQKheEUdxbcaSxjUEsW4+XPmSwUi2HwCnFoA7QEQUUTXTE3d778jN5KuhjzbjTBDSKQZMjHJDigoQUyBw7/gkLncs3h3
        QxhBMkV/yYwivZG1HEAJFXDR2BaoLpFBcFJnpak/+yI8ReSWjNjgQ8Irx7U8RL4TlPcOtZcxpBjBBEYqYuNQAGCJKU/qPSCqNCJzmIwBaBQmaayBoJ+DC0h6pSp3
        KQcfPTjugIQiAS+hCqARwcQld7YmV9mtOO4BGVByQQNdQ8RChayYxxpMQvjr9ANa21UVwCcU11BBJJ8Qag4x5xo8UeHX/FRDA1KWKemiu/q5pJj1Rrn4KnP4EoBE
        QETWPnlvtFJ0/kF8O4V8UwNoOCJG6tL38AAtJL/Mb+NcFMNgrKi6+DMiuXnpryL9avze9Pt1bX59en/2Af4v1tn3RsP7BLP8u6y+WX187+8z3zJkzZ86cOXPmzJk
        zZ/6/+B8/kP8dKpG6aAAAAABJRU5ErkJggg=="
    }
    Process {
        # Determine scripts own name and path
        if (-not $PSCommandPath) {
            Write-Error "Could not determine the script path. Ensure this is run as a .ps1 file, not pasted into a console."
            $false
            return
        }
        $ExecutingScriptPath = $PSCommandPath
        $ExecutingScriptName = Split-Path $PSCommandPath -Leaf
        Write-Verbose "Executing script is enumerated as: $ExecutingScriptPath ($ExecutingScriptName)"

        # Convert GUID to MSI Packed GUID (ProductID) - MSI reverses each segment: segments 1-3 are fully reversed, segments 4-5 are pair-swapped
        # Example: {FEEDBEEF-BEEF-4DAD-BEEF-B628CCCA16E0} -> FEEBDEEFFEEBDAD4EBFE6B82CCAC610E
        [string]$private:stripped = $ARPAppGuid -replace '[{}\-]', ''
        [string]$ARPFuncProductID = (
            ($stripped[7..0]   -join '') +  # Segment 1 (8 chars): reverse
            ($stripped[11..8]  -join '') +  # Segment 2 (4 chars): reverse
            ($stripped[15..12] -join '') +  # Segment 3 (4 chars): reverse
            (($stripped[16..31] | ForEach-Object -Begin { $private:pair = @() } -Process {
                $pair += $_
                if ($pair.Count -eq 2) { $pair[1]; $pair[0]; $pair = @() }
            }) -join '')
        )
        Write-Verbose "Derived MSI Packed GUID (ProductID): $ARPFuncProductID"

        # Standardized deployed names so batches and registry are stable regardless of source filenames.
        [string]$private:DeployedWrapperName     = 'App-Wrapper.ps1'
        [string]$private:DeployedInstallerName   = "installer-$ARPAppGuid.ps1"
        [string]$private:DeployedUninstallerName = "uninstaller-$ARPAppGuid.ps1"
        [string]$DeployedWrapperPath     = Join-Path -Path $ARPAppFolder -ChildPath $DeployedWrapperName
        [string]$DeployedInstallerPath   = Join-Path -Path $ARPAppFolder -ChildPath $DeployedInstallerName
        [string]$DeployedUninstallerPath = Join-Path -Path $ARPAppFolder -ChildPath $DeployedUninstallerName

        # Registry / icon / batch paths
        [string]$ARPFuncIconPath        = Join-Path -Path $ARPAppFolder -ChildPath "$($ARPAppName -replace '\s', '').ico"
        [string]$ARPFuncUninstallRegKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$ARPAppGuid"
        [string]$ARPFuncProductsRegKey  = "HKCR:\Installer\Products\$ARPFuncProductID"

        # Version gate: skip install when an equal-or-newer version is already registered (unless -ARPAppForce $true).
        if (-not $ARPAppForce) {
            [version]$private:CurrentVersion = '0.0.0.0'
            try {
                Write-Verbose "Checking installed version under $ARPFuncUninstallRegKey."
                $private:dv = (Get-ItemProperty -LiteralPath $ARPFuncUninstallRegKey -Name DisplayVersion -ErrorAction Stop).DisplayVersion
                if ($dv) {
                    $CurrentVersion = [version]$dv
                    Write-Verbose "Found installed app, CurrentVersion=$CurrentVersion"
                } else {Write-Verbose "DisplayVersion missing/empty under $ARPFuncUninstallRegKey; treating as not installed."}
            } catch [System.Management.Automation.ItemNotFoundException],[System.Management.Automation.PSArgumentException] {
                Write-Verbose "Registry key $ARPFuncUninstallRegKey not found; treating as not installed."
            } catch {Write-Verbose "Failed to read/parse DisplayVersion from $ARPFuncUninstallRegKey ($_); treating as not installed."}
            if ($CurrentVersion -ge $ARPAppVersion) {
                Write-Verbose "Skipping install: installed version ($CurrentVersion) is >= packaged version ($ARPAppVersion). Use -ARPAppForce `$true to override."
                $false
                return
            }
            Write-Verbose "Proceeding with install: $CurrentVersion -> $ARPAppVersion."
        }
        [string]$ARPFuncUninstallBAT    = Join-Path -Path $ARPAppFolder -ChildPath "uninstall-$ARPAppGuid.bat"
        [string]$ARPFuncModifyBAT       = Join-Path -Path $ARPAppFolder -ChildPath "reinstall-$ARPAppGuid.bat"
        [string]$ARPFuncUninstallString = 'CMD /C START cmd /c "{0}"' -f $ARPFuncUninstallBAT
        [string]$ARPFuncModifyString    = 'CMD /C START cmd /c "{0}"' -f $ARPFuncModifyBAT

        # Common batch line: cd to a known-good working directory before invoking PowerShell
        [string]$ARPFuncUninstallcmd1   = 'cd /d "%SystemRoot%"'
        [string]$ARPFuncModifycmd1      = $ARPFuncUninstallcmd1

        # Build the PowerShell command lines that the .bat files will run.
        $private:BuildPwshLine = {
            param([string]$InstallTypeArg, [string]$ExtraArgs)
            "Powershell.exe -NoProfile -ExecutionPolicy Bypass -Command `"& '$DeployedWrapperPath' -installtype $InstallTypeArg$ExtraArgs`""
        }

        # Uninstall extras: pass -ARPAppUnInstallScript only if a uninstall script will actually be deployed
        [string]$private:UninstallExtraArgs = ''
        if ($ARPAppUnInstallScript -and (Test-Path $ARPAppUnInstallScript)) {
            $UninstallExtraArgs = " -ARPAppUnInstallScript '$DeployedUninstallerPath'"
        }
        [string]$ARPFuncUninstallcmd2 = & $BuildPwshLine 'UnInstall' $UninstallExtraArgs

        # Modify (Repair) extras: forward shortcut/include flags + optional installer script
        [string]$private:ModifyExtraArgs = ''
        if ($ARPAppIncludeFolder)                                    { $ModifyExtraArgs += " -ARPAppIncludeFolder `$true" }
        if (-not [string]::IsNullOrWhiteSpace($ARPAppUserStartFile)) { $ModifyExtraArgs += " -ARPAppUserStartFile '$ARPAppUserStartFile'" }
        if ($ARPAppShortcutOnDesktop)                                { $ModifyExtraArgs += " -ARPAppShortcutOnDesktop `$true" }
        if ($ARPAppShortcutInStart)                                  { $ModifyExtraArgs += " -ARPAppShortcutInStart `$true" }
        if ($ARPAppInstallScript -and (Test-Path $ARPAppInstallScript)) {
            $ModifyExtraArgs = " -ARPAppInstallScript '$DeployedInstallerPath'" + $ModifyExtraArgs
        }
        [string]$ARPFuncModifycmd2 = & $BuildPwshLine 'Repair' $ModifyExtraArgs

        # Ensure application folder exists otherwise create it
        if(-not (Test-Path $ARPAppFolder) -or $ARPAppForce){
            if ($PSCmdlet.ShouldProcess($ARPAppFolder, "Create application folder")) {
                try {
                    New-Item -ItemType Directory -Path $ARPAppFolder -Force -ErrorAction Stop | Out-Null
                    Write-Verbose "Application folder ready: $ARPAppFolder"
                    } catch {Write-Warning "Failed to create folder $ARPAppFolder. Error: $_"}
            }
        } else {Write-Verbose "Application folder already exists: $ARPAppFolder"}

        # Create and Save the AppIcon - prefer external .ico file, then parameter Base64, then embedded default Base64.
        $ARPEffectiveIconBase64 = $ARPAppDefaultIconBase64
        if ($ARPAppIconPath -and (Test-Path $ARPAppIconPath)) {
            try {
                $ARPEffectiveIconBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($ARPAppIconPath))
                Write-Verbose "Loaded AppIcon from file as base64: $ARPAppIconPath"
            } catch {Write-Warning "Failed to read icon file as base64 from $ARPAppIconPath. Falling back to embedded default icon. Error: $_"}
        }
        elseif ($ARPAppIcon) {
            $ARPEffectiveIconBase64 = $ARPAppIcon
            Write-Verbose "Using provided base64 AppIcon string."
        }
        else {Write-Verbose "Using embedded default AppIcon."}
        # Load and rezize the icon
        try {
            $ARPIconMemory = New-Object System.IO.MemoryStream(,[Convert]::FromBase64String($ARPEffectiveIconBase64))
            $ARPSourceIconImage = [System.Drawing.Image]::FromStream($ARPIconMemory, $true, $true)
        } catch {
            Write-Warning "Selected icon source is invalid image/base64. Falling back to embedded default icon. Error: $_"
            $ARPEffectiveIconBase64 = $ARPAppDefaultIconBase64
            $ARPIconMemory = New-Object System.IO.MemoryStream(,[Convert]::FromBase64String($ARPEffectiveIconBase64))
            $ARPSourceIconImage = [System.Drawing.Image]::FromStream($ARPIconMemory, $true, $true)
        }
        $ARPIconBitmap = New-Object System.Drawing.Bitmap($ARPAppIcoSize, $ARPAppIcoSize)
        $ARPGraphics = [System.Drawing.Graphics]::FromImage($ARPIconBitmap)
        $ARPGraphics.SmoothingMode = 'AntiAlias'
        $ARPGraphics.InterpolationMode = 'HighQualityBicubic'
        $ARPGraphics.PixelOffsetMode = 'HighQuality'
        $ARPGraphics.DrawImage($ARPSourceIconImage, 0, 0, $ARPAppIcoSize, $ARPAppIcoSize)

        # Auto-fit font size via binary search
        if ($ARPAppIcoFontSize -eq 0) {
            $ARPMax = $ARPAppIcoSize - 20; $ARPLow = 1; $ARPHigh = 200
            while ($ARPLow -lt $ARPHigh) {
                $ARPMid = [int](($ARPLow + $ARPHigh + 1) / 2)
                $ARPFontMeasure = New-Object System.Drawing.Font($ARPAppIcoFontFamily, $ARPMid, $ARPAppIcoFontWeight, 'Pixel')
                $ARPMeasuredSize = $ARPGraphics.MeasureString($ARPAppName, $ARPFontMeasure); $ARPFontMeasure.Dispose()
                if ($ARPMeasuredSize.Width -le $ARPMax -and $ARPMeasuredSize.Height -le $ARPMax) { $ARPLow = $ARPMid } else { $ARPHigh = $ARPMid - 1 }
            }
            $ARPAppIcoFontSize = $ARPLow
        }

        $ARPFont = New-Object System.Drawing.Font($ARPAppIcoFontFamily, $ARPAppIcoFontSize, $ARPAppIcoFontWeight, 'Pixel')
        $ARPTextSize = $ARPGraphics.MeasureString($ARPAppName, $ARPFont)
        $ARPX = ($ARPAppIcoSize - $ARPTextSize.Width) / 2 + $ARPAppIcoHorizontal
        $ARPY = ($ARPAppIcoSize - $ARPTextSize.Height) / 2 + $ARPAppIcoVertical

        if ($ARPAppIcoRotation) {
            $ARPGraphics.TranslateTransform($ARPX + $ARPTextSize.Width/2, $ARPY + $ARPTextSize.Height/2)
            $ARPGraphics.RotateTransform($ARPAppIcoRotation)
            $ARPGraphics.TranslateTransform(-($ARPX + $ARPTextSize.Width/2), -($ARPY + $ARPTextSize.Height/2))
        }

        $ARPShadowBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(128,0,0,0))
        $ARPTextBrush = New-Object System.Drawing.SolidBrush($ARPAppIcoColor)
        $ARPGraphics.DrawString($ARPAppName, $ARPFont, $ARPShadowBrush, ($ARPX+1), ($ARPY+1))
        $ARPGraphics.DrawString($ARPAppName, $ARPFont, $ARPTextBrush, $ARPX, $ARPY)

        if (-not (Test-Path -LiteralPath $ARPFuncIconPath) -or $ARPAppForce) {
            if ($PSCmdlet.ShouldProcess($ARPFuncIconPath, "Save rendered AppIcon")) {
                try {
                    # GDI+ Bitmap.Save(...,ImageFormat.Icon) is broken (Windows: "file contains no icons").
                    # Build a real multi-size ICO with PNG-encoded entries (valid since Vista).
                    $ARPIcoSizes = 256,64,48,32,16
                    $ARPIcoPngs  = foreach ($sz in $ARPIcoSizes) {
                        $bmp = New-Object System.Drawing.Bitmap($sz, $sz, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
                        $g   = [System.Drawing.Graphics]::FromImage($bmp)
                        $g.InterpolationMode='HighQualityBicubic'; $g.SmoothingMode='AntiAlias'
                        $g.PixelOffsetMode='HighQuality'; $g.CompositingQuality='HighQuality'
                        $g.DrawImage($ARPIconBitmap, 0, 0, $sz, $sz); $g.Dispose()
                        $ms = New-Object System.IO.MemoryStream
                        $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
                        ,$ms.ToArray()
                    }
                    $ico = New-Object System.IO.MemoryStream
                    $bw  = New-Object System.IO.BinaryWriter($ico)
                    $bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$ARPIcoSizes.Count)   # ICONDIR
                    $offset = 6 + 16 * $ARPIcoSizes.Count
                    for ($i = 0; $i -lt $ARPIcoSizes.Count; $i++) {
                        $sz = $ARPIcoSizes[$i]; $len = $ARPIcoPngs[$i].Length
                        $dim = if ($sz -ge 256) { [byte]0 } else { [byte]$sz }                          # 0 == 256
                        $bw.Write($dim); $bw.Write($dim); $bw.Write([byte]0); $bw.Write([byte]0)        # w,h,colors,reserved
                        $bw.Write([uint16]1); $bw.Write([uint16]32)                                     # planes, bpp
                        $bw.Write([uint32]$len); $bw.Write([uint32]$offset)
                        $offset += $len
                    }
                    foreach ($d in $ARPIcoPngs) { $bw.Write($d) }
                    $bw.Flush(); [IO.File]::WriteAllBytes($ARPFuncIconPath, $ico.ToArray())
                    $bw.Dispose(); $ico.Dispose()
                    Write-Verbose "Icon created: $ARPFuncIconPath (font size: $ARPAppIcoFontSize)"
                } catch { Write-Warning "Failed to save rendered AppIcon to $ARPFuncIconPath. Error: $_" }
            }
        } else {Write-Verbose "AppIcon already exists: $ARPFuncIconPath"}

        $ARPShadowBrush.Dispose(); $ARPTextBrush.Dispose(); $ARPFont.Dispose(); $ARPGraphics.Dispose(); $ARPIconBitmap.Dispose(); $ARPSourceIconImage.Dispose(); $ARPIconMemory.Dispose()

        # Save the current PowerShell script (renamed to standardized deployed name)
        if ($ExecutingScriptPath -ne $DeployedWrapperPath -or $ARPAppForce) {
            if ($PSCmdlet.ShouldProcess($DeployedWrapperPath, "Copy wrapper script")) {
                try {
                    Copy-Item $ExecutingScriptPath $DeployedWrapperPath -Force | Out-Null
                    Write-Verbose "Success to copy script to $DeployedWrapperPath"
                } catch {Write-Warning "Failed to copy script to $DeployedWrapperPath. Error: $_"}
            }
        } else {Write-Verbose "Script already exists at target: $DeployedWrapperPath"}

        # Copy external install script if provided (renamed to standardized deployed name)
        if ($ARPAppInstallScript -and (Test-Path $ARPAppInstallScript)) {
            $private:InstallTarget = Join-Path -Path $ARPAppFolder -ChildPath $DeployedInstallerName
            if (-not (Test-Path $InstallTarget) -or $ARPAppForce) {
                if ($PSCmdlet.ShouldProcess($InstallTarget, "Copy install script")) {
                    try {
                        Copy-Item -Path $ARPAppInstallScript -Destination $InstallTarget -Force | Out-Null
                        Write-Verbose "Success to copy install script to $InstallTarget"
                    } catch {Write-Warning "Failed to copy install script. Error: $_"}
                }
            } else {Write-Verbose "Install script already exists at target: $InstallTarget"}
        }

        # Copy external uninstall script if provided (renamed to standardized deployed name)
        if ($ARPAppUnInstallScript -and (Test-Path $ARPAppUnInstallScript)) {
            $private:UninstallTarget = Join-Path -Path $ARPAppFolder -ChildPath $DeployedUninstallerName
            if (-not (Test-Path $UninstallTarget) -or $ARPAppForce) {
                if ($PSCmdlet.ShouldProcess($UninstallTarget, "Copy uninstall script")) {
                    try {
                        Copy-Item -Path $ARPAppUnInstallScript -Destination $UninstallTarget -Force | Out-Null
                        Write-Verbose "Success to copy uninstall script to $UninstallTarget"
                    } catch {Write-Warning "Failed to copy uninstall script. Error: $_"}
                }
            } else {Write-Verbose "Uninstall script already exists at target: $UninstallTarget"}
        }

        # Copy every other file from the wrapper's source folder into the app folder (excluding the wrapper, install/uninstall scripts and icon)
        if ($ARPAppIncludeFolder) {
            [string]$private:SourceFolder = $PSScriptRoot
            if ([string]::IsNullOrWhiteSpace($SourceFolder) -or -not (Test-Path -LiteralPath $SourceFolder -PathType Container)) {
                Write-Warning "ARPAppIncludeFolder set but source folder could not be resolved from `$PSScriptRoot. Skipping folder copy."
            } elseif ((Resolve-Path -LiteralPath $SourceFolder).Path -eq (Resolve-Path -LiteralPath $ARPAppFolder).Path) {
                Write-Verbose "ARPAppIncludeFolder source equals target ($SourceFolder); nothing to copy."
            } else {
                # Build exclude set of source leaf names that are deployed under standardized names (or are the wrapper itself)
                [System.Collections.Generic.HashSet[string]]$private:Excluded = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                [void]$Excluded.Add((Split-Path -Path $PSCommandPath -Leaf))
                if ($ARPAppInstallScript)   { [void]$Excluded.Add((Split-Path -Path $ARPAppInstallScript   -Leaf)) }
                if ($ARPAppUnInstallScript) { [void]$Excluded.Add((Split-Path -Path $ARPAppUnInstallScript -Leaf)) }
                if ($ARPAppIconPath)            { [void]$Excluded.Add((Split-Path -Path $ARPAppIconPath            -Leaf)) }
                foreach ($private:srcFile in (Get-ChildItem -LiteralPath $SourceFolder -File -Force)) {
                    if ($Excluded.Contains($srcFile.Name)) { Write-Verbose "Skipping excluded source file: $($srcFile.Name)"; continue }
                    [string]$private:companionTarget = Join-Path -Path $ARPAppFolder -ChildPath $srcFile.Name
                    if (-not (Test-Path $companionTarget) -or $ARPAppForce) {
                        if ($PSCmdlet.ShouldProcess($companionTarget, "Copy file from source folder")) {
                            try {
                                Copy-Item -LiteralPath $srcFile.FullName -Destination $companionTarget -Force | Out-Null
                                Write-Verbose "Success to copy file to $companionTarget"
                            } catch {Write-Warning "Failed to copy file '$($srcFile.FullName)'. Error: $_"}
                        }
                    } else {Write-Verbose "File already exists at target: $companionTarget"}
                }
            }
        }

        # Create All-Users desktop/start shortcuts. If ARPAppUserStartFile is set and exists in ARPAppFolder it is used, otherwise shortcuts launch the deployed wrapper script.
        if ($ARPAppShortcutOnDesktop -or $ARPAppShortcutInStart) {
            [string]$private:ShortcutTargetPath = $null
            [string]$private:ShortcutArguments  = ''
            [string]$private:ShortcutIconFallback = $DeployedWrapperPath

            if (-not [string]::IsNullOrWhiteSpace($ARPAppUserStartFile)) {
                [string]$private:StartFileLeaf   = Split-Path -Path $ARPAppUserStartFile -Leaf
                [string]$private:StartFileTarget = Join-Path -Path $ARPAppFolder -ChildPath $StartFileLeaf
                if (Test-Path -LiteralPath $StartFileTarget -PathType Leaf) {
                    [string]$private:StartFileExt = [System.IO.Path]::GetExtension($StartFileTarget).ToLowerInvariant()
                    if ($StartFileExt -in '.js','.jse','.vbs','.vbe','.wsf') {
                        # Route .js/.vbs through wscript.exe so no console window is shown when the shortcut is launched.
                        [string]$private:WScriptTarget = Join-Path -Path $env:SystemRoot -ChildPath 'System32\wscript.exe'
                        if (-not (Test-Path -LiteralPath $WScriptTarget -PathType Leaf)) { $WScriptTarget = 'wscript.exe' }
                        $ShortcutTargetPath  = $WScriptTarget
                        $ShortcutArguments   = "`"$StartFileTarget`""
                        $ShortcutIconFallback = $StartFileTarget
                    } else {
                        $ShortcutTargetPath  = $StartFileTarget
                        $ShortcutIconFallback = $StartFileTarget
                    }
                } else {
                    Write-Warning "ARPAppUserStartFile '$StartFileLeaf' not found in $ARPAppFolder. Falling back to deployed wrapper script."
                }
            }

            if (-not $ShortcutTargetPath) {
                [string]$private:PwshTarget = Join-Path -Path $PSHOME -ChildPath 'powershell.exe'
                if (-not (Test-Path -LiteralPath $PwshTarget -PathType Leaf)) { $PwshTarget = 'powershell.exe' }
                $ShortcutTargetPath = $PwshTarget
                $ShortcutArguments = "-NoProfile -ExecutionPolicy Bypass -File `"$DeployedWrapperPath`""
            }

            [string]$private:DesktopLnk   = Join-Path -Path "$Env:Public\Desktop" -ChildPath "$ARPAppName.lnk"
            [string]$private:StartMenuDir = Join-Path -Path "$Env:ProgramData\Microsoft\Windows\Start Menu\Programs" -ChildPath $ARPAppPublisher
            [string]$private:StartMenuLnk = Join-Path -Path $StartMenuDir -ChildPath "$ARPAppName.lnk"
            [string]$private:LnkIcon      = if (Test-Path -LiteralPath $ARPFuncIconPath) { $ARPFuncIconPath } else { $ShortcutIconFallback }

            try {
                $private:WshShell = New-Object -ComObject WScript.Shell
                if ($ARPAppShortcutOnDesktop -and (-not (Test-Path -LiteralPath $DesktopLnk) -or $ARPAppForce)) {
                    if ($PSCmdlet.ShouldProcess($DesktopLnk, "Create Desktop shortcut")) {
                        try {
                            $private:lnk = $WshShell.CreateShortcut($DesktopLnk)
                            $lnk.TargetPath       = $ShortcutTargetPath
                            $lnk.Arguments        = $ShortcutArguments
                            $lnk.WorkingDirectory = $ARPAppFolder
                            $lnk.IconLocation     = $LnkIcon
                            $lnk.Description      = $ARPAppName
                            $lnk.Save()
                            Write-Verbose "Success to create Desktop shortcut: $DesktopLnk"
                        } catch {Write-Warning "Failed to create Desktop shortcut $DesktopLnk. Error: $_"}
                    }
                } elseif ($ARPAppShortcutOnDesktop) {Write-Verbose "Desktop shortcut already exists: $DesktopLnk"}

                if ($ARPAppShortcutInStart) {
                    if (-not (Test-Path -LiteralPath $StartMenuDir)) {
                        if ($PSCmdlet.ShouldProcess($StartMenuDir, "Create Start Menu folder")) {
                            try { New-Item -ItemType Directory -Path $StartMenuDir -Force | Out-Null }
                            catch { Write-Warning "Failed to create Start Menu folder $StartMenuDir. Error: $_" }
                        }
                    }
                    if (-not (Test-Path -LiteralPath $StartMenuLnk) -or $ARPAppForce) {
                        if ($PSCmdlet.ShouldProcess($StartMenuLnk, "Create Start Menu shortcut")) {
                            try {
                                $private:lnk = $WshShell.CreateShortcut($StartMenuLnk)
                                $lnk.TargetPath       = $ShortcutTargetPath
                                $lnk.Arguments        = $ShortcutArguments
                                $lnk.WorkingDirectory = $ARPAppFolder
                                $lnk.IconLocation     = $LnkIcon
                                $lnk.Description      = $ARPAppName
                                $lnk.Save()
                                Write-Verbose "Success to create Start Menu shortcut: $StartMenuLnk"
                            } catch {Write-Warning "Failed to create Start Menu shortcut $StartMenuLnk. Error: $_"}
                        }
                    } else {Write-Verbose "Start Menu shortcut already exists: $StartMenuLnk"}
                }
            } finally {
                if ($WshShell) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($WshShell) }
            }
        }

        # Create and Save the uninstall batch file
        if ($ARPAppEnableUninstall -and (-not (Test-Path $ARPFuncUninstallBAT) -or $ARPAppForce)) {
            if ($PSCmdlet.ShouldProcess($ARPFuncUninstallBAT, "Create uninstall batch file")) {
                try {
                    Set-Content -Path $ARPFuncUninstallBAT -Value @($ARPFuncUninstallcmd1, $ARPFuncUninstallcmd2) -Encoding Ascii -Force
                    Write-Verbose "Success to create Batch file for uninstall to $ARPAppFolder"
                } catch {Write-Warning "Failed to create batch file for uninstall. Error: $_"}
            }
        } elseif (-not $ARPAppEnableUninstall) {Write-Verbose "Uninstall not enabled, skipping batch file creation"}
        else {Write-Verbose "Batch file for uninstall already exists in $ARPAppFolder"}

        # Create and Save the modify batch file
        if ($ARPAppEnableModify -and (-not (Test-Path $ARPFuncModifyBAT) -or $ARPAppForce)) {
            if ($PSCmdlet.ShouldProcess($ARPFuncModifyBAT, "Create modify (reinstall) batch file")) {
                try {
                    Set-Content -Path $ARPFuncModifyBAT -Value @($ARPFuncModifycmd1, $ARPFuncModifycmd2) -Encoding Ascii -Force
                    Write-Verbose "Success to create Batch file for modify to $ARPAppFolder"
                } catch {Write-Warning "Failed to create batch file for modify. Error: $_"}
            }
        } elseif (-not $ARPAppEnableModify) {Write-Verbose "Modify not enabled, skipping batch file creation"}
        else {Write-Verbose "Batch file for modify already exists in $ARPAppFolder"}

        # Create or Add Registry Keys
        Write-Verbose "Starting registry operations."
        try {
            if (-not (Get-PSDrive HKCR -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)) {
                New-PSDrive -PSProvider Registry -Name HKCR -Root HKEY_CLASSES_ROOT | Out-Null
                $private:HKCRDrive = $true
                Write-Verbose "Created HKCR PSDrive."
            }

            # HKLM Registry Uninstall/Modify Entries
            if (-not (Test-Path $ARPFuncUninstallRegKey) -or $ARPAppForce) {
                if ($PSCmdlet.ShouldProcess($ARPFuncUninstallRegKey, "Create Registry Key")) {
                    try {
                        New-Item -Path $ARPFuncUninstallRegKey -Force | Out-Null
                        Write-Verbose "Success to create Registry Path $($ARPFuncUninstallRegKey)."
                    } catch {Write-warning "Failed to create Registry Path $($ARPFuncUninstallRegKey). Error: $_"}
                }
            }else {Write-Verbose "Registry Path already exists: $ARPFuncUninstallRegKey"}

            $RegistryProperties = @(
                @{ Name = "DisplayName";         Type = "String";    Value = $ARPAppName },
                @{ Name = "DisplayVersion";      Type = "String";    Value = $ARPAppVersion.ToString() },
                @{ Name = "Version";             Type = "DWord";     Value = ($ARPAppVersion.Major -shl 24) -bor ($ARPAppVersion.Minor -shl 16) -bor $ARPAppVersion.Build },
                @{ Name = "VersionMajor";        Type = "DWord";     Value = $ARPAppVersion.Major },
                @{ Name = "VersionMinor";        Type = "DWord";     Value = $ARPAppVersion.Minor },
                @{ Name = "Publisher";           Type = "String";    Value = $ARPAppPublisher },
                @{ Name = "DisplayIcon";         Type = "String";    Value = $ARPFuncIconPath },
                @{ Name = "Comments";            Type = "String";    Value = $ARPAppName },
                @{ Name = "InstallLocation";     Type = "String";    Value = $ARPAppFolder },
                @{ Name = "UninstallString";     Type = "String";    Value = $ARPFuncUninstallString },
                @{ Name = "QuietUninstallString";Type = "String";    Value = $ARPFuncUninstallString },
                @{ Name = "ModifyRegistryKey";   Type = "String";    Value = $ARPFuncUninstallRegKey },
                @{ Name = "ModifyString";        Type = "String";    Value = $ARPFuncModifyString },
                @{ Name = "ModifyPath";          Type = "String";    Value = $ARPFuncModifyString },
                @{ Name = "NoRemove";            Type = "DWord";     Value = 1 },# Default: Hide Remove button
                @{ Name = "NoModify";            Type = "DWord";     Value = 1 } # Default: Hide Modify button
            )
            # Adjust Uninstall/Remove if enabled
            if ($ARPAppEnableUninstall) {($RegistryProperties | Where-Object { $_.Name -eq "NoRemove" }).Value = 0}     
            # Adjust Modify/Repair if enabled       
            if ($ARPAppEnableModify) {($RegistryProperties | Where-Object { $_.Name -eq "NoModify" }).Value = 0}

            foreach ($Property in $RegistryProperties) {
                if ($PSCmdlet.ShouldProcess("$ARPFuncUninstallRegKey\$($Property.Name)", "Set Registry Value")) {
                    try {
                        New-ItemProperty -Path $ARPFuncUninstallRegKey -Name $Property.Name -PropertyType $Property.Type -Value $Property.Value -Force | Out-Null
                        Write-Verbose "Success to create/update Registry value '$($Property.Name)' under $($ARPFuncUninstallRegKey)."
                    } catch {Write-warning "Failed to create/update Registry value '$($Property.Name)' under $($ARPFuncUninstallRegKey). Error: $_"}
                }
            }

            # HKCR Registry Installer\Products Entries
            if (-not (Test-Path $ARPFuncProductsRegKey)) {
                if ($PSCmdlet.ShouldProcess($ARPFuncProductsRegKey, "Create Registry Key")) {
                    try {
                        New-Item -Path $ARPFuncProductsRegKey -Force | Out-Null
                        Write-Verbose "Success to create Registry Path $($ARPFuncProductsRegKey)."
                    } catch {Write-warning "Failed to create Registry Path $($ARPFuncProductsRegKey). Error: $_"}
                }
            } else {Write-Verbose "Registry Path already exists: $ARPFuncProductsRegKey"}

            $AdditionalRegistryProperties = @(
                @{ Name = "ProductName";       Type = "String";        Value = $ARPAppName },
                @{ Name = "Manufacturer";      Type = "String";        Value = $ARPAppPublisher },
                @{ Name = "ProductIcon";       Type = "String";        Value = $ARPFuncIconPath },
                @{ Name = "ProductVersion";    Type = "String";        Value = $ARPAppVersion.ToString() },
                @{ Name = "Version";           Type = "DWord";         Value = ($ARPAppVersion.Major -shl 24) -bor ($ARPAppVersion.Minor -shl 16) -bor $ARPAppVersion.Build },
                @{ Name = "VersionMajor";      Type = "DWord";         Value = $ARPAppVersion.Major },
                @{ Name = "VersionMinor";      Type = "DWord";         Value = $ARPAppVersion.Minor },
                @{ Name = "AdvertiseFlags";    Type = "DWord";         Value = 388 },
                @{ Name = "Assignment";        Type = "DWord";         Value = 1 },
                @{ Name = "AuthorizedLUAApp";  Type = "DWord";         Value = 0 },
                @{ Name = "Clients";           Type = "MultiString";   Value = @(":") },
                @{ Name = "DeploymentFlags";   Type = "DWord";         Value = 3 },
                @{ Name = "InstanceType";      Type = "DWord";         Value = 0 },
                @{ Name = "Language";          Type = "DWord";         Value = 1033 }
            )
            foreach ($Property in $AdditionalRegistryProperties) {
                if ($PSCmdlet.ShouldProcess("$ARPFuncProductsRegKey\$($Property.Name)", "Set Registry Value")) {
                    try {
                        New-ItemProperty -Path $ARPFuncProductsRegKey -Name $Property.Name -PropertyType $Property.Type -Value $Property.Value -Force | Out-Null
                        Write-Verbose "Success to create/update Registry value '$($Property.Name)' under $($ARPFuncProductsRegKey)."
                    } catch {Write-warning "Failed to create/update Registry value '$($Property.Name)' under $($ARPFuncProductsRegKey). Error: $_"}
                }
            }

            # HKCR Registry Installer\Products\...\Sourcelist Entries
            $SourceListPath = Join-Path -Path $ARPFuncProductsRegKey -ChildPath "Sourcelist"
            if (-not (Test-Path $SourceListPath)) {
                if ($PSCmdlet.ShouldProcess($SourceListPath, "Create Registry Key")) {
                    try {
                        New-Item -Path $SourceListPath -Force | Out-Null
                        Write-Verbose "Success to create Registry Path $SourceListPath."
                    } catch { Write-warning "Failed to create Registry Path $SourceListPath. Error: $_" }
                }
            } else {Write-Verbose "Registry Path already exists: $SourceListPath"}

            $SourcelistProperties = @(
                @{ Name = "LastUsedSource";    Type = "ExpandString";  Value = "n;1;$($ARPAppFolder)\" },
                @{ Name = "PackageName";       Type = "String";        Value = $DeployedWrapperName }
            )

            foreach ($Property in $SourcelistProperties) {
                if ($PSCmdlet.ShouldProcess("$SourceListPath\$($Property.Name)", "Set Registry Value")) {
                    try {
                        New-ItemProperty -Path $SourceListPath -Name $Property.Name -PropertyType $Property.Type -Value $Property.Value -Force | Out-Null
                        Write-Verbose "Success to create/update Registry value '$($Property.Name)' under $SourceListPath."
                    } catch {Write-warning "Failed to create/update Registry value '$($Property.Name)' under $SourceListPath. Error: $_"}
                }
            }
            
            # HKCR Registry Installer\Products\...\Sourcelist\Media Entries
            $MediaListPath = Join-Path -Path $SourceListPath -ChildPath "Media"
            if (-not (Test-Path $MediaListPath)) {
                if ($PSCmdlet.ShouldProcess($MediaListPath, "Create Registry Key")) {
                    try {
                        New-Item -Path $MediaListPath -Force | Out-Null
                        Write-Verbose "Success to create Registry Path $MediaListPath." 
                    } catch { Write-warning "Failed to create Registry Path $MediaListPath. Error: $_" }
                }
            } else {Write-Verbose "Registry Path already exists: $MediaListPath"}

            if ($PSCmdlet.ShouldProcess("$MediaListPath\1", "Set Registry Value")) {
                try {
                    New-ItemProperty -Path $MediaListPath -Name "1" -PropertyType "String" -Value ";" -Force | Out-Null
                    Write-Verbose "Success to create/update Registry value '1' under $MediaListPath."
                } catch {Write-warning "Failed to create/update Registry value '1' under $MediaListPath. Error: $_"}
            }

            # HKCR Registry Installer\Products\...\Sourcelist\Net Entries
            $NetListPath = Join-Path -Path $SourceListPath -ChildPath "Net"
            if (-not (Test-Path $NetListPath)) {
                if ($PSCmdlet.ShouldProcess($NetListPath, "Create Registry Key")) {
                    try {
                        New-Item -Path $NetListPath -Force | Out-Null
                        Write-Verbose "Success to create Registry Path $NetListPath." 
                    } catch { Write-warning "Failed to create Registry Path $NetListPath. Error: $_" }
                }
            } else {Write-Verbose "Registry Path already exists: $NetListPath"}

            if ($PSCmdlet.ShouldProcess("$NetListPath\1", "Set Registry Value")) {
                try {
                    New-ItemProperty -Path $NetListPath -Name "1" -PropertyType "ExpandString" -Value "$($ARPAppFolder)\" -Force | Out-Null
                    Write-Verbose "Success to create/update Registry value '1' under $NetListPath."
                } catch {Write-warning "Failed to create/update Registry value '1' under $NetListPath. Error: $_"}
            }

        } catch {Write-warning "An error occurred during registry operations section: $_"}
        # Signal caller to proceed with installer payload.
        $true
    }
    End {
        if ($private:HKCRDrive -and (Get-PSDrive HKCR -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)) {
            try {
                Remove-PSDrive -Name HKCR
                Write-Verbose "Successfully removed HKCR PSDrive."
            } catch {Write-warning "Failed to remove HKCR PSDrive. Error: $_"}
        }
        Write-Verbose "Finished function Add-AddRemovePrograms."
    }
}
Function Remove-AddRemovePrograms {
        <#
    .SYNOPSIS
        Removes an application entry from Add Remove Programs (ARP) in Windows, including registry entries and associated files.
    .DESCRIPTION
        This function deletes the registry entries and files that were created to make a script or application appear in the Add Remove Programs list in Windows Settings.
        It is designed to clean up all traces of the application from ARP, including uninstall and modify options, as well as the application icon.
    .NOTES
        Author:  @MrTbone_se (T-bone Granheden)
        Version: 1.1.0
        
        Version History:
        1.0 - Initial version
        1.0.1 - Changed parameter names end improved error handling
        1.1.0 - Major refactor for better maintainability, added verbose logging, and improved error handling with try/catch blocks.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [Parameter(Mandatory, HelpMessage = 'Name of the application/script being removed (used also to determine icon name)')]
        [string]$ARPAppName,

        [Parameter(Mandatory, HelpMessage = 'GUID of the application used during installation')]
        [ValidatePattern('^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$')]
        [string]$ARPAppGuid,

        [Parameter(Mandatory, HelpMessage = 'Application folder path where components were installed')]
        [string]$ARPAppFolder,

        [Parameter(Mandatory = $false, HelpMessage = 'Publisher name used to locate Start Menu shortcut folder')]
        [string]$ARPAppPublisher = ""
    )
    Begin {
        $ErrorActionPreference = 'Stop'
        Write-Verbose "Start Function Remove-AddRemovePrograms"
        $private:HKCRDrive = $false
    }
    Process {
        # Convert GUID to MSI Packed GUID (ProductID) - MSI reverses each segment: segments 1-3 are fully reversed, segments 4-5 are pair-swapped
        # Example: {FEEDBEEF-BEEF-4DAD-BEEF-B628CCCA16E0} -> FEEBDEEFFEEBDAD4EBFE6B82CCAC610E
        [string]$private:stripped = $ARPAppGuid -replace '[{}\-]', ''
        [string]$ARPFuncProductID = (
            ($stripped[7..0]   -join '') +  # Segment 1 (8 chars): reverse
            ($stripped[11..8]  -join '') +  # Segment 2 (4 chars): reverse
            ($stripped[15..12] -join '') +  # Segment 3 (4 chars): reverse
            (($stripped[16..31] | ForEach-Object -Begin { $private:pair = @() } -Process {
                $pair += $_
                if ($pair.Count -eq 2) { $pair[1]; $pair[0]; $pair = @() }
            }) -join '')
        )
        Write-Verbose "Derived MSI Packed GUID (ProductID) for removal: $ARPFuncProductID"

        # Standardized deployed paths (must match the one used in Add-AddRemovePrograms)
        $private:DeployedWrapperPath     = Join-Path -Path $ARPAppFolder -ChildPath 'App-Wrapper.ps1'
        $private:DeployedInstallerPath   = Join-Path -Path $ARPAppFolder -ChildPath "installer-$ARPAppGuid.ps1"
        $private:DeployedUninstallerPath = Join-Path -Path $ARPAppFolder -ChildPath "uninstaller-$ARPAppGuid.ps1"

        # Registry / icon / batch paths
        $ARPFuncIconPath        = Join-Path -Path $ARPAppFolder -ChildPath "$($ARPAppName -replace '\s', '').ico"
        $ARPFuncUninstallRegKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$ARPAppGuid"
        $ARPFuncProductsRegKey  = "HKCR:\Installer\Products\$ARPFuncProductID"
        $ARPFuncUninstallBAT    = Join-Path -Path $ARPAppFolder -ChildPath "uninstall-$ARPAppGuid.bat"
        $ARPFuncModifyBAT       = Join-Path -Path $ARPAppFolder -ChildPath "reinstall-$ARPAppGuid.bat"

        # Remove Registry Keys
        Write-Verbose "Starting registry key removal."
        try {
            if (-not (Get-PSDrive HKCR -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)) {
                New-PSDrive -PSProvider Registry -Name HKCR -Root HKEY_CLASSES_ROOT | Out-Null
                $private:HKCRDrive = $true
                Write-Verbose "Created HKCR PSDrive."
            }

            # Remove HKLM Uninstall Key
            if (Test-Path $ARPFuncUninstallRegKey) {
                if ($PSCmdlet.ShouldProcess($ARPFuncUninstallRegKey, "Remove Registry Key")) {
                    try {
                        Remove-Item -Path $ARPFuncUninstallRegKey -Recurse -Force
                        Write-Verbose "Success to remove registry key: $ARPFuncUninstallRegKey"
                    } catch {Write-Warning "Failed to remove registry key $ARPFuncUninstallRegKey. Error: $_"}
                }
            } else {Write-Verbose "Registry key not found: $ARPFuncUninstallRegKey"}

            # Remove HKCR Installer Products Key
            if (Test-Path $ARPFuncProductsRegKey) {
                if ($PSCmdlet.ShouldProcess($ARPFuncProductsRegKey, "Remove Registry Key")) {
                    try {
                        Remove-Item -Path $ARPFuncProductsRegKey -Recurse -Force
                        Write-Verbose "Success to remove registry key: $ARPFuncProductsRegKey"
                    } catch {Write-Warning "Failed to remove registry key $ARPFuncProductsRegKey. Error: $_"}
                }
            } else {Write-Verbose "Registry key not found: $ARPFuncProductsRegKey"}
        } catch {Write-Warning "An error occurred during registry key removal section: $_"}

        # Remove Files (script, icon, uninstall/reinstall batches, and any companion files staged into $ARPAppFolder)
        Write-Verbose "Starting file removal in $ARPAppFolder."
        $FilesToDelete = [System.Collections.Generic.List[string]]::new()
        $FilesToDelete.Add($ARPFuncIconPath)
        $FilesToDelete.Add($ARPFuncUninstallBAT)
        $FilesToDelete.Add($ARPFuncModifyBAT)
        $FilesToDelete.Add($DeployedWrapperPath)
        $FilesToDelete.Add($DeployedInstallerPath)
        $FilesToDelete.Add($DeployedUninstallerPath)
        # All-Users shortcuts (created in Add-AddRemovePrograms when ARPAppUserStartFile was configured). Always attempt deletion
        $FilesToDelete.Add((Join-Path -Path "$Env:Public\Desktop" -ChildPath "$ARPAppName.lnk"))
        if (-not [string]::IsNullOrWhiteSpace($ARPAppPublisher)) {
            $FilesToDelete.Add((Join-Path -Path "$Env:ProgramData\Microsoft\Windows\Start Menu\Programs\$ARPAppPublisher" -ChildPath "$ARPAppName.lnk"))
        }
        # Any remaining files staged into $ARPAppFolder
        if (Test-Path -LiteralPath $ARPAppFolder -PathType Container) {
            foreach ($private:extraFile in (Get-ChildItem -LiteralPath $ARPAppFolder -File -Force -ErrorAction SilentlyContinue)) {
                $FilesToDelete.Add($extraFile.FullName)
            }
        }

        foreach ($FileItem in $FilesToDelete) {
            if (Test-Path $FileItem) {
                if ($PSCmdlet.ShouldProcess($FileItem, "Remove File")) {
                    try {
                        Remove-Item -Path $FileItem -Force
                        Write-Verbose "Success to remove file: $FileItem"
                    } catch {Write-Warning "Failed to remove file $FileItem. Error: $_"}
                }
            } else {Write-Verbose "File not found: $FileItem"}
        }

        # Remove the publisher Start Menu folder (if empty)
        if (-not [string]::IsNullOrWhiteSpace($ARPAppPublisher)) {
            [string]$private:StartMenuPubDir = Join-Path -Path "$Env:ProgramData\Microsoft\Windows\Start Menu\Programs" -ChildPath $ARPAppPublisher
            if (Test-Path -LiteralPath $StartMenuPubDir) {
                if (@(Get-ChildItem -LiteralPath $StartMenuPubDir -Force -ErrorAction SilentlyContinue).Count -eq 0) {
                    try {
                        [System.IO.Directory]::Delete($StartMenuPubDir, $false)
                        Write-Verbose "Success to remove empty Start Menu publisher folder: $StartMenuPubDir"
                    } catch { Write-Warning "Failed to remove Start Menu publisher folder $StartMenuPubDir. Error: $_" }
                } else { Write-Verbose "Start Menu publisher folder not empty, skipping: $StartMenuPubDir" }
            }
        }

        # Remove Application Folder (if empty), then Publisher Folder (if empty) and so on until a non empty foler is reached, or a protected root
        [string[]]$private:ProtectedRoots = @(
            $Env:ProgramFiles,
            ${Env:ProgramFiles(x86)},
            $Env:ProgramData,
            $Env:SystemDrive,
            $Env:SystemRoot,
            $Env:windir
        ) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') }

        [string]$private:FolderToCheck = $ARPAppFolder
        try { Set-Location -LiteralPath $Env:SystemRoot -ErrorAction Stop } catch { Write-Verbose "Could not Set-Location to $Env:SystemRoot: $_" }
        for ($private:depth = 0; $depth -lt 2 -and $FolderToCheck; $depth++) {
            if (-not (Test-Path $FolderToCheck)) {
                Write-Verbose "Folder not found: $FolderToCheck"
                break
            }
            [string]$private:Trimmed = $FolderToCheck.TrimEnd('\')
            if ($ProtectedRoots -contains $Trimmed) {
                Write-Verbose "Reached protected root, stopping cleanup: $FolderToCheck"
                break
            }
            if (@(Get-ChildItem -Path $FolderToCheck -Force -ErrorAction SilentlyContinue).Count -ne 0) {
                Write-Verbose "Folder not empty, skipping removal: $FolderToCheck"
                break
            }
            if ($PSCmdlet.ShouldProcess($FolderToCheck, "Remove empty directory")) {
                try {
                    [System.IO.Directory]::Delete($FolderToCheck, $false)
                    Write-Verbose "Success to remove empty folder: $FolderToCheck"
                } catch {
                    Write-Warning "Failed to remove folder $FolderToCheck. Error: $_"
                    break
                }
            }
            $FolderToCheck = Split-Path -Path $FolderToCheck -Parent
        }
    }
    End {
        if ($private:HKCRDrive -and (Get-PSDrive HKCR -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)) {
            try {
                Remove-PSDrive -Name HKCR
                Write-Verbose "Successfully removed HKCR PSDrive."
            } catch {Write-Warning "Failed to remove HKCR PSDrive. Error: $_"}
        }
        Write-Verbose "Finished function Remove-AddRemovePrograms."
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
    $NameRegex   = '[<>:"/\\|?*]'
    $PathRegex   = '^\\\\[\w.\-]+\\[\w.\-$]+(?:\\[\w.\-$ ]+)*$'
    $LetterRegex = '^[A-Za-z]$'

    $i = 0
    foreach ($o in $MapObjects) {
        $i++; $e = @()

        if ($o.ContainsKey('Letter')) {
            $letter = $o['Letter']
            if ($letter -is [string]) { $letter = $letter.TrimEnd(':') }
            if ($letter -notmatch $LetterRegex)                                          { $e += "Invalid Letter '$($o['Letter'])'" }
            if (-not $o.ContainsKey('Persistent') -or $o['Persistent'] -isnot [bool])    { $e += "Persistent must be `$true or `$false" }
            $p = $o['Path']
            if (-not ($p -and $p -match $PathRegex))                                     { $e += "Invalid/Missing Path '$p'" }
            if ($o['Label'] -and $o['Label'] -match $NameRegex)                          { $e += "Label contains illegal characters" }
        }
        elseif ($o.ContainsKey('PrinterName')) {
            if ([string]::IsNullOrWhiteSpace($o['PrinterName']))                         { $e += "Missing/Empty PrinterName" }
            elseif ($o['PrinterName'] -match $NameRegex)                                 { $e += "PrinterName contains illegal characters" }
            if (-not $o.ContainsKey('Default') -or $o['Default'] -isnot [bool])          { $e += "Default must be `$true or `$false" }
            $p = $o['Path']
            if (-not ($p -and $p -match $PathRegex))                                     { $e += "Invalid/Missing Path '$p'" }
        }
        else { $e += "Unknown Type: Must have 'Letter' or 'PrinterName'" }

        if ($o['ADGroups']) {
            foreach ($g in @($o['ADGroups'])) {
                if ($g -match $NameRegex) { $e += "ADGroups contains illegal characters: '$g'"; break }
            }
        }

        if ($e.Count -gt 0) { throw "MapObject[$i] validation failed: $($e -join ', ')" }
    }
    return $MapObjects
}
function Get-ADGroupMemberships {
<#
.SYNOPSIS
    Resolves which of the configured AD groups the current user belongs to.
.DESCRIPTION
    Determines which configured AD groups the current user belongs to.
    Prefers the local Kerberos token to minimize DC load and avoid unnecessary LDAP queries.
    Falls back to a single scoped LDAP query only when on-prem group SIDs are not available.
    Returns the matched required group names, resolving the primary group only when needed.
.NOTES
    Author:  @MrTbone_se (T-bone Granheden)
    Version: 3.0

    Version History:
    1.0 - Initial version
    2.0 - Modified connectivity test, added primary group and improved error handling
    3.0 - Added required-group scoping; Kerberos PAC/token path with scoped LDAP fallback to minimize DC load
#>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[String]])]
    param(
        [Parameter(Mandatory = $false,          HelpMessage = 'Domain to search for group memberships')]
        [string]$Domain = $env:USERDNSDOMAIN,

        [Parameter(Mandatory = $false,          HelpMessage = 'Optional ref that returns if a DC is available')]
        [ref]$DCAvailable = $null,

        [Parameter(Mandatory = $false,          HelpMessage = 'Optional group names to limit the membership lookup')]
        [string[]]$RequiredGroups = @()
    )
    
    begin {
        $ADsearcher          = $null
        $UserResult          = $null
        $GroupsResults       = $null
        $PrimaryGroupResult  = $null
        $GroupMembershipList = [System.Collections.Generic.List[String]]::new()

        if (-not ('Native.Netapi' -as [type])) {
            $NetapiDefinition = @(
                '[System.Runtime.InteropServices.DllImport("Netapi32.dll", CharSet=System.Runtime.InteropServices.CharSet.Unicode)]'
                'public static extern int DsGetDcName(string ComputerName, string DomainName, System.IntPtr DomainGuid,'
                'string SiteName, uint Flags, out System.IntPtr DomainControllerInfo);'
                '[System.Runtime.InteropServices.DllImport("Netapi32.dll")]'
                'public static extern int NetApiBufferFree(System.IntPtr Buffer);'
            ) -join [Environment]::NewLine
            Add-Type -Namespace Native -Name Netapi -MemberDefinition $NetapiDefinition
        }
    }
    
    process {
        if ($DCAvailable) { $DCAvailable.Value = $true }  # assume reachable; DC Locator will correct this if needed
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
            
            # Use DC Locator before LDAP queries so that DirectorySearcher only runs when a domain controller is reachable.
            $ptr = [IntPtr]::Zero
            $rc = [Native.Netapi]::DsGetDcName($null, $Domain, [IntPtr]::Zero, $null, 0x40000010, [ref]$ptr)
            try {
                if ($rc -ne 0) {
                    Write-Verbose "DsGetDcName=$rc - no DC for $Domain"
                    if ($DCAvailable) { $DCAvailable.Value = $false }
                    return $GroupMembershipList
                }
            }
            finally {if ($ptr -ne [IntPtr]::Zero) { [Native.Netapi]::NetApiBufferFree($ptr) | Out-Null }}

            # Short-circuit: no group-scoped mappings configured, so no LDAP search is required.
            if (-not $RequiredGroups -or $RequiredGroups.Count -eq 0) {
                Write-Verbose "No RequiredGroups supplied - skipping LDAP group enumeration to spare DC load"
                return $GroupMembershipList
            }
            # Kerberos token path (preferred): zero LDAP queries. The TGT issued by the DC carries every group SID for the user.
            $useFallback = $false
            try {
                # Trigger TGT refresh via a single SMB auth call to the DC
                try { $null = Test-Path -LiteralPath "\\$Domain\SYSVOL" -ErrorAction SilentlyContinue } catch {}
                # Translate ONLY the configured group names to SIDs
                $netBiosDomain = $env:USERDOMAIN
                $translated = @{}
                # Step 1: LSA (skipped silently when authority cannot be resolved)
                foreach ($groupName in $RequiredGroups) {
                    $authoritiesToTry = @()
                    if ($netBiosDomain)              { $authoritiesToTry += $netBiosDomain }    # 1: NetBIOS domain (most reliable)
                    $authoritiesToTry += $null                                                  # 2: bare name (LSA uses default domain)
                    if ($Domain -and $Domain -ne $netBiosDomain) { $authoritiesToTry += $Domain }  # 3: DNS domain (last resort)
                    foreach ($authority in $authoritiesToTry) {
                        try {
                            $nt  = if ($authority) { [System.Security.Principal.NTAccount]::new($authority, $groupName) }
                                   else            { [System.Security.Principal.NTAccount]::new($groupName) }
                            $sid = $nt.Translate([System.Security.Principal.SecurityIdentifier])
                            $translated[$groupName] = $sid.Value
                            break
                        }
                        catch { } # Try next authority; failures are expected on Entra-joined CKT devices
                    }
                }

                # Step 2: If LSA could not resolve like Cloud Native with Kerberos Cloud Trust, do ONE flat indexed LDAP query
                $unresolvedNames = @($RequiredGroups | Where-Object { -not $translated.ContainsKey($_) })
                if ($unresolvedNames.Count -gt 0) {
                    $sidLookupSearcher = $null
                    $sidLookupResults  = $null
                    try {
                        $sidLookupSearcher = [System.DirectoryServices.DirectorySearcher]::new()
                        $sidLookupSearcher.SearchRoot     = [ADSI]"LDAP://$Domain"
                        $sidLookupSearcher.SearchScope    = [System.DirectoryServices.SearchScope]::Subtree
                        $sidLookupSearcher.ServerTimeLimit = [TimeSpan]::FromSeconds(15)
                        $nameClauses = ($unresolvedNames | ForEach-Object {
                            '(name=' + ($_ -replace '([\\*\(\)\x00/])','\\$1') + ')'
                        }) -join ''
                        if ($unresolvedNames.Count -gt 1) { $nameClauses = "(|$nameClauses)" }
                        $sidLookupSearcher.Filter = "(&(objectCategory=group)$nameClauses)"
                        $null = $sidLookupSearcher.PropertiesToLoad.Add("name")
                        $null = $sidLookupSearcher.PropertiesToLoad.Add("objectSid")
                        Write-Verbose "Token path: resolving $($unresolvedNames.Count) group name(s) to SIDs via single flat LDAP query"
                        $sidLookupResults = $sidLookupSearcher.FindAll()
                        foreach ($r in $sidLookupResults) {
                            if ($r.Properties["name"].Count -gt 0 -and $r.Properties["objectSid"].Count -gt 0) {
                                $resName = $r.Properties["name"][0]
                                $sidBytes = $r.Properties["objectSid"][0]
                                try {
                                    $sidObj = [System.Security.Principal.SecurityIdentifier]::new($sidBytes, 0)
                                    if ($RequiredGroups -contains $resName) { $translated[$resName] = $sidObj.Value }
                                } catch { Write-Verbose "Token path: failed to construct SID for '$resName': $($_.Exception.Message)" }
                            }
                        }
                    }
                    catch {
                        Write-Verbose "Token path: flat LDAP SID lookup failed: $($_.Exception.Message)"
                    }
                    finally {
                        if ($sidLookupResults)  { $sidLookupResults.Dispose() }
                        if ($sidLookupSearcher) { $sidLookupSearcher.Dispose() }
                    }
                }

                $stillUnresolved = @($RequiredGroups | Where-Object { -not $translated.ContainsKey($_) })
                if ($stillUnresolved.Count -gt 0) {
                    Write-Verbose "Token path: unable to resolve SIDs for: $($stillUnresolved -join ', ')"
                }

                if ($translated.Count -eq 0) {
                    Write-Verbose "Token path: no configured groups could be resolved to SIDs - falling back to scoped LDAP"
                    $useFallback = $true
                }
                else {
                    # Read the user's transitive group SIDs straight from the local Windows token. No DC traffic.
                    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                    $tokenSidSet     = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                    if ($currentIdentity.Groups) {
                        foreach ($grp in $currentIdentity.Groups) {
                            try { [void]$tokenSidSet.Add($grp.Value) } catch {}
                        }
                    }

                    # Sanity check: the token must contain at least one SID
                    $sampleSid       = ($translated.Values | Select-Object -First 1)
                    $domainSidPrefix = $null
                    if ($sampleSid) {
                        $sidParts = $sampleSid -split '-'
                        # AD domain group SID layout: S-1-5-21-<a>-<b>-<c>-<RID> -> 8 segments, prefix = first 7
                        if ($sidParts.Count -ge 8 -and $sidParts[0] -eq 'S' -and $sidParts[2] -eq '5' -and $sidParts[3] -eq '21') {
                            $domainSidPrefix = ($sidParts[0..6]) -join '-'
                        }
                    }
                    $tokenHasOnpremGroups = $false
                    if ($domainSidPrefix) {
                        foreach ($s in $tokenSidSet) {
                            if ($s.StartsWith("$domainSidPrefix-", [System.StringComparison]::OrdinalIgnoreCase)) {
                                $tokenHasOnpremGroups = $true
                                break
                            }
                        }
                    }

                    if (-not $tokenHasOnpremGroups) {
                        Write-Verbose "Token path: user token has no SIDs from the on-prem domain - falling back to scoped LDAP"
                        $useFallback = $true
                    }
                    else {
                        # Intersect translated required-group SIDs with the token.
                        foreach ($groupName in $RequiredGroups) {
                            if ($translated.ContainsKey($groupName) -and $tokenSidSet.Contains($translated[$groupName])) {
                                $GroupMembershipList.Add($groupName)
                            }
                        }
                        Write-Verbose "Token path: matched $($GroupMembershipList.Count) of $($RequiredGroups.Count) configured group(s) via Kerberos token (no LDAP issued)"
                        return $GroupMembershipList
                    }
                }
            }
            catch {
                Write-Verbose "Token path failed unexpectedly, falling back to scoped LDAP: $($_.Exception.Message)"
                $useFallback = $true
            }

            # If we reach this point the token path was not conclusive and we fall through to the scoped LDAP
            if (-not $useFallback) { return $GroupMembershipList }
            Write-Verbose "Falling back to scoped LDAP query for $($RequiredGroups.Count) configured group(s)"

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

            # Build a single LDAP filter that asks the DC ONLY about the configured groups
            $distinguishedName = $UserResult.Properties["distinguishedname"][0]
            $escapedDN = $distinguishedName -replace '([\\*\(\)\x00/])','\\$1' # Escape LDAP special characters
            $nameClauses = ($RequiredGroups | ForEach-Object {
                '(name=' + ($_ -replace '([\\*\(\)\x00/])','\\$1') + ')'
            }) -join ''
            if ($RequiredGroups.Count -gt 1) { $nameClauses = "(|$nameClauses)" }
            $ADsearcher.Filter = "(&(objectCategory=group)$nameClauses(member:1.2.840.113556.1.4.1941:=$escapedDN))"
            $ADsearcher.PropertiesToLoad.Clear()
            $null = $ADsearcher.PropertiesToLoad.Add("name")
            Write-Verbose "Querying $($RequiredGroups.Count) configured group(s) with scoped chain filter"
            $GroupsResults = $ADsearcher.FindAll()
            if ($GroupsResults.Count -gt 0) {
                foreach ($result in $GroupsResults) {
                    $groupName = $result.Properties["name"]
                    if ($groupName.Count -gt 0) { $GroupMembershipList.Add($groupName[0]) }
                }
            }

            # Primary group (e.g. "Domain Users") is NOT returned by LDAP_MATCHING_RULE_IN_CHAIN.
            $unresolved = @($RequiredGroups | Where-Object { $_ -notin $GroupMembershipList })
            if ($unresolved.Count -gt 0) {
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
                        $primaryName = $PrimaryGroupResult.Properties["name"][0]
                        # Only add if it satisfies an outstanding required group, to keep the result
                        # list aligned with the caller's intent.
                        if ($primaryName -in $unresolved) { $GroupMembershipList.Add($primaryName) }
                    }
                }
            }
            
            if ($GroupMembershipList.Count -gt 0) {
                Write-Verbose "Success to collect user group memberships, found $($GroupMembershipList.Count) groups"
            }
            else {Write-Verbose "No group memberships found for user $UserPrincipalName"}
            return $GroupMembershipList
        }
        catch {
            Write-Error "Failed to collect user group memberships with error: $_"
            return $GroupMembershipList
        }
    }
    
    end {
        # Dispose unmanaged resources to prevent memory leaks.
        if ($GroupsResults) { $GroupsResults.Dispose() }
        if ($ADsearcher)    { $ADsearcher.Dispose() }
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
        
        [Parameter(Mandatory = $true, HelpMessage = "UNC path to the network printer, for example \\printserver\printername")]
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
            catch {Write-Warning "Failed to query existing printer state: $_"}
            finally {if ($PrinterCim) {Remove-Variable -Name PrinterCim -ErrorAction SilentlyContinue}}
            
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
        [Parameter(Mandatory = $true, HelpMessage = "Drive letter to map, for example S")]
        [ValidatePattern('^[A-Z]$')]
        [string]$DriveLetter,
        
        [Parameter(Mandatory = $true, HelpMessage = "UNC path to the network share, for example \\fileserver\share")]
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
                Write-Warning "Failed to add drive '$DriveLetter`:' ($DrivePath) with error: $ErrorVar"
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
                    } else {Write-Warning "Failed to get namespace for drive '$DriveLetter`:' to set label"}
                }
                catch {Write-Warning "Failed to set drive '$DriveLetter`:' label to '$DriveLabel' with error: $_"}
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
            Write-Warning "Failed to remove existing drive '$DriveLetter`:' (exit code: $LASTEXITCODE)"
            return
        }
        Write-Verbose "Success to remove existing drive '$DriveLetter`:'"
        
        # Create the new drive
        $null = & $CreateDriveAndSetLabel
    }
    end {}
}

function Register-IntuneTask {
<#
.SYNOPSIS
    Creates (or replaces) a Windows scheduled task in a universal, reusable way.
.DESCRIPTION
    Wraps Register-ScheduledTask with a simple parameter set covering the most
    common triggers (AtLogon, AtStartup, OnEvent), action (executable + arguments),
    principal (user SID, group SID or built-in account) and common settings.
    Designed to be dropped into any script - all parameters are suffixed with TASK
    to avoid collisions with surrounding script variables.
    Renamed from New-ScheduledTask to avoid collision with the built-in cmdlet of
    the same name in the ScheduledTasks module (which has no -TaskName parameter).
.NOTES
    Author:  @MrTbone_se (T-bone Granheden)
    Version: 1.2
    Version History:
    1.0 - Initial stub
    1.1 - Universal implementation
    1.2 - Renamed from New-ScheduledTask to Register-IntuneTask to avoid collision
          with the built-in ScheduledTasks\New-ScheduledTask cmdlet.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Name of the scheduled task to create or update")]
        [string]$TaskName,

        [Parameter(Mandatory = $false, HelpMessage = "Description shown for the task in Task Scheduler")]
        [string]$TaskDescription,

        [Parameter(Mandatory = $true, HelpMessage = "Full path to the executable that the task should run")]
        [string]$TaskExecute,

        [Parameter(Mandatory = $false, HelpMessage = "Arguments passed to the task executable")]
        [string]$TaskArgument,

        [Parameter(Mandatory = $false, HelpMessage = "Optional working directory for the task action")]
        [string]$TaskWorkingDirectory,

        [Parameter(Mandatory = $false, HelpMessage = "Group SID the task should run as, for example BUILTIN\Users")]
        [string]$TaskPrincipalGroupSid,

        [Parameter(Mandatory = $false, HelpMessage = "User account or SID the task should run as when no group SID is used")]
        [string]$TaskPrincipalUserId,

        [Parameter(Mandatory = $false, HelpMessage = "Run level for the task principal. Default is Limited")]
        [ValidateSet('Limited', 'Highest')]
        [string]$TaskRunLevel = 'Limited',

        [Parameter(Mandatory = $false, HelpMessage = "Logon type used when TaskPrincipalUserId is specified. Default is Interactive")]
        [ValidateSet('Interactive', 'Group', 'ServiceAccount', 'S4U', 'Password')]
        [string]$TaskLogonType = 'Interactive',

        [Parameter(Mandatory = $false, HelpMessage = "Add an AtLogon trigger to the scheduled task")]
        [switch]$TaskTriggerAtLogon,

        [Parameter(Mandatory = $false, HelpMessage = "Add an AtStartup trigger to the scheduled task")]
        [switch]$TaskTriggerAtStartup,

        [Parameter(Mandatory = $false, HelpMessage = "Add an event trigger that fires when a network profile becomes connected (NetworkProfile/Operational EventID 10000)")]
        [switch]$TaskTriggerAtNetConnect,

        [Parameter(Mandatory = $false, HelpMessage = "One or more XML event subscriptions used to create event triggers")]
        [string[]]$TaskTriggerEventSubscription,

        [Parameter(Mandatory = $false, HelpMessage = "Optional pre-built scheduled task settings object")]
        [Microsoft.Management.Infrastructure.CimInstance]$TaskSettings,

        [Parameter(Mandatory = $false, HelpMessage = "Create the task as hidden in Task Scheduler")]
        [switch]$TaskHidden,

        [Parameter(Mandatory = $false, HelpMessage = "Start the task immediately after registration")]
        [switch]$TaskStartImmediately,

        [Parameter(Mandatory = $false, HelpMessage = "Overwrite an existing task registration with the same name")]
        [switch]$TaskForce
    )

    try {
        # Build triggers
        $TaskTriggers = @()
        if ($TaskTriggerAtLogon)   { $TaskTriggers += New-ScheduledTaskTrigger -AtLogOn }
        if ($TaskTriggerAtStartup) { $TaskTriggers += New-ScheduledTaskTrigger -AtStartup }
        $TaskEventSubscriptions = @()
        if ($TaskTriggerEventSubscription) { $TaskEventSubscriptions += $TaskTriggerEventSubscription }
        if ($TaskTriggerAtNetConnect) {
            $TaskEventSubscriptions += "<QueryList><Query Id='0' Path='Microsoft-Windows-NetworkProfile/Operational'><Select Path='Microsoft-Windows-NetworkProfile/Operational'>*[System[Provider[@Name='Microsoft-Windows-NetworkProfile'] and EventID=10000]]</Select></Query></QueryList>"
        }
        if ($TaskEventSubscriptions.Count -gt 0) {
            $TaskEventClass = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace root/Microsoft/Windows/TaskScheduler
            foreach ($TaskSub in $TaskEventSubscriptions) {
                $TaskEventTrigger = $TaskEventClass | New-CimInstance -ClientOnly
                $TaskEventTrigger.Enabled = $true
                $TaskEventTrigger.Subscription = $TaskSub
                $TaskTriggers += $TaskEventTrigger
            }
        }
        if (-not $TaskTriggers -or $TaskTriggers.Count -eq 0) {
            throw "At least one trigger must be specified (TaskTriggerAtLogon, TaskTriggerAtStartup, TaskTriggerAtNetConnect or TaskTriggerEventSubscription)."
        }

        # Build principal
        if ($TaskPrincipalGroupSid)     {$TaskPrincipal = New-ScheduledTaskPrincipal -GroupId $TaskPrincipalGroupSid -Id 'Author'}
        elseif ($TaskPrincipalUserId)   {$TaskPrincipal = New-ScheduledTaskPrincipal -UserId $TaskPrincipalUserId -LogonType $TaskLogonType -RunLevel $TaskRunLevel}
        else                            {$TaskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest}

        # Build action
        $TaskActionParams = @{ Execute = $TaskExecute }
        if ($TaskArgument)         { $TaskActionParams.Argument        = $TaskArgument }
        if ($TaskWorkingDirectory) { $TaskActionParams.WorkingDirectory = $TaskWorkingDirectory }
        $TaskAction = New-ScheduledTaskAction @TaskActionParams

        # Build settings (default if not supplied)
        if (-not $TaskSettings) {
            $TaskSettingsParams = @{
                AllowStartIfOnBatteries = $true
                DontStopIfGoingOnBatteries = $true
            }
            if ($TaskHidden) { $TaskSettingsParams.Hidden = $true }
            $TaskSettings = New-ScheduledTaskSettingsSet @TaskSettingsParams
        }
        elseif ($TaskHidden) {$TaskSettings.Hidden = $true}

        # Register the scheduled task
        $TaskRegisterParams = @{
            TaskName    = $TaskName
            Trigger     = $TaskTriggers
            Action      = $TaskAction
            Principal   = $TaskPrincipal
            Settings    = $TaskSettings
            ErrorAction = 'Stop'
        }
        if ($TaskDescription) { $TaskRegisterParams.Description = $TaskDescription }
        if ($TaskForce)       { $TaskRegisterParams.Force       = $true }
        $null = Register-ScheduledTask @TaskRegisterParams
        Write-Verbose "Scheduled task '$TaskName' registered"

        # When task runs as BUILTIN\Users, grant Users read+execute so non-admins can trigger the task on demand
        if ($TaskPrincipalGroupSid -eq 'S-1-5-32-545') {
            try {
                $TaskService    = New-Object -ComObject 'Schedule.Service'
                $TaskService.Connect()
                $RegisteredTask = $TaskService.GetFolder('\').GetTask($TaskName)
                $TaskDaclSddl   = $RegisteredTask.GetSecurityDescriptor(4)
                if ($TaskDaclSddl -notmatch '\(A;;FRFX;;;BU\)') {
                    $UpdatedTaskDaclSddl = if ($TaskDaclSddl -match '\(A;;FR;;;BU\)') {
                        $TaskDaclSddl -replace '\(A;;FR;;;BU\)', '(A;;FRFX;;;BU)'
                    }
                    elseif ($TaskDaclSddl -like 'D:*') {
                        $TaskSaclIndex = $TaskDaclSddl.IndexOf('S:')
                        if ($TaskSaclIndex -ge 0) { $TaskDaclSddl.Insert($TaskSaclIndex, '(A;;FRFX;;;BU)') }
                        else                      { $TaskDaclSddl + '(A;;FRFX;;;BU)' }
                    }
                    else { 'D:(A;;FRFX;;;BU)' }
                    $RegisteredTask.SetSecurityDescriptor($UpdatedTaskDaclSddl, 0)
                    Write-Verbose "Granted BUILTIN\Users read/execute access to scheduled task '$TaskName'"
                }
            }
            catch { Write-Warning "Failed to grant BUILTIN\Users run access to scheduled task '$TaskName'. Error: $_" }
        }

        # Start the task immediately if requested
        if ($TaskStartImmediately) {
            Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
            Write-Verbose "Scheduled task '$TaskName' started"
        }
        return $true
    }
    catch {
        Write-Error "Failed to create scheduled task '$TaskName': $_"
        return $false
    }
}

function Remove-LegacyV1V2Artifacts {
<#
.SYNOPSIS
    Removes legacy mapping deployment artifacts (V1/V2) for the same object type as the current deployment.
.DESCRIPTION
    Enumerates all legacy Mr T-bone mapping scripts by checking for wscript(.exe)+.vbs mapping tasks
    Removes only files, tasks and app registration for object type matches the current deployment
.NOTES
    Author:  @MrTbone_se (T-bone Granheden)
    Version: 1.1

    Version History:
    1.0 - Initial version
    1.1 - Tighter wscript boundary, stricter CorpData fallback, single-shot regex match,
          pre-compiled patterns, gated logs-folder tracking, pre-computed sort key
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Object type the current deployment manages ('Drive' or 'Printer'); only legacies of this type are removed")]
        [ValidateSet('Drive', 'Printer')]
        [string]$ObjectType
    )
    begin {
        # Markers used to confirm that a discovered .ps1 belongs to one of our legacy mapping scripts.
        $LegacyContentMarker  = 'IntuneDriveMapping|IntunePrinterMapping|MapDrivesCloudNative|MapPrintersCloudNative|Map-DrivesCloudNative|Map-PrintersCloudNative|CorpDataPath'
        # Markers used to classify a confirmed legacy .ps1 as Drive vs Printer (mapping-table signature first, then function calls).
        $DriveTableMarker     = '@\{\s*Letter\b'
        $PrinterTableMarker   = '@\{\s*PrinterName\b'
        $DriveCallMarker      = 'New-PSDrive\b|New-DriveMapping\b|New-SmbMapping\b'
        $PrinterCallMarker    = 'Add-Printer\b|New-PrinterMapping\b'
        # Pattern used to extract hardcoded MSI/Win32 ARP GUIDs from confirmed legacy .ps1 content.
        $LegacyGuidPattern    = '\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}'
        # Filename heuristic for the CorpData\scripts fallback when a sibling .ps1 is missing.
        $LegacyNameHeuristic  = 'Map.*Drive|Map.*Printer|Mapping'
        # Pre-compiled regex patterns for first .vbs token extraction from task arguments.
        $VbsQuotedPattern     = [regex]::new('"([^"]+\.vbs)"',                 [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        $VbsUnquotedPattern   = [regex]::new('(?:^|\s)([^\s"]+\.vbs)(?:\s|$)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        # State counters and case-insensitive sets accumulated during removal.
        $RemovedTasks   = 0
        $RemovedFiles   = 0
        $RemovedArp     = 0
        $LegacyFolders  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $LegacyArpGuids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    }
    process {
        # =================== PHASE 1: ENUMERATE ===================
        # Build a list of legacy candidates (one per scheduled task whose action is wscript+vbs).
        $LegacyCandidates = [System.Collections.Generic.List[object]]::new()

        $LegacyTasks = @()
        try {
            $LegacyTasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
                $hit = $false
                foreach ($action in $_.Actions) {
                    # Skip non-Exec actions (COM handler, email, message box) - they have no Execute/Arguments and would throw under StrictMode.
                    if ($action.CimClass.CimClassName -ne 'MSFT_TaskExecAction') { continue }
                    if (($action.Execute -match '(?:^|\\)wscript(?:\.exe)?$') -and ($action.Arguments -match '\.vbs(?:"|\s|$)')) {
                        $hit = $true; break
                    }
                }
                $hit
            })
        }
        catch { Write-Warning "Failed to enumerate scheduled tasks during legacy cleanup. Error: $_" }

        foreach ($legacyTask in $LegacyTasks) {
            # Pull the first quoted .vbs path from the task arguments, or fall back to an unquoted token.
            # Restrict to MSFT_TaskExecAction so StrictMode doesn't trip on actions without an Arguments property.
            $taskArguments = ($legacyTask.Actions | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskExecAction' } | ForEach-Object { [string]$_.Arguments }) -join ' '
            $legacyVbsPath = $null
            $vbsMatch = $VbsQuotedPattern.Match($taskArguments)
            if ($vbsMatch.Success) { $legacyVbsPath = $vbsMatch.Groups[1].Value }
            else {
                $vbsMatch = $VbsUnquotedPattern.Match($taskArguments)
                if ($vbsMatch.Success) { $legacyVbsPath = $vbsMatch.Groups[1].Value }
            }
            if ([string]::IsNullOrWhiteSpace($legacyVbsPath)) { continue }

            $legacyVbsDir  = Split-Path -Path $legacyVbsPath -Parent
            $legacyVbsBase = [System.IO.Path]::GetFileNameWithoutExtension($legacyVbsPath)
            if ([string]::IsNullOrWhiteSpace($legacyVbsDir) -or [string]::IsNullOrWhiteSpace($legacyVbsBase)) { continue }

            # Derive matching .ps1 from the same folder. Prefer same basename, fall back to any *Mapping.ps1 sibling.
            $legacyPs1Path = Join-Path -Path $legacyVbsDir -ChildPath "$legacyVbsBase.ps1"
            if (-not (Test-Path -LiteralPath $legacyPs1Path -PathType Leaf)) {
                $alternatePs1 = @(Get-ChildItem -LiteralPath $legacyVbsDir -Filter '*Mapping.ps1' -File -Force -ErrorAction SilentlyContinue)
                if ($alternatePs1.Count -gt 0) { $legacyPs1Path = $alternatePs1[0].FullName }
            }

            # Confirm via known markers and capture content for type classification and GUID extraction.
            $legacyConfirmed  = $false
            $legacyPs1Content = $null
            if (Test-Path -LiteralPath $legacyPs1Path -PathType Leaf) {
                try {
                    $legacyPs1Content = Get-Content -LiteralPath $legacyPs1Path -Raw -ErrorAction Stop
                    if ($legacyPs1Content -match $LegacyContentMarker) { $legacyConfirmed = $true }
                }
                catch { Write-Warning "Failed to read '$legacyPs1Path' for legacy verification. Error: $_" }
            }
            elseif (($legacyVbsDir -match '\\CorpData\\scripts\\?$') -and ($legacyVbsBase -match $LegacyNameHeuristic)) {
                $legacyConfirmed = $true
            }
            if (-not $legacyConfirmed) {
                Write-Verbose "Skipping task '$($legacyTask.TaskName)' - .vbs found but does not match a legacy mapping signature"
                continue
            }

            # Classify object type: task name -> .ps1 filename -> .vbs filename -> .ps1 content (mapping table, then function calls).
            $legacyType  = $null
            $taskNameTxt = [string]$legacyTask.TaskName
            $ps1NameTxt  = if ($legacyPs1Path) { [System.IO.Path]::GetFileNameWithoutExtension($legacyPs1Path) } else { '' }
            if     ($taskNameTxt   -match 'Printer') { $legacyType = 'Printer' }
            elseif ($taskNameTxt   -match 'Drive')   { $legacyType = 'Drive' }
            elseif ($ps1NameTxt    -match 'Printer') { $legacyType = 'Printer' }
            elseif ($ps1NameTxt    -match 'Drive')   { $legacyType = 'Drive' }
            elseif ($legacyVbsBase -match 'Printer') { $legacyType = 'Printer' }
            elseif ($legacyVbsBase -match 'Drive')   { $legacyType = 'Drive' }
            elseif ($legacyPs1Content) {
                if     ($legacyPs1Content -match $DriveTableMarker)   { $legacyType = 'Drive' }
                elseif ($legacyPs1Content -match $PrinterTableMarker) { $legacyType = 'Printer' }
                elseif ($legacyPs1Content -match $DriveCallMarker)    { $legacyType = 'Drive' }
                elseif ($legacyPs1Content -match $PrinterCallMarker)  { $legacyType = 'Printer' }
            }
            if (-not $legacyType) {
                Write-Verbose "Skipping task '$($legacyTask.TaskName)' - unable to classify as Drive or Printer"
                continue
            }

            # Extract hardcoded ARP GUIDs from the .ps1 content (if any).
            $taskArpGuids = [System.Collections.Generic.List[string]]::new()
            if ($legacyPs1Content) {
                foreach ($guidMatch in [regex]::Matches($legacyPs1Content, $LegacyGuidPattern)) {
                    [void]$taskArpGuids.Add($guidMatch.Value)
                }
            }

            [void]$LegacyCandidates.Add([pscustomobject]@{
                TaskName   = $legacyTask.TaskName
                TaskPath   = $legacyTask.TaskPath
                VbsPath    = $legacyVbsPath
                Ps1Path    = $legacyPs1Path
                VbsDir     = $legacyVbsDir
                VbsBase    = $legacyVbsBase
                LegacyType = $legacyType
                ArpGuids   = $taskArpGuids
            })
        }

        # Filter to only candidates whose object type matches the current deployment.
        $MatchedCandidates = @($LegacyCandidates | Where-Object { $_.LegacyType -eq $ObjectType })
        $UnmatchedCount    = $LegacyCandidates.Count - $MatchedCandidates.Count
        if ($UnmatchedCount -gt 0) { Write-Verbose "Leaving $UnmatchedCount legacy task(s) intact - they map a different object type than the current deployment ('$ObjectType')" }
        if ($MatchedCandidates.Count -eq 0) {
            Write-Verbose "No legacy '$ObjectType' artifacts detected"
            return
        }
        Write-Verbose "Discovered $($MatchedCandidates.Count) legacy '$ObjectType' candidate(s) for removal"

        # =================== PHASE 2: REMOVE TASKS + FILES ===================
        foreach ($candidate in $MatchedCandidates) {
            # Unregister the legacy scheduled task.
            if ($PSCmdlet.ShouldProcess($candidate.TaskName, 'Remove legacy scheduled task')) {
                try {
                    Unregister-ScheduledTask -TaskName $candidate.TaskName -TaskPath $candidate.TaskPath -Confirm:$false -ErrorAction Stop
                    $RemovedTasks++
                    Write-Verbose "Removed legacy scheduled task '$($candidate.TaskName)' [$($candidate.LegacyType)]"
                }
                catch { Write-Warning "Failed to remove legacy scheduled task '$($candidate.TaskName)'. Error: $_" }
            }

            # Collect ARP GUIDs across all matched candidates for the next phase.
            foreach ($guid in $candidate.ArpGuids) { [void]$LegacyArpGuids.Add($guid) }

            # Remove staged files: .vbs, derived .ps1, optional .version next to it.
            $stagedFiles = @(
                $candidate.VbsPath,
                $candidate.Ps1Path,
                (Join-Path -Path $candidate.VbsDir -ChildPath "$($candidate.VbsBase).version")
            ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
            foreach ($stagedFile in $stagedFiles) {
                if (-not (Test-Path -LiteralPath $stagedFile -PathType Leaf)) { continue }
                if ($PSCmdlet.ShouldProcess($stagedFile, 'Remove legacy file')) {
                    try {
                        Remove-Item -LiteralPath $stagedFile -Force -ErrorAction Stop
                        $RemovedFiles++
                        Write-Verbose "Removed legacy file: $stagedFile"
                    }
                    catch { Write-Warning "Failed to remove legacy file '$stagedFile'. Error: $_" }
                }
            }

            # Track folders for empty-folder cleanup, and remove sibling logs that match the legacy basename.
            [void]$LegacyFolders.Add($candidate.VbsDir)
            $candidateParent = Split-Path -Path $candidate.VbsDir -Parent
            if (-not [string]::IsNullOrWhiteSpace($candidateParent)) {
                [void]$LegacyFolders.Add($candidateParent)
                $candidateLogsDir = Join-Path -Path $candidateParent -ChildPath 'logs'
                if (Test-Path -LiteralPath $candidateLogsDir -PathType Container) {
                    try {
                        $legacyLogFiles = @(Get-ChildItem -LiteralPath $candidateLogsDir -Filter "$($candidate.VbsBase)*.log" -File -Force -ErrorAction Stop)
                        foreach ($legacyLogFile in $legacyLogFiles) {
                            if ($PSCmdlet.ShouldProcess($legacyLogFile.FullName, 'Remove legacy log file')) {
                                try {
                                    Remove-Item -LiteralPath $legacyLogFile.FullName -Force -ErrorAction Stop
                                    $RemovedFiles++
                                    Write-Verbose "Removed legacy log file: $($legacyLogFile.FullName)"
                                }
                                catch { Write-Warning "Failed to remove legacy log file '$($legacyLogFile.FullName)'. Error: $_" }
                            }
                        }
                    }
                    catch { Write-Warning "Failed to enumerate legacy log files in '$candidateLogsDir'. Error: $_" }
                    [void]$LegacyFolders.Add($candidateLogsDir)
                }
            }
        }

        # =================== PHASE 3: REMOVE ARP INSTALLS ===================
        # For each unique GUID extracted, remove from HKLM Uninstall (and the WOW6432Node mirror)
        foreach ($legacyArpGuid in $LegacyArpGuids) {
            $uninstallRoots = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$legacyArpGuid",
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$legacyArpGuid"
            )
            $legacyArpProps = $null
            foreach ($uninstallPath in $uninstallRoots) {
                if (Test-Path -LiteralPath $uninstallPath) {
                    $legacyArpProps = Get-ItemProperty -LiteralPath $uninstallPath -ErrorAction SilentlyContinue
                    if ($legacyArpProps) { break }
                }
            }
            if (-not $legacyArpProps) {
                Write-Verbose "Legacy ARP GUID '$legacyArpGuid' not present under HKLM Uninstall - skipping"
                continue
            }

            $legacyInstallLocation = [string]$legacyArpProps.InstallLocation
            $legacyDisplayName     = [string]$legacyArpProps.DisplayName
            if ([string]::IsNullOrWhiteSpace($legacyDisplayName)) {
                if (-not [string]::IsNullOrWhiteSpace($legacyInstallLocation)) { $legacyDisplayName = Split-Path -Path $legacyInstallLocation -Leaf }
                else                                                           { $legacyDisplayName = $legacyArpGuid }
            }
            $legacyPublisher = [string]$legacyArpProps.Publisher

            if ($PSCmdlet.ShouldProcess($legacyArpGuid, "Remove legacy ARP install '$legacyDisplayName'")) {
                try {
                    $null = Remove-AddRemovePrograms -ARPAppName $legacyDisplayName -ARPAppGuid $legacyArpGuid -ARPAppFolder $legacyInstallLocation -ARPAppPublisher $legacyPublisher
                    $RemovedArp++
                    Write-Verbose "Removed legacy ARP install '$legacyDisplayName' (GUID $legacyArpGuid)"
                }
                catch { Write-Warning "Failed to remove legacy ARP install '$legacyArpGuid'. Error: $_" }
            }
        }

        # =================== PHASE 4: REMOVE EMPTY FOLDERS ===================
        # Pre-compute path depth so Sort-Object doesn't reinvoke a script block per comparison.
        $sortedLegacyFolders = $LegacyFolders |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { [pscustomobject]@{ Path = $_; Depth = ($_ -split '\\').Count } } |
            Sort-Object -Property Depth -Descending |
            ForEach-Object { $_.Path }
        foreach ($legacyFolder in $sortedLegacyFolders) {
            if (-not (Test-Path -LiteralPath $legacyFolder -PathType Container)) { continue }
            try {
                $folderEntries = @(Get-ChildItem -LiteralPath $legacyFolder -Force -ErrorAction Stop)
                if ($folderEntries.Count -ne 0) { continue }
                if ($PSCmdlet.ShouldProcess($legacyFolder, 'Remove empty legacy folder')) {
                    Remove-Item -LiteralPath $legacyFolder -Force -ErrorAction Stop
                    Write-Verbose "Removed empty legacy folder: $legacyFolder"
                }
            }
            catch { Write-Warning "Failed to evaluate or remove legacy folder '$legacyFolder'. Error: $_" }
        }
    }
    end {
        if ($RemovedTasks -eq 0 -and $RemovedFiles -eq 0 -and $RemovedArp -eq 0) { Write-Verbose "No legacy '$ObjectType' mapping artifacts detected" }
        else { Write-Verbose "Legacy '$ObjectType' cleanup summary: tasks=$RemovedTasks files=$RemovedFiles arp=$RemovedArp" }
    }
}

function Show-ProgressGUI {
<#
.SYNOPSIS
    Displays a dark-themed GUI window that executes a list of steps and reports per-step status.
.DESCRIPTION
    Each step has a Name and an Action (scriptblock). The form shows one row per step inside a scrolling
    panel. Rows are colored grey (pending), yellow (running), green (success), orange (warning), and
    red (error). When all steps succeed the window auto-closes after a short delay; on warning or error
    the heading is updated and an OK button is shown so the user can review messages before closing.
    Warning and error text is harvested both from the warning/error streams produced by the action and
    from new entries written to the global $_l log buffer during the step.
    The PowerShell console window is hidden on Windows for the duration of the dialog. On non-Windows
    PowerShell 7 hosts (or when WinForms cannot be loaded) the function falls back to silent execution.
.EXAMPLE
    $steps = @(
        @{ Name = "Step 1: Prepare";   Action = { Start-Sleep -Milliseconds 800 } },
        @{ Name = "Step 2: Install";   Action = { Install-Module Az -Force -Scope CurrentUser } },
        @{ Name = "Step 3: Configure"; Action = { Set-Item Env:\MY_VAR "hello" } }
    )
    Show-ProgressGUI -Steps $steps -Title "My Installer" -Heading "Installing components..."
.NOTES
    Author:  @MrTbone_se (T-bone Granheden)
    Version: 1.1

    Version History:
    1.0 - Initial version
    1.1 - Cross-platform safe console-hide guard, dispose WinForms resources, List-backed control
          collections, accurate help text, distinct warning vs. error labels, single shared silent runner
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, HelpMessage = 'Window title text shown in the title bar')]
        [string]$Title          = "Setup Progress",

        [Parameter(Mandatory = $false, HelpMessage = 'Large heading text shown inside the window')]
        [string]$Heading        = "Running Setup...",

        [Parameter(Mandatory = $true, HelpMessage = 'Array of step objects with Name and Action keys to execute and display')]
        [hashtable[]]$Steps,

        [Parameter(Mandatory = $false, HelpMessage = 'Keep the original heading text after completion instead of replacing it with a summary state')]
        [switch]$KeepHeading,

        [Parameter(Mandatory = $false, HelpMessage = 'Suppress the GUI and run the supplied steps silently instead')]
        [switch]$NoGUI
    )

    # Validate step structure once up front so both -NoGUI and the GUI path get identical behaviour.
    foreach ($step in $Steps) {
        if (-not $step.ContainsKey('Name') -or -not $step.ContainsKey('Action')) {
            Write-Error "Each step must have 'Name' and 'Action' keys. Got: $($step.Keys -join ', ')"
            return
        }
        if ($step.Action -isnot [scriptblock]) {
            Write-Error "Step '$($step.Name)': 'Action' must be a [scriptblock]."
            return
        }
    }

    # Silent runner shared by -NoGUI and the WinForms-load-failure fallback path.
    $RunStepsSilently = {
        foreach ($step in $Steps) {
            Write-Verbose "[$($step.Name)] Starting..."
            try   { & $step.Action; Write-Verbose "[$($step.Name)] Done." }
            catch { Write-Error "[$($step.Name)] Failed: $_"; return }
        }
    }

    if ($NoGUI) {
        Write-Verbose "NoGUI is set. Running steps silently."
        & $RunStepsSilently
        return
    }

    # Console-hide is Windows-only: the kernel32/user32 P/Invoke would crash on PS 7 on Linux/macOS.
    $onWindows = ([Environment]::OSVersion.Platform -eq 'Win32NT')
    if ($onWindows) {
        if (-not ([System.Management.Automation.PSTypeName]'ConsoleWindow').Type) {
            $ConsoleWindowSource = @(
                'using System;'
                'using System.Runtime.InteropServices;'
                'public class ConsoleWindow {'
                '    [DllImport("kernel32.dll")]'
                '    public static extern IntPtr GetConsoleWindow();'
                '    [DllImport("user32.dll")]'
                '    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);'
                '}'
            ) -join [Environment]::NewLine
            try { Add-Type -TypeDefinition $ConsoleWindowSource -ErrorAction Stop } catch { Write-Verbose "ConsoleWindow Add-Type failed: $_" }
        }
        try { [ConsoleWindow]::ShowWindow([ConsoleWindow]::GetConsoleWindow(), 0) | Out-Null } catch { Write-Verbose "ShowWindow call failed: $_" }
    }

    # Load WinForms assemblies (only when GUI is requested). On any failure run silently instead.
    foreach ($asm in @('System.Windows.Forms', 'System.Drawing')) {
        try {
            Add-Type -AssemblyName $asm -ErrorAction Stop
        } catch {
            Write-Warning "Assembly '$asm' failed to load - falling back to silent execution. Error: $_"
            & $RunStepsSilently
            return
        }
    }

    # Create the main form and set properties for a dark-themed progress window.
    $form = New-Object System.Windows.Forms.Form
    try {
        $form.Text            = $Title
        $form.ClientSize      = New-Object System.Drawing.Size(510, 495)
        $form.StartPosition   = "CenterScreen"
        $form.FormBorderStyle = "FixedDialog"
        $form.MaximizeBox     = $false
        $form.MinimizeBox     = $false
        $form.BackColor       = [System.Drawing.Color]::FromArgb(30, 30, 30)
        $form.ForeColor       = [System.Drawing.Color]::White

        # Build the heading label at the top of the form.
        $lblTitle           = New-Object System.Windows.Forms.Label
        $lblTitle.Text      = $Heading
        $lblTitle.Font      = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
        $lblTitle.ForeColor = [System.Drawing.Color]::White
        $lblTitle.Location  = New-Object System.Drawing.Point(20, 15)
        $lblTitle.Size      = New-Object System.Drawing.Size(470, 30)
        $form.Controls.Add($lblTitle)

        # Add a panel to hold the step labels and messages, with auto-scrolling for overflow.
        $stepsPanel               = New-Object System.Windows.Forms.FlowLayoutPanel
        $stepsPanel.Location      = New-Object System.Drawing.Point(20, 55)
        $stepsPanel.Size          = New-Object System.Drawing.Size(470, 380)
        $stepsPanel.BackColor     = [System.Drawing.Color]::FromArgb(20, 20, 20)
        $stepsPanel.BorderStyle   = "FixedSingle"
        $stepsPanel.FlowDirection = "TopDown"
        $stepsPanel.WrapContents  = $false
        $stepsPanel.AutoScroll    = $true
        $stepsPanel.Padding       = New-Object System.Windows.Forms.Padding(6, 6, 6, 6)
        $form.Controls.Add($stepsPanel)

        # Pre-create one row per step (step label + hidden indented message label). SuspendLayout
        # avoids an O(n) relayout on every Controls.Add.
        $rowWidth   = 430
        $stepLabels = [System.Collections.Generic.List[System.Windows.Forms.Label]]::new()
        $msgLabels  = [System.Collections.Generic.List[System.Windows.Forms.Label]]::new()
        $stepsPanel.SuspendLayout()
        foreach ($step in $Steps) {
            $lbl             = New-Object System.Windows.Forms.Label
            $lbl.Text        = "* $($step.Name)"
            $lbl.Font        = New-Object System.Drawing.Font("Segoe UI", 10)
            $lbl.ForeColor   = [System.Drawing.Color]::FromArgb(140, 140, 140)
            $lbl.AutoSize    = $true
            $lbl.MaximumSize = New-Object System.Drawing.Size($rowWidth, 0)
            $lbl.Margin      = New-Object System.Windows.Forms.Padding(0, 4, 0, 0)
            $stepsPanel.Controls.Add($lbl)
            $stepLabels.Add($lbl)

            $msg             = New-Object System.Windows.Forms.Label
            $msg.Text        = ""
            $msg.Font        = New-Object System.Drawing.Font("Consolas", 8)
            $msg.ForeColor   = [System.Drawing.Color]::FromArgb(220, 180, 80)
            $msg.AutoSize    = $true
            $msg.MaximumSize = New-Object System.Drawing.Size(($rowWidth - 20), 0)
            $msg.Margin      = New-Object System.Windows.Forms.Padding(24, 1, 0, 0)
            $msg.Visible     = $false
            $stepsPanel.Controls.Add($msg)
            $msgLabels.Add($msg)
        }
        $stepsPanel.ResumeLayout()

        # OK button - hidden until errors or warnings occur, then revealed for user dismissal.
        $btnOK           = New-Object System.Windows.Forms.Button
        $btnOK.Text      = "OK"
        $btnOK.Location  = New-Object System.Drawing.Point(390, 445)
        $btnOK.Size      = New-Object System.Drawing.Size(100, 28)
        $btnOK.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
        $btnOK.ForeColor = [System.Drawing.Color]::White
        $btnOK.FlatStyle = "Flat"
        $btnOK.Visible   = $false
        $btnOK.Add_Click({ $form.Close() })
        $form.Controls.Add($btnOK)

        # Run the steps when the form is shown, updating step labels with colors and text based on each step's outcome.
        $form.Add_Shown({
            $totalSteps  = $Steps.Count
            $errorCount  = 0
            $warnCount   = 0

            for ($i = 0; $i -lt $totalSteps; $i++) {
                $step      = $Steps[$i]
                $stepLabel = $stepLabels[$i]
                $msgLabel  = $msgLabels[$i]

                $stepLabel.ForeColor = [System.Drawing.Color]::FromArgb(255, 200, 50)  # yellow = running
                $stepLabel.Text      = "* $($step.Name) - running..."
                $stepsPanel.ScrollControlIntoView($stepLabel)
                $form.Refresh()

                $stepHasError   = $false
                $stepHasWarning = $false
                $stepMessages   = [System.Collections.Generic.List[string]]::new()

                # Snapshot the global log buffer so we can detect ERROR/WARN entries written by the step.
                $logBefore = if ($global:_l) { $global:_l.Count } else { 0 }
                try {
                    $rawOutput = & $step.Action 2>&1 3>&1
                    foreach ($item in $rawOutput) {
                        if ($item -is [System.Management.Automation.WarningRecord]) {
                            $stepMessages.Add($item.Message); $stepHasWarning = $true
                        } elseif ($item -is [System.Management.Automation.ErrorRecord]) {
                            $stepMessages.Add($item.Exception.Message); $stepHasError = $true
                        }
                    }
                } catch {$stepMessages.Add($_.Exception.Message); $stepHasError = $true}

                # Inspect log entries added during this step's execution and harvest ERROR/WARN messages.
                if ($global:_l -and $global:_l.Count -gt $logBefore) {
                    for ($li = $logBefore; $li -lt $global:_l.Count; $li++) {
                        $entry = $global:_l[$li]
                        if ($entry -match ',ERROR,[^,]*,[^,]*,(.*)$') {
                            $stepMessages.Add($Matches[1]); $stepHasError = $true
                        } elseif ($entry -match ',WARN,[^,]*,[^,]*,(.*)$') {
                            $stepMessages.Add($Matches[1]); $stepHasWarning = $true
                        }
                    }
                }
                # Update labels based on outcome and accumulate counters for the final summary.
                if ($stepHasError) {
                    $errorCount++
                    $stepLabel.ForeColor = [System.Drawing.Color]::FromArgb(220, 80, 80)   # red
                    $stepLabel.Text      = "* $($step.Name) - Failed"
                    $msgLabel.ForeColor  = [System.Drawing.Color]::FromArgb(220, 120, 120)
                    $msgLabel.Text       = ($stepMessages -join [Environment]::NewLine)
                    $msgLabel.Visible    = $true
                } elseif ($stepHasWarning) {
                    $warnCount++
                    $stepLabel.ForeColor = [System.Drawing.Color]::FromArgb(255, 165, 0)   # orange
                    $stepLabel.Text      = "* $($step.Name) - Completed with warnings"
                    $msgLabel.ForeColor  = [System.Drawing.Color]::FromArgb(220, 180, 80)
                    $msgLabel.Text       = ($stepMessages -join [Environment]::NewLine)
                    $msgLabel.Visible    = $true
                } else {
                    $stepLabel.ForeColor = [System.Drawing.Color]::FromArgb(80, 200, 120)  # green
                    $stepLabel.Text      = "* $($step.Name) - successful"
                }
                $form.Refresh()
            }
            if ($errorCount -gt 0) {
                $lblTitle.ForeColor = [System.Drawing.Color]::FromArgb(220, 80, 80)
                if (-not $KeepHeading) { $lblTitle.Text = "Completed with errors" }
                $btnOK.Visible      = $true
                $form.Refresh()
            }
            elseif ($warnCount -gt 0) {
                $lblTitle.ForeColor = [System.Drawing.Color]::FromArgb(220, 160, 50)
                if (-not $KeepHeading) { $lblTitle.Text = "Completed with warnings" }
                $btnOK.Visible      = $true
                $form.Refresh()
            }
            else {
                $lblTitle.Text = "Complete!"
                $form.Refresh()
                Start-Sleep -Seconds 1
                $form.Close()
            }
        })
        [void]$form.ShowDialog()
    }
    finally {
        if ($form) { try { $form.Dispose() } catch { Write-Verbose "Form Dispose failed: $_" } }
    }
}
#endregion

#region ---------------------------------------------------[[Reusable workflow scriptblocks]----------------------------------------
# ====================> InstallScript (Runs only from Remediate, Intunewin, and elevated Manual installs and reinstalls)===============================================
$InstallScript = {
    # Replace legacy Mr T-Bone mapping script V1 and V2 if the flag is set (caller has already verified canInstall before invoking $InstallScript).
    if ($ReplaceOldV1andV2) { Remove-LegacyV1V2Artifacts -ObjectType $ObjectType }
    try {
        $null = New-Item -ItemType Directory -Path (Split-Path $ScriptSavePath -Parent) -Force -ErrorAction Stop
        Copy-Item -Path $PSCommandPath -Destination $ScriptSavePath -Force -ErrorAction Stop
        [System.IO.File]::WriteAllText($JSSavePath, $JSLauncherContent, [System.Text.Encoding]::ASCII)
        $null = New-Item -ItemType Directory -Path (Split-Path $ShortcutLauncherPath -Parent) -Force -ErrorAction Stop
        [System.IO.File]::WriteAllText($ShortcutLauncherPath, $ShortcutLauncherContent, [System.Text.Encoding]::ASCII)
        Set-Content -Path $VersionFilePath -Value $MappingVersion.ToString() -Force -ErrorAction Stop
    }
    catch { Write-Error "Failed to stage install artifacts. Error: $_"; $script:ScriptExitCode = 5; return $false }
    $taskRegistered = Register-IntuneTask `
        -TaskName              $TaskName `
        -TaskDescription       $TaskDescription `
        -TaskExecute           "$env:SystemRoot\System32\wscript.exe" `
        -TaskArgument          "`"$JSSavePath`" `"$ScriptSavePath`"" `
        -TaskPrincipalGroupSid $UsersGroupSid `
        -TaskTriggerAtLogon:$RunAtLogon `
        -TaskTriggerAtNetConnect:$RunAtNetConnect `
        -TaskHidden `
        -TaskForce `
        -TaskStartImmediately
    if (-not $taskRegistered) { $script:ScriptExitCode = 4; return $false }
    $arpRegistered = Add-AddRemovePrograms -ARPAppName $ARPAppName -ARPAppVersion $ARPAppVersion -ARPAppGuid $ARPAppGuid -ARPAppPublisher $ARPAppPublisher -ARPAppFolder $ARPAppFolder -ARPAppEnableUninstall $ARPAppEnableUninstall `
        -ARPAppEnableModify $ARPAppEnableModify -ARPAppIcon $ARPAppIcon -ARPAppIconPath $ARPAppIconPath -ARPAppInstallScript $ARPAppInstallScript -ARPAppUnInstallScript $ARPAppUnInstallScript -ARPAppIncludeFolder $ARPAppIncludeFolder `
        -ARPAppUserStartFile $EffectiveStartFile -ARPAppShortcutOnDesktop $ARPAppShortcutOnDesktop -ARPAppShortcutInStart $ARPAppShortcutInStart -ARPAppForce ($ARPAppForce -or $forceReinstall)
    if (-not $arpRegistered) { Write-Error "Failed to register Add/Remove Programs entry."; $script:ScriptExitCode = 6; return $false }
    return $true
}

# ====================> WorkflowScript (Resolves AD groups, builds Steps, optionally removes stale objects and runs the mapping with or without GUI) ==================
$WorkflowScript = {
    param([bool]$ShowGui)
    $dcOk       = $true
    $UserGroups = Get-ADGroupMemberships -Domain $DomainName -RequiredGroups $RequiredGroups -DCAvailable ([ref]$dcOk)
    if (-not $dcOk) {
        $dcMsg = $DomainName
        if ($ShowGui) { Show-ProgressGUI -Steps @(@{ Name = "Domain network not available"; Action = [scriptblock]::Create("Write-Warning 'No domain controller was reachable for ''$dcMsg''. Network drive/printer mappings are skipped.'") }) -Title $TaskName -Heading "Domain network not available" -KeepHeading }
        else {Write-Warning "No domain controller was reachable for '$dcMsg'. Network drive/printer mappings are skipped."}
        return
    }
    #Build the list of objects to map
    $FilteredMapObjects = @($MapObjects | Where-Object { [string]::IsNullOrEmpty($_['ADGroups']) -or $_['ADGroups'] -in $UserGroups })
    $Steps              = @()
    foreach ($obj in $FilteredMapObjects) { if ($ObjectType -eq 'Printer') {
            $escapedPrinterName  = $obj.PrinterName -replace "'", "''"
            $escapedPrinterPath  = $obj.Path -replace "'", "''"
            $printerDefaultValue = $obj.Default.ToString().ToLower()
            $Steps += @{
                Name   = "Map Printer: $($obj.PrinterName)"
                Action = [scriptblock]::Create("New-PrinterMapping -PrinterName '$escapedPrinterName' -PrinterPath '$escapedPrinterPath' -PrinterDefault `$$printerDefaultValue")
            }
        }
        else {
            $label              = if ($obj.ContainsKey('Label'))      { $obj.Label }      else { '' }
            $persistent         = if ($obj.ContainsKey('Persistent')) { $obj.Persistent } else { $true }
            $escapedDriveLetter = $obj.Letter -replace "'", "''"
            $escapedDrivePath   = $obj.Path -replace "'", "''"
            $escapedDriveLabel  = $label -replace "'", "''"
            $persistentValue    = $persistent.ToString().ToLower()
            $Steps += @{
                Name   = "Map Drive $($obj.Letter):"
                Action = [scriptblock]::Create("New-DriveMapping -DriveLetter '$escapedDriveLetter' -DrivePath '$escapedDrivePath' -DriveLabel '$escapedDriveLabel' -DrivePersistent `$$persistentValue")
            }
        } }
    # Remove stale objects
    if ($RemoveStaleObjects) { 
        if ($ObjectType -eq 'Printer') {
            $activePaths = @($FilteredMapObjects | ForEach-Object { $_['Path'] })
            Get-Printer -EA SilentlyContinue | Where-Object { $_.Type -eq 'Connection' -and $_.Name -notin $activePaths } | ForEach-Object {
                $pName  = $_.Name
                $Steps += @{ Name = "Remove stale printer: $pName"; Action = [scriptblock]::Create("Remove-Printer -Name '$($pName -replace "'","''")' -EA SilentlyContinue") }
            }
        }
        else {
            $activeLetters = @($FilteredMapObjects | ForEach-Object { $_['Letter'] })
            Get-PSDrive -PSProvider FileSystem -EA SilentlyContinue | Where-Object { $_.DisplayRoot -like '\\*' -and $_.Name -notin $activeLetters } | ForEach-Object {
                $dLetter = $_.Name
                $Steps  += @{ Name = "Remove stale drive ${dLetter}:"; Action = [scriptblock]::Create("net use ${dLetter}: /delete 2>&1 | Out-Null") }
            }
        } }

    if ($Steps.Count -gt 0) { Show-ProgressGUI -Steps $Steps -NoGUI:(-not $ShowGui) -Title $TaskName -Heading "Mapping $($ObjectType)s..." }
    else { Write-Host "No $ObjectType mappings applicable for current user" }
}

# ====================> UninstallScript (Removes scheduled task, staged artifacts, and ARP entry. Optional uninstall helper script runs first) ========================
$UninstallScript = {
    if ($ARPAppUnInstallScript -and (Test-Path -LiteralPath $ARPAppUnInstallScript)) { try {

            Write-Verbose "Running uninstall helper script: $ARPAppUnInstallScript"
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ARPAppUnInstallScript
        } catch {Write-Warning "Failed to run uninstall helper script $ARPAppUnInstallScript. Error: $_"} }

    try {
        $tsService = New-Object -ComObject 'Schedule.Service'
        $tsService.Connect()
        $tsService.GetFolder('\').DeleteTask($TaskName, 0)
        Write-Verbose "Scheduled task removed: $TaskName"
    } catch { if ($ExistingTask) { Write-Warning "Failed to remove scheduled task $TaskName. Error: $_" }

        else { Write-Verbose "Scheduled task not found: $TaskName" } }

    foreach ($ArtifactPath in @($ScriptSavePath, $JSSavePath, $VersionFilePath)) { if (Test-Path -LiteralPath $ArtifactPath) { try {


                Remove-Item -LiteralPath $ArtifactPath -Force -ErrorAction Stop
                Write-Verbose "Removed artifact: $ArtifactPath"
            } catch {Write-Warning "Failed to remove artifact $ArtifactPath. Error: $_"} }
 }

    $null = Remove-AddRemovePrograms -ARPAppName $ARPAppName -ARPAppGuid $ARPAppGuid -ARPAppFolder $ARPAppFolder -ARPAppPublisher $ARPAppPublisher
}
#endregion

#region ---------------------------------------------------[[Script Execution]------------------------------------------------------
# Start T-Bone custom logging
Invoke-TboneLog -LogMode Start -Logname $LogName -LogToGUI $LogToGUI -LogToEventlog $LogToEventlog -LogEventIds $LogEventIds -LogToDisk $LogToDisk -LogPath $LogToDiskPath -LogToHost $LogToHost
#declare variables to track state and results across execution
[int]$ScriptExitCode    = 0
[string]$ExecutionMode  = 'Unknown'
[object[]]$ScriptLog    = @()
[bool]$EmitDetectOutput = $false
[bool]$compliant        = $false
[version]$savedVersion  = [version]'0.0'
$ExistingTask           = $null
$CTX                    = $null
[bool]$forceReinstall   = $ForceReplaceAll -or ($InstallType -eq 'Repair')
# Resolve which file the All-Users desktop/start shortcuts should target. If the caller did not supply an explicit ARPAppUserStartFile, default to the silent JS launcher
[string]$EffectiveStartFile = if ([string]::IsNullOrWhiteSpace($ARPAppUserStartFile)) { $ShortcutLauncherPath } else { $ARPAppUserStartFile }
# Set or clear the MapperShowGUI to specify if the scheduled task should run with or without GUI
$SetUserGuiFlag = {
    try   { [System.Environment]::SetEnvironmentVariable('MapperShowGUI', '1',   'User'); return $true }
    catch { Write-Warning "Failed to set user-scope MapperShowGUI override. Error: $_"; return $false }
}
$ClearUserGuiFlag = {
    try   { [System.Environment]::SetEnvironmentVariable('MapperShowGUI', $null, 'User') }
    catch { Write-Verbose "Failed to delete user-scope MapperShowGUI: $_" }
}
# ==========> Get the execution context to determine script behavior   <========================================================================
try {
    # Validate $MapObjects shape early so configuration errors surface with a readable message before context detection or any side effects.
    try { $null = Test-MapObjectValidation -MapObjects $MapObjects }
    catch { throw [System.ArgumentException]::new("Configuration validation failed: $($_.Exception.Message)") }
    # Auto-require x64 on a 64-bit OS (unless the caller pinned a different value)
    if (-not $CTXReqArchitecture -and [Environment]::Is64BitOperatingSystem) { $CTXReqArchitecture = 'x64' }
    $CTX = Get-RuntimeContext -CTXReqIdentity $CTXReqIdentity -CTXReqArchitecture $CTXReqArchitecture -CTXAutoRelaunchToX64:$CTXAutoRelaunchToX64 -CTXReqPSVersion $CTXReqPSVersion -CTXReqOSBuild $CTXReqOSBuild -CTXAbortIfPendingReboot:$CTXAbortIfPendingReboot -CTXForwardParameters $PSBoundParameters
    if (-not $CTX) { Write-Warning "Execution context validation failed. Exiting with code 2."; $ScriptExitCode = 2 }
    else {
        $MapperShowGUIOverride = $EndUserGUI -and (([System.Environment]::GetEnvironmentVariable('MapperShowGUI') -eq '1') -or ([System.Environment]::GetEnvironmentVariable('MapperShowGUI', 'User') -eq '1'))
        $ExecutionMode = switch ($true) {
            ($CTX.CTXMode   -eq 'Intunewin')     { 'Intunewin';     break }
            ($CTX.CTXMode   -eq 'Detection')     { 'Detect';        break }
            ($CTX.CTXMode   -eq 'Remediation')   { 'Remediate';     break }
            ($CTX.CTXSource -eq 'ScheduledTask') { 'ScheduledTask'; break }
            $MapperShowGUIOverride               { 'ScheduledTask'; break } # MapperShowGUI=1 means the script was invoked manually and should show GUI.
            default                              { 'Manual' }
        }
        Write-Verbose "ExecutionMode = $ExecutionMode (CTXMode=$($CTX.CTXMode), CTXSource=$($CTX.CTXSource), CTXIdentity=$($CTX.CTXIdentity))"
# ==========> Detect compliance (Just detect if compliant and use result in different execution modes)<=========================================
        [bool]$canInstall = $CTX.CTXIdentity -in @('System', 'Admin')
        $ExistingTask = $null
        try {
            $tsService = New-Object -ComObject 'Schedule.Service'
            $tsService.Connect()
            $tsFolder  = $tsService.GetFolder('\')
            $tsTask    = $tsFolder.GetTask($TaskName)
            $tsStateName = switch ([int]$tsTask.State) { 0 {'Unknown'} 1 {'Disabled'} 2 {'Queued'} 3 {'Ready'} 4 {'Running'} default {'Unknown'} }
            $ExistingTask = [pscustomobject]@{ TaskName = $TaskName; State = $tsStateName; Enabled = [bool]$tsTask.Enabled }
        } catch { $ExistingTask = $null }
        $compliant              = $true
        [bool]$shouldReinstall  = $false
        if ($canInstall) {
            $savedVersion = if (Test-Path $VersionFilePath){try {[version](Get-Content $VersionFilePath -Raw -EA Stop).Trim()}catch{[version]'0.0' }}else{[version]'0.0'}
            if (-not (Test-Path $VersionFilePath))                  { Write-Host "Non-compliant: version file missing";                             $compliant = $false }
            if (-not ($savedVersion -ge $MappingVersion))           { Write-Host "Non-compliant: version $savedVersion < required $MappingVersion"; $compliant = $false }
            if (-not (Test-Path $ScriptSavePath))                   { Write-Host "Non-compliant: worker script missing";                            $compliant = $false }
            if (-not (Test-Path $JSSavePath))                       { Write-Host "Non-compliant: JS launcher missing";                              $compliant = $false }
            if (-not $ExistingTask -or [string]$ExistingTask.State -eq 'Disabled') { Write-Host "Non-compliant: scheduled task missing/disabled";   $compliant = $false }
            # ShouldReinstall reflects only the compliance check; force flags are evaluated separately at each branch.
            $shouldReinstall = -not $compliant
        }
        Write-Verbose "Compliance=$compliant, ForceReplaceAll=$ForceReplaceAll, InstallType=$InstallType, ForceReinstall=$forceReinstall, ShouldReinstall=$shouldReinstall, CanInstall=$canInstall"
    # ==========> Uninstall (If InstallType is UnInstall and the user has sufficient privileges to uninstall)<======================================
        if ($InstallType -eq 'UnInstall') {
            if (-not $canInstall) { Write-Warning "InstallType '$InstallType' requires System or Admin. Current identity: $($CTX.CTXIdentity)"; $ScriptExitCode = 3 }
            else                  { & $UninstallScript; $ScriptExitCode = 0 }
        }
        else { switch ($ExecutionMode) {
    # ==========> Detect with Intune Remediaton (Check compliance without making changes)<==========================================================
                'Detect' {
                    $EmitDetectOutput = $true
                    if ($compliant) { $ScriptExitCode = 0 }
                    else { $ScriptExitCode = 1 }
                }
    # ==========> Remediate with Intune Remediaton (Make changes to achieve compliance)<============================================================
                'Remediate' {
                    if (-not $canInstall) { Write-Warning "ExecutionMode '$ExecutionMode' requires System or Admin to install or remediate. Current identity: $($CTX.CTXIdentity)"; $ScriptExitCode = 3; break }
                    if (-not ($shouldReinstall -or $forceReinstall)) { Write-Host "ExecutionMode '$ExecutionMode' and Compliant: $TaskName v$savedVersion - skipping install or remediation"; $ScriptExitCode = 0; break }
                    if (& $InstallScript) { $ScriptExitCode = 0 }
                }
    # ==========> Install with Intune Win32App (Install if the application is not compliant)<=======================================================
                'Intunewin' {
                    if (-not $canInstall) { Write-Warning "ExecutionMode '$ExecutionMode' requires System or Admin to install or remediate. Current identity: $($CTX.CTXIdentity)"; $ScriptExitCode = 3; break }
                    if (-not ($shouldReinstall -or $forceReinstall)) { Write-Host "ExecutionMode '$ExecutionMode' and Compliant: $TaskName v$savedVersion - skipping install or remediation"; $ScriptExitCode = 0; break }
                    if (& $InstallScript) { $ScriptExitCode = 0 }
                }
    # ==========> Manual execution (Install if not compliant and user is elevated or only run existing scheduledtask)<==============================
                'Manual' {
                    # Install or repair (Manual run with permissions to install or repair, and either non-compliant or force-reinstall requested) 
                    if ($canInstall -and ($shouldReinstall -or $forceReinstall)) { 
                        Write-verbose "Elevated manual run detected - installing or repairing all scheduled-task components (ShouldReinstall=$shouldReinstall, ForceReinstall=$forceReinstall)"
                        if (& $InstallScript) { $ScriptExitCode = 0 }
                    }
                    # Run the workflow with or without GUI (Manual run with compliant state and existing scheduled task)
                    elseif ($ExistingTask -and -not ($shouldReinstall -or $forceReinstall)) { 
                        $guiFlagSet = $false
                        if ($EndUserGUI) {
                            $guiFlagSet = & $SetUserGuiFlag
                            if ($guiFlagSet) { Write-Verbose "Set MapperShowGUI=1 in user-scope registry - starting scheduled task '$TaskName' with GUI override" }
                        }
                        else { Write-Verbose "Starting scheduled task '$TaskName' without GUI override" }
                        try {
                            $tsService = New-Object -ComObject 'Schedule.Service'
                            $tsService.Connect()
                            $null = $tsService.GetFolder('\').GetTask($TaskName).Run($null)
                            Write-Verbose "Started scheduled task '$TaskName' with GUI $(if ($guiFlagSet) { 'enabled' } else { 'disabled' })"
                            $guiFlagSet     = $false   # task now owns the flag
                            $ScriptExitCode = 0
                        }
                        catch   { Write-Warning "Failed to start scheduled task '$TaskName'. Error: $_"; $ScriptExitCode = 4 }
                        finally { if ($guiFlagSet) { & $ClearUserGuiFlag } }
                    }
                    # Exit or Run the workflow with or without GUI in non-compliant state (Manual run with non-compliant state but cannot install)
                    else { 
                        if (($shouldReinstall -or $forceReinstall) -and -not $canInstall) { Write-Warning "Non-compliant or force-reinstall requested, but current identity '$($CTX.CTXIdentity)' cannot install or repair. Running mapping directly for this session only" }
                        elseif (-not $ExistingTask) {Write-Warning "Scheduled task '$TaskName' not found - running mapping directly"}
                        & $WorkflowScript -ShowGui ($EndUserGUI -and -not $CTX.CTXNoGUISupport)
                        $ScriptExitCode = 0
                    }
                }
    # ==========> Scheduled Task (Execute the user workflow to map resources)<======================================================================
                'ScheduledTask' {
                    $procOverride = [System.Environment]::GetEnvironmentVariable('MapperShowGUI') -eq '1'
                    $userOverride = [System.Environment]::GetEnvironmentVariable('MapperShowGUI', 'User') -eq '1'
                    $oneShot      = $EndUserGUI -and ($procOverride -or $userOverride)
                    if ($procOverride) { [System.Environment]::SetEnvironmentVariable('MapperShowGUI', $null) }
                    if ($userOverride) { & $ClearUserGuiFlag }
                    Write-Verbose "Scheduled task execution with GUI $(if ($oneShot) { 'enabled' } else { 'disabled' })"
                    & $WorkflowScript -ShowGui $oneShot
                    $ScriptExitCode = 0
                }
            }
        }
    }
}
catch [System.ArgumentException] {Write-Error $_.Exception.Message; $ScriptExitCode = 7}
catch {Write-Error "Unhandled error in script: $($_.Exception.Message)"; $ScriptExitCode = 9}
finally {
    # $CTX is assigned inside the try; guard against StrictMode failures when Get-RuntimeContext threw before assignment or returned $null.
    $ctxIdentityForLog = if ($CTX -and $CTX.PSObject.Properties['CTXIdentity']) { $CTX.CTXIdentity } else { 'Unknown' }
    Write-Verbose "Completed $ExecutionMode execution with installtype $InstallType as $ctxIdentityForLog completed with exit code $ScriptExitCode. Cleaning up environment..."
    # Restore original preference settings
    try { $ErrorActionPreference = $script:OriginalErrorActionPreference } catch {}
    try { $VerbosePreference     = $script:OriginalVerbosePreference } catch {}
    try { $WhatIfPreference      = $script:OriginalWhatIfPreference } catch {}
    # cleanup of environment variables
    try { [System.Environment]::SetEnvironmentVariable('MapperCTXSource', $null) } catch {}
    try { [System.Environment]::SetEnvironmentVariable('MapperShowGUI',   $null) } catch {}
    # Stop T-Bone custom logging and capture any errors during shutdown
    try { $ScriptLog = @(Invoke-TboneLog -LogMode Stop) }
    catch { $ScriptLog = @("Logger shutdown failed: $($_.Exception.Message)") }
}
# If the script was run in detection mode, return a simple compliant/non-compliant message that can be parsed by Intune, otherwise just exit with the appropriate exitcode
if ($EmitDetectOutput) { if ($compliant) { Write-Output "Compliant: $TaskName v$MappingVersion" }
    else { Write-Output "Non-Compliant - $($ScriptLog -join "`n")" } }
exit $ScriptExitCode
#endregion
