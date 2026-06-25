<#PSScriptInfo
.VERSION        3.7.0
.AUTHOR         @MrTbone_se (T-bone Granheden)
.GUID           feedbeef-beef-4dad-beef-b628ccca16be
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
    3.2.1 2026-06-09 fix illegal chars
    3.3.0 2026-06-14 Minor update to not overload Domain Controllers
    3.4.0 2026-06-15 Minor update with a function to remove legacy Mr T-Bone scripts to migrate to the new version
    3.5.0 2026-06-16 Minor update to move redundant tasks to scriptblocks
    3.6.0 2026-06-17 Minor update with adjusted logic for uninstall and detection. If InstallType is Uninstall, Detect will report non-compliant if App exist and remediation will uninstall
    3.7.0 2026-06-25 Minor update to fix ad group discovery and more seamless gui interface for end users and many syntax improvments
#>
<#
.SYNOPSIS
    Maps Intune-managed cloud-native drives or printers by scheduled task, manual run, or remediation workflow.

.DESCRIPTION
    This script deploys and runs a drive-mapping or printer-mapping solution for Entra ID joined / cloud-native Windows devices.
    It supports Intune Win32 app install, Intune remediation, elevated manual install/repair, normal user manual execution, and uninstall.

    During install or remediation, the script stages itself into the application folder, registers a hidden scheduled task that runs in user context,
    writes a launcher script, stores a version marker, and optionally registers the solution in Add/Remove Programs with icon, shortcuts,
    uninstall support, and modify/reinstall support.

    During user execution, the script can either trigger the deployed scheduled-task worker with a one-shot GUI override or run the mapping logic directly.
    Mapping applicability is determined from configured AD group names collected through LDAP after a DC Locator check. If no domain controller is reachable,
    the script aborts mapping instead of continuing with incomplete group data. Optional stale drive or printer cleanup is also supported.

.EXAMPLE
    .\Map-DrivesCloudNative.ps1
    .\Map-PrintersCloudNative.ps1
	Run either script with default settings. Admin/System installs or repairs it; a normal user runs the existing mapping task.

.EXAMPLE
	.\Map-DrivesCloudNative.ps1 -LogVerboseEnabled $true -LogToDisk $true
    .\Map-PrintersCloudNative.ps1 -LogVerboseEnabled $true -LogToDisk $true
	Run either script with verbose logging and save the log to disk.

.EXAMPLE
	.\Map-DrivesCloudNative.ps1 -InstallType UnInstall
    .\Map-PrintersCloudNative.ps1 -InstallType UnInstall
	Remove the scheduled task, staged files, version marker, and Add/Remove Programs entry.

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
	[String]$DomainName = "tbone.se",

	[Parameter(Mandatory = $false, HelpMessage = "Mapping configuration version, increment when adding new or changing drive or printer mappings")]
	[version]$MappingVersion = "3.6.0",

	[Parameter(Mandatory = $false, HelpMessage = "Enable a GUI with mapping results when the user manually executes the script. Default is true.")]
	[Bool]$EndUserGUI = $true,

	[Parameter(Mandatory = $false, HelpMessage = "Remove stale drive/printer mappings that are no longer in the configuration")]
	[Bool]$RemoveStaleObjects = $true,

	[Parameter(Mandatory = $false, HelpMessage = 'Specify how to run the script: Install, Repair or UnInstall')]
	[validateset("Install", "Repair", "UnInstall")]
	[string]$InstallType = "Install",

	[Parameter(Mandatory = $false, HelpMessage = "Force replace all scripts and scheduled tasks even if version is the same")]
	[Bool]$ForceReplaceAll = $false,

	[Parameter(Mandatory = $false, HelpMessage = "Detect and remove legacy mapping deployments from earlier generations before installing or repairing the current deployment")]
	[Bool]$ReplaceOldV1andV2 = $true,

	# ==========> ScheduleTask Triggers (Register-NewScheduledTask) <================================================
	[Parameter(Mandatory = $false, HelpMessage = "Run the script at user logon")]
	[Bool]$TaskTriggerAtLogon = $true,

	[Parameter(Mandatory = $false, HelpMessage = "Delay the logon scheduled-task trigger so VPN or ZTNA has time to connect before mapping starts")]
	[ValidateRange(0, 3600)]
	[int]$TaskTriggerAtLogonDelaySeconds = 30,

	[Parameter(Mandatory = $false, HelpMessage = "Run the script when network connection is established")]
	[Bool]$TaskTriggerAtNetConnect = $false,

	# ==========> AD Discovery (Get-ADGroupMemberships) <==============================================================
	[Parameter(Mandatory = $false, HelpMessage = "Skip token discovery that do not support nested group membership discovery")]
	[Bool]$ADGRPSkipTokenDiscovery = $false,

	[Parameter(Mandatory = $false, HelpMessage = "Maximum time in seconds to wait for a reachable domain controller before skipping mapping")]
	[ValidateRange(0, 3600)]
	[int]$ADGRPDCWaitTimeoutSeconds = 30,

	[Parameter(Mandatory = $false, HelpMessage = "Seconds between domain-controller reachability retries")]
	[ValidateRange(1, 300)]
	[int]$ADGRPDCWaitIntervalSeconds = 5,

	# ==========> Add Application to Add Remove Program (Add-AddRemoveProgram) <===========================================
	[Parameter(Mandatory = $false, HelpMessage = 'Name of the application/script being wrapped')]
	[String]$ARPAppName = "Map Printers",

	[Parameter(Mandatory = $false, HelpMessage = 'Company name used for naming of folders and registry keys')]
	[String]$ARPAppPublisher = "Billerud",

	[Parameter(Mandatory = $false, HelpMessage = 'Hide the app from Add Remove Programs (SystemComponent) while still writing the registry and files for detection')]
	[bool]$ARPAppHidden = $False,

	[Parameter(Mandatory = $false, HelpMessage = 'Hide the uninstall option in Add Remove Programs')]
	[bool]$ARPAppHideUninstall = $False,

	[Parameter(Mandatory = $false, HelpMessage = 'Hide the modify option in Add Remove Programs (typically for repair/reinstall)')]
	[bool]$ARPAppHideModify = $False,

	[Parameter(Mandatory = $false, HelpMessage = 'Optional path to an external .ico file to use as the icon of the app')]
	[string]$ARPAppIconPath = "",

	[Parameter(Mandatory = $false, HelpMessage = 'Optional Base64-encoded .ico content to use as the icon of the app. if not specified, a default icon will be used')]
	[string]$ARPAppIconB64 = "",

	[Parameter(Mandatory = $false, HelpMessage = 'Text color used when rendering the generated app icon. Accepts named colors or #RRGGBB. Default is a high-visibility orange for better contrast.')]
	[string]$ARPAppIconTextColor = '#F6921E',

	[Parameter(Mandatory = $false, HelpMessage = 'Background mode used when rendering the generated app icon')]
	[ValidateSet('Transparent', 'White')]
	[string]$ARPAppIconBackground = 'Transparent',

	[Parameter(Mandatory = $false, HelpMessage = 'Create an All-Users Desktop shortcut (targets ARPAppUserStartFile when set, otherwise the deployed wrapper script)')]
	[bool]$ARPAppShortcutOnDesktop = $true,

	[Parameter(Mandatory = $false, HelpMessage = 'Create an All-Users Start Menu shortcut (targets ARPAppUserStartFile when set, otherwise the deployed wrapper script)')]
	[bool]$ARPAppShortcutInStart = $true,

	[Parameter(Mandatory = $false, HelpMessage = 'GUID of the application/script being wrapped. NOTE: This needs to be unique for each wrapped app')]
	[ValidatePattern('^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$')]
	[String]$ARPAppGuid = "{feedbeef-beef-4dad-beef-b628ccca16be}",

	[Parameter(Mandatory = $false, HelpMessage = "Application folder path, if not specified, it will use the native 64-bit %ProgramFiles%\ARPPublisher\ARPAppName (via %ProgramW6432% so a 32-bit host does not get redirected to 'Program Files (x86)'). Falls back to %ProgramFiles% on a 32-bit OS where ProgramW6432 is unset.")]
	[string]$ARPAppFolder = "$(if (${env:ProgramW6432}) { ${env:ProgramW6432} } else { $env:ProgramFiles })\$ARPAppPublisher\$ARPAppName",

	# ==========> Logging (Invoke-TboneLog) <==============================================================================
	[Parameter(Mandatory = $false, HelpMessage = 'Name of Log, to set name for Eventlog and Filelog')]
	[string]$LogName = "",

	[Parameter(Mandatory = $false, HelpMessage = 'Show output in console during execution')]
	[bool]$LogToGUI = $false,

	[Parameter(Mandatory = $false, HelpMessage = 'Write complete log array to Windows Event when script ends')]
	[bool]$LogToEventlog = $true,

	[Parameter(Mandatory = $false, HelpMessage = 'EventLog IDs as hashtable: @{Info=11001; Warn=11002; Error=11003}')]
	[hashtable]$LogEventIds = @{Info = 11001; Warn = 11002; Error = 11003 },

	[Parameter(Mandatory = $false, HelpMessage = 'Return complete log array as Host output when script ends (Good for Intune Remediations)')]
	[bool]$LogToHost = $false,

	[Parameter(Mandatory = $false, HelpMessage = 'Write complete log array to Disk when script ends')]
	[bool]$LogToDisk = $false,

	[Parameter(Mandatory = $false, HelpMessage = 'Path where Disk logs are saved (if LogToDisk is enabled)')]
	[string]$LogToDiskPath = "$env:TEMP",

	[Parameter(Mandatory = $false, HelpMessage = "Enable verbose logging. Default is false")]
	[bool]$LogVerboseEnabled = $true
)
#endregion

#region ---------------------------------------------------[Modifiable Parameters and defaults]------------------------------------
#IMPORTANT! When adding new Drivers make sure to also increment Version in $MappingVersion above
# Add Objects to Map here either Printers or Drives (Not Both) with the following syntax
# Printers:  $MapObjects += @{PrinterName="PrinterName"  ;Default=$true      ;Path="\\printserver\printerName"   ;ADGroups="My Group"}
# Drives:    $MapObjects += @{Letter="X"                 ;Persistent=$true   ;Path="\\fileserver\fileshare"      ;ADGroups="My Group"    ;Label="My drive"}
$MapObjects = @()
$MapObjects += @{PrinterName =	"Printer1"	; Default = $false	; Path =	"\\T-Bone-Print.tbone.se\Printer1"	; ADGroups =	"Sales" }
$MapObjects += @{PrinterName =	"Printer2"	; Default = $false	; Path =	"\\T-Bone-Print.tbone.se\Printer2"	; ADGroups =	"Consultant" }
$MapObjects += @{PrinterName =	"Printer3"	; Default = $true	; Path =	"\\T-Bone-Print.tbone.se\Printer3"	; ADGroups =	"" }

# Add your custom Icon in Base64 format to use for shortcut and add remove programs entry
$ARPAppCustomIconB64 = ""
#endregion

#region ---------------------------------------------------[Set global script settings]--------------------------------------------
# set strict mode to latest version
Set-StrictMode -Version Latest
# Save original preference states at script scope for restoration in finally block
[System.Management.Automation.ActionPreference]$script:OriginalErrorActionPreference = $ErrorActionPreference
[System.Management.Automation.ActionPreference]$script:OriginalVerbosePreference = $VerbosePreference
[bool]$script:OriginalWhatIfPreference = $WhatIfPreference
# Set verbose- and whatif- preference based on parameter instead of hardcoded values
if ($LogVerboseEnabled) { $VerbosePreference = 'Continue' }
else { $VerbosePreference = 'SilentlyContinue' }
#endregion

#region ---------------------------------------------------[Static Variables]------------------------------------------------------
# ==========> Requirements and defaults to run script (Get-Executioncontext) <=========================================
[version]$CTXReqPSVersion = $null
[string[]]$CTXReqIdentity = @()
[string]$CTXReqArchitecture = ""
[bool]$CTXAutoRelaunchToX64 = $true
[bool]$CTXAbortIfPendingReboot = $false
[int]$CTXReqOSBuild = 0
# ==========> Application settings for Add Remove Program (Add-AddRemoveProgram) <=====================================
# Determine object type from the first mapping object (Drive or Printer)
if (-not $MapObjects) { throw "MapObjects array is empty or not defined" }
$ObjectType =
if ($MapObjects[0].ContainsKey('Letter')) { 'Drive' }
elseif ($MapObjects[0].ContainsKey('PrinterName')) { 'Printer' }
else { throw "Unknown MapObject type: First object must contain 'Letter' or 'PrinterName' key" }
# Build the unique list of AD group names referenced in $MapObjects. Used to scope LDAP queries to only those groups
[string[]]$ADGRPRequiredGroups = @($MapObjects | ForEach-Object { $_['ADGroups'] } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
# Static ARP wrapper options for this script usage pattern
[version]$ARPAppVersion = $MappingVersion
[string]$ARPAppInstallScript = ""
[string]$ARPAppUnInstallScript = ""
[string]$ARPAppUserStartFile = ""
[bool]$ARPAppIncludeFolder = $false
[bool]$ARPAppForce = $false
# ==========> Settings for ScheduleTask Triggers (Register-NewScheduledTask) <=======================================
[string]$TaskPrincipalGroupSid = "S-1-5-32-545"    # Built-in Users group, used for scheduled task
[string]$TaskName = "Intune$($ObjectType)Mapping"
[string]$TaskDescription = "Map $($ObjectType) with script from Intune"
[string]$TaskLauncherPath = $(Join-Path -Path $ARPAppFolder -ChildPath "script-$ARPAppGuid\$($TaskName).js")
# JS launchers content used by wscript that hides the console window
[string]$TaskLauncherContent = @'
var shell = new ActiveXObject("WScript.Shell");
shell.Environment("Process")("MapperCTXSource") = "ScheduledTask";
var cmd = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File \"" + WScript.Arguments(0) + "\"";
shell.Run(cmd, 0, false);
'@
# General paths for the scheduled task and its associated scripts, version marker, and shortcut
[string]$APPScriptPath = $(Join-Path -Path $ARPAppFolder -ChildPath "script-$ARPAppGuid\$($TaskName).ps1")
[string]$APPVersionPath = $(Join-Path -Path $ARPAppFolder -ChildPath "script-$ARPAppGuid\$($TaskName).version")
[string]$APPShortcutPath = $(Join-Path -Path $ARPAppFolder -ChildPath "$($TaskName)-Run-$ARPAppGuid.js")
# JS launcher content used by user-facing shortcuts: silently sets MapperShowGUI in HKCU\Environment and triggers the scheduled task
[string]$APPShortcutContent = @"
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
# No modules or extensions needed for this script, but you can add them here if required in the future
#endregion

#region ---------------------------------------------------[Functions]------------------------------------------------------------
function Invoke-TboneLog {
	<#
.SYNOPSIS
	Unified tiny logger for PowerShell 5.1-7.5 and Azure Automation; overrides Write-* cmdlets and stores all messages in-memory
.DESCRIPTION
	A lightweight, cross-platform logging solution that intercepts all Write-Host, Write-Output, Write-Verbose, Write-Warning, and Write-Error calls.
    Stores messages in memory with timestamps and can optionally output to the console, write to disk, or write to the Windows Event Log at script completion.
.NOTES
	Author:  @MrTbone_se (T-bone Granheden)
	Version: 1.2.0

	Version History:
	1.0 - Initial version
	1.0.1 - Fixed event log source creation for first-time runs
	1.1.0 - Added parameter logName and logEventIds to customize event log source and file log name
	1.2.0 - Added LogVerboseEnabled parameter to capture or hide verbose messages
#>
	[CmdletBinding()]
	param(
		[Parameter(HelpMessage = 'Start=Begin logging, Stop=End and output log array')]
		[ValidateSet('Start', 'Stop')]
		[string]$LogMode,
		[Parameter(HelpMessage = 'Name of Log, to set name for Eventlog and Filelog')]
		[string]$LogName = "PowerShellScript",
		[Parameter(HelpMessage = 'Show output in console during execution')]
		[bool]$LogToGUI = $true,
		[Parameter(HelpMessage = 'Write complete log array to Windows Eventlog when script ends')]
		[bool]$LogToEventlog = $true,
		[Parameter(HelpMessage = 'EventLog IDs as hashtable: @{Info=11001; Warn=11002; Error=11003}')]
		[hashtable]$LogEventIds = @{Info = 11001; Warn = 11002; Error = 11003 },
		[Parameter(HelpMessage = 'Return complete log array as Host output when script ends (Good for Intune Remediations)')]
		[bool]$LogToHost = $True,
		[Parameter(HelpMessage = 'Write complete log array to filelog on disk when script ends')]
		[bool]$LogToDisk = $true,
		[Parameter(HelpMessage = 'Path where Disk logs are saved (if LogToDisk is enabled)')]
		[string]$LogPath = "$env:TEMP",
		[Parameter(HelpMessage = 'Capture and emit verbose messages')]
		[bool]$LogVerboseEnabled = $false
	)
	# Auto-detect mode: if logger functions is already loaded in memory and no mode specified, assume Stop
	if (!$LogMode) { $LogMode = if (Get-Variable -Name _l -Scope Global -EA 0) { 'Stop' }else { 'Start' } }
	if (!$LogPath) { $LogPath = if ($global:_p) { $global:_p }elseif ($env:TEMP) { $env:TEMP }else { '/tmp' } }
	# Stop mode: Save logs and cleanup
	if ($LogMode -eq 'Stop') {
		if ((Get-Variable -Name _l -Scope Global -EA 0) -and (Test-Path function:\global:_Save)) { _Save; if ($global:_r) { , $global:_l.ToArray() } }
		Unregister-Event -SourceIdentifier PowerShell.Exiting -ea 0 -WhatIf:$false
		if (Test-Path function:\global:_Clean) { _Clean }
		return
	}
	# Start mode: Initialize logging and proxy all Write-* functions
	if ($LogMode -eq 'Start') {
		# Create helper functions and variables
		$global:_az = $env:AZUREPS_HOST_ENVIRONMENT -or $env:AUTOMATION_ASSET_ACCOUNTID # Detect Azure Automation environment
		$global:_l = [Collections.Generic.List[string]]::new(); $global:_g = $LogToGUI; $global:_s = $Logname; $global:_n = "{0}-{1:yyyyMMdd-HHmmss}" -f $Logname, (Get-Date); $global:_p = $LogPath; $global:_d = $LogToDisk; $global:_e = $LogToEventlog; $global:_i = $LogEventIds; $global:_r = $LogToHost; $global:_v = $LogVerboseEnabled; $global:_w = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
		if (!(Test-Path function:\global:_Time)) { function global:_Time { Get-Date -f 'yyyy-MM-dd,HH:mm:ss' } }
		if (!(Test-Path function:\global:_ID)) { function global:_ID { $c = (Get-PSCallStack)[2]; $n = if ($c.Command -and $c.Command -ne '<ScriptBlock>') { $c.Command }elseif ($c.FunctionName -and $c.FunctionName -ne '<ScriptBlock>') { $c.FunctionName }else { 'Main-Script' }; if ($n -like '*.ps1') { 'Main-Script' }else { $n } } }
		if (!(Test-Path function:\global:_Save)) { function global:_Save { try { if ($global:_d) { [IO.Directory]::CreateDirectory($global:_p) | Out-Null; [IO.File]::WriteAllLines((Join-Path $global:_p "$($global:_n).log"), $global:_l.ToArray()) }; if ($global:_e -and $global:_w) { $isAdmin = $false; try { $id = [Security.Principal.WindowsIdentity]::GetCurrent(); $isAdmin = ([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) }catch {}; $la = $global:_l -join "`n"; $h = $la -match ',ERROR,'; $w = $la -match ',WARN,'; $eid = if ($h) { $global:_i.Error }elseif ($w) { $global:_i.Warn }else { $global:_i.Info }; $et = if ($h) { 'Error' }elseif ($w) { 'Warning' }else { 'Information' }; $ok = $false; try { Write-EventLog -LogName Application -Source $global:_s -EventId $eid -EntryType $et -Message $la -EA Stop; $ok = $true }catch {}; if (-not $ok -and $isAdmin) { try { [Diagnostics.EventLog]::CreateEventSource($global:_s, 'Application') }catch {}; try { Write-EventLog -LogName Application -Source $global:_s -EventId $eid -EntryType $et -Message $la }catch {} } } }catch {} } }
		if (!(Test-Path function:\global:_Clean)) { function global:_Clean { $WhatIfPreference = $false; Remove-Item -Path function:\Write-Host, function:\Write-Output, function:\Write-Warning, function:\Write-Error, function:\Write-Verbose, function:\_Save, function:\_Clean, function:\_ID, function:\_Time -ea 0 -Force; Remove-Variable -Name _l, _g, _s, _n, _p, _d, _e, _i, _r, _v, _w, _az -Scope Global -ea 0 } }
		# Register exit handler FIRST (before Write-* overrides)
		$null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action { if ($global:_l) { try { _Save }catch {} }; if (Test-Path function:\_Clean) { _Clean } } -MaxTriggerCount 1
		# Create Write-* proxy functions (skip in Azure Automation)
		function Script:Write-Host { $m = "$args"; $c = (Get-PSCallStack)[1]; $r = "Row$($c.ScriptLineNumber)"; $e = "$(_Time),INFO,$r,$(_ID),$m"; $global:_l.Add($e); if ($global:_g) { if ($global:_az) { Microsoft.PowerShell.Utility\Write-Output $m }else { Microsoft.PowerShell.Utility\Write-Host $e -ForegroundColor Green } } }
		function Script:Write-Output { $m = "$args"; $c = (Get-PSCallStack)[1]; $r = "Row$($c.ScriptLineNumber)"; $e = "$(_Time),OUTPUT,$r,$(_ID),$m"; $global:_l.Add($e); if ($global:_g) { if ($global:_az) { Microsoft.PowerShell.Utility\Write-Output $m }else { Microsoft.PowerShell.Utility\Write-Host $e -ForegroundColor Green } } }
		function Script:Write-Verbose { if (-not $global:_v) { return }; $m = "$args"; $c = (Get-PSCallStack)[1]; $r = "Row$($c.ScriptLineNumber)"; $e = "$(_Time),VERBOSE,$r,$(_ID),$m"; $global:_l.Add($e); if ($global:_g -and $VerbosePreference -ne 'SilentlyContinue') { if ($global:_az) { Microsoft.PowerShell.Utility\Write-Verbose $m }else { Microsoft.PowerShell.Utility\Write-Host $e -ForegroundColor cyan } } }
		function Script:Write-Warning { $m = "$args"; $c = (Get-PSCallStack)[1]; $r = "Row$($c.ScriptLineNumber)"; $e = "$(_Time),WARN,$r,$(_ID),$m"; $global:_l.Add($e); if ($global:_g) { if ($global:_az) { Microsoft.PowerShell.Utility\Write-Warning $m }else { Microsoft.PowerShell.Utility\Write-Host $e -ForegroundColor Yellow } }; if ($WarningPreference -eq 'Stop') { _Save; _Clean; exit } }
		function Script:Write-Error { $m = "$args"; $c = (Get-PSCallStack)[1]; $r = "Row$($c.ScriptLineNumber)"; $e = "$(_Time),ERROR,$r,$(_ID),$m"; $global:_l.Add($e); if ($global:_g) { if ($global:_az) { Microsoft.PowerShell.Utility\Write-Error $m }else { Microsoft.PowerShell.Utility\Write-Host $e -ForegroundColor Red } }; if ($ErrorActionPreference -eq 'Stop') { _Save; _Clean; exit } }
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
	Author:  @MrTbone_se (T-bone Granheden)
	Version: 1.1.0

	Version History:
	1.0 - Initial version
	1.0.1 - Fixed some edge cases in detection logic
	1.1.0 - Added requirements parameters and validation logic, and auto-relaunch to x64 if required and running x86
#>
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(HelpMessage = 'Required execution identity. Valid: System, LocalService, NetworkService, ServiceAccount, Admin, User')]
		[ValidateSet('System', 'LocalService', 'NetworkService', 'ServiceAccount', 'Admin', 'User')]
		[string[]]$CTXReqIdentity = @(),

		[Parameter(HelpMessage = 'Required process architecture. Valid: x64, x86 (empty = no requirement)')]
		[ValidateSet('x64', 'x86', '')]
		[string]$CTXReqArchitecture = '',

		[Parameter(HelpMessage = 'Required execution mode (any value returned in CTXMode).')]
		[string[]]$CTXReqMode = @(),

		[Parameter(HelpMessage = 'Minimum required PowerShell version (e.g. 5.1). Fails if PSVersionTable.PSVersion is lower.')]
		[version]$CTXReqPSVersion = $null,

		[Parameter(HelpMessage = 'Minimum required OS build number (e.g. 19041 for Win10 2004). Fails if OS build is lower.')]
		[int]$CTXReqOSBuild = 0,

		[Parameter(HelpMessage = 'If set, abort when a reboot is pending (CBS, Windows Update, or file rename pending).')]
		[switch]$CTXAbortIfPendingReboot,

		[Parameter(HelpMessage = 'If set and process is x86 while x64 is required, relaunch via SysNative.')]
		[switch]$CTXAutoRelaunchToX64,

		[Parameter(HelpMessage = 'Caller bound parameters to forward on relaunch (pass $PSBoundParameters from the caller).')]
		[hashtable]$CTXForwardParameters = @{}
	)
	Write-Verbose "-- START Function $($MyInvocation.MyCommand.Name) --"
	Write-Host "===== ENUMERATING Execution Context ====="
	# Initialize variables
	[string]$CTXMode = 'Standalone'
	[string]$CTXPath = 'Other'
	[string]$CTXSource = 'Managed'
	[string]$CTXIdentity = 'User'
	[string]$scriptPath = $script:PSCommandPath
	[string]$scriptRoot = $script:PSScriptRoot
	# PS5.1 Desktop is always Windows; PS6+ exposes $IsWindows
	[bool]$isWin = ($PSVersionTable.PSEdition -eq 'Desktop') -or $IsWindows

	# Helper: walk parent processes from $PID up to 8 levels using a PID->Win32_Process hashtable
	$getAncestors = {
		param([hashtable]$Table)
		$list = [System.Collections.Generic.List[int]]::new()
		$cur = $PID
		while ($list.Count -lt 8 -and $Table.ContainsKey($cur)) {
			$parent = [int]$Table[$cur].ParentProcessId
			if ($parent -eq 0 -or $parent -eq $cur) { break }
			$list.Add($parent)
			$cur = $parent
		}
		, $list
	}

	# ---- Execution Mode detection -------------------------------------------------------------------------------------------------------------------------------------------------------------------
	# Cross-platform managed-host signals first (env vars and PSPrivateMetadata work on every platform)
	if ((Test-Path variable:PSPrivateMetadata) -and $PSPrivateMetadata.JobId) { $CTXMode = 'AzureAutomation' }
	elseif ($env:FUNCTIONS_WORKER_RUNTIME -or $env:AZURE_FUNCTIONS_ENVIRONMENT) { $CTXMode = 'AzureFunction' }
	elseif ($env:GITHUB_ACTIONS -eq 'true') { $CTXMode = 'GitHubActions' }
	elseif ($env:GITLAB_CI -eq 'true') { $CTXMode = 'GitLabCI' }
	elseif ($env:TF_BUILD -eq 'True') { $CTXMode = 'AzureDevOps' }
	elseif ($env:_SMSTSType -or $env:_SMSTSPackageID -or $env:SMSTSLogPath) { $CTXMode = 'TaskSequence' }
	if ($CTXMode -eq 'Standalone' -and $isWin) {
		try { if (Test-Path 'HKLM:\SYSTEM\ControlSet001\Control\MiniNT' -ErrorAction Stop) { $CTXMode = 'WinPE' } } catch {}
	}
	Write-Verbose "Enumerated CTXMode = $CTXMode after environment variable check"

	# If still standalone, get execution mode from script path (Remediation, Detection, PlatformScript, Intunewin, TaskSequence, SCCM)
	if ($CTXMode -eq 'Standalone' -and $scriptPath) {
		if ($scriptPath -match 'IMECache\\HealthScripts\\.*\\remediate\.ps1$') { $CTXMode = 'Remediation' }
		elseif ($scriptPath -match 'IMECache\\HealthScripts\\.*\\detect\.ps1$') { $CTXMode = 'Detection' }
		elseif ($scriptPath -match 'IMECache\\Scripts\\') { $CTXMode = 'PlatformScript' }
		elseif ($scriptPath -match 'Microsoft Intune Management Extension\\Content\\') { $CTXMode = 'Intunewin' }
		elseif ($scriptPath -match '_SMSTaskSequence\\') { $CTXMode = 'TaskSequence' }
		elseif ($scriptPath -match '\\ccmcache\\') { $CTXMode = 'SCCM' }
	}
	Write-Verbose "Enumerated CTXMode = $CTXMode after script path check"

	# If still standalone, walk parent processes via CIM (Windows-only) to detect Intunewin / GPO / SCCM / TaskSequence
	[hashtable]$procTable = @{}
	[System.Collections.Generic.List[int]]$ancestorPids = [System.Collections.Generic.List[int]]::new()
	if ($CTXMode -eq 'Standalone' -and $isWin) {
		try {
			Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId, Name -ErrorAction Stop -Verbose:$false |
			ForEach-Object { $procTable[[int]$_.ProcessId] = $_ }
		}
		catch { Write-Verbose "Failed to build process table with CIM: $_" }
		if ($procTable.Count -gt 0) {
			$ancestorPids = & $getAncestors $procTable
			foreach ($aPid in $ancestorPids) {
				if (-not $procTable.ContainsKey($aPid)) { continue }
				$procName = $procTable[$aPid].Name
				if ($procName -in 'AgentExecutor.exe', 'IntuneManagementExtension.exe') { $CTXMode = 'Intunewin'; break }
				elseif ($procName -eq 'gpscript.exe') { $CTXMode = 'GPO'; break }
				elseif ($procName -in 'CcmExec.exe', 'ccmsetup.exe') { $CTXMode = 'SCCM'; break }
				elseif ($procName -in 'TSManager.exe', 'smstsbootstrap.exe') { $CTXMode = 'TaskSequence'; break }
			}
		}
	}
	Write-Verbose "Enumerated CTXMode = $CTXMode after CIM process detection"

	# ---- Execution path detection -------------------------------------------------------------------------------------------------------------------------------------------------------------------
	if ($scriptRoot) {
		$root = $scriptRoot.TrimEnd('\')
		$sc = [StringComparison]::OrdinalIgnoreCase
		if ($env:ProgramFiles -and $root.StartsWith($env:ProgramFiles.TrimEnd('\'), $sc)) { $CTXPath = 'ProgramFiles' }
		elseif (${env:ProgramFiles(x86)} -and $root.StartsWith(${env:ProgramFiles(x86)}.TrimEnd('\') + '\Microsoft Intune Management Extension', $sc)) { $CTXPath = 'IMEContent' }
		elseif (${env:ProgramFiles(x86)} -and $root.StartsWith(${env:ProgramFiles(x86)}.TrimEnd('\'), $sc)) { $CTXPath = 'ProgramFilesX86' }
		elseif ($env:ProgramData -and $root.StartsWith($env:ProgramData.TrimEnd('\'), $sc)) { $CTXPath = 'ProgramData' }
		elseif ($env:APPDATA -and $root.StartsWith($env:APPDATA.TrimEnd('\'), $sc)) { $CTXPath = 'AppDataRoaming' }
		elseif ($env:LOCALAPPDATA -and $root.StartsWith($env:LOCALAPPDATA.TrimEnd('\'), $sc)) { $CTXPath = 'AppDataLocal' }
		elseif ($env:SystemRoot -and $root.StartsWith($env:SystemRoot.TrimEnd('\') + '\IMECache', $sc)) { $CTXPath = 'IMECache' }
		elseif ($env:SystemRoot -and $root.StartsWith($env:SystemRoot.TrimEnd('\') + '\ccmcache', $sc)) { $CTXPath = 'CCMCache' }
		elseif ($env:SystemRoot -and $root.StartsWith($env:SystemRoot.TrimEnd('\'), $sc)) { $CTXPath = 'SystemRoot' }
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
					$parentName = if ($ancestorPids.Count -gt 0 -and $procTable.ContainsKey($ancestorPids[0])) { $procTable[$ancestorPids[0]].Name } else { '' }
					$svchostPid = $ancestorPids | Where-Object { $procTable.ContainsKey($_) -and $procTable[$_].Name -eq 'svchost.exe' } | Select-Object -First 1
					$svcNames = if ($svchostPid) { @(Get-CimInstance Win32_Service -Filter "ProcessId=$svchostPid" -Property Name -ErrorAction SilentlyContinue | ForEach-Object Name) } else { @() }
					if ($svcNames -contains 'Schedule') { $CTXSource = 'ScheduledTask' }
					elseif ($parentName -eq 'wsmprovhost.exe') { $CTXSource = 'RemoteSession' }
					elseif ($Host.Name -eq 'Visual Studio Code Host' -or [bool]($ancestorNames -match '^Code( - Insiders)?\.exe$')) { $CTXSource = 'VSCodeDebug' }
					elseif ($Host.Name -eq 'Windows PowerShell ISE Host') { $CTXSource = 'ISE' }
					elseif ($parentName -eq 'explorer.exe') { $CTXSource = 'Explorer' }
					elseif ($parentName -eq 'cmd.exe') { $CTXSource = 'Batch' }
					elseif ($parentName -in 'powershell.exe', 'pwsh.exe') { $CTXSource = 'Interactive' }
				}
   }
			catch { $CTXSource = 'Manual' }
		}
	}
	Write-Verbose "Enumerated CTXSource = $CTXSource after source detection"

	# ---- Identity detection (Windows-only; WindowsIdentity throws on Linux/macOS pwsh) --------------------------------------------------------------------------------------------------------------
	if ($isWin) {
		try {
			$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
			$principal = [System.Security.Principal.WindowsPrincipal]$currentIdentity
			if ($currentIdentity.IsSystem) { $CTXIdentity = 'System' }
			elseif ($currentIdentity.User.Value -eq 'S-1-5-19') { $CTXIdentity = 'LocalService' }
			elseif ($currentIdentity.User.Value -eq 'S-1-5-20') { $CTXIdentity = 'NetworkService' }
			elseif ($currentIdentity.Name -like 'NT SERVICE\*' -or $currentIdentity.Name -like 'NT AUTHORITY\*') { $CTXIdentity = 'ServiceAccount' }
			elseif ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) { $CTXIdentity = 'Admin' }
			else { $CTXIdentity = 'User' }
		}
		catch { Write-Verbose "Failed to detect CTXIdentity, defaulting to 'User'. Error: $_" }
	}
	Write-Verbose "Enumerated CTXIdentity = $CTXIdentity after identity detection"

	# ---- Architecture / PS version / OS build / pending reboot --------------------------------------------------------------------------------------------------------------------------------------
	[string]$CTXArchitecture = if ([Environment]::Is64BitProcess) { 'x64' } else { 'x86' }
	[version]$CTXPSVersion = $PSVersionTable.PSVersion
	[int]$CTXOSBuild = if ($isWin) { [Environment]::OSVersion.Version.Build } else { 0 }
	[bool]$CTXPendingReboot = $false
	if ($isWin) {
		try {
			if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $CTXPendingReboot = $true }
			elseif (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $CTXPendingReboot = $true }
			else {
				$pfro = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
				if ($pfro -and $pfro.PendingFileRenameOperations) { $CTXPendingReboot = $true }
			}
		}
		catch { Write-Verbose "Failed to detect pending reboot state. Error: $_" }
	}
	# GUI availability: $true = GUI cannot be shown (non-Windows or non-interactive session)
	[bool]$CTXNoGUISupport = (-not [System.Environment]::UserInteractive) -or ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows)

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
		CTXNoGUISupport  = $CTXNoGUISupport
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
			# Pick an x64 host that matches the CURRENT PowerShell edition and relaunch the caller script with the same parameters
			[string]$x64Host = ''
			if ($PSVersionTable.PSEdition -eq 'Core') {
				$pwshRoot = Join-Path $env:ProgramW6432 'PowerShell'
				if (Test-Path -LiteralPath $pwshRoot) {
					$x64Host = Get-ChildItem -LiteralPath $pwshRoot -Filter 'pwsh.exe' -Recurse -ErrorAction SilentlyContinue |
					Where-Object { $_.FullName -notmatch '-preview' } |
					Sort-Object FullName -Descending |
					Select-Object -First 1 -ExpandProperty FullName
				}
			}
			if (-not $x64Host) {
				$x64Host = "$env:SystemRoot\SysNative\WindowsPowerShell\v1.0\powershell.exe"
			}
			if (-not $callerScript -or -not (Test-Path -LiteralPath $callerScript)) {
				Write-Error "CTXAutoRelaunchToX64 requires a file-based script (caller path '$callerScript' not resolvable). Architecture requirement failed."
				return $null
			}
			if (-not (Test-Path -LiteralPath $x64Host)) {
				Write-Error "CTXAutoRelaunchToX64 failed: x64 host '$x64Host' not found. Architecture requirement failed."
				return $null
			}
			# Build a single -Command line that re-invokes the caller script with forwarded parameters
			[string]$cmdLine = "& '" + ($callerScript -replace "'", "''") + "'"
			foreach ($k in $CTXForwardParameters.Keys) {
				$v = $CTXForwardParameters[$k]
				if ($v -is [switch]) { if ($v.IsPresent) { $cmdLine += " -$k" } }
				elseif ($v -is [bool]) { $cmdLine += " -${k}:`$$($v.ToString().ToLower())" }
				elseif ($v -is [array]) { $cmdLine += " -$k '" + (($v | ForEach-Object { $_ -replace "'", "''" }) -join "','") + "'" }
				else { $cmdLine += " -$k '" + ($v.ToString() -replace "'", "''") + "'" }
			}
			Write-Warning "Process is x86; relaunching as x64: $x64Host"
			$proc = Start-Process -FilePath $x64Host -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $cmdLine) -Wait -NoNewWindow -PassThru
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
	Write-Verbose "-- END Function $($MyInvocation.MyCommand.Name) --"
	$CTXSummary = ($CTX.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ', '
	Write-Verbose "Results: $CTXSummary"
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
		Version: 1.10.0

		Version History:
		1.0 - Initial version
		1.0.1 - Changed parameter names end improved error handling
		1.1.0 - Major refactor to support more features, better logging and error handling, and to be more modular and maintainable. Added parameters for shortcuts and folder copying.
		1.2.0 - Added icon handling improvements and adding program name to the icon for better UX in ARP and shortcuts.
		1.3.0 - De-duplicated registry writes via a local SetRegistryValues helper (identical behavior, messages and -WhatIf support; PS5.1-7.x).
		1.4.0 - Renamed ARPAppEnableUninstall/ARPAppEnableModify to ARPAppHideUninstall/ARPAppHideModify and inverted the registry flag logic.
		1.5.0 - De-duplicated script-copy and shortcut creation into local helpers (identical behavior, messages and -WhatIf support; PS5.1-7.x).
		1.6.0 - De-duplicated registry-key creation (EnsureRegistryKey) and uninstall/modify batch creation (SaveBatchFile) into local helpers (same behavior and -WhatIf support; PS5.1-7.x).
		1.7.0 - Rearchitected AppIcon generation into three focused helpers (ConvertBase64ToBitmap / NewCaptionedIcon / SaveIcoFile); same rendered icon and multi-size DIB .ico output, less code, PS5.1-7.x.
		1.8.0 - HKCR Installer\Products subtree now written in a single reg.exe import instead of per-key New-Item on the HKCR provider (each ~2s because the Windows Installer service reacts per key); removes the unused HKCR PSDrive and cuts install time by ~8s. Same keys, value names, types and data.
		1.9.0 - Aligned the HKLM Uninstall/Modify key into the same single reg.exe import as the HKCR subtree (one transaction for the whole ARP footprint); retired the EnsureRegistryKey/SetRegistryValues helpers. Same keys, value names, types and data.
		1.10.0 - Code hygiene: moved local helper scriptblocks into Begin, standardized object creation on ::new(), disposed per-frame icon MemoryStreams in SaveIcoFile, and hardened ARPAppUserStartFile against single-quote injection in the Repair command line. No functional change.
	#>
	[CmdletBinding(SupportsShouldProcess = $true)]
	Param(
		[Parameter(Mandatory = $false, HelpMessage = 'Name of the application/script being wrapped')]
		[String]$ARPAppName = "App Name",

		[Parameter(Mandatory = $false, HelpMessage = 'Version of the application. Increment when changing config')]
		[ValidatePattern("^\d+\.\d+\.\d+$")]
		[version]$ARPAppVersion = "1.0.0",

		[Parameter(Mandatory = $false, HelpMessage = 'GUID of the application/script being wrapped. NOTE: This needs to be unique for each wrapped app')]
		[ValidatePattern('^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$')]
		[String]$ARPAppGuid = "{feedbeef-beef-4dad-beef-b628ccca16e0}",

		[Parameter(Mandatory = $false, HelpMessage = 'Company name used for naming of folders and registry keys')]
		[String]$ARPAppPublisher = "Coligo",

		[Parameter(Mandatory = $false, HelpMessage = "Application folder path, if not specified, it will use %ProgramFiles%\ARPPublisher\ARPAppName ")]
		[string]$ARPAppFolder = "$Env:Programfiles\$ARPAppPublisher\$ARPAppName",

		[Parameter(Mandatory = $false, HelpMessage = 'Hide the uninstall option in Add Remove Programs')]
		[bool]$ARPAppHideUninstall = $False,

		[Parameter(Mandatory = $false, HelpMessage = 'Hide the modify option in Add Remove Programs (typically for repair/reinstall)')]
		[bool]$ARPAppHideModify = $False,

		[Parameter(Mandatory = $false, HelpMessage = 'Hide the app from Add Remove Programs (SystemComponent) while still writing the registry and files for detection')]
		[bool]$ARPAppHidden = $False,

		[Parameter(Mandatory = $false, HelpMessage = 'Optional Base64-encoded .ico content to use as the icon of the app')]
		[string]$ARPAppIconB64 = "",

		[Parameter(Mandatory = $false, HelpMessage = 'Text color used when rendering the generated app icon. Accepts named colors or #RRGGBB.')]
		[string]$ARPAppIconTextColor = '#F6921E',

		[Parameter(Mandatory = $false, HelpMessage = 'Background mode used when rendering the generated app icon')]
		[ValidateSet('Transparent', 'White')]
		[string]$ARPAppIconBackground = 'Transparent',

		[Parameter(Mandatory = $false, HelpMessage = 'Optional fallback Base64-encoded .ico content to use when ARPAppIconPath and ARPAppIconB64 are not provided')]
		[string]$ARPAppCustomIconB64 = "",

		[Parameter(Mandatory = $false, HelpMessage = 'Optional path to a .ps1 file to use as the installer script')]
		[string]$ARPAppInstallScript = "",

		[Parameter(Mandatory = $false, HelpMessage = 'Optional path to a .ps1 file to use as the uninstaller script')]
		[string]$ARPAppUnInstallScript = "",

		[Parameter(Mandatory = $false, HelpMessage = 'Optional path to a .ico file to use as the icon of the app')]
		[string]$ARPAppIconPath = "",

		[Parameter(Mandatory = $false, HelpMessage = 'If $true, copy every file in the wrapper''s source folder into the app folder (excluding the wrapper itself, the install/uninstall scripts and the icon, which are deployed under standardized names).')]
		[bool]$ARPAppIncludeFolder = $false,

		[Parameter(Mandatory = $false, HelpMessage = 'Optional name of a companion file inside the app folder to launch (t-bone.exe). If blank, shortcuts default to launching the deployed wrapper script.')]
		[string]$ARPAppUserStartFile = "",

		[Parameter(Mandatory = $false, HelpMessage = 'Create an All-Users Desktop shortcut (targets ARPAppUserStartFile when set, otherwise the deployed wrapper script)')]
		[bool]$ARPAppShortcutOnDesktop = $false,

		[Parameter(Mandatory = $false, HelpMessage = 'Create an All-Users Start Menu shortcut (targets ARPAppUserStartFile when set, otherwise the deployed wrapper script)')]
		[bool]$ARPAppShortcutInStart = $false,

		[Parameter(Mandatory = $false, HelpMessage = 'Force the action to reregister the application in ARP even if it is already present. This can be useful to update the icon or other metadata.')]
		[bool]$ARPAppForce = $False
	)
	Begin {
		$ErrorActionPreference = 'Stop'
		Write-Verbose "-- START Function $($MyInvocation.MyCommand.Name) --"
		$Utf8BomEncoding = [System.Text.UTF8Encoding]::new($true)
		# Ensure System.Drawing is loaded - it is not auto-loaded in SYSTEM / headless / PS7 sessions
		try { Add-Type -AssemblyName 'System.Drawing' -ErrorAction Stop }
		catch { Write-Warning "Failed to load System.Drawing assembly. Icon generation will be skipped. Error: $_" }
		# ARP app icon settings (used for dynamic icon generation when Base64 or file path is provided, or as defaults for the demo icon)
		$ARPAppIcoHorizontal = 0	# 0 = center
		$ARPAppIcoVertical = 0	# 0 = center
		$ARPAppIcoRotation = 0	# degrees
		$ARPAppIcoFontSize = 0	# 0 = auto-fit
		$ARPAppIcoFontFamily = 'Segoe UI Semibold'
		$ARPAppIcoFontWeight = [System.Drawing.FontStyle]::Regular  # Use the Semibold face directly; avoid synthetic extra-bold styling
		try {
			if ($ARPAppIconTextColor -match '^#[0-9a-fA-F]{6}$') {
				$ARPAppIcoColor = [System.Drawing.ColorTranslator]::FromHtml($ARPAppIconTextColor)
			}
			else {
				$ARPAppIcoColor = [System.Drawing.Color]::FromName($ARPAppIconTextColor)
				if (-not $ARPAppIcoColor.IsKnownColor -and -not $ARPAppIcoColor.IsNamedColor -and $ARPAppIcoColor.ToArgb() -eq 0) {
					throw "Unknown color '$ARPAppIconTextColor'"
				}
			}
		}
		catch {
			Write-Warning "Invalid ARPAppIconTextColor '$ARPAppIconTextColor'. Falling back to #F6921E. Error: $_"
			$ARPAppIcoColor = [System.Drawing.ColorTranslator]::FromHtml('#F6921E')
		}
		$ARPAppIcoOutlineColor = [System.Drawing.Color]::FromArgb(220, 24, 24, 24)
		$ARPAppIcoSize = 256
		# Default Mr T-Bone demo app icon, used when no icon path or Base64 is provided
		$ARPAppDefaultIconBase64 = "iVBORw0KGgoAAAANSUhEUgAAAGAAAABgCAMAAADVRocKAAABF1BMVEVPMyg9Jh0yIBkoHhkmHRg1IxxuPi07JBtJLSNmLBd
		XLSItIRtJIxk2Ix0nGhaFRCukWCZqOCloNiZaMyhXJxhjNyeISzWtck0gFA9ILCV9UDw4KiVxLxdpWk+He2+UiX2lmo1VIxKScGCzqp29tKjVzsPj29Ds5dvx6d7
		08OhWHAo4FQoxEQmWjoPb1MnMxLespJjl3tM2GxRXUEi2rqJ4cWdvZlw1LyqMhHmln5d+eG9KOTBNRDzTyr0YEg4oIh0bFA8bFxN3cmm2UQTJWQeQNAPXZwb8iAv
		/pCzpbwSpPAB3OyeSW0V4RTR4QS+SUzllLBuEPSSvh2zMl2pFHROck4hHGwzEu64XCQUpEgwlDQcKBAP6eAH1a2l7AAAAS3RSTlMAFk+QsdGsLqDc/mz+/f7++Pv
		+/v5p/v7O/tL+/v7+/v759P7+/v3+/v7+/vb9/v7+/v7+/v38+/7bqPv+/v795v7S/v7+/v7+/v1UtKsPAAAKbklEQVR42uyQxYHDMBBFzSA0zGrC1I5YSf+tBEo
		I3Nbv/jH7ZywsLOR5/nPLoqzq5mXbdnXfk76mv8xoO8aF4Nq0WS4Hra0brZe/SshpNU0zkJmBNH8VSP9EIWLxk+7liq/Xa5gg+Bh9QASZEFO6ot/k31xOy6oru5q
		Q9Xa7vU06uLjzfhde1RNe8Znm+4/ta+nH9Zo83RmbCQGl5C6qXdw5Pe7Ti8PxeDJ+02YfUcA5kKf/PM+3eQzOaaeDvTw4LxPuRJEviruOOUjKgXD8x1YMNqARWkD
		2GbGQNuoYoqHPkd3v/zn+D2ffl8q+vV+9uvc+KmOOF8TpbPY8/37FvX7/vxGakvwpSZLJJHwLw7D3JXz7uBCU2fyX6/l5zr336eg/6ZAwo2jEMKNeL+xJo95brM5
		uJWfwUi34fDabzbnRiWZa/0GB5uUS0TQdRWEYjSJWE6HacrmE4nA88LIUlSl8NdeiiGGYzs/x/ocC6OSQpE50xNCn/plChjlToOBSSWNLmFUU2zEM1rYWLmzhHLV
		vbu7efbC++ebbxj+of9HRcPBA0ICAPuRs9aQoisqPjSG6t24AK89zXdfRKowYeIV0tzxOmSvCer789u/qt3RZh6FAksTpxDBnsshWY5WzvHucZdnKUuCE5lpWZrC
		KSQ/KR1G93nbS55mywr49m9/9zf6RrucI6QRDUdGEIQAwNDwfQ/myLH1WrcQVUAUomLe3Xp+WJvUmQvF0mjol9uO58NfGbaOczIscDRiKBgmJpMj0+++rw0IGD4B
		ncSXrslTNpFHvPaI7TYTRYpm2N1lgzcTmHw0coN4s0B1iNLzPC+iAYSYMTTHF96Vhw3lW5kY8A/tM2QROptd/60FIekynvskyayp0mziwFPGrX1uyOpZHVvv8fWP
		kABU6yuWcrMrTJ4qUC6itk4NBAV0U3ni5hB4+JvTb2/uX0Zd3COKkXusEwXiqdbs4cKfq3S/23Wl5nztdx52Z6uebwgSpo0KW5VyvVKYpmiFJEgY1QV7I/HuVq0A
		swnfaG388naGDiKrX6ggqc41u4MdTrQlbbn24q9cfDdN2xLmB2ZmZGVoHiAMdABUhB6eSBIQNhI5o0AIYOvQyYFUAPPOnMDPUmSKmphazjVoHocU0bjQDJxXtRq3
		paEvl48YQ56kwU42SmxqlwTWgARIA4KJclotiCE08nOiqPkVRDENeijK7N8zldPmcnpPSE76fHPOPTfCeHytuo40txW3Xuv5iaq9S2zXF5cJaO0gV/HK8AEAbACT
		Uzwt4wxjdE2cAUEAIGWlCwBnpRjxVpjOFlUsvhYCLa9U83VUATbEfsSGM/U4drRQOlQsXewqPDdVZiYsy0FiQu3mv6wwJScuzHKphhC4MHZ5COqpeCD3Lcm98Gxt
		2AXJYNmsYnvNQAYa86HquyAWdWjOwljYu3afSW1vlWAhYxS4tvlWZ9B7JJHMBCbKigFc01KkTFUFxKTxTELqyWNlrGBwzt8gQqlotIM9wKMjhVT6OuVS4q7cDXvU
		C7HIlu4bz17C1Zm3T6FR+rRxKkpAiDH+JiyxAA9h/yJzPpxPFDPIyW7GpCAAuL8vvw5cPkmYFMAUDB0NLFT9gR9WcAC/i0kodbC6wm3Kx1735Fjx6YUhZvuQFvkW
		ruCdh4JF0eKZp5nuVNVEUlwKZVT/PddjPpFPrBo5gGhhjJ1bNwFi7LQC4pWsGfjrGrmBsmo9GhWjpOYiQJBdoHjSo1JYhBqPtC2SWYvQy072n9VpUVCq5XAjqgXx
		4YCBozcATzA/dIEN2mnqsajWDgLMyjoNuLGzx7cYGx3e3FmBT5CVJZLlCFLjY7SP6sjt8t/vSO4PKJaisqmtRZKUJwxDMw+mBvqsBwBD4Va2F4aPA2qrdDHyexfx
		TaaRWudK+eixtt3EbpnmQg8iwPRkExJl0/O5rUn45HL7Aw21yySqVUyAo45BmQoagKIJuAAAMqq1qXQCYvGGrLEROWPnCuDT42DEszrG09g+P+6KQATCZyDcv7Y6
		HrTy6Hg47eHZKSVZClnkgKIv+WxSdTieaIKqEYsOM27VGELAmZ7Cp0cIsjxzBKp2YFwzH1WLnxynefdzkn+SEAQL08Hq9bovt4XqQRqF0/PqmMpemqqidwj7cZKj
		JhbkBWHMBAIRs88kxTAtVGnuCXWL2ycgC30GNXwzYx+ITAJIkz+Tt8fiSXPf7g7R/2R72clbqnguAtcC+93vRZELQ0DoAbNNtVWZyect3uEXpmF7puGAs39n4vt/
		q/GqEbwo4I1A6k/b7l/3u8Lo/SvvD9uWYgAieZQJB/dh777+BeakqoY/gFAC0Ak+LIQ6WaWsWypDj+0O/Wes0flX+1gOokEALo+v29bq/Sse9dDwWkkQWEDVbE9J
		0PYaH2f9CmmRugMDSxs26j6G0k2Hf5iy/NYR9dxp/fJWpCLDk3XW3ux7gkF4k0EImK8DQAN1SNabD0Zk+0ZcqPxs0BkALO/x41dqgAPkbmOH1v7p7farqJ9vDaHS
		97qD66Lpj6IjUM1DZ5XlBhUcCODekJo0fAJafOfxi5dc7bafdrP/t7UgGgPRylUbHqwSA3WEHw4KBqCHP0ng+FVgoT4cUAR00MB5zTzD/x47fqbb3j+6/EITR/pp
		I16O8gw5ewgncMuRKZZvTeFOwz+9h/0TQMOp81uXcJ831/M2/uGy3ZHl33MvS9lV+vb4UCUNEdELCQPXYJ07T0nH0NoLLd9SsI2yPDcfx0eZvT+bXZpVer1sZ4vt
		p97K9kET19CR1sJHhxlw8ZuFeKjH0pNVBqJLVb/3bfzs7n3Y7KZfkIpPlYjgYECACCWc0NMZPljG877+HoArTroEh2/+6+q2HlgwrqRAYw32Y+l5l3WANR5fpfj8
		8nZlL8+/v7X+hA4y+yk4wuoFAPxAPZAEqO37x//bMmMdRGIjCFrnbEPCCcJ4QVtK43bmK9qTV9r4EF2gU+///kPPwF0w6PlHP0wwY3hvoOY7LKOm2LQuxU5bgzEs
		+n9fHYLMZ6GJyJhu7ZfRBo1ZFyJvPsQN9bwrQlA/zDO/vEjvhgEtp3v+VKAswpfTdNdArkUYu7/vFj32ADidV2MNPZGlBrNi8YoUZ/Oj7sV/6cXkae72oQqpIzOA
		Y6dVZ6CbXH/249P/64L3XN1OpQiZycMwUY7xpuprHw/fe3/1ivoIx1p/KW4icoRQpfdq5ydkzD8jf7warhtiKUk4ypJVjkh5uOpjn0ssdzp6+0X+bWhUziYLjlGJ
		KnYbMXhiuV2tv+FDFnOW0BSYRSPM6DP4ZgsmmyFqrQ63KaaUD8JZMullj8MZsm6R5xb1SOzBtAkRiZrrPuYGDtXMk/pKMtgMVSQ8sni9KMpkzMRIHPGu1C9NMDHB
		WoSSxg0iyCobhcVJ7IE5mM0uUL4EBb6S+r5Sw05MkAsQCMuwMTKv2ok0k8KaAEByc8eGi9qNKiTIsszJAPtCPod51h92mFIkcMWujZZXxcVb7Uv2JW/xZAZjhUqn
		dOf/IiFatG7Ribt+AWBkN1Gf1Lk7Tb/l18E7eWv3g4ODg4ODgPxcZb46e8C80AAAAAElFTkSuQmCC"
		# ====================== Local helper scriptblocks (defined once in Begin) ======================

		# Build the PowerShell command lines that the .bat files will run
		$private:BuildPwshLine = {
			param([string]$InstallTypeArg, [string]$ExtraArgs)
			"Powershell.exe -NoProfile -ExecutionPolicy Bypass -Command `"& '$DeployedWrapperPath' -installtype $InstallTypeArg$ExtraArgs`""
		}

		# Decode a Base64 image (PNG/JPG/ICO) to a Bitmap. For an ICO the largest frame is used: PNG-compressed
		$private:ConvertBase64ToBitmap = {
			param([string]$Base64)
			[byte[]]$bytes = [Convert]::FromBase64String(($Base64 -replace '\s', ''))
			$isIco = $bytes.Length -ge 6 -and $bytes[0] -eq 0 -and $bytes[1] -eq 0 -and $bytes[2] -eq 1 -and $bytes[3] -eq 0
			if ($isIco) {
				# Find the largest directory entry by pixel area
				$count = [BitConverter]::ToUInt16($bytes, 4)
				$best = $null
				for ($i = 0; $i -lt $count; $i++) {
					$e = 6 + 16 * $i
					if ($e + 16 -gt $bytes.Length) { break }
					$w = if ($bytes[$e] -eq 0) { 256 } else { [int]$bytes[$e] }
					$h = if ($bytes[$e + 1] -eq 0) { 256 } else { [int]$bytes[$e + 1] }
					$len = [BitConverter]::ToUInt32($bytes, $e + 8)
					$off = [BitConverter]::ToUInt32($bytes, $e + 12)
					if ($len -le 0 -or ($off + $len) -gt $bytes.Length) { continue }
					if (-not $best -or ($w * $h) -gt $best.Area) { $best = [pscustomobject]@{ Area = $w * $h; Offset = $off; Length = $len } }
				}
				if ($best) {
					$frame = [byte[]]::new($best.Length)
					[Array]::Copy($bytes, $best.Offset, $frame, 0, $best.Length)
					$ms = [System.IO.MemoryStream]::new($frame); $img = $null
					try { $img = [System.Drawing.Image]::FromStream($ms, $true, $true); return [System.Drawing.Bitmap]::new($img) }
					catch { Write-Verbose "ICO frame is not a standalone image; using the Icon loader. Error: $_" }
					finally { if ($img) { $img.Dispose() }; $ms.Dispose() }
				}
				# Fallback: let GDI+ pick the frame that best matches 256x256 from the whole ICO
				$ms = [System.IO.MemoryStream]::new($bytes); $ico = $null
				try { $ico = [System.Drawing.Icon]::new($ms, 256, 256); return $ico.ToBitmap() }
				finally { if ($ico) { $ico.Dispose() }; $ms.Dispose() }
			}
			# Non-ICO image (PNG/JPG/BMP/GIF)
			$ms = [System.IO.MemoryStream]::new($bytes); $img = $null
			try { $img = [System.Drawing.Image]::FromStream($ms, $true, $true); return [System.Drawing.Bitmap]::new($img) }
			finally { if ($img) { $img.Dispose() }; $ms.Dispose() }
		}

		# Compose the 256x256 app icon: draw the source, then the app name as a centered, outlined caption
		$private:NewCaptionedIcon = {
			param([System.Drawing.Bitmap]$Source)
			$size = $ARPAppIcoSize
			$caption = ($ARPAppName -replace '\s+', "`n").Trim()
			$bmp = [System.Drawing.Bitmap]::new($size, $size)
			$g = [System.Drawing.Graphics]::FromImage($bmp)
			$g.SmoothingMode = 'AntiAlias'; $g.InterpolationMode = 'HighQualityBicubic'; $g.PixelOffsetMode = 'HighQuality'
			$g.Clear($(if ($ARPAppIconBackground -eq 'White') { [System.Drawing.Color]::White } else { [System.Drawing.Color]::Transparent }))
			$g.DrawImage($Source, 0, 0, $size, $size)

			$fmt = [System.Drawing.StringFormat]::new()
			$fmt.Alignment = 'Center'; $fmt.LineAlignment = 'Center'

			# Auto-fit the caption to the icon via binary search when no explicit font size is configured
			$fontSize = $ARPAppIcoFontSize
			if ($fontSize -eq 0) {
				$max = $size - 20; $lo = 1; $hi = 200
				while ($lo -lt $hi) {
					$mid = [int](($lo + $hi + 1) / 2)
					$f = [System.Drawing.Font]::new($ARPAppIcoFontFamily, $mid, $ARPAppIcoFontWeight, 'Pixel')
					$m = $g.MeasureString($caption, $f); $f.Dispose()
					if ($m.Width -le $max -and $m.Height -le $max) { $lo = $mid } else { $hi = $mid - 1 }
				}
				$fontSize = $lo
			}
			$font = [System.Drawing.Font]::new($ARPAppIcoFontFamily, $fontSize, $ARPAppIcoFontWeight, 'Pixel')

			$cx = $size / 2 + $ARPAppIcoHorizontal
			$cy = $size / 2 + $ARPAppIcoVertical
			if ($ARPAppIcoRotation) { $g.TranslateTransform($cx, $cy); $g.RotateTransform($ARPAppIcoRotation); $g.TranslateTransform(-$cx, - $cy) }

			# Faux outline: draw the caption in 8 directions behind the fill so it stays legible on any background
			$outlineBrush = [System.Drawing.SolidBrush]::new($ARPAppIcoOutlineColor)
			$textBrush = [System.Drawing.SolidBrush]::new($ARPAppIcoColor)
			$d = [Math]::Max(1, [int][Math]::Round($size / 128))
			foreach ($o in @(@( - $d, - $d), @( - $d, 0), @( - $d, $d), @(0, - $d), @(0, $d), @($d, - $d), @($d, 0), @($d, $d))) {
				$g.DrawString($caption, $font, $outlineBrush, ($cx + $o[0]), ($cy + $o[1]), $fmt)
			}
			$g.DrawString($caption, $font, $textBrush, $cx, $cy, $fmt)

			foreach ($disposable in @($outlineBrush, $textBrush, $font, $fmt, $g)) { $disposable.Dispose() }
			return $bmp
		}

		# PNG frames when reporting an icon's "Dimensions", so DIB frames make Explorer correctly report 256x256
		$private:SaveIcoFile = {
			param([System.Drawing.Bitmap]$Bitmap, [string]$Path)
			$sizes = 256, 64, 48, 32, 16
			$dibs = foreach ($sz in $sizes) {
				$bmp = [System.Drawing.Bitmap]::new($sz, $sz, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
				$g = [System.Drawing.Graphics]::FromImage($bmp)
				$g.InterpolationMode = 'HighQualityBicubic'; $g.SmoothingMode = 'AntiAlias'; $g.PixelOffsetMode = 'HighQuality'; $g.CompositingQuality = 'HighQuality'
				$g.DrawImage($Bitmap, 0, 0, $sz, $sz); $g.Dispose()
				$rect = [System.Drawing.Rectangle]::new(0, 0, $sz, $sz)
				$data = $bmp.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::ReadOnly, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
				$stride = $data.Stride
				$pixels = [byte[]]::new($stride * $sz)
				[System.Runtime.InteropServices.Marshal]::Copy($data.Scan0, $pixels, 0, $pixels.Length)
				$bmp.UnlockBits($data); $bmp.Dispose()
				$ms = [System.IO.MemoryStream]::new()
				$w = [System.IO.BinaryWriter]::new($ms)
				# BITMAPINFOHEADER (biHeight doubled for the empty AND mask), then bottom-up BGRA, then a zeroed AND mask
				$w.Write([uint32]40); $w.Write([int32]$sz); $w.Write([int32]($sz * 2))
				$w.Write([uint16]1); $w.Write([uint16]32)
				$w.Write([uint32]0); $w.Write([uint32]0); $w.Write([int32]0); $w.Write([int32]0); $w.Write([uint32]0); $w.Write([uint32]0)
				for ($row = $sz - 1; $row -ge 0; $row--) { $w.Write($pixels, ($row * $stride), ($sz * 4)) }
				$andStride = [int][Math]::Floor((($sz + 31) / 32)) * 4   # AND mask rows padded to 32-bit
				$w.Write([byte[]]::new($andStride * $sz), 0, ($andStride * $sz))
				$w.Flush()
				$frameBytes = $ms.ToArray()
				$w.Dispose(); $ms.Dispose()
				, $frameBytes
			}
			$ico = [System.IO.MemoryStream]::new()
			$bw = [System.IO.BinaryWriter]::new($ico)
			$bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$sizes.Count)   # ICONDIR
			$offset = 6 + 16 * $sizes.Count
			for ($i = 0; $i -lt $sizes.Count; $i++) {
				$sz = $sizes[$i]; $len = $dibs[$i].Length
				$dim = if ($sz -ge 256) { [byte]0 } else { [byte]$sz }                       # 0 == 256
				$bw.Write($dim); $bw.Write($dim); $bw.Write([byte]0); $bw.Write([byte]0)     # w, h, colors, reserved
				$bw.Write([uint16]1); $bw.Write([uint16]32)                                  # planes, bpp
				$bw.Write([uint32]$len); $bw.Write([uint32]$offset)
				$offset += $len
			}
			foreach ($d in $dibs) { $bw.Write($d) }
			$bw.Flush(); [IO.File]::WriteAllBytes($Path, $ico.ToArray())
			$bw.Dispose(); $ico.Dispose()
		}

		# Local helper: save a PowerShell script as UTF-8 with BOM so Windows PowerShell 5.1 preserves non-ASCII characters
		$private:SaveDeployedScript = {
			param([string]$SourcePath, [string]$TargetPath, [string]$Label)
			if (-not ($SourcePath -and (Test-Path -LiteralPath $SourcePath -PathType Leaf))) { return }
			if (-not (Test-Path -LiteralPath $TargetPath) -or $ARPAppForce) {
				if ($PSCmdlet.ShouldProcess($TargetPath, "Save $($Label.ToLower()) script as UTF-8 with BOM")) {
					$private:ScriptReader = $null
					try {
						$ScriptReader = [System.IO.StreamReader]::new($SourcePath, $true)
						$ScriptContent = $ScriptReader.ReadToEnd()
						[System.IO.File]::WriteAllText($TargetPath, $ScriptContent, $Utf8BomEncoding)
						Write-Verbose "Success to save $($Label.ToLower()) script to $TargetPath as UTF-8 with BOM"
					}
					catch { Write-Warning "Failed to save $($Label.ToLower()) script to $TargetPath. Error: $_" }
					finally {
						if ($ScriptReader) { $ScriptReader.Dispose() }
					}
				}
			}
			else { Write-Verbose "$Label script already exists at target: $TargetPath" }
		}

		# Local helper: create an ARP action batch file (uninstall/modify) unless the action is hidden. Honors -WhatIf/-Confirm and -ARPAppForce
		$private:SaveBatchFile = {
			param([string]$Path, [string[]]$Lines, [bool]$Hidden, [string]$Label)
			if ($Hidden) { Write-Verbose "$Label option hidden, skipping batch file creation"; return }
			if (-not (Test-Path $Path) -or $ARPAppForce) {
				if ($PSCmdlet.ShouldProcess($Path, "Create $($Label.ToLower()) batch file")) {
					try {
						Set-Content -Path $Path -Value $Lines -Encoding Ascii -Force
						Write-Verbose "Success to create Batch file for $($Label.ToLower()) to $ARPAppFolder"
					}
					catch { Write-Warning "Failed to create batch file for $($Label.ToLower()). Error: $_" }
				}
			}
			else { Write-Verbose "Batch file for $($Label.ToLower()) already exists in $ARPAppFolder" }
		}

		# Local helper: create a shortcut (.lnk) via the shared WScript.Shell COM object (honors -WhatIf). Private locals are passed in because &-invoked scriptblocks cannot read $private: scope
		$private:NewAppShortcut = {
			param([string]$LnkPath, [string]$Label, $Shell, [string]$TargetPath, [string]$Arguments, [string]$IconLocation)
			if ($PSCmdlet.ShouldProcess($LnkPath, "Create $Label shortcut")) {
				try {
					$private:sc = $Shell.CreateShortcut($LnkPath)
					$sc.TargetPath = $TargetPath
					$sc.Arguments = $Arguments
					$sc.WorkingDirectory = $ARPAppFolder
					$sc.IconLocation = $IconLocation
					$sc.Description = $ARPAppName
					$sc.Save()
					Write-Verbose "Success to create $Label shortcut: $LnkPath"
				}
				catch { Write-Warning "Failed to create $Label shortcut $LnkPath. Error: $_" }
			}
		}

		# Encode one value definition into .reg syntax (REG_SZ / REG_DWORD / REG_EXPAND_SZ / REG_MULTI_SZ)
		$private:ConvertToRegLine = {
			param([hashtable]$Property)
			switch ($Property.Type) {
				'DWord' { '"{0}"=dword:{1:x8}' -f $Property.Name, ([uint32]$Property.Value) }
				'ExpandString' {
					$bytes = [System.Text.Encoding]::Unicode.GetBytes([string]$Property.Value + [char]0)
					'"{0}"=hex(2):{1}' -f $Property.Name, (($bytes | ForEach-Object { '{0:x2}' -f $_ }) -join ',')
				}
				'MultiString' {
					$mb = [System.Collections.Generic.List[byte]]::new()
					foreach ($s in @($Property.Value)) {
						$mb.AddRange([System.Text.Encoding]::Unicode.GetBytes([string]$s))
						$mb.AddRange([byte[]]@(0, 0))
					}
					$mb.AddRange([byte[]]@(0, 0))
					'"{0}"=hex(7):{1}' -f $Property.Name, (($mb | ForEach-Object { '{0:x2}' -f $_ }) -join ',')
				}
				default { '"{0}"="{1}"' -f $Property.Name, ((([string]$Property.Value) -replace '\\', '\\') -replace '"', '\"') }
			}
		}
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
			($stripped[7..0] -join '') + # Segment 1 (8 chars): reverse
			($stripped[11..8] -join '') + # Segment 2 (4 chars): reverse
			($stripped[15..12] -join '') + # Segment 3 (4 chars): reverse
			($stripped[17, 16, 19, 18, 21, 20, 23, 22, 25, 24, 27, 26, 29, 28, 31, 30] -join '') # Segments 4-5: pair-swap
		)
		Write-Verbose "Derived MSI Packed GUID (ProductID): $ARPFuncProductID"

		# Standardized deployed names so batches and registry are stable regardless of source filenames
		[string]$private:DeployedWrapperName = "App-Wrapper-$ARPAppGuid.ps1"
		[string]$private:DeployedInstallerName = "installer-$ARPAppGuid.ps1"
		[string]$private:DeployedUninstallerName = "uninstaller-$ARPAppGuid.ps1"
		[string]$DeployedWrapperPath = Join-Path -Path $ARPAppFolder -ChildPath $DeployedWrapperName
		[string]$DeployedInstallerPath = Join-Path -Path $ARPAppFolder -ChildPath $DeployedInstallerName
		[string]$DeployedUninstallerPath = Join-Path -Path $ARPAppFolder -ChildPath $DeployedUninstallerName

		# Registry / icon / batch paths
		[string]$ARPFuncIconPath = Join-Path -Path $ARPAppFolder -ChildPath "$($ARPAppName -replace '\s', '')-$ARPAppGuid.ico"
		[string]$ARPFuncUninstallRegKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$ARPAppGuid"
		[string]$ARPFuncProductsRegKey = "HKCR:\Installer\Products\$ARPFuncProductID"

		# Version gate: skip install when an equal-or-newer version is already registered (unless -ARPAppForce $true)
		if (-not $ARPAppForce) {
			[version]$private:CurrentVersion = '0.0.0.0'
			try {
				Write-Verbose "Checking installed version under $ARPFuncUninstallRegKey."
				$private:dv = (Get-ItemProperty -LiteralPath $ARPFuncUninstallRegKey -Name DisplayVersion -ErrorAction Stop).DisplayVersion
				if ($dv) {
					$CurrentVersion = [version]$dv
					Write-Verbose "Found installed app, CurrentVersion=$CurrentVersion"
				}
				else { Write-Verbose "DisplayVersion missing/empty under $ARPFuncUninstallRegKey; treating as not installed." }
			}
			catch [System.Management.Automation.ItemNotFoundException], [System.Management.Automation.PSArgumentException] {
				Write-Verbose "Registry key $ARPFuncUninstallRegKey not found; treating as not installed."
			}
			catch { Write-Verbose "Failed to read/parse DisplayVersion from $ARPFuncUninstallRegKey ($_); treating as not installed." }
			if ($CurrentVersion -ge $ARPAppVersion) {
				Write-Verbose "Skipping install: installed version ($CurrentVersion) is >= packaged version ($ARPAppVersion). Use -ARPAppForce `$true to override."
				$false
				return
			}
			Write-Verbose "Proceeding with install: $CurrentVersion -> $ARPAppVersion."
		}
		[string]$ARPFuncUninstallBAT = Join-Path -Path $ARPAppFolder -ChildPath "uninstall-$ARPAppGuid.bat"
		[string]$ARPFuncModifyBAT = Join-Path -Path $ARPAppFolder -ChildPath "reinstall-$ARPAppGuid.bat"
		[string]$ARPFuncUninstallString = 'CMD /C START cmd /c "{0}"' -f $ARPFuncUninstallBAT
		[string]$ARPFuncModifyString = 'CMD /C START cmd /c "{0}"' -f $ARPFuncModifyBAT

		# Common batch line: cd to a known-good working directory before invoking PowerShell
		[string]$ARPFuncUninstallcmd1 = 'cd /d "%SystemRoot%"'
		[string]$ARPFuncModifycmd1 = $ARPFuncUninstallcmd1

		# Uninstall extras: pass -ARPAppUnInstallScript only if a uninstall script will actually be deployed
		[string]$private:UninstallExtraArgs = ''
		if ($ARPAppUnInstallScript -and (Test-Path $ARPAppUnInstallScript)) {
			$UninstallExtraArgs = " -ARPAppUnInstallScript '$DeployedUninstallerPath'"
		}
		[string]$ARPFuncUninstallcmd2 = & $BuildPwshLine 'UnInstall' $UninstallExtraArgs

		# Modify (Repair) extras: forward shortcut/include flags + optional installer script
		[string]$private:ModifyExtraArgs = ''
		if ($ARPAppIncludeFolder) { $ModifyExtraArgs += " -ARPAppIncludeFolder `$true" }
		if (-not [string]::IsNullOrWhiteSpace($ARPAppUserStartFile)) { $ModifyExtraArgs += " -ARPAppUserStartFile '$($ARPAppUserStartFile -replace "'", "''")'" }
		if ($ARPAppShortcutOnDesktop) { $ModifyExtraArgs += " -ARPAppShortcutOnDesktop `$true" }
		if ($ARPAppShortcutInStart) { $ModifyExtraArgs += " -ARPAppShortcutInStart `$true" }
		if ($ARPAppInstallScript -and (Test-Path $ARPAppInstallScript)) {
			$ModifyExtraArgs = " -ARPAppInstallScript '$DeployedInstallerPath'" + $ModifyExtraArgs
		}
		[string]$ARPFuncModifycmd2 = & $BuildPwshLine 'Repair' $ModifyExtraArgs

		# Ensure application folder exists otherwise create it
		if (-not (Test-Path $ARPAppFolder) -or $ARPAppForce) {
			if ($PSCmdlet.ShouldProcess($ARPAppFolder, "Create application folder")) {
				try {
					New-Item -ItemType Directory -Path $ARPAppFolder -Force -ErrorAction Stop | Out-Null
					Write-Verbose "Application folder ready: $ARPAppFolder"
				}
				catch { Write-Warning "Failed to create folder $ARPAppFolder. Error: $_" }
			}
		}
		else { Write-Verbose "Application folder already exists: $ARPAppFolder" }

		# --- AppIcon generation -----------------------------------------------------------------------
		# Pick the icon source (priority: external .ico file, parameter Base64, custom Base64, embedded default)
		$ARPEffectiveIconBase64 = $null
		if ($ARPAppIconPath) {
			try {
				if (-not (Test-Path -LiteralPath $ARPAppIconPath)) { throw "Icon path not found: $ARPAppIconPath" }
				$ARPEffectiveIconBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($ARPAppIconPath))
				Write-Verbose "Loaded AppIcon from file as base64: $ARPAppIconPath"
			}
			catch { Write-Warning "Failed to read icon file as base64 from $ARPAppIconPath. Falling back to base64/default icon selection. Error: $_" }
		}
		if (-not $ARPEffectiveIconBase64) {
			$ARPEffectiveIconBase64 =
			if ($ARPAppIconB64) { Write-Verbose "Using provided base64 AppIcon string."; $ARPAppIconB64 }
			elseif ($ARPAppCustomIconB64) { Write-Verbose "Using custom fallback base64 AppIcon string."; $ARPAppCustomIconB64 }
			else { Write-Verbose "Using embedded default AppIcon."; $ARPAppDefaultIconBase64 }
		}

		# Decode the chosen source (falling back to the embedded default if it is invalid), compose, then save
		try { $ARPSourceIconImage = & $ConvertBase64ToBitmap $ARPEffectiveIconBase64 }
		catch {
			Write-Warning "Selected icon source is invalid image/base64. Falling back to embedded default icon. Error: $_"
			$ARPSourceIconImage = & $ConvertBase64ToBitmap $ARPAppDefaultIconBase64
		}
		$ARPIconBitmap = & $NewCaptionedIcon $ARPSourceIconImage

		if (-not (Test-Path -LiteralPath $ARPFuncIconPath) -or $ARPAppForce) {
			if ($PSCmdlet.ShouldProcess($ARPFuncIconPath, "Save rendered AppIcon")) {
				try {
					& $SaveIcoFile $ARPIconBitmap $ARPFuncIconPath
					Write-Verbose "Icon created: $ARPFuncIconPath"
				}
				catch { Write-Warning "Failed to save rendered AppIcon to $ARPFuncIconPath. Error: $_" }
			}
		}
		else { Write-Verbose "AppIcon already exists: $ARPFuncIconPath" }

		foreach ($private:DisposableObject in @($ARPIconBitmap, $ARPSourceIconImage)) {
			if ($DisposableObject) { $DisposableObject.Dispose() }
		}

		# Save the current PowerShell script (renamed to standardized deployed name)
		if ($ExecutingScriptPath -ne $DeployedWrapperPath -or $ARPAppForce) {
			& $SaveDeployedScript $ExecutingScriptPath $DeployedWrapperPath 'Wrapper'
		}
		else { Write-Verbose "Script already exists at target: $DeployedWrapperPath" }

		# Copy external install script if provided (renamed to standardized deployed name)
		& $SaveDeployedScript $ARPAppInstallScript $DeployedInstallerPath 'Install'

		# Copy external uninstall script if provided (renamed to standardized deployed name)
		& $SaveDeployedScript $ARPAppUnInstallScript $DeployedUninstallerPath 'Uninstall'

		# Copy every other file from the wrapper's source folder into the app folder (excluding the wrapper, install/uninstall scripts and icon)
		if ($ARPAppIncludeFolder) {
			[string]$private:SourceFolder = $PSScriptRoot
			if ([string]::IsNullOrWhiteSpace($SourceFolder) -or -not (Test-Path -LiteralPath $SourceFolder -PathType Container)) {
				Write-Warning "ARPAppIncludeFolder set but source folder could not be resolved from `$PSScriptRoot. Skipping folder copy."
			}
			elseif ((Resolve-Path -LiteralPath $SourceFolder).Path -eq (Resolve-Path -LiteralPath $ARPAppFolder).Path) {
				Write-Verbose "ARPAppIncludeFolder source equals target ($SourceFolder); nothing to copy."
			}
			else {
				# Build exclude set of source leaf names that are deployed under standardized names (or are the wrapper itself)
				[System.Collections.Generic.HashSet[string]]$private:Excluded = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
				[void]$Excluded.Add((Split-Path -Path $PSCommandPath -Leaf))
				if ($ARPAppInstallScript) { [void]$Excluded.Add((Split-Path -Path $ARPAppInstallScript   -Leaf)) }
				if ($ARPAppUnInstallScript) { [void]$Excluded.Add((Split-Path -Path $ARPAppUnInstallScript -Leaf)) }
				if ($ARPAppIconPath) { [void]$Excluded.Add((Split-Path -Path $ARPAppIconPath            -Leaf)) }
				foreach ($private:srcFile in (Get-ChildItem -LiteralPath $SourceFolder -File -Force)) {
					if ($Excluded.Contains($srcFile.Name)) { Write-Verbose "Skipping excluded source file: $($srcFile.Name)"; continue }
					[string]$private:companionTarget = Join-Path -Path $ARPAppFolder -ChildPath $srcFile.Name
					if (-not (Test-Path $companionTarget) -or $ARPAppForce) {
						if ($PSCmdlet.ShouldProcess($companionTarget, "Copy file from source folder")) {
							try {
								Copy-Item -LiteralPath $srcFile.FullName -Destination $companionTarget -Force | Out-Null
								Write-Verbose "Success to copy file to $companionTarget"
							}
							catch { Write-Warning "Failed to copy file '$($srcFile.FullName)'. Error: $_" }
						}
					}
					else { Write-Verbose "File already exists at target: $companionTarget" }
				}
			}
		}

		# Create All-Users desktop/start shortcuts. If ARPAppUserStartFile is set and exists in ARPAppFolder it is used, otherwise shortcuts launch the deployed wrapper script
		if ($ARPAppShortcutOnDesktop -or $ARPAppShortcutInStart) {
			[string]$private:ShortcutTargetPath = $null
			[string]$private:ShortcutArguments = ''
			[string]$private:ShortcutIconFallback = $DeployedWrapperPath

			if (-not [string]::IsNullOrWhiteSpace($ARPAppUserStartFile)) {
				[string]$private:StartFileLeaf = Split-Path -Path $ARPAppUserStartFile -Leaf
				[string]$private:StartFileTarget = Join-Path -Path $ARPAppFolder -ChildPath $StartFileLeaf
				if (Test-Path -LiteralPath $StartFileTarget -PathType Leaf) {
					[string]$private:StartFileExt = [System.IO.Path]::GetExtension($StartFileTarget).ToLowerInvariant()
					if ($StartFileExt -in '.js', '.jse', '.vbs', '.vbe', '.wsf') {
						# Route .js/.vbs through wscript.exe so no console window is shown when the shortcut is launched
						[string]$private:WScriptTarget = Join-Path -Path $env:SystemRoot -ChildPath 'System32\wscript.exe'
						if (-not (Test-Path -LiteralPath $WScriptTarget -PathType Leaf)) { $WScriptTarget = 'wscript.exe' }
						$ShortcutTargetPath = $WScriptTarget
						$ShortcutArguments = "`"$StartFileTarget`""
						$ShortcutIconFallback = $StartFileTarget
					}
					else {
						$ShortcutTargetPath = $StartFileTarget
						$ShortcutIconFallback = $StartFileTarget
					}
				}
				else {
					Write-Warning "ARPAppUserStartFile '$StartFileLeaf' not found in $ARPAppFolder. Falling back to deployed wrapper script."
				}
			}

			if (-not $ShortcutTargetPath) {
				[string]$private:PwshTarget = Join-Path -Path $PSHOME -ChildPath 'powershell.exe'
				if (-not (Test-Path -LiteralPath $PwshTarget -PathType Leaf)) { $PwshTarget = 'powershell.exe' }
				$ShortcutTargetPath = $PwshTarget
				$ShortcutArguments = "-NoProfile -ExecutionPolicy Bypass -File `"$DeployedWrapperPath`""
			}

			[string]$private:DesktopLnk = Join-Path -Path "$Env:Public\Desktop" -ChildPath "$ARPAppName.lnk"
			[string]$private:StartMenuDir = Join-Path -Path "$Env:ProgramData\Microsoft\Windows\Start Menu\Programs" -ChildPath $ARPAppPublisher
			[string]$private:StartMenuLnk = Join-Path -Path $StartMenuDir -ChildPath "$ARPAppName.lnk"
			[string]$private:LnkIcon = if (Test-Path -LiteralPath $ARPFuncIconPath) { $ARPFuncIconPath } else { $ShortcutIconFallback }

			try {
				$private:WshShell = New-Object -ComObject WScript.Shell
				if ($ARPAppShortcutOnDesktop -and (-not (Test-Path -LiteralPath $DesktopLnk) -or $ARPAppForce)) {
					& $NewAppShortcut $DesktopLnk 'Desktop' $WshShell $ShortcutTargetPath $ShortcutArguments $LnkIcon
				}
				elseif ($ARPAppShortcutOnDesktop) { Write-Verbose "Desktop shortcut already exists: $DesktopLnk" }

				if ($ARPAppShortcutInStart) {
					if (-not (Test-Path -LiteralPath $StartMenuDir)) {
						if ($PSCmdlet.ShouldProcess($StartMenuDir, "Create Start Menu folder")) {
							try { New-Item -ItemType Directory -Path $StartMenuDir -Force | Out-Null }
							catch { Write-Warning "Failed to create Start Menu folder $StartMenuDir. Error: $_" }
						}
					}
					if (-not (Test-Path -LiteralPath $StartMenuLnk) -or $ARPAppForce) {
						& $NewAppShortcut $StartMenuLnk 'Start Menu' $WshShell $ShortcutTargetPath $ShortcutArguments $LnkIcon
					}
					else { Write-Verbose "Start Menu shortcut already exists: $StartMenuLnk" }
				}
			}
			finally {
				if ($WshShell) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($WshShell) }
			}
		}

		# Create and Save the uninstall and modify (reinstall) batch files
		& $SaveBatchFile $ARPFuncUninstallBAT @($ARPFuncUninstallcmd1, $ARPFuncUninstallcmd2) $ARPAppHideUninstall 'Uninstall'
		& $SaveBatchFile $ARPFuncModifyBAT    @($ARPFuncModifycmd1, $ARPFuncModifycmd2)    $ARPAppHideModify    'Modify'

		# Create or Add Registry Keys
		Write-Verbose "Starting registry operations."
		try {
			# Registry paths in .reg form (full hive names) for the single import below
			$private:UninstallRegPath = $ARPFuncUninstallRegKey -replace '^HKLM:', 'HKEY_LOCAL_MACHINE'
			$private:ProductsRegPath = $ARPFuncProductsRegKey -replace '^HKCR:', 'HKEY_CLASSES_ROOT'
			$private:SourceListRegPath = "$ProductsRegPath\Sourcelist"

			# HKLM Uninstall/Modify values
			$RegistryProperties = @(
				@{ Name = "DisplayName"; Type = "String"; Value = $ARPAppName },
				@{ Name = "DisplayVersion"; Type = "String"; Value = $ARPAppVersion.ToString() },
				@{ Name = "Version"; Type = "DWord"; Value = ($ARPAppVersion.Major -shl 24) -bor ($ARPAppVersion.Minor -shl 16) -bor $ARPAppVersion.Build },
				@{ Name = "VersionMajor"; Type = "DWord"; Value = $ARPAppVersion.Major },
				@{ Name = "VersionMinor"; Type = "DWord"; Value = $ARPAppVersion.Minor },
				@{ Name = "Publisher"; Type = "String"; Value = $ARPAppPublisher },
				@{ Name = "DisplayIcon"; Type = "String"; Value = $ARPFuncIconPath },
				@{ Name = "Comments"; Type = "String"; Value = $ARPAppName },
				@{ Name = "InstallLocation"; Type = "String"; Value = $ARPAppFolder },
				@{ Name = "UninstallString"; Type = "String"; Value = $ARPFuncUninstallString },
				@{ Name = "QuietUninstallString"; Type = "String"; Value = $ARPFuncUninstallString },
				@{ Name = "ModifyRegistryKey"; Type = "String"; Value = $ARPFuncUninstallRegKey },
				@{ Name = "ModifyString"; Type = "String"; Value = $ARPFuncModifyString },
				@{ Name = "ModifyPath"; Type = "String"; Value = $ARPFuncModifyString },
				@{ Name = "NoRemove"; Type = "DWord"; Value = [int][bool]$ARPAppHideUninstall },# 1 = Hide Remove button
				@{ Name = "NoModify"; Type = "DWord"; Value = [int][bool]$ARPAppHideModify },# 1 = Hide Modify button
				@{ Name = "SystemComponent"; Type = "DWord"; Value = 0 } # Default: Visible in Add Remove Programs (1 = hidden)
			)
			# Hide from Add Remove Programs while keeping registry and files for detection
			if ($ARPAppHidden) { ($RegistryProperties | Where-Object { $_.Name -eq "SystemComponent" }).Value = 1 }

			# HKCR Installer\Products values
			$AdditionalRegistryProperties = @(
				@{ Name = "ProductName"; Type = "String"; Value = $ARPAppName },
				@{ Name = "Manufacturer"; Type = "String"; Value = $ARPAppPublisher },
				@{ Name = "ProductIcon"; Type = "String"; Value = $ARPFuncIconPath },
				@{ Name = "ProductVersion"; Type = "String"; Value = $ARPAppVersion.ToString() },
				@{ Name = "Version"; Type = "DWord"; Value = ($ARPAppVersion.Major -shl 24) -bor ($ARPAppVersion.Minor -shl 16) -bor $ARPAppVersion.Build },
				@{ Name = "VersionMajor"; Type = "DWord"; Value = $ARPAppVersion.Major },
				@{ Name = "VersionMinor"; Type = "DWord"; Value = $ARPAppVersion.Minor },
				@{ Name = "AdvertiseFlags"; Type = "DWord"; Value = 388 },
				@{ Name = "Assignment"; Type = "DWord"; Value = 1 },
				@{ Name = "AuthorizedLUAApp"; Type = "DWord"; Value = 0 },
				@{ Name = "Clients"; Type = "MultiString"; Value = @(":") },
				@{ Name = "DeploymentFlags"; Type = "DWord"; Value = 3 },
				@{ Name = "InstanceType"; Type = "DWord"; Value = 0 },
				@{ Name = "Language"; Type = "DWord"; Value = 1033 }
			)
			$SourcelistProperties = @(
				@{ Name = "LastUsedSource"; Type = "ExpandString"; Value = "n;1;$($ARPAppFolder)\" },
				@{ Name = "PackageName"; Type = "String"; Value = $DeployedWrapperName }
			)
			$MediaProperties = @(@{ Name = "1"; Type = "String"; Value = ";" })
			$NetProperties = @(@{ Name = "1"; Type = "ExpandString"; Value = "$($ARPAppFolder)\" })

			# Assemble one .reg document for the whole ARP footprint and apply it in a single reg.exe import
			$private:RegSections = [ordered]@{
				$UninstallRegPath          = $RegistryProperties
				$ProductsRegPath           = $AdditionalRegistryProperties
				$SourceListRegPath         = $SourcelistProperties
				"$SourceListRegPath\Media" = $MediaProperties
				"$SourceListRegPath\Net"   = $NetProperties
			}
			$private:RegLines = [System.Collections.Generic.List[string]]::new()
			$RegLines.Add('Windows Registry Editor Version 5.00')
			foreach ($Section in $RegSections.GetEnumerator()) {
				$RegLines.Add('')
				$RegLines.Add("[$($Section.Key)]")
				foreach ($Property in $Section.Value) { $RegLines.Add([string](& $ConvertToRegLine $Property)) }
			}

			if ($PSCmdlet.ShouldProcess($UninstallRegPath, "Import ARP registry footprint")) {
				$private:RegFilePath = Join-Path -Path $env:TEMP -ChildPath "arp-$ARPAppGuid.reg"
				$private:RegErrPath = "$RegFilePath.err"
				try {
					[System.IO.File]::WriteAllText($RegFilePath, ($RegLines -join "`r`n"), [System.Text.Encoding]::Unicode)
					# Start-Process (not the call operator) so reg.exe's stderr is not turned into a terminating NativeCommandError under $ErrorActionPreference='Stop' on PS5.1
					$private:RegProc = Start-Process -FilePath "$env:SystemRoot\System32\reg.exe" -ArgumentList @('import', "`"$RegFilePath`"") -Wait -PassThru -WindowStyle Hidden -RedirectStandardError $RegErrPath
					if ($RegProc.ExitCode -eq 0) { Write-Verbose "Imported ARP registry footprint (HKLM Uninstall + HKCR Installer\Products) in one transaction." }
					else { Write-Warning "reg.exe import failed (exit $($RegProc.ExitCode)): $(Get-Content -Raw -LiteralPath $RegErrPath -ErrorAction SilentlyContinue)" }
				}
				catch { Write-Warning "Failed to import ARP registry footprint. Error: $_" }
				finally { Remove-Item -Path $RegFilePath, $RegErrPath -Force -ErrorAction SilentlyContinue }
			}

		}
		catch { Write-warning "An error occurred during registry operations section: $_" }
		# Signal caller to proceed with installer payload
		$true
	}
	End {
		Write-Verbose "-- END Function $($MyInvocation.MyCommand.Name) --"
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
		Version: 1.3.0

		Version History:
		1.0 - Initial version
		1.0.1 - Changed parameter names end improved error handling
		1.1.0 - Major refactor for better maintainability, added verbose logging, and improved error handling with try/catch blocks.
		1.2.0 - De-duplicated registry-key removal into a local RemoveRegistryKey helper (identical behavior, messages and -WhatIf support; PS5.1-7.x).
		1.3.0 - Aligned registry removal with Add-AddRemovePrograms: deletes the HKLM Uninstall key and HKCR Installer\Products subtree via a single reg.exe import of a [-key] deletion file (no HKCR PSDrive mount). Tightened file/folder operations to -LiteralPath.
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
	$ErrorActionPreference = 'Stop'
	Write-Verbose "-- START Function $($MyInvocation.MyCommand.Name) --"
	$private:PushedLocation = $false

	# Convert GUID to MSI Packed GUID (ProductID) - MSI reverses each segment: segments 1-3 are fully reversed, segments 4-5 are pair-swapped
	# Example: {FEEDBEEF-BEEF-4DAD-BEEF-B628CCCA16E0} -> FEEBDEEFFEEBDAD4EBFE6B82CCAC610E
	[string]$private:stripped = $ARPAppGuid -replace '[{}\-]', ''
	[string]$ARPFuncProductID = (
		($stripped[7..0] -join '') + # Segment 1 (8 chars): reverse
		($stripped[11..8] -join '') + # Segment 2 (4 chars): reverse
		($stripped[15..12] -join '') + # Segment 3 (4 chars): reverse
		($stripped[17, 16, 19, 18, 21, 20, 23, 22, 25, 24, 27, 26, 29, 28, 31, 30] -join '') # Segments 4-5: pair-swap
	)
	Write-Verbose "Derived MSI Packed GUID (ProductID) for removal: $ARPFuncProductID"

	# Standardized deployed paths (must match the one used in Add-AddRemovePrograms)
	$private:DeployedWrapperPath = Join-Path -Path $ARPAppFolder -ChildPath "App-Wrapper-$ARPAppGuid.ps1"
	$private:DeployedInstallerPath = Join-Path -Path $ARPAppFolder -ChildPath "installer-$ARPAppGuid.ps1"
	$private:DeployedUninstallerPath = Join-Path -Path $ARPAppFolder -ChildPath "uninstaller-$ARPAppGuid.ps1"

	# Registry / icon / batch paths
	$ARPFuncIconPath = Join-Path -Path $ARPAppFolder -ChildPath "$($ARPAppName -replace '\s', '')-$ARPAppGuid.ico"
	$ARPFuncUninstallRegKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$ARPAppGuid"
	$ARPFuncProductsRegKey = "HKCR:\Installer\Products\$ARPFuncProductID"
	$ARPFuncUninstallBAT = Join-Path -Path $ARPAppFolder -ChildPath "uninstall-$ARPAppGuid.bat"
	$ARPFuncModifyBAT = Join-Path -Path $ARPAppFolder -ChildPath "reinstall-$ARPAppGuid.bat"

	# Remove Registry Keys
	Write-Verbose "Starting registry key removal."
	try {
		# Assemble one .reg document for the whole ARP footprint and apply it in a single reg.exe import to remove the keys
		$private:UninstallRegPath = $ARPFuncUninstallRegKey -replace '^HKLM:', 'HKEY_LOCAL_MACHINE'
		$private:ProductsRegPath = $ARPFuncProductsRegKey -replace '^HKCR:', 'HKEY_CLASSES_ROOT'

		$private:RegLines = [System.Collections.Generic.List[string]]::new()
		$RegLines.Add('Windows Registry Editor Version 5.00')
		$RegLines.Add('')
		$RegLines.Add("[-$UninstallRegPath]")
		$RegLines.Add('')
		$RegLines.Add("[-$ProductsRegPath]")

		if ($PSCmdlet.ShouldProcess($UninstallRegPath, "Remove ARP registry footprint")) {
			$private:RegFilePath = Join-Path -Path $env:TEMP -ChildPath "arp-del-$ARPAppGuid.reg"
			$private:RegErrPath = "$RegFilePath.err"
			try {
				[System.IO.File]::WriteAllText($RegFilePath, ($RegLines -join "`r`n"), [System.Text.Encoding]::Unicode)
				# Start-Process (not the call operator) so reg.exe's stderr is not turned into a terminating NativeCommandError under $ErrorActionPreference='Stop' on PS5.1
				$private:RegProc = Start-Process -FilePath "$env:SystemRoot\System32\reg.exe" -ArgumentList @('import', "`"$RegFilePath`"") -Wait -PassThru -WindowStyle Hidden -RedirectStandardError $RegErrPath
				if ($RegProc.ExitCode -eq 0) { Write-Verbose "Removed ARP registry footprint (HKLM Uninstall + HKCR Installer\Products) in one transaction." }
				else { Write-Warning "reg.exe import failed (exit $($RegProc.ExitCode)): $(Get-Content -Raw -LiteralPath $RegErrPath -ErrorAction SilentlyContinue)" }
			}
			catch { Write-Warning "Failed to remove ARP registry footprint. Error: $_" }
			finally { Remove-Item -LiteralPath $RegFilePath, $RegErrPath -Force -ErrorAction SilentlyContinue }
		}
	}
 catch { Write-Warning "An error occurred during registry key removal section: $_" }

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
	# Any remaining files staged into $ARPAppFolder (recurse so nested companion content is also removed)
	if (Test-Path -LiteralPath $ARPAppFolder -PathType Container) {
		foreach ($private:extraFile in (Get-ChildItem -LiteralPath $ARPAppFolder -File -Recurse -Force -ErrorAction SilentlyContinue)) {
			$FilesToDelete.Add($extraFile.FullName)
		}
	}

	foreach ($FileItem in $FilesToDelete) {
		if (Test-Path -LiteralPath $FileItem) {
			if ($PSCmdlet.ShouldProcess($FileItem, "Remove File")) {
				try {
					Remove-Item -LiteralPath $FileItem -Force
					Write-Verbose "Success to remove file: $FileItem"
				}
				catch { Write-Warning "Failed to remove file $FileItem. Error: $_" }
			}
		}
		else { Write-Verbose "File not found: $FileItem" }
	}

	# Remove any now-empty subdirectories inside the app folder (deepest first) so the folder can be cleaned up below
	if (Test-Path -LiteralPath $ARPAppFolder -PathType Container) {
		$private:SubDirs = Get-ChildItem -LiteralPath $ARPAppFolder -Directory -Recurse -Force -ErrorAction SilentlyContinue |
		Sort-Object { $_.FullName.Length } -Descending
		foreach ($private:SubDir in $SubDirs) {
			if (@(Get-ChildItem -LiteralPath $SubDir.FullName -Force -ErrorAction SilentlyContinue).Count -eq 0) {
				if ($PSCmdlet.ShouldProcess($SubDir.FullName, "Remove empty directory")) {
					try {
						[System.IO.Directory]::Delete($SubDir.FullName, $false)
						Write-Verbose "Success to remove empty subfolder: $($SubDir.FullName)"
					}
					catch { Write-Warning "Failed to remove subfolder $($SubDir.FullName). Error: $_" }
				}
			}
			else { Write-Verbose "Subfolder not empty, skipping: $($SubDir.FullName)" }
		}
	}

	# Remove the publisher Start Menu folder (if empty)
	if (-not [string]::IsNullOrWhiteSpace($ARPAppPublisher)) {
		[string]$private:StartMenuPubDir = Join-Path -Path "$Env:ProgramData\Microsoft\Windows\Start Menu\Programs" -ChildPath $ARPAppPublisher
		if (Test-Path -LiteralPath $StartMenuPubDir) {
			if (@(Get-ChildItem -LiteralPath $StartMenuPubDir -Force -ErrorAction SilentlyContinue).Count -eq 0) {
				try {
					[System.IO.Directory]::Delete($StartMenuPubDir, $false)
					Write-Verbose "Success to remove empty Start Menu publisher folder: $StartMenuPubDir"
				}
				catch { Write-Warning "Failed to remove Start Menu publisher folder $StartMenuPubDir. Error: $_" }
			}
			else { Write-Verbose "Start Menu publisher folder not empty, skipping: $StartMenuPubDir" }
		}
	}

	# Remove Application Folder (if empty), then Publisher Folder (if empty) and so on until a non empty folder is reached, or a protected root
	[string[]]$private:ProtectedRoots = @(
		$Env:ProgramFiles,
		${Env:ProgramFiles(x86)},
		$Env:ProgramData,
		$Env:SystemDrive,
		$Env:SystemRoot,
		$Env:windir
	) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') }

	[string]$private:FolderToCheck = $ARPAppFolder
	# Move the working directory off the folder being deleted so it is not held open. Skip during -WhatIf; restore afterwards
	if (-not $WhatIfPreference) {
		try { Push-Location -LiteralPath $Env:SystemRoot -ErrorAction Stop; $private:PushedLocation = $true }
		catch { Write-Verbose "Could not Push-Location to $Env:SystemRoot: $_" }
	}
	for ($private:depth = 0; $depth -lt 2 -and $FolderToCheck; $depth++) {
		if (-not (Test-Path -LiteralPath $FolderToCheck)) {
			Write-Verbose "Folder not found: $FolderToCheck"
			break
		}
		[string]$private:Trimmed = $FolderToCheck.TrimEnd('\')
		if ($ProtectedRoots -contains $Trimmed) {
			Write-Verbose "Reached protected root, stopping cleanup: $FolderToCheck"
			break
		}
		if (@(Get-ChildItem -LiteralPath $FolderToCheck -Force -ErrorAction SilentlyContinue).Count -ne 0) {
			Write-Verbose "Folder not empty, skipping removal: $FolderToCheck"
			break
		}
		if ($PSCmdlet.ShouldProcess($FolderToCheck, "Remove empty directory")) {
			try {
				[System.IO.Directory]::Delete($FolderToCheck, $false)
				Write-Verbose "Success to remove empty folder: $FolderToCheck"
			}
			catch {
				Write-Warning "Failed to remove folder $FolderToCheck. Error: $_"
				break
			}
		}
		$FolderToCheck = Split-Path -Path $FolderToCheck -Parent
	}

	# Restore the caller's working directory if we changed it
	if ($private:PushedLocation) {
		try { Pop-Location } catch { Write-Verbose "Failed to Pop-Location: $_" }
	}
	Write-Verbose "-- END Function $($MyInvocation.MyCommand.Name) --"
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
    1.1 - Added regex validation for ADGroups and improved error messages
#>
	[CmdletBinding()]
	param ([Parameter(Mandatory)][array]$MapObjects)
	Write-Verbose "-- START Function $($MyInvocation.MyCommand.Name) --"
	# Pre-compiled regex patterns for validation
	[regex]$NameRegex = '[<>:"/\\|?*]'
	[regex]$PathRegex = '^\\\\[\w.\-]+\\[\w.\-$]+(?:\\[\w.\-$ ]+)*$'
	[regex]$LetterRegex = '^[A-Za-z]$'

	$i = 0
	foreach ($o in $MapObjects) {
		$i++
		$e = [System.Collections.Generic.List[string]]::new()

		if ($o.ContainsKey('Letter')) {
			$letter = $o['Letter']
			if ($letter -is [string]) { $letter = $letter.TrimEnd(':') }
			if (-not $LetterRegex.IsMatch([string]$letter)) { $e.Add("Invalid Letter '$($o['Letter'])'") }
			if (-not $o.ContainsKey('Persistent') -or $o['Persistent'] -isnot [bool]) { $e.Add("Persistent must be `$true or `$false") }
			$p = $o['Path']
			if (-not ($p -and $PathRegex.IsMatch([string]$p))) { $e.Add("Invalid/Missing Path '$p'") }
			if ($o['Label'] -and $NameRegex.IsMatch([string]$o['Label'])) { $e.Add("Label contains illegal characters") }
		}
		elseif ($o.ContainsKey('PrinterName')) {
			if ([string]::IsNullOrWhiteSpace($o['PrinterName'])) { $e.Add("Missing/Empty PrinterName") }
			elseif ($NameRegex.IsMatch([string]$o['PrinterName'])) { $e.Add("PrinterName contains illegal characters") }
			if (-not $o.ContainsKey('Default') -or $o['Default'] -isnot [bool]) { $e.Add("Default must be `$true or `$false") }
			$p = $o['Path']
			if (-not ($p -and $PathRegex.IsMatch([string]$p))) { $e.Add("Invalid/Missing Path '$p'") }
		}
		else { $e.Add("Unknown Type: Must have 'Letter' or 'PrinterName'") }

		if ($o['ADGroups']) {
			foreach ($g in @($o['ADGroups'])) {
				if ($NameRegex.IsMatch([string]$g)) { $e.Add("ADGroups contains illegal characters: '$g'"); break }
			}
		}

		if ($e.Count -gt 0) { throw "MapObject[$i] validation failed: $($e -join ', ')" }
	}
	Write-Verbose "-- END Function $($MyInvocation.MyCommand.Name) --"
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
		[Parameter(Mandatory = $false, HelpMessage = 'Domain to search for group memberships')]
		[string]$ADGRPDomainName = $env:USERDNSDOMAIN,

		[Parameter(Mandatory = $false, HelpMessage = 'Optional ref that returns if a DC is available')]
		[ref]$ADGRPDCAvailable = $null,

		[Parameter(Mandatory = $false, HelpMessage = 'Optional group names to limit the membership lookup')]
		[string[]]$ADGRPRequiredGroups = @(),

		[Parameter(Mandatory = $false, HelpMessage = 'Skip Kerberos token discovery and use scoped LDAP group discovery directly')]
		[bool]$ADGRPSkipTokenDiscovery = $false
	)

	begin {
		Write-Verbose "-- START Function $($MyInvocation.MyCommand.Name) --"
		$ADGRPSearcher = $null
		$ADGRPUserResult = $null
		$ADGRPGroupsResults = $null
		$ADGRPPrimaryGroupResult = $null
		$ADGRPGroupMembershipList = [System.Collections.Generic.List[String]]::new()

		# Local helpers (single source of LDAP escaping / name-clause construction)
		$ADGRPEscapeLdap = { param([string]$Value) $Value -replace '([\\*\(\)\x00/])', '\$1' }
		$ADGRPBuildNameClauses = {
			param([string[]]$Names)
			$ADGRPClauses = ($Names | ForEach-Object { '(name=' + (& $ADGRPEscapeLdap $_) + ')' }) -join ''
			if ($Names.Count -gt 1) { "(|$ADGRPClauses)" } else { $ADGRPClauses }
		}
	}

	process {
		if ($ADGRPDCAvailable) { $ADGRPDCAvailable.Value = $true }  # assume reachable; DC Locator will correct this if needed
		try {
			# Validate and set domain - use fallback if empty
			if ([string]::IsNullOrEmpty($ADGRPDomainName)) {
				$ADGRPDomainName = $env:USERDNSDOMAIN
				if ([string]::IsNullOrEmpty($ADGRPDomainName)) {
					Write-Error "No domain specified and USERDNSDOMAIN environment variable is empty"
					return $ADGRPGroupMembershipList
				}
			}
			Write-Verbose "Using domain: $ADGRPDomainName"

			# Get current user's UPN - with fallback for hybrid scenarios
			$ADGRPUserPrincipalName = try { whoami /upn 2>$null } catch { $null }
			if (-not $ADGRPUserPrincipalName -or $ADGRPUserPrincipalName -notlike "*@*") {
				Write-Error "Failed to enumerate UserPrincipalName - user may not be domain-joined"
				return $ADGRPGroupMembershipList
			}
			Write-Verbose "Success to enumerate UserPrincipalName: $ADGRPUserPrincipalName"

			# Locate a domain controller before LDAP queries so DirectorySearcher only runs when one is reachable.
			$ADGRPDCLocated = $false
			try {
				$ADGRPDirContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $ADGRPDomainName)
				$null = [System.DirectoryServices.ActiveDirectory.DomainController]::FindOne($ADGRPDirContext)
				$ADGRPDCLocated = $true
			}
			catch { $ADGRPDCLocated = $false }
			if (-not $ADGRPDCLocated) {
				Write-Verbose "No domain controller reachable for $ADGRPDomainName"
				if ($ADGRPDCAvailable) { $ADGRPDCAvailable.Value = $false }
				return $ADGRPGroupMembershipList
			}

			# Short-circuit: no group-scoped mappings configured, so no LDAP search is required.
			if (-not $ADGRPRequiredGroups -or $ADGRPRequiredGroups.Count -eq 0) {
				Write-Verbose "No ADGRPRequiredGroups supplied - skipping LDAP group enumeration to spare DC load"
				return $ADGRPGroupMembershipList
			}
			# Kerberos token path (preferred): zero LDAP queries. The TGT issued by the DC carries every group SID for the user.
			if ($ADGRPSkipTokenDiscovery) {
				Write-Verbose "ADGRPSkipTokenDiscovery is enabled - skipping Kerberos token discovery and using scoped LDAP"
			}
			if (-not $ADGRPSkipTokenDiscovery) {
				try {
					# Trigger TGT refresh via a single SMB auth call to the DC
					try { $null = Test-Path -LiteralPath "\\$ADGRPDomainName\SYSVOL" -ErrorAction SilentlyContinue } catch {}
					# Translate ONLY the configured group names to SIDs
					$ADGRPNetBiosDomain = $env:USERDOMAIN
					$ADGRPTranslatedGroupSids = @{}
					# Step 1: LSA (skipped silently when authority cannot be resolved)
					foreach ($ADGRPGroupName in $ADGRPRequiredGroups) {
						$ADGRPAuthoritiesToTry = @()
						if ($ADGRPNetBiosDomain) { $ADGRPAuthoritiesToTry += $ADGRPNetBiosDomain }    # 1: NetBIOS domain (most reliable)
						$ADGRPAuthoritiesToTry += $null                                                              # 2: bare name (LSA uses default domain)
						if ($ADGRPDomainName -and $ADGRPDomainName -ne $ADGRPNetBiosDomain) { $ADGRPAuthoritiesToTry += $ADGRPDomainName }  # 3: DNS domain (last resort)
						foreach ($ADGRPAuthority in $ADGRPAuthoritiesToTry) {
							try {
								$ADGRPNTAccount = if ($ADGRPAuthority) { [System.Security.Principal.NTAccount]::new($ADGRPAuthority, $ADGRPGroupName) }
								else { [System.Security.Principal.NTAccount]::new($ADGRPGroupName) }
								$ADGRPSid = $ADGRPNTAccount.Translate([System.Security.Principal.SecurityIdentifier])
								$ADGRPTranslatedGroupSids[$ADGRPGroupName] = $ADGRPSid.Value
								break
							}
							catch { } # Try next authority; failures are expected on Entra-joined CKT devices
						}
					}

					# Step 2: If LSA could not resolve like Cloud Native with Kerberos Cloud Trust, do ONE flat indexed LDAP query
					$ADGRPUnresolvedNames = @($ADGRPRequiredGroups | Where-Object { -not $ADGRPTranslatedGroupSids.ContainsKey($_) })
					if ($ADGRPUnresolvedNames.Count -gt 0) {
						$ADGRPSidLookupSearcher = $null
						$ADGRPSidLookupResults = $null
						try {
							$ADGRPSidLookupSearcher = [System.DirectoryServices.DirectorySearcher]::new()
							$ADGRPSidLookupSearcher.SearchRoot = [ADSI]"LDAP://$ADGRPDomainName"
							$ADGRPSidLookupSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
							$ADGRPSidLookupSearcher.ServerTimeLimit = [TimeSpan]::FromSeconds(15)
							$ADGRPNameClauses = & $ADGRPBuildNameClauses $ADGRPUnresolvedNames
							$ADGRPSidLookupSearcher.Filter = "(&(objectCategory=group)$ADGRPNameClauses)"
							$null = $ADGRPSidLookupSearcher.PropertiesToLoad.Add("name")
							$null = $ADGRPSidLookupSearcher.PropertiesToLoad.Add("objectSid")
							Write-Verbose "Token path: resolving $($ADGRPUnresolvedNames.Count) group name(s) to SIDs via single flat LDAP query"
							$ADGRPSidLookupResults = $ADGRPSidLookupSearcher.FindAll()
							foreach ($ADGRPSidLookupResult in $ADGRPSidLookupResults) {
								if ($ADGRPSidLookupResult.Properties["name"].Count -gt 0 -and $ADGRPSidLookupResult.Properties["objectSid"].Count -gt 0) {
									$ADGRPResolvedName = $ADGRPSidLookupResult.Properties["name"][0]
									$ADGRPSidBytes = $ADGRPSidLookupResult.Properties["objectSid"][0]
									try {
										$ADGRPSidObject = [System.Security.Principal.SecurityIdentifier]::new($ADGRPSidBytes, 0)
										if ($ADGRPRequiredGroups -contains $ADGRPResolvedName) { $ADGRPTranslatedGroupSids[$ADGRPResolvedName] = $ADGRPSidObject.Value }
									}
									catch { Write-Verbose "Token path: failed to construct SID for '$ADGRPResolvedName': $($_.Exception.Message)" }
								}
							}
						}
						catch {
							Write-Verbose "Token path: flat LDAP SID lookup failed: $($_.Exception.Message)"
						}
						finally {
							if ($ADGRPSidLookupResults) { $ADGRPSidLookupResults.Dispose() }
							if ($ADGRPSidLookupSearcher) { $ADGRPSidLookupSearcher.Dispose() }
						}
					}

					$ADGRPStillUnresolved = @($ADGRPRequiredGroups | Where-Object { -not $ADGRPTranslatedGroupSids.ContainsKey($_) })
					if ($ADGRPStillUnresolved.Count -gt 0) {
						Write-Verbose "Token path: unable to resolve SIDs for: $($ADGRPStillUnresolved -join ', ')"
					}

					if ($ADGRPTranslatedGroupSids.Count -eq 0) {
						Write-Verbose "Token path: no configured groups could be resolved to SIDs - falling back to scoped LDAP"
					}
					else {
						# Read the user's transitive group SIDs straight from the local Windows token. No DC traffic.
						$ADGRPCurrentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
						$ADGRPTokenSidSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
						if ($ADGRPCurrentIdentity.Groups) {
							foreach ($ADGRPTokenGroup in $ADGRPCurrentIdentity.Groups) {
								try { [void]$ADGRPTokenSidSet.Add($ADGRPTokenGroup.Value) } catch {}
							}
						}
						Write-Verbose "Token path: current identity '$($ADGRPCurrentIdentity.Name)' token contains $($ADGRPTokenSidSet.Count) group SID(s)"
						foreach ($ADGRPTokenSid in @($ADGRPTokenSidSet | Sort-Object)) {
							Write-Verbose "Token path: token SID: $ADGRPTokenSid"
						}

						# Sanity check: the token must contain at least one SID
						$ADGRPSampleSid = ($ADGRPTranslatedGroupSids.Values | Select-Object -First 1)
						$ADGRPDomainSidPrefix = $null
						if ($ADGRPSampleSid) {
							$ADGRPSidParts = $ADGRPSampleSid -split '-'
							# AD domain group SID layout: S-1-5-21-<a>-<b>-<c>-<RID> -> 8 segments, prefix = first 7
							if ($ADGRPSidParts.Count -ge 8 -and $ADGRPSidParts[0] -eq 'S' -and $ADGRPSidParts[2] -eq '5' -and $ADGRPSidParts[3] -eq '21') {
								$ADGRPDomainSidPrefix = ($ADGRPSidParts[0..6]) -join '-'
							}
						}
						$ADGRPTokenHasOnpremGroups = $false
						if ($ADGRPDomainSidPrefix) {
							foreach ($ADGRPTokenSid in $ADGRPTokenSidSet) {
								if ($ADGRPTokenSid.StartsWith("$ADGRPDomainSidPrefix-", [System.StringComparison]::OrdinalIgnoreCase)) {
									$ADGRPTokenHasOnpremGroups = $true
									break
								}
							}
						}

						if (-not $ADGRPTokenHasOnpremGroups) {
							Write-Verbose "Token path: user token has no SIDs from the on-prem domain - falling back to scoped LDAP"
						}
						else {
							# Intersect translated required-group SIDs with the token.
							foreach ($ADGRPGroupName in $ADGRPRequiredGroups) {
								if ($ADGRPTranslatedGroupSids.ContainsKey($ADGRPGroupName) -and $ADGRPTokenSidSet.Contains($ADGRPTranslatedGroupSids[$ADGRPGroupName])) {
									$ADGRPGroupMembershipList.Add($ADGRPGroupName)
								}
							}
							Write-Verbose "Token path: matched $($ADGRPGroupMembershipList.Count) of $($ADGRPRequiredGroups.Count) configured group(s) via Kerberos token (no LDAP issued)"
							return $ADGRPGroupMembershipList
						}
					}
				}
				catch {
					Write-Verbose "Token path failed unexpectedly, falling back to scoped LDAP: $($_.Exception.Message)"
				}
   }

			# If we reach this point the token path was not conclusive and we fall through to the scoped LDAP
			Write-Verbose "Falling back to scoped LDAP query for $($ADGRPRequiredGroups.Count) configured group(s)"

			# Create DirectorySearcher and find user
			$ADGRPSearcher = [System.DirectoryServices.DirectorySearcher]::new()
			$ADGRPSearcher.SearchRoot = [ADSI]"LDAP://$ADGRPDomainName"
			$ADGRPSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
			$ADGRPSearcher.ServerTimeLimit = [TimeSpan]::FromSeconds(30)
			$null = $ADGRPSearcher.PropertiesToLoad.Add("distinguishedname")
			$null = $ADGRPSearcher.PropertiesToLoad.Add("primarygroupid")
			$null = $ADGRPSearcher.PropertiesToLoad.Add("userprincipalname")
			$null = $ADGRPSearcher.PropertiesToLoad.Add("samaccountname")
			$null = $ADGRPSearcher.PropertiesToLoad.Add("mail")
			$ADGRPEscapedUPN = & $ADGRPEscapeLdap $ADGRPUserPrincipalName # Escape LDAP special characters
			$ADGRPUserLookupFilters = [System.Collections.Generic.List[object]]::new()
			$ADGRPUserLookupFilters.Add([pscustomobject]@{ Method = 'userPrincipalName'; Filter = "(&(objectCategory=person)(objectClass=user)(userprincipalname=$ADGRPEscapedUPN))" })
			$ADGRPUserLookupFilters.Add([pscustomobject]@{ Method = 'mail'; Filter = "(&(objectCategory=person)(objectClass=user)(mail=$ADGRPEscapedUPN))" })
			$ADGRPUserLookupFilters.Add([pscustomobject]@{ Method = 'proxyAddresses'; Filter = "(&(objectCategory=person)(objectClass=user)(|(proxyAddresses=smtp:$ADGRPEscapedUPN)(proxyAddresses=SMTP:$ADGRPEscapedUPN)))" })
			if ($ADGRPUserPrincipalName -like '*@*') {
				$ADGRPEscapedSam = & $ADGRPEscapeLdap (($ADGRPUserPrincipalName -split '@', 2)[0])
				$ADGRPUserLookupFilters.Add([pscustomobject]@{ Method = 'samAccountName'; Filter = "(&(objectCategory=person)(objectClass=user)(samaccountname=$ADGRPEscapedSam))" })
			}
			foreach ($ADGRPUserLookupFilter in $ADGRPUserLookupFilters) {
				$ADGRPSearcher.Filter = $ADGRPUserLookupFilter.Filter
				Write-Verbose "User lookup: trying $($ADGRPUserLookupFilter.Method) for '$ADGRPUserPrincipalName'"
				$ADGRPUserResult = $ADGRPSearcher.FindOne()
				if ($ADGRPUserResult -and $ADGRPUserResult.Properties["distinguishedname"]) {
					Write-Verbose "User lookup: matched '$ADGRPUserPrincipalName' by $($ADGRPUserLookupFilter.Method)"
					break
				}
			}
			if (-not $ADGRPUserResult -or -not $ADGRPUserResult.Properties["distinguishedname"]) {
				Write-Error "Failed to find user $ADGRPUserPrincipalName in directory by userPrincipalName, mail, proxyAddresses, or samAccountName"
				return $ADGRPGroupMembershipList
			}

			# tokenGroups approach: 2 LDAP queries total regardless of configured group count
			$ADGRPDistinguishedName = $ADGRPUserResult.Properties["distinguishedname"][0]
			$ADGRPMatchedUPN = if ($ADGRPUserResult.Properties["userprincipalname"].Count -gt 0) { $ADGRPUserResult.Properties["userprincipalname"][0] } else { '<empty>' }
			$ADGRPMatchedSam = if ($ADGRPUserResult.Properties["samaccountname"].Count -gt 0) { $ADGRPUserResult.Properties["samaccountname"][0] }   else { '<empty>' }
			$ADGRPMatchedMail = if ($ADGRPUserResult.Properties["mail"].Count -gt 0) { $ADGRPUserResult.Properties["mail"][0] }             else { '<empty>' }
			Write-Verbose "User lookup: matched DN '$ADGRPDistinguishedName' (UPN='$ADGRPMatchedUPN', sAMAccountName='$ADGRPMatchedSam', mail='$ADGRPMatchedMail')"

			# --- LDAP query 1: read tokenGroups (BASE scope on the user DN) ---
			$ADGRPTokenGroupSearcher = [System.DirectoryServices.DirectorySearcher]::new([ADSI]"LDAP://$ADGRPDomainName/$ADGRPDistinguishedName")
			$ADGRPTokenGroupSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
			$ADGRPTokenGroupSearcher.ServerTimeLimit = [TimeSpan]::FromSeconds(15)
			$ADGRPTokenGroupSearcher.Filter = '(objectClass=*)'
			$null = $ADGRPTokenGroupSearcher.PropertiesToLoad.Add('tokenGroups')
			$ADGRPTokenGroupResult = $ADGRPTokenGroupSearcher.FindOne()
			$ADGRPUserSidSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
			if ($ADGRPTokenGroupResult -and $ADGRPTokenGroupResult.Properties['tokenGroups'].Count -gt 0) {
				foreach ($ADGRPSidBytes in $ADGRPTokenGroupResult.Properties['tokenGroups']) {
					try { [void]$ADGRPUserSidSet.Add(([System.Security.Principal.SecurityIdentifier]::new($ADGRPSidBytes, 0)).Value) } catch {}
				}
			}
			$ADGRPTokenGroupSearcher.Dispose()
			Write-Verbose "Scoped LDAP: tokenGroups returned $($ADGRPUserSidSet.Count) transitive group SID(s) for user"

			if ($ADGRPUserSidSet.Count -eq 0) {
				Write-Verbose "Scoped LDAP: tokenGroups returned no SIDs - cannot verify group membership"
			}
			else {
				# --- LDAP query 2: resolve configured group names to objectSid in one query ---
				$ADGRPNameClauses = & $ADGRPBuildNameClauses $ADGRPRequiredGroups
				$ADGRPSearcher.Filter = "(&(objectCategory=group)$ADGRPNameClauses)"
				$ADGRPSearcher.PropertiesToLoad.Clear()
				$null = $ADGRPSearcher.PropertiesToLoad.Add('name')
				$null = $ADGRPSearcher.PropertiesToLoad.Add('objectSid')
				$null = $ADGRPSearcher.PropertiesToLoad.Add('samaccountname')
				Write-Verbose "Scoped LDAP: resolving $($ADGRPRequiredGroups.Count) configured group(s) to SIDs"
				Write-Verbose "Scoped LDAP: group lookup filter: $($ADGRPSearcher.Filter)"
				$ADGRPGroupsResults = $ADGRPSearcher.FindAll()
				Write-Verbose "Scoped LDAP: configured group lookup returned $($ADGRPGroupsResults.Count) group result(s)"
				foreach ($ADGRPGroupResult in $ADGRPGroupsResults) {
					$ADGRPGroupName = $ADGRPGroupResult.Properties['name']
					$ADGRPGroupSam = if ($ADGRPGroupResult.Properties['samaccountname'].Count -gt 0) { $ADGRPGroupResult.Properties['samaccountname'][0] } else { '<empty>' }
					if ($ADGRPGroupName.Count -gt 0 -and $ADGRPGroupResult.Properties['objectSid'].Count -gt 0) {
						try {
							$ADGRPGroupSidString = ([System.Security.Principal.SecurityIdentifier]::new($ADGRPGroupResult.Properties['objectSid'][0], 0)).Value
							if ($ADGRPUserSidSet.Contains($ADGRPGroupSidString)) {
								$ADGRPGroupMembershipList.Add($ADGRPGroupName[0])
								Write-Verbose "Scoped LDAP: verified membership in '$($ADGRPGroupName[0])' (sAMAccountName='$ADGRPGroupSam', SID=$ADGRPGroupSidString)"
							}
							else { Write-Verbose "Scoped LDAP: user is not a member of '$($ADGRPGroupName[0])' (sAMAccountName='$ADGRPGroupSam', SID=$ADGRPGroupSidString)" }
						}
						catch { Write-Verbose "Scoped LDAP: failed to parse SID for '$($ADGRPGroupName[0])': $($_.Exception.Message)" }
					}
				}
			}
			# Diagnostic: log configured groups that were not found in AD at all
			$ADGRPUnresolvedGroups = @($ADGRPRequiredGroups | Where-Object { $_ -notin $ADGRPGroupMembershipList })
			if ($ADGRPUnresolvedGroups.Count -gt 0) {
				Write-Verbose "Scoped LDAP: membership not verified for configured group(s): $($ADGRPUnresolvedGroups -join ', ')"
			}

			if ($ADGRPGroupMembershipList.Count -gt 0) {
				Write-Verbose "Success to collect user group memberships, found $($ADGRPGroupMembershipList.Count) groups"
			}
			else { Write-Verbose "No group memberships found for user $ADGRPUserPrincipalName" }
			return $ADGRPGroupMembershipList
		}
		catch {
			Write-Error "Failed to collect user group memberships with error: $_"
			return $ADGRPGroupMembershipList
		}
	}

	end {
		Write-Verbose "-- END Function $($MyInvocation.MyCommand.Name) --"
		# Dispose unmanaged resources to prevent memory leaks.
		if ($ADGRPGroupsResults) { $ADGRPGroupsResults.Dispose() }
		if ($ADGRPSearcher) { $ADGRPSearcher.Dispose() }
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
		$PrinterCim = $null
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
			catch { Write-Warning "Failed to query existing printer state: $_" }
			finally { if ($PrinterCim) { Remove-Variable -Name PrinterCim -ErrorAction SilentlyContinue } }

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
					}
					else { Write-Warning "Failed to get namespace for drive '$DriveLetter`:' to set label" }
				}
				catch { Write-Warning "Failed to set drive '$DriveLetter`:' label to '$DriveLabel' with error: $_" }
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

function Register-NewScheduledTask {
	<#
.SYNOPSIS
	Creates (or replaces) a Windows scheduled task in a universal, reusable way.
.DESCRIPTION
	Wraps Register-ScheduledTask with a simple parameter set covering the most
	common triggers (AtLogon, AtStartup, OnEvent), action (executable + arguments),
	principal (user SID, group SID or built-in account) and common settings.
.NOTES
	Author:  @MrTbone_se (T-bone Granheden)
	Version: 1.2
	Version History:
	1.0 - Initial stub
	1.1 - Universal implementation
	1.2 - Renamed from New-ScheduledTask to Register-NewScheduledTask to avoid collision with the built-in ScheduledTasks\New-ScheduledTask cmdlet.
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
		[bool]$TaskTriggerAtLogon = $false,

		[Parameter(Mandatory = $false, HelpMessage = "Delay in seconds for the AtLogon trigger")]
		[ValidateRange(0, 3600)]
		[int]$TaskTriggerAtLogonDelaySeconds = 0,

		[Parameter(Mandatory = $false, HelpMessage = "Add an AtStartup trigger to the scheduled task")]
		[bool]$TaskTriggerAtStartup = $false,

		[Parameter(Mandatory = $false, HelpMessage = "Add an event trigger that fires when a network profile becomes connected (NetworkProfile/Operational EventID 10000)")]
		[bool]$TaskTriggerAtNetConnect = $false,

		[Parameter(Mandatory = $false, HelpMessage = "One or more XML event subscriptions used to create event triggers")]
		[string[]]$TaskTriggerEventSubscription,

		[Parameter(Mandatory = $false, HelpMessage = "Optional pre-built scheduled task settings object")]
		[Microsoft.Management.Infrastructure.CimInstance]$TaskSettings,

		[Parameter(Mandatory = $false, HelpMessage = "Create the task as hidden in Task Scheduler")]
		[bool]$TaskHidden = $false,

		[Parameter(Mandatory = $false, HelpMessage = "Start the task immediately after registration")]
		[bool]$TaskStartImmediately = $false,

		[Parameter(Mandatory = $false, HelpMessage = "Overwrite an existing task registration with the same name")]
		[bool]$TaskForce = $false
	)

	try {
		write-Verbose "-- BEGIN Function $($MyInvocation.MyCommand.Name) --"
		# Build triggers
		$TaskTriggers = @()
		if ($TaskTriggerAtLogon) {
			$TaskLogonTrigger = New-ScheduledTaskTrigger -AtLogOn
			if ($TaskTriggerAtLogonDelaySeconds -gt 0) {
				$TaskLogonTrigger.Delay = [System.Xml.XmlConvert]::ToString([TimeSpan]::FromSeconds($TaskTriggerAtLogonDelaySeconds))
				Write-Verbose "AtLogon trigger delay set to $TaskTriggerAtLogonDelaySeconds seconds"
			}
			$TaskTriggers += $TaskLogonTrigger
		}
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
		if ($TaskPrincipalGroupSid) { $TaskPrincipal = New-ScheduledTaskPrincipal -GroupId $TaskPrincipalGroupSid -Id 'Author' }
		elseif ($TaskPrincipalUserId) { $TaskPrincipal = New-ScheduledTaskPrincipal -UserId $TaskPrincipalUserId -LogonType $TaskLogonType -RunLevel $TaskRunLevel }
		else { $TaskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest }

		# Build action
		$TaskActionParams = @{ Execute = $TaskExecute }
		if ($TaskArgument) { $TaskActionParams.Argument = $TaskArgument }
		if ($TaskWorkingDirectory) { $TaskActionParams.WorkingDirectory = $TaskWorkingDirectory }
		$TaskAction = New-ScheduledTaskAction @TaskActionParams

		# Build settings (default if not supplied)
		if (-not $TaskSettings) {
			$TaskSettingsParams = @{
				AllowStartIfOnBatteries    = $true
				DontStopIfGoingOnBatteries = $true
			}
			if ($TaskHidden) { $TaskSettingsParams.Hidden = $true }
			$TaskSettings = New-ScheduledTaskSettingsSet @TaskSettingsParams
		}
		elseif ($TaskHidden) { $TaskSettings.Hidden = $true }

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
		if ($TaskForce) { $TaskRegisterParams.Force = $true }
		$null = Register-ScheduledTask @TaskRegisterParams
		Write-Verbose "Scheduled task '$TaskName' registered"

		# When task runs as BUILTIN\Users, grant Users read+execute so non-admins can trigger the task on demand
		if ($TaskPrincipalGroupSid -eq 'S-1-5-32-545') {
			try {
				$TaskService = New-Object -ComObject 'Schedule.Service'
				$TaskService.Connect()
				$RegisteredTask = $TaskService.GetFolder('\').GetTask($TaskName)
				$TaskDaclSddl = $RegisteredTask.GetSecurityDescriptor(4)
				if ($TaskDaclSddl -notmatch '\(A;;FRFX;;;BU\)') {
					$UpdatedTaskDaclSddl = if ($TaskDaclSddl -match '\(A;;FR;;;BU\)') {
						$TaskDaclSddl -replace '\(A;;FR;;;BU\)', '(A;;FRFX;;;BU)'
					}
					elseif ($TaskDaclSddl -like 'D:*') {
						$TaskSaclIndex = $TaskDaclSddl.IndexOf('S:')
						if ($TaskSaclIndex -ge 0) { $TaskDaclSddl.Insert($TaskSaclIndex, '(A;;FRFX;;;BU)') }
						else { $TaskDaclSddl + '(A;;FRFX;;;BU)' }
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
		Write-Verbose "-- END Function $($MyInvocation.MyCommand.Name) --"
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
	1.1 - Tighter wscript boundary, stricter CorpData fallback, single-shot regex match, pre-compiled patterns, gated logs-folder tracking, pre-computed sort key
#>
	[CmdletBinding(SupportsShouldProcess)]
	param(
		[Parameter(Mandatory = $true, HelpMessage = "Object type the current deployment manages ('Drive' or 'Printer'); only legacies of this type are removed")]
		[ValidateSet('Drive', 'Printer')]
		[string]$ObjectType
	)
	begin {
		Write-Verbose "-- BEGIN Function $($MyInvocation.MyCommand.Name) --"
		# Markers used to confirm that a discovered .ps1 belongs to one of our legacy mapping scripts
		$LegacyContentMarker = 'IntuneDriveMapping|IntunePrinterMapping|MapDrivesCloudNative|MapPrintersCloudNative|Map-DrivesCloudNative|Map-PrintersCloudNative|CorpDataPath'
		# Markers used to classify a confirmed legacy .ps1 as Drive vs Printer (mapping-table signature first, then function calls)
		$DriveTableMarker = '@\{\s*Letter\b'
		$PrinterTableMarker = '@\{\s*PrinterName\b'
		$DriveCallMarker = 'New-PSDrive\b|New-DriveMapping\b|New-SmbMapping\b'
		$PrinterCallMarker = 'Add-Printer\b|New-PrinterMapping\b'
		# Pattern used to extract hardcoded MSI/Win32 ARP GUIDs from confirmed legacy .ps1 content
		$LegacyGuidPattern = '\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}'
		# Filename heuristic for the CorpData\scripts fallback when a sibling .ps1 is missing
		$LegacyNameHeuristic = 'Map.*Drive|Map.*Printer|Mapping'
		# Pre-compiled regex patterns for first .vbs token extraction from task arguments
		$VbsQuotedPattern = [regex]::new('"([^"]+\.vbs)"', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
		$VbsUnquotedPattern = [regex]::new('(?:^|\s)([^\s"]+\.vbs)(?:\s|$)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
		# State counters and case-insensitive sets accumulated during removal
		$RemovedTasks = 0
		$RemovedFiles = 0
		$RemovedArp = 0
		$LegacyFolders = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
		$LegacyArpGuids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
	}
	process {
		# =================== PHASE 1: ENUMERATE ===================
		# Build a list of legacy candidates (one per scheduled task whose action is wscript+vbs)
		$LegacyCandidates = [System.Collections.Generic.List[object]]::new()

		$LegacyTasks = @()
		try {
			$LegacyTasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
					$hit = $false
					foreach ($action in $_.Actions) {
						# Skip non-Exec actions (COM handler, email, message box) - they have no Execute/Arguments and would throw under StrictMode
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
			# Pull the first quoted .vbs path from the task arguments, or fall back to an unquoted token
			$taskArguments = ($legacyTask.Actions | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskExecAction' } | ForEach-Object { [string]$_.Arguments }) -join ' '
			$legacyVbsPath = $null
			$vbsMatch = $VbsQuotedPattern.Match($taskArguments)
			if ($vbsMatch.Success) { $legacyVbsPath = $vbsMatch.Groups[1].Value }
			else {
				$vbsMatch = $VbsUnquotedPattern.Match($taskArguments)
				if ($vbsMatch.Success) { $legacyVbsPath = $vbsMatch.Groups[1].Value }
			}
			if ([string]::IsNullOrWhiteSpace($legacyVbsPath)) { continue }

			$legacyVbsDir = Split-Path -Path $legacyVbsPath -Parent
			$legacyVbsBase = [System.IO.Path]::GetFileNameWithoutExtension($legacyVbsPath)
			if ([string]::IsNullOrWhiteSpace($legacyVbsDir) -or [string]::IsNullOrWhiteSpace($legacyVbsBase)) { continue }

			# Derive matching .ps1 from the same folder. Prefer same basename, fall back to any *Mapping.ps1 sibling
			$legacyPs1Path = Join-Path -Path $legacyVbsDir -ChildPath "$legacyVbsBase.ps1"
			if (-not (Test-Path -LiteralPath $legacyPs1Path -PathType Leaf)) {
				$alternatePs1 = @(Get-ChildItem -LiteralPath $legacyVbsDir -Filter '*Mapping.ps1' -File -Force -ErrorAction SilentlyContinue)
				if ($alternatePs1.Count -gt 0) { $legacyPs1Path = $alternatePs1[0].FullName }
			}

			# Confirm via known markers and capture content for type classification and GUID extraction
			$legacyConfirmed = $false
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

			# Classify object type: task name -> .ps1 filename -> .vbs filename -> .ps1 content (mapping table, then function calls)
			$legacyType = $null
			$taskNameTxt = [string]$legacyTask.TaskName
			$ps1NameTxt = if ($legacyPs1Path) { [System.IO.Path]::GetFileNameWithoutExtension($legacyPs1Path) } else { '' }
			if ($taskNameTxt -match 'Printer') { $legacyType = 'Printer' }
			elseif ($taskNameTxt -match 'Drive') { $legacyType = 'Drive' }
			elseif ($ps1NameTxt -match 'Printer') { $legacyType = 'Printer' }
			elseif ($ps1NameTxt -match 'Drive') { $legacyType = 'Drive' }
			elseif ($legacyVbsBase -match 'Printer') { $legacyType = 'Printer' }
			elseif ($legacyVbsBase -match 'Drive') { $legacyType = 'Drive' }
			elseif ($legacyPs1Content) {
				if ($legacyPs1Content -match $DriveTableMarker) { $legacyType = 'Drive' }
				elseif ($legacyPs1Content -match $PrinterTableMarker) { $legacyType = 'Printer' }
				elseif ($legacyPs1Content -match $DriveCallMarker) { $legacyType = 'Drive' }
				elseif ($legacyPs1Content -match $PrinterCallMarker) { $legacyType = 'Printer' }
			}
			if (-not $legacyType) {
				Write-Verbose "Skipping task '$($legacyTask.TaskName)' - unable to classify as Drive or Printer"
				continue
			}

			# Extract hardcoded ARP GUIDs from the .ps1 content (if any)
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

		# Filter to only candidates whose object type matches the current deployment
		$MatchedCandidates = @($LegacyCandidates | Where-Object { $_.LegacyType -eq $ObjectType })
		$UnmatchedCount = $LegacyCandidates.Count - $MatchedCandidates.Count
		if ($UnmatchedCount -gt 0) { Write-Verbose "Leaving $UnmatchedCount legacy task(s) intact - they map a different object type than the current deployment ('$ObjectType')" }
		if ($MatchedCandidates.Count -eq 0) {
			Write-Verbose "No legacy '$ObjectType' artifacts detected"
			return
		}
		Write-Verbose "Discovered $($MatchedCandidates.Count) legacy '$ObjectType' candidate(s) for removal"

		# =================== PHASE 2: REMOVE TASKS + FILES ===================
		foreach ($candidate in $MatchedCandidates) {
			# Unregister the legacy scheduled task
			if ($PSCmdlet.ShouldProcess($candidate.TaskName, 'Remove legacy scheduled task')) {
				try {
					Unregister-ScheduledTask -TaskName $candidate.TaskName -TaskPath $candidate.TaskPath -Confirm:$false -ErrorAction Stop
					$RemovedTasks++
					Write-Verbose "Removed legacy scheduled task '$($candidate.TaskName)' [$($candidate.LegacyType)]"
				}
				catch { Write-Warning "Failed to remove legacy scheduled task '$($candidate.TaskName)'. Error: $_" }
			}

			# Collect ARP GUIDs across all matched candidates for the next phase
			foreach ($guid in $candidate.ArpGuids) { [void]$LegacyArpGuids.Add($guid) }

			# Remove staged files: .vbs, derived .ps1, optional .version next to it
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

			# Track folders for empty-folder cleanup, and remove sibling logs that match the legacy basename
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
			$legacyDisplayName = [string]$legacyArpProps.DisplayName
			if ([string]::IsNullOrWhiteSpace($legacyDisplayName)) {
				if (-not [string]::IsNullOrWhiteSpace($legacyInstallLocation)) { $legacyDisplayName = Split-Path -Path $legacyInstallLocation -Leaf }
				else { $legacyDisplayName = $legacyArpGuid }
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
		# Pre-compute path depth so Sort-Object doesn't reinvoke a script block per comparison
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
		Write-Verbose "-- END Function $($MyInvocation.MyCommand.Name) --"
		if ($RemovedTasks -eq 0 -and $RemovedFiles -eq 0 -and $RemovedArp -eq 0) { Write-Verbose "No legacy '$ObjectType' mapping artifacts detected" }
		else { Write-Verbose "Legacy '$ObjectType' cleanup summary: tasks=$RemovedTasks files=$RemovedFiles arp=$RemovedArp" }
	}
}

function Show-ProgressGUI {
	<#
.SYNOPSIS
	Displays a dark-themed GUI window that executes a list of steps and reports per-step status.
.DESCRIPTION
	Runs named scriptblock steps in a dark-themed WinForms progress window with per-step status colors
	Collects warning/error output from action streams and the global $_l log buffer for review
	Auto-closes on success; on warnings/errors shows OK, hides the console on Windows, and falls back silently when GUI is unavailable
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
	1.1 - Cross-platform safe console-hide guard, dispose WinForms resources, List-backed control collections, accurate help text, distinct warning vs. error labels, single shared silent runner
	1.2 - Shared color palette and fonts, single row-builder helper for initial and appended steps, shared fonts disposed in finally
#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $false, HelpMessage = 'Window title text shown in the title bar')]
		[string]$Title = "Setup Progress",

		[Parameter(Mandatory = $false, HelpMessage = 'Large heading text shown inside the window')]
		[string]$Heading = "Running Setup...",

		[Parameter(Mandatory = $false, HelpMessage = 'Optional persistent status text shown below the heading and above the step list')]
		[string]$TopStatusMessage = '',

		[Parameter(Mandatory = $true, HelpMessage = 'Array of step objects with Name and Action keys to execute and display')]
		[hashtable[]]$Steps,

		[Parameter(Mandatory = $false, HelpMessage = 'Optional scriptblock returning additional step hashtables to append and run in the SAME window after the initial steps finish')]
		[scriptblock]$AdditionalStepsProvider,

		[Parameter(Mandatory = $false, HelpMessage = 'Keep the original heading text after completion instead of replacing it with a summary state')]
		[switch]$KeepHeading,

		[Parameter(Mandatory = $false, HelpMessage = 'Suppress the GUI and run the supplied steps silently instead')]
		[switch]$NoGUI
	)

	# Validate step structure once up front so both -NoGUI and the GUI path get identical behaviour
	Write-Verbose "--- BEGIN Function $($MyInvocation.MyCommand.Name) ---"
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

	# Silent runner shared by -NoGUI and the WinForms-load-failure fallback path
	$RunStepsSilently = {
		foreach ($step in $Steps) {
			Write-Verbose "[$($step.Name)] Starting..."
			try { & $step.Action; Write-Verbose "[$($step.Name)] Done." }
			catch { Write-Error "[$($step.Name)] Failed: $_"; return }
		}
	}

	if ($NoGUI) {
		Write-Verbose "NoGUI is set. Running steps silently."
		& $RunStepsSilently
		return
	}

	# Console-hide is Windows-only: the kernel32/user32 P/Invoke would crash on PS 7 on Linux/macOS
	$onWindows = ([Environment]::OSVersion.Platform -eq 'Win32NT')
	if ($onWindows) {
		if (([System.Management.Automation.PSTypeName]'ConsoleWindow').Type) {
			try { [ConsoleWindow]::ShowWindow([ConsoleWindow]::GetConsoleWindow(), 0) | Out-Null } catch { Write-Verbose "ShowWindow call failed: $_" }
		}
	}

	# Load WinForms assemblies (only when GUI is requested). On any failure run silently instead
	foreach ($asm in @('System.Windows.Forms', 'System.Drawing')) {
		try {
			Add-Type -AssemblyName $asm -ErrorAction Stop
		}
		catch {
			Write-Warning "Assembly '$asm' failed to load - falling back to silent execution. Error: $_"
			& $RunStepsSilently
			return
		}
	}

	# Dark-theme palette and shared fonts. Created once and reused by every control (fewer GDI
	$C = @{
		Bg       = [System.Drawing.Color]::FromArgb(30, 30, 30)
		Panel    = [System.Drawing.Color]::FromArgb(20, 20, 20)
		Btn      = [System.Drawing.Color]::FromArgb(60, 60, 60)
		White    = [System.Drawing.Color]::White
		Grey     = [System.Drawing.Color]::FromArgb(140, 140, 140)
		Running  = [System.Drawing.Color]::FromArgb(255, 200, 50)
		Green    = [System.Drawing.Color]::FromArgb(80, 200, 120)
		Orange   = [System.Drawing.Color]::FromArgb(255, 165, 0)
		Amber    = [System.Drawing.Color]::FromArgb(220, 180, 80)
		RedStep  = [System.Drawing.Color]::FromArgb(220, 80, 80)
		RedMsg   = [System.Drawing.Color]::FromArgb(220, 120, 120)
		Info     = [System.Drawing.Color]::FromArgb(180, 200, 240)
		WarnHead = [System.Drawing.Color]::FromArgb(220, 160, 50)
	}
	$F = @{
		Heading = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
		Step    = New-Object System.Drawing.Font("Segoe UI", 10)
		Msg     = New-Object System.Drawing.Font("Consolas", 8)
	}

	# Create the main form and set properties for a dark-themed progress window
	$form = New-Object System.Windows.Forms.Form
	try {
		$script:ProgressGUICancelRequested = $false
		$ProgressGUIState = [pscustomobject]@{ AllowClose = $false }
		$form.Text = $Title
		$form.ClientSize = New-Object System.Drawing.Size(510, 495)
		$form.StartPosition = "CenterScreen"
		$form.FormBorderStyle = "FixedDialog"
		$form.MaximizeBox = $false
		$form.MinimizeBox = $false
		$form.BackColor = $C.Bg
		$form.ForeColor = $C.White
		# Heading label at the top of the form
		$lblTitle = New-Object System.Windows.Forms.Label
		$lblTitle.Text = $Heading
		$lblTitle.Font = $F.Heading
		$lblTitle.ForeColor = $C.White
		$lblTitle.Location = New-Object System.Drawing.Point(20, 15)
		$lblTitle.Size = New-Object System.Drawing.Size(470, 30)
		$form.Controls.Add($lblTitle)
		# Optional persistent status line shown below the heading
		$topStatusLabel = New-Object System.Windows.Forms.Label
		$topStatusLabel.Text = $TopStatusMessage
		$topStatusLabel.Font = $F.Msg
		$topStatusLabel.ForeColor = $C.Green
		$topStatusLabel.AutoSize = $true
		$topStatusLabel.MaximumSize = New-Object System.Drawing.Size(470, 0)
		$topStatusLabel.Location = New-Object System.Drawing.Point(20, 48)
		$topStatusLabel.Visible = -not [string]::IsNullOrWhiteSpace($TopStatusMessage)
		$form.Controls.Add($topStatusLabel)
		# The steps panel is positioned below the heading and optional status line, and its height is adjusted based on whether the status line is visible
		$stepsPanelTop = if ($topStatusLabel.Visible) { 82 }  else { 55 }
		$stepsPanelHeight = if ($topStatusLabel.Visible) { 353 } else { 380 }
		# Scrolling panel that holds the step rows
		$stepsPanel = New-Object System.Windows.Forms.FlowLayoutPanel
		$stepsPanel.Location = New-Object System.Drawing.Point(20, $stepsPanelTop)
		$stepsPanel.Size = New-Object System.Drawing.Size(470, $stepsPanelHeight)
		$stepsPanel.BackColor = $C.Panel
		$stepsPanel.BorderStyle = "FixedSingle"
		$stepsPanel.FlowDirection = "TopDown"
		$stepsPanel.WrapContents = $false
		$stepsPanel.AutoScroll = $true
		$stepsPanel.Padding = New-Object System.Windows.Forms.Padding(6, 6, 6, 6)
		$form.Controls.Add($stepsPanel)
		# Helper for initial and added step rows
		$rowWidth = 430
		$stepLabels = [System.Collections.Generic.List[System.Windows.Forms.Label]]::new()
		$msgLabels = [System.Collections.Generic.List[System.Windows.Forms.Label]]::new()
		$AddStepRow = {
			param([string]$StepName)
			$rowLbl = New-Object System.Windows.Forms.Label
			$rowLbl.Text = "* $StepName"
			$rowLbl.Font = $F.Step
			$rowLbl.ForeColor = $C.Grey
			$rowLbl.AutoSize = $true
			$rowLbl.MaximumSize = New-Object System.Drawing.Size($rowWidth, 0)
			$rowLbl.Margin = New-Object System.Windows.Forms.Padding(0, 4, 0, 0)
			$stepsPanel.Controls.Add($rowLbl)
			$stepLabels.Add($rowLbl)
			$rowMsg = New-Object System.Windows.Forms.Label
			$rowMsg.Font = $F.Msg
			$rowMsg.ForeColor = $C.Amber
			$rowMsg.AutoSize = $true
			$rowMsg.MaximumSize = New-Object System.Drawing.Size(($rowWidth - 20), 0)
			$rowMsg.Margin = New-Object System.Windows.Forms.Padding(24, 1, 0, 0)
			$rowMsg.Visible = $false
			$stepsPanel.Controls.Add($rowMsg)
			$msgLabels.Add($rowMsg)
		}
		$stepsPanel.SuspendLayout()
		foreach ($step in $Steps) { & $AddStepRow $step.Name }
		$stepsPanel.ResumeLayout()
		# OK button - hidden until errors or warnings occur, then revealed for user dismissal
		$btnOK = New-Object System.Windows.Forms.Button
		$btnOK.Text = "OK"
		$btnOK.Location = New-Object System.Drawing.Point(390, 445)
		$btnOK.Size = New-Object System.Drawing.Size(100, 28)
		$btnOK.BackColor = $C.Btn
		$btnOK.ForeColor = $C.White
		$btnOK.FlatStyle = "Flat"
		$btnOK.Visible = $false
		$btnOK.Add_Click({ $ProgressGUIState.AllowClose = $true; $form.Close() })
		$form.Controls.Add($btnOK)
		$form.Add_FormClosing({
				param($formSender, $closingArgs)
				if (-not $ProgressGUIState.AllowClose -and $closingArgs.CloseReason -eq [System.Windows.Forms.CloseReason]::UserClosing) {
					$script:ProgressGUICancelRequested = $true
					$closingArgs.Cancel = $true
					$lblTitle.ForeColor = $C.Orange
					$lblTitle.Text = "Cancelling..."
					$form.Refresh()
				}
			})

		# Run the steps when the form is shown, updating each row's color and text by outcome
		$form.Add_Shown({
				$errorCount = 0
				$warnCount = 0
				$providerInvoked = $false
				# Growable queue so a second phase (e.g. mapping steps) can be appended and run in the same window
				$stepList = [System.Collections.Generic.List[hashtable]]::new()
				foreach ($initialStep in $Steps) { $stepList.Add($initialStep) }

				$i = 0
				while ($true) {
					if ($i -ge $stepList.Count) {
						if ($providerInvoked -or -not $AdditionalStepsProvider) { break }
						$providerInvoked = $true
						if (-not $script:ProgressGUICancelRequested) {
							$extraSteps = @()
							try { $extraSteps = @(& $AdditionalStepsProvider) }
							catch { Write-Verbose "AdditionalStepsProvider failed: $($_.Exception.Message)" }
							foreach ($extraStep in $extraSteps) {
								if ($extraStep -is [hashtable] -and $extraStep.ContainsKey('Name') -and $extraStep.ContainsKey('Action') -and $extraStep.Action -is [scriptblock]) {
									$stepList.Add($extraStep)
									& $AddStepRow $extraStep.Name
								}
							}
						}
						if ($i -ge $stepList.Count) { break }
					}
					if ($script:ProgressGUICancelRequested) { break }
					$step = $stepList[$i]
					$stepLabel = $stepLabels[$i]
					$msgLabel = $msgLabels[$i]

					$stepLabel.ForeColor = $C.Running
					$stepLabel.Text = "* $($step.Name) - running..."
					$stepsPanel.ScrollControlIntoView($stepLabel)
					$form.Refresh()

					$stepHasError = $false
					$stepHasWarning = $false
					$stepMessages = [System.Collections.Generic.List[string]]::new()

					# Snapshot the global log buffer so we can detect ERROR/WARN entries written by the step
					$logBefore = if ($global:_l) { $global:_l.Count } else { 0 }
					$previousProgressStatusCallback = if (Test-Path -Path 'variable:script:ProgressGUIStatusCallback') { $script:ProgressGUIStatusCallback } else { $null }
					$script:ProgressGUIStatusCallback = {
						param([string]$Message, [string]$State = 'Info')
						if ([string]::IsNullOrWhiteSpace($Message)) { return }
						$msgLabel.ForeColor = switch ($State) {
							'Waiting' { $C.Amber; break }
							'Success' { $C.Green; break }
							'Warning' { $C.Orange; break }
							default { $C.Info }
						}
						$msgLabel.Text = $Message
						$msgLabel.Visible = $true
						$stepsPanel.ScrollControlIntoView($msgLabel)
						$form.Refresh()
						[System.Windows.Forms.Application]::DoEvents()
						if ($script:ProgressGUICancelRequested) { throw [System.OperationCanceledException]::new("User cancelled $Title") }
					}
					try {
						$rawOutput = & $step.Action 2>&1 3>&1
						foreach ($item in $rawOutput) {
							if ($item -is [System.Management.Automation.WarningRecord]) {
								$stepMessages.Add($item.Message); $stepHasWarning = $true
							}
							elseif ($item -is [System.Management.Automation.ErrorRecord]) {
								$stepMessages.Add($item.Exception.Message); $stepHasError = $true
							}
						}
					}
					catch { $stepMessages.Add($_.Exception.Message); $stepHasError = $true }
					finally {
						if ($null -ne $previousProgressStatusCallback) { $script:ProgressGUIStatusCallback = $previousProgressStatusCallback }
						else { Remove-Variable -Scope Script -Name ProgressGUIStatusCallback -ErrorAction SilentlyContinue }
					}
					if ($script:ProgressGUICancelRequested) {
						$stepLabel.ForeColor = $C.Orange
						$stepLabel.Text = "* $($step.Name) - cancelled"
						$msgLabel.ForeColor = $C.Amber
						$msgLabel.Text = "Cancelled by user. No further steps will run."
						$msgLabel.Visible = $true
						$form.Refresh()
						break
					}

					# Harvest ERROR/WARN messages written to the global log buffer during this step
					if ($global:_l -and $global:_l.Count -gt $logBefore) {
						for ($li = $logBefore; $li -lt $global:_l.Count; $li++) {
							$entry = $global:_l[$li]
							if ($entry -match ',ERROR,[^,]*,[^,]*,(.*)$') {
								$stepMessages.Add($Matches[1]); $stepHasError = $true
							}
							elseif ($entry -match ',WARN,[^,]*,[^,]*,(.*)$') {
								$stepMessages.Add($Matches[1]); $stepHasWarning = $true
							}
						}
					}
					# Colour the row by outcome and accumulate counters for the final summary
					if ($stepHasError) {
						$errorCount++
						$stepLabel.ForeColor = $C.RedStep
						$stepLabel.Text = "* $($step.Name) - Failed"
						$msgLabel.ForeColor = $C.RedMsg
						$msgLabel.Text = ($stepMessages -join [Environment]::NewLine)
						$msgLabel.Visible = $true
					}
					elseif ($stepHasWarning) {
						$warnCount++
						$stepLabel.ForeColor = $C.Orange
						$stepLabel.Text = "* $($step.Name) - Completed with warnings"
						$msgLabel.ForeColor = $C.Amber
						$msgLabel.Text = ($stepMessages -join [Environment]::NewLine)
						$msgLabel.Visible = $true
					}
					else {
						$stepLabel.ForeColor = $C.Green
						$stepLabel.Text = "* $($step.Name) - successful"
					}
					$form.Refresh()
					[System.Windows.Forms.Application]::DoEvents()
					$i++
				}
				if ($script:ProgressGUICancelRequested) {
					$lblTitle.ForeColor = $C.Orange
					$lblTitle.Text = "Cancelled"
					$form.Refresh()
					Start-Sleep -Milliseconds 350
					$ProgressGUIState.AllowClose = $true
					$form.Close()
				}
				elseif ($errorCount -gt 0) {
					$lblTitle.ForeColor = $C.RedStep
					if (-not $KeepHeading) { $lblTitle.Text = "Completed with errors" }
					$btnOK.Visible = $true
					$form.Refresh()
				}
				elseif ($warnCount -gt 0) {
					$lblTitle.ForeColor = $C.WarnHead
					if (-not $KeepHeading) { $lblTitle.Text = "Completed with warnings" }
					$btnOK.Visible = $true
					$form.Refresh()
				}
				else {
					$lblTitle.Text = "Complete!"
					$form.Refresh()
					Start-Sleep -Seconds 1
					$ProgressGUIState.AllowClose = $true
					$form.Close()
				}
			})
		[void]$form.ShowDialog()
		if ($script:ProgressGUICancelRequested) { throw [System.OperationCanceledException]::new("User cancelled $Title") }
	}
	finally {
		Remove-Variable -Scope Script -Name ProgressGUICancelRequested -ErrorAction SilentlyContinue
		if ($form) { try { $form.Dispose() } catch { Write-Verbose "Form Dispose failed: $_" } }
		if ($F) { foreach ($sharedFont in $F.Values) { try { $sharedFont.Dispose() } catch {} } }
		Write-Verbose "-- END Function $($MyInvocation.MyCommand.Name) --"
	}
}
#endregion

#region ---------------------------------------------------[[Reusable workflow scriptblocks]----------------------------------------
# ====================> InstallScript (Runs only from Remediate, Intunewin, and elevated Manual installs and reinstalls)===============================================
$InstallScript = {
	Write-Host "===== INSTALLING $ARPAppName ====="
	#=================== PHASE 1: REMOVE LEGACY ARTIFACTS ===================
	# Replace legacy Mr T-Bone mapping script V1 and V2 if the flag is set (caller has already verified canInstall before invoking $InstallScript)
	if ($ReplaceOldV1andV2) { Remove-LegacyV1V2Artifacts -ObjectType $ObjectType }
	#=================== PHASE 2: STAGE RUNTIME FILES ===================
	try {
		$null = New-Item -ItemType Directory -Path (Split-Path $APPScriptPath -Parent) -Force -ErrorAction Stop
		$InstallScriptReader = $null
		try {
			$InstallScriptReader = [System.IO.StreamReader]::new($PSCommandPath, $true)
			$InstallScriptContent = $InstallScriptReader.ReadToEnd()
			[System.IO.File]::WriteAllText($APPScriptPath, $InstallScriptContent, [System.Text.UTF8Encoding]::new($true))
		}
		finally { If ($InstallScriptReader) { $InstallScriptReader.Dispose() } }
		[System.IO.File]::WriteAllText($TaskLauncherPath, $TaskLauncherContent, [System.Text.Encoding]::ASCII)
		$null = New-Item -ItemType Directory -Path (Split-Path $APPShortcutPath -Parent) -Force -ErrorAction Stop
		[System.IO.File]::WriteAllText($APPShortcutPath, $APPShortcutContent, [System.Text.Encoding]::ASCII)
		Set-Content -Path $APPVersionPath -Value $MappingVersion.ToString() -Force -ErrorAction Stop
	}
	catch { Write-Error "Failed to stage install runtime files. Error: $_"; $script:ScriptExitCode = 5; return $false }
	#================== PHASE 3: REGISTER TASK AND ARP ===================
	$taskRegistered = Register-NewScheduledTask `
		-TaskName              			$TaskName `
		-TaskDescription       			$TaskDescription `
		-TaskExecute           			"$env:SystemRoot\System32\wscript.exe" `
		-TaskArgument          			"`"$TaskLauncherPath`" `"$APPScriptPath`"" `
		-TaskPrincipalGroupSid 			$TaskPrincipalGroupSid `
		-TaskTriggerAtLogon				$TaskTriggerAtLogon `
		-TaskTriggerAtLogonDelaySeconds	$TaskTriggerAtLogonDelaySeconds `
		-TaskTriggerAtNetConnect		$TaskTriggerAtNetConnect `
		-TaskHidden 					$true `
		-TaskForce 						$true `
		-TaskStartImmediately 			$true
	if (-not $taskRegistered) { Write-Error "Failed to register scheduled task"; $script:ScriptExitCode = 4; return $false }
	$arpRegistered = Add-AddRemovePrograms `
		-ARPAppName					$ARPAppName `
		-ARPAppVersion				$ARPAppVersion `
		-ARPAppGuid					$ARPAppGuid `
		-ARPAppPublisher			$ARPAppPublisher `
		-ARPAppFolder				$ARPAppFolder `
		-ARPAppHideUninstall		$ARPAppHideUninstall `
		-ARPAppHideModify			$ARPAppHideModify `
		-ARPAppHidden				$ARPAppHidden `
		-ARPAppIconB64				$ARPAppIconB64 `
		-ARPAppIconTextColor		$ARPAppIconTextColor `
		-ARPAppIconBackground		$ARPAppIconBackground `
		-ARPAppCustomIconB64		$ARPAppCustomIconB64 `
		-ARPAppIconPath				$ARPAppIconPath `
		-ARPAppInstallScript		$ARPAppInstallScript `
		-ARPAppUnInstallScript		$ARPAppUnInstallScript `
		-ARPAppIncludeFolder		$ARPAppIncludeFolder `
		-ARPAppUserStartFile		$EffectiveStartFile `
		-ARPAppShortcutOnDesktop	$ARPAppShortcutOnDesktop `
		-ARPAppShortcutInStart		$ARPAppShortcutInStart `
		-ARPAppForce ($ARPAppForce -or $forceReinstall)
	if (-not $arpRegistered) { Write-Error "Failed to register Add/Remove Programs entry"; $script:ScriptExitCode = 6; return $false }
	return $true
}

# ====================> WorkflowScript (Resolves AD groups, builds Steps, optionally removes stale objects and runs the mapping with or without GUI) ==================
$WorkflowScript = {
	#=================== PHASE 1: RESOLVE AD GROUPS ===================
	param([bool]$ShowGui)
	Write-Host "===== WORKFLOW $ARPAppName ====="
	$ADGRPState = [pscustomobject]@{ DCOk = $false; UserGroups = @() }
	$ADGRPProgressBarWidth = 60

	# Push a status line to the active GUI step row; a no-op during silent (-NoGUI) runs
	$ReportStatus = {
		param([string]$Message, [string]$State = 'Info')
		if (Test-Path -Path 'variable:script:ProgressGUIStatusCallback') { & $script:ProgressGUIStatusCallback $Message $State }
	}

	# Wait for a reachable DC, then resolve the user's required AD groups. Polls on the configured
	$ResolveADGroups = {
		$ADGRPWaitStopAt = [DateTime]::UtcNow.AddSeconds($ADGRPDCWaitTimeoutSeconds)
		$ADGRPWaitTotal = [Math]::Max(1, $ADGRPDCWaitTimeoutSeconds)
		$ADGRPInterval = [Math]::Max(1, $ADGRPDCWaitIntervalSeconds)
		$ADGRPAttempt = 0
		$ADGRPNextLookupAt = [DateTime]::UtcNow
		while (-not $ADGRPState.DCOk -and [DateTime]::UtcNow -lt $ADGRPWaitStopAt) {
			if ([DateTime]::UtcNow -ge $ADGRPNextLookupAt) {
				$ADGRPAttempt++
				$ADGRPDCReachable = $true
				$ADGRPStatus = "Checking domain controller for '$DomainName' (attempt $ADGRPAttempt, timeout ${ADGRPDCWaitTimeoutSeconds}s)"
				Write-Verbose $ADGRPStatus
				& $ReportStatus $ADGRPStatus 'Info'
				$ADGRPState.UserGroups = @(Get-ADGroupMemberships -ADGRPDomainName $DomainName -ADGRPRequiredGroups $ADGRPRequiredGroups -ADGRPDCAvailable ([ref]$ADGRPDCReachable) -ADGRPSkipTokenDiscovery $ADGRPSkipTokenDiscovery)
				$ADGRPState.DCOk = $ADGRPDCReachable
				if ($ADGRPState.DCOk) {
					$ADGRPStatus = "Connected to '$DomainName'. AD group memberships resolved."
					Write-Verbose $ADGRPStatus
					& $ReportStatus $ADGRPStatus 'Success'
					break
				}
				$ADGRPNextLookupAt = [DateTime]::UtcNow.AddSeconds($ADGRPInterval)
			}
			$ADGRPRemaining = [int][Math]::Max(0, ($ADGRPWaitStopAt - [DateTime]::UtcNow).TotalSeconds)
			if ($ADGRPRemaining -le 0) { break }
			# Fixed-width bar: fill proportional to elapsed fraction, always exactly $ADGRPProgressBarWidth chars
			$ADGRPElapsed = [Math]::Min($ADGRPWaitTotal, [Math]::Max(0, $ADGRPWaitTotal - $ADGRPRemaining))
			$ADGRPFilled = [int][Math]::Round(($ADGRPElapsed / [double]$ADGRPWaitTotal) * $ADGRPProgressBarWidth)
			$ADGRPFilled = [Math]::Min($ADGRPProgressBarWidth, [Math]::Max(0, $ADGRPFilled))
			$ADGRPBar = ('#' * $ADGRPFilled).PadRight($ADGRPProgressBarWidth, '.').Substring(0, $ADGRPProgressBarWidth)
			$ADGRPRetryIn = [int][Math]::Min($ADGRPRemaining, [Math]::Max(1, [Math]::Ceiling(($ADGRPNextLookupAt - [DateTime]::UtcNow).TotalSeconds)))
			& $ReportStatus "Waiting for domain connectivity. Retry in ${ADGRPRetryIn}s (Remain ${ADGRPRemaining}s of ${ADGRPWaitTotal}s)`n[$ADGRPBar]" 'Waiting'
			Start-Sleep -Seconds 1
		}
		if (-not $ADGRPState.DCOk) {
			$ADGRPStatus = "No domain controller was reachable for '$DomainName'. Network drive/printer mappings are skipped."
			& $ReportStatus $ADGRPStatus 'Warning'
			Write-Warning $ADGRPStatus
		}
	}
	#=================== PHASE 2: BUILD MAPPING STEPS ===================
	$BuildMappingSteps = {
		if (-not $ADGRPState.DCOk) { return @() }
		$Escape = { param([string]$Value) $Value -replace "'", "''" }   # quote-escaper for generated commands
		$Resolved = @($ADGRPState.UserGroups)
		$Wanted = @($MapObjects | Where-Object { [string]::IsNullOrEmpty($_['ADGroups']) -or $_['ADGroups'] -in $Resolved })
		$Steps = [System.Collections.Generic.List[hashtable]]::new()
		foreach ($obj in $Wanted) {
			if ($ObjectType -eq 'Printer') {
				$cmd = "New-PrinterMapping -PrinterName '$(& $Escape $obj.PrinterName)' -PrinterPath '$(& $Escape $obj.Path)' -PrinterDefault `$$($obj.Default.ToString().ToLower())"
				$Steps.Add(@{ Name = "Map Printer: $($obj.PrinterName)"; Action = [scriptblock]::Create($cmd) })
			}
			else {
				$label = if ($obj.ContainsKey('Label')) { $obj.Label }      else { '' }
				$persistent = if ($obj.ContainsKey('Persistent')) { $obj.Persistent } else { $true }
				$cmd = "New-DriveMapping -DriveLetter '$(& $Escape $obj.Letter)' -DrivePath '$(& $Escape $obj.Path)' -DriveLabel '$(& $Escape $label)' -DrivePersistent `$$($persistent.ToString().ToLower())"
				$Steps.Add(@{ Name = "Map Drive $($obj.Letter):"; Action = [scriptblock]::Create($cmd) })
			}
		}
		if ($RemoveStaleObjects) {
			if ($ObjectType -eq 'Printer') {
				$active = @($Wanted | ForEach-Object { $_['Path'] })
				Get-Printer -EA SilentlyContinue | Where-Object { $_.Type -eq 'Connection' -and $_.Name -notin $active } | ForEach-Object {
					$Steps.Add(@{ Name = "Remove stale printer: $($_.Name)"; Action = [scriptblock]::Create("Remove-Printer -Name '$(& $Escape $_.Name)' -EA SilentlyContinue") })
				}
			}
			else {
				$active = @($Wanted | ForEach-Object { $_['Letter'] })
				Get-PSDrive -PSProvider FileSystem -EA SilentlyContinue | Where-Object { $_.DisplayRoot -like '\\*' -and $_.Name -notin $active } | ForEach-Object {
					$Steps.Add(@{ Name = "Remove stale drive $($_.Name):"; Action = [scriptblock]::Create("net use $($_.Name): /delete 2>&1 | Out-Null") })
				}
			}
		}
		return $Steps.ToArray()
	}
	#=================== PHASE 3: RUN MAPPING STEPS (GUI or silent) ===================
	if ($ShowGui) {
		# One seamless window: the resolve step runs first, then the mapping steps are appended and run in the SAME window via -AdditionalStepsProvider
		Show-ProgressGUI -Steps @(@{ Name = "Connect domain and find AD groups"; Action = $ResolveADGroups }) -AdditionalStepsProvider $BuildMappingSteps -Title $TaskName -Heading "Mapping $($ObjectType)s..."
	}
	else {
		& $ResolveADGroups
		if (-not $ADGRPState.DCOk) { return }
		$Steps = @(& $BuildMappingSteps)
		if ($Steps.Count -gt 0) { Show-ProgressGUI -Steps $Steps -NoGUI -Title $TaskName -Heading "Mapping $($ObjectType)s..." }
		else { Write-Host "No $ObjectType mappings applicable for current user" }
	}
}

# ====================> UninstallScript (Removes scheduled task, staged artifacts, and ARP entry. Optional uninstall helper script runs first) ========================
$UninstallScript = {
	#=================== PHASE 1: TRY TO RUN UNINSTALL HELPER SCRIPT ===================
	Write-Host "===== UNINSTALLING $ARPAppName ====="
	if ($ARPAppUnInstallScript -and (Test-Path -LiteralPath $ARPAppUnInstallScript)) {
		try {
			Write-Verbose "Running uninstall helper script: $ARPAppUnInstallScript"
			& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ARPAppUnInstallScript
		}
		catch { Write-Warning "Failed to run uninstall helper script $ARPAppUnInstallScript. Error: $_" }
	}
	#=================== PHASE 2: REMOVE SCHEDULED TASK ===================
	try {
		$tsService = New-Object -ComObject 'Schedule.Service'
		$tsService.Connect()
		$tsService.GetFolder('\').DeleteTask($TaskName, 0)
		Write-Verbose "Scheduled task removed: $TaskName"
	}
	catch {
		if ($ExistingTask) { Write-Warning "Failed to remove scheduled task $TaskName. Error: $_" }
		else { Write-Verbose  "Scheduled task not found: $TaskName" }
	}
	#=================== PHASE 3: REMOVE STAGED RUNTIME ARTIFACTS ===================
	foreach ($ArtifactPath in @($APPScriptPath, $TaskLauncherPath, $APPShortcutPath, $APPVersionPath)) {
		if (Test-Path -LiteralPath $ArtifactPath) {
			try {
				Remove-Item -LiteralPath $ArtifactPath -Force -ErrorAction Stop
				Write-Verbose "Removed artifact: $ArtifactPath"
			}
			catch { Write-Warning "Failed to remove artifact $ArtifactPath. Error: $_" }
		}
		else { Write-Verbose "Artifact not found, skipping: $ArtifactPath" }
	}
	#=================== PHASE 4: REMOVE ARP ENTRY AND CLEANUP ===================
	$null = Remove-AddRemovePrograms -ARPAppName $ARPAppName -ARPAppGuid $ARPAppGuid -ARPAppFolder $ARPAppFolder -ARPAppPublisher $ARPAppPublisher
}
#endregion

#region ---------------------------------------------------[[Script Execution]------------------------------------------------------
# Start T-Bone custom logging
Invoke-TboneLog -LogMode Start -Logname $LogName -LogToGUI $LogToGUI -LogToEventlog $LogToEventlog -LogEventIds $LogEventIds -LogToDisk $LogToDisk -LogPath $LogToDiskPath -LogToHost $LogToHost -LogVerboseEnabled $LogVerboseEnabled
# Declare variables to track state and results across execution
[int]$ScriptExitCode = 0
[bool]$EmitDetectOutput = $false
[bool]$compliant = $false
[bool]$forceReinstall = $ForceReplaceAll -or ($InstallType -eq 'Repair')
[string]$ExecutionMode = 'Unknown'
[string]$EffectiveStartFile = if ([string]::IsNullOrWhiteSpace($ARPAppUserStartFile)) { $APPShortcutPath } else { $ARPAppUserStartFile }
[object[]]$ScriptLog = @()
[version]$savedVersion = [version]'0.0'
[pscustomobject]$CTX = $null
[pscustomobject]$ExistingTask	= $null
# Set or clear the MapperShowGUI to specify if the scheduled task should run with or without GUI
[string]$MapperShowGUIRegPath = 'HKCU:\Environment'
$SetUserGuiFlag = {
	try { Set-ItemProperty -LiteralPath $MapperShowGUIRegPath -Name 'MapperShowGUI' -Value '1' -Type String -Force -ErrorAction Stop; return $true }
	catch { Write-Warning "Failed to set user-scope MapperShowGUI override. Error: $_"; return $false }
}
$ClearUserGuiFlag = {
	try { Remove-ItemProperty -LiteralPath $MapperShowGUIRegPath -Name 'MapperShowGUI' -Force -ErrorAction SilentlyContinue }
	catch { Write-Verbose "Failed to delete user-scope MapperShowGUI: $_" }
}
# ==========> Get the execution context to determine script behavior   <========================================================================
try {
	# Validate $MapObjects shape early so configuration errors surface with a readable message before context detection or any side effects
	try { $null = Test-MapObjectValidation -MapObjects $MapObjects }
	catch { throw [System.ArgumentException]::new("Configuration validation failed: $($_.Exception.Message)") }
	# Auto-require x64 on a 64-bit OS (unless the caller pinned a different value)
	if (-not $CTXReqArchitecture -and [Environment]::Is64BitOperatingSystem) { $CTXReqArchitecture = 'x64' }
	$CTX = Get-RuntimeContext -CTXReqIdentity $CTXReqIdentity -CTXReqArchitecture $CTXReqArchitecture -CTXAutoRelaunchToX64:$CTXAutoRelaunchToX64 -CTXReqPSVersion $CTXReqPSVersion -CTXReqOSBuild $CTXReqOSBuild -CTXAbortIfPendingReboot:$CTXAbortIfPendingReboot -CTXForwardParameters $PSBoundParameters
	if (-not $CTX) { Write-Warning "Execution context validation failed. Exiting with code 2."; $ScriptExitCode = 2; return }
	$MapperShowGUIOverride = $EndUserGUI -and (([System.Environment]::GetEnvironmentVariable('MapperShowGUI') -eq '1') -or ([System.Environment]::GetEnvironmentVariable('MapperShowGUI', 'User') -eq '1'))
	$ExecutionMode = switch ($true) {
		($CTX.CTXMode -eq 'Intunewin') { 'Intunewin'; break }
		($CTX.CTXMode -eq 'Detection') { 'Detect'; break }
		($CTX.CTXMode -eq 'Remediation') { 'Remediate'; break }
		($CTX.CTXSource -eq 'ScheduledTask') { 'ScheduledTask'; break }
		$MapperShowGUIOverride { 'ScheduledTask'; break } # MapperShowGUI=1 means the script was invoked manually and should show GUI.
		default { 'Manual' }
	}
	Write-Host "ExecutionMode = $ExecutionMode (CTXMode=$($CTX.CTXMode), CTXSource=$($CTX.CTXSource), CTXIdentity=$($CTX.CTXIdentity))"
	# ==========> Detect compliance (Just detect if compliant and use result in different execution modes)<=========================================
	Write-Host "===== DETECTING $ARPAppName ====="
	[bool]$canInstall = $CTX.CTXIdentity -in @('System', 'Admin')
	$ExistingTask = $null
	try {
		$tsService = New-Object -ComObject 'Schedule.Service'
		$tsService.Connect()
		$tsFolder = $tsService.GetFolder('\')
		$tsTask = $tsFolder.GetTask($TaskName)
		$tsStateName = switch ([int]$tsTask.State) { 0 { 'Unknown' } 1 { 'Disabled' } 2 { 'Queued' } 3 { 'Ready' } 4 { 'Running' } default { 'Unknown' } }
		$ExistingTask = [pscustomobject]@{ TaskName = $TaskName; State = $tsStateName; Enabled = [bool]$tsTask.Enabled }
	}
 catch { $ExistingTask = $null }
	$compliant = $true
	[bool]$shouldReinstall = $false
	if ($canInstall) {
		[bool]$versionFileExists = Test-Path -LiteralPath $APPVersionPath
		$savedVersion = if ($versionFileExists) { try { [version](Get-Content -LiteralPath $APPVersionPath -Raw -EA Stop).Trim() } catch { [version]'0.0' } } else { [version]'0.0' }
		if (-not $versionFileExists) { Write-Host "Non-compliant: version file missing"; $compliant = $false }
		if (-not ($savedVersion -ge $MappingVersion)) { Write-Host "Non-compliant: version $savedVersion < required $MappingVersion"; $compliant = $false }
		if (-not (Test-Path $APPScriptPath)) { Write-Host "Non-compliant: worker script missing"; $compliant = $false }
		if (-not (Test-Path $TaskLauncherPath)) { Write-Host "Non-compliant: JS launcher missing"; $compliant = $false }
		if (-not $ExistingTask -or [string]$ExistingTask.State -eq 'Disabled') { Write-Host "Non-compliant: scheduled task missing/disabled"; $compliant = $false }
		# ShouldReinstall reflects only the compliance check; force flags are evaluated separately at each branch
		$shouldReinstall = -not $compliant
	}
	Write-Host "Compliance=$compliant, ForceReplaceAll=$ForceReplaceAll, InstallType=$InstallType, ForceReinstall=$forceReinstall, ShouldReinstall=$shouldReinstall, CanInstall=$canInstall"
	# ==========> Uninstall (If InstallType is UnInstall)<==========================================================================================
	# UnInstall intent inverts compliance: the device is compliant only when the app is fully removed
	if ($InstallType -eq 'UnInstall') {
		[bool]$appPresent = [bool]$ExistingTask -or (Test-Path $APPVersionPath) -or (Test-Path $APPScriptPath) -or (Test-Path $TaskLauncherPath) -or (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$ARPAppGuid")
		$compliant = -not $appPresent
		Write-Host "UnInstall mode: AppPresent=$appPresent, Compliant=$compliant, ExecutionMode=$ExecutionMode, CanInstall=$canInstall"
		switch ($ExecutionMode) {
			# ==========> Detect uninstall (Report non-compliant while the app is still present so remediation runs; compliant once removed)<===============
			'Detect' {
				$EmitDetectOutput = $true
				if ($compliant) { Write-Host "Compliant: $TaskName already removed"; $ScriptExitCode = 0 }
				else { Write-Host "Non-compliant: $TaskName still present - remediation will uninstall"; $ScriptExitCode = 1 }
			}
			# ==========> Remediate / Win32 / Manual uninstall (Remove the app when present; already-removed counts as success)<============================
			default {
				if (-not $canInstall) { Write-Warning "InstallType '$InstallType' requires System or Admin to uninstall. Current identity: $($CTX.CTXIdentity)"; $ScriptExitCode = 3; break }
				if ($appPresent) { & $UninstallScript; $ScriptExitCode = 0 }
				else { Write-Host "ExecutionMode '$ExecutionMode' and already removed: $TaskName - nothing to uninstall"; $ScriptExitCode = 0 }
			}
		}
	}
	else {
		switch ($ExecutionMode) {
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
					Write-Verbose "Elevated manual run detected - installing or repairing all scheduled-task components (ShouldReinstall=$shouldReinstall, ForceReinstall=$forceReinstall)"
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
						$guiFlagSet = $false   # task now owns the flag
						$ScriptExitCode = 0
					}
					catch { Write-Warning "Failed to start scheduled task '$TaskName'. Error: $_"; $ScriptExitCode = 4 }
					finally { if ($guiFlagSet) { & $ClearUserGuiFlag } }
				}
				# Exit or Run the workflow with or without GUI in non-compliant state (Manual run with non-compliant state but cannot install)
				else {
					if (($shouldReinstall -or $forceReinstall) -and -not $canInstall) { Write-Warning "Non-compliant or force-reinstall requested, but current identity '$($CTX.CTXIdentity)' cannot install or repair. Running mapping directly for this session only" }
					elseif (-not $ExistingTask) { Write-Warning "Scheduled task '$TaskName' not found - running mapping directly" }
					& $WorkflowScript -ShowGui ($EndUserGUI -and -not $CTX.CTXNoGUISupport)
					$ScriptExitCode = 0
				}
			}
			# ==========> Scheduled Task (Execute the user workflow to map resources)<======================================================================
			'ScheduledTask' {
				$procOverride = [System.Environment]::GetEnvironmentVariable('MapperShowGUI') -eq '1'
				$userOverride = [System.Environment]::GetEnvironmentVariable('MapperShowGUI', 'User') -eq '1'
				$oneShot = $EndUserGUI -and ($procOverride -or $userOverride)
				if ($procOverride) { [System.Environment]::SetEnvironmentVariable('MapperShowGUI', $null) }
				if ($userOverride) { & $ClearUserGuiFlag }
				Write-Verbose "Scheduled task execution with GUI $(if ($oneShot) { 'enabled' } else { 'disabled' })"
				& $WorkflowScript -ShowGui $oneShot
				$ScriptExitCode = 0
			}
		}
	}
}
catch [System.ArgumentException] { Write-Error $_.Exception.Message; $ScriptExitCode = 7 }
catch [System.OperationCanceledException] { Write-Warning $_.Exception.Message; $ScriptExitCode = 10 }
catch { Write-Error "Unhandled error in script: $($_.Exception.Message)"; $ScriptExitCode = 9 }
finally {
	# $CTX is assigned inside the try; guard against StrictMode failures when Get-RuntimeContext threw before assignment or returned $null
	$ctxIdentityForLog = if ($CTX -and $CTX.PSObject.Properties['CTXIdentity']) { $CTX.CTXIdentity } else { 'Unknown' }
	Write-Verbose "Completed $ExecutionMode execution with installtype $InstallType as $ctxIdentityForLog completed with exit code $ScriptExitCode. Cleaning up environment..."
	# Restore original preference settings
	try { $ErrorActionPreference = $script:OriginalErrorActionPreference } catch {}
	try { $VerbosePreference = $script:OriginalVerbosePreference } catch {}
	try { $WhatIfPreference = $script:OriginalWhatIfPreference } catch {}
	# cleanup of environment variables
	try { [System.Environment]::SetEnvironmentVariable('MapperCTXSource', $null) } catch {}
	try { [System.Environment]::SetEnvironmentVariable('MapperShowGUI', $null) } catch {}
	# Stop T-Bone custom logging and capture any errors during shutdown
	try { $ScriptLog = @(Invoke-TboneLog -LogMode Stop) }
	catch { $ScriptLog = @("Logger shutdown failed: $($_.Exception.Message)") }
}
# If the script was run in detection mode, return a simple compliant/non-compliant message that can be parsed by Intune, otherwise just exit with the appropriate exitcode
if ($EmitDetectOutput) {
	if ($compliant) {
		if ($InstallType -eq 'UnInstall') { Write-Output "Compliant: $TaskName removed" }
		else { Write-Output "Compliant: $TaskName v$MappingVersion" }
	}
	else { Write-Output "Non-Compliant - $($ScriptLog -join "`n")" }
}
exit $ScriptExitCode
#endregion
