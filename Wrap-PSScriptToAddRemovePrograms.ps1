<#PSScriptInfo
.VERSION        3.0.1
.AUTHOR         @MrTbone_se (T-bone Granheden)
.GUID           feedbeef-beef-4dad-beef-b628ccca16e0
.COPYRIGHT      (c) 2026 T-bone Granheden. MIT License - free to use with attribution.
.TAGS           Intune DeviceManagement Win32App PowerShellScript AddRemovePrograms ARP Wrapper Logging
.LICENSEURI     https://opensource.org/licenses/MIT
.PROJECTURI     https://github.com/Mr-Tbone/Intune
.RELEASENOTES
    1.0 2022-02-18 Initial Build
    2.0.0 2026-04-13 Major update with updated functions, logic and error handling
    2.0.1 2026-04-16 Fixed MSI version detection from Intune
    2.0.2 2026-05-27 Added function for detection of execution context
    3.0.0 2026-04-30 Major update to script logic and new function added
    3.0.1 2026-04-30 fixed Script rename references
#>

<#
.SYNOPSIS
    Script for Intune to build an app that show in Add/Remove Programs from a PowerShell Script
.DESCRIPTION
    This script will act as a wrapper for PowerShell script.
    It will copy the script and icon to program files and add the necessary registry keys to show up in Add/Remove Programs.
    The PowerShell based app can be installed, uninstalled and reinstalled from Add/Remove Programs and also show the app version and icon.

.EXAMPLE
   .\Wrap-PSScriptToAddRemovePrograms.ps1
    Will run the wrapped powershell script once to install with the default parameters.

.EXAMPLE
   .\Wrap-PSScriptToAddRemovePrograms.ps1 -InstallType ReInstall
    Will re-run the wrapped powershell script to install with the default parameters.

.EXAMPLE
   .\Wrap-PSScriptToAddRemovePrograms.ps1 -InstallType UnInstall
    Will run the wrapped powershell script to uninstall with the default parameters..

.NOTES
    Please feel free to use this, but make sure to credit @MrTbone_se as the original author

.LINK
    https://tbone.se
#>

#region ---------------------------------------------------[Modifiable Parameters and Defaults]------------------------------------
# Customizations
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false,          HelpMessage = "Name of the script action for logging")]
    [string]$ScriptActionName       = "Add Remove Program Wrapper",

    [Parameter(Mandatory = $false,          HelpMessage = 'Specify how to run the script: Install, ReInstall or UnInstall')]    
    [validateset("Install", "ReInstall", "UnInstall")]
    [string]$InstallType            = "Install",

    [Parameter(Mandatory = $false,          HelpMessage = "Testmode, same as -WhatIf. Default is false")]
    [bool]$Testmode                 = $false,

# ==========> Add Application to Add Remove Program (Add-AddRemoveProgram) <===========================================
    [Parameter(Mandatory = $false,          HelpMessage = 'Name of the application/script being wrapped')]
    [String]$ARPAppName             = "T-Bone App",

    [Parameter(Mandatory = $false,          HelpMessage = 'GUID of the application/script being wrapped. NOTE: This needs to be unique for each wrapped app')]
    [ValidatePattern('^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$')]
    [String]$ARPAppGuid             = "{feedbeef-beef-4dad-beef-b628ccca16e0}",

    [Parameter(Mandatory = $false,          HelpMessage = 'Version of the application. Increment when changing config')]
    [ValidatePattern("^\d+\.\d+\.\d+$")]
    [version]$ARPAppVersion         = "1.0.0",

    [Parameter(Mandatory = $false,          HelpMessage = 'Company name used for naming of folders and registry keys')]
    [String]$ARPAppPublisher        = "T-Bone",
    
    [Parameter(Mandatory = $false,          HelpMessage = 'Optional Base64-encoded .ico content to use as the icon of the app')]
    [string]$ARPAppIcon             = "",

    [Parameter(Mandatory = $false,          HelpMessage = "Application folder path, if not specified, it will use %ProgramFiles%\ARPPublisher\ARPAppName ")]
    [string]$ARPAppFolder           = "$Env:Programfiles\$ARPAppPublisher\$ARPAppName",
    
    [Parameter(Mandatory = $false,          HelpMessage = 'Enable an uninstall option in Add Remove Programs, require administrator privileges to uninstall')]
    [bool]$ARPAppEnableUninstall    = $True,

    [Parameter(Mandatory = $false,          HelpMessage = 'Enable a modify option in Add Remove Programs (typically for repair/reinstall), require administrator privileges to modify')]
    [bool]$ARPAppEnableModify       = $True,

    [Parameter(Mandatory = $false,          HelpMessage = 'Optional path to a .ps1 file to use as the installer script')]
    [string]$ARPAppInstallScript    = "",

    [Parameter(Mandatory = $false,          HelpMessage = 'Optional path to a .ps1 file to use as the uninstaller script')]
    [string]$ARPAppUnInstallScript  = "",

    [Parameter(Mandatory = $false,          HelpMessage = 'Optional path to a .ico file to use as the icon of the app')]
    [string]$ARPAppIconPath         = "",

    [Parameter(Mandatory = $false,          HelpMessage = 'If $true, copy every file in the wrapper''s source folder into the app folder (excluding the wrapper itself, the install/uninstall scripts and the icon, which are deployed under standardized names).')]
    [bool]$ARPAppIncludeFolder      = $false,

    [Parameter(Mandatory = $false,          HelpMessage = 'Optional leaf name of a companion file inside the app folder to launch the app (e.g. t-bone.exe). Required for shortcut creation.')]
    [string]$ARPAppUserStartFile    = "",

    [Parameter(Mandatory = $false,          HelpMessage = 'Create an All-Users Desktop shortcut to ARPAppUserStartFile')]
    [bool]$ARPAppShortcutOnDesktop  = $false,

    [Parameter(Mandatory = $false,          HelpMessage = 'Create an All-Users Start Menu shortcut to ARPAppUserStartFile (under Programs\<Publisher>\<AppName>.lnk)')]
    [bool]$ARPAppShortcutInStart    = $false,

    [Parameter(Mandatory = $false,          HelpMessage = 'Force the action, ignoring any prompts or checks')]
    [bool]$ARPAppForce              = $false,

# ==========> Logging (Invoke-TboneLog) <==============================================================================
    [Parameter(Mandatory = $false,          HelpMessage='Name of Log, to set name for Eventlog and Filelog')]
    [string]$LogName                = "",

    [Parameter(Mandatory = $false,          HelpMessage='Show output in console during execution')]
    [bool]$LogToGUI                 = $true,

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
    [bool]$LogVerboseEnabled        = $true
)
#endregion

#region ---------------------------------------------------[Modifiable Parameters and defaults]------------------------------------
# If you want to use inline scriptblocks instead of external .ps1 files for installer and uninstaller, 
# you can define them here and they will be used instead of the file paths if those are not empty. 
# This is useful for simple scripts or when you want to keep everything in one file without external dependencies. 
# Just make sure to set the $ARPAppInstallScript and $ARPAppUnInstallScript parameters to empty strings if you want to use the inline scriptblocks.

# Define inline scriptblocks, these are just examples and can be replaced with any valid PowerShell code.
# You can add logic inside the scriptblocks to differentiate behavior based on the $InstallType variable or other conditions if needed.
# The Add Remove Program function will only add or remove the regkeys and copy the files to the app folder.

# Note that these scripts will run at install, reinstall
[scriptblock]$InlineInstallerScript = {
write-host "hello world"
}
# Note that these scripts will run at Uninstall
[scriptblock]$InlineUnInstallerScript = {
write-host "hello world"
}
#endregion

#region ---------------------------------------------------[Set global script settings]--------------------------------------------
# set strict mode to latest version
Set-StrictMode -Version Latest

# Save original preference states at script scope for restoration in finally block
[System.Management.Automation.ActionPreference]$script:OriginalErrorActionPreference    = $ErrorActionPreference
[System.Management.Automation.ActionPreference]$script:OriginalVerbosePreference        = $VerbosePreference
[bool]$script:OriginalWhatIfPreference                                                  = $WhatIfPreference

# Set verbose- and whatif- preference based on parameter instead of hardcoded values or manually enable whatif mode with parameter $Testmode for testing
if ($LogVerboseEnabled)     {$VerbosePreference = 'Continue'}
else                        {$VerbosePreference = 'SilentlyContinue'}
if($Testmode)               {$WhatIfPreference = 1}
#endregion

#region ---------------------------------------------------[Static Variables]------------------------------------------------------
$ARPAppRegKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$ARPAppGuid"

# ==========> Logging (Invoke-TboneLog) <==============================================================================
if([string]::IsNullOrWhiteSpace($LogName)) {[string]$LogName = $ScriptActionName}           # Logname defaults to script action name
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
        if(!(Test-Path function:\global:_Save)){function global:_Save{try{if($global:_d){[IO.Directory]::CreateDirectory($global:_p)|Out-Null;[IO.File]::WriteAllLines((Join-Path $global:_p "$($global:_n).log"),$global:_l.ToArray())};if($global:_e -and $global:_w){$isAdmin=$false;try{$id=[Security.Principal.WindowsIdentity]::GetCurrent();$isAdmin=([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)}catch{};$la=$global:_l -join"`n";$h=$la -match ',ERROR,';$et=if($h){'Error'}elseif($la -match ',WARN,'){$global:_i.Warn}else{$global:_i.Info};$ok=$false;try{Write-EventLog -LogName Application -Source $global:_s -EventId $eid -EntryType $et -Message $la -EA Stop;$ok=$true}catch{};if(-not $ok -and $isAdmin){try{[Diagnostics.EventLog]::CreateEventSource($global:_s,'Application')}catch{};try{Write-EventLog -LogName Application -Source $global:_s -EventId $eid -EntryType $et -Message $la}catch{}}}}catch{}}}
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

function Get-ScriptExecutionContext {
<#
.SYNOPSIS
    Detects how the script is being executed and returns a context object with all relevant properties.
.DESCRIPTION
    Inspects environment variables, the script path, parent/ancestor processes, and identity to determine and return a PSCustomObject with the following properties:
    - ExecutionMode     : WinPE, AzureAutomation, AzureFunction, GitHubActions, GitLabCI, AzureDevOps, TaskSequence,
                          Remediation, Detection, PlatformScript, Intunewin, SCCM, GPO, or Standalone
    - ExecutionPath     : ProgramFiles, ProgramFilesX86, IMEContent, ProgramData, AppDataRoaming, AppDataLocal,
                          IMECache, CCMCache, SystemRoot, or Other
    - ExecutionSource   : Managed (set for any non-Standalone ExecutionMode), or one of
                          Manual, ScheduledTask, RemoteSession, VSCodeDebug, ISE, Explorer, Batch, Interactive
    - ExecutionIdentity : System, LocalService, NetworkService, ServiceAccount, Admin, or User
.NOTES
    Author:  @MrTbone_se (T-bone Granheden)
    Version: 1.2.0
#>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()
    # Initialize variables
    [string]$ExecutionMode                  = 'Standalone'
    [string]$ExecutionPath                  = 'Other'
    [string]$ExecutionSource                = 'Managed'
    [string]$ExecutionIdentity              = 'User'
    [string]$private:scriptPath             = $script:PSCommandPath
    [string]$private:scriptRoot             = $script:PSScriptRoot

    # ---- Execution Mode detection -------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Get execution mode from environment variables (quick and reliable for managed contexts, but not always present)
    if     (Test-Path 'HKLM:\SYSTEM\ControlSet001\Control\MiniNT')                          { $ExecutionMode = 'WinPE'           }
    elseif ((Test-Path variable:PSPrivateMetadata) -and $PSPrivateMetadata.JobId)           { $ExecutionMode = 'AzureAutomation' }
    elseif ($env:FUNCTIONS_WORKER_RUNTIME -or $env:AZURE_FUNCTIONS_ENVIRONMENT)             { $ExecutionMode = 'AzureFunction'   }
    elseif ($env:GITHUB_ACTIONS -eq 'true')                                                 { $ExecutionMode = 'GitHubActions'   }
    elseif ($env:GITLAB_CI -eq 'true')                                                      { $ExecutionMode = 'GitLabCI'        }
    elseif ($env:TF_BUILD -eq 'True')                                                       { $ExecutionMode = 'AzureDevOps'     }
    elseif ($env:_SMSTSType -or $env:_SMSTSPackageID -or $env:SMSTSLogPath)                 { $ExecutionMode = 'TaskSequence'    }
    Write-Verbose "ExecutionMode = $($ExecutionMode) ExecutionPath = $($ExecutionPath) ExecutionSource = $($ExecutionSource) ExecutionIdentity = $($ExecutionIdentity) after environment variable check"

    # If still standalone, Get execution mode from script path to determine if running as Remediation, Detection, Platformscript, Intunewin, Tasksequence, or from SCCM
    if ($ExecutionMode -eq 'Standalone' -and $scriptPath) {
        if     ($scriptPath -match 'IMECache\\HealthScripts\\.*\\remediate\.ps1$')          { $ExecutionMode = 'Remediation'    }
        elseif ($scriptPath -match 'IMECache\\HealthScripts\\.*\\detect\.ps1$')             { $ExecutionMode = 'Detection'      }
        elseif ($scriptPath -match 'IMECache\\Scripts\\')                                   { $ExecutionMode = 'PlatformScript' }
        elseif ($scriptPath -match 'Microsoft Intune Management Extension\\Content\\')      { $ExecutionMode = 'Intunewin'      }
        elseif ($scriptPath -match '_SMSTaskSequence\\')                                    { $ExecutionMode = 'TaskSequence'   }
        elseif ($scriptPath -match '\\ccmcache\\')                                          { $ExecutionMode = 'SCCM'           }
    }
    Write-Verbose "ExecutionMode = $($ExecutionMode) ExecutionPath = $($ExecutionPath) ExecutionSource = $($ExecutionSource) ExecutionIdentity = $($ExecutionIdentity) after script path check"

    # If still standalone, Get execution mode from CIM and inspect parent processes for known hosts to determine if running by Intunewin, GPO, SCCM or Tasksequence
    $private:procTable    = @{}
    $private:ancestorPids = [System.Collections.Generic.List[int]]::new()
    if ($ExecutionMode -eq 'Standalone') {
        try {
            $private:allProcs = Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId, Name -ErrorAction Stop -Verbose:$false
            foreach ($p in $allProcs) { $procTable[[int]$p.ProcessId] = $p }
        } catch {Write-Verbose "Get-ScriptExecutionContext: Failed to build process table with CIM, parent process detection will be unavailable. Error: $_"}
        if ($procTable.Count -gt 0) {
            $private:walkPid = $PID
            while ($ancestorPids.Count -lt 8 -and $procTable.ContainsKey($walkPid)) {
                $private:parentId = [int]$procTable[$walkPid].ParentProcessId
                if ($parentId -eq 0 -or $parentId -eq $walkPid) { break }
                $ancestorPids.Add($parentId)
                $walkPid = $parentId
            }
            foreach ($aPid in $ancestorPids) {
                if (-not $procTable.ContainsKey($aPid)) { continue }
                $private:procName = $procTable[$aPid].Name
                if     ($procName -in 'AgentExecutor.exe','IntuneManagementExtension.exe')  { $ExecutionMode = 'Intunewin';    break }
                elseif ($procName -eq 'gpscript.exe')                                       { $ExecutionMode = 'GPO';          break }
                elseif ($procName -in 'CcmExec.exe','ccmsetup.exe')                         { $ExecutionMode = 'SCCM';         break }
                elseif ($procName -in 'TSManager.exe','smstsbootstrap.exe')                 { $ExecutionMode = 'TaskSequence'; break }
            }
        }
    }
    Write-Verbose "ExecutionMode = $($ExecutionMode) ExecutionPath = $($ExecutionPath) ExecutionSource = $($ExecutionSource) ExecutionIdentity = $($ExecutionIdentity) after CIM process detection"

    # ---- Execution path detection -------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Check if running from a known folder like Program Files, imecontent, ProgramData, AppData imecache, or SystemRoot to determine if running from a well-known location or a random Other path
    if ($scriptRoot) {
        $private:root = $scriptRoot.TrimEnd('\')
        $private:sc   = [StringComparison]::OrdinalIgnoreCase
        if     ($env:ProgramFiles        -and $root.StartsWith($env:ProgramFiles.TrimEnd('\'),                                                   $sc)) { $ExecutionPath = 'ProgramFiles'    }
        elseif (${env:ProgramFiles(x86)} -and $root.StartsWith(${env:ProgramFiles(x86)}.TrimEnd('\') + '\Microsoft Intune Management Extension', $sc)) { $ExecutionPath = 'IMEContent'      }
        elseif (${env:ProgramFiles(x86)} -and $root.StartsWith(${env:ProgramFiles(x86)}.TrimEnd('\'),                                            $sc)) { $ExecutionPath = 'ProgramFilesX86' }
        elseif ($env:ProgramData         -and $root.StartsWith($env:ProgramData.TrimEnd('\'),                                                    $sc)) { $ExecutionPath = 'ProgramData'     }
        elseif ($env:APPDATA             -and $root.StartsWith($env:APPDATA.TrimEnd('\'),                                                        $sc)) { $ExecutionPath = 'AppDataRoaming'  }
        elseif ($env:LOCALAPPDATA        -and $root.StartsWith($env:LOCALAPPDATA.TrimEnd('\'),                                                   $sc)) { $ExecutionPath = 'AppDataLocal'    }
        elseif ($env:SystemRoot          -and $root.StartsWith($env:SystemRoot.TrimEnd('\') + '\IMECache',                                       $sc)) { $ExecutionPath = 'IMECache'        }
        elseif ($env:SystemRoot          -and $root.StartsWith($env:SystemRoot.TrimEnd('\') + '\ccmcache',                                       $sc)) { $ExecutionPath = 'CCMCache'        }
        elseif ($env:SystemRoot          -and $root.StartsWith($env:SystemRoot.TrimEnd('\'),                                                     $sc)) { $ExecutionPath = 'SystemRoot'      }
    }
    Write-Verbose "ExecutionMode = $($ExecutionMode) ExecutionPath = $($ExecutionPath) ExecutionSource = $($ExecutionSource) ExecutionIdentity = $($ExecutionIdentity) after path detection"

    # ---- Source detection ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Check process to determine if running from a scheduled task, remote session, VSCode debug session, ISE, Explorer, cmd or interactively in powershell. Only check if still in standalone mode
    if ($ExecutionMode -eq 'Standalone') {
        $ExecutionSource = 'Manual'
        try {
            # Build procTable if not already built (managed paths skipped CIM)
            if ($procTable.Count -eq 0) {
                Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId, Name -ErrorAction Stop -Verbose:$false|
                    ForEach-Object { $procTable[[int]$_.ProcessId] = $_ }
                $private:walkPid = $PID
                for ($private:i = 0; $i -lt 8; $i++) {
                    if (-not $procTable.ContainsKey($walkPid)) { break }
                    $private:parentId = [int]$procTable[$walkPid].ParentProcessId
                    if ($parentId -eq 0 -or $parentId -eq $walkPid) { break }
                    $ancestorPids.Add($parentId)
                    $walkPid = $parentId
                }
            }

            # Detect ExecutionSource from parent process and ancestor services
            $private:parentName  = if ($ancestorPids.Count -gt 0 -and $procTable.ContainsKey($ancestorPids[0])) { $procTable[$ancestorPids[0]].Name } else { '' }
            $private:ancestorNames = $ancestorPids | Where-Object { $procTable.ContainsKey($_) } | ForEach-Object { $procTable[$_].Name }
            $private:svchostPid  = $ancestorPids | Where-Object { $procTable.ContainsKey($_) -and $procTable[$_].Name -eq 'svchost.exe' } | Select-Object -First 1
            $private:svcNames    = if ($svchostPid) { (Get-CimInstance Win32_Service -Filter "ProcessId=$svchostPid" -Property Name -ErrorAction SilentlyContinue).Name } else { @() }
            if     ($svcNames -contains 'Schedule')                             { $ExecutionSource = 'ScheduledTask'  }
            elseif ($parentName -eq 'wsmprovhost.exe')                          { $ExecutionSource = 'RemoteSession'  }
            elseif ($Host.Name -eq 'Visual Studio Code Host' -or
                    [bool]($ancestorNames -match '^Code( - Insiders)?\.exe$')) { $ExecutionSource = 'VSCodeDebug'    }
            elseif ($Host.Name -eq 'Windows PowerShell ISE Host')               { $ExecutionSource = 'ISE'            }
            elseif ($parentName -eq 'explorer.exe')                             { $ExecutionSource = 'Explorer'       }
            elseif ($parentName -eq 'cmd.exe')                                  { $ExecutionSource = 'Batch'          }
            elseif ($parentName -in 'powershell.exe', 'pwsh.exe')               { $ExecutionSource = 'Interactive'    }
        } catch                                                                 { $ExecutionSource = 'Manual'         }
    }
    Write-Verbose "ExecutionMode = $($ExecutionMode) ExecutionPath = $($ExecutionPath) ExecutionSource = $($ExecutionSource) ExecutionIdentity = $($ExecutionIdentity) after source detection"

    # ---- Identity detection -------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Detect identity — System, LocalService, NetworkService, ServiceAccount, Admin, or User (falls back to init value 'User' if detection fails)
    try {
        $private:currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $private:principal       = [System.Security.Principal.WindowsPrincipal]$currentIdentity
        if     ($currentIdentity.IsSystem)                                                                      {$ExecutionIdentity = 'System'         }
        elseif ($currentIdentity.User.Value -eq 'S-1-5-19')                                                     {$ExecutionIdentity = 'LocalService'   }
        elseif ($currentIdentity.User.Value -eq 'S-1-5-20')                                                     {$ExecutionIdentity = 'NetworkService' }
        elseif ($currentIdentity.Name -like 'NT SERVICE\*' -or $currentIdentity.Name -like 'NT AUTHORITY\*')    {$ExecutionIdentity = 'ServiceAccount' }
        elseif ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))             {$ExecutionIdentity = 'Admin'          }
        else                                                                                                    {$ExecutionIdentity = 'User'           }
    } catch { Write-Verbose "Get-ScriptExecutionContext: Failed to detect identity, defaulting to 'User'. Error: $_" }

    Write-Verbose "ExecutionMode = $($ExecutionMode) ExecutionPath = $($ExecutionPath) ExecutionSource = $($ExecutionSource) ExecutionIdentity = $($ExecutionIdentity) after identity detection"
    [PSCustomObject]@{
        ExecutionMode     = $ExecutionMode
        ExecutionPath     = $ExecutionPath
        ExecutionSource   = $ExecutionSource
        ExecutionIdentity = $ExecutionIdentity
    }
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
        Version: 1.1.0
        
        Version History:
        1.0 - Initial version
        1.0.1 - Changed parameter names end improved error handling
        1.1.0 - Major refactor to support more features, better logging and error handling, and to be more modular and maintainable. Added parameters for shortcuts and folder copying.
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

        [Parameter(Mandatory = $false,          HelpMessage = 'Optional leaf name of a companion file inside the app folder to launch the app (e.g. t-bone.exe). Required for shortcut creation.')]
        [string]$ARPAppUserStartFile    = "",

        [Parameter(Mandatory = $false,          HelpMessage = 'Create an All-Users Desktop shortcut to ARPAppUserStartFile')]
        [bool]$ARPAppShortcutOnDesktop  = $false,

        [Parameter(Mandatory = $false,          HelpMessage = 'Create an All-Users Start Menu shortcut to ARPAppUserStartFile')]
        [bool]$ARPAppShortcutInStart    = $false,

        [Parameter(Mandatory = $false,          HelpMessage = 'Force overwrite of existing files and registry entries')]
        [bool]$ARPAppForce              = $False
    )
    Begin {
        $ErrorActionPreference = 'Stop'
        Write-Verbose "Start Function Add-AddRemovePrograms"
        $private:HKCRDrive = $false

        # Default demo app icon, used when no icon path or Base64 is provided.
        $script:DefaultIconBase64 = ('AAABAAIAEBAAAAEAIAD+AwAAJgAAACAgAAABACAAJQsAACQEAACJUE5HDQoaCgAAAA1JSERSAAAAEAAAABAIBgAAAB/z/2EAAAABc1JHQgCuzhzpAAAABGdBTUEAALGPC/xhBQAAAAlwSFlzAAAOwwAADsMBx2+oZAAAA5NJREFUOE9F0ttP2wUUB/AvE+jl
                    96O0rP219EbpjdtaeqHtyg9GS0tHW+7CGKWj4ybShQ46tpay0UlH2EQckxkxJrKEB02MxpmYGB988JKYGB98W1yMxsTEB2P8D46pGD3JeTyf883JwViLDpO2RiQcFqS8rVjucSI32IXdZD8O5ofwaH4IB3ODeLiSxFsPinjn8R4O93dwt5BFsbAGxK0ajLc1
                    YNppwTxvx1qUx58f7ePkXhYAqt+8Non9+VHsrS3g8H4Rj1/fwf3SJu7krmMrvwqEjPUItVox7W5K92oV2yMGOS3b6+loto+ell6mJzOhG6XUMEqri9jb3sCD0iaKhSw2b67gdi4DBAwqeLXcxy/ZdbTo0NEvz76jL7/5gsp1cPAqrYc7CIDu6ScfFL79+vNQ
                    eXP+xjXksmnks2nAazIsWOpqKWVrJJ6rIRlQHvgHCMrO0HEyRBbgaLuYo1try2SqZ3Fy/HbTxvrKrdd2t47R3cA9dyokxFaL6JKtmTJOC1UB9Otvzyke5Cm9NEstEsFuIZehO7nMDxOjMbq3tU4b62lKTAz+iNpaabufY0krZugwWEU/pxnqk4IevrFH7+/c
                    pCmDrJwovlPKf3o1MUblnhofoMT4AMUjPV/Bp5Lg2ZIVnjqG/lgC/ZQELRgqKBKN0PefvUerdnUZCN/OZ2go2vt7kPc+AWA9efcRLo/FgS4Vg0G9CBfFMA1pK8knF9HouWbSqlW0nhymjENHVSw7AoEwcGV8AKPxMAYiPYhHejAcCwF9aiFG9AKMNwpBr2gQ
                    rGfJJGFpzKqlo347XXcZaK5V1zHha8NwwId4uBvhC+cR4D2IBDqBuEaAmEaAPo0IQTUDm1SY61GKqV0hpbSnmcJmPc06G+cSDhMm3E2IdboQ8Ltx3m0D73UAffUCXFCKwCvF4JUMAuoa+OSiv7rk1RRtkNJih5HcEgGuOIyYcZkw5bIg5G6Ds60J55qMgF8h
                    hFchhk/BwM8x4JUsIrra8nE/TLjMc2NWFabtDUg5jZjrMGOVb0W/VYPKigpUlJ/dcVYMt1wMTxnhGHQqWXSrJQjpZIibOLzYokHC3oCrLiPmPWak3GbYVTKcAU4Be50YzrNidMjF8HIM/KoadKtr0auvQ8zEYbRFg8s2PWb+TTBpN0DJCP8HWmUitNeJ4Cqn
                    4NhTQHMKRE0cRpo1uGTTI+lsRMptwkWLGmzlC/8BfwOcUBv1oWxTjwAAAABJRU5ErkJggolQTkcNChoKAAAADUlIRFIAAAAgAAAAIAgGAAAAc3p69AAAAAFzUkdCAK7OHOkAAAAEZ0FNQQAAsY8L/GEFAAAACXBIWXMAAA7DAAAOwwHHb6hkAAAKuklEQVRY
                    R+WWeWyT9xnHvzlsx06c2PERx3Z830d8xVec2zmcA0IuEnIfBEJIKAmQAiGMI4EQGgKEo1Ao59qyDpW2QmvVatXard00CdRKnTamoW1dV1XV2q6ddmp+ptfQDlWtRPfvHumr16/9vM/349/1PsADUaaVo0wnR7leiahRhSqLBtVWLaptejS4TFgTsGKk0IKx
                    sBGjYRPGiyyYLLVhR9SOvTEnZmudaFKLwAOQDCDpK/ra6DRL0W2Voc+pwIBbg26PHqscesQsGsSsWtTbdKi369HkNqI3aMWmEismSyyYKLVha4UD09Uu7K/34HCjD4urCjDm1yMzOQmpAFLu6wuYr401Jim6LDL0OhTod6nR49GjLd+AFTYdGmw6NDr0aM7X
                    o8NrxHChFVOVTuyqcWFXrRd7V/ox3xzEkbYwjrWFsdgUxM4KJ/K4bHAAsAGwGIgkIDUFyMoC1OqvALQYJOgw56DHLkdfvgo9bh3aXQa0OA1ochrQ5jKiy2dmUvkeX0C8tzHIfOYZgKg3CfbTgzU42VOBo+0lOLAyhN3tNViam8Gvbr+B5cdmcWJxDsuLc1iY
                    m8Zg70qoVF+BqFKLscogRYclFz0OJXpcGnS69FjjNoLo97AqFBtXmZRUqsymUU8uzZWIFx71ZtOBBhed7QnQcnnuoycH63GgqRjbawKY3TSE00cP4vzpJVw+t4yr50/gqYuncfnccQx0NaO9uR59nS0Y7u/AxnW9QFAhRlQtwUpDDrq1fPtkxPR5ldNGq90W
                    qtHKqTJPTJvMQtpmFdBs1E5z7TH60cVD9M5LV+iHl47Tk+OdtNuvqNxe48fm2ggO7pzAiSNzePz4ITz5+BKuPnkST188jVPH5rF/9xQ2jQxguK8DI0NdGB/pBzxyCUJKCSq1MjQo+G92GwTUq8+iuXIzPeoU00tHZ+gvn7xP3xQ/ee4KdelEBEAw3hjF3PQk
                    jszvwbHD+3FmeQGXnziOi2ePYX7/dEI7toxhdLgHY+v6MDG2FvAqc1BjVMErE/7GpdXQupCDJiMOmghbSCsV0r/in9HtW6/Hh3paqCzoTJjevfN2HABxU0ANTi2NmLKpR515A4Dm5vPX6MzyAl1/+jzd/tlrvrMnDmPp0B7s3bUVC7O7sGfnJDZvHMLExiFM
                    TYwAQVUuzHLZTa8ih/KEAhr0mmjYJqdWk5z5V8RhJTNXxjBhSvQZwxBPBsgB0On6fNofVlOfkvcCgPe//9Q5am6o+lSjlNG7t16nhdlpzGzfjN3bN+PQ7DT2zWzFgb3b0d7c0P7K81eB3y5tZZUYVKTLFpCDz6ZqXS5tDllpsshOERGXYhoJtdo1cfl9gDvv
                    /jQBMFVkoh2tUXp5YRtdneylmRL7FQDSo4f30br+9qlCv5tevXntb0SE5753+apcKmq5dvXcu9eunCW/2/73c6cW6cCeqduotmgXy9US8sqySc/nkpLPI41IRIMBG20LW2hL2EKbfLp4Wa4gMSLXn34iATDZVkdlpWH6818/ol/8+h1aeGTwEwC2C2eWKBYt
                    fm9pfg+TLx8d7qPGuig9sqGfXr35DO2aGqORtd1UHC6gx+Z2XkCBUtrtkwmoySAhpzCdRGls4rPYZMhVxEcDjnivQ0/T0UC8za5PAEyNDzL+8TOLs4l7RikAFXLwHoCKpy6coPrqUlo6uIsmx4ffeOLEISbnn4M9bbR7+zhNjg/R/pkttHl0gPneD59cDJM0
                    m2rUQqpSZJJJkEHsFC5FZcn0nagmfqGWR2+sN8VHPNaEWcRjpX//46P4rbdeoSKAOm0qGgrYaMQoHgMw8Mylk0xejygrg37w3GV65uIyc//myFAXTYwN0akj+6ipoZKCvvzPx0f67sCVI2AOzDxdZtovi6VcataLSMDKoBsx0I1ViNMM6HqLIP5Cmyzu4YKE
                    3FS6e+fn8Q8+vEu7/Uqa9Gmoy6mhAsAAYPd3zx9lpggOs46OHpqhY4dmKBL0UWHATQPdLdSyooqCXie1N8USebCLM5EvzoBfkg5teurzdaosMvCz6NZq0J/GU+hWJ+itdsSvREExWUpiFG48ez7+8ad/oD3VLpqvtFGnXUXzW9czB+vxS2ceY3JGt20aJr/b
                    RiGvk9YPrKFMHuflTB5nkHnprmldgVX1lWioKQMs2RlwZvNQIOaiVMaDLTPtw7CAS7e7QR9vAJ0qBP1uEPHNXnW8RilJACwe3Bm/e/dtOjExQNN+FQ26dfRIRwMcNtMH1y4epw1D3dS6sobefO0GpAJ+6dq+dpRF/IgEPCgJeVFeFEBNeQSxighgEfKQn81F
                    QJyGclkaFgJc9GtYdLEyhWISDm3Qg5qMoniny0a9Dk0CYGxdV/zZ65dopDVGOwpU1GeVk4bPmXE7LWTW5RGXlbx9cmwItdEiVBQHEoaMeYHLllDI50RZYQGiJUHAKkiDR8hBWMxBdS4bzSo2FkMcyNjsPzqzuJQvSCcWO4MqvR7aUualbIBMRlVczefQ7nIH
                    LdZ5qckop9aVMdR6zIiGPKgo8t8zjvhRFPAg4nch5HXC4zDDZTPC6zQj7HOiOOQBVOkseIVsRMRsVMpYiMlZqMxlo1zGQQ6HdaU+L4MaVJnE56RRlV5BFTkZVJKTRfuKLXSs2kHH61y02qygIYt0S3u+DrVuMyIeO4IeR8KUkd9tR0G+FflWIxwmHZxmHVxW
                    A9w2w71ORZ+RirCIhSIJC4ViFvwiDvxiLopz0hGQpNNqXRZ5BWlkEvCp3qql+RURWq5101LMRVt8auq0KqkvYKNulx6dbj1WuIwIOs0oyLcwuwEOs/6eTDrYTVrYjJoHGgKmZUoCHFmp8AlZcAvZcGenwSfmIShJZ361hyTp1KgRkI7HInlmJnXY1PEjdX6a
                    LXfSoN9GxQ4bdbgN1OXSo8etT3RVc3WJxgXs1BQkJ31jQ/bfYCUDtiw2HMI0uLK58Ih48Et4CEvT4c7mvthmEFKZlEuhbA4pBAKqtugpppGRTSqhqEJAEz7Vj3vdWvR7dBjy6fHiWH2iLtMbPoT9vVCms2EXchO7ggEoEPMQkqajWy+AV8yjZp2A6hQ88mel
                    kIULqlLwqc0kobFCM+2MBVYwxsMFeowGmG6K2TD3esKHjtTkJNgE9wDcIh5jmoAISJhGGyxbJpvC4jSqlHFptUlMQx4VjRZaaGPYfIYxXxcwYiRowljY8mVN7rcdBSOPBef9UWB0bzq48Im4eKdRzawNKpZnUZNdRf1+4+EuWRIGfToM+w1YHzRiJGTGnip3
                    olb4gboPDZAHwM5lwZ7JgV2QllgT+UIuvCIegtJ0hEVpKNIrS6qUWWi1KdHt1mDAp8NaBiBgxLqg8ctaVQ/UfWgAGQBLUhIs7BRY+OwEBDMKPkk6QjI+ihUCVKjFqDXI0GxTYo1Lgz6vDoMFhgREp0cDMY+FTAASIHH9VlPAPGRilASYOalwMCelOB2BHD4i
                    CgFK8kQo10hQY5Ch0apEe74a3R4d+nx69Pl0CGqFSEtJ+t8BRMw6uC9TchLcQh4CskwUKgQozstGqVqCcq0UVYZcNFiUaHWq0enWosurQ4NTDrEwGexkgH8fgLl+KwAmmBf7FyrITkeJSoRStThhXqaRolyXg0pDLmJmBVbYVGi0q1FhlUKpBLIy8SWA+H8F
                    +L+K/wCOcMeE2Xdw+QAAAABJRU5ErkJggg==')
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

        # Convert GUID to MSI Packed GUID (ProductID)
        # MSI reverses each segment: segments 1-3 are fully reversed, segments 4-5 are pair-swapped
        # Example: {FEEDBEEF-BEEF-4DAD-BEEF-B628CCCA16E0} → FEEBDEEFFEEBDAD4EBFE6B82CCAC610E
        [string]$private:stripped = $ARPAppGuid -replace '[{}\-]', ''
        [string]$ARPFuncProductID = (
            # Segment 1 (8 chars): reverse
            ($stripped[7..0] -join '') +
            # Segment 2 (4 chars): reverse
            ($stripped[11..8] -join '') +
            # Segment 3 (4 chars): reverse
            ($stripped[15..12] -join '') +
            # Segments 4+5 (16 chars): swap each pair
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
        [string]$private:DeployedWrapperPath     = Join-Path -Path $ARPAppFolder -ChildPath $DeployedWrapperName
        [string]$private:DeployedInstallerPath   = Join-Path -Path $ARPAppFolder -ChildPath $DeployedInstallerName
        [string]$private:DeployedUninstallerPath = Join-Path -Path $ARPAppFolder -ChildPath $DeployedUninstallerName

        # Registry / icon / batch paths
        [string]$ARPFuncIconPath        = Join-Path -Path $ARPAppFolder -ChildPath "$($ARPAppName -replace '\s', '').ico"
        [string]$ARPFuncUninstallRegKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$ARPAppGuid"
        [string]$ARPFuncProductsRegKey  = "HKCR:\Installer\Products\$ARPFuncProductID"

        # Version gate: skip install when an equal-or-newer version is already registered (unless -ARPAppForce $true).
        # Emits $true if the caller should proceed with the installer payload, $false to skip.
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

        # Modify (ReInstall) extras: forward shortcut/include flags + optional installer script
        [string]$private:ModifyExtraArgs = ''
        if ($ARPAppIncludeFolder)                                    { $ModifyExtraArgs += " -ARPAppIncludeFolder `$true" }
        if (-not [string]::IsNullOrWhiteSpace($ARPAppUserStartFile)) { $ModifyExtraArgs += " -ARPAppUserStartFile '$ARPAppUserStartFile'" }
        if ($ARPAppShortcutOnDesktop)                                { $ModifyExtraArgs += " -ARPAppShortcutOnDesktop `$true" }
        if ($ARPAppShortcutInStart)                                  { $ModifyExtraArgs += " -ARPAppShortcutInStart `$true" }
        if ($ARPAppInstallScript -and (Test-Path $ARPAppInstallScript)) {
            $ModifyExtraArgs = " -ARPAppInstallScript '$DeployedInstallerPath'" + $ModifyExtraArgs
        }
        [string]$ARPFuncModifycmd2 = & $BuildPwshLine 'ReInstall' $ModifyExtraArgs

        # Ensure application folder exists otherwise create it
        if(-not (Test-Path $ARPAppFolder) -or $ARPAppForce){
            if ($PSCmdlet.ShouldProcess($ARPAppFolder, "Create application folder")) {
                try {
                    New-Item -ItemType Directory -Path $ARPAppFolder -Force -ErrorAction Stop | Out-Null
                    Write-Verbose "Application folder ready: $ARPAppFolder"
                    } catch {Write-Warning "Failed to create folder $ARPAppFolder. Error: $_"}
            }
        } else {Write-Verbose "Application folder already exists: $ARPAppFolder"}

        # Create and Save the AppIcon - prefer external .ico file, then parameter Base64, then embedded default Base64
        [string]$private:EffectiveIconBase64 = if ($ARPAppIcon) { $ARPAppIcon } else { $script:DefaultIconBase64 }
        if ($ARPAppIconPath -and (Test-Path $ARPAppIconPath)) {
            if (-not (Test-Path $ARPFuncIconPath) -or $ARPAppForce) {
                if ($PSCmdlet.ShouldProcess($ARPFuncIconPath, "Copy AppIcon from $ARPAppIconPath")) {
                    try {
                        Copy-Item -Path $ARPAppIconPath -Destination $ARPFuncIconPath -Force | Out-Null
                        Write-Verbose "Success to copy AppIcon from $ARPAppIconPath to $ARPFuncIconPath"
                    } catch {Write-Warning "Failed to copy AppIcon from $ARPAppIconPath. Error: $_"}
                }
            } else {Write-Verbose "AppIcon already exists: $ARPFuncIconPath"}
        } elseif ($EffectiveIconBase64 -and (-not (Test-Path $ARPFuncIconPath) -or $ARPAppForce)) {
            if ($PSCmdlet.ShouldProcess($ARPFuncIconPath, "Save AppIcon from Base64")) {
                try {
                    $ContentBytes = [System.Convert]::FromBase64String($EffectiveIconBase64)
                    [System.IO.File]::WriteAllBytes($ARPFuncIconPath, $ContentBytes)
                    Write-Verbose "Success to save AppIcon from Base64 to $ARPFuncIconPath"
                } catch {Write-Warning "Failed to save AppIcon to $ARPFuncIconPath. Error: $_"}
            }
        } elseif (Test-Path $ARPFuncIconPath) {Write-Verbose "AppIcon already exists: $ARPFuncIconPath"}

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

        # Create All-Users desktop and startmenu shortcuts to the configured start file (after companion-file copy so the target exists)
        if (-not [string]::IsNullOrWhiteSpace($ARPAppUserStartFile)) {
            [string]$private:StartFileLeaf   = Split-Path -Path $ARPAppUserStartFile -Leaf
            [string]$private:StartFileTarget = Join-Path -Path $ARPAppFolder -ChildPath $StartFileLeaf
            if (-not (Test-Path -LiteralPath $StartFileTarget -PathType Leaf)) {
                Write-Warning "ARPAppUserStartFile '$StartFileLeaf' not found in $ARPAppFolder. Place it in the wrapper's source folder and use -ARPAppIncludeFolder `$true. Skipping shortcut creation."
            } elseif ($ARPAppShortcutOnDesktop -or $ARPAppShortcutInStart) {
                [string]$private:DesktopLnk   = Join-Path -Path "$Env:Public\Desktop" -ChildPath "$ARPAppName.lnk"
                [string]$private:StartMenuDir = Join-Path -Path "$Env:ProgramData\Microsoft\Windows\Start Menu\Programs" -ChildPath $ARPAppPublisher
                [string]$private:StartMenuLnk = Join-Path -Path $StartMenuDir -ChildPath "$ARPAppName.lnk"
                [string]$private:LnkIcon      = if (Test-Path -LiteralPath $ARPFuncIconPath) { $ARPFuncIconPath } else { $StartFileTarget }
                try {
                    $private:WshShell = New-Object -ComObject WScript.Shell
                    if ($ARPAppShortcutOnDesktop -and (-not (Test-Path -LiteralPath $DesktopLnk) -or $ARPAppForce)) {
                        if ($PSCmdlet.ShouldProcess($DesktopLnk, "Create Desktop shortcut")) {
                            try {
                                $private:lnk = $WshShell.CreateShortcut($DesktopLnk)
                                $lnk.TargetPath        = $StartFileTarget
                                $lnk.WorkingDirectory  = $ARPAppFolder
                                $lnk.IconLocation      = $LnkIcon
                                $lnk.Description       = $ARPAppName
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
                                    $lnk.TargetPath        = $StartFileTarget
                                    $lnk.WorkingDirectory  = $ARPAppFolder
                                    $lnk.IconLocation      = $LnkIcon
                                    $lnk.Description       = $ARPAppName
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
        # Convert GUID to ProductID (it needs to be in reversed order)
        [string]$private:parts = $ARPAppGuid -replace '[{}]', ''
        [array]$private:seg    = $parts.Split('-')
        [char[]]$private:tail  = $seg[4].ToCharArray()
        $ARPFuncProductID = $seg[0] + $seg[1] + $seg[2] + $seg[3] + (-join ($tail[1],$tail[0],$tail[3],$tail[2],$tail[5],$tail[4],$tail[7],$tail[6],$tail[9],$tail[8],$tail[11],$tail[10]))
        Write-Verbose "Derived ProductID for removal: $ARPFuncProductID"

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
#endregion

#region ---------------------------------------------------[[Script Execution]------------------------------------------------------
# Start T-Bone custom logging (can be removed if you don't want to use T-Bone logging)
Invoke-TboneLog -LogMode Start -Logname $LogName -LogToGUI $LogToGUI -LogToEventlog $LogToEventlog -LogEventIds $LogEventIds -LogToDisk $LogToDisk -LogPath $LogToDiskPath -LogToHost $LogToHost

# Detect execution context
$ScriptContext = Get-ScriptExecutionContext

# Classify location and elevation
[bool]$IsInstalled = $ScriptContext.ExecutionPath -in 'ProgramFiles','ProgramFilesX86','ProgramData'
[bool]$IsElevated  = $ScriptContext.ExecutionIdentity -in 'System','Admin'

# Hard-fail when the requested action requires HKLM/Program Files writes but we lack elevation.
[bool]$NeedsElevation = -not ($IsInstalled -and $InstallType -eq 'Install')
if ($NeedsElevation -and -not $IsElevated) {
    Write-Error "InstallType '$InstallType' from '$($ScriptContext.ExecutionPath)' requires Admin/System (current identity: '$($ScriptContext.ExecutionIdentity)'). Aborting."
    Invoke-TboneLog Stop
    return
}

# Check and add scripts as wrapped Un/installer scripts if provided, otherwise use the inline scripts defined in the function bodies 
$WrappedInstallerScript   = $InlineInstallerScript
if (-not [string]::IsNullOrWhiteSpace($ARPAppInstallScript)) {
    if (Test-Path -LiteralPath $ARPAppInstallScript -PathType Leaf) {
        try {
            $WrappedInstallerScript = [scriptblock]::Create((Get-Content -LiteralPath $ARPAppInstallScript -Raw -ErrorAction Stop))
            Write-Verbose "Loaded installer script from: $ARPAppInstallScript"
        } catch {Write-Warning "Failed to load installer script from '$ARPAppInstallScript': $($_.Exception.Message). Using inline installer."}
    } else {Write-Warning "Installer script file not found at '$ARPAppInstallScript'. Using inline installer."}
} else {Write-Verbose "No ARPAppInstallScript provided. Using inline installer."}
$WrappedUnInstallerScript = $InlineUnInstallerScript
if (-not [string]::IsNullOrWhiteSpace($ARPAppUnInstallScript)) {
    if (Test-Path -LiteralPath $ARPAppUnInstallScript -PathType Leaf) {
        try {
            $WrappedUnInstallerScript = [scriptblock]::Create((Get-Content -LiteralPath $ARPAppUnInstallScript -Raw -ErrorAction Stop))
            Write-Verbose "Loaded uninstaller script from: $ARPAppUnInstallScript"
        } catch {Write-Warning "Failed to load uninstaller script from '$ARPAppUnInstallScript': $($_.Exception.Message). Using inline uninstaller."}
    } else {Write-Warning "Uninstaller script file not found at '$ARPAppUnInstallScript'. Using inline uninstaller."}
} else {Write-Verbose "No ARPAppUnInstallScript provided. Using inline uninstaller."}

# Dispatch by Executionpath + InstallType Logic:
#   Installed + Install     : No install - Just run wrapped script
#   Staging   + Install     : Version check -> Stage files -> Register ARP -> Run wrapped script
#   Installed + ReInstall   : Re-register ARP -> Run wrapped script
#   Staging   + ReInstall   : Run from installed path if exists -> Skip version check -> Stage files -> Register ARP -> Run wrapped script
#   Installed + UnInstall   : Run wrapped uninstaller -> Remove ARP -> Delete app folder + Companion files
#   Staging   + UnInstall   : Run from installed path if exists - Run wrapped uninstaller -> Remove ARP -> Delete app folder + Companion files

try {
    switch ($InstallType) {
        'Install' {
            if ($IsInstalled) {
                Write-Verbose "Running Installmode from installed location ($($ScriptContext.ExecutionPath)) - running payload only"
                if ($PSCmdlet.ShouldProcess('Installer payload', 'Run installer script')) { & $WrappedInstallerScript }; break
            }
            Write-Verbose "Running Installmode from staging ($($ScriptContext.ExecutionPath)) - install if version check passes"
            [bool]$private:Proceed = Add-AddRemovePrograms -ARPAppName $ARPAppName -ARPAppVersion $ARPAppVersion -ARPAppGuid $ARPAppGuid -ARPAppPublisher $ARPAppPublisher -ARPAppFolder $ARPAppFolder -ARPAppEnableUninstall $ARPAppEnableUninstall `
                -ARPAppEnableModify $ARPAppEnableModify -ARPAppIcon $ARPAppIcon -ARPAppIconPath $ARPAppIconPath -ARPAppInstallScript $ARPAppInstallScript -ARPAppUnInstallScript $ARPAppUnInstallScript -ARPAppIncludeFolder $ARPAppIncludeFolder `
                -ARPAppUserStartFile $ARPAppUserStartFile -ARPAppShortcutOnDesktop $ARPAppShortcutOnDesktop -ARPAppShortcutInStart $ARPAppShortcutInStart -ARPAppForce $ARPAppForce
            if (-not $Proceed) { break }
            if ($PSCmdlet.ShouldProcess('Installer payload', 'Run installer script')) { & $WrappedInstallerScript }
        }
        'ReInstall' {
            if (-not $IsInstalled) {
                write-verbose "Running ReInstallmode from staging location ($($ScriptContext.ExecutionPath)) - Redirecting to installed app folder for ReInstall execution."
                [string]$private:ReinstallBatPath = Join-Path -Path $ARPAppFolder -ChildPath "reinstall-$ARPAppGuid.bat"
                if (Test-Path -LiteralPath $ReinstallBatPath) {
                    Write-Verbose "Redirecting ReInstall from '$($ScriptContext.ExecutionPath)' to installed batch: $ReinstallBatPath"
                    if ($PSCmdlet.ShouldProcess($ReinstallBatPath, 'Run installed batch (ReInstall)')) { & $ReinstallBatPath }
                    break
                }
                Write-Verbose "No redirect batch found at $ReinstallBatPath; continuing in-process ReInstall."
            }
            Write-Verbose "Running ReInstallmode from installed location$($ScriptContext.ExecutionPath) (installed=$IsInstalled). Re-registering ARP and running installer."
            $null = Add-AddRemovePrograms -ARPAppName $ARPAppName -ARPAppVersion $ARPAppVersion -ARPAppGuid $ARPAppGuid -ARPAppPublisher $ARPAppPublisher -ARPAppFolder $ARPAppFolder -ARPAppEnableUninstall $ARPAppEnableUninstall `
                -ARPAppEnableModify $ARPAppEnableModify -ARPAppIcon $ARPAppIcon -ARPAppIconPath $ARPAppIconPath -ARPAppInstallScript $ARPAppInstallScript -ARPAppUnInstallScript $ARPAppUnInstallScript -ARPAppIncludeFolder $ARPAppIncludeFolder `
                -ARPAppUserStartFile $ARPAppUserStartFile -ARPAppShortcutOnDesktop $ARPAppShortcutOnDesktop -ARPAppShortcutInStart $ARPAppShortcutInStart -ARPAppForce $true
            if ($PSCmdlet.ShouldProcess('Installer payload', 'Run installer script')) { & $WrappedInstallerScript }
        }
        'UnInstall' {
            if (-not $IsInstalled) {
                write-verbose "Running UnInstallmode from staging location ($($ScriptContext.ExecutionPath)) - Redirecting to installed app folder for UnInstall execution."
                [string]$private:UninstallBatPath = Join-Path -Path $ARPAppFolder -ChildPath "uninstall-$ARPAppGuid.bat"
                if (Test-Path -LiteralPath $UninstallBatPath) {
                    Write-Verbose "Redirecting UnInstall from '$($ScriptContext.ExecutionPath)' to installed batch: $UninstallBatPath"
                    if ($PSCmdlet.ShouldProcess($UninstallBatPath, 'Run installed batch (UnInstall)')) { & $UninstallBatPath }
                    break
                }
                Write-Verbose "No redirect batch found at $UninstallBatPath; continuing in-process UnInstall."
            }
            Write-Verbose "Running UnInstallmode from installed location ($($ScriptContext.ExecutionPath)) - Running uninstaller and removing ARP."
            if ($PSCmdlet.ShouldProcess('Uninstaller payload', 'Run uninstaller script')) { & $WrappedUnInstallerScript }
            Remove-AddRemovePrograms -ARPAppName $ARPAppName -ARPAppGuid $ARPAppGuid -ARPAppFolder $ARPAppFolder -ARPAppPublisher $ARPAppPublisher
        }
    }
    write-Verbose "Completed InstallType '$InstallType' execution."
}
finally {
    Invoke-TboneLog Stop
}
#endregion

