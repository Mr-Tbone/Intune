<#PSScriptInfo
.SYNOPSIS
    Script for Intune to build a PowerShell based win32 app 
 
.DESCRIPTION
    This script will act as a wrapper for PowerShell script to a win32 app for Intune.
    The script will show up as an app in settings > Apps > Apps & features
        
.EXAMPLE
   .\Intune-Win32AppWrapper.ps1
    Will run the wrapped powershell script once to install with the default parameters.

   .\Intune-Win32AppWrapper.ps1 -InstallType ReInstall
    Will re-run the wrapped powershell script to install with the default parameters.

   .\Intune-Win32AppWrapper.ps1 -InstallType UnInstall
    Will run the wrapped powershell script to uninstall with the default parameters.

.NOTES
    Written by Mr-Tbone (Tbone Granheden) Coligo AB
    torbjorn.granheden@coligo.se

.VERSION
    1.0

.RELEASENOTES
    1.0 2022-02-18 Initial Build

.AUTHOR
    Tbone Granheden 
    @MrTbone_se

.COMPANYNAME 
    Coligo AB

.GUID 
    65FD0F16-91BE-4346-BDA4-24BAAA2344E2

.COPYRIGHT
    Feel free to use this, But would be grateful if My name is mentioned in Notes 

.CHANGELOG
    1.0.2505.1 - Initial Version
#>

#region ---------------------------------------------------[Set script requirements]-----------------------------------------------
#
#Requires -Version 4.0
#Requires -RunAsAdministrator
#endregion

#region ---------------------------------------------------[Script Parameters]-----------------------------------------------
#modify the parameters defaultsbelow to change the values for the script if running without parameters
Param(
    [Parameter(HelpMessage = 'Enter Install, ReInstall or UnInstall.')]    
    [validateset("Install", "ReInstall", "UnInstall")]
    [string]$InstallType = "Install",

    [Parameter(HelpMessage = 'Company name used for naming of folders and registry keys.')]
    [String]$Company = "Coligo",

    [Parameter(HelpMessage = 'Name of the application/script being wrapped.')]
    [String]$AppName = "App Name",

    [Parameter(HelpMessage = 'Version of the application. Increment when changing config.')]
    [ValidatePattern("^\d+\.\d+(\.\d+)?$")]
    [version]$AppVersion = "1.0",

    [Parameter(HelpMessage = 'Register an App in Add Remove Programs for versioning and uninstall.')]
    [ValidateSet("True", "False")]
    [bool]$AddRemoveProgramEnabled = $True,

    [Parameter(HelpMessage = 'Enable an uninstall option in Add Remove Programs.')]
    [ValidateSet("True", "False")]
    [bool]$AddRemoveProgramUninstall = $True,

    [Parameter(HelpMessage = 'Enable a modify option in Add Remove Programs (typically for repair/reinstall).')]
    [ValidateSet("True", "False")]
    [bool]$AddRemoveProgramModify = $True,

    [Parameter(HelpMessage = 'Enable GUI logging for testing script in manual execution.')]
    [ValidateSet("True", "False")]
    [bool]$GUILogEnabled = $False,

    [Parameter(HelpMessage = 'Create an event log in Event Viewer Application log.')]
    [ValidateSet("True", "False")]
    [bool]$EventLogEnabled = $True,

    [Parameter(HelpMessage = 'Create a file log for troubleshooting in the specified path.')]
    [ValidateSet("True", "False")]
    [bool]$FileLogEnabled = $True,

    [Parameter(HelpMessage = 'Path to the file log.')]
    [string]$FileLogPath = "$env:TEMP",

    [Parameter(HelpMessage = 'Purge old file logs to cleanup after previous executions.')]
    [ValidateSet("True", "False")]
    [bool]$FileLogPurge = $True,

    [Parameter(HelpMessage = 'Number of old file logs to keep when purging.')]
    [ValidateRange(1, 99)]
    [int]$FileLogHistory = 10,
    
    [Parameter(HelpMessage = 'Optional path to a .ps1 file to use as the installer script.')]
    [string]$InstallerScriptPath,

    [Parameter(HelpMessage = 'Optional path to a .ps1 file to use as the uninstaller script.')]
    [string]$UninstallerScriptPath
)
#endregion

#region ---------------------------------------------------[Modifiable Parameters and defaults]------------------------------------
# Application GUID for app used in Add Remove Programs and detections. NOTE: This needs to be unique for each wrapped app.
$AppGuid        = "{FEEDBEEF-BEEF-BEEF-BEEF-FEEDBEEF0002}"  
# If using MSI detection method in Intune the AppGuid must be converted to a valid MSI GUID format.
# This can be done by a special reformating and reordering the app guid. the above example would be: {FEEBDEEF-FEEB-FEEB-EBFE-FEEDBEEF0002}
# For simplicity use the above example and change only the last 4 digits. The Intune MSI version detection will not work. 

# Define default scriptblocks first
[scriptblock]$DefaultWrappedInstallerScript = {
    $viveToolExe    = ".\ViVeTool.exe"          # Path to ViVeTool executable
    $featureIds     = @(47557358, 45317806)     # Feature IDs to check
    # Disable features if they are enabled
    foreach ($featureId in $featureIds) {
        try {
            $result = & $viveToolExe /query /id:$featureId 2>&1
            if ($result -match "State\s*:\s*Enabled") {
                Write-verbose "Feature ID $featureId is Enabled, trying to Disable."
                & $viveToolExe /disable /id:$featureId
            }
            elseif($result -match "No configuration for feature ID"){
                Write-Verbose  "Feature ID $featureId does not exist. No need to Disable"
            }
            elseif($result -match "Unhandled Exception"){
                Write-Error  "Unhandled Exception occured with tool $viveToolExe. Exiting. Error: $result"
            }
            else {
                Write-host  "Feature ID $featureId is Disabled. No need to Disable"
            }
        } catch {
            Write-Error "Failed to query or Disable feature ID $featureId. Exiting. Error: $($_.Exception.Message)"
        }
    }
}

[scriptblock]$DefaultWrappedUnInstallerScript = {
    $viveToolExe    = ".\ViVeTool.exe"          # Path to ViVeTool executable
    $featureIds     = @(47557358, 45317806)     # Feature IDs to check
    # Disable features if they are enabled
    foreach ($featureId in $featureIds) {
        try {
            $result = & $viveToolExe /query /id:$featureId 2>&1
            if ($result -match "State\s*:\s*Enabled") {
                Write-host "Feature ID $featureId is Disabled, trying to Enable."
                & $viveToolExe /enable /id:$featureId
            }
            elseif($result -match "No configuration for feature ID"){
                Write-host  "Feature ID $featureId does not exist. No need to Enable"
            }
            elseif($result -match "Unhandled Exception"){
                Write-Error  "Unhandled Exception occured with tool $viveToolExe. Exiting. Error: $result"
            }
            else {
                Write-host  "Feature ID $featureId is Enabled. No need to Enable"
            }
        } catch {
            Write-Error "Failed to query or Enable feature ID $featureId. Exiting. Error: $($_.Exception.Message)"
        }
    }
}

# Initialize with defaults
$WrappedInstallerScript = $DefaultWrappedInstallerScript
$WrappedUnInstallerScript = $DefaultWrappedUnInstallerScript
#endregion

#region ---------------------------------------------------[Set global script settings]--------------------------------------------
Set-StrictMode -Version Latest
#endregion

#region ---------------------------------------------------[Static Variables]------------------------------------------------------
#Log File Info
$script:GetTimestamp = { Get-Date -Format 'yyyy-MM-dd HH:mm:ss' }

#Apps and version settings
$AppPublisher   = $company                                  # The publisher of the application in Add Remove Programs
$AppFolder      = "$Env:Programfiles\$company"              # The folder for uninstallation scripts
$AppKey         = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$AppGuid"

# Imported icon for Add remove Programs in Base64 format 
$AppIcon = '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'
#endregion

#region ---------------------------------------------------[Import Modules and Extensions]-----------------------------------------
#endregion

#region ---------------------------------------------------[Functions]------------------------------------------------------------
Function Invoke-TboneLogging {
    # Function to capture all common write- cmdlets and send those messages to GUI, File and/or Event log
    # Requires a start call with invoke-TboneLogging -logfile -type "Start" -Logstring "Start of script execution"
    # Requires a stop call with invoke-TboneLogging -logfile -type "End" -Logstring "End of script execution"
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,   HelpMessage = "The message to be logged. Timestamp and Type will be added automatically")]
        [string]$Logstring = "",

        [Parameter(Mandatory = $false,  HelpMessage = "The Type of log entry: Info, Warning, Error, Start, or End. Optional and defaults to Start")]
        [ValidateSet("Info", "Warning", "Error", "Start", "End")]
        [string]$LogType = "Start",

        [Parameter(Mandatory = $false, HelpMessage = "Name of the script being executed, default is the script name from the execution context")]
        [string]$ScriptName = "PS: $(Split-Path -Leaf $PSCommandPath)",

        [Parameter(Mandatory = $false, HelpMessage = "Enable GUI logging. Defaults to true")]
        [ValidateSet("True", "False")]
        [bool]$GUILogEnabled = $true,

        [Parameter(Mandatory = $false, HelpMessage = "Enable Event logging. Defaults to false")]
        [ValidateSet("True", "False")]
        [bool]$EventLogEnabled = $true,

        [Parameter(Mandatory = $false, HelpMessage = "Event ID for success logging. Defaults to 11001")]
        [ValidateRange(10000,19999)]
        [string]$EventLogSuccessEventId = "11001",

        [Parameter(Mandatory = $false, HelpMessage = "Event ID for warning logging. Defaults to 11002")]
        [ValidateRange(10000,19999)]
        [string]$EventLogWarningEventId = "11002",

        [Parameter(Mandatory = $false, HelpMessage = "Event ID for error logging. Defaults to 11003")]
        [ValidateRange(10000,19999)]
        [string]$EventLogErrorEventId  = "11003",

        [Parameter(Mandatory = $false, HelpMessage = "Enable File logging. Defaults to false")]
        [ValidateSet("True", "False")]
        [bool]$FileLogEnabled = $false,

        [Parameter(Mandatory = $false,  HelpMessage = "Path to store the log file. Defaults to TEMP directory")]
        [System.IO.DirectoryInfo]$FileLogPath = "$($env:TEMP)",

        [Parameter(Mandatory = $false, HelpMessage = "Enable purging of old log files. Defaults to true")]
        [ValidateSet("True", "False")]
        [bool]$FileLogPurge = $true,

        [Parameter(Mandatory = $false, HelpMessage = "Number of old log files to keep. Defaults to 10")]
        [ValidateRange(1, 99)]
        [int]$FileLogHistory = 10
    )
    Begin {
        
        # Initialize timestamp function
        $script:GetTimestamp = { Get-Date -Format 'yyyy-MM-dd HH:mm:ss' }

        # Initialize script scope variables if first time called i.e Type "Start"
        if (-not (Test-Path variable:script:LoggingStarted)) {
            $script:OriginalFunctions   = @{}
            $script:LoggingStarted      = $false
            $script:AllEventlogs        = [System.Text.StringBuilder]::new()
            # Get function variables and set as script variables for consistant config
            if (!(Test-Path variable:Script:Scriptname))      {$script:ScriptName         = $ScriptName}
            if (!(Test-Path variable:script:GUILogEnabled))   {$script:GUILogEnabled      = $GUILogEnabled}
            if (!(Test-Path variable:script:EventLogEnabled)) {$script:EventLogEnabled    = $EventLogEnabled}
            if (!(Test-Path variable:script:FileLogEnabled))  {$script:FileLogEnabled     = $FileLogEnabled}
            if (!(Test-Path variable:script:FileLogPath))     {$script:FileLogPath        = $FileLogPath}
            if (!(Test-Path variable:script:FileLogPurge))    {$script:FileLogPurge       = $FileLogPurge}
            if (!(Test-Path variable:script:FileLogHistory))  {$script:FileLogHistory     = $FileLogHistory}
            # Store original write- functions trying to use them
            $script:OriginalFunctions = @{
                'Write-Host'    = Get-Command Write-Host
                'Write-Verbose' = Get-Command Write-Verbose
                'Write-Output'  = Get-Command Write-Output
                'Write-Warning' = Get-Command Write-Warning
                'Write-Error'   = Get-Command Write-Error
            }
            # Override all Write- functions with custom logging functions
            Set-Item -Path "function:global:Write-Verbose" -Value {
                param([string]$Message)
                $callStack = Get-PSCallStack
                $callerFunction = if ($callStack.Count -gt 1) {$callStack[1].FunctionName} else {""}
                $patterns = "<begin>", "<process>", "<end>"
                foreach ($pattern in $patterns) {$callerFunction = $callerFunction -replace $pattern, ""}
                Invoke-TboneLogging -LogType "Info" -Logstring "$callerFunction,$Message"
            }
            Set-Item -Path "function:global:Write-Warning" -Value {
                param([string]$Message)
                $callStack = Get-PSCallStack
                $callerFunction = if ($callStack.Count -gt 1) {$callStack[1].FunctionName} else {""}
                $patterns = "<begin>", "<process>", "<end>"
                foreach ($pattern in $patterns) {$callerFunction = $callerFunction -replace $pattern, ""}
                Invoke-TboneLogging -LogType "Warning" -Logstring "$callerFunction,$Message"
            }           
            Set-Item -Path "function:global:Write-Error" -Value {
                param([string]$Message)
                $callStack = Get-PSCallStack
                $callerFunction = if ($callStack.Count -gt 1) {$callStack[1].FunctionName} else {""}
                $patterns = "<begin>", "<process>", "<end>"
                foreach ($pattern in $patterns) {$callerFunction = $callerFunction -replace $pattern, ""}
                Invoke-TboneLogging -LogType "Error" -Logstring "$callerFunction,$Message"
            }
            Set-Item -Path "function:global:Write-Output" -Value {
                param([string]$Message)
                $callStack = Get-PSCallStack
                $callerFunction = if ($callStack.Count -gt 1) {$callStack[1].FunctionName} else {""}
                $patterns = "<begin>", "<process>", "<end>"
                foreach ($pattern in $patterns) {$callerFunction = $callerFunction -replace $pattern, ""}
                Invoke-TboneLogging -LogType "Info" -Logstring "$callerFunction,$Message"
            }
            Set-Item -Path "function:global:Write-Host" -Value {
                param([string]$Message)
                $callStack = Get-PSCallStack
                $callerFunction = if ($callStack.Count -gt 1) {$callStack[1].FunctionName} else {""}
                $patterns = "<begin>", "<process>", "<end>"
                foreach ($pattern in $patterns) {$callerFunction = $callerFunction -replace $pattern, ""}
                Invoke-TboneLogging -LogType "Info" -Logstring "$callerFunction,$Message"
            }

            # If Filelogging is enabled
            if ($Script:FileLogEnabled) {
                #Create the log path if it doesn't exist
                $SanitizedTimestamp = ($Script:GetTimestamp.Invoke()) -replace "[:]", "-"
                $SanitizedScriptName = $Script:ScriptName -replace "[:\\/*?""<>|]", "_"
                $script:LogFilePath = Join-Path $script:FileLogPath "$($SanitizedScriptName)_$($SanitizedTimestamp).log"
                if (!(Test-Path $script:FileLogPath)) {
                    Try {New-Item -ItemType Directory -Path $script:FileLogPath -Force}
                    Catch {& $script:OriginalFunctions['Write-Error'] "$($script:GetTimestamp.Invoke()),Error,Failed to create log directory $($script:FileLogPath) with error: $_"}
                }
                # If FileLogPurge is enabled, remove old log files
                if ($script:FileLogPurge) {
                    Try {Get-ChildItem -Path $script:FileLogPath | Where-Object { $_.Name -like "$($script:ScriptName)*" } | Sort-Object CreationTime -Descending | Select-Object -Skip $script:FileLogHistory | Remove-Item -Force}
                    Catch {& $script:OriginalFunctions['Write-Warning'] "$($script:GetTimestamp.Invoke()),Warning,Failed to purge log files in directory $($script:FileLogPath) with error: $_"}
                    $script:FileLogPurge = $false
                }
                #Create the log file if it doesn't exist
                if (!(Test-Path $script:LogFilePath)) {
                    Try {$null = New-Item -ItemType File -Path $script:LogFilePath -Force}
                    Catch {& $script:OriginalFunctions['Write-Error'] "$($script:GetTimestamp.Invoke()),Error,Failed to create log file $($script:LogFilePath) with error: $_"}
                }
            }
            # If Event logging is enabled
            if ($script:EventLogEnabled){
                # Create the event log source if it doesn't exist
                If(![System.Diagnostics.Eventlog]::SourceExists($script:scriptName)){
                    Try {$null = New-EventLog -LogName Application -Source "$script:scriptName"}
                    Catch{& $script:OriginalFunctions['Write-Error'] "$($script:GetTimestamp.Invoke()),Error,Failed to create event log source with error:$_"}
                }
            }
        }
        else {$script:LoggingStarted = $true} # Set logging started to true if not already set
    }

    Process {
        try {
            # Auto-convert to End if already started, set the logmessage for end with scriptname if not set by function call
            if ($LogType -eq "Start" -and $script:LoggingStarted) {$LogType = "End"}
            
            # Set the log message if not set by function call
            if ([string]::IsNullOrWhiteSpace($Logstring)) {
                $Logstring = switch ($LogType) {
                    'Start' { "Starting script execution: $script:ScriptName" }
                    'End'   { "Ending script execution: $script:ScriptName" }
                    default { "No message provided for type: $LogType" }
                }
            }
            
            # Set the log message
            $LogMessage = "$($Script:GetTimestamp.Invoke()),$LogType,$Logstring"
            $null = $Script:AllEventlogs.AppendLine($LogMessage)

            # GUI Logging
            if ($script:GUILogEnabled) {
                # Set color based on type
                $foreGroundColor = switch ($LogType) {
                    "Info"    { [System.ConsoleColor]::Green }
                    "Warning" { [System.ConsoleColor]::Yellow }
                    "Error"   { [System.ConsoleColor]::Red }
                    default   { [System.ConsoleColor]::White }
                }
                & $script:OriginalFunctions['Write-Host'] $LogMessage -ForegroundColor $foreGroundColor
            }

            # File logging
            if ($script:FileLogEnabled) {
                Try {Add-content $script:LogFilePath -value $LogMessage}
                Catch{& $script:OriginalFunctions['Write-Error'] "$($script:GetTimestamp.Invoke()),Error,Failed to write to log file with error:$_"}
                }

        }
        catch {& $script:OriginalFunctions['Write-Error'] "$($script:GetTimestamp.Invoke()),Error,Logging failed: $_"}
    }
    
    End {
                # File logging enabled
        if ($script:FileLogEnabled -and ($LogType -eq "End")) {
            # Write the complete log to the file
           Write-Verbose "Logfile saved at: $($script:LogFilePath)"
        }
        # Event logging enabled
if ($script:EventLogEnabled -and ($LogType -eq "End")) {
    $EventlogTextLimit = 32000
    # Convert StringBuilder to proper string content
    $eventlog = $Script:AllEventlogs.ToString()

    # Determine most severe event type
    $EventType = switch ($true) {
        { $eventlog -match "Error" }   { "Error" }
        { $eventlog -match "Warning" -and $eventlog -notmatch "Error" } { "Warning" }
        default                        { "Information" }
    }

    $EventLogEventID = switch ($true) {
        { $eventlog -match "Error" }   { $EventLogErrorEventId }
        { $eventlog -match "Warning" -and $eventlog -notmatch "Error" } { $EventLogWarningEventId }
        default                        { $EventLogSuccessEventId }
    }

    # Split long messages if needed
    $EventLogParts = @()
    $EventLogParts = $eventlog -split "(.{$($EventlogTextLimit)})" -ne ""
    
    # Write each part to event log
    for ($i = 0; $i -lt $EventLogParts.Count; $i++) {
        $EventLogPrefix = if ($EventLogParts.Count -gt 1) {
            "Part $($i + 1) of $($EventLogParts.Count)`n"
        } else { "" }
        
        Try {
            Write-EventLog -LogName Application -Source $script:scriptName -EntryType $EventType -EventID $EventLogEventId -Message ($EventLogPrefix + $EventLogParts[$i])
        }
        Catch {
            & $script:OriginalFunctions['Write-Error'] "$($script:GetTimestamp.Invoke()),Error,Failed to write to event log:$_"
        }
    }
}

        # Cleanup and restore original functions when logging ends
        if ($LogType -eq "End" ) {
            # Remove all custom write- functions
            Remove-Item -Path Function:Write-* -Force -ErrorAction SilentlyContinue
            # Restore original functions
            $script:originalFunctions.Keys | ForEach-Object {
                try {
                    $functionName = $_
                    $functionDef = $script:originalFunctions[$functionName]
                    Set-Item -Path "function:$functionName" -Value ([ScriptBlock]::Create($functionDef)) -Force
                }
                catch {Write-Warning "Failed to restore function $functionName : $_"}
            }
            # Clean up script-scope variables
            (Get-Variable * -Scope Local).Name | Where-Object { $_ -ne "function" -and $_ -notlike "*Preference" } | ForEach-Object { Remove-Variable -Name $_ -ErrorAction SilentlyContinue -Scope Script}
        }
    }
}

Function Add-AddRemovePrograms {
    # Function to add the script as an application in Settings > Apps > Apps & features
    Param(
        [Parameter(Mandatory, HelpMessage = "Display name of the application.")]
        [string]$DisplayName,

        [Parameter(Mandatory, HelpMessage = "Version of the application.")]
        [version]$Version, 

        [Parameter(Mandatory, HelpMessage = "GUID of the application.")]
        [string]$Guid,

        [Parameter(Mandatory, HelpMessage = "Publisher of the application.")]
        [string]$Publisher,

        [Parameter(Mandatory, HelpMessage = "Base64-encoded Icon.")]
        [string]$Icon,

        [Parameter(Mandatory, HelpMessage = "Application folder path.")]
        [string]$AppFolder,

        [Parameter(Mandatory, HelpMessage = "Enable uninstall option.")]
        [bool]$UnInstallEnabled,

        [Parameter(Mandatory, HelpMessage = "Enable modify option.")]
        [bool]$ModifyEnabled
    )
    Begin {
        $ErrorActionPreference = 'Stop'
        Write-Verbose "Start Function Add-AddRemovePrograms"
        $private:hkcrDriveCreatedByThisFunction = $false # Flag to track PSDrive creation
    }
    Process {
        # Determine script's own name and path
        $ExecutingScriptPath = $PSCommandPath
        $ExecutingScriptName = (Split-Path $ExecutingScriptPath -Leaf) # Name with .ps1
        if (-not $ExecutingScriptPath) {
            Write-Error "Could not determine the script path using `$PSCommandPath."
            return
        }
        Write-Verbose "Executing script:$($ExecutingScriptPath) $($ExecutingScriptName)"

        # Convert GUID to ProductID (it needs to be in reversed order)
        [string]$LocalProductID = $Guid -replace '[{}]', ""
        [array]$LocalProductIDArray = $LocalProductID.Split("-")
        [string]$id0_local = $LocalProductIDArray[0]
        [string]$id1_local = $LocalProductIDArray[1]
        [string]$id2_local = $LocalProductIDArray[2]
        [string]$id3_local = $LocalProductIDArray[3]
        [char[]]$id4_local_chars = $LocalProductIDArray[4].ToCharArray()
        [string]$id4_local = -join ($id4_local_chars[1], $id4_local_chars[0], $id4_local_chars[3], $id4_local_chars[2], $id4_local_chars[5], $id4_local_chars[4], $id4_local_chars[7], $id4_local_chars[6], $id4_local_chars[9], $id4_local_chars[8], $id4_local_chars[11], $id4_local_chars[10])
        $LocalProductID = $id0_local + $id1_local + $id2_local + $id3_local + $id4_local

        # Define variables based on input parameters
        [string]$LocalAppIconName        = $DisplayName -replace '\s', ''
        [string]$LocalAppIconPath        = Join-Path -Path $AppFolder -ChildPath "$LocalAppIconName.ico"
        [string]$LocalAppUninstallRegKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$Guid"
        [string]$LocalAppProductsRegKey  = "HKCR:\Installer\Products\$LocalProductID"
        [string]$LocalAppUninstallString = "CMD /C START cmd /c " + '"' + (Join-Path -Path $AppFolder -ChildPath "uninstall-$Guid.bat") + '"'
        [string]$LocalAppUninstallBAT    = Join-Path -Path $AppFolder -ChildPath "uninstall-$Guid.bat"
        [string]$LocalAppUninstallcmd1   = "cd `"$AppFolder`"" # Ensure path with spaces is handled
        [string]$LocalAppUninstallcmd2   = "Powershell.exe -NoProfile -ExecutionPolicy Bypass -File `".\$ExecutingScriptName`" -installtype UnInstall" # Added -NoProfile
        [string]$LocalAppModifyString    = "CMD /C START cmd /c " + '"' + (Join-Path -Path $AppFolder -ChildPath "reinstall-$Guid.bat") + '"'
        [string]$LocalAppModifyBAT       = Join-Path -Path $AppFolder -ChildPath "reinstall-$Guid.bat"
        [string]$LocalAppModifycmd1      = "cd `"$AppFolder`"" # Ensure path with spaces is handled
        [string]$LocalAppModifycmd2      = "Powershell.exe -NoProfile -ExecutionPolicy Bypass -File `".\$ExecutingScriptName`" -installtype ReInstall"
        # Create modify string with both direct command and bat file options
        [string]$LocalAppModifyString    = "CMD /C START cmd /c " + '"' + $LocalAppModifyBAT + '"'

        # Ensure application folder exists
        if (!(Test-Path $AppFolder)) {
            try {
                New-Item -ItemType Directory -Path $AppFolder -Force | Out-Null
                Write-Verbose "Success to create folder: $AppFolder"
            } catch {
                Write-warning "Failed to create folder $AppFolder. Error: $_"
            }
        }

        # Save the AppIcon
        try {
            $ContentBytes = [System.Convert]::FromBase64String($Icon)
            # Set-Content -Path $LocalAppIconPath -Value $ContentBytes -Encoding Byte -Force # Original line
            [System.IO.File]::WriteAllBytes($LocalAppIconPath, $ContentBytes) # Changed line
            Write-Verbose "Success to save AppIcon to $LocalAppIconPath"
        } catch {
            Write-warning "Failed to save AppIcon to $LocalAppIconPath. Error: $_"
        }

        # Copy script to application folder (ensure $Global:ScriptPath and $Global:ScriptName are valid in this function's context)
        $TargetScriptPath = Join-Path -Path $AppFolder -ChildPath $ExecutingScriptName # Use derived script name
        if ($ExecutingScriptPath -ne $TargetScriptPath) { # Check if source and target are different
            try {
                Copy-Item $ExecutingScriptPath $TargetScriptPath -Force | Out-Null # Use derived script path
                Write-Verbose "Success to copy script to $TargetScriptPath"
            } catch {
                Write-warning "Failed to copy script to $TargetScriptPath. Error: $_"
            }
        }

        # Create batch files
        try {
            Set-Content -Path $LocalAppUninstallBAT -Value $LocalAppUninstallcmd1 -Encoding Ascii -Force
            Add-Content -Path $LocalAppUninstallBAT -Value $LocalAppUninstallcmd2 -Encoding Ascii
            Set-Content -Path $LocalAppModifyBAT -Value $LocalAppModifycmd1 -Encoding Ascii -Force
            Add-Content -Path $LocalAppModifyBAT -Value $LocalAppModifycmd2 -Encoding Ascii
            Write-Verbose "Batch files created successfully in $AppFolder"
        } catch {
            Write-warning "Failed to create batch files. Error: $_"
        }

        # --- Registry Operations ---
        Write-Verbose "Starting registry operations."
        try {
            # Ensure HKCR PSDrive is available for all subsequent HKCR operations
            if (!(Get-PSDrive HKCR -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)) {
                New-PSDrive -PSProvider Registry -Name HKCR -Root HKEY_CLASSES_ROOT | Out-Null
                $private:hkcrDriveCreatedByThisFunction = $true
                Write-Verbose "Created HKCR PSDrive."
            }

            # HKLM Uninstall Entries
            if (!(Test-Path $LocalAppUninstallRegKey)) {
                try {
                    New-Item -Path $LocalAppUninstallRegKey -Force | Out-Null
                    Write-Verbose "Created Registry Path $($LocalAppUninstallRegKey)."
                } catch {
                    Write-warning "Failed to create Registry Path $($LocalAppUninstallRegKey). Error: $_"
                }
            }              $RegistryProperties = @(
                @{ Name = "DisplayName";        Type = "String";    Value = $DisplayName },
                @{ Name = "DisplayVersion";     Type = "String";    Value = $Version.ToString() }, # Use .ToString() for version object
                @{ Name = "Version";            Type = "DWord";     Value = ($Version.Major -shl 16) + $Version.Minor }, # Packed version as DWord for WMI compatibility
                @{ Name = "VersionMajor";       Type = "DWord";     Value = $Version.Major }, # Typically DWord for MSI
                @{ Name = "VersionMinor";       Type = "DWord";     Value = $Version.Minor }, # Typically DWord for MSI
                @{ Name = "Publisher";          Type = "String";    Value = $Publisher },
                @{ Name = "DisplayIcon";        Type = "String";    Value = $LocalAppIconPath },
                @{ Name = "Comments";           Type = "String";    Value = $DisplayName },
                @{ Name = "InstallLocation";    Type = "String";    Value = $AppFolder }, # Changed to $AppFolder
                @{ Name = "NoRemove";           Type = "DWord";     Value = 1 }, # Default: Hide Remove button
                @{ Name = "NoModify";           Type = "DWord";     Value = 1 }, # Default: Hide Modify button
                # Special key for Windows Settings app to detect modify capability
                @{ Name = "ModifyRegistryKey";  Type = "String";    Value = $LocalAppUninstallRegKey }
            )

            if ($UnInstallEnabled) {
                $RegistryProperties += @{ Name = "UninstallString"; Type = "String"; Value = $LocalAppUninstallString }
                # If Uninstall is enabled, allow removal (NoRemove = 0)
                ($RegistryProperties | Where-Object { $_.Name -eq "NoRemove" }).Value = 0
            }            if ($ModifyEnabled) {
                # Add both standard and alternative Modify keys
                $RegistryProperties += @{ Name = "ModifyString"; Type = "String"; Value = $LocalAppModifyString }
                $RegistryProperties += @{ Name = "ModifyPath"; Type = "String"; Value = $LocalAppModifyString }
                # If Modify is enabled, allow modification (NoModify = 0)
                ($RegistryProperties | Where-Object { $_.Name -eq "NoModify" }).Value = 0
                
                # Add explicit registry flag that forces display of Modify button
                $RegistryProperties += @{ Name = "QuietUninstallString"; Type = "String"; Value = $LocalAppUninstallString }
            }

            foreach ($Property in $RegistryProperties) {
                try {
                    New-ItemProperty -Path $LocalAppUninstallRegKey -Name $Property.Name -PropertyType $Property.Type -Value $Property.Value -Force | Out-Null
                    Write-Verbose "Success to create/update Registry value '$($Property.Name)' under $($LocalAppUninstallRegKey)."
                } catch {
                    Write-warning "Failed to create/update Registry value '$($Property.Name)' under $($LocalAppUninstallRegKey). Error: $_"
                }
            }

            # HKCR Installer\Products Entries
            if (!(Test-Path $LocalAppProductsRegKey)) {
                try {
                    New-Item -Path $LocalAppProductsRegKey -Force | Out-Null
                    Write-Verbose "Success to create Registry Path $($LocalAppProductsRegKey)."
                } catch {
                    Write-warning "Failed to create Registry Path $($LocalAppProductsRegKey). Error: $_"
                }
            }            $AdditionalRegistryProperties = @(
                @{ Name = "ProductName";       Type = "String";        Value = $DisplayName },
                @{ Name = "ProductIcon";       Type = "String";        Value = $LocalAppIconPath },
                @{ Name = "ProductVersion";    Type = "String";        Value = $Version.ToString() }, # Additional version for WMI
                @{ Name = "Version";           Type = "DWord";         Value = ($Version.Major -shl 16) + $Version.Minor }, # Packed version as DWord
                @{ Name = "VersionMajor";      Type = "DWord";         Value = $Version.Major }, # Duplicate for HKCR registry
                @{ Name = "VersionMinor";      Type = "DWord";         Value = $Version.Minor }, # Duplicate for HKCR registry
                @{ Name = "AdvertiseFlags";    Type = "DWord";         Value = 388 }, # Common value, ensure it's appropriate
                @{ Name = "Assignment";        Type = "DWord";         Value = 1 },
                @{ Name = "AuthorizedLUAApp";  Type = "DWord";         Value = 0 },
                @{ Name = "Clients";           Type = "MultiString";   Value = @(":") }, # Common default
                @{ Name = "DeploymentFlags";   Type = "DWord";         Value = 3 },
                @{ Name = "InstanceType";      Type = "DWord";         Value = 0 },
                @{ Name = "Language";          Type = "DWord";         Value = 1033 } # US English
            )
            foreach ($Property in $AdditionalRegistryProperties) {
                try {
                    New-ItemProperty -Path $LocalAppProductsRegKey -Name $Property.Name -PropertyType $Property.Type -Value $Property.Value -Force | Out-Null
                    Write-Verbose "Success to create/update Registry value '$($Property.Name)' under $($LocalAppProductsRegKey)."
                } catch {
                    Write-warning "Failed to create/update Registry value '$($Property.Name)' under $($LocalAppProductsRegKey). Error: $_"
                }
            }

            # HKCR Installer\Products\...\Sourcelist Entries
            $SourceListPath = Join-Path -Path $LocalAppProductsRegKey -ChildPath "Sourcelist"
            if (!(Test-Path $SourceListPath)) {
                try { New-Item -Path $SourceListPath -Force | Out-Null; Write-Verbose "Success to create Registry Path $SourceListPath." }
                catch { Write-warning "Failed to create Registry Path $SourceListPath. Error: $_" }
            }
            $SourcelistProperties = @(
                @{ Name = "LastUsedSource";    Type = "ExpandString";  Value = "n;1;$($AppFolder)\" },
                @{ Name = "PackageName";       Type = "String";        Value = $ExecutingScriptName } # Use derived script name
            )
            foreach ($Property in $SourcelistProperties) {
                try {
                    New-ItemProperty -Path $SourceListPath -Name $Property.Name -PropertyType $Property.Type -Value $Property.Value -Force | Out-Null
                    Write-Verbose "Success to create/update Registry value '$($Property.Name)' under $SourceListPath."
                } catch {
                    Write-warning "Failed to create/update Registry value '$($Property.Name)' under $SourceListPath. Error: $_"
                }
            }
            
            # HKCR Installer\Products\...\Sourcelist\Media Entries
            $MediaListPath = Join-Path -Path $SourceListPath -ChildPath "Media"
            if (!(Test-Path $MediaListPath)) {
                try { New-Item -Path $MediaListPath -Force | Out-Null; Write-Verbose "Success to create Registry Path $MediaListPath." }
                catch { Write-warning "Failed to create Registry Path $MediaListPath. Error: $_" }
            }
            try {
                New-ItemProperty -Path $MediaListPath -Name "1" -PropertyType "String" -Value ";" -Force | Out-Null # Common placeholder
                Write-Verbose "Success to create/update Registry value '1' under $MediaListPath."
            } catch {
                Write-warning "Failed to create/update Registry value '1' under $MediaListPath. Error: $_"
            }

            # HKCR Installer\Products\...\Sourcelist\Net Entries
            $NetListPath = Join-Path -Path $SourceListPath -ChildPath "Net"
            if (!(Test-Path $NetListPath)) {
                try { New-Item -Path $NetListPath -Force | Out-Null; Write-Verbose "Success to create Registry Path $NetListPath." }
                catch { Write-warning "Failed to create Registry Path $NetListPath. Error: $_" }
            }
            try {
                New-ItemProperty -Path $NetListPath -Name "1" -PropertyType "ExpandString" -Value "$($AppFolder)\" -Force | Out-Null
                Write-Verbose "Success to create/update Registry value '1' under $NetListPath."
            } catch {
                Write-warning "Failed to create/update Registry value '1' under $NetListPath. Error: $_"
            }

        } catch {
            # General catch for the entire registry operations block
            Write-warning "An error occurred during registry operations section: $_"
        }
    }
    End {
        # Cleanup HKCR PSDrive if it was created by this function
        if ($private:hkcrDriveCreatedByThisFunction -and (Get-PSDrive HKCR -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)) {
            try {
                Remove-PSDrive -Name HKCR
                Write-Verbose "Successfully removed HKCR PSDrive."
            } catch {
                Write-warning "Failed to remove HKCR PSDrive. Error: $_"
            }
        }
        Write-Verbose "Finished function Add-AddRemovePrograms."
    }
}
Function remove-AddRemovePrograms {
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [Parameter(Mandatory, HelpMessage = "Display name of the application (used to determine original icon name).")]
        [string]$DisplayName,

        [Parameter(Mandatory, HelpMessage = "GUID of the application used during installation.")]
        [string]$Guid,

        [Parameter(Mandatory, HelpMessage = "Application folder path where components were installed.")]
        [string]$AppFolder
    )
    Begin {
        $ErrorActionPreference = 'Stop' # Set for the scope of this function
        Write-Verbose "Starting function remove-AddRemovePrograms"
        $private:hkcrDriveCreatedByThisFunction = $false # Flag to track PSDrive creation
    }
    Process {
        Write-Verbose "Preparing to remove application components for GUID: $Guid"

        # Determine script's own name (assuming this remove function is in the same script that was installed)
        $ExecutingScriptPath = $PSCommandPath
        $ExecutingScriptName = (Split-Path $ExecutingScriptPath -Leaf) # Name with .ps1
        if (-not $ExecutingScriptPath) {
            Write-Error "Could not determine the script path using `$PSCommandPath."
            return
        }
        Write-Verbose "Executing script:$($ExecutingScriptPath) $($ExecutingScriptName)"


        # --- Variable Preparations ---
        # Convert GUID to ProductID (it needs to be in reversed order, same logic as Add-AddRemovePrograms)
        [string]$LocalProductIDForRemoval = $Guid -replace '[{}]', ""
        [array]$LocalProductIDArray = $LocalProductIDForRemoval.Split("-")

        if ($LocalProductIDArray.Count -ne 5) {
            Write-Error "Invalid GUID format: $Guid. Cannot derive ProductID for removal."
            return
        }

        [string]$id0_local = $LocalProductIDArray[0]
        [string]$id1_local = $LocalProductIDArray[1]
        [string]$id2_local = $LocalProductIDArray[2]
        [string]$id3_local = $LocalProductIDArray[3] # This part was unusual but kept for consistency
        [char[]]$id4_local_chars = $LocalProductIDArray[4].ToCharArray()

        if ($id4_local_chars.Length -ne 12) {
            Write-Error "Invalid GUID format for ProductID conversion (part 4 length mismatch): $($LocalProductIDArray[4])"
            return
        }
        [string]$id4_local = -join ($id4_local_chars[1], $id4_local_chars[0], $id4_local_chars[3], $id4_local_chars[2], $id4_local_chars[5], $id4_local_chars[4], $id4_local_chars[7], $id4_local_chars[6], $id4_local_chars[9], $id4_local_chars[8], $id4_local_chars[11], $id4_local_chars[10])
        $LocalProductIDForRemoval = $id0_local + $id1_local + $id2_local + $id3_local + $id4_local

        # Define variables based on input parameters (mirroring Add-AddRemovePrograms)
        [string]$LocalAppIconName        = $DisplayName -replace '\s', ''
        [string]$LocalAppIconPath        = Join-Path -Path $AppFolder -ChildPath "$LocalAppIconName.ico"
        [string]$LocalAppUninstallRegKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$Guid"
        [string]$LocalAppProductsRegKey  = "HKCR:\Installer\Products\$LocalProductIDForRemoval"
        [string]$LocalAppUninstallBAT    = Join-Path -Path $AppFolder -ChildPath "uninstall-$Guid.bat"
        [string]$LocalAppModifyBAT       = Join-Path -Path $AppFolder -ChildPath "reinstall-$Guid.bat"
        
        # Assuming $Global:ScriptName is available and set as used by Add-AddRemovePrograms
        # If Add-AddRemovePrograms used "$($Global:ScriptName).ps1", we use the same here.
        [string]$CopiedScriptFileName = $ExecutingScriptName # Use the derived script name
        [string]$TargetScriptPath = Join-Path -Path $AppFolder -ChildPath $CopiedScriptFileName


        Write-Verbose "Derived ProductID for removal: $LocalProductIDForRemoval"
        Write-Verbose "Target HKLM Uninstall Registry Key: $LocalAppUninstallRegKey"
        Write-Verbose "Target HKCR Products Registry Key: $LocalAppProductsRegKey"

        # --- Registry Deletion ---
        Write-Verbose "Starting registry key removal."
        try {
            # Ensure HKCR PSDrive is available
            if (!(Get-PSDrive HKCR -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)) {
                New-PSDrive -PSProvider Registry -Name HKCR -Root HKEY_CLASSES_ROOT | Out-Null
                $private:hkcrDriveCreatedByThisFunction = $true
                Write-Verbose "Created HKCR PSDrive for removal operations."
            }

            # Remove HKLM Uninstall Key
            if (Test-Path $LocalAppUninstallRegKey) {
                if ($PSCmdlet.ShouldProcess($LocalAppUninstallRegKey, "Remove Registry Key")) {
                    try {
                        Remove-Item -Path $LocalAppUninstallRegKey -Recurse -Force
                        Write-Verbose "Successfully removed registry key: $LocalAppUninstallRegKey"
                    } catch {
                        Write-warning "Failed to remove registry key $LocalAppUninstallRegKey. Error: $_"
                    }
                }
            } else {
                Write-Verbose "Registry key not found (already removed or never existed): $LocalAppUninstallRegKey"
            }

            # Remove HKCR Installer Products Key
            if (Test-Path $LocalAppProductsRegKey) {
                if ($PSCmdlet.ShouldProcess($LocalAppProductsRegKey, "Remove Registry Key")) {
                    try {
                        Remove-Item -Path $LocalAppProductsRegKey -Recurse -Force
                        Write-Verbose "Successfully removed registry key: $LocalAppProductsRegKey"
                    } catch {
                        Write-warning "Failed to remove registry key $LocalAppProductsRegKey. Error: $_"
                    }
                }
            } else {
                Write-Verbose "Registry key not found (already removed or never existed): $LocalAppProductsRegKey"
            }
        } catch {
            Write-warning "An error occurred during registry key removal section: $_"
        }

        # --- File Deletion ---
        Write-Verbose "Starting file removal in $AppFolder."
        $FilesToDelete = @(
            $LocalAppIconPath,
            $LocalAppUninstallBAT,
            $LocalAppModifyBAT,
            $TargetScriptPath
        )

        foreach ($FileItem in $FilesToDelete) {
            if (Test-Path $FileItem) {
                if ($PSCmdlet.ShouldProcess($FileItem, "Remove File")) {
                    try {
                        Remove-Item -Path $FileItem -Force
                        Write-Verbose "Successfully removed file: $FileItem"
                    } catch {
                        Write-warning "Failed to remove file $FileItem. Error: $_"
                    }
                }
            } else {
                Write-Verbose "File not found (already removed or never existed): $FileItem"
            }
        }

        # --- Application Folder Deletion (if empty) ---
        Write-Verbose "Checking application folder $AppFolder for potential removal."
        if (Test-Path $AppFolder) {
            # Check if the folder is empty (excluding potential hidden/system files if any, though ideally it's truly empty)
            if (@(Get-ChildItem -Path $AppFolder -Force -ErrorAction SilentlyContinue).Count -eq 0) {
                if ($PSCmdlet.ShouldProcess($AppFolder, "Remove Directory (if empty)")) {
                    try {
                        Remove-Item -Path $AppFolder -Force #-Recurse (use with caution, ensure it's the correct folder)
                        Write-Verbose "Successfully removed empty application folder: $AppFolder"
                    } catch {
                        Write-warning "Failed to remove application folder $AppFolder. It might not be truly empty or access is denied. Error: $_"
                    }
                }
            } else {
                Write-Verbose "Application folder $AppFolder is not empty. Skipping removal of the folder itself."
            }
        } else {
            Write-Verbose "Application folder not found (already removed or never existed): $AppFolder"
        }
    }
    End {
        # Cleanup HKCR PSDrive if it was created by this function
        if ($private:hkcrDriveCreatedByThisFunction -and (Get-PSDrive HKCR -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)) {
            try {
                Remove-PSDrive -Name HKCR
                Write-Verbose "Successfully removed HKCR PSDrive."
            } catch {
                Write-warning "Failed to remove HKCR PSDrive. Error: $_"
            }
        }
        Write-Verbose "Finished function remove-AddRemovePrograms."
    }
}

Function Invoke-ScriptBlockWithMonitoring {
    # This function executes a provided scriptblock. It supports enforcing verbose logging and provides a detailed execution context.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "The scriptblock to execute")]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $false, HelpMessage = "Force verbose logging during execution")]
        [switch]$ForceVerbose,

        [Parameter(Mandatory = $false, HelpMessage = "Return the output from the scriptblock")]
        [switch]$PassThru
    )

    Begin {
        Write-Verbose "Starting execution of scriptblock with monitoring"
        # Store original verbose preference
        $originalVerbosePreference = $VerbosePreference
        # Force verbose if requested
        if ($ForceVerbose) {
            $VerbosePreference = 'Continue'
            Write-Verbose "Verbose logging enforced for scriptblock execution"
        }
    }
    Process {
        try {
            # Execute the scriptblock and capture output if PassThru is specified
            if ($PassThru) {
                $result = & $ScriptBlock
                Write-Verbose "Scriptblock executed successfully with output capture"
                return $result
            } else {
                & $ScriptBlock
                Write-Verbose "Scriptblock executed successfully"
            }
        }
        catch {
            Write-Error "Error executing scriptblock: $($_.Exception.Message)"
        }
    }

    End {
        # Restore original verbose preference
        if ($ForceVerbose) {
            $VerbosePreference = $originalVerbosePreference
            Write-Verbose "Verbose preference restored to original setting"
        }
        Write-Verbose "Invoke-ScriptBlock execution completed"
    }
}

#endregion

#region ---------------------------------------------------[[Script Execution]------------------------------------------------------
Invoke-TboneLogging -GUILogEnabled $GUILogEnabled -EventLogEnabled $EventLogEnabled -FileLogEnabled $FileLogEnabled

if ($PSBoundParameters.ContainsKey('InstallerScriptPath') -and -not([string]::IsNullOrWhiteSpace($InstallerScriptPath))) {
    if (Test-Path $InstallerScriptPath -PathType Leaf) {
        try {
            $InstallerScriptContent = Get-Content -Path $InstallerScriptPath -Raw -ErrorAction Stop
            $WrappedInstallerScript = [scriptblock]::Create($InstallerScriptContent)
            Write-Verbose "Successfully loaded installer script from: $InstallerScriptPath"
        } catch {Write-Warning "Failed to load installer script from '$InstallerScriptPath': $($_.Exception.Message). Using default embedded installer script."}
    } else {Write-Warning "Installer script file not found at '$InstallerScriptPath'. Using default embedded installer script."}
} else {Write-Verbose "No InstallerScriptPath provided. Using default embedded installer script."}

# Attempt to load from UninstallerScriptPath if provided
if ($PSBoundParameters.ContainsKey('UninstallerScriptPath') -and -not([string]::IsNullOrWhiteSpace($UninstallerScriptPath))) {
    if (Test-Path $UninstallerScriptPath -PathType Leaf) {
        try {
            $UninstallerScriptContent = Get-Content -Path $UninstallerScriptPath -Raw -ErrorAction Stop
            $WrappedUnInstallerScript = [scriptblock]::Create($UninstallerScriptContent)
            Write-Verbose "Successfully loaded uninstaller script from: $UninstallerScriptPath"
        } catch {Write-Warning "Failed to load uninstaller script from '$UninstallerScriptPath': $($_.Exception.Message). Using default embedded uninstaller script."}
    } else {Write-Warning "Uninstaller script file not found at '$UninstallerScriptPath'. Using default embedded uninstaller script."}
} else {Write-Verbose "No UninstallerScriptPath provided. Using default embedded uninstaller script."}

#Import the Icon if provided as parameter
$icoFile = @(Get-ChildItem -Path . -Filter *.ico -ErrorAction SilentlyContinue)
if ($icoFile.Count -gt 0) {
    $iconFilePath = $icoFile[0].FullName
    $iconBytes = [System.IO.File]::ReadAllBytes($iconFilePath)
    $AppIcon = [System.Convert]::ToBase64String($iconBytes)
} else {
    $AppIcon = $iconBase64
}

# Check if app already exist and what versions
[version]$CurrentVersion = "0.0.0.0"
if(Test-Path $AppKey){
    Try{$CurrentVersion = (Get-ItemProperty -Path $AppKey -Name DisplayVersion -ErrorAction SilentlyContinue).DisplayVersion
       Write-Verbose "Success to get the App from registry, Currentversion is $($CurrentVersion)"
    } catch{
        Write-Verbose "Failed to parse App from registry, setting $($CurrentVersion) as version. Error: $($_.Exception.Message)"
    }
}
else {Write-Verbose "Registry key $AppKey not found, setting $($CurrentVersion) as version"}

#Script Runs in Install mode (Default)
if($InstallType -eq "Install" -and $CurrentVersion -lt $AppVersion){
    Write-Verbose "Install mode detected, Current version is $CurrentVersion and App version is $AppVersion"
    Invoke-ScriptBlockWithMonitoring -ScriptBlock $WrappedInstallerScript -ForceVerbose
    # Add the application to Add/Remove Programs
    Add-AddRemovePrograms -DisplayName $AppName -Version $AppVersion -Guid $AppGUID -Publisher $AppPublisher -Icon $AppIcon -AppFolder $AppFolder -UnInstallEnabled $AddRemoveProgramUninstall -ModifyEnabled $AddRemoveProgramModify
}

#Script run in ReInstall mode
elseif($InstallType -eq "ReInstall"){
    Write-Verbose "ReInstall mode detected, Current version is $CurrentVersion and App version is $AppVersion"
    Invoke-ScriptBlockWithMonitoring -ScriptBlock $WrappedInstallerScript -ForceVerbose
    # Add the application to Add/Remove Programs
    Add-AddRemovePrograms -DisplayName $AppName -Version $AppVersion -Guid $AppGUID -Publisher $AppPublisher -Icon $AppIcon -AppFolder $AppFolder -UnInstallEnabled $AddRemoveProgramUninstall -ModifyEnabled $AddRemoveProgramModify
}

#Script run in UnInstall mode
elseif($InstallType -eq "UnInstall"){
    Write-Verbose "UnInstall mode detected, Current version is $CurrentVersion and App version is $AppVersion"
    Invoke-ScriptBlockWithMonitoring -ScriptBlock $WrappedUnInstallerScript -ForceVerbose
    # Remove the application from Add/Remove Programs
    remove-AddRemovePrograms -DisplayName $AppName -Guid $AppGUID -AppFolder $AppFolder
}

#Script will not run in any of the above modes
else{
    if ($InstallType -eq "Install" -and ($CurrentVersion -ge $AppVersion)) {
        Write-verbose "Skipped main script execution. Reason: Current version ($CurrentVersion) is the same as or newer than the application version ($AppVersion)."
    } elseif ($InstallType -ne "Install" -and $InstallType -ne "ReInstall" -and $InstallType -ne "UnInstall") {
        Write-verbose "Skipped main script execution. Reason: InstallType '$InstallType' is not a recognized execution path or no action is defined for it in the current state."
    } else {
        Write-verbose "Skipped main script execution. Reason: No action defined for InstallType '$InstallType' with CurrentVersion '$CurrentVersion' and AppVersion '$AppVersion'."
    }
}

Invoke-TboneLogging 
#endregion