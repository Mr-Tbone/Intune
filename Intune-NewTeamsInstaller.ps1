<#PSScriptInfo
.SYNOPSIS
    Script for Intune 
 
.DESCRIPTION
    This script will remove the old Classic Teams and install the New Teams.
        
.EXAMPLE
   .\Intune-NewTeamsInstaller.ps1
    Will uninstall the old Classic Teams and install the New Teams.

.NOTES
    Written by Mr-Tbone (Tbone Granheden) Coligo AB
    torbjorn.granheden@coligo.se

.VERSION
    1.0

.RELEASENOTES
    1.0 2024-02-19 Initial Build

.AUTHOR
    Tbone Granheden 
    @MrTbone_se

.COMPANYNAME 
    Coligo AB

.GUID 
    00000000-0000-0000-0000-000000000011

.COPYRIGHT
    Feel free to use this, But would be grateful if My name is mentioned in Notes 

.CHANGELOG
    1.0.2402.1 - Initial Version
#>

#region ---------------------------------------------------[Set script requirements]-----------------------------------------------
#
#Requires -Version 4.0
#Requires -RunAsAdministrator
#endregion

#region ---------------------------------------------------[Script Parameters]-----------------------------------------------
#endregion

#region ---------------------------------------------------[Modifiable Parameters and defaults]------------------------------------
[string]$NewTeamsInstaller      = ".\teamsbootstrapper.exe" #Path to the new Teams installer
[string]$NewTeamsInstallerArgs  = "-p"                      #Arguments for the new Teams installer
[bool]$RemovePersonalTeams      = $true                     #Remove Personal Teams to avoid confution between Corporate and Personal Teams

[string]$TaskName               = "Intune-NewTeamsInstaller"#TaskName for the eventlog
[string]$CorpDataPath           = "C:\ProgramData\MrTbone"  #Path for the logfiles
#endregion

#region ---------------------------------------------------[Set global script settings]--------------------------------------------
Set-StrictMode -Version Latest
#endregion

#region ---------------------------------------------------[Static Variables]------------------------------------------------------
#Log File Info
[string]$logpath 			= "$($CorpDataPath)\logs"
[string]$LogFile            = "$($logpath)\$($TaskName)$(Get-Date -Format 'yyyyMMdd')$(Get-Date -format 'HHmmss').log"
#endregion

#region ---------------------------------------------------[Import Modules and Extensions]-----------------------------------------
#endregion

#region ---------------------------------------------------[Functions]------------------------------------------------------------

function Write-ToEventlog {
    Param(
        [string]$Logtext,
        [string]$EventSource,
        [int]$Global:EventId,
        [validateset("Information", "Warning", "Error")]$Global:EventType = "Information"
    )
    Begin {}
    Process {
    if ([bool]($(whoami -user) -match "S-1-5-18")){
        if (!([System.Diagnostics.EventLog]::SourceExists($EventSource))) {
            New-EventLog -LogName 'Application' -Source $EventSource -ErrorAction ignore | Out-Null
            }
        }
    Write-EventLog -LogName 'Application' -Source $EventSource -EntryType $Global:EventType -EventId $Global:EventId -Message $Logtext -ErrorAction ignore | Out-Null
    }
    End {}
}
function Uninstall-ProgramFromRegKey {
    Param(
        $AppName
    )
    Begin {}
    Process {
        ForEach ($Architecture in "SOFTWARE", "SOFTWARE\Wow6432Node" ) {
            $UninstallKey = "HKLM:$Architecture\Microsoft\Windows\CurrentVersion\Uninstall" 
            if (Test-path $UninstallKey) {
                $UninstallInfo = Get-ChildItem -Path $UninstallKey | Get-ItemProperty | Where-Object { $_.PSObject.Properties.Name -contains 'DisplayName' -and $_.DisplayName -match $AppName } | Select-Object PSChildName -ExpandProperty PSChildName
                If ( $UninstallInfo ) {
                    $UninstallInfo | ForEach-Object {
                        $AppName = (Get-ItemProperty "$UninstallKey\$_" ).DisplayName
                        $params = @{
                            "FilePath" = "$Env:SystemRoot\system32\msiexec.exe"
                            "ArgumentList" = @(
                              "/x$($_)"
                              "/qn"
                            )
                            "Verb" = "runas"
                            "PassThru" = $true
                          }
                          write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Trying to Uninstall: $($AppName) with $($params.ArgumentList)"
                          $process = start-process @params -Wait -ErrorAction Stop
                      
#                        $process = Start-Process -FilePath $uninstallfile -ArgumentList $uninstallargs -PassThru -Wait -ErrorAction Stop
                        if ($process.ExitCode -eq 0){write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to Uninstall $($AppName)"} 
                        elseif ($process.ExitCode -eq 1605) {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),warning,Failed to Uninstall $($AppName), does not exist"}
                        else{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),error,Failed to Uninstall $($AppName) with exit code $($process.ExitCode)"}
                    }
                }
            }
            else{
                write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,No Uninstall keys found for $($AppName)"
            }   
        }
    }
    End {}
}
function Uninstall-ProgramFromFolder {
    Param(
        [string]$Path,
        [string]$uninstaller,
        [string]$UninstallArgs
    )
    Begin {}
    Process {
        $uninstallerpath = Join-path $Path $uninstaller
        if (test-path $uninstallerpath) {
            write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Trying to Uninstall $($uninstallerpath)"
            $process = Start-Process -FilePath "$($uninstallerpath)" -ArgumentList "$($UninstallArgs)" -PassThru -Wait -ErrorAction STOP
            if ($process.ExitCode -eq 0){write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to Uninstall $($uninstallerpath)"} 
            elseif ($process.ExitCode -eq 1605) {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),warning,Failed to Uninstall $($uninstallerpath), does not exist"}
            else{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),error,Failed to Uninstall $($uninstallerpath) with exit code $($process.ExitCode)"}

            try {Remove-Item -Path $Path -Force -Recurse -ErrorAction SilentlyContinue
            Write-Verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to remove $($Path)"}
            catch {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),error,Failed to remove $($Path)"}
        }
        else {
            write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,No program found with $($uninstallerpath)"
        } 
    }
    End {}
}

function Remove-DesktopShortcuts {
    Param(
        [string]$ShortcutName
    )
    Begin {}
    Process {
        $desktopPath = [System.Environment]::GetFolderPath("Desktop")
        $desktopShortcuts = Get-ChildItem -Path $desktopPath -Filter "*.lnk" -Recurse
        foreach ($shortcut in $desktopShortcuts) {
            $shell = New-Object -ComObject WScript.Shell
            $targetPath = $shell.CreateShortcut($shortcut.FullName).TargetPath
            if ($targetPath -like "*$ShortcutName*") {
                write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Trying to Delete shortcut: $($shortcut.FullName)"
                try{Remove-Item -Path $shortcut.FullName -Force
                Write-Verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to remove $($shortcut.FullName)"}
                catch{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),error,Failed to remove $($shortcut.FullName)"}
            }
        }
    }
    End {}
}
function Remove-StartMenuShortcuts {
    Param(
        [string]$ShortcutName
    )
    Begin {}
    Process {
        $startMenuPath = [System.Environment]::GetFolderPath("StartMenu")
        $startMenuShortcuts = Get-ChildItem -Path $startMenuPath -Filter "*.lnk" -Recurse
        foreach ($shortcut in $startMenuShortcuts) {
            $shell = New-Object -ComObject WScript.Shell
            $targetPath = $shell.CreateShortcut($shortcut.FullName).TargetPath
            if ($targetPath -like "*$ShortcutName*") {
                write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Trying to Delete shortcut: $($shortcut.FullName)"
                try{Remove-Item -Path $shortcut.FullName -Force
                Write-Verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to remove $($shortcut.FullName)"}
                catch{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),error,Failed to remove $($shortcut.FullName)"}
            }
        }
    }
    End {}
}
function Remove-RegistryKeys {
    param (
        [string]$registryPath,
        [string[]]$keyNames
    )
    Begin {}
    Process {
        # Loop through each key
        foreach ($keyName in $keyNames) {
            # Check if the key exists
            if (Test-Path -Path "$registryPath\$keyName") {
                write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Trying to remove $($registryPath)\$($keyName)"
                try {Remove-ItemProperty -Path $registryPath -Name $keyName -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                Write-Verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to remove $($registryPath)\$($keyName)"}
                catch{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),error,Failed to remove $($registryPath)\$($keyName)"}
            }
        }
    }
    End {}    
}
#endregion

#region ---------------------------------------------------[[Script Execution]------------------------------------------------------
Start-Transcript -Path $LogFile

# Stop all Classic Teams processes
try{get-process "teams*" | stop-process -Force -ErrorAction SilentlyContinue
    Write-Verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to stop all Teams processes"}
catch{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),error,Failed to stop all Teams processes"}

#Remove Personal Teams to avoid confusion
if ($RemovePersonalTeams) {
    # Uninstall Teams from the user profile
    try{Get-AppxPackage "MicrosoftTeams*" -AllUsers | Remove-AppPackage -AllUsers -ErrorAction SilentlyContinue
        Write-Verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to uninstall Personal Teams appx packages for all users"}
    catch{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),error,Failed to uninstall Personal Teams appx packages for all users"}
}

# Uninstall All Classic Teams appx packages
try{Get-AppxPackage "Teams*" -AllUsers | Remove-AppPackage -AllUsers -ErrorAction SilentlyContinue
    Write-Verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to uninstall all Classic Teams appx packages"}
catch{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),error,Failed to uninstall all Classic Teams appx packages"}

# Uninstall Classic Teams Machine-Wide Installer app with an uninstall regkey
Uninstall-ProgramFromRegKey -AppName "Teams Machine-Wide Installer"

# Uninstall All Classic Teams apps with installation folder in program files
Uninstall-ProgramFromFolder -Path (Join-Path ${env:ProgramFiles(x86)} "Teams Installer") -uninstaller "teams.exe" -UninstallArgs "--uninstall"
Uninstall-ProgramFromFolder -Path (Join-Path ${env:ProgramFiles} "Teams Installer")  -uninstaller "teams.exe" -UninstallArgs "--uninstall"
Uninstall-ProgramFromFolder -Path (Join-Path ${env:ProgramFiles(x86)} "Microsoft\Teams\current")  -uninstaller "update.exe" -UninstallArgs "--uninstall -s"
Uninstall-ProgramFromFolder -Path (Join-Path ${env:ProgramFiles} "Microsoft\Teams\current")  -uninstaller "update.exe" -UninstallArgs "--uninstall -s"

# Uninstall All Classic Teams apps with installation folder in personal profile
$userProfile = $env:USERPROFILE
$usersDirectory = Split-Path $userProfile
$userDirectories = Get-ChildItem -Path $usersDirectory -Directory
# Loop through each userprofile directory and uninstall
foreach ($userdirectory in $userDirectories) {
    $username = Split-Path $userdirectory -Leaf
    Uninstall-ProgramFromFolder -Path (Join-Path $userdirectory "appdata\local\Microsoft\Teams") -uninstaller "update.exe" -UninstallArgs "--uninstall -s"
    Uninstall-ProgramFromFolder -Path (Join-Path $($env:ProgramData) "$($username)\Microsoft\Teams") -uninstaller "update.exe" -UninstallArgs "--uninstall -s"
}

#cleanup Classic Teams shortcuts from device 
Remove-DesktopShortcuts -ShortcutName "*Teams*"
Remove-StartMenuShortcuts -ShortcutName "*Teams*"

# Remove Classic Teams from startup registry key
Remove-RegistryKeys -registryPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'             -keyNames 'Teams', 'TeamsMachineUninstallerLocalAppData', 'TeamsMachineUninstallerProgramData', 'com.squirrel.Teams.Teams', 'TeamsMachineInstaller'
Remove-RegistryKeys -registryPath 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' -keyNames 'Teams', 'TeamsMachineUninstallerLocalAppData', 'TeamsMachineUninstallerProgramData', 'com.squirrel.Teams.Teams', 'TeamsMachineInstaller'
Remove-RegistryKeys -registryPath 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'             -keyNames 'Teams', 'TeamsMachineUninstallerLocalAppData', 'TeamsMachineUninstallerProgramData', 'com.squirrel.Teams.Teams', 'TeamsMachineInstaller'
Remove-RegistryKeys -registryPath 'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' -keyNames 'Teams', 'TeamsMachineUninstallerLocalAppData', 'TeamsMachineUninstallerProgramData', 'com.squirrel.Teams.Teams', 'TeamsMachineInstaller'

# Remove Classic Teams folders and icons
$ClassicTeamsShared = "$($env:ProgramData)\*\Microsoft\Teams"
try{Get-Item $ClassicTeamsShared | Remove-Item -Force -Recurse
    Write-Verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to remove $($ClassicTeamsShared)"}
catch{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),error,Failed to remove $($ClassicTeamsShared)"}

$ClassicTeamsPersonallocal = "$($usersDirectory)\*\AppData\Local\Microsoft\Teams"
try{Get-Item $ClassicTeamsPersonallocal | Remove-Item -Force -Recurse
    Write-Verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to remove $($ClassicTeamsPersonallocal)"}
catch{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),error,Failed to remove $($ClassicTeamsPersonallocal)"}

$ClassicTeamsPersonalroaming = "$($usersDirectory)\*\AppData\Roaming\Microsoft\Teams"
try{Get-Item $ClassicTeamsPersonalroaming | Remove-Item -Force -Recurse
    Write-Verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to remove $($ClassicTeamsPersonalroaming)"}
catch{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),error,Failed to remove $($ClassicTeamsPersonalroaming)"}

# Install New Teams
$process = Start-Process -FilePath $NewTeamsInstaller -ArgumentList $NewTeamsInstallerArgs -Wait -PassThru -ErrorAction STOP
if ($process.ExitCode -eq 0){write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to Install $($NewTeamsInstaller)"
    $Global:EventId=10
    $Global:EventType="Information"
    } 
else{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),error,Failed to Install $($NewTeamsInstaller) with exit code $($process.ExitCode)"
    $Global:EventId=11
    $Global:EventType="Error"
    }

#stop transcript and write to eventlog
Stop-Transcript |out-null
$Transcript = ((Get-Content $LogFile -Raw) -split ([regex]::Escape("**********************")))[-3]
$EventText =  "New Teams installer result: `n$($Transcript)"
Write-ToEventlog $EventText $TaskName $Global:EventId $Global:EventType
if ($Global:EventId=10) {exit 0}
else {exit 1}
#endregion