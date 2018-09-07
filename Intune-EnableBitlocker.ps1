<#
.SYNOPSIS
    Intune ScheduleJob Wrapper with scriptblock to enable bitlocker and backup bitlockker key
 
.DESCRIPTION
    Coligo Intune Scripts for Office 365
    This script needs to be distributed with Intune powershell feature
    It must be run under system, ie "Run this script using the logged on credentials" set to "No".
    This script is a wrapper to schedule a powershell job with a scriptblock at specified time and interwall
    Scriptblock contains script to enable bitlocker and backup bitlockker key
           
.EXAMPLE
   .\Intune-EnableBitlocker.ps1           
    Schedule a job to execute scriptblock
    Scriptblock contains script to enable bitlocker and backup bitlockker key
 
.NOTES
    Written by Torbjörn Granheden Coligo AB
    torbjorn.granheden@coligo.se
#>

#region ---------------------------------------------------[Set script requirements]-----------------------------------------------
#
#Requires -Version 3.0
#Requires -RunAsAdministrator
#endregion

#region ---------------------------------------------------[Modifyable Parameters and defaults]------------------------------------
$jobName = "BitlockerTrigger"          # Name of the job
#ScheduleJob Schedules
$TriggerOnce = @{                                        
    Once                = $true                         #Trigger the scheduledjob to run once and repeat
    At                  = (get-date 14:00:00)           #Trigger the scheduledjob to run once at this hour
    RepetitionInterval  = (New-TimeSpan -Hours 24)      #Trigger the scheduledjob repeat comment out if no repeat
    RepetitionDuration  = (New-TimeSpan -Days 30)}      #Trigger the scheduledjob to run repeat for this long time
$triggerDaily = @{
    Daily               = $false                        #Trigger the scheduledjob to run daily
    At                  = (get-date 10:00:00)           #Trigger the scheduledjob to run once at this hour
    DaysInterval        = 1}                            #Trigger the scheduledjob to run dayly at this interval             
$triggerWeekly = @{
    Weekly              = $false                        #Trigger the scheduledjob to run weekly
    At                  = (get-date 10:00:00)           #Trigger the scheduledjob to run once at this hour
    WeeksInterval       = 1                             #Trigger the scheduledjob to run weekly at this interval 
    DaysOfWeek          = "Monday","Wednesday"}         #Trigger the scheduledjob to run weekly on these days
$triggerAtStartup = @{atstartup = $false}               #Trigger the scheduledjob to run at startup
$triggerAtLogon = @{atlogon = $false}                   #Trigger the scheduledjob to run at logon
#ScheduleJob Options
$OptionsParams = @{
    HideInTaskScheduler = $False
    RunElevated = $true
    RequireNetwork = $true
    WakeToRun = $false
    IdleTimeout = (New-TimeSpan -Minutes 10)
    IdleDuration = (New-TimeSpan -Minutes 10)
    StartIfOnBattery = $true
    ContinueIfGoingOnBattery = $true
    StartIfIdle = $true
    StopIfGoingOffIdle = $false
    RestartOnIdleResume = $false
    DoNotAllowDemandStart = $false
}   
#Log settings
$Global:LogEnabled = $True
$Global:GUILogEnabled = $False
$Logpath = $OsDrive + "\Windows\Temp"
#endregion

#region ---------------------------------------------------[Set global script settings]--------------------------------------------
Set-StrictMode -Version Latest
#endregion

#region ---------------------------------------------------[Static Variables]------------------------------------------------------
$trigger = @()
if (($triggerOnce).Once) {$trigger += New-JobTrigger @triggerOnce}
if (($triggerDaily).Daily) {$trigger += New-JobTrigger @triggerDaily}
if (($triggerWeekly).weekly) {$trigger += New-JobTrigger @triggerWeekly}
if (($triggerAtStartup).atstartup) {$trigger += New-JobTrigger @triggerAtStartup}
if (($triggerAtLogon).atlogon) {$trigger += New-JobTrigger @triggerAtLogon}
$Options = New-ScheduledJobOption @OptionsParams
$Scriptname = $MyInvocation.MyCommand.Name
$PSscriptRoot = Split-Path (Resolve-Path $myInvocation.MyCommand.Path)
#Log File Info
$startTime = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$Logfile = $Logpath + "\" + $scriptName + " " + $startTime + ".log"
$success = $true
#endregion

#region ---------------------------------------------------[Import Modules and Extensions]-----------------------------------------
#endregion

#region ---------------------------------------------------[Functions]------------------------------------------------------------
Function LogWrite {
    Param(
        $logfile = "$logfile",
        [validateset("Info", "Warning", "Error")]$type = "Info",
        [string]$Logstring
    )
    Begin { }
    Process {
        If ($Global:LogEnabled) {
            Try {
                Add-content $Logfile -value "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') - $type - $logstring"
                if ($Global:GUILogEnabled) {
                    if ($type -eq "Info") {$foreGroundColor = "Green"}
                    elseif ($type -eq "Warning") {$foreGroundColor = "Cyan"}
                    elseif ($type -eq "Error") {$foreGroundColor = "Red"}
                    Write-Host $(Get-Date -Format 'dd-MM-yy yy HH:mm:ss') - $logstring -ForegroundColor $foreGroundColor
                }
            }    
            Catch {
                Write-Host $(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') - $_ -ForegroundColor Cyan
                Break
            }
        }
    }
    End { }
}
#endregion

#region ---------------------------------------------------[Script Block]------------------------------------------------------
#All code in this region is added to a scriptblock for execution in a scheduled powershell job

$scriptblock = {
    <#
.SYNOPSIS
    Enable Bitlocker with powershell and backup key  
 
.DESCRIPTION
    Coligo Intune Scripts for Office 365
    This script needs to be distributed with Intune powershell feature via scheduledjob wrapper
    It must be run as administrator
    The script enable bitlocker and backup bitlocker key, if successful it deletes the scheduled job
        
.EXAMPLE
   .\Intune-EnableBitlocker.ps1
    Enable Bitlocker with powershell and backup key   
 
.NOTES
    Written by Torbjörn Granheden Coligo AB
    torbjorn.granheden@coligo.se
#>

    #region ---------------------------------------------------[Set script requirements]-----------------------------------------------
    #
    #Requires -Version 3.0
    #Requires -RunAsAdministrator
    #Requires -Module Bitlocker
    #endregion

    #region ---------------------------------------------------[Modifyable Parameters and defaults]------------------------------------
    $EncryptionMethod = "Aes256"    # Supported values: Aes128, Aes256, XtsAes128, XtsAes256
    $SkipHardwareTest = $true       # Will prompt users if set to $false
    $BackupkeyToDisk = $True
    $BackupkeyToAD = $True
    $BackupkeyToAAD = $True
    $Global:LogEnabled = $True
    $Global:GUILogEnabled = $False
    $Logpath = $OsDrive + "\Windows\Temp"
    #endregion

    #region ---------------------------------------------------[Set global script settings]--------------------------------------------
    Set-StrictMode -Version Latest
    #endregion

    #region ---------------------------------------------------[Static Variables]------------------------------------------------------
    $Scriptname = $MyInvocation.MyCommand.Name
    $PSscriptRoot = Split-Path (Resolve-Path $myInvocation.MyCommand.Path)
    #Log File Info
    $startTime = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $Logfile = $Logpath + "\" + $scriptName + " " + $startTime + ".log"
    $OsDrive = $env:SystemDrive
    $BitlockerSuccess = $true
    #endregion

    #region ---------------------------------------------------[Import Modules and Extensions]-----------------------------------------
    Import-Module Bitlocker -DisableNameChecking
    #endregion

    #region ---------------------------------------------------[Functions]------------------------------------------------------------
    Function LogWrite {
        Param(
            $logfile = "$logfile",
            [validateset("Info", "Warning", "Error")]$type = "Info",
            [string]$Logstring
        )
        Begin { }
        Process {
            If ($Global:LogEnabled) {
                Try {
                    Add-content $Logfile -value "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') - $type - $logstring"
                    if ($Global:GUILogEnabled) {
                        if ($type -eq "Info") {$foreGroundColor = "Green"}
                        elseif ($type -eq "Warning") {$foreGroundColor = "Cyan"}
                        elseif ($type -eq "Error") {$foreGroundColor = "Red"}
                        Write-Host $(Get-Date -Format 'dd-MM-yy yy HH:mm:ss') - $logstring -ForegroundColor $foreGroundColor
                    }
                }    
                Catch {
                    Write-Host $(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') - $_ -ForegroundColor Cyan
                    Break
                }
            }
        }
        End { }
    }
    #endregion

    #region ---------------------------------------------------[Script Execution]------------------------------------------------------
    logwrite -Logstring "Starting script to Enable Bitlocker with powershell and backup key to AAD" -type Info

    ###########################
    #Enable BitLocker         #
    ###########################
    logwrite -Logstring "Checking if Bitlocker is enabled" -type Info
    $Bitlockerstatus = (Get-BitLockerVolume -MountPoint $OSDrive).volumestatus
    logwrite -Logstring "Bitlocker status detected on $OSDrive = $Bitlockerstatus" -type Info
    if ($Bitlockerstatus -eq "FullyDecrypted") {
        #Checking if Bitlocker has been enabled in history and created a xml file
        $SourceFile = $OSDrive + "\Windows\System32\Recovery\REAgent.xml"
        $Newfile = $SourceFile + $startTime + ".old"
        if (Test-Path -Path $SourceFile) {
            logwrite -Logstring "Bitlocker has been enabled in history and an xml file exists $sourcefile, trying to rename" -type Info
            try {
                Rename-Item -Path $SourceFile -NewName $Newfile
                logwrite -Logstring "Renamed Bitlocker old Bitlocker xml from $sourcefile to $Newfile" -type Info
            }
            catch {logwrite -Logstring "Failed to rename old Bitlocker xml with error: '$_.Exception.Message'" -type error}
        }
        logwrite -Logstring "All external drives must be ejected to enable Bitlocker, trying to eject DVD/ISO" -type Info
        try {
            # Automatically unmount any CD/DVD or ISO
            $Diskmaster = New-Object -ComObject IMAPI2.MsftDiscMaster2
            if ($diskmaster.count -ge 1) {
                $DiskRecorder = New-Object -ComObject IMAPI2.MsftDiscRecorder2
                $DiskRecorder.InitializeDiscRecorder($DiskMaster)
                $DiskRecorder.EjectMedia()
                logwrite -Logstring "Eject CD/DVD drive executed sucessfully" -type Info
            }
            Else {logwrite -Logstring "No DVD/ISO was detected" -type Info}
        }
        catch {logwrite -Logstring "Failed to eject DVD/ISO drive with error: '$_.Exception.Message'" -type error}
        logwrite -Logstring "All external drives must be ejected to enable Bitlocker, trying to eject USB" -type Info
        try {
            # Automatically unmount any USB sticks
            $volumes = get-wmiobject -Class Win32_Volume | where-object {$_.drivetype -eq '2'}
            if ($volumes.count -ge 1) {
                foreach ($volume in $volumes) {
                    $ejectCmd = New-Object -comObject Shell.Application
                    $ejectCmd.NameSpace(17).ParseName($volume.driveletter).InvokeVerb("Eject")
                    logwrite -Logstring "Eject USB drive executed for '$volume.driveletter'" -type Info
                }
            }
            Else {logwrite -Logstring "No USB was detected" -type Info}
        }
        catch {logwrite -Logstring "Failed to eject USB drive with error: '$_.Exception.Message'" -type error}
        logwrite -Logstring "Trying to enable Bitlocker on $OSDrive" -type Info
        if ($SkipHardwareTest){
            try {
                Enable-BitLocker -MountPoint $OSDrive -EncryptionMethod $EncryptionMethod -UsedSpaceOnly -TpmProtector -RecoveryPasswordProtector -SkipHardwareTest -ErrorAction Continue
                logwrite -Logstring "Bitlocker enable command sent to disksystem" -type Info
            }
            catch {
                logwrite -Logstring "Failed to enable Bitlocker on $OSDrive with error: '$_.Exception.Message'" -type error
                $BitlockerSuccess = $false
            }
        }
        else{
            try {
                Enable-BitLocker -MountPoint $OSDrive -EncryptionMethod $EncryptionMethod -UsedSpaceOnly -TpmProtector -RecoveryPasswordProtector -ErrorAction Continue
                logwrite -Logstring "Bitlocker enable command sent to disksystem" -type Info
            }
            catch {
                logwrite -Logstring "Failed to enable Bitlocker on $OSDrive with error: '$_.Exception.Message'" -type error
                $BitlockerSuccess = $false
            }
        }

    }
    else {logwrite -Logstring "Bitlocker is already triggered on $OSDrive, no need to enable bitlocker"}

    ###########################
    #Enable recovery key      #
    ###########################
    logwrite -Logstring "Checking if Bitlocker has recoverykey" -type Info

    if (!($Bitlockerkeys = (Get-BitLockerVolume -MountPoint $OSDrive).KeyProtector | Where-Object {$_.KeyProtectorType -eq "RecoveryPassword"})) {
        logwrite -Logstring "Bitlocker has no recoverykey for $OSDrive, trying to create"
        try {
            Add-BitLockerKeyProtector -MountPoint $OSDrive  -RecoveryPasswordProtector -ErrorAction Continue | out-null
            logwrite -Logstring "Bitlocker recoverykey requested from disksystem" -type Info
        }
        catch {
            logwrite -Logstring "Failed to enable Bitlocker recoverykey on $OSDrive with error: '$_.Exception.Message'" -type error
            $BitlockerSuccess = $false
        }               
    }
    else {logwrite -Logstring "Bitlocker already has a recoverykey for $OSDrive"} 

    ###########################
    #Backup recoverykey       #
    ###########################
    logwrite -Logstring "Starting to backup recoverkey" -type Info
    If ($Bitlockerkeys = (Get-BitLockerVolume -MountPoint $OSDrive).KeyProtector | Where-Object {$_.KeyProtectorType -eq "RecoveryPassword"}) {
        if ($BackupkeyToDisk) {
            #Local backup
            logwrite -Logstring "Trying to backup recoverkey to localdisk" -type Info
            New-Item -ItemType Directory -Force -Path "$OSDrive\temp" | out-null
            Try {
                $Bitlockerkeys  | Out-File "$OSDrive\temp\$($env:computername)_BitlockerRecoveryPassword.txt"
                logwrite -Logstring "Bitlocker recoverykey stored locally in $OSDrive\temp\$($env:computername)_BitlockerRecoveryPassword.txt" -type Info
            }
            catch {
                logwrite -Logstring "Failed to backup Bitlocker recoverykey to local disk with error: '$_.Exception.Message'" -type error
                $BitlockerSuccess = $false
            }
        }
        Else {logwrite -Logstring "Backup Bitlocker key to localdisk skipped" -type Info}
    
        if ($BackupkeyToAD) {
            #AD Backup
            if (Get-Command "Backup-BitLockerKeyProtector" -ErrorAction SilentlyContinue) {
                logwrite -Logstring "Trying to backup key to AD with Backup-BitLockerKeyProtector" -type Info
                foreach ($bitlockerkey in $bitlockerkeys) {
                    try {
                        Backup-BitLockerKeyProtector -MountPoint $OSDrive -KeyProtectorId $Bitlockerkey.KeyProtectorId -ErrorAction continue | Out-Null
                        logwrite -Logstring "Bitlocker recoverykey backed up to AD with success" -type Info
                    }
                    catch {
                        logwrite -Logstring "Failed to backup Bitlocker recoverykey to AD with error: '$_.Exception.Message'" -type error
                        $BitlockerSuccess = $false
                    }
                }
            }
        }
        else {logwrite -Logstring "Backup Bitlocker key to AD skipped"}

        if ($BackupkeyToAAD) {
            #AAD Backup
            if (Get-Command "BackupToAAD-BitLockerKeyProtector" -ErrorAction SilentlyContinue) {
                logwrite -Logstring "Trying to backup key to AAD with BackupToAAD-BitLockerKeyProtector" -type Info
                foreach ($bitlockerkey in $bitlockerkeys) {
                    try {
                        BackupToAAD-BitLockerKeyProtector -MountPoint $OSDrive -KeyProtectorId $Bitlockerkey.KeyProtectorId -ErrorAction continue | Out-Null
                        logwrite -Logstring "Bitlocker recoverykey backed up to AAD with success" -type Info
                    }
                    catch {
                        logwrite -Logstring "Failed to backup Bitlocker recoverykey to AAD with error: '$_.Exception.Message'" -type error
                        $BitlockerSuccess = $false
                    }
                }
            }
        }
        else {logwrite -Logstring "Backup Bitlocker key to AAD skipped"}
    }
    Else {
        logwrite -Logstring "No bitlocker key exists, backup fails" -type Warning
        $BitlockerSuccess = $false
    }
    ###########################
    #Remove-scheduledtask     #
    ###########################

    if ($BitlockerSuccess) {
        logwrite -Logstring "Script to enable Bitlocker was run successfully, removing scheduled job" -type Info
        if (Get-ScheduledJob -name "BitlockerTrigger" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) {
            try {
                Unregister-scheduledjob -Name "BitlockerTrigger" -Confirm:$false
                logwrite -Logstring "Schedulejob removed successfully" -type Info
            }
            catch {logwrite -Logstring "Failed to remove schedulejob with error: '$_.Exception.Message'" -type error}
        }
        else {logwrite -Logstring "Schedulejob does not exist" -type Info}
    }

    Set-StrictMode -Off
    logwrite -Logstring "Script finished" -type info
    return $BitlockerSuccess
    # Close PowerShell windows upon completion
    stop-process -Id $PID
    #endregion
}
#endregion
#region ---------------------------------------------------[Script Execution]------------------------------------------------------
logwrite -Logstring "Starting script to schedule a powershell job $jobname" -type Info

logwrite -Logstring "Checking if a schedulejob $jobname already exists" -type Info
if (Get-ScheduledJob -Name $jobname -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) {
    logwrite -Logstring "Schedulejob $jobname already exists, trying to delete" -type Info
    Try {Unregister-scheduledjob -Name $jobname -Confirm:$false
        logwrite -Logstring "Schedulejob $jobname deleted successfully" -type Info}
    catch {logwrite -Logstring "Failed to remove schedulejob $jobnamewith error: '$_.Exception.Message'" -type error
        $success = $false}
}
if (!$trigger) {logwrite -Logstring "No schedule is configured for the scheduledJob. At least one schedule is needed" -type error
        $success = $false}
$JobParams = @{
    Name               = $jobname
    scriptblock        = $scriptblock
    Trigger            = $trigger
    ScheduledJobOption = $Options}
logwrite -Logstring "Trying to create Schedule powershell job $jobname" -type Info
Try {register-scheduledjob @JobParams
    logwrite -Logstring "Schedulejob $jobname created successfully" -type Info}
catch {logwrite -Logstring "Failed to create schedulejob $jobname with error: '$_.Exception.Message'" -type error
    $success = $false}
Set-StrictMode -Off
logwrite -Logstring "Script finished" -type info
return $success
# Close PowerShell windows upon completion
stop-process -Id $PID
#endregion