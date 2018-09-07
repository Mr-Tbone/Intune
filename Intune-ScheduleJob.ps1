<#
.SYNOPSIS
    Intune ScheduleJob Wrapper
 
.DESCRIPTION
    Coligo Intune Scripts for Office 365
    This script needs to be distributed with Intune powershell feature
    It must be run under system, ie "Run this script using the logged on credentials" set to "No".
    This script is a wrapper to schedule a powershell job with a scriptblock at specified time and interval
           
.EXAMPLE
   .\Intune-ScheduleJob.ps1
    Schedule a job to execute scriptblock
 
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
$jobName = "PowershellJob"          # Name of the job
#ScheduleJob Schedules
$TriggerOnce = @{                                        
    Once                = $true                         #Trigger the scheduledjob to run once and repeat
    At                  = (get-date 10:00:00)           #Trigger the scheduledjob to run once at this hour
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
    #Add scriptblock to execute
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
