<#PSScriptInfo
.SYNOPSIS
    Script for Intune Remediation to detect registry keys (This example with Branding)

.DESCRIPTION
    This script will Detect registrykeys and veriofy the correct values
    It will log the transcript and write it to eventlog, The transcript text will also be returned to Intune

.NOTES
    .AUTHOR         Mr Tbone Granheden @MrTbone_se 
    .COMPANYNAME    Coligo AB @coligoAB
    .COPYRIGHT      Feel free to use this, but would be grateful if my name is mentioned in notes

.RELESENOTES
    1.0 Initial version
#>

#region ------------------------------------------------[Set script requirements]------------------------------------------------
#Requires -Version 4.0
#Requires -RunAsAdministrator
#endregion

#region -------------------------------------------------[Modifiable Parameters]-------------------------------------------------
$RemediationName    = "Reg-Branding"    # Used for Eventlog
$Logpath            = "$($env:TEMP)"    # Path to log transcript
$RegistryKeys = @(
    @{
        RegKeyPath  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation"
        RegKeyName  = "SupportURL"
        RegKeyValue = "https://www.coligo.se"
        RegType     = "String"
    },
    @{
        RegKeyPath  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation"
        RegKeyName  = "Manufacturer"
        RegKeyValue = "Coligo AB"
        RegType     = "String"
    },
    @{
        RegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation"
        RegKeyName = "SupportHours"
        RegKeyValue = "09:00-16:00"
        RegType     = "String"
    },
    @{
        RegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation"
        RegKeyName = "SupportPhone"
        RegKeyValue = "+46 8 214466"
        RegType     = "String"
    },
    @{
        RegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation"
        RegKeyName = "RegisteredOwner"
        RegKeyValue = "Coligo AB"
        RegType     = "String"
    },
    @{
        RegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation"
        RegKeyName = "RegisteredOrganization"
        RegKeyValue = "Coligo AB"
        RegType     = "String"
    }
)
#endregion

#region --------------------------------------------------[Static Variables]-----------------------------------------------------
#Declare variables
[string]$Transcript = $null
[string]$EventType  = $null
[int32]$eventID     = $null
#set defaults
[Bool]$Detected     = $False
#set Eventsource and Logfile
[string]$Logfile    = "$($Logpath)\Detect-$($RemediationName).log"
[string]$eventsource="Detect-$($RemediationName)"
#endregion

#region --------------------------------------------[Import Modules and Extensions]----------------------------------------------
#endregion

#region ------------------------------------------------------[Functions]--------------------------------------------------------
Function Detect-RegistryKeys {
    Param(
        [array]$RegistryKeys
    )
    Begin {}
    Process {
        Foreach ($Key in $RegistryKeys) {
            $RegKeyPath = $Key.RegKeyPath
            $RegKeyValue = $Key.RegKeyValue
            $RegKeyName = $Key.RegKeyName
            $ExistingValue = $null
            if (Test-Path -Path "$($RegKeyPath)" -ErrorAction silentlycontinue) {
                $ExistingValue = (Get-ItemProperty -Path "$($Key.RegKeyPath)" -Name "$($RegKeyName)" -ErrorAction silentlycontinue).$RegKeyName
                if (($existingvalue) -and ($error.count -eq 0)){write-verbose "Found existing regkey $($RegKeyName)" -verbose}
                else{write-warning "The regkey $($RegKeyName) is missing. Need to Remediate"}
                if(($ExistingValue -ne $RegKeyValue) -or ($null -eq $ExistingValue)){
                    write-verbose "The value in regkey $($RegKeyName) is not correct. Need to Remediate" -verbose
                    return $false
                }
                else {write-verbose "The value in $($RegKeyName) is correct" -verbose}
            }
            else {
                write-warning "The regpath $($RegKeyPath) is missing. Need to Remediate" -verbose
                return $false
            }
        }
        return $true
        }
    End {}
}
function Write-ToEventlog {
    Param(
        [string]$Logtext,
        [string]$EventSource,
        [int]$EventID,
        [validateset("Information", "Warning", "Error")]$EventType = "Information"
    )
    Begin {}
    Process {
    if (!([System.Diagnostics.EventLog]::SourceExists($EventSource))) {
        New-EventLog -LogName 'Application' -Source $EventSource -ErrorAction ignore | Out-Null
        }
    Write-EventLog -LogName 'Application' -Source $EventSource -EntryType $EventType -EventId $EventID -Message $Logtext -ErrorAction ignore | Out-Null
    }
    End {}
}
#endregion
#region --------------------------------------------------[Script Execution]-----------------------------------------------------
#Clear all Errors before start
$Error.Clear()
#Start logging
start-transcript -Path $Logfile

#Detect
$Detected = Detect-RegistryKeys $RegistryKeys

#Get transcript and cleanup the text
Stop-Transcript |out-null
$Transcript = ((Get-Content $LogFile -Raw) -split ([regex]::Escape("**********************")))[-3]
#endregion

#region -----------------------------------------------------[Detection]---------------------------------------------------------
#Compliant
if ($Detected){
    $EventText =  "Compliant - No need to Remediate `n$($Transcript)";$eventID=10;$EventType="Information"
    Write-ToEventlog $EventText $EventSource $eventID $EventType
    Write-output "$($EventText -replace "`n",", " -replace "`r",", ")" #with no line breaks
    Exit 0
}
#Non Compliant
Else{
    $EventText =  "NON Compliant - Need to Remediate `n$($Transcript)";$eventID=11;$EventType="Warning"
    Write-ToEventlog $EventText $EventSource $eventID $EventType
    Write-output "$($EventText -replace "`n",", " -replace "`r",", ")" #with no line breaks
    Exit 1
}
#endregion