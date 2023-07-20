<#PSScriptInfo
.SYNOPSIS
    Script for Intune Remediation to add a registry keys (This example with Branding)

.DESCRIPTION
    This script will Detect and Remediate by adding or updating all registrykeys to the correct values
    It will log the transcript and write it to eventlog, The transcript text will also be returned to Intune
    Combined script for both detection and remediation

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
[Bool]$Remediated   = $False
#set Eventsource and Logfile depending on remediation or detection mode
if ((([io.fileinfo]$MyInvocation.MyCommand.Definition).BaseName) -like "*remediate*"){
    $remediate          = $True
    [string]$Logfile    = "$($Logpath)\Remediate-$($RemediationName).log"
    [string]$eventsource="Remediate-$($RemediationName)"
}
else{
    $remediate = $False
    [string]$Logfile    = "$($Logpath)\Detect-$($RemediationName).log"
    [string]$eventsource="Detect-$($RemediationName)"
}
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
Function Remediate-RegistryKeys {
    Param(
        [array]$RegistryKeys
    )
    Begin {}
    Process {
        foreach ($Key in $RegistryKeys) {
            $RegKeyPath = $Key.RegKeyPath
            $RegKeyValue = $Key.RegKeyValue
            $RegKeyName = $Key.RegKeyName
            $ExistingValue = $null
            $NewRegValue = $null
            $NewRegKey = $null

            if (Test-Path -Path $RegKeyPath -ErrorAction Ignore) {
                $ExistingValue = (Get-ItemProperty -Path "$($RegKeyPath)" -Name $RegKeyName -ErrorAction silentlycontinue).$RegKeyName
                if (($existingvalue) -and ($error.count -eq 0)){write-verbose "Found existing regkey $($RegKeyName)" -verbose}
                else{write-warning "Failed to find existing regkey $($RegKeyName) with error:$($error.Exception.Message)";$error.Clear()}

                if(($ExistingValue -ne $RegKeyValue) -or ($null -eq $ExistingValue)){
                    $NewRegValue = Set-ItemProperty -Path "$($Key.RegKeyPath)" -Name "$($RegKeyName)" -Value $RegKeyValue -ErrorAction silentlycontinue
                    $ExistingValue = (Get-ItemProperty -Path $RegKeyPath -Name $RegKeyName -ErrorAction silentlycontinue).$RegKeyName
                    if(($error.count -eq 0) -and ($ExistingValue -eq $RegKeyValue)){
                        write-verbose "Remediated the value in $($RegKeyName)" -verbose}
                    else{write-warning "Failed to remediate the value in $($RegKeyName) with error:$($error.Exception.Message)";return $false}
                }
                else {write-verbose "The value in $($RegKeyName) is correct No need to remediate" -verbose}
            }
            else {
                $NewRegKey= New-Item -Path $RegKeyPath -Force -ErrorAction silentlycontinue
                if (($NewRegKey) -and ($error.count -eq 0)){write-verbose "Created the missing reg path to $($RegKeyName)" -verbose}
                else{write-warning "Failed to create the missing reg path to $($RegKeyName) with error:$($error.Exception.Message)";return $false}
            
                $NewRegValue = New-ItemProperty -Path $RegKeyPath -Name $RegKeyName -Value $RegKeyValue -Force -ErrorAction silentlycontinue
                if (($NewRegValue) -and ($error.count -eq 0)){write-verbose "Remediated the value in $($RegKeyName)" -verbose}
                else{write-warning "Failed to remediate the value in $($RegKeyName) with error:$($error.Exception.Message)";return $false}
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
    if (!($Remediate)){$Detected = Detect-RegistryKeys $RegistryKeys}
#Remediate
    else{$Remediated =  Remediate-RegistryKeys $RegistryKeys}

#Get transcript and cleanup the text
Stop-Transcript |out-null
$Transcript = ((Get-Content $LogFile -Raw) -split ([regex]::Escape("**********************")))[-3]
#endregion

#region -----------------------------------------------------[Detection]---------------------------------------------------------
#Compliant
if ($Detected -and !($Remediate)){
    $EventText =  "Compliant - No need to Remediate `n$($Transcript)";$eventID=10;$EventType="Information"
    Write-ToEventlog $EventText $EventSource $eventID $EventType
    Write-output "$($EventText -replace "`n",", " -replace "`r",", ")" #with no line breaks
    Exit 0
}
#Non Compliant
Elseif(!($Detected) -and !($Remediate)){
    $EventText =  "NON Compliant - Need to Remediate `n$($Transcript)";$eventID=11;$EventType="Warning"
    Write-ToEventlog $EventText $EventSource $eventID $EventType
    Write-output "$($EventText -replace "`n",", " -replace "`r",", ")" #with no line breaks
    Exit 1
}
#endregion

#region ----------------------------------------------------[Remediation]--------------------------------------------------------
#Remediated
Elseif($Remediated -and $Remediate){
    $EventText =  "Remediated - Successful remediation `n$($Transcript)";$eventID=20;$EventType="information"
    Write-ToEventlog $EventText $EventSource $eventID $EventType
    Write-output "$($EventText -replace "`n",", " -replace "`r",", ")" #with no line breaks
    Exit 0
}
#Remediation Failed
Else{
    $EventText =  "Failed Remediate - Error:$($error.Exception.Message) `n$($Transcript)";$eventID=21;$EventType="Error"
    Write-ToEventlog $EventText $EventSource $eventID $EventType
    Write-error "$($EventText -replace "`n",", " -replace "`r",", ")" #with no line breaks
    Exit 1
}
#endregion