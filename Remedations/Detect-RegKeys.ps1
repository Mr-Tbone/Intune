<#PSScriptInfo
.SYNOPSIS
    Script for Intune Remediation to detect registry keys (Example)

.DESCRIPTION
    This script will Detect registrykeys and verify the correct values
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
$RemediationName    = "Reg-Win11Context"    # Used for Eventlog
$Logpath            = "$($env:TEMP)"    # Path to log transcript
$RegistryKeys = @(
    @{
        RegKeyPath  = "HKLM:\SOFTWARE\Tbone"
        RegKeyName  = ""        #If no name is specified, the default regkey is used
        RegKeyValue = "Tbone"        
        RegKeyType  = "String"  #Valid values are String, Dword, Qword, Binary, MultiString, ExpandString
    },
    @{
        RegKeyPath  = "HKLM:\SOFTWARE\Tbone"
        RegKeyName  = "Tbone-string"    
        RegKeyValue = "Tbone-string"
        RegKeyType  = "string"
    },
    @{
        RegKeyPath  = "HKLM:\SOFTWARE\Tbone"
        RegKeyName  = "Tbone-Dword"    
        RegKeyValue = "7"
        RegKeyType  = "dword"
    },
    @{
        RegKeyPath  = "HKLM:\SOFTWARE\Tbone"
        RegKeyName  = "Tbone-Qword"    
        RegKeyValue = "7"
        RegKeyType  = "qword"
    },
    @{
        RegKeyPath  = "HKLM:\SOFTWARE\Tbone"
        RegKeyName  = "Tbone-Binary"    
        RegKeyValue = "10,10"
        RegKeyType  = "binary"
    },
    @{
        RegKeyPath  = "HKLM:\SOFTWARE\Tbone"
        RegKeyName  = "Tbone-Multistring"    
        RegKeyValue = "Tbone-Multistring"
        RegKeyType  = "MultiString"
    },
    @{
        RegKeyPath  = "HKLM:\SOFTWARE\Tbone"
        RegKeyName  = "Tbone-Expandstring"    
        RegKeyValue = "Tbone-Expandstring"
        RegKeyType  = "ExpandString"
    }
)
#endregion

#region --------------------------------------------------[Static Variables]-----------------------------------------------------
#Declare variables
[string]$Transcript = $null
[string]$EventType  = $null
[int32]$eventID     = $null
#set defaults
[Bool]$Remediated   = $False
#set Eventsource and Logfile depending on remediation or detection mode
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
            if($Key.RegKeyName -eq ""){$Key.RegKeyName = "(Default)"}
            $CurrentRegValue  = $null
            $CurrentRegType   = $null
            if (Test-Path -Path $Key.RegKeyPath -ErrorAction silentlycontinue) {
                $CurrentRegValue = (Get-ItemProperty -Path $Key.RegKeyPath -Name "$($Key.RegKeyName)" -ErrorAction silentlycontinue)."$($Key.RegKeyName)"
                if (($null -ne $CurrentRegValue) -and $CurrentRegValue.gettype() -like "*Byte*"){
                    $CurrentRegValue = ([System.BitConverter]::ToString([byte[]]$currentregvalue)).Replace('-',',')}
                if (($null -ne $CurrentRegValue) -and ($error.count -eq 0)){
                    write-verbose "Found existing regkey $($Key.RegKeyName)" -verbose}
                else{write-warning "The regkey $($Key.RegKeyName) is missing. Need to Remediate"
                    return $false}
                if ($Key.RegKeyName -ne "(Default)") {
                    $CurrentRegType = (Get-Item -Path $Key.RegKeyPath -ErrorAction SilentlyContinue).GetValueKind($Key.RegKeyName)
                    if (($($Key.RegKeytype) -ne $CurrentRegType) -or ($null -eq $CurrentRegType)){
                        write-warning "The regkey $($Key.RegKeyName) is not correct type. Need to Remediate" -verbose
                        return $false}
                    else {write-verbose "The type on regkey $($Key.RegKeyName) is correct" -verbose}
                }
                if(($CurrentRegValue -ne $Key.RegKeyValue) -or ($null -eq $CurrentRegValue)){
                    write-verbose "The value in regkey $($Key.RegKeyName) is not correct. Need to Remediate" -verbose
                    return $false}
                else {write-verbose "The value in $($Key.RegKeyName) is correct" -verbose}
            }
            else {
                write-warning "The regpath $($Key.RegKeyPath) is missing. Need to Remediate" -verbose
                return $false}
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