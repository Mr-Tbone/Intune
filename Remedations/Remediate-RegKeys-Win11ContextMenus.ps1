<#PSScriptInfo
.SYNOPSIS
    Script for Intune Remediation to remediate and add registry keys (Example to enable old context menu in Windows 11)

.DESCRIPTION
    This script will Remediate by adding or updating all registrykeys to the correct values
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
$RemediationName    = "Reg-"    # Used for Eventlog
$Logpath            = "$($env:TEMP)"    # Path to log transcript
$RegistryKeys = @(
    @{
        RegKeyPath  = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
        RegKeyName  = ""        #If no name is specified, the default regkey is used
        RegKeyValue = ""        
        RegKeyType  = "String"  #Valid values are String, Dword, Qword, Binary, MultiString, ExpandString
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
Function Remediate-RegistryKeys {
    Param(
        [array]$RegistryKeys
    )
    Begin {}
    Process {
        foreach ($Key in $RegistryKeys) {
            if($Key.RegKeyName -eq ""){$Key.RegKeyName = "(Default)"}
            $CurrentRegValue  = $null
            $CurrentRegType   = $null 
            $NewRegValue = $null
            $NewRegKey = $null
            if ($Key.RegKeyType -eq "Binary" ) { #-and $Key.RegKeyValue -ne ""
                $NewKeyValue = [byte[]]$($Key.RegKeyValue -split ',' | ForEach-Object {[char][byte]"0x$_"})}
            else{$NewKeyValue = "$($Key.RegKeyValue)"}
#does the regkey exist?
            if (Test-Path -Path $Key.RegKeyPath -ErrorAction Ignore) {
                $CurrentRegValue = (Get-ItemProperty -Path $Key.RegKeyPath -Name "$($Key.RegKeyName)" -ErrorAction silentlycontinue)."$($Key.RegKeyName)"
                if (($null -ne $CurrentRegValue) -and $CurrentRegValue.gettype() -like "*Byte*"){
                    $CurrentRegValue = ([System.BitConverter]::ToString([byte[]]$currentregvalue)).Replace('-',',')}
                if (($null -ne $CurrentRegValue) -and ($error.count -eq 0)){
                    write-verbose "Found existing regkey for $($key.RegKeyName)" -verbose
#Check existing regkey type
                    if ($Key.RegKeyName -ne "(Default)") {
                        $CurrentRegType = (Get-Item -Path $Key.RegKeyPath -ErrorAction SilentlyContinue).GetValueKind($Key.RegKeyName)
                        if (($($Key.RegKeytype) -ne $CurrentRegType) -or ($null -eq $CurrentRegType)){
                            write-warning "The regkey $($Key.RegKeyName) is not correct type. Need to Remediate" -verbose
                            $NewRegValue = New-ItemProperty -Path $key.RegKeyPath -Name $key.RegKeyName -Value $NewKeyValue -PropertyType $key.RegKeyType -Force -ErrorAction silentlycontinue
                            if (($null -ne $NewRegValue) -and ($error.count -eq 0)){write-verbose "Remediated the value in $($key.RegKeyName)" -verbose}
                            else{write-warning "Failed to remediate the value in $($key.RegKeyName) with error:$($error.Exception.Message)";return $false}
                        }
                        else {write-verbose "The type on regkey $($Key.RegKeyName) is correct" -verbose}
                    }
    #Check existing regkey value   
                        if(($CurrentRegValue -ne $key.RegKeyValue) -or ($null -eq $CurrentRegValue)){
                            $NewRegValue = Set-ItemProperty -Path $Key.RegKeyPath -Name $Key.RegKeyName -Value $NewKeyValue -ErrorAction silentlycontinue
                            $CurrentRegValue = (Get-ItemProperty -Path $Key.RegKeyPath -Name $Key.RegKeyName -ErrorAction silentlycontinue)."$($Key.RegKeyName)"
                            if (($null -ne $CurrentRegValue) -and $CurrentRegValue.gettype() -like "*Byte*"){
                                $CurrentRegValue = ([System.BitConverter]::ToString([byte[]]$currentregvalue)).Replace('-',',')}
                            if(($error.count -eq 0) -and ($CurrentRegValue -eq $key.RegKeyValue)){
                                write-verbose "Remediated the value in $($Key.RegKeyName)" -verbose}
                            else{write-warning "Failed to remediate the value in $($Key.RegKeyName) with error:$($error.Exception.Message)";return $false}
                        }
                        else {write-verbose "The value in $($Key.RegKeyName) is correct No need to remediate" -verbose}
                    }
                else{write-warning "The regkey $($Key.RegKeyName) is missing. Error:$($error.Exception.Message)";$error.Clear()
                    $NewRegValue = New-ItemProperty -Path $key.RegKeyPath -Name $key.RegKeyName -Value $newKeyValue -PropertyType $key.RegKeyType -Force -ErrorAction silentlycontinue
                    if (($null -ne $NewRegValue) -and ($error.count -eq 0)){write-verbose "Remediated the value in $($key.RegKeyName)" -verbose}
                    else{write-warning "Failed to remediate the value in $($key.RegKeyName) with error:$($error.Exception.Message)";return $false}
                }
            }
            else {
                $NewRegKey= New-Item -Path $key.RegKeyPath -Force -ErrorAction silentlycontinue
                if (($null -ne $NewRegKey) -and ($error.count -eq 0)){write-verbose "Created the missing reg path to $($key.RegKeyName)" -verbose}
                else{write-warning "Failed to create the missing reg path to $($key.RegKeyName) with error:$($error.Exception.Message)";return $false}
            
                $NewRegValue = New-ItemProperty -Path $key.RegKeyPath -Name $key.RegKeyName -Value $newKeyValue -PropertyType $key.RegKeyType -Force -ErrorAction silentlycontinue
                if (($null -ne $NewRegValue) -and ($error.count -eq 0)){write-verbose "Remediated the value in $($key.RegKeyName)" -verbose}
                else{write-warning "Failed to remediate the value in $($key.RegKeyName) with error:$($error.Exception.Message)";return $false}
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

#Remediate
$Remediated =  Remediate-RegistryKeys $RegistryKeys

#Get transcript and cleanup the text
Stop-Transcript |out-null
$Transcript = ((Get-Content $LogFile -Raw) -split ([regex]::Escape("**********************")))[-3]
#endregion

#region ----------------------------------------------------[Remediation]--------------------------------------------------------
#Remediated
if($Remediated){
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