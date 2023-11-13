<#PSScriptInfo
.SYNOPSIS
    Script to Map Objects for AAD joined computers

.DESCRIPTION
    This script will map drives and printers for AAD joined computers
    It can be used as both script and remediation script in Intune. 
    I prefer to use it as a remediation script to be able to update with new versions.
        
.NOTES
    Written by Mr-Tbone (Tbone Granheden) @ Colig AB     @MrTbone_se
    Initial ideas for the script from Nicola Suter @nicolonsky

.VERSION
    1.2

.RELEASENOTES
    1.0 2023-10-02 Initial Build
    1.1 2021-10-04 Added logging to eventlog
    1.2 2021-10-05 Added detection mode to run as remediation script

.AUTHOR
    Tbone Granheden 
    @MrTbone_se

.COMPANYNAME 
    Coligo AB

.GUID 
    00000000-0000-0000-0000-000000000000

.COPYRIGHT
    Feel free to use this, But would be grateful if My name is mentioned in Notes 
#>
 
#region ---------------------------------------------------[Set script requirements]-----------------------------------------------
#endregion

#region ---------------------------------------------------[Script Parameters]-----------------------------------------------
#endregion

#region ---------------------------------------------------[Modifiable Parameters and defaults]------------------------------------

#IMPORTANT! When adding new Drivers make sure to also increment Version in Psscriptinfo above. 
#Add Objects to Map here either Printers or Drives (Not Both) with the following syntax
#Printers:  $MapObjects += @{PrinterName="PrinterName"  ;Default=$true      ;Path="\\printserver\printerName"   ;ADGroups="My Group"}
#Drives:    $MapObjects += @{Letter="X"                 ;Persistent=$true   ;Path="\\fileserver\fileshare"      ;ADGroups="My Group"    ;Label="My drive"}
$MapObjects = @()
$MapObjects+=@{Letter="S";Persistent=$true;Path="\\fileserver.tbone.se\Sales"	    ;ADGroups=	"Sales"	        ;Label="Sales"      }
$MapObjects+=@{Letter="C";Persistent=$true;Path="\\fileserver.tbone.se\Consult"     ;ADGroups=	"Consultants"   ;Label="Consultants"}
$MapObjects+=@{Letter="W";Persistent=$true;Path="\\fileserver.tbone.se\Common"	    ;ADGroups=	"Loc_ESC"       ;Label=""           }

[String]$CorpDataPath		= "C:\ProgramData\CorpData" #Set to the path where you want to store the script and logs
[String]$global:searchRoot  = "tbone.se"                #Set to the domain you want to search for group memberships
[Bool]$removeStaleObjects   = $false                    #Set to true to remove stale objects
[Bool]$forceReplaceAll      = $false                    #Set to true to force replace all scripts and scheduled tasks
[int]$KeepNumberOfLogs      = 10                        #Set to the number of logs you want to keep in logs folder
#endregion

#region ---------------------------------------------------[Import Modules and Extensions]-----------------------------------------
#endregion

#region ---------------------------------------------------[Set global script settings]--------------------------------------------
Set-StrictMode -Version Latest
#endregion

#region ---------------------------------------------------[Static Variables]------------------------------------------------------
$groupMemberships = $null
$compliance = @()
$compliance += $true
[string]$Transcript = $null
[string]$Global:EventType  = "information"
[int32]$Global:EventId     = 10
if ($PSCommandPath -like "*detect*"){[Bool]$Remediation = $false}
else{[Bool]$Remediation = $true}
if ($MapObjects -and $MapObjects[0] -and $MapObjects[0].Keys -contains 'Letter') {[string]$ObjectType = "Drive"}
else {[string]$ObjectType = "Printer"}
[string]$TaskName 		    = "Intune$($ObjectType)Mapping"
[string]$TaskDescription    = "Map $($ObjectType) with script from Intune"
[string]$logpath 			= "$($CorpDataPath)\logs"
[string]$LogFile            = "$($logpath)\$($TaskName)$(Get-Date -Format 'yyyyMMdd')$(Get-Date -format 'HHmmss').log"
[string]$ScriptSavePath     = $(Join-Path -Path $CorpDataPath -ChildPath "scripts\$($TaskName).ps1")
[string]$vbsSavePath        = $(Join-Path -Path $CorpDataPath -ChildPath "scripts\$($TaskName).vbs")
#endregion

#region ---------------------------------------------------[Functions]------------------------------------------------------------
function Get-ADGroupMembership {
    param()
    process {
        $testResult = Test-NetConnection -ComputerName $global:searchRoot -Port 389 -InformationLevel Quiet
        if ($testResult) {
            write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to connect to domain controller for $($global:searchRoot)"
            $UserPrincipalName = $(whoami -upn)
            if ($UserPrincipalName -and $UserPrincipalName -like "*@*"){
                write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to enumerate userprincipalname to: $($UserPrincipalName)"
                # if no domain specified fallback to PowerShell environment variable
                if ([string]::IsNullOrEmpty($global:searchRoot)) {
                    $global:searchRoot = $env:USERDNSDOMAIN
                }
                # Check if there is connectivity to a domain controller
                    $null = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain((New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $global:searchRoot) -ErrorAction SilentlyContinue -ErrorVariable errorvar))
                    if ($errorvar.count -eq 0){
                        write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to connect to domain controller for $($global:searchRoot)"
                        # Set Active Directory Search Settings
                        try{
                            $searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher
                            $searcher.Filter = "(&(userprincipalname=$UserPrincipalName))"
                            $searcher.SearchRoot = "LDAP://$global:searchRoot"
                            $distinguishedName = $searcher.FindOne().Properties.distinguishedname
                            $searcher.Filter = "(member:1.2.840.113556.1.4.1941:=$distinguishedName)"
                            [void]$searcher.PropertiesToLoad.Add("name")
                            $list = [System.Collections.Generic.List[String]]@()
                            $results = $searcher.FindAll()
                        }
                        catch{
                            write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),error,Failed to collect user group memberships with error: $_";$errorvar=$null;$Global:EventId=12;$Global:EventType="Error"
                            return $null
                        }
                        if ($results) {
                            write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to collect user group memberships and found $($results.count) groups"
                            foreach ($result in $results) {
                                $resultItem = $result.Properties
                                [void]$List.add($resultItem.name)
                            }
                            return $list
                        }
                        else {
                            write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Failed to collect user group memberships for user $($UserPrincipalName)"
                            return $null
                        }
                    }
                    else {
                        write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),error,Failed to connect to domain controller for $($global:searchRoot) with error: $($errorvar)";$errorvar=$null;$Global:EventId=12;$Global:EventType="Error"
                        return $null
                    }
                }
            else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),error,Failed to enumerate userprincipalname"}
        }
        else{
            write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),error,Failed to connect to domain controller for $($global:searchRoot)";$errorvar=$null;$Global:EventId=12;$Global:EventType="Error"
            return $null
        }
    }
    End {}
}
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
function Map-Printer {
    Param(
        [string]$PrinterName,
        [string]$Printerpath,
        [bool]$Default
    )
    Begin {}
    Process {
        $existingPrinter = $null
        # Get the existing printer
        $null = $existingPrinter = Get-Printer -Name $Printerpath -ErrorAction SilentlyContinue -ErrorVariable errorvar
        if ($errorvar.count -eq 0){
            write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,success to find existing printer already mapped with same path as $($PrinterPath)"
            # Check if the printer exists and has the correct properties
            $printer = Get-CimInstance -Class win32_printer -filter "Name='$($Printerpath -replace '\\','\\')'" -ErrorAction SilentlyContinue -ErrorVariable errorvar
            if ($existingPrinter -and $printer.default -eq $Default){
                # If it does, no need to do anything
                write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to verify existing printer $($PrinterPath) already correctly mapped"
                }
            else {
                # If it doesn't, remove it if exists
                $null = Remove-Printer -Name $Printerpath -ErrorAction SilentlyContinue -ErrorVariable errorvar
                if ($errorvar.count -eq 0){
                    write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to remove existing printer map with same path as $($PrinterPath)"
                    $null = Add-Printer -ConnectionName $PrinterPath -ErrorAction silentlycontinue -ErrorVariable errorvar
                    if ($errorvar.count -eq 0){
                        write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to add printer $($PrinterPath)"
                        # Set the new printer as the default printer if specified
                        if ($Default) {
                            $printer = Get-CimInstance -Class win32_printer -filter "Name='$($Printerpath -replace '\\','\\')'" -ErrorAction SilentlyContinue -ErrorVariable errorvar
                            if ($errorvar.count -eq 0){
                                write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to get printer to set as default on $($PrinterPath)"
                                $null = Invoke-CimMethod -InputObject $printer -MethodName SetDefaultPrinter -ErrorAction silentlycontinue -ErrorVariable errorvar
                                if ($errorvar.count -eq 0){
                                    write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to set printer $($PrinterPath) as default"
                                }
                                else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Warning,Failed to set printer $($PrinterPath) as default with error: $($errorvar)";$errorvar=$null;$Global:EventId=11;$Global:EventType="Warning"}
                            }
                            else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Warning,Failed to get printer to set as default on $($PrinterPath) with error: $($errorvar)";$errorvar=$null;$Global:EventId=11;$Global:EventType="Warning"}
                        }
                    }
                    else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Error,Failed to add printer $($PrinterPath) with error: $($errorvar)";$errorvar=$null;$Global:EventId=12;$Global:EventType="Error"}
                }
                else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Error,Failed to remove existing printer map with same path as $($PrinterPath) with error: $($errorvar)";$errorvar=$null;$Global:EventId=12;$Global:EventType="Error"}
                }
            }
        else{
            $null = Add-Printer -ConnectionName $PrinterPath -ErrorAction silentlycontinue -ErrorVariable errorvar
            if ($errorvar.count -eq 0){
                write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to add printer $($PrinterPath)"
                # Set the new printer as the default printer if specified
                if ($Default) {
                    $printer = Get-CimInstance -Class win32_printer -filter "Name='$($Printerpath -replace '\\','\\')'" -ErrorAction SilentlyContinue -ErrorVariable errorvar
                    if ($errorvar.count -eq 0){
                        write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to get printer to set as default on $($PrinterPath)"
                        $null = Invoke-CimMethod -InputObject $printer -MethodName SetDefaultPrinter -ErrorAction silentlycontinue -ErrorVariable errorvar
                        if ($errorvar.count -eq 0){
                            write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to set printer $($PrinterPath) as default"
                        }
                        else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Warning,Failed to set printer $($PrinterPath) as default with error: $($errorvar)";$errorvar=$null;$Global:EventId=11;$Global:EventType="Warning"}
                    }
                    else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Warning,Failed to get printer to set as default on $($PrinterPath) with error: $($errorvar)";$errorvar=$null;$Global:EventId=11;$Global:EventType="Warning"}
                }
            }
            else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Error,Failed to add printer $($PrinterPath) with error: $($errorvar)";$errorvar=$null;$Global:EventId=12;$Global:EventType="Error"}
        }
    }
    End {}
}
function Map-Drive {
    Param(
        [string]$Letter,
        [string]$DrivePath,
        [string]$Label,
        [bool]$Persistant
    )
    Begin {}
    Process {
        $existingDrive = $null
        # Get the existing Drive
        $existingDrive = Get-PSDrive -Name $Letter -ErrorAction SilentlyContinue -ErrorVariable errorvar
        if ($errorvar.count -eq 0){
            write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to find existing drive map with same path as $($DrivePath)"
            #Fix psDrive values to get correct compare results 
            if($existingDrive.Root -match '\$env:') {$existingDrive.Root = $ExecutionContext.InvokeCommand.ExpandString($existingDrive.Root)}
            if($existingDrive -and ($null -eq $existingDrive.Description)) {$existingDrive.Description = ""}
            #Check if the PSDrive exists and has the correct path
            if ($existingDrive.displayroot -eq $DrivePath) {
                # If it does, no need to do anything
                write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to verify existing drive $($Letter) already correctly mapped"
            }
            else {
                #If it doesn't, remove it and remap it
                Try{net use "$($Letter):" /delete #Remove-PSDrive -Name $Letter -ErrorAction silentlycontinue
                    write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success,Removed $($Letter):"}
                catch{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Error,Failed to remove $($Letter): with error: $($_.Exception.Message)";$errorvar=$null;$Global:EventId=12;$Global:EventType="error"}
                #Map the drive
                $null = New-PSDrive -PSProvider FileSystem -Name $Letter -Root $DrivePath -Description $Label -Persist:$Persistant -Scope global -ErrorAction silentlyContinue -ErrorVariable errorvar
                if ($errorvar.count -eq 0){
                    write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to add drive $($Letter):"
                    #Set the drive Label
                    (New-Object -ComObject Shell.Application -ErrorAction SilentlyContinue -ErrorVariable errorvar).NameSpace("$($Letter):").Self.Name = $Label
                    if ($errorvar.count -eq 0){write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to set drive $($Letter): Label to $($Label)"}
                    else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Warning,Failed to set drive $($Letter): Label to $($Label) with error: $($errorvar)";$errorvar=$null;$Global:EventId=11;$Global:EventType="Warning"}
                    }
                else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Error,Failed to add drive $($Letter): with error: $($errorvar)";$errorvar=$null;$Global:EventId=12;$Global:EventType="Error"}
            }
        }
        else{
            # Create the new PSDrive
            $null = New-PSDrive -PSProvider FileSystem -Name $Letter -Root $DrivePath -Description $Label -Persist:$Persistant -Scope global -ErrorAction silentlyContinue -ErrorVariable errorvar
            if ($errorvar.count -eq 0){
                write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to add drive $($Letter):"
                #Set the drive Label
                (New-Object -ComObject Shell.Application -ErrorAction SilentlyContinue -ErrorVariable errorvar).NameSpace("$($Letter):").Self.Name = $Label
                if ($errorvar.count -eq 0){write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to set drive $($Letter): Label to $($Label)"}
                else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Warning,Failed to set drive $($Letter): Label to $($Label) with error: $($errorvar)";$errorvar=$null;$Global:EventId=11;$Global:EventType="Warning"}
                }
            else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Error,Failed to add drive $($Letter): with error: $($errorvar)";$errorvar=$null;$Global:EventId=12;$Global:EventType="Error"}
        }
    }
    End {}
}
#endregion

#region ---------------------------------------------------[[Script Execution]------------------------------------------------------

#check if running as system
$RunningAsSystem = [bool]($(whoami -user) -match "S-1-5-18")

#If running as system, create scheduled task to run the powershell script as user
if ($RunningAsSystem) {
	#Create corpdata folder if it doesn't exist
	if (-not (Test-Path $CorpDataPath)) {
        if ($Remediation){
            $null = New-Item -ItemType Directory -Path $CorpDataPath -Force -ErrorAction silentlycontinue -ErrorVariable errorvar
            if ($errorvar.count -eq 0){write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success,Created corpdata folder"}
            else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Error,Failed to create corpdata folder with error: $($errorvar)";$errorvar=$null;$Global:EventId=12;$Global:EventType="Error"}
        }
        else {$compliance += $false}
    }
    #Create scripts and logs folder if it doesn't exist
	if (-not (Test-Path $CorpDataPath\scripts)) {
        if ($Remediation){
            $null = New-Item -ItemType Directory -Path $CorpDataPath\scripts -Force -ErrorAction silentlycontinue -ErrorVariable errorvar
            if ($errorvar.count -eq 0){write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success,Created corpdata scripts folder"}
            else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Error,Failed to create corpdata scripts folder with error: $($errorvar)";$errorvar=$null;$Global:EventId=12;$Global:EventType="Error"}
        }
        else {$compliance += $false}
    }
    #Create scripts and logs folder if it doesn't exist
    if (-not (Test-Path $CorpDataPath\logs)) {
        if ($Remediation){
            $null = New-Item -ItemType Directory -Path $CorpDataPath\Logs -Force -ErrorAction silentlycontinue -ErrorVariable errorvar
            if ($errorvar.count -eq 0){write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success,Created corpdata logs folder"}
            else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Error,Failed to create corpdata logs folder with error: $($errorvar)";$errorvar=$null;$Global:EventId=12;$Global:EventType="Error"}
        }
        else {$compliance += $false}
    }

	#Start Transcript logging
	Start-Transcript -Path $LogFile
	write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Start to create scheduled task as system for the users"
    if (!$Remediation){write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Running in detection mode, will NOT remediate and create scheduled task"}
	# load current script and check if current script exists in corpdata folder
	$currentScript = Get-Content -Path $($PSCommandPath)
    if (!$forceReplaceAll){
        if(Test-Path $ScriptSavePath){
            $ScriptSavedVersion = Test-ScriptFileInfo -Path $ScriptSavePath -ErrorAction SilentlyContinue -ErrorVariable errorvar | Select-Object version 
            if ($errorvar.count -eq 2){write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to read saved script info in corpdata folder"}
            else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,warning,Failed to read saved script info in corpdata folder with error: $($errorvar)";$errorvar=$null;$Global:EventId=11;$Global:EventType="warning"}
            $ScriptCurrentVersion = Test-ScriptFileInfo -path $MyInvocation.MyCommand.Path -ErrorAction SilentlyContinue -ErrorVariable errorvar | Select-Object version
            if ($errorvar.count -eq 2){write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to read current script info"}
            else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,warning,Failed to read current script info with error: $($errorvar)";$errorvar=$null;$Global:EventId=11;$Global:EventType="warning"}
            #Check if current script is the same as saved script
            if([version]$ScriptSavedVersion.version -ge [version]$ScriptCurrentVersion.version){
                $ReplaceScript = $False
                write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,ScriptSavedVersion = $($ScriptSavedVersion.version) is the same or newer than ScriptCurrentVersion = $($ScriptCurrentVersion.version)"
                }
            else{$ReplaceScript = $True
                write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),System,ScriptSavedVersion = $($ScriptSavedVersion.version) differ from ScriptCurrentVersion = $($ScriptCurrentVersion.version)"
            }
        }
        else {
            $ReplaceScript = $True
            write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,No existing saved script found"
        }
    }
    else {$ReplaceScript = $true
        write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,ForceReplaceScript is set to true, will replace existing script in corpdata folder"
    }
    if ($ReplaceScript){
        if ($Remediation){
            #Save current script to corpdata folder
            $currentScript | Out-File -FilePath $ScriptSavePath -Force -ErrorAction SilentlyContinue -ErrorVariable errorvar
            if ($errorvar.count -eq 0){
                write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to save the script in corpdata folder"
            
            }
            else{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),error,Failed to save the script in corpdata folder with error: $($errorvar)";$errorvar=$null;$Global:EventId=11;$Global:EventType="warning"}
        }
            else {
            write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Running in detection mode, Script needs to be replaced but will NOT remediate"
            $compliance += $false}
    }
    #Check if vbscript already exist
    if(!(Test-Path $vbsSavePath) -or $forceReplaceAll){
        if ($Remediation){ 
    # Create dummy vbscript to hide PowerShell Window popping up at logon
            $vbsScript = "
                Dim shell,fso,file
                Set shell=CreateObject(`"WScript.Shell`")
                Set fso=CreateObject(`"Scripting.FileSystemObject`")
                strPath=WScript.Arguments.Item(0)
                If fso.FileExists(strPath) Then
                set file=fso.GetFile(strPath)
                strCMD=`"powershell -nologo -executionpolicy ByPass -command `" & Chr(34) & `"&{`" &_
                file.ShortPath & `"}`" & Chr(34)
                shell.Run strCMD,0
                End If
                "
	        $vbsScript | Out-File -FilePath $vbsSavePath -Force -ErrorAction SilentlyContinue -ErrorVariable errorvar
            if ($errorvar.count -eq 0){write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to save the vbscript in corpdata folder"}
            else{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Error,Failed to save vbscript in corpdata folder with error: $($errorvar)";$errorvar=$null;$Global:EventId=12;$Global:EventType="error"}
            }
        else {
            write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Running in detection mode, vbscript needs to be replaced but will NOT remediate"
            $compliance += $false}
        }
    else{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to verify vbscript already exist in corpdata folder"}

    #Check if scheduled task already exist
    if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) -or $forceReplaceAll) {
        if ($Remediation){ 
            #Create Task Trigger
            $class = Get-cimclass MSFT_TaskEventTrigger root/Microsoft/Windows/TaskScheduler
            $Trigger_onEvent = $class | New-CimInstance -ClientOnly
            $trigger_onEvent.Enabled = $true
            $trigger_onEvent.Subscription = @"
                <QueryList>
                    <Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational">
                        <Select Path="Microsoft-Windows-NetworkProfile/Operational">
                            *[System[EventID=10000]]
                        </Select>
                    </Query>
                </QueryList>
"@
            $Trigger_atLogon = New-ScheduledTaskTrigger -AtLogOn
            #Execute task in users context
            $principal = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-545" -Id "Author"
            # Set path to wscript.exe
            $wscriptPath = Join-Path $env:SystemRoot -ChildPath "System32\wscript.exe"
            # Set task to call the vbscript helper and pass the Powershell script as argument
            $action = New-ScheduledTaskAction -Execute $wscriptPath -Argument "`"$vbsSavePath`" `"$scriptSavePath`""
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

            # Register scheduled task
            $null = Register-ScheduledTask -TaskName $TaskName -Trigger $Trigger_atLogon, $Trigger_onEvent -Action $action  -Principal $principal -Settings $settings -Description $TaskDescription -Force -ErrorAction SilentlyContinue -ErrorVariable errorvar
            if ($errorvar.count -eq 0){write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to register scheduled task"}
            else{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Error,Failed to register scheduled task with error: $($errorvar)";$errorvar=$null;$Global:EventId=12;$Global:EventType="error"}

            #Start scheduled task
            Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue -ErrorVariable errorvar
            if ($errorvar.count -eq 0){write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to start scheduled task"}
            else{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Error,Failed to start scheduled task with error: $($errorvar)";$errorvar=$null;$Global:EventId=12;$Global:EventType="error"}
            }
        else {
            write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Running in detection mode, scheduled task needs to be created but will NOT remediate"
            $compliance += $false}
        }
    else{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),System,Success,Script already exist in corpdata folder"}

    #stop transcript logging
    Stop-Transcript |out-null
    $Transcript = ((Get-Content $LogFile -Raw) -split ([regex]::Escape("**********************")))[-3]
#region ----------------------------------------------------[Remediation]--------------------------------------------------------
    #Detection Compliant
    if (!($Remediation) -and !($compliance -contains $false)){
        $EventText =  "Compliant `n$($Transcript)";$Global:EventId=20;$Global:EventType="information"
        Write-ToEventlog $EventText $TaskName $Global:EventId $Global:EventType
        write-host "$($EventText -replace "`n",", " -replace "`r",", ")" #with no line breaks
        Exit 0
    }
    #Detection Non compliant
    Elseif(!($Remediation) -and ($compliance -contains $false)){
        $EventText =  "NON Compliant or Failed Remediate `n$($Transcript)";$Global:EventId=21;$Global:EventType="warning"
        Write-ToEventlog $EventText $TaskName $Global:EventId $Global:EventType
        write-host "$($EventText -replace "`n",", " -replace "`r",", ")" #with no line breaks
        Exit 1
    }
    Else{
        $EventText =  "Remediated `n$($Transcript)";$Global:EventId=22;$Global:EventType="information"
        Write-ToEventlog $EventText $TaskName $Global:EventId $Global:EventType
        write-host "$($EventText -replace "`n",", " -replace "`r",", ")" #with no line breaks
        Exit 0
    }
#endregion
}

# If running as user (as a scheduled task), run scheduled task to map objects
else{
	Start-Transcript -Path $LogFile
    write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Start to map $($ObjectType) as user"
    
    # Get user group memberships
	$groupMemberships = Get-ADGroupMembership
	if ($groupMemberships){
        write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to collect user group memberships collected $($groupMemberships.count) groups"
		#Get target user mappings list based on groupmembeships
        $TargetUserMappings = $MapObjects | Where-Object {
            if ($_.ADGroups -ne $null) {
                foreach ($ADGroup in $_.ADGroups -split ";") {
                    if ($ADGroup -eq "" -or $groupMemberships -contains $ADGroup) {return $true}
                }
            }
            return $false
        }
        if ($TargetUserMappings){
            write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success to find $($TargetUserMappings.count) $($ObjectType) to map"
            #Iterate through all Target Objects to Map and check if they already exist
            foreach ($TargetUserMap in $TargetUserMappings) {
                if ($ObjectType -eq "Drive"){Map-Drive -Letter $TargetUserMap.Letter -DrivePath $TargetUserMap.Path -Label $TargetUserMap.Label -Persistant $TargetUserMap.Persistent}
                else{Map-Printer -PrinterName $TargetUserMap.PrinterName -PrinterPath $TargetUserMap.Path -Default $TargetUserMap.default}
            }

            # Remove unassigned Mapped Objects
            if ($removeStaleObjects) {
                if ($ObjectType -eq "Drive"){
                    $ExistingMappings = Get-PSDrive -ErrorAction SilentlyContinue -ErrorVariable errorvar | Where-Object { $_.Provider.Name -eq "FileSystem" -and $_.Root -notin @("$env:SystemDrive\", "D:\")}
                    if ($ExistingMappings){
                        foreach ($psdrive in $ExistingMappings){
                            if ($psdrive.name -notin $TargetUserMappings.Letter){
                                write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,found mapped drive $($psdrive.name) that has not been assigned will try to remove"
                                Try{net use "$($Letter):" /delete #Remove-PSDrive -Name $Letter -ErrorAction silentlycontinue
                                write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success,Removed unassigned drive $($Letter):"}
                            catch{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Error,Failed to remove unassigned drive $($Letter): with error: $($_.Exception.Message)";$errorvar=$null;$Global:EventId=12;$Global:EventType="error"}
                            }
                        }
                    }
                    else{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,No existing unassigned drives to be removed."}
                }
                else{
                    $ExistingMappings = Get-Printer  -ErrorAction SilentlyContinue -ErrorVariable errorvar| Where-Object {($_.shared -eq $true) -and ($_.Name -like "\\*")}
                    if ($ExistingMappings){
                        foreach ($printer in $ExistingMappings){
                            if ($printer.Name -notin $TargetUserMappings.Path){
                                write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,found mapped printer $($printer.Name) that has not been assigned will try to remove"
                                remove-printer -Name $printer.Name -Force -ErrorAction SilentlyContinue -ErrorVariable errorvar
                                if ($errorvar.count -eq 0){write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Success,Removed unassigned printer $($printer.Name)"}
                                else{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),Error,Failed to remove unassigned printer $($printer.Name) with error: $($_.Exception.Message)";$errorvar=$null;$Global:EventId=12;$Global:EventType="error"}
                            }
                        }
                    }
                    else {write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,No existing unassigned printers to be removed."}
                }
            }
            # Fix to ensure Mapped Drives are mapped as persistent!
            if ($ObjectType -eq "Drive"){
                $null = Get-ChildItem -Path HKCU:\Network -ErrorAction SilentlyContinue | ForEach-Object {New-ItemProperty -Name ConnectionType -Value 1 -Path $_.PSPath -Force -ErrorAction SilentlyContinue}
            }
        }
        else{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Error,Failed to find any $($ObjectType) to map"}
        }
    else{write-verbose -verbose "$(Get-Date -Format 'yyyy-MM-dd'),$(Get-Date -format 'HH:mm:ss'),info,Error,Failed to get user group memberships script cannot continue"}
 
    Stop-Transcript |out-null
    $Transcript = ((Get-Content $LogFile -Raw) -split ([regex]::Escape("**********************")))[-3]
    $EventText =  "Task running as User to map $($ObjectType) `n$($Transcript)"
    Write-ToEventlog $EventText $TaskName $Global:EventId $Global:EventType
    #cleanup logs and keep tha last 10 
    $null = Get-ChildItem -Path $logpath | Where-Object{ $_.name -like "$($taskname)*"} | Sort-Object CreationTime -Descending | Select-Object -Skip $KeepNumberOfLogs |remove-item -force
}
#endregion