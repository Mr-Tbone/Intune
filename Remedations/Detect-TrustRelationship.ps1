<#PSScriptInfo
.SYNOPSIS
    Script for Intune Remediation to detect if Trust relationship with domain is good
    
.DESCRIPTION
    This script will detect if Trust relationship with domain is good

.NOTES
    .AUTHOR         Mr Tbone Granheden @MrTbone_se 
    .COMPANYNAME    Coligo AB @coligoAB
    .COPYRIGHT      Feel free to use this, but would be grateful if my name is mentioned in notes

.RELESENOTES
    1.0 Initial version
#>

#region ------------------------------------------------[Set script requirements]------------------------------------------------
#Requires -Version 4.0
#endregion

#region -------------------------------------------------[Modifiable Parameters]-------------------------------------------------
$domainFQDN = "hufvudstaden.se" #Set the domain FQDN to check trust relationship with

#region --------------------------------------------------[Script Execution]-----------------------------------------------------
#Get domain controller if domain controller is available
try{
    $context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $domainFQDN)
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($context)
    $PDCServer = $domain.PdcRoleOwner
    $PDCServerName = $PDCServer.Name
}
catch {
    write-host "No Domain network available, exiting script"
    exit 0
}
#test if domain controller is available
if (Test-NetConnection -ComputerName $PDCServerName -Port 389 -InformationLevel Quiet) {
    if (!(Test-ComputerSecureChannel)) {
        write-host "Broken Trust relationship with domain"
        exit 1
    }
    else{
        write-host "Good Trust relationship with domain"
        exit 0
    }
}
else {
    write-host "Failed to Connect to Domaincontroller, $PDCServerName is not available"
    exit 0
}
#endregion