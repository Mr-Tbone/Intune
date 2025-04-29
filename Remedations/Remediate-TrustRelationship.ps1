<#PSScriptInfo
.SYNOPSIS
    Script for Intune Remediation to detect if Trust relationship with domain is good
    And fix it by repair the trust relationship with the domain
    
.DESCRIPTION
    This script will detect if Trust relationship with domain is good
    And fix it by repair the trust relationship with the domain

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
$domainFQDN = "tbone.se"        #Set the domain FQDN to check trust relationship with
$username = "tbone\joinaccount" #Set the domain username to repair trust relationship with
#Note: This account must have permission to join computers to the domain
$password = "TboneTbone911!"    #Set the domain password to repair trust relationship with
#Note: This password will be stored in plain text, use with caution! I strongly recommend to use a secure password vault or similar to store the password securely.
$securepassword = $password | ConvertTo-SecureString -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username, $securepassword)

#region --------------------------------------------------[Script Execution]-----------------------------------------------------
#Get domain controller if domain controller is available
try{
    $context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $domainFQDN)
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($context)
    $PDCServer = $domain.PdcRoleOwner
    $PDCServerName = $PDCServer.Name
}
catch {
    write-host "No Domain network available, exiting script with error $_"
    exit 0
}
#test if domain controller is available
if (Test-NetConnection -ComputerName $PDCServerName -Port 389 -InformationLevel Quiet) {
    if (!(Test-ComputerSecureChannel)) {
        write-host "Broken Trust relationship with domain"
        try{Test-ComputerSecureChannel -Repair -Credential $credential -Verbose
            write-host "Repaired Trust relationship with domain"
            exit 0
        }
        catch {
            write-host "Failed to repair Trust relationship with domain"
            exit 1
        }
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