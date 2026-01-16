<#PSScriptInfo
.VERSION        2.0.0
.AUTHOR         @MrTbone_se (T-bone Granheden)
.GUID           feedbeef-beef-4dad-beef-b628ccca16bd
.COPYRIGHT      (c) 2026 T-bone Granheden. MIT License - free to use with attribution.
.TAGS           Intune Graph PrimaryUser DeviceManagement MicrosoftGraph Azure
.LICENSEURI     https://opensource.org/licenses/MIT
.PROJECTURI     https://github.com/Mr-Tbone/Intune
.RELEASENOTES
    1.0 2025-03-19 Initial Build
    2.0.0 2026-01-16 Major Archived old azuread module
#>

<#
.SYNOPSIS
    Script for Azure to add required Microsoft Graph API permissions to a Managed Identity

.DESCRIPTION
    This script connects to Azure AD with the old AzureAD module
    Then assign the listed Microsoft Graph API permissions to the specified Managed Identity.

.EXAMPLE
    .\Set-AzureADManagedIdentityPermissions.ps1
    Will set the required Microsoft Graph API permissions on the specified Managed Identity that is specified in the script parameters defaults.

.EXAMPLE
    .\Set-AzureADManagedIdentityPermissions.ps1 -tenantID "your-tenant-id" -ManagedIdentity "Your-Managed-Identity-Name" -Permissions @("User.Read.All", "DeviceManagementManagedDevices.Read.All")
    Will set the specified Microsoft Graph API permissions on the specified Managed Identity.

.NOTES
    Please feel free to use this, but make sure to credit @MrTbone_se as the original author

.LINK
    https://tbone.se
#>

#region ---------------------------------------------------[Set Script Requirements]-----------------------------------------------
#Requires -Modules Microsoft.Graph.Authentication
#Requires -Version 5.1
#endregion

#region ---------------------------------------------------[Modifiable Parameters and Defaults]------------------------------------
# Customizations
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false,          HelpMessage = "The Tenant ID for the Azure AD tenant.")]
    [string]$TenantID       = "11111-08a2-4ade-9a68-0db7586d80ad",
    [Parameter(Mandatory = $false,          HelpMessage = "The name of the Managed Identity to assign permissions to.")]
    [string]$ManagedIdentity = "Tbone-Automate",
    [Parameter(Mandatory = $false,          HelpMessage = "Array of Microsoft Graph API permissions to assign to the Managed Identity.")]
    [string[]]$Permissions  = @("DeviceManagementManagedDevices.Read.All", "DeviceManagementManagedDevices.ReadWrite.All", "AuditLog.Read.All", "User.Read.All")
)
#endregion

#region ---------------------------------------------------[Modifiable Variables and defaults]------------------------------------
# Graph App ID for Microsoft Graph
$GraphAppId = "00000003-0000-0000-c000-000000000000"
#endregion

#region ---------------------------------------------------[Import Modules and Extensions]-----------------------------------------
# Check if Microsoft.Graph.Authentication module is already loaded, if not import it silently by suppressing verbose output
[string]$moduleName = 'AzureAD'
if (-not (Get-Module -Name $moduleName)) {
    & {$VerbosePreference = 'SilentlyContinue'; Import-Module $moduleName -ErrorAction Stop}
} else {Write-Verbose "Module '$moduleName' is already loaded"}
#endregion

#region ---------------------------------------------------[[Script Execution]------------------------------------------------------
Connect-AzureAD -TenantId $TenantID
$ManagedIdentityServicePrincipal = (Get-AzureADServicePrincipal -Filter "displayName eq '$ManagedIdentity'")
$GraphServicePrincipal = Get-AzureADServicePrincipal -Filter "appId eq '$GraphAppId'"

foreach ($Permission in $Permissions)
    {
    $AppRole = $GraphServicePrincipal.AppRoles | Where-Object {$_.Value -eq $Permission -and $_.AllowedMemberTypes -contains "Application"}
    New-AzureAdServiceAppRoleAssignment -ObjectId $ManagedIdentityServicePrincipal.ObjectId -PrincipalId $ManagedIdentityServicePrincipal.ObjectId -ResourceId $GraphServicePrincipal.ObjectId -Id $AppRole.Id
    }
 #endregion
