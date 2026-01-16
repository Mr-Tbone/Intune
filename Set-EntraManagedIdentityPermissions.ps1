<#PSScriptInfo
.VERSION        2.0.0
.AUTHOR         @MrTbone_se (T-bone Granheden)
.GUID           feedbeef-beef-4dad-beef-22247f74f7ce
.COPYRIGHT      (c) 2026 T-bone Granheden. MIT License - free to use with attribution.
.TAGS           Intune Graph DeviceManagement MicrosoftGraph Entra Azure
.LICENSEURI     https://opensource.org/licenses/MIT
.PROJECTURI     https://github.com/Mr-Tbone/Intune
.RELEASENOTES
    1.0 2025-03-19 Initial Build
    2.0.0 2026-01-16 Major Archived old azuread module
#>

<#
.SYNOPSIS
    Script for Entra/Azure to add required Microsoft Graph API permissions to a Managed Identity

.DESCRIPTION
    This script connects to Entra ID with the Microsoft Graph module
    Then assign the listed Microsoft Graph API permissions to the specified Managed Identity.

.EXAMPLE
    .\Set-EntraManagedIdentityPermissions.ps1
    Will set the required Microsoft Graph API permissions on the specified Managed Identity that is specified in the script parameters defaults.

.EXAMPLE
    .\Set-EntraManagedIdentityPermissions.ps1 -tenantID "your-tenant-id" -ManagedIdentity "Your-Managed-Identity-Name" -Permissions @("User.Read.All", "DeviceManagementManagedDevices.Read.All")
    Will set the specified Microsoft Graph API permissions on the specified Managed Identity.

.EXAMPLE
    .\Set-EntraManagedIdentityPermissions.ps1 -WhatIf
    Shows what permissions would be assigned without making any changes.

.NOTES
    Please feel free to use this, but make sure to credit @MrTbone_se as the original author

.LINK
    https://tbone.se
#>

#region ---------------------------------------------------[Set Script Requirements]-----------------------------------------------
#Requires -Modules Microsoft.Graph.Authentication
#Requires -Modules Microsoft.Graph.Applications
#Requires -Version 5.1
#endregion

#region ---------------------------------------------------[Modifiable Parameters and Defaults]------------------------------------
# Customizations
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false,          HelpMessage = "The Tenant ID for the Azure AD tenant.")]
    [string]$TenantID           = "11111-08a2-4ade-9a68-0db7586d80ad",
    [Parameter(Mandatory = $false,          HelpMessage = "The name of the Managed Identity to assign permissions to.")]
    [string]$ManagedIdentity    = "T-BoneAutomation",
    [Parameter(Mandatory = $false,          HelpMessage = "Array of Microsoft Graph API permissions to assign to the Managed Identity.")]
    [string[]]$Permissions      = @("DeviceManagementManagedDevices.Read.All", "DeviceManagementManagedDevices.ReadWrite.All", "AuditLog.Read.All", "User.Read.All")
)
#endregion

#region ---------------------------------------------------[Static Variables]------------------------------------------------------
    $GraphAppId = "00000003-0000-0000-c000-000000000000"                            # Ms Graph App ID Don't change this.
    $AdminPermissions = @("Application.Read.All","AppRoleAssignment.ReadWrite.All") # Required to set permissions on Managed Identity
#endregion

#region ---------------------------------------------------[Import Modules and Extensions]-----------------------------------------
    import-module Microsoft.Graph.Authentication
    import-module Microsoft.Graph.Applications
#endregion

#region ---------------------------------------------------[Functions]------------------------------------------------------------
#endregion

#region ---------------------------------------------------[[Script Execution]------------------------------------------------------
try {
    # Connect to Microsoft Graph
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph -TenantId $TenantId -Scopes $AdminPermissions -NoWelcome -ErrorAction Stop
    Write-Host "Successfully connected to Microsoft Graph" -ForegroundColor Green

    # Get the Managed Identity Service Principal
    Write-Host "Looking up Managed Identity: $ManagedIdentity..." -ForegroundColor Cyan
    $IdentityServicePrincipal = Get-MgServicePrincipal -Filter "DisplayName eq '$ManagedIdentity'" -ErrorAction Stop
    if (-not $IdentityServicePrincipal) {
        throw "Managed Identity '$ManagedIdentity' not found in tenant"
    }
    Write-Host "Found Managed Identity with Id: $($IdentityServicePrincipal.Id)" -ForegroundColor Green

    # Get the Microsoft Graph Service Principal
    Write-Host "Looking up Microsoft Graph Service Principal..." -ForegroundColor Cyan
    $GraphServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'" -ErrorAction Stop
    if (-not $GraphServicePrincipal) {
        throw "Microsoft Graph Service Principal not found (AppId: $GraphAppId)"
    }

    # Get requested App Roles
    $AppRoles = $GraphServicePrincipal.AppRoles | Where-Object { $_.Value -in $Permissions -and $_.AllowedMemberTypes -contains "Application" }
    if (-not $AppRoles -or $AppRoles.Count -eq 0) {
        throw "No matching App Roles found for permissions: $($Permissions -join ', ')"
    }
    
    # Validate all requested permissions were found
    $foundPermissions = $AppRoles.Value
    $missingPermissions = $Permissions | Where-Object { $_ -notin $foundPermissions }
    if ($missingPermissions) {
        Write-Warning "The following permissions were not found: $($missingPermissions -join ', ')"
    }

    Write-Host "Found $($AppRoles.Count) App Role(s) to assign" -ForegroundColor Cyan
    
    # Show WhatIf mode indicator
    if ($WhatIfPreference) {
        Write-Host "`n[WhatIf Mode] The following permissions would be assigned:" -ForegroundColor Magenta
    }

    # Assign each App Role
    $successCount = 0
    $skipCount = 0
    $errorCount = 0
    $whatIfCount = 0

    foreach ($AppRole in $AppRoles) {
        try {
            if ($PSCmdlet.ShouldProcess("$ManagedIdentity", "Assign permission '$($AppRole.Value)'")) {
                $AppRoleAssignment = @{
                    "PrincipalId" = $IdentityServicePrincipal.Id
                    "ResourceId"  = $GraphServicePrincipal.Id
                    "AppRoleId"   = $AppRole.Id
                }
                New-MgServicePrincipalAppRoleAssignment `
                    -ServicePrincipalId $AppRoleAssignment.PrincipalId `
                    -BodyParameter $AppRoleAssignment `
                    -ErrorAction Stop | Out-Null
                
                Write-Host "  [OK] Assigned: $($AppRole.Value)" -ForegroundColor Green
                $successCount++
            }
            else {
                # WhatIf mode - count what would be done
                $whatIfCount++
            }
        }
        catch {
            # Check if permission already exists (common error)
            if ($_.Exception.Message -match "Permission being assigned already exists") {
                Write-Host "  [SKIP] Already assigned: $($AppRole.Value)" -ForegroundColor Yellow
                $skipCount++
            }
            else {
                Write-Host "  [ERROR] Failed to assign: $($AppRole.Value) - $($_.Exception.Message)" -ForegroundColor Red
                $errorCount++
            }
        }
    }

    # Summary
    Write-Host "`n========== Summary ==========" -ForegroundColor Cyan
    Write-Host "Managed Identity: $ManagedIdentity" -ForegroundColor White
    if ($WhatIfPreference) {
        Write-Host "[WhatIf] Would assign: $whatIfCount permission(s)" -ForegroundColor Magenta
    }
    else {
        Write-Host "Permissions assigned: $successCount" -ForegroundColor Green
    }
    Write-Host "Already existed (skipped): $skipCount" -ForegroundColor Yellow
    if ($errorCount -gt 0) {
        Write-Host "Errors: $errorCount" -ForegroundColor Red
    }
    Write-Host "=============================" -ForegroundColor Cyan
}
catch {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Script execution failed. Please check the error above and try again." -ForegroundColor Red
    
    # Re-throw if running in a pipeline or if strict mode
    if ($ErrorActionPreference -eq 'Stop') {
        throw
    }
}
finally {
    # Always disconnect from Microsoft Graph
    if (Get-MgContext -ErrorAction SilentlyContinue) {
        Write-Host "`nDisconnecting from Microsoft Graph..." -ForegroundColor Cyan
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Write-Host "Disconnected" -ForegroundColor Green
    }
}
#endregion



























# Test change


# Test change



