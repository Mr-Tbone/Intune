# Collection of Mr T-Bone´s Intune scripts

## [Set-IntunePrimaryUsers.ps1](<Set-IntunePrimaryUsers.ps1>)
Script for Intune to set Primary User on Device

### Description
This script gets Entra Sign-in logs for Windows and application sign-ins,
determines the most frequent user in the last 30 days, and sets them as Primary User.
Uses Microsoft Graph and requires only the Microsoft.Graph.Authentication module.
## [Add-IntuneDeviceToGroupBasedOnPrimaryUser.ps1](<Add-IntuneDeviceToGroupBasedOnPrimaryUser.ps1>)
Script for Intune to add device to a group based on primary user

### Description
This script will get the All devices in Intune and their primary users.
The script then use a given attribute from the primary user (like Country, City) to add the device to a group based on that value
The script uses Ms Graph and only requires the Microsoft.Graph.Authentication module
## [Add-IntuneScopeTagsBasedOnPrimaryUser.ps1](<Add-IntuneScopeTagsBasedOnPrimaryUser.ps1>)
Script for Intune to set Scope Tags on Device based on Primary Users and their attributes

### Description
This script will get all devices and their current primary user and current scope tags
Get all users and the significant attribute for scope tagging
It will then set scope tags based on that attribute
The script uses Ms Graph and only requires the Microsoft.Graph.Authentication module
## [Set-EntraManagedIdentityPermissions.ps1](Set-EntraManagedIdentityPermissions.ps1)
Script for Entra/Azure to add required Microsoft Graph API permissions to a Managed Identity

### Description
This script connects to Entra ID with the Microsoft Graph module
Then assign the listed Microsoft Graph API permissions to the specified Managed Identity.

## Intune - Drive Mapping.ps1 ([Remediation-MapDrivesCloudNative.ps1](<Remedations/Remediation-MapDrivesCloudNative.ps1>))
> [!IMPORTANT]
> Renamed to [Remediation-MapDrivesCloudNative.ps1](<Remedations/Remediation-MapDrivesCloudNative.ps1>) and moved to Remedations folder

This script will map drives and printers for cloud native devices
It can be used as both script and remediation script in Intune.
I prefer to use it as a remediation script to be able to update with new versions.

### Description
This script maps network drives or printers for cloud-native (Entra ID joined) Windows devices.
When run as SYSTEM (via Intune), it creates a scheduled task that runs as the logged-in user.
The scheduled task executes on logon and network connection events to map drives/printers.
Group memberships are queried via LDAP to determine which mappings apply to the user.

## Intune - Printer Mapping.ps1 ([Remediation-MapPrintersCloudNative.ps1](<Remedations/Remediation-MapPrintersCloudNative.ps1>))
> [!IMPORTANT]
> Renamed to [Remediation-MapPrintersCloudNative.ps1](<Remedations/Remediation-MapPrintersCloudNative.ps1>) and moved to Remedations folder

This script will map drives and printers for cloud native devices
It can be used as both script and remediation script in Intune.
I prefer to use it as a remediation script to be able to update with new versions.

### Description
This script maps network drives or printers for cloud-native (Entra ID joined) Windows devices.
When run as SYSTEM (via Intune), it creates a scheduled task that runs as the logged-in user.
The scheduled task executes on logon and network connection events to map drives/printers.
Group memberships are queried via LDAP to determine which mappings apply to the user.

## [Intune-Wrapper-ToAddRemovePrograms.ps1](<Intune-Wrapper-ToAddRemovePrograms.ps1>)
Script for Intune to build an app that show in Add/Remove Programs from a PowerShell Script

### Description
This script will act as a wrapper for PowerShell script.
It will copy the script and icon to program files and add the necessary registry keys to show up in Add/Remove Programs.
The PowerShell based app can be installed, uninstalled and reinstalled from Add/Remove Programs and also show the app version and icon.

## [Wrap-PSScriptToAddRemovePrograms.ps1](<Wrap-PSScriptToAddRemovePrograms.ps1>)
Script for Intune to build an app that show in Add/Remove Programs from a PowerShell Script

### Description
This script will act as a wrapper for PowerShell script.
It will copy the script and icon to program files and add the necessary registry keys to show up in Add/Remove Programs.
The PowerShell based app can be installed, uninstalled and reinstalled from Add/Remove Programs and also show the app version and icon.

## [Map-DrivesCloudNative.ps1](<Map-DrivesCloudNative.ps1>)
Maps Intune-managed cloud-native drives or printers by scheduled task, manual run, or remediation workflow.

### Description
This script deploys and runs a drive-mapping or printer-mapping solution for Entra ID joined / cloud-native Windows devices.
It supports Intune Win32 app install, Intune remediation, elevated manual install/repair, normal user manual execution, and uninstall.

During install or remediation, the script stages itself into the application folder, registers a hidden scheduled task that runs in user context,
writes a launcher script, stores a version marker, and optionally registers the solution in Add/Remove Programs with icon, shortcuts,
uninstall support, and modify/reinstall support.

During user execution, the script can either trigger the deployed scheduled-task worker with a one-shot GUI override or run the mapping logic directly.
Mapping applicability is determined from configured AD group names collected through LDAP after a DC Locator check. If no domain controller is reachable,
the script aborts mapping instead of continuing with incomplete group data. Optional stale drive or printer cleanup is also supported.
## [Map-PrintersCloudNative.Ps1](<Map-PrintersCloudNative.Ps1>)
Maps Intune-managed cloud-native drives or printers by scheduled task, manual run, or remediation workflow.

### Description
This script deploys and runs a drive-mapping or printer-mapping solution for Entra ID joined / cloud-native Windows devices.
It supports Intune Win32 app install, Intune remediation, elevated manual install/repair, normal user manual execution, and uninstall.

During install or remediation, the script stages itself into the application folder, registers a hidden scheduled task that runs in user context,
writes a launcher script, stores a version marker, and optionally registers the solution in Add/Remove Programs with icon, shortcuts,
uninstall support, and modify/reinstall support.

During user execution, the script can either trigger the deployed scheduled-task worker with a one-shot GUI override or run the mapping logic directly.
Mapping applicability is determined from configured AD group names collected through LDAP after a DC Locator check. If no domain controller is reachable,
the script aborts mapping instead of continuing with incomplete group data. Optional stale drive or printer cleanup is also supported.

