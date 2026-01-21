# Collection of Mr T-Bone´s Intune scripts

## [Set-IntunePrimaryUsers.ps1](Set-IntunePrimaryUsers.ps1)
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
