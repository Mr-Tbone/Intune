# Intune
Collection of my Intunescripts

## Set-IntunePrimaryUsers.ps1
Script for Intune to set Primary User on Device

### Description
This script gets Entra Sign-in logs for Windows and application sign-ins,
determines the most frequent user in the last 30 days, and sets them as Primary User.
Uses Microsoft Graph and requires only the Microsoft.Graph.Authentication module.

## Add-IntuneDeviceToGroupBasedOnPrimaryUser.ps1
Script for Intune to add device to a group based on primary user

### Description
This script will get the All devices in Intune and their primary users.
The script then use a given attribute from the primary user (like Country, City) to add the device to a group based on that value
The script uses Ms Graph and only requires the Microsoft.Graph.Authentication module

## Add-IntuneScopeTagsBasedOnPrimaryUser.ps1
Script for Intune to set Scope Tags on Device based on Primary Users and their attributes

### Description
This script will get all devices and their current primary user and current scope tags
Get all users and the significant attribute for scope tagging
It will then set scope tags based on that attribute
The script uses Ms Graph and only requires the Microsoft.Graph.Authentication module
