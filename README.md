# Intune
Collection of my Intunescripts

## Set-IntunePrimaryUsers.ps1
Script for Intune to set Primary User on Device

### Description
This script gets Entra Sign-in logs for Windows and application sign-ins,
determines the most frequent user in the last 30 days, and sets them as Primary User.
Uses Microsoft Graph and requires only the Microsoft.Graph.Authentication module.
