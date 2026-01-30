# Collecions of @MrTbone_se Intune Remedation scripts

## [Detect-SecureBoot.ps1](<Detect-SecureBoot.ps1>)
Script for Intune remediation to detect if Secure Boot is enabled

### Description
The script detects if Secure Boot is enabled on the device and also collects diagnostic info on the device.
Returns Compliant (exit 0) if enabled, Non-Compliant (exit 1) if disabled or not supported.
The compact function invoke-TboneTinyLog is used to capture logs and return them to Intune and disk for troubleshooting.
## [Remediation-SecureBootCert.ps1](<Remediation-SecureBootCert.ps1>)
Script for Intune Remediation to both detect and remediate if Secure Boot Certificate is old and need to be updated to Secure Boot CA 2023

### Description
The script detects and remediates regkeys and other settings required for Secure Boot CA 2023 certificate to be deployed.
The script is both for detect and remediate and can self detect if running as detect or remediate based the Intune assigned scriptname
The script invoke logging in the start and send the logs to Intune after it is done. It will also save a log on disk for troubleshooting.
## [Remediation-MapDrivesCloudNative.ps1](<Remediation-MapDrivesCloudNative.ps1>)
This script will map drives and printers for cloud native devices
It can be used as both script and remediation script in Intune.
I prefer to use it as a remediation script to be able to update with new versions.

### Description
This script maps network drives or printers for cloud-native (Entra ID joined) Windows devices.
When run as SYSTEM (via Intune), it creates a scheduled task that runs as the logged-in user.
The scheduled task executes on logon and network connection events to map drives/printers.
Group memberships are queried via LDAP to determine which mappings apply to the user.

## [Remediation-MapPrintersCloudNative.ps1](<Remediation-MapPrintersCloudNative.ps1>)
This script will map drives and printers for cloud native devices
It can be used as both script and remediation script in Intune.
I prefer to use it as a remediation script to be able to update with new versions.

### Description
This script maps network drives or printers for cloud-native (Entra ID joined) Windows devices.
When run as SYSTEM (via Intune), it creates a scheduled task that runs as the logged-in user.
The scheduled task executes on logon and network connection events to map drives/printers.
Group memberships are queried via LDAP to determine which mappings apply to the user.






