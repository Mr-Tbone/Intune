# Collecions of @MrTbone_se Intune Remedation scripts

## Detect-SecureBoot.ps1
Script for Intune remediation to detect if Secure Boot is enabled

### Description
The script detects if Secure Boot is enabled on the device and also collects diagnostic info on the device.
Returns Compliant (exit 0) if enabled, Non-Compliant (exit 1) if disabled or not supported.
The compact function invoke-TboneTinyLog is used to capture logs and return them to Intune and disk for troubleshooting.
