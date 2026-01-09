# Collecions of @MrTbone_se Intune Remedation scripts

## [Detect-SecureBoot.ps1](Detect-SecureBoot.ps1)
Script for Intune remediation to detect if Secure Boot is enabled

### Description
The script detects if Secure Boot is enabled on the device and also collects diagnostic info on the device.
Returns Compliant (exit 0) if enabled, Non-Compliant (exit 1) if disabled or not supported.
The compact function invoke-TboneTinyLog is used to capture logs and return them to Intune and disk for troubleshooting.

## [Remediation-SecureBootCert.ps1](Remediation-SecureBootCert.ps1)
Script for Intune Remediation to both detect and remediate if Secure Boot Certificate is old and need to be updated to Secure Boot CA 2023

### Description
The script detects and remediates regkeys and other settings required for Secure Boot CA 2023 certificate to be deployed.
The script is both for detect and remediate and can self detect if running as detect or remediate based the Intune assigned scriptname
The script invoke logging in the start and send the logs to Intune after it is done. It will also save a log on disk for troubleshooting.
