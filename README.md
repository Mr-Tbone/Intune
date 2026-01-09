# Intune
Collection of my Intunescripts

## Set-IntunePrimaryUsers.ps1

### Description
This script gets Entra Sign-in logs for Windows and application sign-ins,
determines the most frequent user in the last 30 days, and sets them as Primary User.
Uses Microsoft Graph and requires only the Microsoft.Graph.Authentication module.

### Release Notes
- 1.0.2202.1 - Initial Version
- 2.0.2312.1 - Large update to use Graph batching and reduce runtime
- 3.0.2407.1 - Added support for Group filtering
- 3.0.2407.2 - Added a verification of required permissions
- 4.0.2503.1 - Added new functions and new structure for the script
- 5.0.2504.1 - Changed all requests to use invoke-mggraphrequets
- 5.0.2504.2 - Bug fixing and error and throttling handling
- 5.1.2504.3 - Changed sorting and selecting from the sign-in logs and overall performance improvements
- 6.0.2510.1 - A complete rewrite of the processes due to changes in Microsoft Graph, now 10x faster and more reliable
- 6.0.2510.2 - Added T-Bone logging function throughout the script to better track execution and errors
- 6.0.2510.3 - Improved logic and performance of the user sign-in data processing
- 6.0.2510.4 - Added a fallback for windows devices with no Windows sign-in logs, to use application sign-in logs instead
- 6.0.2510.5 - New parameters for keep and replace accounts
- 6.0.2511.1 - New parameters for Intune only or both Intune and Co-managed
- 6.1.2511.2 - Bug fixes with DeviceTimeSpan and changed the name of the script to Set-IntunePrimaryUsers.ps1
- 6.1.2512.1 - Added Certificate based auth and app based auth support in Invoke-ConnectMgGraph function
- 6.2 2512.1 - Added versions on functions to keep track of changes, aslo worked through declarations, comments and fixed minor bugs
- 6.1.1 2025-12-22 Fixed a better connect with parameter check
- 7.0.0 2025-12-23 Major update to allign all primary user scripts. Many small changes to improve performance and reliability.
- 7.0.1 2026-01-07 Fixed missing variable
- 7.0.2 2026-01-09 Fixed header to comply with best practice
