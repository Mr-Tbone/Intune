# Detect if Windows Optional Feature is enabled.
$featureName = "VirtualMachinePlatform" 
if((Get-WindowsOptionalFeature -Online -FeatureName $featureName).State -eq "Enabled")
{
    Write-host "Windows Optional Feature $featureName is enabled" 
    Exit 0
}
else
{
    Write-host "Windows Optional Feature $featureName is not enabled"
    Exit 1
}