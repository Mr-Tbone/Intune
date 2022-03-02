# Remediate and Enable Windows Optional Feature.

$featureName = "VirtualMachinePlatform" 

Try
{
    if((Get-WindowsOptionalFeature -Online -FeatureName $featureName).State -ne "Enabled")
        {
        Try{Enable-WindowsOptionalFeature -Online -FeatureName $featureName -All -NoRestart
            write-host "$featureName successfully enabled"}
        catch{Write-host "$featureName failed to enable: $error"}
       }
    else {Write-host "$featureName already enabled"}  
}
Catch
    {
        Write-host "$error"
    }