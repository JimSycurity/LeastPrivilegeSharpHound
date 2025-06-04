<######
# There are 2 basic methods for remote registry access via PowerShell or .NET:
# 1. [Microsoft.Win32.RegistryKey]
# 2. WMI StdRegProv
#
# SharpHound uses Win32.RegistryKey class, which is what this will replicate
# WMI StdRegProv can be utilized something like this:
    $user = "Domain\Username"
    $pass = ConvertTo-SecureString "Password" -AsPlainText -Force
    $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user,$pass

    $reg = Get-WmiObject -List -Namespace root\default -ComputerName $server -Credential $cred | Where-Object {$_.Name -eq "StdRegProv"}
    $HKLM = 2147483650
    $value = $reg.GetStringValue($HKLM,"Software\Microsoft\.NetFramework","InstallRoot").sValue
#
#######>

$Computer = 'TellerDC01'
$Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $Computer)

$ValueKeyPairs = [ordered]@{
    # SharpHound
    StrongCertificateBindingEnforcement           = 'SYSTEM\CurrentControlSet\Services\Kdc'
    CertificateMappingMethods                     = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
    ClientAllowedNTLMServers                      = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    NtlmMinClientSec                              = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    NtlmMinServerSec                              = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    RestrictReceivingNTLMTraffic                  = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    RestrictSendingNTLMTraffic                    = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    LMCompatibilityLevel                          = 'SYSTEM\CurrentControlSet\Control\Lsa'
    UseMachineId                                  = 'SYSTEM\CurrentControlSet\Control\Lsa'
    EnableSecuritySignature                       = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    RequireSecuritySignature                      = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    # Network access: Remotely accessible registry paths
    ProductSuite                                  = 'System\CurrentControlSet\Control\ProductOptions'
    ProductName                                   = 'Software\Microsoft\Windows NT\CurrentVersion'
    # Network access: Remotely accessible registry paths and subpaths
    DefaultSpoolDirectory                         = 'System\CurrentControlSet\Control\Print\Printers'
    RequiredPrivileges                            = 'System\CurrentControlSet\Services\Eventlog'
    DoNotInstallCompatibleDriverFromWindowsUpdate = 'Software\Microsoft\Windows NT\CurrentVersion\Print'
    Spooler                                       = 'Software\Microsoft\Windows NT\CurrentVersion\Windows'
}

$SubKeyPath = ''

foreach ($value in $ValueKeyPairs.Keys) {
    $RegSubKey = $null
    $state = $null
    $regval = $null

    $SubKeyPath = $ValueKeyPairs["$value"]

    Write-Host "`r`n-----------------------------------"

    try {
        $RegSubKey = $Reg.OpenSubKey($SubKeyPath)
    }
    catch {
        #Write-Warning "Error on $value OpenSubKey" $Error[0]
        $state = 'OpenSubKey Error'
    }
    try {
        $regval = $RegSubKey.GetValue($value)
    }
    catch {
        #Write-Warning "Error on $value GetValue" $Error[0]
        $state = 'GetValue Error'
    }
    $fullpath = 'HKLM\' + $SubKeyPath + '\' + $value

    if ($null -ne $regval) {
        Write-Host "Path: $fullpath  Data: $regval"
    }
    else {
        Write-Host "Path: $fullpath - $state" -ForegroundColor DarkYellow
    }
    Write-Host "-----------------------------------"
}
