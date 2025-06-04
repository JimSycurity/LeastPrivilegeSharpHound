$AllACEs = $true

$ValueKeyPairs = [ordered]@{
    # SharpHound
    StrongCertificateBindingEnforcement = 'SYSTEM\CurrentControlSet\Services\Kdc'
    CertificateMappingMethods           = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
    ClientAllowedNTLMServers            = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    NtlmMinClientSec                    = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    NtlmMinServerSec                    = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    RestrictReceivingNTLMTraffic        = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    RestrictSendingNTLMTraffic          = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    LMCompatibilityLevel                = 'SYSTEM\CurrentControlSet\Control\Lsa'
    UseMachineId                        = 'SYSTEM\CurrentControlSet\Control\Lsa'
    EnableSecuritySignature             = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    RequireSecuritySignature            = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    # Network access: Remotely accessible registry paths
    ProductSuite                        = 'System\CurrentControlSet\Control\ProductOptions' # Control Subkey
    # ProductName = 'Software\Microsoft\Windows NT\CurrentVersion'
    # Network access: Remotely accessible registry paths and subpaths
    DefaultSpoolDirectory               = 'System\CurrentControlSet\Control\Print\Printers' # Control Subkey
    # RequiredPrivileges = 'System\CurrentControlSet\Services\Eventlog'
    # DoNotInstallCompatibleDriverFromWindowsUpdate = 'Software\Microsoft\Windows NT\CurrentVersion\Print'
    # Spooler = 'Software\Microsoft\Windows NT\CurrentVersion\Windows'
}

$SubKeyPath = ''

<#
## SDDL Access Masks:
    # Generic Mappings
    GA  = GenericAll    = 0x10000000
    GR  = GenericRead   = 	0x80000000
    GW  = GenericWrite  = 0x40000000
    GX  = GenericExecute  = 0x20000000
    # Standard Access Rights
    RC  = ReadControl    = 0x20000
    SD  = Delete    = 0x10000
    WD  = WriteDACL  = 0x40000
    WO  = WriteOwner  = 0x80000
    SY  = Synchronize
    AS  = AccessSystemSecurity
    # Registry Access Rights
    KA  = KeyAllAccess = 0xF003F
    KR  = KeyRead = 0x20019
    KW  = KeyWrite = 	0x20006
    KX  = KeyExecute = 0x20019
    KL  = KeyCreateLink
    K64 = KeyWow64_64Key
    K32 = KeyWow64_32Key
    KR  = KeyWow64_Res
    K?  = KeyCreateSubKeys = 0x0004
    KE  = KeyEnumerateSubKeys = 	0x0008
    KN  = KeyNotify = 0x0010
    KS  = KeySetValue = 0x0002
    KQ  = KeyQueryValue = 0x001

## SDDL Trustees:
   AC = All applications running in an app package context
   AO = Account Operators
   RU = Pre-Win2k - Flag
   AN = Anonymous Login -Flag
   AU = Authenticated Users -Flag
   BA = Builtin Administrators
   BG = Builtin Guests
   BO = Backup Operators
   BU = Builtin Users - Flag
   CO = Creator Owner
   DA = Domain Admins
   DU = Domain Users - Flag
   WD = Everyone - Flag
   SY = System
   SO = Server Operators
   UD = Users - Flag
   SU = Service
   LU = Local Users -Flag
   NU = Network Users -Flag
#>

$FlaggedRights = 'GA|GR|KA|KR'
$FlaggedTrustees = 'RU|AN|AU|BU|DU|WD|UD|LU|NU'
$SDDLRegex = '\(([A|D|OA|OD|AU|AL|OU|OL]+);([A-Z]*);(GA|GR|KA|KR);([a-zA-Z-0-9-]*);([a-zA-Z0-9-]*);(RU|AN|AU|BU|DU|WD|UD|LU|NU)\)'


foreach ($value in $ValueKeyPairs.Keys) {
    $RegSD = $null
    $RegSDDL = $null
    $state = $null
    $MatchedACEs = $null
    $ParsedACEs = $null

    $SubKeyPath = $ValueKeyPairs["$value"]

    Write-Host "`r`n-----------------------------------"

    try {
        $RegSD = Get-Acl -Path "Registry::HKEY_LOCAL_MACHINE\$($SubKeyPath)"
        $RegSDDL = $RegSD.Sddl
    }
    catch {
        $state = 'ReadControl Error'
    }
    $fullpath = 'HKLM\' + $SubKeyPath + '\' + $value
    $MatchedACEs = Select-String -InputObject $RegSDDL -Pattern $SDDLRegex -AllMatches
    if ($MatchedACEs) {
        $ParsedACEs = $MatchedACEs.Matches.Value -join ''
        Write-Host "Path: $fullpath - Standard User SubKey ACEs: $ParsedACEs"
        if ($AllACEs) {
            Write-Host "Full SDDL: $RegSDDL"
        }
    }
    elseif ($state) {
        Write-Host "Path: $fullpath - $state" -ForegroundColor Red
    }
    else {
        Write-Host "Path: $fullpath - Standard Users have no access" -ForegroundColor DarkYellow
    }
    Write-Host "-----------------------------------"
}
