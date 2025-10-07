<#
.SYNOPSIS
    Tests LSA User Rights Assignment enumeration locally or remotely.

.DESCRIPTION
    Uses P/Invoke to call LSA APIs (LsaOpenPolicy and LsaEnumerateAccountsWithUserRight)
    to test whether the current user has sufficient privileges to enumerate User Rights
    Assignments. Designed to test SharpHound Enterprise's least-privilege capabilities.

.PARAMETER ComputerName
    Target computer name (NetBIOS or FQDN). Defaults to local computer.

.PARAMETER UseNetBIOS
    Force using NetBIOS name format instead of attempting FQDN resolution.

.PARAMETER Console
    Display colorful console output instead of returning objects. Use for interactive testing.

.EXAMPLE
    .\Test-LSAEnum.ps1
    Tests enumeration on the local system and returns a PowerShell object.

.EXAMPLE
    .\Test-LSAEnum.ps1 -Console
    Tests enumeration on the local system with colorful console output.

.EXAMPLE
    $result = .\Test-LSAEnum.ps1 -ComputerName DC01
    $result | Format-List
    $result.Rights | Where-Object {$_.Status -eq "Success"} | Format-Table
    Tests enumeration on remote computer DC01 and stores result for analysis.

.EXAMPLE
    .\Test-LSAEnum.ps1 -ComputerName DC01 -Console
    Tests enumeration on remote computer DC01 with console output.

.EXAMPLE
    $computers = @("DC01", "WS01", "WS02")
    $results = $computers | ForEach-Object { .\Test-LSAEnum.ps1 -ComputerName $_ }
    $results | Export-Csv -Path "LSA_Enum_Results.csv" -NoTypeInformation
    Run enumeration against multiple computers and export results.

.EXAMPLE
    .\Test-LSAEnum.ps1 -ComputerName 192.168.1.10 -UseNetBIOS -Console
    Tests enumeration on remote computer using IP/NetBIOS format with console output.

.NOTES
    Author: Security Research Team
    Requires: Network access and appropriate permissions for remote enumeration
    Emulates: https://github.com/SpecterOps/SharpHoundCommon/blob/1ec7cbaee444f4a2cf6e257042c8591e4ae831e2/src/CommonLib/Processors/UserRightsAssignmentProcessor.cs
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerName = $env:COMPUTERNAME,

    [Parameter(Mandatory=$false)]
    [switch]$UseNetBIOS,

    [Parameter(Mandatory=$false)]
    [switch]$Console,

    [Parameter(Mandatory=$false)]
    [switch]$EnableAuditPrivilege,

    [Parameter(Mandatory=$false)]
    [switch]$EnableServiceLogonRight
)

#region P/Invoke Definitions

$LsaDefinitions = @"
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace LSAUtil
{
    public enum LSA_AccessPolicy : long
    {
        POLICY_VIEW_LOCAL_INFORMATION = 0x00000001L,
        POLICY_VIEW_AUDIT_INFORMATION = 0x00000002L,
        POLICY_GET_PRIVATE_INFORMATION = 0x00000004L,
        POLICY_TRUST_ADMIN = 0x00000008L,
        POLICY_CREATE_ACCOUNT = 0x00000010L,
        POLICY_CREATE_SECRET = 0x00000020L,
        POLICY_CREATE_PRIVILEGE = 0x00000040L,
        POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080L,
        POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100L,
        POLICY_AUDIT_LOG_ADMIN = 0x00000200L,
        POLICY_SERVER_ADMIN = 0x00000400L,
        POLICY_LOOKUP_NAMES = 0x00000800L,
        POLICY_NOTIFICATION = 0x00001000L
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_UNICODE_STRING
    {
        public UInt16 Length;
        public UInt16 MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_ENUMERATION_INFORMATION
    {
        public IntPtr Sid;
    }

    public class NativeMethods
    {
        [DllImport("advapi32.dll", PreserveSig = true)]
        public static extern UInt32 LsaOpenPolicy(
            ref LSA_UNICODE_STRING SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            Int32 DesiredAccess,
            out IntPtr PolicyHandle
        );

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        public static extern uint LsaEnumerateAccountsWithUserRight(
            IntPtr PolicyHandle,
            ref LSA_UNICODE_STRING UserRight,
            out IntPtr Buffer,
            out int CountReturned
        );

        [DllImport("advapi32.dll")]
        public static extern int LsaNtStatusToWinError(uint Status);

        [DllImport("advapi32.dll")]
        public static extern uint LsaClose(IntPtr ObjectHandle);

        [DllImport("advapi32.dll")]
        public static extern uint LsaFreeMemory(IntPtr Buffer);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint LsaAddAccountRights(
            IntPtr PolicyHandle,
            IntPtr AccountSid,
            LSA_UNICODE_STRING[] UserRights,
            int CountOfRights
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool LookupAccountSid(
            string lpSystemName,
            IntPtr Sid,
            StringBuilder lpName,
            ref uint cchName,
            StringBuilder ReferencedDomainName,
            ref uint cchReferencedDomainName,
            out int peUse
        );
    }
}
"@

# Only add the type if it hasn't been added already
if (-not ([System.Management.Automation.PSTypeName]'LSAUtil.NativeMethods').Type) {
    Add-Type -TypeDefinition $LsaDefinitions
}

#endregion

#region Helper Functions

function Initialize-LsaString {
    param([string]$String)

    $lsaString = New-Object LSAUtil.LSA_UNICODE_STRING
    if ($String) {
        $lsaString.Buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($String)
        $lsaString.Length = [UInt16]($String.Length * 2)
        $lsaString.MaximumLength = [UInt16](($String.Length * 2) + 2)
    }
    else {
        $lsaString.Buffer = [IntPtr]::Zero
        $lsaString.Length = 0
        $lsaString.MaximumLength = 0
    }
    return $lsaString
}

function ConvertFrom-Sid {
    param(
        [IntPtr]$SidPtr,
        [string]$SystemName = $null
    )

    $nameBuilder = New-Object System.Text.StringBuilder 256
    $domainBuilder = New-Object System.Text.StringBuilder 256
    [uint32]$nameSize = 256
    [uint32]$domainSize = 256
    [int]$sidType = 0

    $result = [LSAUtil.NativeMethods]::LookupAccountSid(
        $SystemName,
        $SidPtr,
        $nameBuilder,
        [ref]$nameSize,
        $domainBuilder,
        [ref]$domainSize,
        [ref]$sidType
    )

    if ($result) {
        $domain = $domainBuilder.ToString()
        $name = $nameBuilder.ToString()
        if ($domain) {
            return "$domain\$name"
        }
        return $name
    }

    # If lookup fails, convert SID to string
    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($SidPtr)
        return $sid.Value
    }
    catch {
        return "Unknown SID"
    }
}

function New-SidPointer {
    param(
        [string]$SidString
    )

    $sid = New-Object System.Security.Principal.SecurityIdentifier($SidString)
    $bytes = New-Object byte[] ($sid.BinaryLength)
    $sid.GetBinaryForm($bytes, 0)

    $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length)
    [System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $ptr, $bytes.Length)

    return [PSCustomObject]@{
        Pointer = $ptr
        Length  = $bytes.Length
    }
}

function Grant-LsaAccountRight {
    param(
        [IntPtr]$PolicyHandle,
        [string]$SidString,
        [string[]]$Rights,
        [switch]$Console
    )

    $granted = New-Object System.Collections.Generic.List[string]
    $errors = New-Object System.Collections.ArrayList
    $sidInfo = $null

    try {
        $sidInfo = New-SidPointer -SidString $SidString
    }
    catch {
        $errorMsg = "Unable to convert SID $SidString to binary form: $($_.Exception.Message)"
        [void]$errors.Add([PSCustomObject]@{
            Right = $null
            Message = $errorMsg
        })
        if ($Console) {
            Write-Host "[!] $errorMsg" -ForegroundColor Red
        }
        return [PSCustomObject]@{
            Granted = $granted
            Errors  = $errors
        }
    }

    try {
        foreach ($right in $Rights) {
            $lsaString = Initialize-LsaString -String $right
            try {
                $status = [LSAUtil.NativeMethods]::LsaAddAccountRights(
                    $PolicyHandle,
                    $sidInfo.Pointer,
                    [LSAUtil.LSA_UNICODE_STRING[]]@($lsaString),
                    1
                )

                if ($status -eq 0) {
                    $granted.Add($right) | Out-Null
                    if ($Console) {
                        Write-Host "[+] Granted $right to SID $SidString" -ForegroundColor Green
                    }
                }
                else {
                    $winError = [LSAUtil.NativeMethods]::LsaNtStatusToWinError($status)
                    $message = "Failed to grant $right (NTSTATUS 0x$($status.ToString('X8')), Win32 $winError)"
                    [void]$errors.Add([PSCustomObject]@{
                        Right = $right
                        Message = $message
                    })
                    if ($Console) {
                        Write-Host "[!] $message" -ForegroundColor Red
                    }
                }
            }
            finally {
                if ($lsaString.Buffer -ne [IntPtr]::Zero) {
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($lsaString.Buffer)
                }
            }
        }
    }
    finally {
        if ($sidInfo -and $sidInfo.Pointer -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($sidInfo.Pointer)
        }
    }

    return [PSCustomObject]@{
        Granted = $granted
        Errors  = $errors
    }
}

#endregion

#region Main Script

$targetSystem = if ($ComputerName -eq $env:COMPUTERNAME) { "Local System" } else { $ComputerName }

# Initialize results object with ArrayLists for proper collection management
$rightsList = New-Object System.Collections.ArrayList
$errorsList = New-Object System.Collections.ArrayList
$grantsList = New-Object System.Collections.ArrayList

$results = [PSCustomObject]@{
    ComputerName = $ComputerName
    TargetSystem = $targetSystem
    UserContext = "$env:USERDOMAIN\$env:USERNAME"
    LSAPolicyOpened = $false
    SystemName = $null
    Rights = $rightsList
    SuccessCount = 0
    FailureCount = 0
    Errors = $errorsList
    PrivilegeGrants = $grantsList
    CanEnumerateUserRights = $false
}

if ($Console) {
    Write-Host "[*] LSA User Rights Assignment Enumeration Test" -ForegroundColor Cyan
    Write-Host "[*] Testing with current user context: $($results.UserContext)" -ForegroundColor Cyan
    Write-Host "[*] Target System: $targetSystem" -ForegroundColor Cyan
    Write-Host ""
}

# Test remote connectivity if not local
if ($ComputerName -ne $env:COMPUTERNAME) {
    if ($Console) {
        Write-Host "[*] Testing connectivity to remote system..." -ForegroundColor Yellow
    }

    if (-not (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
        if ($Console) {
            Write-Host "[!] Unable to ping $ComputerName - continuing anyway as some systems block ICMP" -ForegroundColor Yellow
        }
    }
    else {
        if ($Console) {
            Write-Host "[+] Remote system is reachable" -ForegroundColor Green
        }
    }

    if ($Console) {
        Write-Host ""
    }
}

# Initialize LSA_OBJECT_ATTRIBUTES
$objectAttributes = New-Object LSAUtil.LSA_OBJECT_ATTRIBUTES
$objectAttributes.Length = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][LSAUtil.LSA_OBJECT_ATTRIBUTES])
$objectAttributes.RootDirectory = [IntPtr]::Zero
$objectAttributes.ObjectName = [IntPtr]::Zero
$objectAttributes.Attributes = 0
$objectAttributes.SecurityDescriptor = [IntPtr]::Zero
$objectAttributes.SecurityQualityOfService = [IntPtr]::Zero

# Initialize system name
# Format: \\COMPUTERNAME for remote systems, null for local
$systemNameString = if ($ComputerName -eq $env:COMPUTERNAME) {
    $null
}
elseif ($UseNetBIOS.IsPresent) {
    "\\$ComputerName"
}
else {
    # Try to resolve FQDN if not using NetBIOS
    try {
        $fqdn = [System.Net.Dns]::GetHostEntry($ComputerName).HostName
        "\\$fqdn"
    }
    catch {
        if ($Console) {
            Write-Host "[!] Could not resolve FQDN, using NetBIOS name" -ForegroundColor Yellow
        }
        "\\$ComputerName"
    }
}

$results.SystemName = if ($systemNameString) { $systemNameString } else { "(Local System)" }

if ($Console) {
    Write-Host "[*] LSA System Name: $($results.SystemName)" -ForegroundColor Gray
    Write-Host "[*] Attempting to open LSA Policy with POLICY_LOOKUP_NAMES and POLICY_VIEW_LOCAL_INFORMATION..." -ForegroundColor Yellow
}

$systemName = Initialize-LsaString -String $systemNameString

# Open LSA Policy with minimal required access
$desiredAccess = [int][LSAUtil.LSA_AccessPolicy]::POLICY_LOOKUP_NAMES -bor [int][LSAUtil.LSA_AccessPolicy]::POLICY_VIEW_LOCAL_INFORMATION
if ($EnableAuditPrivilege -or $EnableServiceLogonRight) {
    $desiredAccess = $desiredAccess -bor [int][LSAUtil.LSA_AccessPolicy]::POLICY_CREATE_ACCOUNT
}
$policyHandle = [IntPtr]::Zero

$result = [LSAUtil.NativeMethods]::LsaOpenPolicy(
    [ref]$systemName,
    [ref]$objectAttributes,
    $desiredAccess,
    [ref]$policyHandle
)

if ($result -ne 0) {
    $winError = [LSAUtil.NativeMethods]::LsaNtStatusToWinError($result)
    $errorMsg = "LsaOpenPolicy failed with status: 0x$($result.ToString('X8')), Win32 Error: $winError"
    [void]$results.Errors.Add($errorMsg)

    if ($Console) {
        Write-Host "[!] $errorMsg" -ForegroundColor Red

        if ($ComputerName -ne $env:COMPUTERNAME) {
            Write-Host "[!] Common remote access issues:" -ForegroundColor Yellow
            Write-Host "    - Firewall blocking RPC (TCP 135 + dynamic ports)" -ForegroundColor Yellow
            Write-Host "    - Insufficient permissions on remote system" -ForegroundColor Yellow
            Write-Host "    - Network connectivity issues" -ForegroundColor Yellow
            Write-Host "    - Remote system not reachable via specified name" -ForegroundColor Yellow
        }
    }

    # Cleanup
    if ($systemName.Buffer -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($systemName.Buffer)
    }

    return $results
}

$results.LSAPolicyOpened = $true

if ($Console) {
    Write-Host "[+] Successfully opened LSA Policy handle: 0x$($policyHandle.ToString('X'))" -ForegroundColor Green
    Write-Host ""
}

if ($EnableAuditPrivilege -or $EnableServiceLogonRight) {
    if ($Console) {
        Write-Host "[*] Privilege enablement requested. Attempting to grant rights to current user..." -ForegroundColor Yellow
    }

    try {
        $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    }
    catch {
        $sidError = "Unable to determine current user SID: $($_.Exception.Message)"
        [void]$results.Errors.Add($sidError)
        if ($Console) {
            Write-Host "[!] $sidError" -ForegroundColor Red
        }
        $currentSid = $null
    }

    if ($null -ne $currentSid) {
        $requestedRights = @()
        if ($EnableAuditPrivilege) {
            $requestedRights += "SeAuditPrivilege"
        }
        if ($EnableServiceLogonRight) {
            $requestedRights += "SeServiceLogonRight"
        }

        $grantOutcome = Grant-LsaAccountRight -PolicyHandle $policyHandle -SidString $currentSid -Rights $requestedRights -Console:$Console

        foreach ($grantedRight in $grantOutcome.Granted) {
            [void]$grantsList.Add([PSCustomObject]@{
                Right = $grantedRight
                Status = "Granted"
                Message = "Granted to $($results.UserContext)"
            })
        }

        foreach ($grantError in $grantOutcome.Errors) {
            [void]$grantsList.Add([PSCustomObject]@{
                Right = $grantError.Right
                Status = "Error"
                Message = $grantError.Message
            })
            [void]$results.Errors.Add($grantError.Message)
        }

        if ($Console) {
            Write-Host ""  # spacer
        }
    }
}

# Common user rights to enumerate
$userRights = @(
    "SeNetworkLogonRight",
    "SeInteractiveLogonRight",
    "SeBatchLogonRight",
    "SeServiceLogonRight",
    "SeDenyNetworkLogonRight",
    "SeDenyInteractiveLogonRight",
    "SeDenyBatchLogonRight",
    "SeDenyServiceLogonRight",
    "SeRemoteInteractiveLogonRight",
    "SeTcbPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeDebugPrivilege",
    "SeImpersonatePrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeLoadDriverPrivilege",
    "SeSystemtimePrivilege",
    "SeShutdownPrivilege",
    "SeTakeOwnershipPrivilege"
)

foreach ($right in $userRights) {
    if ($Console) {
        Write-Host "[*] Enumerating accounts with right: $right" -ForegroundColor Yellow
    }

    $accountsList = New-Object System.Collections.ArrayList

    $rightResult = [PSCustomObject]@{
        Right = $right
        Status = $null
        StatusCode = $null
        AccountCount = 0
        Accounts = $accountsList
        ErrorMessage = $null
    }

    $userRight = Initialize-LsaString -String $right
    $buffer = [IntPtr]::Zero
    [int]$count = 0

    $enumResult = [LSAUtil.NativeMethods]::LsaEnumerateAccountsWithUserRight(
        $policyHandle,
        [ref]$userRight,
        [ref]$buffer,
        [ref]$count
    )

    # Free the user right string buffer
    if ($userRight.Buffer -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($userRight.Buffer)
    }

    if ($enumResult -eq 0) {
        $results.SuccessCount++
        $rightResult.Status = "Success"
        $rightResult.StatusCode = "0x$($enumResult.ToString('X8'))"
        $rightResult.AccountCount = $count

        if ($Console) {
            Write-Host "[+] Success! Found $count account(s)" -ForegroundColor Green
        }

        if ($count -gt 0) {
            $current = $buffer
            $structSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][LSAUtil.LSA_ENUMERATION_INFORMATION])

            for ($i = 0; $i -lt $count; $i++) {
                $enumInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($current, [Type][LSAUtil.LSA_ENUMERATION_INFORMATION])
                $accountName = ConvertFrom-Sid -SidPtr $enumInfo.Sid -SystemName $ComputerName
                [void]$accountsList.Add($accountName)

                if ($Console) {
                    Write-Host "    - $accountName" -ForegroundColor Gray
                }

                $current = [IntPtr]::Add($current, $structSize)
            }

            [void][LSAUtil.NativeMethods]::LsaFreeMemory($buffer)
        }
    }
    elseif ($enumResult -eq 0xC0000034) {
        # STATUS_OBJECT_NAME_NOT_FOUND - No accounts have this right
        $results.SuccessCount++
        $rightResult.Status = "NoAccountsAssigned"
        $rightResult.StatusCode = "0x$($enumResult.ToString('X8'))"

        if ($Console) {
            Write-Host "    (No accounts assigned this right)" -ForegroundColor Gray
        }
    }
    elseif ($enumResult -eq 0xC0000022) {
        # STATUS_ACCESS_DENIED
        $results.FailureCount++
        $rightResult.Status = "AccessDenied"
        $rightResult.StatusCode = "0x$($enumResult.ToString('X8'))"
        $rightResult.ErrorMessage = "Access Denied - insufficient privileges"

        if ($Console) {
            Write-Host "[!] Access Denied - insufficient privileges" -ForegroundColor Red
        }
    }
    else {
        $results.FailureCount++
        $winError = [LSAUtil.NativeMethods]::LsaNtStatusToWinError($enumResult)
        $rightResult.Status = "Failed"
        $rightResult.StatusCode = "0x$($enumResult.ToString('X8'))"
        $rightResult.ErrorMessage = "Win32 Error: $winError"

        if ($Console) {
            Write-Host "[!] Failed with status: 0x$($enumResult.ToString('X8')) (Win32: $winError)" -ForegroundColor Red
        }
    }

    [void]$results.Rights.Add($rightResult)

    if ($Console) {
        Write-Host ""
    }
}

# Close LSA Policy handle
[void][LSAUtil.NativeMethods]::LsaClose($policyHandle)

# Free system name buffer if allocated
if ($systemName.Buffer -ne [IntPtr]::Zero) {
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($systemName.Buffer)
}

# Set overall result
$results.CanEnumerateUserRights = ($results.FailureCount -le 6 -and $results.SuccessCount -gt 0)

if ($Console) {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "[*] Enumeration Complete" -ForegroundColor Cyan
    Write-Host "[*] Successful enumerations: $($results.SuccessCount)" -ForegroundColor Green
    Write-Host "[*] Failed enumerations: $($results.FailureCount)" -ForegroundColor $(if ($results.FailureCount -gt 0) { "Red" } else { "Green" })
    Write-Host "========================================" -ForegroundColor Cyan

    if ($results.CanEnumerateUserRights) {
        Write-Host "`n[+] Result: Current user has sufficient privileges to enumerate User Rights Assignments!" -ForegroundColor Green
        if ($ComputerName -ne $env:COMPUTERNAME) {
            Write-Host "[+] Remote enumeration successful - SharpHound Enterprise should work across the network." -ForegroundColor Green
        }
        else {
            Write-Host "[+] SharpHound Enterprise should be able to use least-privilege access." -ForegroundColor Green
        }
    }
    elseif ($results.FailureCount -gt 0) {
        Write-Host "`n[!] Result: Some enumerations failed due to access denial." -ForegroundColor Yellow
        Write-Host "[!] Current user may not have sufficient privileges for all User Rights." -ForegroundColor Yellow
        if ($ComputerName -ne $env:COMPUTERNAME) {
            Write-Host "[!] For remote enumeration, ensure:" -ForegroundColor Yellow
            Write-Host "    - Network connectivity to target system" -ForegroundColor Yellow
            Write-Host "    - RPC/DCOM ports accessible (typically TCP 135, dynamic ports)" -ForegroundColor Yellow
            Write-Host "    - User has appropriate permissions on remote system" -ForegroundColor Yellow
            Write-Host "    - Windows Firewall allows remote LSA access" -ForegroundColor Yellow
        }
    }
}

# Return results object
return $results

#endregion
