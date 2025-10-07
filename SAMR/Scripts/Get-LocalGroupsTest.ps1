# https://github.com/SpecterOps/SharpHoundCommon/blob/1ec7cbaee444f4a2cf6e257042c8591e4ae831e2/src/CommonLib/Processors/LocalGroupProcessor.cs
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ComputerName
)

$csharpCorePath = Join-Path $PSScriptRoot 'SamrInterop.Core.cs'
$csharpEnumeratorPath = Join-Path $PSScriptRoot 'SamrInterop.Enumerator.cs'

if (-not (Test-Path $csharpCorePath) -or -not (Test-Path $csharpEnumeratorPath)) {
    throw "Required SamrInterop source files not found."
}

$csharp = (Get-Content -Path $csharpCorePath -Raw) + [Environment]::NewLine + (Get-Content -Path $csharpEnumeratorPath -Raw)

$existingType = [System.Management.Automation.PSTypeName]'SamrInterop.SamrLocalGroupEnumerator'
if (-not $existingType.Type) {
    Add-Type -Language CSharp -TypeDefinition $csharp -ErrorAction Stop
}

$normalizedComputer = $ComputerName
if (-not [string]::IsNullOrWhiteSpace($normalizedComputer)) {
    $normalizedComputer = $normalizedComputer.Trim()
    if ($normalizedComputer.StartsWith('\\')) {
        $normalizedComputer = $normalizedComputer.TrimStart('\\')
    }
    if ($normalizedComputer -eq '.' -or $normalizedComputer -eq 'localhost') {
        $normalizedComputer = $env:COMPUTERNAME
    }
}

try {
    $groups = [SamrInterop.SamrLocalGroupEnumerator]::Enumerate($normalizedComputer)

    $groupObjects = @(
        foreach ($group in $groups) {
            $memberObjects = @(
                foreach ($member in $group.Members) {
                    [PSCustomObject]@{
                        Sid = $member.Sid
                        Account = if ($member.FullName) { $member.FullName } else { $member.Sid }
                        AccountName = $member.AccountName
                        AccountDomain = $member.AccountDomain
                        AccountType = $member.AccountType
                        Attributes = $member.Attributes
                    }
                }
            )

            [PSCustomObject]@{
                ComputerName = $group.ComputerName
                DomainName = $group.DomainName
                GroupName = $group.GroupName
                GroupSid = $group.GroupSid
                RelativeId = $group.RelativeId
                MembersEnumerated = $group.MembersEnumerated
                Error = $group.Error
                MemberCount = $memberObjects.Count
                Members = $memberObjects
            }
        }
    )

    [PSCustomObject]@{
        ComputerName = $normalizedComputer
        Success = $true
        RetrievedAt = Get-Date
        GroupCount = $groupObjects.Count
        Groups = $groupObjects
    }
}
catch {
    $ex = $_.Exception
    $errorMessage = if ($ex) { $ex.Message } else { $_.ToString() }
    $ntStatus = $null
    if ($ex -and $ex.Data.Contains('NtStatus')) {
        $ntStatus = $ex.Data['NtStatus']
    }

    [PSCustomObject]@{
        ComputerName = $normalizedComputer
        Success = $false
        RetrievedAt = Get-Date
        ErrorMessage = $errorMessage
        NtStatus = $ntStatus
        FullyQualifiedErrorId = $_.FullyQualifiedErrorId
    }
}
