<#
.SYNOPSIS
Creates tiered least-privilege SharpHound Enterprise collectors for Active Directory environments.

.DESCRIPTION
This script provisions Group Managed Service Accounts (gMSAs), supporting security groups, and Group Policy
artifacts that enable SharpHound Enterprise data collection with least-privilege permissions. It supports
three operational tiers that align with privileged access workstation models:
- Tier 0 targets domain controllers and other Tier 0 assets.
- Tier 1 targets server-class assets.
- Tier 2 targets workstation and end-user assets.

By default all three tiers are created using opinionated naming (T0/T1/T2). Users can scope execution to a
single tier and customise gMSA names, collectors, and OU targets. The script keeps track of created objects so
that they can be rolled back within the same session or via the companion rollback script.

.PARAMETER Tier
Specifies which tier or tiers to process. Accepts T0, T1, T2, or All. Defaults to All (process every tier).

.PARAMETER Action
Indicates whether to create or roll back tier artefacts. Defaults to Create. Use Rollback to remove
resources created by this script.

.PARAMETER ServiceAccountOUDN
Distinguished Name of the OU that stores the shared tier service accounts and security groups. Optional
per-tier overrides are available (Tier0ServiceAccountOUDN, Tier1ServiceAccountOUDN, Tier2ServiceAccountOUDN).
When omitted, security groups are created in the default Users container and gMSAs in the domain's
Managed Service Accounts container for the root domain.

.PARAMETER Tier0ServiceAccountOUDN
Optional Distinguished Name override for Tier 0 service account and group placement. Falls back to
ServiceAccountOUDN when not provided.

.PARAMETER Tier1ServiceAccountOUDN
Optional Distinguished Name override for Tier 1 service account and group placement. Falls back to
ServiceAccountOUDN when not provided.

.PARAMETER Tier2ServiceAccountOUDN
Optional Distinguished Name override for Tier 2 service account and group placement. Falls back to
ServiceAccountOUDN when not provided.

.PARAMETER Tier0AssetOUs
Collection of Distinguished Names representing Tier 0 computer OUs. When provided the Tier 0 GPO is
linked automatically; otherwise the link must be performed manually.

.PARAMETER Tier1AssetOUs
Collection of Distinguished Names representing Tier 1 computer OUs. When provided the Tier 1 GPO is
linked automatically; otherwise the link must be performed manually.

.PARAMETER Tier2AssetOUs
Collection of Distinguished Names representing Tier 2 computer OUs. When provided the Tier 2 GPO is
linked automatically; otherwise the link must be performed manually.

.PARAMETER Tier0Collector
SamAccountName (without domain suffix) of the Tier 0 SharpHound collector computer object. Defaults to
T0SharpHoundCollector.

.PARAMETER Tier1Collector
SamAccountName (without domain suffix) of the Tier 1 SharpHound collector computer object. Defaults to
T1SharpHoundCollector.

.PARAMETER Tier2Collector
SamAccountName (without domain suffix) of the Tier 2 SharpHound collector computer object. Defaults to
T2SharpHoundCollector.

.PARAMETER Tier0GMSAName
Name of the Tier 0 gMSA. Defaults to T0_gMSA_SHS.

.PARAMETER Tier1GMSAName
Name of the Tier 1 gMSA. Defaults to T1_gMSA_SHS.

.PARAMETER Tier2GMSAName
Name of the Tier 2 gMSA. Defaults to T2_gMSA_SHS.

.PARAMETER EnableRegistryRollback
When enabled, registry Group Policy Preferences are deployed using Replace mode with removePolicy and
bypassErrors so that unlinking the GPO removes the settings automatically.

.PARAMETER EnableDeletedObjectsAccess
Enables creation of the Tier 0 Deleted Objects Read delegation group and associated permissions. Disabled
by default; enable only after validating the security posture.

.PARAMETER RollbackOnError
Automatically roll back any newly created artefacts if provisioning fails.

.EXAMPLE
.\Create-TieredLeastPrivilegeSharpHound.ps1 -ServiceAccountOUDN "OU=ServiceAccounts,DC=contoso,DC=com" \
    -Tier0AssetOUs "OU=Tier0,DC=contoso,DC=com" -Tier1AssetOUs "OU=Servers,DC=contoso,DC=com" \
    -Tier2AssetOUs "OU=Workstations,DC=contoso,DC=com"

.EXAMPLE
.\Create-TieredLeastPrivilegeSharpHound.ps1 -Tier T1 -Action Rollback -ServiceAccountOUDN \
    "OU=ServiceAccounts,DC=contoso,DC=com"

.NOTES
Author: Jim Sykora
Contributor: Codex (GPT-5)
Version: 1.0.0
Requires: PowerShell 5.1+, ActiveDirectory module, GroupPolicy module, domain admin rights.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $false)]
    [ValidateSet('T0', 'T1', 'T2', 'All')]
    [string[]]$Tier = 'All',

    [Parameter(Mandatory = $false)]
    [ValidateSet('Create', 'Rollback')]
    [string]$Action = 'Create',

    [Parameter(Mandatory = $false)]
    [string]$ServiceAccountOUDN = $null,

    [Parameter(Mandatory = $false)]
    [string]$Tier0ServiceAccountOUDN,

    [Parameter(Mandatory = $false)]
    [string]$Tier1ServiceAccountOUDN,

    [Parameter(Mandatory = $false)]
    [string]$Tier2ServiceAccountOUDN,

    [Parameter(Mandatory = $false)]
    [string[]]$Tier0AssetOUs,

    [Parameter(Mandatory = $false)]
    [string[]]$Tier1AssetOUs,

    [Parameter(Mandatory = $false)]
    [string[]]$Tier2AssetOUs,

    [Parameter(Mandatory = $false)]
    [string]$Tier0Collector = 'T0SharpHoundCollector',

    [Parameter(Mandatory = $false)]
    [string]$Tier1Collector = 'T1SharpHoundCollector',

    [Parameter(Mandatory = $false)]
    [string]$Tier2Collector = 'T2SharpHoundCollector',

    [Parameter(Mandatory = $false)]
    [string]$Tier0GMSAName = 'T0_gMSA_SHS',

    [Parameter(Mandatory = $false)]
    [string]$Tier1GMSAName = 'T1_gMSA_SHS',

    [Parameter(Mandatory = $false)]
    [string]$Tier2GMSAName = 'T2_gMSA_SHS',

    [Parameter(Mandatory = $false)]
    [switch]$EnableRegistryRollback = $false,

    [Parameter(Mandatory = $false)]
    [switch]$EnableDeletedObjectsAccess = $false,

    [Parameter(Mandatory = $false)]
    [switch]$RollbackOnError = $false
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:GmsaUpnMap = @{}
$script:ProvisionState = New-Object System.Collections.Generic.List[psobject]

#region Helper Functions

function Write-ScriptLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $color = switch ($Level) {
        'Info' { 'White' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
        'Success' { 'Green' }
    }

    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Resolve-GmsaName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $Name
    }

    $normalized = $Name.Trim("'`"")

    if ($normalized -like '*@*') {
        $parts = $normalized.Split('@', 2, [System.StringSplitOptions]::RemoveEmptyEntries)
        if ($parts.Length -ge 1) {
            $normalized = $parts[0].Trim()
        }
    }

    if ($normalized -like '*\\*') {
        $netbiosParts = $normalized.Split('\\', 2, [System.StringSplitOptions]::RemoveEmptyEntries)
        if ($netbiosParts.Length -ge 2) {
            $normalized = $netbiosParts[1].Trim()
        }
        elseif ($netbiosParts.Length -eq 1) {
            $normalized = $netbiosParts[0].Trim()
        }
    }

    return $normalized.Trim().TrimEnd('$')
}

function Get-TierScopedName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string]$BaseName,
        [Parameter(Mandatory = $true)][string]$Tier
    )

    $trimmedBase = if ([string]::IsNullOrWhiteSpace($BaseName)) { '' } else { $BaseName.Trim() }
    $normalizedTier = if ([string]::IsNullOrWhiteSpace($Tier)) { '' } else { $Tier.Trim() }

    if ($normalizedTier -match '^Tier\s*([0-9]+)$') {
        $normalizedTier = 'T{0}' -f $Matches[1]
    }

    if (-not [string]::IsNullOrWhiteSpace($normalizedTier)) {
        $normalizedTier = $normalizedTier.ToUpperInvariant()
    }

    if ([string]::IsNullOrWhiteSpace($trimmedBase)) {
        return $normalizedTier
    }

    if ([string]::IsNullOrWhiteSpace($normalizedTier)) {
        return $trimmedBase
    }

    return ('{0}_{1}' -f $trimmedBase, $normalizedTier)
}

$script:GmsaNormalization = New-Object System.Collections.Generic.List[psobject]
foreach ($gmsaTier in @(
        @{ TierKey = 'T0'; Variable = 'Tier0GMSAName' },
        @{ TierKey = 'T1'; Variable = 'Tier1GMSAName' },
        @{ TierKey = 'T2'; Variable = 'Tier2GMSAName' }
    )) {
    $originalValue = Get-Variable -Name $gmsaTier.Variable -ValueOnly
    $trimmedInput = if ([string]::IsNullOrWhiteSpace($originalValue)) { '' } else { $originalValue.Trim("'`"") }
    $candidateUpn = $null
    $normalizedInput = $trimmedInput

    if ($normalizedInput -like '*@*') {
        $parts = $normalizedInput.Split('@', 2, [System.StringSplitOptions]::RemoveEmptyEntries)
        if ($parts.Length -ge 1) {
            $normalizedInput = $parts[0].Trim()
        }
        if ($parts.Length -ge 2) {
            $domainPart = $parts[1].Trim()
            if (-not [string]::IsNullOrWhiteSpace($domainPart) -and -not [string]::IsNullOrWhiteSpace($normalizedInput)) {
                $candidateUpn = ('{0}@{1}' -f $normalizedInput.TrimEnd('$'), $domainPart)
            }
        }
    }

    if ($normalizedInput -like '*\\*') {
        $netbiosParts = $normalizedInput.Split('\\', 2, [System.StringSplitOptions]::RemoveEmptyEntries)
        if ($netbiosParts.Length -ge 2) {
            $normalizedInput = $netbiosParts[1].Trim()
        }
        elseif ($netbiosParts.Length -eq 1) {
            $normalizedInput = $netbiosParts[0].Trim()
        }
    }

    $normalizedValue = Resolve-GmsaName -Name $normalizedInput

    if ([string]::IsNullOrWhiteSpace($normalizedValue)) {
        throw ([System.String]::Format('Resolved {0} gMSA name is empty after normalization.', $gmsaTier.TierKey))
    }

    Set-Variable -Name $gmsaTier.Variable -Value $normalizedValue -Scope Script
    $script:GmsaUpnMap[$gmsaTier.TierKey] = $candidateUpn

    if ($originalValue -ne $normalizedValue) {
        $entry = [pscustomobject]@{
            Tier = $gmsaTier.TierKey
            Original = $originalValue
            Normalized = $normalizedValue
        }
        [void]$script:GmsaNormalization.Add($entry)
    }
}

function Register-ProvisionResult {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Tier,

        [Parameter(Mandatory = $true)]
        [string]$Type,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [hashtable]$Metadata
    )

    $entry = [pscustomobject]@{
        Tier = $Tier
        Type = $Type
        Name = $Name
        Metadata = $Metadata
    }
    [void]$script:ProvisionState.Add($entry)
}

function Test-Prerequisites {
    [CmdletBinding()]
    param()

    Write-ScriptLog "Validating prerequisites..." -Level Info

    $requiredModules = @('ActiveDirectory', 'GroupPolicy')
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            throw "Required PowerShell module '$module' is not available. Install RSAT tools before continuing."
        }
        Import-Module $module -Force
        Write-ScriptLog "Imported module: $module" -Level Success
    }

    $domainMode = (Get-ADDomain).DomainMode
    if ($domainMode -notmatch '2012|2016|2019|2022|2025') {
        Write-ScriptLog "Warning: Domain functional level '$domainMode' may not support gMSAs." -Level Warning
    } else {
        Write-ScriptLog "Domain functional level '$domainMode' supports gMSAs." -Level Success
    }
}

function Get-DomainContextForDN {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string]$DistinguishedName
    )

    $dcComponents = ($DistinguishedName -split ',') | Where-Object { $_ -like 'DC=*' }
    if (-not $dcComponents) {
        throw "Unable to determine domain components from distinguished name '$DistinguishedName'."
    }

    $fqdn = ($dcComponents -replace 'DC=', '') -join '.'
    $domain = Get-ADDomain -Identity $fqdn -ErrorAction Stop
    return [pscustomobject]@{
        Domain = $domain
        Server = $domain.PDCEmulator
        Fqdn = $domain.DNSRoot
    }
}

function Resolve-ServiceAccountPaths {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)][string]$RequestedPath,
        [Parameter(Mandatory = $true)][Microsoft.ActiveDirectory.Management.ADDomain]$RootDomain,
        [Parameter(Mandatory = $true)][string]$Tier,
        [Parameter(Mandatory = $false)][switch]$AllowMissing
    )

    if ($RequestedPath) {
        $domainContext = Get-DomainContextForDN -DistinguishedName $RequestedPath

        try {
            Get-ADObject -Identity $RequestedPath -Server $domainContext.Server -ErrorAction Stop | Out-Null
            Write-ScriptLog ("Validated service account container '{0}' for tier {1}." -f $RequestedPath, $Tier) -Level Success
        }
        catch {
            if ($AllowMissing) {
                Write-ScriptLog ("Service account container '{0}' for tier {1} could not be resolved; continuing due to AllowMissingOUs." -f $RequestedPath, $Tier) -Level Warning
            }
            else {
                throw ("Service account container '{0}' for tier {1} does not exist or is unreachable." -f $RequestedPath, $Tier)
            }
        }

        return [pscustomobject]@{
            GroupPath = $RequestedPath
            GmsaPath = $RequestedPath
            Domain = $domainContext.Domain
            Server = $domainContext.Server
        }
    }

    $groupPath = "CN=Users,$($RootDomain.DistinguishedName)"
    $gmsaPath = $RootDomain.ManagedServiceAccountsContainer

    if ([string]::IsNullOrWhiteSpace($gmsaPath)) {
        $gmsaPath = "CN=Managed Service Accounts,$($RootDomain.DistinguishedName)"
    }

    try {
        Get-ADObject -Identity $gmsaPath -Server $RootDomain.PDCEmulator -ErrorAction Stop | Out-Null
        Write-ScriptLog ("Resolved default gMSA container '{0}' for tier {1}." -f $gmsaPath, $Tier) -Level Info
    }
    catch {
        if ($AllowMissing) {
            Write-ScriptLog ("Default gMSA container '{0}' for tier {1} not found; continuing due to AllowMissingOUs." -f $gmsaPath, $Tier) -Level Warning
        }
        else {
            throw ("Default Managed Service Accounts container '{0}' for tier {1} was not found. Specify ServiceAccountOUDN or create the container." -f $gmsaPath, $Tier)
        }
    }

    Write-ScriptLog ("Service account container not provided for tier {0}; using defaults (Groups: {1}, gMSA: {2})." -f $Tier, $groupPath, $gmsaPath) -Level Info

    return [pscustomobject]@{
        GroupPath = $groupPath
        GmsaPath = $gmsaPath
        Domain = $RootDomain
        Server = $RootDomain.PDCEmulator
    }
}

function Resolve-TargetTiers {
    [CmdletBinding()]
    param (
        [string[]]$RequestedTiers
    )

    if ($RequestedTiers -contains 'All' -or $RequestedTiers.Count -eq 0) {
        return @('T0', 'T1', 'T2')
    }

    return ($RequestedTiers | Select-Object -Unique)
}

function Get-TierDefinitions {
    [CmdletBinding()]
    param (
        [Microsoft.ActiveDirectory.Management.ADDomain]$RootDomain,
        [switch]$AllowMissingOUs = $false
    )

    $defaults = @{
        'T0' = [pscustomobject]@{
            Name = 'T0'
            GMSAName = $Tier0GMSAName
            GMSAUserPrincipalName = $script:GmsaUpnMap['T0']
            Collector = $Tier0Collector
            ServiceAccountOU = if ($Tier0ServiceAccountOUDN) { $Tier0ServiceAccountOUDN } else { $ServiceAccountOUDN }
            AssetOUs = $Tier0AssetOUs
            IncludeDomainControllers = $true
            IncludeDeletedObjects = [bool]$EnableDeletedObjectsAccess
            Description = 'Collects forest-wide AD structure and Tier 0 asset telemetry.'
        }
        'T1' = [pscustomobject]@{
            Name = 'T1'
            GMSAName = $Tier1GMSAName
            GMSAUserPrincipalName = $script:GmsaUpnMap['T1']
            Collector = $Tier1Collector
            ServiceAccountOU = if ($Tier1ServiceAccountOUDN) { $Tier1ServiceAccountOUDN } else { $ServiceAccountOUDN }
            AssetOUs = $Tier1AssetOUs
            IncludeDomainControllers = $false
            IncludeDeletedObjects = $false
            Description = 'Collects local groups, sessions, NTLM, and registry data on Tier 1 server assets.'
        }
        'T2' = [pscustomobject]@{
            Name = 'T2'
            GMSAName = $Tier2GMSAName
            GMSAUserPrincipalName = $script:GmsaUpnMap['T2']
            Collector = $Tier2Collector
            ServiceAccountOU = if ($Tier2ServiceAccountOUDN) { $Tier2ServiceAccountOUDN } else { $ServiceAccountOUDN }
            AssetOUs = $Tier2AssetOUs
            IncludeDomainControllers = $false
            IncludeDeletedObjects = $false
            Description = 'Collects local groups, sessions, NTLM, and registry data on Tier 2 workstation assets.'
        }
    }

    foreach ($tier in $defaults.Keys) {
        $requestedPath = $defaults[$tier].ServiceAccountOU
        $resolvedPaths = Resolve-ServiceAccountPaths -RequestedPath $requestedPath -RootDomain $RootDomain -Tier $tier -AllowMissing:$AllowMissingOUs

        $defaults[$tier] | Add-Member -MemberType NoteProperty -Name RequestedServiceAccountOU -Value $requestedPath -Force
        $defaults[$tier].ServiceAccountOU = $resolvedPaths.GroupPath
        $defaults[$tier] | Add-Member -MemberType NoteProperty -Name GmsaContainerPath -Value $resolvedPaths.GmsaPath -Force
        $defaults[$tier] | Add-Member -MemberType NoteProperty -Name ServiceDomain -Value $resolvedPaths.Domain -Force
        $defaults[$tier] | Add-Member -MemberType NoteProperty -Name ServiceServer -Value $resolvedPaths.Server -Force
    }

    return $defaults
}

function Ensure-CollectorComputer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Tier
    )

    try {
        $computer = Get-ADComputer -Identity $Name -ErrorAction Stop
        Write-ScriptLog "Validated collector computer '$Name' for tier $Tier." -Level Success
        return $computer
    }
    catch {
        throw "Collector computer '$Name' for tier $Tier was not found. Create the computer object before running this script."
    }
}

function Ensure-AdGroup {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)][string]$Tier,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Server
    )

    $created = $false
    if ($PSCmdlet.ShouldProcess($Name, 'Ensure security group')) {
        try {
            $group = New-ADGroup -Name $Name -GroupScope Universal -GroupCategory Security -Path $Path -Description $Description -Server $Server -PassThru -ErrorAction Stop
            $created = $true
            Write-ScriptLog "Created security group '$Name' for tier $Tier." -Level Success
        }
        catch {
            if ($_.Exception.Message -match 'already exists') {
                $group = Get-ADGroup -Identity $Name -Server $Server -ErrorAction Stop
                Write-ScriptLog "Security group '$Name' already exists; reusing for tier $Tier." -Level Warning
            }
            else {
                throw ("Failed to create security group '{0}' for tier {1}: {2}" -f $Name, $Tier, $_)
            }
        }

        if ($created) {
            Register-ProvisionResult -Tier $Tier -Type 'ADGroup' -Name $group.DistinguishedName -Metadata @{ Server = $Server }
        }
        return $group
    }
    else {
        Write-ScriptLog "[WhatIf] Would ensure security group '$Name' for tier $Tier." -Level Info
        return $null
    }
}

function Ensure-GMSA {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)][string]$Tier,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$PrincipalsAllowed,
        [Parameter(Mandatory = $true)][string]$Server,
        [Parameter(Mandatory = $false)][string]$UserPrincipalName
    )

    $created = $false
    $desiredUpn = if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) { $null } else { $UserPrincipalName.Trim() }
    if ($PSCmdlet.ShouldProcess($Name, 'Ensure gMSA')) {
        try {
            $targetServer = $Server
            $domain = $null

            if (-not [string]::IsNullOrWhiteSpace($Path)) {
                try {
                    $pathContext = Get-DomainContextForDN -DistinguishedName $Path
                    if ($pathContext) {
                        if ($pathContext.Server) { $targetServer = $pathContext.Server }
                        if ($pathContext.Domain) { $domain = $pathContext.Domain }
                    }
                }
                catch {
                    Write-ScriptLog ("Unable to resolve domain context from '{0}' for gMSA {1}: {2}" -f $Path, $Name, $_) -Level Warning
                }
            }

            if (-not $targetServer) {
                $targetServer = $Server
            }

            if (-not $domain) {
                $domain = Get-ADDomain -Server $targetServer
            }
            else {
                $domain = Get-ADDomain -Identity $domain.DNSRoot -Server $targetServer
            }

            $dnsHostName = "$Name.$($domain.DNSRoot)"
            $baseSam = if ([string]::IsNullOrWhiteSpace($Name)) { '' } else { $Name.TrimEnd('$') }
            if (-not $desiredUpn -and -not [string]::IsNullOrWhiteSpace($baseSam) -and $domain -and -not [string]::IsNullOrWhiteSpace($domain.DNSRoot)) {
                $desiredUpn = '{0}@{1}' -f $baseSam, $domain.DNSRoot
            }
            $gmsaParams = @{
                Name                            = $Name
                Description                     = "SharpHound tier $Tier service account"
                DNSHostname                     = $dnsHostName
                ManagedPasswordIntervalInDays   = 1 # Set to 1 for SHDelegatorServiceTesting
                PrincipalsAllowedToRetrieveManagedPassword  = $PrincipalsAllowed
                Enabled                         = $true
                AccountNotDelegated             = $true
                KerberosEncryptionType          = 'AES128,AES256'
                Path                            = $Path
                Server                          = $targetServer
            }
            if ($desiredUpn) {
                $gmsaParams['OtherAttributes'] = @{ userPrincipalName = $desiredUpn }
            }
            $gmsa = New-ADServiceAccount @gmsaParams -PassThru -ErrorAction Stop
            $created = $true
            Write-ScriptLog "Created gMSA '$Name' for tier $Tier." -Level Success
        }
        catch {
            $message = $_.Exception.Message
            if ($message -match 'already exists' -or $message -match 'not unique forest-wide') {
                $gmsa = Get-ADServiceAccount -Identity $Name -Server $targetServer -ErrorAction Stop
                if ($desiredUpn -and -not [string]::Equals($gmsa.userPrincipalName, $desiredUpn, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $setParams = @{ Identity = $gmsa.DistinguishedName; Replace = @{ userPrincipalName = $desiredUpn }; ErrorAction = 'Stop'; Server = $targetServer }
                    Set-ADServiceAccount @setParams
                    Write-ScriptLog "Updated gMSA userPrincipalName to $desiredUpn" -Level Info
                    $gmsa = Get-ADServiceAccount -Identity $Name -Server $targetServer -ErrorAction Stop
                }
                Write-ScriptLog "gMSA '$Name' already exists; reusing for tier $Tier." -Level Warning
            }
            else {
                throw ("Failed to create gMSA '{0}' for tier {1}: {2}" -f $Name, $Tier, $_)
            }
        }

        if ($created) {
            Register-ProvisionResult -Tier $Tier -Type 'GMSA' -Name $Name -Metadata @{ Server = $targetServer }
        }
        return $gmsa
    }
    else {
        Write-ScriptLog "[WhatIf] Would ensure gMSA '$Name' for tier $Tier." -Level Info
        return $null
    }
}

function Ensure-GPO {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)][string]$Tier,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Comment,
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)][string]$Server
    )

    $created = $false
    if ($PSCmdlet.ShouldProcess($Name, 'Ensure GPO')) {
        try {
            $gpo = New-GPO -Name $Name -Comment $Comment -Domain $Domain -Server $Server -ErrorAction Stop
            $created = $true
            Write-ScriptLog "Created GPO '$Name' in $Domain for tier $Tier." -Level Success
        }
        catch {
            if ($_.Exception.Message -match 'exists') {
                $gpo = Get-GPO -Name $Name -Domain $Domain -Server $Server -ErrorAction Stop
                Write-ScriptLog "GPO '$Name' already exists in $Domain; reusing for tier $Tier." -Level Warning
            }
            else {
                throw ("Failed to create or retrieve GPO '{0}' in {1} for tier {2}: {3}" -f $Name, $Domain, $Tier, $_)
            }
        }

        if ($created) {
            Register-ProvisionResult -Tier $Tier -Type 'GPO' -Name $gpo.Id -Metadata @{ Domain = $Domain }
        }
        return $gpo
    }
    else {
        Write-ScriptLog "[WhatIf] Would ensure GPO '$Name' in $Domain for tier $Tier." -Level Info
        return $null
    }
}

function Ensure-GPLink {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)][string]$Tier,
        [Parameter(Mandatory = $true)][Guid]$GpoId,
        [Parameter(Mandatory = $true)][string]$GpoName,
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)][string]$Server
    )

    if (-not $PSCmdlet.ShouldProcess($Target, "Link GPO $GpoName")) {
        Write-ScriptLog "[WhatIf] Would link GPO '$GpoName' to '$Target'." -Level Info
        return
    }

    $inheritance = Get-GPInheritance -Target $Target -Domain $Domain -Server $Server -ErrorAction SilentlyContinue
    $existing = $inheritance.GpoLinks | Where-Object { $_.GpoId -eq $GpoId }
    if ($existing) {
        Write-ScriptLog "GPO '$GpoName' already linked to '$Target'." -Level Warning
        return
    }

    New-GPLink -Guid $GpoId -Target $Target -LinkEnabled Yes -Domain $Domain -Server $Server -Order 1 | Out-Null
    Write-ScriptLog "Linked GPO '$GpoName' to '$Target'." -Level Success
    Register-ProvisionResult -Tier $Tier -Type 'GpoLink' -Name "$($GpoId)::${Target}" -Metadata @{ Domain = $Domain }
}

function Enable-RegistryRollback {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][Guid]$GpoId,
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][string]$ValueName,
        [Parameter(Mandatory = $true)][string]$Domain
    )

    $registryXmlPath = "\\$Domain\SYSVOL\$Domain\Policies\{$GpoId}\Machine\Preferences\Registry\Registry.xml"
    if (-not (Test-Path $registryXmlPath)) {
        Write-ScriptLog "Registry.xml not found for GPO {$GpoId}; rollback metadata cannot be updated." -Level Warning
        return
    }

    $xml = [xml](Get-Content -Path $registryXmlPath)
    $keyWithoutHive = $Key -replace '^HKL[MU]\\', '' -replace '^HKEY_LOCAL_MACHINE\\', '' -replace '^HKEY_CURRENT_USER\\', ''
    $node = $xml.RegistrySettings.Registry | Where-Object { $_.Properties.key -eq $keyWithoutHive -and $_.Properties.name -eq $ValueName } | Select-Object -First 1

    if (-not $node) {
        Write-ScriptLog "Registry preference entry $Key\\$ValueName not found in GPO {$GpoId}." -Level Warning
        return
    }

    $node.SetAttribute('image', '6')
    $node.SetAttribute('removePolicy', '1')
    $node.SetAttribute('bypassErrors', '1')
    $xml.Save($registryXmlPath)
    Write-ScriptLog "Enabled rollback metadata for $Key\\$ValueName in GPO {$GpoId}." -Level Success
}

function Set-GPPRegistryValue {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)][Guid]$GpoId,
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][string]$ValueName,
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][ValidateSet('String', 'MultiString', 'DWord', 'QWord')][string]$Type,
        [Parameter(Mandatory = $true)][int]$Order,
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)][string]$Server
    )

    if (-not $PSCmdlet.ShouldProcess($Key, "Set registry preference $ValueName")) {
        Write-ScriptLog "[WhatIf] Would set registry value $Key\\$ValueName" -Level Info
        return
    }

    $action = if ($EnableRegistryRollback) { 'Replace' } else { 'Update' }
    Set-GPPrefRegistryValue -Guid $GpoId -Context Computer -Key $Key -ValueName $ValueName -Value $Value -Type $Type -Order $Order -Action $action -Domain $Domain -Server $Server
    Write-ScriptLog "Configured registry preference $Key\\$ValueName via $action for GPO {$GpoId}." -Level Success

    if ($EnableRegistryRollback) {
        Enable-RegistryRollback -GpoId $GpoId -Key $Key -ValueName $ValueName -Domain $Domain
    }
}

function Set-GPOLocalGroupMembership {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)][Guid]$GpoId,
        [Parameter(Mandatory = $true)][string]$GpoName,
        [Parameter(Mandatory = $true)]$Domain,
        [Parameter(Mandatory = $true)][string]$Server,
        [Parameter(Mandatory = $true)][string]$LocalGroup,
        [Parameter(Mandatory = $true)][string[]]$Members
    )

    if (-not $PSCmdlet.ShouldProcess($LocalGroup, "Configure local group membership via $GpoName")) {
        Write-ScriptLog "[WhatIf] Would configure $LocalGroup membership in $GpoName." -Level Info
        return
    }

    $domainObject = if ($Domain -is [string]) {
        try {
            Get-ADDomain -Identity $Domain -Server $Server -ErrorAction Stop
        }
        catch {
            throw ("Failed to resolve domain '{0}' for Set-GPOLocalGroupMembership: {1}" -f $Domain, $_)
        }
    }
    else {
        $Domain
    }

    $domainName = $domainObject.DNSRoot
    $domainDn = $domainObject.DistinguishedName

    $gpo = Get-GPO -Guid $GpoId -Domain $domainName -Server $Server
    $sysvolPath = "\\$domainName\SYSVOL\$domainName\Policies\{$GpoId}\Machine\Preferences\Groups"
    $groupsXmlPath = Join-Path $sysvolPath 'Groups.xml'

    if (-not (Test-Path $sysvolPath)) {
        New-Item -Path $sysvolPath -ItemType Directory -Force | Out-Null
        Write-ScriptLog "Created Groups.xml directory at $sysvolPath." -Level Success
    }

    $xmlContent = @"
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
"@

    foreach ($member in $Members) {
        $memberGuid = (New-Guid).ToString().ToUpper()
        $groupDisplayName = if ($LocalGroup -eq 'Print Operators') { 'Print Operators (built-in)' } else { $LocalGroup }
        $description = 'Configured for SharpHound least-privilege access'

        $memberSid = ''
        try {
            if ($member.Contains('\\')) {
                $account = [System.Security.Principal.NTAccount]$member
                $memberSid = $account.Translate([System.Security.Principal.SecurityIdentifier]).Value
            }
        }
        catch {
            Write-ScriptLog "Could not resolve SID for $member; continuing without SID." -Level Warning
        }

        $xmlContent += @"
	<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="$groupDisplayName"
		image="2" changed="$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" uid="{$memberGuid}"
		userContext="0" removePolicy="0" desc="$description">
		<Properties action="U" newName="" description="$description"
			deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="" groupName="$groupDisplayName">
			<Members>
				<Member name="$member" action="ADD"
					sid="$memberSid" />
			</Members>
		</Properties>
	</Group>
"@
    }

    $xmlContent += @"
</Groups>
"@

    $xmlContent | Out-File -FilePath $groupsXmlPath -Encoding UTF8 -Force
    Write-ScriptLog "Wrote Groups.xml for $LocalGroup in $GpoName with $($Members.Count) member(s)." -Level Success

    $acl = Get-Acl $sysvolPath
    Set-Acl -Path $groupsXmlPath -AclObject $acl

    $extensionNames = "[{00000000-0000-0000-0000-000000000000}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}][{17D89FEC-5C44-4972-B12D-241CAEF74509}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}][{B087BE9D-ED37-454F-AF9C-04291E351182}{BEE07A6A-EC9F-4659-B8C9-0B1937907C83}]"
    $gpoPath = "CN={$GpoId},CN=Policies,CN=System,$domainDn"
    Set-ADObject -Identity $gpoPath -Replace @{
        gPCMachineExtensionNames = $extensionNames
    } -Server $Server -ErrorAction SilentlyContinue

    $gptIniPath = "\\$domainName\SYSVOL\$domainName\Policies\{$GpoId}\GPT.INI"
    if (Test-Path $gptIniPath) {
        $gptContent = Get-Content $gptIniPath
        $versionNumber = $gpo.Computer.DSVersion + 1
        $gptContent = $gptContent -replace 'Version=\d+', "Version=$versionNumber"
        $gptContent | Set-Content -Path $gptIniPath -Encoding ASCII
    }
}

function Add-GroupMemberIfMissing {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string]$Tier,
        [Parameter(Mandatory = $true)]$Group,
        [Parameter(Mandatory = $true)]$Member,
        [Parameter(Mandatory = $true)][string]$Server
    )

    $groupId = $Group.DistinguishedName
    $memberDN = if ($Member -is [string]) { $Member } else { $Member.DistinguishedName }

    $existing = Get-ADGroupMember -Identity $Group -Server $Server -ErrorAction SilentlyContinue | Where-Object { $_.DistinguishedName -eq $memberDN }
    if ($existing) {
        Write-ScriptLog "Member '$memberDN' already belongs to group '$($Group.SamAccountName)'." -Level Info
        return
    }

    Add-ADGroupMember -Identity $Group -Members $Member -Server $Server -Confirm:$false
    Write-ScriptLog "Added '$memberDN' to group '$($Group.SamAccountName)' for tier $Tier." -Level Success
    Register-ProvisionResult -Tier $Tier -Type 'GroupMembership' -Name "$($Group.DistinguishedName)->$memberDN" -Metadata @{ Server = $Server }
}

function Add-PrintOperatorsMembership {  # TODO: Only Tier0 should be added to print operators, rest need to be GPP
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string]$Tier,
        [Parameter(Mandatory = $true)][Microsoft.ActiveDirectory.Management.ADGroup]$PrintOperatorsGroup,
        [Parameter(Mandatory = $true)][Microsoft.ActiveDirectory.Management.ADGroup]$SessionGroup,
        [Parameter(Mandatory = $true)][string]$DomainServer,
        [Parameter(Mandatory = $true)][string]$FallbackServer
    )

    $existingMembers = Get-ADGroupMember -Identity $PrintOperatorsGroup -Server $DomainServer -ErrorAction SilentlyContinue
    $alreadyMember = $existingMembers | Where-Object { $_.DistinguishedName -eq $SessionGroup.DistinguishedName }
    if ($alreadyMember) {
        Write-ScriptLog "Session group already a member of Print Operators in $($PrintOperatorsGroup.DistinguishedName)." -Level Info
        return
    }

    try {
        Set-ADObject -Identity $PrintOperatorsGroup.DistinguishedName -Add @{ member = $SessionGroup.DistinguishedName } -Server $DomainServer -ErrorAction Stop
        Write-ScriptLog "Added session group to Print Operators via Set-ADObject for tier $Tier." -Level Success
        Register-ProvisionResult -Tier $Tier -Type 'DomainGroupMembership' -Name "$($PrintOperatorsGroup.DistinguishedName)->$($SessionGroup.DistinguishedName)" -Metadata @{ Server = $DomainServer }
    }
    catch {
        Write-ScriptLog ("Primary addition to Print Operators failed: {0}" -f $_) -Level Warning
        try {
            Add-ADGroupMember -Identity $PrintOperatorsGroup -Members $SessionGroup -Server $FallbackServer -ErrorAction Stop
            Write-ScriptLog "Added session group to Print Operators using fallback Add-ADGroupMember." -Level Success
            Register-ProvisionResult -Tier $Tier -Type 'DomainGroupMembership' -Name "$($PrintOperatorsGroup.DistinguishedName)->$($SessionGroup.DistinguishedName)" -Metadata @{ Server = $FallbackServer }
        }
        catch {
            throw ("Failed to grant Print Operators membership for tier {0}: {1}" -f $Tier, $_)
        }
    }
}

function Invoke-TierProvision {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string]$Tier,
        [Parameter(Mandatory = $true)]$TierDefinition,
        [Parameter(Mandatory = $true)][Microsoft.ActiveDirectory.Management.ADForest]$Forest,
        [Parameter(Mandatory = $true)][Microsoft.ActiveDirectory.Management.ADDomain]$RootDomain,
        [Parameter(Mandatory = $true)][Microsoft.ActiveDirectory.Management.ADDomain[]]$Domains
    )

    Write-ScriptLog "--- Processing tier $Tier ---" -Level Info
    Write-ScriptLog $TierDefinition.Description -Level Info

    if (-not $TierDefinition.GMSAName) {
        throw "Tier '$Tier' configuration does not include a GMSAName value."
    }

    if (-not $TierDefinition.ServiceAccountOU) {
        throw "Tier '$Tier' configuration does not include a ServiceAccountOU value."
    }

    if (-not $TierDefinition.GmsaContainerPath) {
        throw "Tier '$Tier' configuration does not include a GmsaContainerPath value."
    }

    Write-ScriptLog ("Tier {0} security groups container: {1}" -f $Tier, $TierDefinition.ServiceAccountOU) -Level Info
    Write-ScriptLog ("Tier {0} gMSA container: {1}" -f $Tier, $TierDefinition.GmsaContainerPath) -Level Info

    $collector = Ensure-CollectorComputer -Name $TierDefinition.Collector -Tier $Tier

    $dc = $RootDomain.PDCEmulator
    if ([string]::IsNullOrWhiteSpace($dc) -or $dc -ieq $TierDefinition.Collector) {
        $contextDn = if ([string]::IsNullOrWhiteSpace($TierDefinition.ServiceAccountOU)) {
            if ([string]::IsNullOrWhiteSpace($TierDefinition.GmsaContainerPath)) { $RootDomain.DistinguishedName } else { $TierDefinition.GmsaContainerPath }
        }
        else {
            $TierDefinition.ServiceAccountOU
        }

        try {
            $domainContext = Get-DomainContextForDN -DistinguishedName $contextDn
            if ($domainContext -and $domainContext.Server) {
                $dc = $domainContext.Server
                if ($domainContext.Domain) {
                    $TierDefinition | Add-Member -MemberType NoteProperty -Name ServiceDomain -Value $domainContext.Domain -Force
                }
                Write-ScriptLog ("Using domain controller {0} for tier {1} operations." -f $dc, $Tier) -Level Info
            }
        }
        catch {
            Write-ScriptLog ("Failed to resolve domain controller for tier {0}: {1}" -f $Tier, $_) -Level Warning
        }
    }

    if ([string]::IsNullOrWhiteSpace($dc)) {
        $dc = $RootDomain.PDCEmulator
        Write-ScriptLog ("Defaulting tier {0} operations to root domain controller {1}." -f $Tier, $dc) -Level Warning
    }

    $TierDefinition | Add-Member -MemberType NoteProperty -Name ServiceServer -Value $dc -Force

    $pwdReadersGroupName = '{0}_pwdRead' -f $TierDefinition.GMSAName

    $groupDefinitions = @()
    $groupDefinitions += [pscustomobject]@{
        Key = 'PasswordReaders'
        Name = $pwdReadersGroupName
        Description = 'Password retrieval group for SharpHound gMSA.'
        AddToGMSA = $false
        AddCollector = $true
    }
    $groupDefinitions += [pscustomobject]@{
        Key = 'Allow_SamConnect'
        Name = Get-TierScopedName -BaseName 'Allow_SamConnect' -Tier $Tier
        Description = 'Allows remote SAM connections for SharpHound least privilege.'
        AddToGMSA = $true
        AddCollector = $false
    }
    $groupDefinitions += [pscustomobject]@{
        Key = 'Allow_NetwkstaUserEnum'
        Name = Get-TierScopedName -BaseName 'Allow_NetwkstaUserEnum' -Tier $Tier
        Description = 'Allows session enumeration via Print Operators membership.'
        AddToGMSA = $true
        AddCollector = $false
    }
    $groupDefinitions += [pscustomobject]@{
        Key = 'Allow_WinReg'
        Name = Get-TierScopedName -BaseName 'Allow_WinReg' -Tier $Tier
        Description = 'Allows remote registry reads for SharpHound least privilege.'
        AddToGMSA = $true
        AddCollector = $false
    }
    if ($TierDefinition.IncludeDeletedObjects) {
        $groupDefinitions += [pscustomobject]@{
            Key = 'DeletedObjects_Read'
            Name = Get-TierScopedName -BaseName 'DeletedObjects_Read' -Tier $Tier
            Description = 'Allows read access to Deleted Objects container for Tier 0 collections.'
            AddToGMSA = $true
            AddCollector = $false
        }
    }

    $groups = @{}
    foreach ($definition in $groupDefinitions) {
        $groupObject = Ensure-AdGroup -Tier $Tier -Name $definition.Name -Description $definition.Description -Path $TierDefinition.ServiceAccountOU -Server $dc
        if ($groupObject) {
            $groups[$definition.Key] = $groupObject
        }
    }

    $pwdReadersGroup = $groups['PasswordReaders']
    if (-not $pwdReadersGroup) {
        throw "Tier '$Tier' password reader group was not created successfully; cannot continue provisioning."
    }

    $principalsAllowed = $null
    if ($pwdReadersGroup) {
        if ($pwdReadersGroup.SID -and $pwdReadersGroup.SID.Value) {
            $principalsAllowed = $pwdReadersGroup.SID.Value
        }
        elseif ($pwdReadersGroup.DistinguishedName) {
            $principalsAllowed = $pwdReadersGroup.DistinguishedName
        }
        else {
            $principalsAllowed = $pwdReadersGroup.SamAccountName
        }
    }

    $gmsa = Ensure-GMSA -Tier $Tier -Name $TierDefinition.GMSAName -Path $TierDefinition.GmsaContainerPath -PrincipalsAllowed $principalsAllowed -Server $dc -UserPrincipalName $TierDefinition.GMSAUserPrincipalName

    if ($gmsa) {
        if ($PSCmdlet.ShouldProcess("Group memberships for tier $Tier", 'Configure SharpHound membership')) {
            if ($pwdReadersGroup) {
                Add-GroupMemberIfMissing -Tier $Tier -Group $pwdReadersGroup -Member $collector -Server $dc
            }

            foreach ($definition in $groupDefinitions | Where-Object { $_.AddToGMSA }) {
                if ($groups[$definition.Key]) {
                    Add-GroupMemberIfMissing -Tier $Tier -Group $groups[$definition.Key] -Member $gmsa -Server $dc
                }
            }
        }
        else {
            Write-ScriptLog "[WhatIf] Would configure group memberships for tier $Tier." -Level Info
        }
    }

    if ($TierDefinition.IncludeDeletedObjects -and -not $EnableDeletedObjectsAccess) {
        Write-ScriptLog "Tier $Tier requested Deleted Objects permissions but global switch is disabled; skipping." -Level Warning
    }

    foreach ($domain in $Domains) {
        Write-ScriptLog "Configuring domain $($domain.DNSRoot) for tier $Tier." -Level Info

        $sessionGroup = $groups['Allow_NetwkstaUserEnum']
        if ($sessionGroup) {
            try {
                $printOperators = Get-ADGroup -Identity 'Print Operators' -Server $domain.PDCEmulator -ErrorAction Stop
                Add-PrintOperatorsMembership -Tier $Tier -PrintOperatorsGroup $printOperators -SessionGroup $sessionGroup -DomainServer $domain.PDCEmulator -FallbackServer $dc
            }
            catch {
                Write-ScriptLog ("Failed to configure Print Operators membership in {0}: {1}" -f $domain.DNSRoot, $_) -Level Warning
            }
        }

        $dcGpo = $null
        if ($TierDefinition.IncludeDomainControllers) {
            $dcGpoName = "SharpHound Collector - $Tier - Domain Controllers"
            $dcGpo = Ensure-GPO -Tier $Tier -Name $dcGpoName -Comment 'Configures SharpHound least-privilege settings for Tier 0 domain controllers.' -Domain $domain.DNSRoot -Server $domain.PDCEmulator
            if ($dcGpo) {
                Ensure-GPLink -Tier $Tier -GpoId $dcGpo.Id -GpoName $dcGpoName -Target "OU=Domain Controllers,$($domain.DistinguishedName)" -Domain $domain.DNSRoot -Server $domain.PDCEmulator
                Configure-TierRegistrySettings -Tier $Tier -Gpo $dcGpo -Domain $domain -Groups $groups -Scope 'DomainControllers'
            }
        }

        $memberGpoName = "SharpHound Collector - $Tier - Members"
        $memberGpo = Ensure-GPO -Tier $Tier -Name $memberGpoName -Comment 'Configures SharpHound least-privilege settings for tiered member computers.' -Domain $domain.DNSRoot -Server $domain.PDCEmulator
        if ($memberGpo) {
            Configure-TierRegistrySettings -Tier $Tier -Gpo $memberGpo -Domain $domain -Groups $groups -Scope 'Members'

            if ($TierDefinition.AssetOUs) {
                $linkedAny = $false
                foreach ($ou in $TierDefinition.AssetOUs) {
                    if ($ou -like "*${($domain.DistinguishedName)}") {
                        Ensure-GPLink -Tier $Tier -GpoId $memberGpo.Id -GpoName $memberGpoName -Target $ou -Domain $domain.DNSRoot -Server $domain.PDCEmulator
                        $linkedAny = $true
                    }
                }
                if (-not $linkedAny) {
                    Write-ScriptLog "No Tier $Tier asset OU matched domain $($domain.DNSRoot); manual link required." -Level Warning
                }
            }
            else {
                Write-ScriptLog "Tier $Tier asset OUs not provided; link GPO '$memberGpoName' manually." -Level Warning
            }

            $gpoMemberName = '{0}\{1}' -f $TierDefinition.ServiceDomain.NetBIOSName, $sessionGroup.SamAccountName
            Set-GPOLocalGroupMembership -GpoId $memberGpo.Id -GpoName $memberGpoName -Domain $domain.DNSRoot -Server $domain.PDCEmulator -LocalGroup 'Print Operators' -Members @($gpoMemberName)
        }
    }

    Write-ScriptLog "Completed processing tier $Tier." -Level Success
}

function Configure-TierRegistrySettings {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string]$Tier,
        [Parameter(Mandatory = $true)]$Gpo,
        [Parameter(Mandatory = $true)][Microsoft.ActiveDirectory.Management.ADDomain]$Domain,
        [Parameter(Mandatory = $true)][hashtable]$Groups,
        [Parameter(Mandatory = $true)][ValidateSet('DomainControllers', 'Members')][string]$Scope
    )

    $samGroup = $Groups['Allow_SamConnect']
    $remoteSAMSDDL = if ($samGroup) { "O:BAG:BAD:(A;;RC;;;$($samGroup.SID))(A;;RC;;;BA)" } else { 'O:BAG:BAD:(A;;RC;;;BA)' }

    $gpoId = $Gpo.Id
    $domainName = $Domain.DNSRoot

    Set-GPPRegistryValue -GpoId $gpoId -Key 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' -ValueName 'RestrictRemoteSam' -Value $remoteSAMSDDL -Type 'String' -Order 1 -Domain $domainName -Server $Domain.PDCEmulator

    $dcRegistryPaths = @(
        'System\CurrentControlSet\Control\ProductOptions',
        'System\CurrentControlSet\Control\Server Applications',
        'Software\Microsoft\Windows NT\CurrentVersion',
        'SYSTEM\CurrentControlSet\Services\Kdc',
        'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL',
        'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0',
        'SYSTEM\CurrentControlSet\Control\Lsa',
        'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
        'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    )

    $memberRegistryPaths = @(
        'System\CurrentControlSet\Control\ProductOptions',
        'System\CurrentControlSet\Control\Server Applications',
        'Software\Microsoft\Windows NT\CurrentVersion',
        'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0',
        'SYSTEM\CurrentControlSet\Control\Lsa',
        'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    )

    if ($Scope -eq 'DomainControllers') {
        Set-GPPRegistryValue -GpoId $gpoId -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths' -ValueName 'Machine' -Value $dcRegistryPaths -Type 'MultiString' -Order 2 -Domain $domainName -Server $Domain.PDCEmulator
    }
    else {
        Set-GPPRegistryValue -GpoId $gpoId -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths' -ValueName 'Machine' -Value $memberRegistryPaths -Type 'MultiString' -Order 2 -Domain $domainName -Server $Domain.PDCEmulator
    }
}

function Remove-TierResources {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string]$Tier,
        [Parameter(Mandatory = $true)]$TierDefinition,
        [Parameter(Mandatory = $true)][Microsoft.ActiveDirectory.Management.ADDomain[]]$Domains
    )

    if (-not $TierDefinition) {
        Write-ScriptLog "Tier definition missing for $Tier; skipping deterministic rollback." -Level Warning
        return
    }

    Write-ScriptLog "--- Deterministic rollback for tier $Tier ---" -Level Warning

    $server = $TierDefinition.ServiceServer
    $pwdGroupName = '{0}_pwdRead' -f $TierDefinition.GMSAName
    $groupNames = @(
        (Get-TierScopedName -BaseName 'Allow_SamConnect' -Tier $Tier),
        (Get-TierScopedName -BaseName 'Allow_NetwkstaUserEnum' -Tier $Tier),
        (Get-TierScopedName -BaseName 'Allow_WinReg' -Tier $Tier)
    )
    $deletedObjectsGroupName = Get-TierScopedName -BaseName 'DeletedObjects_Read' -Tier $Tier
    if ($groupNames -notcontains $deletedObjectsGroupName) {
        $groupNames += $deletedObjectsGroupName
    }

    $sessionGroupName = Get-TierScopedName -BaseName 'Allow_NetwkstaUserEnum' -Tier $Tier

    $gmsa = Get-ADServiceAccount -Identity $TierDefinition.GMSAName -Server $server -ErrorAction SilentlyContinue
    if ($gmsa) {
        Write-ScriptLog "Found gMSA $($TierDefinition.GMSAName) for tier $Tier; removing delegations." -Level Info
    }

    foreach ($groupName in $groupNames) {
        $group = Get-ADGroup -Identity $groupName -Server $server -ErrorAction SilentlyContinue
        if ($group -and $gmsa) {
            try {
                Remove-ADGroupMember -Identity $group -Members $gmsa -Server $server -Confirm:$false -ErrorAction Stop
                Write-ScriptLog "Removed gMSA from group '$groupName'." -Level Success
            }
            catch {
                Write-ScriptLog ("Failed to remove gMSA from group {0}: {1}" -f $groupName, $_) -Level Warning
            }
        }
    }

    $pwdGroup = Get-ADGroup -Identity $pwdGroupName -Server $server -ErrorAction SilentlyContinue
    if ($pwdGroup) {
        $collector = Get-ADComputer -Identity $TierDefinition.Collector -ErrorAction SilentlyContinue
        if ($collector) {
            try {
                Remove-ADGroupMember -Identity $pwdGroup -Members $collector -Server $server -Confirm:$false -ErrorAction Stop
                Write-ScriptLog "Removed collector $($TierDefinition.Collector) from $pwdGroupName." -Level Success
            }
            catch {
                Write-ScriptLog ("Failed to remove collector from password reader group: {0}" -f $_) -Level Warning
            }
        }
    }

    if ($gmsa) {
        try {
            Remove-ADServiceAccount -Identity $TierDefinition.GMSAName -Server $server -Confirm:$false -ErrorAction Stop
            Write-ScriptLog "Removed gMSA $($TierDefinition.GMSAName)." -Level Success
        }
        catch {
            Write-ScriptLog ("Failed to remove gMSA {0}: {1}" -f $TierDefinition.GMSAName, $_) -Level Warning
        }
    }

    foreach ($groupName in ($groupNames + $pwdGroupName)) {
        $group = Get-ADGroup -Identity $groupName -Server $server -ErrorAction SilentlyContinue
        if ($group) {
            try {
                Remove-ADGroup -Identity $group -Server $server -Confirm:$false -ErrorAction Stop
                Write-ScriptLog "Removed group $groupName." -Level Success
            }
            catch {
                Write-ScriptLog ("Failed to remove group {0}: {1}" -f $groupName, $_) -Level Warning
            }
        }
    }

    $sessionGroup = Get-ADGroup -Identity $sessionGroupName -Server $server -ErrorAction SilentlyContinue

    foreach ($domain in $Domains) {
        if ($sessionGroup) {
            try {
                $printOperators = Get-ADGroup -Identity 'Print Operators' -Server $domain.PDCEmulator -ErrorAction Stop
                Set-ADObject -Identity $printOperators.DistinguishedName -Remove @{ member = $sessionGroup.DistinguishedName } -Server $domain.PDCEmulator -ErrorAction SilentlyContinue
                Write-ScriptLog "Removed session group from Print Operators in $($domain.DNSRoot)." -Level Success
            }
            catch {
                Write-ScriptLog ("Failed to remove session group from Print Operators in {0}: {1}" -f $domain.DNSRoot, $_) -Level Warning
            }
        }

        if ($TierDefinition.IncludeDomainControllers) {
            $dcGpoName = "SharpHound Collector - $Tier - Domain Controllers"
            try {
                $dcGpo = Get-GPO -Name $dcGpoName -Domain $domain.DNSRoot -Server $domain.PDCEmulator -ErrorAction Stop
                Remove-GPLink -Guid $dcGpo.Id -Target "OU=Domain Controllers,$($domain.DistinguishedName)" -Domain $domain.DNSRoot -Confirm:$false -ErrorAction SilentlyContinue
                Remove-GPO -Guid $dcGpo.Id -Domain $domain.DNSRoot -Confirm:$false -ErrorAction SilentlyContinue
                Write-ScriptLog "Removed Domain Controllers GPO $dcGpoName from $($domain.DNSRoot)." -Level Success
            }
            catch {
                Write-ScriptLog ("Tier {0}: Domain Controllers GPO not removed in {1}: {2}" -f $Tier, $domain.DNSRoot, $_) -Level Warning
            }
        }

        $memberGpoName = "SharpHound Collector - $Tier - Members"
        try {
            $memberGpo = Get-GPO -Name $memberGpoName -Domain $domain.DNSRoot -Server $domain.PDCEmulator -ErrorAction Stop
            if ($TierDefinition.AssetOUs) {
                foreach ($ou in $TierDefinition.AssetOUs) {
                    if ($ou -like "*${($domain.DistinguishedName)}") {
                        Remove-GPLink -Guid $memberGpo.Id -Target $ou -Domain $domain.DNSRoot -Confirm:$false -ErrorAction SilentlyContinue
                    }
                }
            }
            Remove-GPO -Guid $memberGpo.Id -Domain $domain.DNSRoot -Confirm:$false -ErrorAction SilentlyContinue
            Write-ScriptLog "Removed Members GPO $memberGpoName from $($domain.DNSRoot)." -Level Success
        }
        catch {
            Write-ScriptLog ("Tier {0}: Members GPO not removed in {1}: {2}" -f $Tier, $domain.DNSRoot, $_) -Level Warning
        }
    }

    Write-ScriptLog "Completed deterministic rollback for tier $Tier." -Level Success
}

function Invoke-TierRollback {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string[]]$TargetTiers,
        [Parameter(Mandatory = $true)]$TierDefinitions,
        [Parameter(Mandatory = $true)][Microsoft.ActiveDirectory.Management.ADDomain[]]$Domains
    )

    $stateEntries = @($script:ProvisionState | Where-Object { $TargetTiers -contains $_.Tier })

    if ($stateEntries.Count -gt 0) {
        Write-ScriptLog "Rolling back recorded artefacts for tiers: $($TargetTiers -join ', ')." -Level Warning
        for ($index = $script:ProvisionState.Count - 1; $index -ge 0; $index--) {
            $entry = $script:ProvisionState[$index]
            if ($TargetTiers -notcontains $entry.Tier) {
                continue
            }

            try {
                switch ($entry.Type) {
                    'GroupMembership' {
                        $parts = $entry.Name -split '->'
                        $groupDN = $parts[0]
                        $memberDN = $parts[1]
                        Remove-ADGroupMember -Identity $groupDN -Members $memberDN -Server $entry.Metadata.Server -Confirm:$false -ErrorAction Stop
                        Write-ScriptLog "Rolled back group membership $memberDN from $groupDN." -Level Success
                    }
                    'DomainGroupMembership' {
                        $parts = $entry.Name -split '->'
                        $groupDN = $parts[0]
                        $memberDN = $parts[1]
                        Set-ADObject -Identity $groupDN -Remove @{ member = $memberDN } -Server $entry.Metadata.Server -ErrorAction Stop
                        Write-ScriptLog "Rolled back domain group membership $memberDN from $groupDN." -Level Success
                    }
                    'GpoLink' {
                        $details = $entry.Name -split '::'
                        $gpoId = [Guid]$details[0]
                        $target = $details[1]
                        Remove-GPLink -Guid $gpoId -Target $target -Domain $entry.Metadata.Domain -Confirm:$false -ErrorAction Stop
                        Write-ScriptLog "Removed GPO link {$gpoId} from $target." -Level Success
                    }
                    'GPO' {
                        Remove-GPO -Guid $entry.Name -Domain $entry.Metadata.Domain -Confirm:$false -ErrorAction Stop
                        Write-ScriptLog "Removed GPO {$($entry.Name)} from $($entry.Metadata.Domain)." -Level Success
                    }
                    'GMSA' {
                        Remove-ADServiceAccount -Identity $entry.Name -Server $entry.Metadata.Server -Confirm:$false -ErrorAction Stop
                        Write-ScriptLog "Removed gMSA '$($entry.Name)'." -Level Success
                    }
                    'ADGroup' {
                        Remove-ADGroup -Identity $entry.Name -Server $entry.Metadata.Server -Confirm:$false -ErrorAction Stop
                        Write-ScriptLog "Removed security group '$($entry.Name)'." -Level Success
                    }
                    default {
                        Write-ScriptLog "Unknown rollback entry type '$($entry.Type)' for name '$($entry.Name)'." -Level Warning
                    }
                }
            }
            catch {
                Write-ScriptLog ("Rollback failed for entry '{0}' ({1}): {2}" -f $entry.Name, $entry.Type, $_) -Level Error
            }
        }
    }
    else {
        Write-ScriptLog 'No captured provisioning state; executing deterministic rollback.' -Level Warning
        foreach ($tier in $TargetTiers) {
            Remove-TierResources -Tier $tier -TierDefinition $TierDefinitions[$tier] -Domains $Domains
        }
    }
}

#endregion

function Invoke-Main {
    [CmdletBinding()]
    param()

    if ($script:GmsaNormalization.Count -gt 0) {
        foreach ($entry in $script:GmsaNormalization) {
            Write-ScriptLog ("Normalized {0} gMSA input '{1}' to '{2}'" -f $entry.Tier, $entry.Original, $entry.Normalized) -Level Info
        }
    }

    Test-Prerequisites

    $forest = Get-ADForest
    $rootDomain = Get-ADDomain -Identity $forest.RootDomain
    $domains = @()
    foreach ($domainName in $forest.Domains) {
        try {
            $domains += Get-ADDomain -Identity $domainName
        }
        catch {
            Write-ScriptLog ("Unable to query domain {0}. {1}" -f $domainName, $_) -Level Warning
        }
    }

    $targetTiers = Resolve-TargetTiers -RequestedTiers $Tier
    $tierDefinitions = Get-TierDefinitions -RootDomain $rootDomain -AllowMissingOUs:($Action -eq 'Rollback')

    if ($Action -eq 'Rollback') {
        Invoke-TierRollback -TargetTiers $targetTiers -TierDefinitions $tierDefinitions -Domains $domains
        return
    }

    try {
        foreach ($tier in $targetTiers) {
            Invoke-TierProvision -Tier $tier -TierDefinition $tierDefinitions[$tier] -Forest $forest -RootDomain $rootDomain -Domains $domains
        }
        Write-ScriptLog 'Provisioning completed successfully.' -Level Success
    }
    catch {
        Write-ScriptLog ("Provisioning failed: {0}" -f $_) -Level Error
        if ($RollbackOnError) {
            Write-ScriptLog 'RollbackOnError enabled; attempting automatic rollback.' -Level Warning
            Invoke-TierRollback -TargetTiers $targetTiers -TierDefinitions $tierDefinitions -Domains $domains
        }
        throw
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-Main
}
