<#
.SYNOPSIS
Rolls back tiered least-privilege SharpHound Enterprise collectors by invoking the tiered creation script in
rollback mode.

.DESCRIPTION
This helper script is a thin wrapper around Create-TieredLeastPrivilegeSharpHound.ps1. It accepts the same
naming controls for tiers, gMSAs, collectors, and OUs, then executes the creation script with -Action Rollback.
Use this script when you need a dedicated rollback entry point (for example in pipelines or automation
runbooks) without manually specifying -Action Rollback in the main script.

.PARAMETER Tier
Specifies which tier or tiers to roll back. Accepts T0, T1, T2, or All. Defaults to All.

.PARAMETER ServiceAccountOUDN
Distinguished Name of the OU where the tiered service accounts and security groups reside.

.PARAMETER Tier0ServiceAccountOUDN
Optional Distinguished Name override for Tier 0 service account and group placement.

.PARAMETER Tier1ServiceAccountOUDN
Optional Distinguished Name override for Tier 1 service account and group placement.

.PARAMETER Tier2ServiceAccountOUDN
Optional Distinguished Name override for Tier 2 service account and group placement.

.PARAMETER Tier0AssetOUs
Distinguished Names for Tier 0 asset OUs whose SharpHound GPO links should be removed.

.PARAMETER Tier1AssetOUs
Distinguished Names for Tier 1 asset OUs whose SharpHound GPO links should be removed.

.PARAMETER Tier2AssetOUs
Distinguished Names for Tier 2 asset OUs whose SharpHound GPO links should be removed.

.PARAMETER Tier0Collector
SamAccountName of the Tier 0 SharpHound collector computer. Defaults to T0SharpHoundCollector.

.PARAMETER Tier1Collector
SamAccountName of the Tier 1 SharpHound collector computer. Defaults to T1SharpHoundCollector.

.PARAMETER Tier2Collector
SamAccountName of the Tier 2 SharpHound collector computer. Defaults to T2SharpHoundCollector.

.PARAMETER Tier0GMSAName
Name of the Tier 0 gMSA. Defaults to T0_gMSA_SHS.

.PARAMETER Tier1GMSAName
Name of the Tier 1 gMSA. Defaults to T1_gMSA_SHS.

.PARAMETER Tier2GMSAName
Name of the Tier 2 gMSA. Defaults to T2_gMSA_SHS.

.PARAMETER EnableDeletedObjectsAccess
Include the Tier 0 Deleted Objects delegation artefacts when rolling back (matches the creation switch).

.EXAMPLE
.\Rollback-TieredLeastPrivilegeSharpHound.ps1 -ServiceAccountOUDN "OU=ServiceAccounts,DC=contoso,DC=com"

.EXAMPLE
.\Rollback-TieredLeastPrivilegeSharpHound.ps1 -Tier T1 -ServiceAccountOUDN "OU=ServiceAccounts,DC=contoso,DC=com" \
    -Tier1AssetOUs "OU=Servers,DC=contoso,DC=com"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateSet('T0', 'T1', 'T2', 'All')]
    [string[]]$Tier = 'All',

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceAccountOUDN,

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
    [switch]$EnableDeletedObjectsAccess = $false
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$createScriptPath = Join-Path $scriptDirectory 'Create-TieredLeastPrivilegeSharpHound.ps1'

if (-not (Test-Path $createScriptPath)) {
    throw "Create-TieredLeastPrivilegeSharpHound.ps1 not found at $createScriptPath."
}

$arguments = @{
    Tier = $Tier
    Action = 'Rollback'
    ServiceAccountOUDN = $ServiceAccountOUDN
    Tier0Collector = $Tier0Collector
    Tier1Collector = $Tier1Collector
    Tier2Collector = $Tier2Collector
    Tier0GMSAName = $Tier0GMSAName
    Tier1GMSAName = $Tier1GMSAName
    Tier2GMSAName = $Tier2GMSAName
}

if ($PSBoundParameters.ContainsKey('Tier0ServiceAccountOUDN')) { $arguments['Tier0ServiceAccountOUDN'] = $Tier0ServiceAccountOUDN }
if ($PSBoundParameters.ContainsKey('Tier1ServiceAccountOUDN')) { $arguments['Tier1ServiceAccountOUDN'] = $Tier1ServiceAccountOUDN }
if ($PSBoundParameters.ContainsKey('Tier2ServiceAccountOUDN')) { $arguments['Tier2ServiceAccountOUDN'] = $Tier2ServiceAccountOUDN }
if ($PSBoundParameters.ContainsKey('Tier0AssetOUs')) { $arguments['Tier0AssetOUs'] = $Tier0AssetOUs }
if ($PSBoundParameters.ContainsKey('Tier1AssetOUs')) { $arguments['Tier1AssetOUs'] = $Tier1AssetOUs }
if ($PSBoundParameters.ContainsKey('Tier2AssetOUs')) { $arguments['Tier2AssetOUs'] = $Tier2AssetOUs }
if ($EnableDeletedObjectsAccess) { $arguments['EnableDeletedObjectsAccess'] = $true }

& $createScriptPath @arguments
