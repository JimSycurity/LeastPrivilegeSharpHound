<#
.SYNOPSIS
Removes all components created by Create-LeastPrivilegeSharpHound.ps1 including GPOs, security groups, and optionally the gMSA.

.DESCRIPTION
This rollback script safely removes all SharpHound least-privilege components from the Active Directory forest:
- Removes Group Policy Objects from all domains
- Removes security groups created for delegation
- Removes group memberships (Print Operators)
- Optionally removes the Group Managed Service Account
- Provides detailed logging and confirmation prompts

.PARAMETER GMSAName
Name of the Group Managed Service Account to remove (if RemoveGMSA is specified).
Default: LP_gMSA_SHS

.PARAMETER TargetOUDN
Distinguished Name of the OU where security groups and gMSA are located.
Example: "OU=Tier0,DC=magic,DC=lab,DC=lan"

.PARAMETER RemoveGMSA
Switch to also remove the Group Managed Service Account.
Default: $false (keeps the gMSA for safety)

.PARAMETER Force
Skip confirmation prompts and proceed with removal.
Default: $false (interactive confirmation required)

.EXAMPLE
.\Remove-LeastPrivilegeSharpHound.ps1 -TargetOUDN "OU=ServiceAccounts,DC=contoso,DC=com"

.EXAMPLE
.\Remove-LeastPrivilegeSharpHound.ps1 -GMSAName "BH_gMSA" -TargetOUDN "OU=Tier0,DC=lab,DC=local" -RemoveGMSA -Force

.NOTES
Version: 1.0.0
Author: Jim Sykora
Last Modified: 2025-09-04

Requirements:
- PowerShell 5.1 or higher
- ActiveDirectory PowerShell module
- GroupPolicy PowerShell module
- Domain Administrator privileges

Safety Considerations:
- Interactive confirmation required unless -Force is specified
- gMSA removal requires explicit -RemoveGMSA parameter
- Detailed logging of all removal actions
- Graceful handling of missing components
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$GMSAName = "LP_gMSA_SHS",

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TargetOUDN,

    [Parameter(Mandatory = $false)]
    [switch]$RemoveGMSA = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Force = $false
)

# Requires modules
#Requires -Modules ActiveDirectory, GroupPolicy

# Script variables
$script:LogLevel = 'Info'
$script:LogFile = $null

function Write-ScriptLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"

    # Color coding for console output
    $color = switch ($Level) {
        'Info'    { 'White' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        'Success' { 'Green' }
    }

    Write-Host $logMessage -ForegroundColor $color

    # Write to log file if specified
    if ($script:LogFile) {
        Add-Content -Path $script:LogFile -Value $logMessage
    }
}

function Get-ConfirmationPrompt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if ($Force) {
        Write-ScriptLog "Force mode enabled - skipping confirmation for: $Title" -Level Warning
        return $true
    }

    $choices = @(
        [System.Management.Automation.Host.ChoiceDescription]::new('&Yes', 'Proceed with removal')
        [System.Management.Automation.Host.ChoiceDescription]::new('&No', 'Skip this removal')
        [System.Management.Automation.Host.ChoiceDescription]::new('&Cancel', 'Cancel entire operation')
    )

    $result = $Host.UI.PromptForChoice($Title, $Message, $choices, 1)

    switch ($result) {
        0 { return $true }   # Yes
        1 { return $false }  # No
        2 { throw "Operation cancelled by user" }  # Cancel
    }
}

function Remove-SharpHoundGPOs {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-ScriptLog "Starting GPO removal process..." -Level Info

    # Get all domains in the forest with error handling for inaccessible domains
    try {
        $forest = Get-ADForest
        $domains = @()

        Write-ScriptLog "Forest name: $($forest.Name)" -Level Info
        Write-ScriptLog "Forest domains found: $($forest.Domains -join ', ')" -Level Info

        foreach ($domainName in $forest.Domains) {
            try {
                Write-ScriptLog "Attempting to connect to domain: $domainName" -Level Info
                $domain = Get-ADDomain -Identity $domainName -ErrorAction Stop
                $domains += $domain
                Write-ScriptLog "Successfully connected to domain: $($domain.DNSRoot)" -Level Success
            }
            catch {
                Write-ScriptLog "Failed to connect to domain '$domainName': $_" -Level Warning
                Write-ScriptLog "Skipping inaccessible domain: $domainName" -Level Warning
            }
        }

        if ($domains.Count -eq 0) {
            Write-ScriptLog "No accessible domains found in forest" -Level Error
            throw "No accessible domains found in forest"
        }

        Write-ScriptLog "Successfully enumerated $($domains.Count) accessible domains" -Level Success
    }
    catch {
        Write-ScriptLog "Failed to enumerate forest domains: $_" -Level Error
        throw
    }

    $gpoNames = @(
        'SharpHound Collector - Least Privilege - DCs',
        'SharpHound Collector - Least Privilege - Members'
    )

    foreach ($domain in $domains) {
        Write-ScriptLog "Processing domain: $($domain.DNSRoot)" -Level Info

        foreach ($gpoName in $gpoNames) {
            try {
                $gpo = Get-GPO -Name $gpoName -Domain $domain.DNSRoot -Server $domain.PDCEmulator -ErrorAction SilentlyContinue

                if ($gpo) {
                    $confirmTitle = "Remove GPO"
                    $confirmMessage = "Remove GPO '$gpoName' from domain '$($domain.DNSRoot)'?"

                    if (Get-ConfirmationPrompt -Title $confirmTitle -Message $confirmMessage) {
                        if ($PSCmdlet.ShouldProcess($gpoName, "Remove GPO from $($domain.DNSRoot)")) {
                            Remove-GPO -Guid $gpo.Id -Domain $domain.DNSRoot -Server $domain.PDCEmulator -Confirm:$false
                            Write-ScriptLog "Removed GPO '$gpoName' from domain '$($domain.DNSRoot)'" -Level Success
                        }
                    }
                    else {
                        Write-ScriptLog "Skipped GPO removal: $gpoName in $($domain.DNSRoot)" -Level Info
                    }
                }
                else {
                    Write-ScriptLog "GPO '$gpoName' not found in domain '$($domain.DNSRoot)'" -Level Info
                }
            }
            catch {
                Write-ScriptLog "Failed to remove GPO '$gpoName' from domain '$($domain.DNSRoot)': $_" -Level Warning
            }
        }
    }
}

function Remove-SharpHoundGroups {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-ScriptLog "Starting security group removal process..." -Level Info

    # Get root domain for group operations
    try {
        $rootDomain = Get-ADDomain -Identity (Get-ADForest).RootDomain
        Write-ScriptLog "Root domain: $($rootDomain.DNSRoot)" -Level Info
    }
    catch {
        Write-ScriptLog "Failed to get root domain: $_" -Level Error
        throw
    }

    # Define groups to remove (in reverse dependency order)
    $groupsToRemove = @(
        "${GMSAName}_pwdRead",
        'DeletedObjects_Read',
        'Allow_SamConnect',
        'Allow_NetwkstaUserEnum',
        'Allow_WinReg'
    )

    foreach ($groupName in $groupsToRemove) {
        try {
            # First remove from Print Operators if applicable
            if ($groupName -eq 'Allow_NetwkstaUserEnum') {
                Remove-FromPrintOperators -GroupName $groupName -RootDomain $rootDomain
            }

            $group = Get-ADGroup -Identity $groupName -SearchBase $TargetOUDN -Server $rootDomain.PDCEmulator -ErrorAction SilentlyContinue

            if ($group) {
                $confirmTitle = "Remove Security Group"
                $confirmMessage = "Remove security group '$groupName' and all its memberships?"

                if (Get-ConfirmationPrompt -Title $confirmTitle -Message $confirmMessage) {
                    if ($PSCmdlet.ShouldProcess($groupName, "Remove Security Group")) {
                        Remove-ADGroup -Identity $group -Server $rootDomain.PDCEmulator -Confirm:$false
                        Write-ScriptLog "Removed security group: $groupName" -Level Success
                    }
                }
                else {
                    Write-ScriptLog "Skipped group removal: $groupName" -Level Info
                }
            }
            else {
                Write-ScriptLog "Security group not found: $groupName" -Level Info
            }
        }
        catch {
            Write-ScriptLog "Failed to remove security group '$groupName': $_" -Level Warning
        }
    }
}

function Remove-FromPrintOperators {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupName,

        [Parameter(Mandatory = $true)]
        [Microsoft.ActiveDirectory.Management.ADDomain]$RootDomain
    )

    Write-ScriptLog "Removing $GroupName from Print Operators in all domains..." -Level Info

    try {
        $forest = Get-ADForest
        $domains = @()

        foreach ($domainName in $forest.Domains) {
            try {
                $domain = Get-ADDomain -Identity $domainName -ErrorAction Stop
                $domains += $domain
            }
            catch {
                Write-ScriptLog "Failed to connect to domain '$domainName' for Print Operators cleanup: $_" -Level Warning
            }
        }

        $targetGroup = Get-ADGroup -Identity $GroupName -Server $RootDomain.PDCEmulator -ErrorAction SilentlyContinue

        if (-not $targetGroup) {
            Write-ScriptLog "Target group '$GroupName' not found" -Level Warning
            return
        }

        foreach ($domain in $domains) {
            try {
                $printOperators = Get-ADGroup -Identity 'Print Operators' -Server $domain.PDCEmulator
                $members = Get-ADGroupMember -Identity $printOperators -Server $domain.PDCEmulator

                if ($members | Where-Object { $_.SID -eq $targetGroup.SID }) {
                    if ($PSCmdlet.ShouldProcess("Print Operators in $($domain.DNSRoot)", "Remove $GroupName")) {
                        Remove-ADGroupMember -Identity $printOperators -Members $targetGroup -Server $RootDomain.PDCEmulator -Confirm:$false
                        Write-ScriptLog "Removed $GroupName from Print Operators in $($domain.DNSRoot)" -Level Success
                    }
                }
                else {
                    Write-ScriptLog "$GroupName not found in Print Operators for $($domain.DNSRoot)" -Level Info
                }
            }
            catch {
                Write-ScriptLog "Failed to remove from Print Operators in $($domain.DNSRoot): $_" -Level Warning
            }
        }
    }
    catch {
        Write-ScriptLog "Failed to process Print Operators removal: $_" -Level Warning
    }
}

function Remove-SharpHoundGMSA {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if (-not $RemoveGMSA) {
        Write-ScriptLog "Skipping gMSA removal (use -RemoveGMSA to include)" -Level Info
        return
    }

    Write-ScriptLog "Starting gMSA removal process..." -Level Info

    try {
        $rootDomain = Get-ADDomain -Identity (Get-ADForest).RootDomain
        $gmsa = Get-ADServiceAccount -Identity $GMSAName -SearchBase $TargetOUDN -Server $rootDomain.PDCEmulator -ErrorAction SilentlyContinue

        if ($gmsa) {
            $confirmTitle = "Remove gMSA Account"
            $confirmMessage = "Remove Group Managed Service Account '$GMSAName'? This action cannot be undone!"

            if (Get-ConfirmationPrompt -Title $confirmTitle -Message $confirmMessage) {
                if ($PSCmdlet.ShouldProcess($GMSAName, "Remove gMSA")) {
                    Remove-ADServiceAccount -Identity $gmsa -Server $rootDomain.PDCEmulator -Confirm:$false
                    Write-ScriptLog "Removed gMSA: $GMSAName" -Level Success
                }
            }
            else {
                Write-ScriptLog "Skipped gMSA removal: $GMSAName" -Level Info
            }
        }
        else {
            Write-ScriptLog "gMSA not found: $GMSAName" -Level Info
        }
    }
    catch {
        Write-ScriptLog "Failed to remove gMSA '$GMSAName': $_" -Level Error
        throw
    }
}

# Main execution
try {
    Write-ScriptLog "=== SHARPHOUND LEAST PRIVILEGE REMOVAL ===" -Level Info
    Write-ScriptLog "Starting rollback process..." -Level Info
    Write-ScriptLog "Target OU: $TargetOUDN" -Level Info
    Write-ScriptLog "gMSA Name: $GMSAName" -Level Info
    Write-ScriptLog "Remove gMSA: $RemoveGMSA" -Level Info
    Write-ScriptLog "Force mode: $Force" -Level Info

    if (-not $Force) {
        Write-Host ""
        Write-Host "WARNING: This will remove SharpHound least-privilege components from your forest!" -ForegroundColor Red
        Write-Host "This includes GPOs, security groups, and optionally the gMSA account." -ForegroundColor Red
        Write-Host ""

        $finalConfirm = $Host.UI.PromptForChoice(
            "Final Confirmation",
            "Are you sure you want to proceed with the removal?",
            @(
                [System.Management.Automation.Host.ChoiceDescription]::new('&Yes', 'Proceed with removal')
                [System.Management.Automation.Host.ChoiceDescription]::new('&No', 'Cancel operation')
            ),
            1
        )

        if ($finalConfirm -ne 0) {
            Write-ScriptLog "Operation cancelled by user" -Level Info
            exit 0
        }
    }

    # Remove components in dependency order
    Write-ScriptLog "Phase 1: Removing Group Policy Objects..." -Level Info
    Remove-SharpHoundGPOs

    Write-ScriptLog "Phase 2: Removing Security Groups..." -Level Info
    Remove-SharpHoundGroups

    Write-ScriptLog "Phase 3: Processing gMSA..." -Level Info
    Remove-SharpHoundGMSA

    Write-ScriptLog "=== REMOVAL COMPLETED ===" -Level Success
    Write-ScriptLog "SharpHound least-privilege components have been removed from the forest" -Level Success

    if (-not $RemoveGMSA) {
        Write-ScriptLog "NOTE: gMSA '$GMSAName' was preserved (use -RemoveGMSA to remove it)" -Level Info
    }
}
catch {
    Write-ScriptLog "REMOVAL FAILED: $_" -Level Error
    Write-ScriptLog "Some components may have been partially removed" -Level Warning
    Write-ScriptLog "Review the log and manually clean up any remaining components if needed" -Level Warning
    throw
}