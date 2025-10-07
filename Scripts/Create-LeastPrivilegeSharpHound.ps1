<#
.SYNOPSIS
Creates a Group Managed Service Account (gMSA) for SharpHound Enterprise with least-privilege access in an Active Directory forest.

.DESCRIPTION
This script creates a gMSA service account for SharpHound data collection with minimal required permissions
instead of full administrator rights. It creates necessary security groups, applies permissions, and
configures Group Policy preferences for proper operation.

.PARAMETER GMSAName
Name of the Group Managed Service Account to create.
Default: LP_gMSA_SHS

.PARAMETER TargetOUDN
Distinguished Name of the OU where security groups and gMSA will be created.
Optional: when omitted the gMSA is created in the domain's default Managed Service Accounts container and supporting security groups are created in the default Users container.
Example: "OU=Tier0,DC=magic,DC=lab,DC=lan"

.PARAMETER CollectorComputer
Name of the computer that will run SharpHound (without domain suffix).
Example: "BHECollector"

.PARAMETER CreateDeletedObjectsAccess
Switch to enable creation of Deleted Objects container access (requires ownership changes).
Default: $false (disabled due to security considerations)

.PARAMETER RollbackEnabled
Switch to enable rollback capability for registry settings via Group Policy Preferences.
When enabled, registry preferences use "Replace" action with removePolicy and bypassErrors enabled.
This allows the settings to be automatically removed if the GPO is unlinked or deleted.
Default: $false (uses "Update" action for standard deployment)

.EXAMPLE
.\Create-LeastPrivilegeSharpHound.ps1 -TargetOUDN "OU=ServiceAccounts,DC=contoso,DC=com" -CollectorComputer "SHCollector"

.EXAMPLE
.\Create-LeastPrivilegeSharpHound.ps1 -GMSAName "BH_gMSA" -TargetOUDN "OU=Tier0,DC=lab,DC=local" -CollectorComputer "Collector01" -WhatIf

.EXAMPLE
.\Create-LeastPrivilegeSharpHound.ps1 -TargetOUDN "OU=ServiceAccounts,DC=contoso,DC=com" -CollectorComputer "SHCollector" -RollbackEnabled

.NOTES
Version: 2.8.0
Author: Jim Sykora
Last Modified: 2025-09-03

Requirements:
- PowerShell 5.1 or higher
- ActiveDirectory PowerShell module
- GroupPolicy PowerShell module
- Domain Administrator privileges
- Windows Server 2012 R2 or higher domain functional level for gMSA support
- KDS Root Key must be configured (Add-KdsRootKey -EffectiveImmediately)

Security Considerations:
- Creates minimal required permissions for SharpHound operation
- Does not grant unnecessary administrative privileges
- Uses secure gMSA password management
- Implements least-privilege principle throughout
#>

# Requires modules
#Requires -Modules ActiveDirectory, GroupPolicy

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$GMSAName = 'LP_gMSA_SHS',

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$TargetOUDN = $null,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CollectorComputer,

    [Parameter(Mandatory = $false)]
    [switch]$CreateDeletedObjectsAccess = $false,

    [Parameter(Mandatory = $false)]
    [switch]$RollbackEnabled = $false,

    [Parameter(Mandatory = $false)]
    [string]$UserPrincipalName = $null
)

# Set strict mode and error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Helper Functions

function Write-ScriptLog {
    [CmdletBinding()]
    param(
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

function Test-Prerequisites {
    [CmdletBinding()]
    param()

    Write-ScriptLog "Checking prerequisites..." -Level Info

    # Check PowerShell modules
    $requiredModules = @('ActiveDirectory', 'GroupPolicy')
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            throw "Required PowerShell module '$module' is not available. Please install RSAT tools."
        }
        Import-Module $module -Force
        Write-ScriptLog "Imported module: $module" -Level Success
    }

    # Check domain connectivity
    try {
        $domain = Get-ADDomain
        Write-ScriptLog "Connected to domain: $($domain.DNSRoot)" -Level Success
    }
    catch {
        throw "Unable to connect to Active Directory domain: $_"
    }

    # Validate target OU exists when provided
    if ($TargetOUDN) {
        try {
            Get-ADOrganizationalUnit -Identity $TargetOUDN | Out-Null
            Write-ScriptLog "Target OU verified: $TargetOUDN" -Level Success
        }
        catch {
            throw "Target OU does not exist: $TargetOUDN"
        }
    }
    else {
        Write-ScriptLog "No Target OU specified; defaults will be applied at runtime." -Level Info
    }

    # Validate collector computer exists
    try {
        Get-ADComputer -Identity $CollectorComputer | Out-Null
        Write-ScriptLog "Collector computer verified: $CollectorComputer" -Level Success
    }
    catch {
        throw "Collector computer does not exist: $CollectorComputer"
    }

    # Validate KDS Root Key exists for gMSA support
    Write-ScriptLog "Checking KDS Root Key for gMSA support..." -Level Info
    try {
        $kdsRootKeys = @(Get-KdsRootKey)
        if ($kdsRootKeys.Count -eq 0) {
            Write-ScriptLog "No KDS Root Key found - gMSA creation will fail" -Level Error
            throw "KDS Root Key is required for Group Managed Service Accounts. Run: Add-KdsRootKey -EffectiveImmediately"
        }

        # Check for usable KDS root keys (effective time in the past)
        $usableKeys = $kdsRootKeys | Where-Object { $_.EffectiveTime -le (Get-Date) }
        if ($usableKeys.Count -eq 0) {
            $newestKey = $kdsRootKeys | Sort-Object EffectiveTime -Descending | Select-Object -First 1
            Write-ScriptLog "KDS Root Key exists but is not yet effective (effective at $($newestKey.EffectiveTime))" -Level Warning
            Write-ScriptLog "gMSA creation may fail. Wait until the key is effective or use -EffectiveImmediately for immediate use." -Level Warning
        } else {
            Write-ScriptLog "Found $($usableKeys.Count) usable KDS Root Key(s) - gMSA support confirmed" -Level Success
        }
    }
    catch {
        if ($_.Exception.Message -like "*not recognized*" -or $_.Exception.Message -like "*not found*") {
            throw "KDS Root Key cmdlets not available. Ensure you're running on a domain controller with Windows Server 2012 R2 or higher."
        }
        throw "Failed to check KDS Root Key: $_"
    }

    # Check domain functional level for gMSA support
    $domainFunctionalLevel = (Get-ADDomain).DomainMode
    if ($domainFunctionalLevel -notmatch "2012|2016|2019|2022|2025") {
        Write-ScriptLog "Domain functional level: $domainFunctionalLevel" -Level Warning
        Write-ScriptLog "gMSA requires Windows Server 2012 R2 DFL or higher" -Level Warning
    } else {
        Write-ScriptLog "Domain functional level supports gMSA: $domainFunctionalLevel" -Level Success
    }
}

function New-SharpHoundSecurityGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [string]$Server
    )

    if ($PSCmdlet.ShouldProcess($Name, "Create Security Group")) {
        try {
            $params = @{
                Name = $Name
                GroupScope = 'Universal'
                GroupCategory = 'Security'
                Path = $Path
                Description = $Description
                PassThru = $true
            }
            if ($Server) {
                $params['Server'] = $Server
            }
            $group = New-ADGroup @params
            Write-ScriptLog "Created security group: $Name" -Level Success
            return $group
        }
        catch {
            if ($_.Exception.Message -match "already exists") {
                Write-ScriptLog "Security group already exists: $Name" -Level Warning
                return Get-ADGroup -Identity $Name
            }
            else {
                throw "Failed to create security group '$Name': $_"
            }
        }
    }
    else {
        Write-ScriptLog "[WhatIf] Would create security group: $Name" -Level Info
        return $null
    }
}

function New-SharpHoundGMSA {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$PrincipalsAllowedToRetrieveManagedPassword,

        [Parameter(Mandatory = $false)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [string]$UserPrincipalName
    )

    if ($PSCmdlet.ShouldProcess($Name, "Create gMSA")) {
        try {
            # Get domain information for DNS hostname
            if ($Server) {
                $domain = Get-ADDomain -Server $Server
            } else {
                $domain = Get-ADDomain
            }
            $dnsHostName = "$Name.$($domain.DNSRoot)"
            $baseSam = if ([string]::IsNullOrWhiteSpace($Name)) { '' } else { $Name.TrimEnd('$') }
            $desiredUpn = if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) { $null } else { $UserPrincipalName.Trim() }
            if (-not $desiredUpn -and -not [string]::IsNullOrWhiteSpace($baseSam) -and $domain -and -not [string]::IsNullOrWhiteSpace($domain.DNSRoot)) {
                $desiredUpn = '{0}@{1}' -f $baseSam, $domain.DNSRoot
            }

            $gmsaParams = @{
                Name = $Name
                Description = 'SharpHound service account for BloodHound Enterprise - Least Privilege'
                DNSHostName = $dnsHostName
                ManagedPasswordIntervalInDays = 30
                PrincipalsAllowedToRetrieveManagedPassword = $PrincipalsAllowedToRetrieveManagedPassword
                Enabled = $true
                AccountNotDelegated = $true
                KerberosEncryptionType = 'AES128', 'AES256'
                Path = $Path
                PassThru = $true
            }

            if ($desiredUpn) {
                $gmsaParams['OtherAttributes'] = @{ userPrincipalName = $desiredUpn }
            }

            if ($Server) {
                $gmsaParams['Server'] = $Server
            }

            $gmsa = New-ADServiceAccount @gmsaParams
            Write-ScriptLog "Created gMSA: $Name with DNS name: $dnsHostName" -Level Success
            return $gmsa
        }
        catch {
            if ($_.Exception.Message -match "already exists") {
                Write-ScriptLog "gMSA already exists: $Name" -Level Warning
                $getParams = @{ Identity = $Name }
                if ($Server) { $getParams['Server'] = $Server }
                $gmsa = Get-ADServiceAccount @getParams
                if ($desiredUpn -and -not [string]::Equals($gmsa.userPrincipalName, $desiredUpn, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $setParams = @{ Identity = $gmsa.DistinguishedName; Replace = @{ userPrincipalName = $desiredUpn }; ErrorAction = 'Stop' }
                    if ($Server) { $setParams['Server'] = $Server }
                    Set-ADServiceAccount @setParams
                    Write-ScriptLog "Updated gMSA userPrincipalName to $desiredUpn" -Level Info
                    $gmsa = Get-ADServiceAccount @getParams
                }
                return $gmsa
            }
            else {
                throw "Failed to create gMSA '$Name': $_"
            }
        }
    }
    else {
        Write-ScriptLog "[WhatIf] Would create gMSA: $Name" -Level Info
        return $null
    }
}

function Enable-RegistryRollback {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GPOId,

        [Parameter(Mandatory = $true)]
        [string]$Key,

        [Parameter(Mandatory = $true)]
        [string]$ValueName,

        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $true)]
        [string]$Server
    )

    try {
        # Build path to Registry.xml in SYSVOL
        $registryXmlPath = "\\$Domain\SYSVOL\$Domain\Policies\{$GPOId}\Machine\Preferences\Registry\Registry.xml"

        if (-not (Test-Path $registryXmlPath)) {
            Write-ScriptLog "Registry.xml not found at $registryXmlPath - cannot enable rollback" -Level Warning
            return
        }

        # Load and modify the Registry.xml
        $xml = [xml](Get-Content $registryXmlPath)

        # Extract the key part without the hive prefix (e.g., HKLM\System\... -> System\...)
        $keyWithoutHive = $Key -replace '^HKL[MU]\\', '' -replace '^HKEY_LOCAL_MACHINE\\', '' -replace '^HKEY_CURRENT_USER\\', ''

        Write-ScriptLog "Searching for registry entry - Key: '$keyWithoutHive', ValueName: '$ValueName'" -Level Info

        # List all registry entries for debugging
        foreach ($entry in $xml.RegistrySettings.Registry) {
            Write-ScriptLog "Found registry entry - Key: '$($entry.Properties.key)', Name: '$($entry.Properties.name)'" -Level Info
        }

        # Find the registry entry that matches our key and value name (case-insensitive)
        $registryNode = $xml.RegistrySettings.Registry | Where-Object {
            $_.Properties.key -eq $keyWithoutHive -and $_.Properties.name -eq $ValueName
        } | Select-Object -First 1

        if ($registryNode) {
            # Enable rollback attributes
            $registryNode.SetAttribute('image', '6')
            $registryNode.SetAttribute('removePolicy', '1')
            $registryNode.SetAttribute('bypassErrors', '1')

            # Save the modified XML
            $xml.Save($registryXmlPath)
            Write-ScriptLog "Enabled rollback for registry entry: $Key\$ValueName" -Level Success
        }
        else {
            Write-ScriptLog "Could not find registry entry in XML for rollback: $Key\$ValueName" -Level Warning
        }
    }
    catch {
        Write-ScriptLog "Failed to enable rollback for registry entry '$Key\$ValueName': $_" -Level Warning
    }
}

function Set-GroupPolicyRegistryValue {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GPOId,

        [Parameter(Mandatory = $true)]
        [string]$Key,

        [Parameter(Mandatory = $true)]
        [string]$ValueName,

        [Parameter(Mandatory = $true)]
        $Value,

        [Parameter(Mandatory = $true)]
        [ValidateSet('String', 'MultiString', 'DWord', 'QWord')]
        [string]$Type,

        [Parameter(Mandatory = $true)]
        [int]$Order,

        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [switch]$EnableRollback = $false
    )

    if ($PSCmdlet.ShouldProcess($Key, "Set GPO Registry Value")) {
        try {
            # Check if the registry value already exists with the same value
            $existingValue = $null
            try {
                $existingValues = Get-GPPrefRegistryValue -Guid $GPOId -Context Computer -Key $Key -Domain $Domain -Server $Server -ErrorAction SilentlyContinue
                $existingValue = $existingValues | Where-Object { $_.ValueName -eq $ValueName }
            }
            catch {
                # Ignore errors when checking existing values (key/value might not exist yet)
                Write-ScriptLog "Registry key/value doesn't exist yet: $Key\$ValueName" -Level Info
            }

            # Compare existing value with new value
            $needsUpdate = $true
            if ($existingValue) {
                # Convert values to comparable format
                $existingVal = $existingValue.Value
                $newVal = $Value

                # Handle different value types
                if ($Type -eq 'MultiString' -and $existingVal -is [Array] -and $newVal -is [Array]) {
                    $needsUpdate = $null -ne (Compare-Object $existingVal $newVal)
                }
                elseif ($Type -eq 'DWord' -or $Type -eq 'QWord') {
                    $needsUpdate = [int64]$existingVal -ne [int64]$newVal
                }
                else {
                    $needsUpdate = $existingVal -ne $newVal
                }

                if (-not $needsUpdate) {
                    Write-ScriptLog "Registry value already set correctly: $Key\$ValueName" -Level Info
                    return
                }
            }

            # Set the registry value
            $action = if ($EnableRollback) { 'Replace' } else { 'Update' }
            $params = @{
                Context = 'Computer'
                Key = $Key
                ValueName = $ValueName
                Value = $Value
                Order = $Order
                Type = $Type
                Action = $action
                Domain = $Domain
                Server = $Server
            }

            Set-GPPrefRegistryValue -Guid $GPOId @params

            # If rollback is enabled, modify the Registry.xml directly to add removePolicy and bypassErrors
            if ($EnableRollback) {
                Enable-RegistryRollback -GPOId $GPOId -Key $Key -ValueName $ValueName -Domain $Domain -Server $Server
            }

            $actionText = if ($EnableRollback) { "with rollback enabled (Replace action)" } else { "(Update action)" }
            Write-ScriptLog "Set registry value: $Key\$ValueName $actionText" -Level Success
        }
        catch {
            Write-ScriptLog "Failed to set registry value '$Key\$ValueName': $_" -Level Error
            throw
        }
    }
    else {
        Write-ScriptLog "[WhatIf] Would set registry value: $Key\$ValueName" -Level Info
    }
}

function Set-GPOLocalGroupMembership {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GPOName,

        [Parameter(Mandatory = $true)]
        [string]$LocalGroupName,

        [Parameter(Mandatory = $true)]
        [string[]]$Members,

        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $true)]
        [string]$Server
    )

    if ($PSCmdlet.ShouldProcess($LocalGroupName, "Set GPO Local Group Membership")) {
        try {
            Write-ScriptLog "Configuring local group '$LocalGroupName' membership in GPO '$GPOName'" -Level Info

            # Get GPO information
            $gpo = Get-GPO -Name $GPOName -Domain $Domain -Server $Server

            # Build SYSVOL path for Groups.xml
            $sysvolPath = "\\$Domain\SYSVOL\$Domain\Policies\{$($gpo.Id)}\Machine\Preferences\Groups"
            $groupsXmlPath = Join-Path $sysvolPath "Groups.xml"

            # Ensure the directory exists
            if (-not (Test-Path $sysvolPath)) {
                New-Item -Path $sysvolPath -ItemType Directory -Force | Out-Null
                Write-ScriptLog "Created Groups preferences directory: $sysvolPath" -Level Success
            }

            # Determine group SID based on well-known groups
            $groupSid = switch ($LocalGroupName) {
                'Print Operators' { 'S-1-5-32-550' }
                'Print Operators (built-in)' { 'S-1-5-32-550' }
                'Server Operators' { 'S-1-5-32-549' }
                'Backup Operators' { 'S-1-5-32-551' }
                'Network Configuration Operators' { 'S-1-5-32-556' }
                'Performance Log Users' { 'S-1-5-32-559' }
                'Event Log Readers' { 'S-1-5-32-573' }
                default { '' }
            }

            # Create Groups.xml content matching the provided template
            $xmlContent = @"
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
"@

            # Add each member as a separate group configuration
            foreach ($member in $Members) {
                $memberGuid = (New-Guid).ToString().ToUpper()
                $groupDisplayName = if ($LocalGroupName -eq 'Print Operators') { 'Print Operators (built-in)' } else { $LocalGroupName }
                $description = if ($LocalGroupName -eq 'Print Operators') { 'Used to allow session enumeration' } else { 'Configured for SharpHound least-privilege access' }

                # Try to resolve member SID if it's a domain group
                $memberSid = ""
                try {
                    if ($member.Contains('\')) {
                        $memberObj = ([System.Security.Principal.NTAccount]$member).Translate([System.Security.Principal.SecurityIdentifier])
                        $memberSid = $memberObj.Value
                    }
                }
                catch {
                    Write-ScriptLog "Could not resolve SID for $member, leaving blank" -Level Warning
                }

                $xmlContent += @"
	<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="$groupDisplayName"
		image="2" changed="$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" uid="{$memberGuid}"
		userContext="0" removePolicy="0" desc="$description">
		<Properties action="U" newName="" description="$description"
			deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="$groupSid"
			groupName="$groupDisplayName">
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

            # Write the Groups.xml file
            $xmlContent | Out-File -FilePath $groupsXmlPath -Encoding UTF8 -Force
            Write-ScriptLog "Created Groups.xml for local group '$LocalGroupName' with $(($Members).Count) members" -Level Success

            # Set proper permissions on the file (inherit from parent)
            $acl = Get-Acl $sysvolPath
            Set-Acl -Path $groupsXmlPath -AclObject $acl

            # Increment GPO version to ensure the changes take effect
            $currentVersion = $gpo.Computer.DSVersion
            $newVersion = $currentVersion + 1

            # Update GPO version and extension names in AD
            $gpoPath = "CN={$($gpo.Id)},CN=Policies,CN=System,$((Get-ADDomain -Server $Server).DistinguishedName)"

            # Set proper gPCMachineExtensionNames for Group Policy Preferences
            $extensionNames = "[{00000000-0000-0000-0000-000000000000}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}][{17D89FEC-5C44-4972-B12D-241CAEF74509}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}][{B087BE9D-ED37-454F-AF9C-04291E351182}{BEE07A6A-EC9F-4659-B8C9-0B1937907C83}]"

            Set-ADObject -Identity $gpoPath -Replace @{
                versionNumber = $newVersion
                gPCMachineExtensionNames = $extensionNames
            } -Server $Server

            Write-ScriptLog "Updated GPO extension names for Group Policy Preferences support" -Level Success

            # Update GPO version in SYSVOL (GPT.INI file)
            $gptIniPath = "\\$Domain\SYSVOL\$Domain\Policies\{$($gpo.Id)}\GPT.INI"
            if (Test-Path $gptIniPath) {
                $gptContent = Get-Content $gptIniPath
                $gptContent = $gptContent -replace 'Version=\d+', "Version=$newVersion"
                $gptContent | Set-Content -Path $gptIniPath -Encoding ASCII
                Write-ScriptLog "Updated GPO version to $newVersion for proper policy application" -Level Success
            }

        }
        catch {
            Write-ScriptLog "Failed to configure local group membership for '$LocalGroupName': $_" -Level Error
            throw
        }
    }
    else {
        Write-ScriptLog "[WhatIf] Would configure local group '$LocalGroupName' membership in GPO '$GPOName'" -Level Info
    }
}

#endregion

#region Main Script Logic

try {
    $originalGmsaName = $GMSAName
    $gmsaUserPrincipalName = if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) { $null } else { $UserPrincipalName.Trim("'`"") }
    if (-not [string]::IsNullOrWhiteSpace($GMSAName)) {
        $normalizedInput = $GMSAName.Trim("'`"")
        if ($normalizedInput -like '*@*') {
            $normalizedParts = $normalizedInput.Split('@', 2, [System.StringSplitOptions]::RemoveEmptyEntries)
            if ($normalizedParts.Length -ge 1) {
                $normalizedInput = $normalizedParts[0].Trim()
            }
            if ($normalizedParts.Length -ge 2) {
                $domainPart = $normalizedParts[1].Trim()
                if (-not [string]::IsNullOrWhiteSpace($domainPart) -and -not $gmsaUserPrincipalName) {
                    $gmsaUserPrincipalName = ('{0}@{1}' -f $normalizedInput.TrimEnd('$'), $domainPart)
                }
            }
        }
        $normalizedGmsa = $normalizedInput
        if ($normalizedGmsa -like '*\\*') {
            $netbiosParts = $normalizedGmsa.Split('\\', 2, [System.StringSplitOptions]::RemoveEmptyEntries)
            if ($netbiosParts.Length -ge 2) {
                $normalizedGmsa = $netbiosParts[1].Trim()
            }
            elseif ($netbiosParts.Length -eq 1) {
                $normalizedGmsa = $netbiosParts[0].Trim()
            }
        }
        $GMSAName = $normalizedGmsa.Trim().TrimEnd('$')
    }

    if ([string]::IsNullOrWhiteSpace($GMSAName)) {
        throw 'Resolved gMSA name is empty after normalization.'
    }

    if ($originalGmsaName -ne $GMSAName) {
        Write-ScriptLog ("Normalized gMSA input '{0}' to '{1}'" -f $originalGmsaName, $GMSAName) -Level Info
    }

    Write-ScriptLog "Starting SharpHound Least Privilege gMSA creation script" -Level Info
    $ouLogValue = if ([string]::IsNullOrEmpty($TargetOUDN)) { '<default>' } else { $TargetOUDN }
    Write-ScriptLog "Parameters: gMSA=$GMSAName, OU=$ouLogValue, Collector=$CollectorComputer" -Level Info

    if ($WhatIfPreference) {
        Write-ScriptLog "Running in WhatIf mode - no changes will be made" -Level Warning
    }

    # Test prerequisites
    Test-Prerequisites

    # Get forest information
    Write-ScriptLog "Gathering forest information..." -Level Info
    $forest = Get-ADForest
    $rootDomain = Get-ADDomain -Identity $forest.RootDomain
    Write-ScriptLog "Forest root domain: $($rootDomain.DNSRoot)" -Level Info

    # Resolve paths for security groups and gMSA creation
    if ($TargetOUDN) {
        $groupContainerPath = $TargetOUDN
        $gmsaContainerPath = $TargetOUDN
    }
    else {
        $groupContainerPath = "CN=Users,$($rootDomain.DistinguishedName)"
        $gmsaContainerPath = $rootDomain.ManagedServiceAccountsContainer

        if ([string]::IsNullOrEmpty($gmsaContainerPath)) {
            $gmsaContainerPath = "CN=Managed Service Accounts,$($rootDomain.DistinguishedName)"
        }

        try {
            Get-ADObject -Identity $gmsaContainerPath -Server $rootDomain.PDCEmulator | Out-Null
        }
        catch {
            throw "Default Managed Service Accounts container not found: $gmsaContainerPath. Specify -TargetOUDN or create the container."
        }

        Write-ScriptLog "Target OU not provided; using domain defaults for containers." -Level Info
    }

    Write-ScriptLog "gMSA will be created in: $gmsaContainerPath" -Level Info
    Write-ScriptLog "Security groups will be created in: $groupContainerPath" -Level Info

    $domainsArray = foreach ($domain in $forest.Domains) {
        try {
            Get-ADDomain -Identity $domain
        }
        catch {
            Write-ScriptLog "Warning: Could not access domain $domain" -Level Warning
        }
    }
    Write-ScriptLog "Found $($domainsArray.Count) accessible domains in forest" -Level Success

    # Log rollback mode status
    if ($RollbackEnabled) {
        Write-ScriptLog "ROLLBACK MODE ENABLED: Registry settings will use Replace action with removePolicy and bypassErrors enabled" -Level Info
        Write-ScriptLog "This allows automatic removal of settings when GPOs are unlinked or deleted" -Level Info
    } else {
        Write-ScriptLog "Standard mode: Registry settings will use Update action (persistent)" -Level Info
    }

    # Create security groups
    Write-ScriptLog "Creating security groups..." -Level Info

    $groupDefinitions = @{
        "$($GMSAName)_pwdRead" = "This group grants the rights to retrieve the password of the BloodHound data collector gMSA '$GMSAName'."
        "DeletedObjects_Read" = "This group grants the rights to read the Deleted Objects container(s) of the forest"
        "Allow_SamConnect" = "This group grants the rights to perform remote SAM connections"
        "Allow_NetwkstaUserEnum" = "This group grants the rights to enumerate sessions via nested membership in Print Operators"
        "Allow_WinReg" = "This group grants the rights to perform remote registry reads"
    }

    $groups = @{}
    foreach ($groupName in $groupDefinitions.Keys) {
        $groups[$groupName] = New-SharpHoundSecurityGroup -Name $groupName -Description $groupDefinitions[$groupName] -Path $groupContainerPath -Server $rootDomain.PDCEmulator
    }

    # Create gMSA
    Write-ScriptLog "Creating Group Managed Service Account..." -Level Info
    $gmsa = New-SharpHoundGMSA -Name $GMSAName -Path $gmsaContainerPath -PrincipalsAllowedToRetrieveManagedPassword "$($GMSAName)_pwdRead" -Server $rootDomain.PDCEmulator -UserPrincipalName $gmsaUserPrincipalName

    # Configure group memberships
    Write-ScriptLog "Configuring group memberships..." -Level Info

    if ($PSCmdlet.ShouldProcess("Group memberships", "Configure")) {
        # Add collector computer to password read group
        $collectorObject = Get-ADComputer -Identity $CollectorComputer
        Add-ADGroupMember -Identity "$($GMSAName)_pwdRead" -Members $collectorObject
        Write-ScriptLog "Added $CollectorComputer to $($GMSAName)_pwdRead group" -Level Success

        # Add gMSA to delegation groups
        $delegationGroups = @('DeletedObjects_Read', 'Allow_SamConnect', 'Allow_NetwkstaUserEnum', 'Allow_WinReg')
        foreach ($groupName in $delegationGroups) {
            if ($groups[$groupName]) {
                Add-ADGroupMember -Identity $groups[$groupName] -Members $gmsa
                Write-ScriptLog "Added $GMSAName to $groupName group" -Level Success
            }
        }
    }
    else {
        Write-ScriptLog "[WhatIf] Would configure group memberships" -Level Info
    }

    # Handle Deleted Objects access (optional)
    if ($CreateDeletedObjectsAccess) {
        Write-ScriptLog "Configuring Deleted Objects container access..." -Level Warning
        Write-ScriptLog "Note: This feature requires taking ownership of containers - use with caution" -Level Warning

        if ($PSCmdlet.ShouldProcess("Deleted Objects containers", "Grant access")) {
            # Implementation would go here - commented out for security
            Write-ScriptLog "Deleted Objects access configuration is disabled for security reasons" -Level Warning
        }
    }
    else {
        Write-ScriptLog "Skipping Deleted Objects access configuration (use -CreateDeletedObjectsAccess to enable)" -Level Info
    }

    # Configure per-domain settings
    Write-ScriptLog "Configuring per-domain Group Policy settings..." -Level Info

    foreach ($domain in $domainsArray) {
        Write-ScriptLog "Processing domain: $($domain.DNSRoot)" -Level Info

        if ($PSCmdlet.ShouldProcess($domain.DNSRoot, "Configure domain settings")) {
            # Add session enumeration group to Print Operators using Set-ADObject approach
            try {
                $PrintOperators = Get-ADGroup -Identity 'Print Operators' -Server $domain.PDCEmulator
                $Allow_NetwkstaUserEnum = Get-ADGroup -Identity 'Allow_NetwkstaUserEnum' -Server $rootDomain.PDCEmulator

                # Check if the group is already a member to avoid duplicate additions
                $currentMembers = Get-ADGroupMember -Identity $PrintOperators -Server $domain.PDCEmulator -ErrorAction SilentlyContinue
                $alreadyMember = $currentMembers | Where-Object { $_.SID -eq $Allow_NetwkstaUserEnum.SID }

                if ($alreadyMember) {
                    Write-ScriptLog "Allow_NetwkstaUserEnum is already a member of Print Operators in $($domain.DNSRoot)" -Level Info
                }
                else {
                    # Use Set-ADObject to directly modify the member attribute
                    Set-ADObject -Identity $PrintOperators.DistinguishedName -Add @{member = $Allow_NetwkstaUserEnum.DistinguishedName} -Server $domain.PDCEmulator
                    Write-ScriptLog "Added Allow_NetwkstaUserEnum to Print Operators in $($domain.DNSRoot) using Set-ADObject" -Level Success
                }
            }
            catch {
                Write-ScriptLog "Failed to add to Print Operators in $($domain.DNSRoot): $_" -Level Warning

                # Try alternative approach: use Add-ADGroupMember with root domain server
                try {
                    Write-ScriptLog "Attempting fallback approach using Add-ADGroupMember with root domain server for $($domain.DNSRoot)" -Level Info
                    Add-ADGroupMember -Identity $PrintOperators -Server $rootDomain.PDCEmulator -Members $Allow_NetwkstaUserEnum -ErrorAction Stop
                    Write-ScriptLog "Successfully added Allow_NetwkstaUserEnum to Print Operators using fallback method" -Level Success
                }
                catch {
                    Write-ScriptLog "Fallback approach also failed: $_" -Level Warning
                    Write-ScriptLog "Manual addition may be required for domain: $($domain.DNSRoot)" -Level Warning
                }
            }

            # Create Group Policy Objects
            $dcGPOName = 'SharpHound Collector - Least Privilege - DCs'
            $memberGPOName = 'SharpHound Collector - Least Privilege - Members'

            try {
                $dcGPO = New-GPO -Name $dcGPOName -Comment 'Configure Least-Privilege Access for SharpHound collection on Domain Controllers' -Domain $domain.DNSRoot -Server $domain.PDCEmulator
                Write-ScriptLog "Created GPO: $dcGPOName" -Level Success
            }
            catch {
                Write-ScriptLog "GPO may already exist: $dcGPOName" -Level Warning
                $dcGPO = Get-GPO -Name $dcGPOName -Domain $domain.DNSRoot -Server $domain.PDCEmulator
            }

            try {
                $memberGPO = New-GPO -Name $memberGPOName -Comment 'Configure Least-Privilege Access for SharpHound collection on non-DCs' -Domain $domain.DNSRoot -Server $domain.PDCEmulator
                Write-ScriptLog "Created GPO: $memberGPOName" -Level Success
            }
            catch {
                Write-ScriptLog "GPO may already exist: $memberGPOName" -Level Warning
                $memberGPO = Get-GPO -Name $memberGPOName -Domain $domain.DNSRoot -Server $domain.PDCEmulator
            }

            # Link GPOs to appropriate OUs
            try {
                $dcOU = "OU=Domain Controllers,$($domain.DistinguishedName)"
                New-GPLink -Guid $dcGPO.Id -Target $dcOU -LinkEnabled Yes -Order 1 -Domain $domain.DNSRoot -Server $domain.PDCEmulator
                Write-ScriptLog "Linked DC GPO to: $dcOU" -Level Success
            }
            catch {
                Write-ScriptLog "DC GPO may already be linked" -Level Warning
            }

            try {
                New-GPLink -Guid $memberGPO.Id -Target $domain.DistinguishedName -LinkEnabled Yes -Order 1 -Domain $domain.DNSRoot -Server $domain.PDCEmulator
                Write-ScriptLog "Linked Member GPO to domain root (consider linking to specific OUs)" -Level Warning
            }
            catch {
                Write-ScriptLog "Member GPO may already be linked" -Level Warning
            }

            # Configure Print Operators group membership for Allow_NetwkstaUserEnum group (session enumeration)
            Write-ScriptLog "Configuring Print Operators group membership for SharpHound session enumeration" -Level Info
            $allowNetworkUserEnumGroup = "$($rootDomain.NetBIOSName)\Allow_NetwkstaUserEnum"
            Set-GPOLocalGroupMembership -GPOName $memberGPOName -LocalGroupName 'Print Operators' -Members @($allowNetworkUserEnumGroup) -Domain $domain.DNSRoot -Server $domain.PDCEmulator

            # Configure registry settings via Group Policy Preferences
            Write-ScriptLog "Configuring registry settings for $($domain.DNSRoot)..." -Level Info

            # Remote SAM access configuration
            $remoteSAMSDDL = "O:BAG:BAD:(A;;RC;;;$($groups['Allow_SamConnect'].SID))(A;;RC;;;BA)"

            Set-GroupPolicyRegistryValue -GPOId $dcGPO.Id -Key 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' -ValueName 'RestrictRemoteSam' -Value $remoteSAMSDDL -Type 'String' -Order 1 -Domain $domain.DNSRoot -Server $domain.PDCEmulator -EnableRollback:$RollbackEnabled
            Set-GroupPolicyRegistryValue -GPOId $memberGPO.Id -Key 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' -ValueName 'RestrictRemoteSam' -Value $remoteSAMSDDL -Type 'String' -Order 1 -Domain $domain.DNSRoot -Server $domain.PDCEmulator -EnableRollback:$RollbackEnabled

            # Remote registry access configuration
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

            Set-GroupPolicyRegistryValue -GPOId $dcGPO.Id -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths' -ValueName 'Machine' -Value $dcRegistryPaths -Type 'MultiString' -Order 2 -Domain $domain.DNSRoot -Server $domain.PDCEmulator -EnableRollback:$RollbackEnabled
            Set-GroupPolicyRegistryValue -GPOId $memberGPO.Id -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths' -ValueName 'Machine' -Value $memberRegistryPaths -Type 'MultiString' -Order 2 -Domain $domain.DNSRoot -Server $domain.PDCEmulator -EnableRollback:$RollbackEnabled

            Write-ScriptLog "Completed configuration for domain: $($domain.DNSRoot)" -Level Success
        }
        else {
            Write-ScriptLog "[WhatIf] Would configure domain: $($domain.DNSRoot)" -Level Info
        }
    }

    # Final summary
    Write-ScriptLog "SharpHound Least Privilege gMSA setup completed successfully!" -Level Success
    Write-ScriptLog "Summary:" -Level Info
    Write-ScriptLog "- Created gMSA: $GMSAName" -Level Info
    Write-ScriptLog "- Created 5 security groups for delegated permissions" -Level Info
    Write-ScriptLog "- Configured GPOs for $($domainsArray.Count) domains" -Level Info
    Write-ScriptLog "- Applied least-privilege registry settings" -Level Info

    Write-ScriptLog "Next steps:" -Level Info
    Write-ScriptLog "1. Test gMSA installation on collector computer: Install-ADServiceAccount -Identity $GMSAName" -Level Info
    Write-ScriptLog "2. Configure SharpHound to use gMSA: $GMSAName" -Level Info
    Write-ScriptLog "3. Force Group Policy update on target computers: gpupdate /force" -Level Info
    Write-ScriptLog "4. Test SharpHound collection with new least-privilege account" -Level Info
}
catch {
    Write-ScriptLog "Script execution failed: $_" -Level Error
    Write-ScriptLog "Stack trace: $($_.ScriptStackTrace)" -Level Error
    exit 1
}

#endregion
