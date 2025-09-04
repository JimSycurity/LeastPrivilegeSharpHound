# Todo convert entire script to a function and parameterize these values
$gmsaName = 'LP_gMSA_SHS' # Name of the gMSA
$targetOUDN = 'OU=Tier0,DC=magic,DC=lab,DC=lan' # Distinguished Name of OU to create objects in
$collector = 'BHECollector$'

Import-Module ActiveDirectory
Import-Module GroupPolicy

<#
 Function to Get Domains in Forest
#>
## TODO convert this to a function
$forest = Get-ADForest
$domainsArray = foreach ($domain in $forest.Domains) {
    Get-ADDomain -Identity $domain -ErrorAction SilentlyContinue
}

<#
 Create Groups
#>

# gMSA password retrieval group
New-ADGroup `
    -Name "$($gmsaName)_pwdRead" `
    -GroupScope Global `
    -GroupCategory Security `
    -Path $targetOUDN `
    -Description "This group grants the rights to retrieve the password of the BloodHound data collector (SharpHound) gMSA '$gmsaName'." `
    -PassThru

# Deleted Objects read group
$DeletedObjects_Read = New-ADGroup `
    -Name "DeletedObjects_Read" `
    -GroupScope Global `
    -GroupCategory Security `
    -Path $targetOUDN `
    -Description "This group grants the rights to read the Deleted Objects container(s) of the forest" `
    -PassThru

# Local Group Membership read group
$Allow_SamConnect = New-ADGroup `
    -Name "Allow_SamConnect" `
    -GroupScope Global `
    -GroupCategory Security `
    -Path $targetOUDN `
    -Description "This group grants the rights to perform remote SAM connections" `
    -PassThru

# Session Enumeration
$Allow_NetwkstaUserEnum = New-ADGroup `
    -Name "Allow_NetwkstaUserEnum" `
    -GroupScope Global `
    -GroupCategory Security `
    -Path $targetOUDN `
    -Description "This group grants the rights to enumerate sessions via nested membership in Print Operators" `
    -PassThru

# Remote Registry Enumeration
$Allow_WinReg = New-ADGroup `
    -Name "Allow_WinReg" `
    -GroupScope Global `
    -GroupCategory Security `
    -Path $targetOUDN `
    -Description "This group grants the rights to perform remote registry reads" `
    -PassThru


<#
 Create Service Account
#>

# Create gMSA for SharpHound Service
$gmsa = New-ADServiceAccount -Name $gmsaName `
    -Description 'SharpHound service account for BloodHound' `
    -DNSHostName "$($gmsaName).$((Get-ADDomain).DNSRoot)" `
    -ManagedPasswordIntervalInDays 32 `
    -PrincipalsAllowedToRetrieveManagedPassword "$($gmsaName)_pwdRead" `
    -Enabled $True `
    -AccountNotDelegated $True `
    -KerberosEncryptionType AES128,AES256 `
    -Path $targetOUDN `
    -PassThru

# Grant Access to the Deleted Objects Container
## Build ACL
$group = Get-ADGroup -Identity 'DeletedObjects_Read'
$identity = [System.Security.Principal.SecurityIdentifier]::new($group.sid)
$ADRight = [System.DirectoryServices.ActiveDirectoryRights] "GenericRead"
$type = [System.Security.AccessControl.AccessControlType] "Allow"
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $ADRight, $type)

## Determine Deleted Objects container for each domain in forest & add access rule
Set-Location AD:
foreach ($domain in $domainsArray) {
    # TODO: need to set current user as owner first and then switch it back to DA after
    $acl = Get-Acl -Path $domain.DeletedObjectsContainer
    $acl.AddAccessRule($rule)
    Set-Acl -path $($domain.DeletedObjectsContainer) -AclObject $ACL
}

## Determine Configuration NC Deleted Objects container & add access rule
$configNC = (Get-ADRootDSE).configurationNamingContext
$acl =  Get-Acl -Path $configNC
$acl.AddAccessRule($rule)
Set-Acl -Path $configNC -AclObject $ACL


<#
 Group Memberships
#>

# Add Allow_NetwkstaUserEnum to Print Operators group (for each domain in forest)
foreach ($domain in $domainsArray) {
    Add-ADGroupMember -Identity 'Print Operators' -Server $($domain.PDCEmulator) -Members $Allow_NetwkstaUserEnum
}

# Add SharpHound Collector Server to pwdRead group
$collectorObject = Get-ADComputer -Identity $collector
Add-ADGroupMember -Identity "$($gmsaName)_pwdRead" -Members $collectorObject

# Add gMSA to delegation groups: DeletedObjects_Read, Allow_SamConnect, Allow_NetwkstaUserEnum, Allow_WinReg
Add-ADGroupMember -Identity $DeletedObjects_Read -Members $gmsa
Add-ADGroupMember -Identity $Allow_SamConnect -Members $gmsa
Add-ADGroupMember -Identity $Allow_NetwkstaUserEnum -Members $gmsa
Add-ADGroupMember -Identity $Allow_WinReg -Members $gmsa


<#
 Local Group Memberships & Registry settings via Group Policy Preferences
#>

foreach ($domain in $domainsArray) {
# Create New GPOs
New-GPO -Name 'SharpHound Collector - Least Privilege - DCs' -Comment 'Configure Least-Privilege Access for SharpHound collection on Domain Controllers' -Domain $domain -Server $($domain.PDCEmulator)
New-GPO -Name 'SharpHound Collector - Least Privilege - Members' -Comment 'Configure Least-Privilege Access for SharpHound collection on non-DCs' -Domain $domain -Server $($domain.PDCEmulator)

# GPPs


# Link GPOs
$dcGPO = Get-GPO -Name 'SharpHound Collector - Least Privilege - DCs'  -Domain $domain -Server $($domain.PDCEmulator)
$memberGPO = Get-GPO -Name 'SharpHound Collector - Least Privilege - Members'  -Domain $domain -Server $($domain.PDCEmulator)

New-GPLink -Guid $dcGPO.Id -Target "OU=Domain Controllers,$($domain.DistinguishedName)" -LinkEnabled Yes -Order 1
New-GPLink -Guid $memberGPO.Id -Target "$($domain.DistinguishedName)" -LinkEnabled Yes -Order 1  # NOTE: Ideally this would be individually linked to OUs where workstation and server objects are located instead of at Domain Root

$remoteSAMSDDL = "O:BAG:BAD:(A;;RC;;;$($Allow_SamConnect.SID)(A;;RC;;;BA)"
$params = @{
    Context = 'Computer'
    Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
    ValueName = 'RestrictRemoteSam'
    Value = $remoteSAMSDDL
    Type = 'String'
    Action = 'Update'
    Domain = $domain.DNSRoot
    Server = $domain.PDCEmulator
}
Set-GPPrefRegistryValue -Guid $dcGPO @params
Set-GPPrefRegistryValue -Guid $memberGPO @params


