# SharpHound Local Group Membership Least-Privilege Collection

SharpHound utilizes SamConnect() to collect Local Group data. By default, local Administrator or SAM-R access is required to collect.

# Questions:

1. Is there any other least-privilege method to allow SAMR access beyond the 'Network access: Restrict clients allowed to make remote calls to SAM' GP setting?
   - No. This GPO setting configures the registry key below and there is no effective additional granularity by configuring raw SDDL.
2. If the GP setting is the best method, what is the appropriate least-privilege security descriptor in SDDL format for each collection tier?
   - AccessAllowed, StandardRightsRead, SIDofCollectorAccount

# Notes:

- The registry key for controlling SAM-R access is HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RestrictRemoteSam
- The Microsoft supported method to modify this registry value is via the Group Policy Setting [Network access: Restrict clients allowed to make remote calls to SAM](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls)
- By default, Domain Controllers allow anonymous access to the Netlogon, samr, and lsarpc Named Pipes per: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-named-pipes-that-can-be-accessed-anonymously

# Resources:

- https://bloodhound.specterops.io/collect-data/permissions#local-group-membership
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls
- https://github.com/NotMedic/DogDoor
- https://github.com/idnahacks/NetCeasePlusPlus
