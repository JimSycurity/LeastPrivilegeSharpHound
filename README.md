# Least-Privilege SharpHound

Repository of scriptlets and documentation on achieving least-privilege data collection with SharpHound.

# Questions:

- **What privileges are required for session enumeration?**
  - Adding the SharpHound collection account as a member of the builtin Print Operators group allows collection of this data. Group Policy Preferences can assist with configuring tiered collection. It is only necessary to add a collection account to the builtin domain Print Operators group if collecting sessions from Domain Controllers.
- **What privileges are required for local group collection?**
  - The SharpHound collection account can be configured with an Allow ACE on the DACL of the registry key HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RestrictRemoteSam. The preferred method to do this is via the GPO setting [Network access: Restrict clients allowed to make remote calls to SAM](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls)
- **Are there any conflicts between BHE data collection and protection of MDE (e.g. for session collection)?**
  - More research required
- **What other information can we gain from connecting to all systems (e.g. SMB signing configuration)?**
  - More research required
- **What attack paths are opened with this (e.g. are credentials of the collection user left on the systems through interactive logon, …)?**
  - All collection methods utilize [Network logon types](https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/reference-tools-logon-types), which do not cache credentials on the remote system. If a remote host configured for collection is configured with Kerberos Unconstrainted Delegation, then a Kerberos TGT for the service account may be captured on that host. To prevent this, ensure the collection service account is marked [sensitive and cannot be delegated](https://learn.microsoft.com/en-us/archive/blogs/poshchap/security-focus-analysing-account-is-sensitive-and-cannot-be-delegated-for-privileged-accounts). Additionally, if using a gMSA service account you may wish to test configuring it as a member of the [Protected Users](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/how-to-configure-protected-accounts) group for additional protections.

- **What hardening can we apply?**
  - Apply tiering principles to all SharpHound collection accounts
  - Utilize User Rights Assignments to deny interactive login and remote interactive login to all SharpHound collection accounts
  - Limit network traffic (SMB & RPC) required by SharpHound to only SharpHound collector hosts wherever possible.

## [Registry Configuration](/RemoteRegistry/README.md)

SharpHound captures registry configuration related to via RemoteRegistry. Keys related to certificate authentication are collected from Domain Controllers and Certificate Authorities. Keys related to NTLM Relay are captured from all hosts.

For remotely collecting registry data over the network via SharpHound there are two known feasible least-privilege approaches:

1. Create WinReg named pipe remote connection exceptions for specific registry paths. This will allow any Authenticated User to connect to the named pipe for those specific key paths. Security descriptors on the registry keys and subkeys provide granular control. Of the 2 exception options, AllowExactPaths is more secure as it does not allow access to subkeys over the winreg connection. If configuration via GPO is desired, this would be the ‘Network access: Remotely accessible registry paths’ setting.

2. Modify the DACL of the HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers\\winreg subkey by adding an Allow Read ACE with the trustee principal being a tier-appropriate domain local security group which is placed in a secure OU for that tier. Add the SharpHound collection service account for that tier into the corresponding security group. Security descriptors on the registry keys and subkeys provide granular control.

There is no perfect solution here. Each is a tradeoff between granting some trust across the entire winreg named pipe to the SharpHound collector account for that tier vs granting trust across explicit registry paths in the winreg named pipe to any Authenticated User.

## [Local Groups](/SAMR/README.md)

SharpHound captures local group data via SamConnect().

Least-privilege collection can be achieved by setting a correctly defined security descriptor in SDDL format in the HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RestrictRemoteSam registry key on each host. The security descriptor must grant the SharpHound collector account Standard_Rights_Read (0x020000).

The preferred method of delegating read access to the SharpHound service account is via the GPO setting [Network access: Restrict clients allowed to make remote calls to SAM](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls)

## [Session Data](/Sessions/README.md)

SharpHound Enterprise captures session data via NetwkstaUserEnum().

Least-privilege collection can be achieved by adding the SharpHound collector account to the builtin Print Operators of the remote host. Membership in the builtin domainlocal Print Operators group is only necessary for collecting session data on Domain Controllers.

## [User Rights Assignments](/Lsa/README.md)

SharpHound captures User Rights Assignments for Remote Desktop via LSAOpenPolicy() and LSAEnumerateAccountsWithUserRight().

There is **no known least-privilege method** to accurately collect this data. Parsing GPOs for specific Scope of Management(SoM) could provide partial data, however local security policy can also impact this configuration and this type of GPO parsing is not currently supported by SharpHound and BloodHound.

## [Relay Attack Surface](/NTLM/README.md)

No research performed.

## [SMB Signing and Encryption](/SMB%20Protocol/README.md)

SharpHound captures data with SMBv3 enforced.
