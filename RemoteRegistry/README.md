# SharpHound Registry Least-Privilege Collection

SharpHound currently utilizes Remote Registry to capture key registry data from Domain Controllers, AD CS Certificate Authorities, and domain-joined workstations and servers.

Remote Registry access for the purposes of collecting this data requires:

- Network access from client to server via SMB (tcp445)\
- Remote Registry service to be running on both the client and the server
- Permissions to open a handle to the \\PIPE\\winreg named pipe with Read access rights
- Permission granted to open the registry Key with Read access
- Permissions granted on the specific registry SubKeys with Read access

There are two methods to provide remote registry access without Administrator privileges on the remote host:

1. Configure DACL on the HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers\\winreg subkey
2. Create an exception to the winreg subkey DACL using either:
   a. HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers\\winreg\\AllowedExactPaths
   b. HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers\\winreg\\AllowedPaths

Both methods 1 and 2 can be configured manually, with scripting, or via GPO. Neither of these methods will override DACLs configured on the registry key or subkey level.

All registry subkeys that SharpHound can currently collect have DACLs in the registry which permit Authenticated Users or Builtin Users to read the subkey and its data. An unprivileged principal on host is a different scenario than any principal remotely from a security aspect.

Across data gathered in my lab from Windows Server 2012 R2, Windows Server 2019, and Windows Server 2025 there are between 61 and 69 total subkeys in the registry paths that SharpHound desires to collect. Of those, only 4 or 5 of those subkeys do not grant unprivileged principals KeyRead rights.

For remotely collecting registry data over the network via SharpHound there are two known feasible approaches:

1. Create WinReg named pipe remote connection exceptions for specific registry paths. This will allow any Authenticated User to connect to the named pipe for those specific key paths. Security descriptors on the registry keys and subkeys provide granular control. Of the 2 exception options, AllowExactPaths is more secure as it does not allow access to subkeys over the winreg connection. If configuration via GPO is desired, this would be the ‘Network access: Remotely accessible registry paths’ setting.

2. Modify the DACL of the HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers\\winreg subkey by adding an Allow Read ACE with the trustee principal being a tier-appropriate domain local security group which is placed in a secure OU for that tier. Add the SharpHound collection service account for that tier into the corresponding security group. Security descriptors on the registry keys and subkeys provide granular control.

There is no perfect solution here. Each is a tradeoff between granting some trust across the entire winreg named pipe to the SharpHound collector for that tier vs granting trust across explicit registry paths in the winreg named pipe to any Authenticated User.

Additional Remote Registry attack surface reduction considerations:

- For all but Domain Controllers and File servers, restrict inbound SMB (tcp445) traffic from all but SharpHound collector host(s) and other management or administrative hosts at the network or host’s network layer.

- Consider whether the Remote Registry service needs to be always running. Is it feasible for this service to be started only during times when it is necessary? Service start and stop can be orchestrated. A simple option could be utilizing Scheduled Tasks, perhaps pushed out via GPO. The event trigger for the task to start Remote Registry could be a timeframe. It could also be an event, such as a successful logon from the SharpHound collector host. This may not be feasible if Remote Registry is required for other administrative, management, or posture activities.

- Adding the SharpHound collector, via group membership as a trustee granted Allow Read access on the winreg subkey to enable registry-wide access for the collection account can be offset with targeted Deny ACEs in the registry hierarchy. Well-known highly-sensitive registry paths do not grant allow access to non-privileged principals by default.

- Deny ACEs could also be utilized in the registry hierarchy in instances where the AllowedPaths or AllowedExactPaths winreg exemptions are used. However, it is more challenging to deny access to Authenticated Users and allow access to the SharpHound collector along with the other required principals such as SYSTEM, Administrators, Backup Operators, All Application Packages, etc. Without carefully crafted combinations of inherited deny ACEs with explicit allow ACEs this strategy is impossible. Even with perfectly crafted ACEs and a very targeted set of registry paths this method would be troublesome.

**Registry Paths:**

- Domain Controllers
  - SYSTEM\\CurrentControlSet\\Services\\Kdc
    - StrongCertificateBindingEnforcement
  - SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL
    - CertificateMappingMethods
- Certificate Authorities
  - SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{caName}
    - Security
    - EnrollmentAgentRights
    - RoleSeparationEnabled
  - SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{caName}\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy
    - EditFlags
- All Hosts (NTLM Relay)
  - SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0
    - ClientAllowedNTLMServers
    - NtlmMinClientSec
    - NtlmMinServerSec
    - RestrictReceivingNTLMTraffic
    - RestrictSendingNTLMTraffic
  - SYSTEM\\CurrentControlSet\\Control\\Lsa
    - LMCompatibilityLevel
    - UseMachineId
  - SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters
    - EnableSecuritySignature
    - RequireSecuritySignature

_Note: Microsoft AD CS role automatically creates a remote registry path exception in the HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers\\winreg\\AllowedPaths\\Machine value. If making modifications to AllowedPaths via GPO be mindful of this when scoping the policy._

# Remaining Questions:

# Notes:

Per [Remote Hash Extraction On Demand Via Host Security Descriptor Modification](https://blog.harmj0y.net/activedirectory/remote-hash-extraction-on-demand-via-host-security-descriptor-modification/) there are sensitive keys in the HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa path:

- HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\JD
- HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Skew1
- HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Data
- HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\GBG
  Per data collected from my lab (<computername>-Get-SharpHoundSubKeyPermissions0n.txt), all four of these registry keys provide no access to a standard user account.

Per the same blog, additional sensitive registry keys:

- HKEY_LOCAL_MACHINE\SECURITY\Policy\PolEKList
- HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\$MACHINE.ACC\CurrVal
- HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users
- HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\NL$KM\CurrVal
- HKEY_LOCAL_MACHINE\SECURITY\Cache\NL$<1-10>
  None of these overlap the paths SharpHound uses, so I haven't yet collected data on their DACLs.

TODO: It bears further investigation to determine if a standard user account granted Read permissions on WinReg could possibly read these keys.

# Resources:

- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-remotely-accessible-registry-paths
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-remotely-accessible-registry-paths-and-subpaths
- https://bloodhound.specterops.io/collect-data/enterprise-collection/permissions#dc-registry
- https://bloodhound.specterops.io/collect-data/enterprise-collection/permissions#ca-registry
- https://blog.harmj0y.net/activedirectory/remote-hash-extraction-on-demand-via-host-security-descriptor-modification/
