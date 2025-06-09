# Sharp Hound Session Least-Privilege Collection

For session enumeration, SharpHound primarily uses NetWkstaUserEnum. This is the only method SharpHound Enterprise currently uses. SharpHound CE can also fallback to enumerating sessions via NetSessionEnum and RemoteRegistry.

To be clear there are 3 session enumeration methods:

- NetWkstaUserEnum - All
- NetSessionEnum - SHCE
- RemoteRegistry - SHCE

# Questions:

1. Why exactly is Print Operators able to call NetwkstaUserEnum? Is this due to permissions on a NamedPipe or RPC interface? Is this a User Rights Assignment thing?
2. If this is a DACL or URA, what would be the best method to set least-privilege access by tier?

# Notes:

- The DACL which controls access for the NetSessionEnum() function is a REG_BINARY value located at HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\SrvsvcSessionInfo
  - NetSessionEnum() is a fairly well-known topic. There are multiple blogs on allowing lesser privileged access to NetSessionEnum().
  - ~~It's not Print Operators that are able to call NetwkstaUserEnum by default, it's Server Operators.~~ - I had NetSessionEnum() and NetWkstaUserEnum() conflated when I first looked at this. BHE uses only NetWkstaUserEnum(), so the NetSessionEnum() less-priv is not applicable.

NetSessionEnum:

```PowerShell
PS C:\Windows\system32> Get-CurrentACLs
Current ACL for NetSessionEnum

SecurityIdentifier AccessMask       AceType
------------------ ----------       -------
S-1-5-32-544           983059 AccessAllowed
S-1-5-32-549           983059 AccessAllowed
S-1-5-32-547           983059 AccessAllowed
S-1-5-4                     1 AccessAllowed
S-1-5-6                     1 AccessAllowed
S-1-5-3                     1 AccessAllowed


---------------------
No ACLs for RestrictRemoteSam found
```

From [Deconstructing Logon Session Enumeration](https://posts.specterops.io/deconstructing-logon-session-enumeration-0426b8452ef5):

> As Microsoft documentation says: “This list includes interactive, service, and batch logons” and “Members of the Administrators, and the Server, System, and Print Operator local groups can also view information.” This API call has different permission requirements and returns a different set of information than the NetSessionEnum API call; however, just like NetSessionEnum, the RPC server is implemented only via the \PIPE\wkssvc named pipe. Again, this blog from Compass Security goes into more detail about the requirements.

# References:

- https://learn.microsoft.com/en-us/windows/win32/api/lmwksta/nf-lmwksta-netwkstauserenum
- https://github.com/NotMedic/DogDoor
- https://gist.github.com/2XXE-SRA/e02f6e8e30457b0fcd9c9581f302dd18
- https://www.powershellgallery.com/packages/PSReflect-Functions/1.0/Content/netapi32%5CNetWkstaUserEnum.ps1
- https://posts.specterops.io/deconstructing-logon-session-enumeration-0426b8452ef5
  - https://github.com/SpecterOps/SharpHoundCommon/blob/v3/src/CommonLib/Processors/ComputerSessionProcessor.cs#L174
  - https://github.com/SpecterOps/SharpHoundCommon/blob/v3/src/CommonLib/Processors/ComputerSessionProcessor.cs#L48
  - https://github.com/SpecterOps/SharpHoundCommon/blob/v3/src/CommonLib/Processors/ComputerSessionProcessor.cs#L279
- https://learn.microsoft.com/en-us/windows/win32/api/lmshare/nf-lmshare-netsessionenum
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/c30de0d7-f503-441a-8789-89c69f81ad39
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/02b1f559-fda2-4ba3-94c2-806eb2777183
- https://www.bordergate.co.uk/session-enumeration-with-netsessionenum/
- https://github.com/idnahacks/NetCeasePlusPlus
- https://learn.microsoft.com/en-us/windows/win32/netmgmt/requirements-for-network-management-functions-on-servers-and-workstations
- https://learn.microsoft.com/en-us/windows/win32/netmgmt/requirements-for-network-management-functions-on-active-directory-domain-controllers
- https://blog.compass-security.com/2022/05/bloodhound-inner-workings-part-2/
