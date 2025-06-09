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

From [BloodHound Inner Workings Part 2](https://blog.compass-security.com/2022/05/bloodhound-inner-workings-part-2/):

> A Wireshark trace of a successful SharpHound call allows us to highlight the steps involved:
>
> 1. Establish an SMB connection to the remote host (Kerberos authentication)
> 2. Connect to the IPC$ share
> 3. Open the wkssvc named pipe (this is similar to opening a file with that name)
> 4. Bind to the wkssvc interface with UUID 6BFFD098-A112-3610-9833-46C3F87E345A using RPC over SMB
> 5. Interact using the Workstation Service Remote Protocol, call NetWkstaUserEnum
> 6. Close and logoff
>
> Authorization is performed at three different places in this trace:
>
> 1.  When we attempt to open the IPC$ share
> 2.  When we attempt to open the wkssvc pipe
> 3.  When we attempt to execute an RPC call via the pipe
>     This last part fails with a low-privileged user on newer Windows as we’ll see below.
>
> You can try it for yourself using the following Wireshark filter:
>
> ```
> ((smb2) || (wkssvc)|| (dcerpc) || (smb)) && !(smb2.ioctl.function == 0x001401fc)
> ```

Presumably, we can connect to the IPC$ share on the remote host because we can connect to the winreg pipe.

If a low-privileged principal fails on executing an RPC call on the wkssvc pipe, is there a security descriptor on that RPC interface that prevents access?

### Print Operators

I added ACE_Enum_NetSession_T1 to Print Operators on AADC01. This allowed enumeration via NetWkstaUserEnum:

```PowerShell
PS C:\Users\sa_SHCE> $aadc = @('AADC01')

PS C:\Users\sa_SHCE> NetWkstaUserEnum -ComputerName $aadc -Level 1

wkui1_username wkui1_logon_domain wkui1_oth_domains wkui1_logon_server
-------------- ------------------ ----------------- ------------------
jasea          MAGIC                                TELLERDC01
jasea          MAGIC                                TELLERDC01
AADC01$        MAGIC
AADC01$        MAGIC
AADC01$        MAGIC
AADC01$        MAGIC
AADC01$        MAGIC
AADC01$        MAGIC
AADC01$        MAGIC
AADC01$        MAGIC
AADC01$        MAGIC



PS C:\Users\sa_SHCE>
```

Additionally, adding the sa_SHCE account to the Print Operators group for the domain also allowed NetWkstaUserEnum on Domain Controllers:

```PowerShell
PS C:\Users\sa_SHCE> $DCs = @('TellerDC01', 'TellerDC02')

PS C:\Users\sa_SHCE> NetWkstaUserEnum -ComputerName $DCs -Level 1

wkui1_username wkui1_logon_domain wkui1_oth_domains wkui1_logon_server
-------------- ------------------ ----------------- ------------------
jasea          MAGIC                                TELLERDC01
jasea          MAGIC                                TELLERDC01
TELLERDC01$    MAGIC
TELLERDC01$    MAGIC
TELLERDC01$    MAGIC
TELLERDC01$    MAGIC
TELLERDC01$    MAGIC
TELLERDC01$    MAGIC
TELLERDC01$    MAGIC
TELLERDC01$    MAGIC
TELLERDC01$    MAGIC
TELLERDC01$    MAGIC
TELLERDC01$    MAGIC
jasea          MAGIC                                TELLERDC02
jasea          MAGIC                                TELLERDC02
TELLERDC02$    MAGIC
TELLERDC02$    MAGIC
TELLERDC02$    MAGIC
TELLERDC02$    MAGIC
TELLERDC02$    MAGIC



PS C:\Users\sa_SHCE>
```

Defanging the Print Operators group on Domain Controllers, and likely all other non-print server hosts, could be a viable path forward for lesser-privileged session enumeration.

Defanging Print Operators:

- Remove User Rights Assignments in GPO applied to Domain Controllers OU:
  - SeInteractiveLogonRight
  - SeLoadDriverPrivilege
  - SeShutdownPrivilege

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
- https://gist.github.com/rvazarkar/b984506baa4fda6963f70b0a8c0e251e
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wkst/55118c55-2122-4ef9-8664-0c1ff9e168f3
