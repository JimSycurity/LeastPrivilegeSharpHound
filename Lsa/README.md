# SharpHound User Rights Assignment Least-Privilege Collection

SharpHound utilizes LSAOpenPolicy() and LSAEnumerateAccountsWithUserRight() to collect User Rights Assignments across hosts. This generally requires the SharpHound collection service account or principal to be a member of the Local Administrators group for that host.

# Questions:

1. Does SharpHound attempt to collect anything from Domain Controllers via LSA?
   - Only if you attempt to collect User Rights Assignment data from Domain Controllers.
2. Could we create documentation for creating GPPs that are linked to appropriate scopes of management to add appropriate tier SH collector accounts to correlating tier hosts?
   - Yes, is documented in my blog on least-privilege SharpHound collection.
3. Why is membership in Administrators required for this capability? Is there a DACL somewhere which only allows Administrators or is this hard-coded into the LSA server APIs?
   a. Is Administrators membership required to enumerate this locally on host or is this only for remote enumeration?

# Notes:

Based on queries with Claude.ai, it was suggested as a posibility that assigning a security principal SeAuditPrivilege or SeServiceLogonRight would provide sufficiant LSA read access. In initial testing, this did not appear to be the case. However, I did not validate at the time that these rights were active during the attempt, just assigned.

Additional suggestions from Claude were to delegate specific LSA permssions using LSAAddAccountRights() to grant:

- POLICY_VIEW_LOCAL_INFORMATION
- POLICY_LOOKUP_NAMES

The script `Test-LSAEnum.ps1` is designed to mimic how SharpHound collects User Rights Assignment data via LSAOpenPolicy and LSAEnumerateAccountsWithUserRight.

The JSON files in `Lsa\Data\Test-LSAEnum` are results from the `Test-LSAEnum.ps1` script ran against a small lab environment using a series of security principals that are members of nearly every domain and local security group possible.

The JSON files in `Lsa\Data\Test-LSAEnumv2` are results from the `Test-LSAEnum.ps1` script ran against a small lab environment using a series of security principals that are members of nearly every domain and local security group possible, but also attempting to activate the SeAuditPrivilege and SeServiceLogonRight privileges.

Regardless of the configuration, only members of the Administrators group (domain builtin for DCs and local for domain members) were able to enumerate User Rights via LSA.

# References:

- https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaopenpolicy
- https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaenumerateaccountswithuserright
- https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaenumerateaccountrights
- https://stackoverflow.com/questions/21252677/how-to-get-user-rights-and-privileges-of-a-windows-user-account
- https://syfuhs.net/a-bit-about-the-local-security-authority
- https://learn.microsoft.com/en-us/windows/win32/secmgmt/policy-object-access-rights
- https://github.com/blakedrumm/SCOM-Scripts-and-SQL/blob/master/Powershell/General%20Functions/Get-UserRights.ps1
