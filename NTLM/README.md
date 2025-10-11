# SharpHound NTLM/Coercion/Relay Least-Privilege Collection

NTLM coercion and relay has been added to SharpHound collection recently.

# Questions:

1. What are the full requirements to properly collect relay and coercion data via SharpHound?

# Notes:

The script `Get-CertEnrollmentTest.ps1` is designed to mimic how SharpHound collects data on AD CS enrollment endpoints.

The JSON files in `NTLM\Data\Get-CertEnrollmentTest` are results from the `Get-CertEnrollmentTest.ps1` script ran against a CA server in my lab using a series of security principals that are members of nearly every domain and local security group possible.

The script `Get-DCLdapConfiguration.ps1` is designed to mimic how SharpHound collects data on LDAP configuration.

The JSON files in `NTLM\Data\Get-DCLdapConfiguration` are results from the `Get-DCLdapConfiguration.ps1` script ran against domain controllers in my lab using a series of security principals that are members of nearly every domain and local security group possible.

# Resources:
