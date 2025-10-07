# SharpHound SMB Least-Privilege Collection

SharpHound utilizes SMB over 445/tcp to determine if a computer object is active.

# Questions:

1. **Can SMBv3 be enforced on all hosts (servers) and still allow SharpHound collection?**
   - Yes

# Notes:

SharpHound utilizes standard SMB libraries. In lab testing I was able to demonstrate that SharpHound can collect data from a host when SMBv3 is enforced on both the collector and the remote host.

The script `Get-SMBServer.ps1` generally replicates SMB checks that SharpHound may perform against target devices for the purpose of determining NTLM relay capabilities.

The JSON files in `SMB Protocol\Data\Get-SMBServer` are results from the `Get-SMBServer.ps1` script ran against a small domain in my lab using a series of security principals that are members of nearly every domain and local security group possible.

# References:
