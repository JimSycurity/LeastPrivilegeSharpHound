# SharpHound SMB Least-Privilege Collection

SharpHound utilizes SMB over 445/tcp to determine if a computer object is active.

# Questions:

1. **Can SMBv3 be enforced on all hosts (servers) and still allow SharpHound collection?**
   - Yes

# Notes:

SharpHound utilizes standard SMB libraries. In lab testing I was able to demonstrate that SharpHound can collect data from a host when SMBv3 is enforced on both the collector and the remote host.

# References:
