# Sharp Hound Session Least-Privilege Collection

# Questions:

1. Why exactly is Print Operators able to call NetwkstaUserEnum? Is this due to permissions on a NamedPipe or RPC interface? Is this a User Rights Assignment thing?
2. If this is a DACL or URA, what would be the best method to set least-privilege access by tier?

# Notes:

# References:

- https://learn.microsoft.com/en-us/windows/win32/api/lmwksta/nf-lmwksta-netwkstauserenum
