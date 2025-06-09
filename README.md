# Least-Privilege SharpHound

Repository of scriptlets and documentation on achieving least-privilege data collection with SharpHound.

# Questions:

- What privileges are required for session enumeration?
- What privileges are required for local group collection?
- Is there any conflict between BHE data collection and protection of MDE (e.g. for session collection)?
- What other information can we gain from connecting to all systems (e.g. SMB signing configuration)?
- What attack paths are opened with this (e.g. are credentials of the collection user left on the systems through interactive logon, …)?
- What hardening can we apply?

## Registry Configuration

SharpHound captures via RemoteRegistry

## Local Groups

SharpHound captuers via SamConnect()

## Session Data

SharpHound captures via NetwkstaUserEnum()

## User Rights Assignments

SharpHound captures via LSAOpenPolicy() and LSAEnumerateAccountsWithUserRight()

## Relay Attack Surface

<Jim is currently unsure if this requires any privilege>
