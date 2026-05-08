# About
A collection of helper scripts for Active Directory penetration testing from Linux.

Built during CRTE lab work and real engagements. These are small, focused utilities that fill gaps in existing tooling — not replacements for Impacket, NetExec, or BloodHound, but things you reach for when those tools don't cover a specific need.

# Table of Contents
- [decodeSid](#decodesid) — Base64 SID → `S-1-5-21-...`
- [decodeFiletime](#decodefiletime) — Windows FILETIME → human-readable dates & durations
- [decodeGmsaMembership](#decodegmsamembership) — gMSA security descriptor → who can read the password
- [enumGPO](#enumgpo) — GPO security settings → Restricted Groups, GPP passwords, scheduled tasks, scripts

# Scripts
| Script | Description |
|---|---|
| `decodeSid.py` | Decodes base64-encoded Active Directory SIDs (as returned by `ldapsearch`) into human-readable format (`S-1-5-21-...`) |
| `decodeFiletime.py` | Converts Windows `FILETIME` values from AD — negative values for relative durations (`maxPwdAge`, `lockoutDuration`), positive values for absolute timestamps (`pwdLastSet`, `lastLogonTimestamp`) |
| `decodeGmsaMembership.py` | Decodes the `msDS-GroupMSAMembership` binary security descriptor from base64 to show which principals can read a gMSA password |
| `enumGPO.py` | Enumerates GPO security settings from SYSVOL — Restricted Groups (with SID resolution + GPO-to-OU-to-computer mapping), GPP passwords, scheduled tasks, user rights assignments, and logon/startup scripts |

# decodeSid
## Context
When you run `ldapsearch` against a DC, attributes like `objectSid` and `securityIdentifier` come back as base64 blobs. Most guides tell you to pipe through a chain of `base64 -d | xxd | awk` — this just does it cleanly in one command.
## Usage
```bash
# Decode a base64 SID from ldapsearch output
python3 decodeSid.py "AQQAAAAAAAUVAAAAw5SODBZBSpaM7roJ"
# Output: S-1-5-21-210670787-2521448726-163245708
```
## Requirements
* Python 3.6+
* No external dependencies

# decodeFiletime
## Context
When you run `ldapsearch` against a DC, FILETIME values come in two flavors and both are unreadable raw:

* **Relative durations**: attributes like `maxPwdAge`, `minPwdAge`, `lockoutDuration` and `lockoutObservationWindow` come back as negative 100-nanosecond intervals. Seeing `-36288000000000` and knowing it means `42 days` isn't something you do in your head.

* **Absolute timestamps**: attributes like `pwdLastSet`, `lastLogonTimestamp` and `accountExpires` come back as positive 100-nanosecond intervals since January 1, 1601. Seeing `134182246383416108` means nothing until you convert it.

`decodeFiletime.py` detects the type automatically and converts both.

## Usage
```bash
# Relative durations (negative values — policy attributes)
python3 decodeFiletime.py -36288000000000
# Output: 42.0 days (1008.0 hours)

python3 decodeFiletime.py -18000000000
# Output: 30 minutes

# Absolute timestamps (positive values — user/computer attributes)
python3 decodeFiletime.py 134182246383416108
# Output: 2025-11-14 08:23:58 UTC (173 days ago)

python3 decodeFiletime.py 0
# Output: Never / Not set
```
## Requirements
* Python 3.6+
* No external dependencies

# decodeGmsaMembership
## Context
Group Managed Service Accounts (gMSAs) store who can read their password in the `msDS-GroupMSAMembership` attribute, a binary security descriptor. When you pull it with `ldapsearch`, you get a base64 blob.</br>
`decodeGmsaMembership.py` parses the security descriptor and shows which SIDs have access. Unresolved domain SIDs can be looked up with a follow-up `ldapsearch` query.

## Usage
```bash
# Get the gMSA info via ldapsearch
ldapsearch -x -H ldap://dc.domain.local -D "USERNAME@domain.local" -w 'PASSWORD' -b "DC=domain,DC=local" "(objectClass=msDS-GroupManagedServiceAccount)" sAMAccountName dNSHostName servicePrincipalName memberOf msDS-GroupMSAMembership msDS-ManagedPasswordInterval

# Decode the base64 blob (join multi-line output into one string)
python3 decodeGmsaMembership.py "AQAEgBQAAAAEAAAAAAAUV..."

# Resolve the SID to a name
ldapsearch -x -H ldap://dc.domain.local -D "USERNAME@domain.local" -w 'PASSWORD' -b "DC=domain,DC=local" "(objectSid=S-1-5-21-...)" sAMAccountName objectClass
```

## Requirements
* Python 3.6+
* No external dependencies

# enumGPO
## Context
On every internal pentest, one of the first questions is "who has local admin where?" Restricted Groups is a GPO mechanism that pushes principals into local Administrators on every machine the GPO applies to. </br>
</br>
BloodHound doesn't show ACL edges on OUs, and it doesn't parse SYSVOL for Restricted Groups. So this attack surface is invisible unless you check manually.</br>
</br> 
`enumGPO.py` does the full chain in one command: 
1. Connects to SYSVOL via SMB
2. Parses every GPO's `GptTmpl.inf` for Restricted Groups
3. Resolves SIDs via LDAP
4. Maps GPO to linked OUs
5. Lists computers in those OUs
6. Tells you in plain language who has local admin on which machines.
</br>
It also checks for GPP passwords (`cpassword`), scheduled tasks, user rights assignments, and logon/startup scripts.
 
## Usage
```bash
# Full enumeration — Restricted Groups, GPP passwords, scheduled tasks, scripts, user rights
proxychains -q python3 enumGPO.py -u USERNAME -p 'PASSWORD' -d domain.local -t dc01
 
# Restricted Groups only — with full SID resolution and GPO-to-OU-to-computer mapping
proxychains -q python3 enumGPO.py -u USERNAME -p 'PASSWORD' -d domain.local -t dc01 --restricted-only
```
 
Example output (`--restricted-only`):
```
[*] Connecting to dc01...
[+] Authenticated as domain.local\user
[*] Resolving GPO display names...
 
======================================================================
[+] RESTRICTED GROUPS — GPO: Mgmt ({B78BFC6B-76DB-4AA4-9CF6-26260697A8F9})
======================================================================
 
    [>] MachineAdmins (S-1-5-21-210670787-2521448726-163245708-1118)
        is pushed into → BUILTIN\Administrators (S-1-5-32-544)
 
        GPO is linked to:
          OU: OU=Mgmt,DC=us,DC=techcorp,DC=local
          Affected machines:
            - US-MGMT$ (US-Mgmt.us.techcorp.local)
 
    [!] SUMMARY: 'MachineAdmins' has local admin on: US-MGMT$
 
[*] Done
```
 
## Requirements
* Python 3.6+
* Impacket (`pip install impacket`)
* `ldapsearch` (from `ldap-utils` package — usually pre-installed on Kali)
