# About
A collection of helper scripts for Active Directory penetration testing from Linux.
Built during CRTE lab work and real engagements. These are small, focused utilities that fill gaps in existing tooling — not replacements for Impacket, NetExec, or BloodHound, but things you reach for when those tools don't cover a specific need.

# Scripts

| Script | Description |
|---|---|
| `decode-sid.py` | Decodes base64-encoded Active Directory SIDs (as returned by `ldapsearch`) into human-readable format (`S-1-5-21-...`) |

# decodeSID
## Context
When you run ldapsearch against a DC, attributes like objectSid and securityIdentifier come back as base64 blobs. Most guides tell you to pipe through a chain of `base64 -d | xxd | awk` — this just does it cleanly in one command.

## Usage

```bash
# Decode a base64 SID from ldapsearch output
python3 decode-sid.py "AQQAAAAAAAUVAAAAw5SODBZBSpaM7roJ"
# Output: S-1-5-21-210670787-2521448726-163245708
```

## Requirements

* Python 3.6+
* No external dependencies
