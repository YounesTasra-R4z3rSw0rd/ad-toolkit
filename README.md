# About
A collection of helper scripts for Active Directory penetration testing from Linux.
Built during CRTE lab work and real engagements. These are small, focused utilities that fill gaps in existing tooling — not replacements for Impacket, NetExec, or BloodHound, but things you reach for when those tools don't cover a specific need.

# Scripts

| Script | Description |
|---|---|
| `decode-sid.py` | Decodes base64-encoded Active Directory SIDs (as returned by `ldapsearch`) into human-readable format (`S-1-5-21-...`) |
| `decode-sid.py` | Converts Windows `FILETIME` values (100-nanosecond intervals) from AD attributes like `maxPwdAge`, `lockoutDuration`, etc. into human-readable durations |

# decodeSID
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
When you run `ldapsearch` against a DC, attributes like `maxPwdAge`, `minPwdAge`, `lockoutDuration` and `lockoutObservationWindow` come back as negative 100-nanosecond intervals (Windows FILETIME format). Seeing `-36288000000000` and knowing it means `42 days` isn't something you do in your head — `decodeFiletime.py` handles it.

## Usage
```bash
# Convert a FILETIME value from ldapsearch
python3 decodeFiletime.py -36288000000000
# Output: 42.0 days (1008.0 hours)

python3 decodeFiletime.py -18000000000
# Output: 30 minutes
```

## Requirements

* Python 3.6+
* No external dependencies
