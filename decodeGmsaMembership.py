#!/usr/bin/env python3
import sys, base64, struct

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <base64-encoded-msDS-GroupMSAMembership>")
    print(f"\nDecodes the binary security descriptor to show which principals can read the gMSA password.")
    sys.exit(1)

data = base64.b64decode(sys.argv[1])

# Parse SECURITY_DESCRIPTOR header
revision = data[0]
control = struct.unpack('<H', data[2:4])[0]
owner_offset = struct.unpack('<I', data[4:8])[0]
group_offset = struct.unpack('<I', data[8:12])[0]
sacl_offset = struct.unpack('<I', data[12:16])[0]
dacl_offset = struct.unpack('<I', data[16:20])[0]

def parse_sid(data, offset):
    rev = data[offset]
    sub_count = data[offset + 1]
    auth = int.from_bytes(data[offset + 2:offset + 8], 'big')
    subs = [struct.unpack('<I', data[offset + 8 + 4*i:offset + 12 + 4*i])[0] for i in range(sub_count)]
    return f"S-{rev}-{auth}-" + "-".join(str(s) for s in subs)

def sid_length(data, offset):
    sub_count = data[offset + 1]
    return 8 + 4 * sub_count

# Well-known SID mappings
KNOWN_SIDS = {
    "S-1-5-10": "SELF",
    "S-1-5-18": "SYSTEM",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-3-0": "CREATOR OWNER",
    "S-1-5-11": "Authenticated Users",
}

if dacl_offset == 0:
    print("No DACL present")
    sys.exit(0)

# Parse DACL
dacl_rev = data[dacl_offset]
dacl_size = struct.unpack('<H', data[dacl_offset + 2:dacl_offset + 4])[0]
ace_count = struct.unpack('<H', data[dacl_offset + 4:dacl_offset + 6])[0]

print(f"Principals allowed to read gMSA password ({ace_count} ACEs):\n")

offset = dacl_offset + 8
for i in range(ace_count):
    ace_type = data[offset]
    ace_flags = data[offset + 1]
    ace_size = struct.unpack('<H', data[offset + 2:offset + 4])[0]
    access_mask = struct.unpack('<I', data[offset + 4:offset + 8])[0]

    # ACE type 0 = ACCESS_ALLOWED_ACE
    if ace_type == 0:
        sid = parse_sid(data, offset + 8)
        name = KNOWN_SIDS.get(sid, sid)
        print(f"  ALLOW  {name}")
        print(f"         AccessMask: 0x{access_mask:08x}")
    # ACE type 5 = ACCESS_ALLOWED_OBJECT_ACE
    elif ace_type == 5:
        flags = struct.unpack('<I', data[offset + 8:offset + 12])[0]
        sid_start = offset + 12
        if flags & 1:
            sid_start += 16
        if flags & 2:
            sid_start += 16
        sid = parse_sid(data, sid_start)
        name = KNOWN_SIDS.get(sid, sid)
        print(f"  ALLOW  {name}")
        print(f"         AccessMask: 0x{access_mask:08x}")

    offset += ace_size

print(f"\nSIDs shown as raw S-1-5-21-... need to be resolved against the domain.")
print(f"Run: ldapsearch -x -H ldap://dc.domain.local -D \"samaccountname@domain.local\" -w 'password' -b \"DC=domain,DC=local\" \"(objectSid={name})\" sAMAccountName objectClass")
