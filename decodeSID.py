#!/usr/bin/env python3
import sys, base64, struct

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <base64-encoded-SID>")
    sys.exit(1)

data = base64.b64decode(sys.argv[1])
rev = data[0]
sub_count = data[1]
auth = int.from_bytes(data[2:8], 'big')
subs = [struct.unpack('<I', data[8+4*i:12+4*i])[0] for i in range(sub_count)]
print(f"S-{rev}-{auth}-" + "-".join(str(s) for s in subs))
