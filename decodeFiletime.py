#!/usr/bin/env python3
import sys

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <filetime-value>")
    print(f"Example: {sys.argv[0]} -36288000000000")
    print(f"\nConverts Windows FILETIME values (100-nanosecond intervals) to human-readable format.")
    print(f"Common in AD attributes: maxPwdAge, minPwdAge, lockoutDuration, lockoutObservationWindow")
    sys.exit(1)

val = int(sys.argv[1])

if val == 0:
    print("Value: 0 → Not set / None")
    sys.exit(0)

if val == -9223372036854775808:
    print("Value: Never expires")
    sys.exit(0)

minutes = val / -600000000
hours = minutes / 60
days = hours / 24

if days >= 1:
    print(f"{days:.1f} days ({hours:.1f} hours)")
elif hours >= 1:
    print(f"{hours:.1f} hours ({minutes:.0f} minutes)")
else:
    print(f"{minutes:.0f} minutes")
