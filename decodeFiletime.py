#!/usr/bin/env python3
import sys
from datetime import datetime, timedelta

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <filetime-value>")
    print(f"\nExamples:")
    print(f"  {sys.argv[0]} -36288000000000        # Relative (maxPwdAge, lockoutDuration)")
    print(f"  {sys.argv[0]} 134182246383416108      # Absolute (pwdLastSet, lastLogonTimestamp)")
    sys.exit(1)

val = int(sys.argv[1])

if val == 0:
    print("Never / Not set")
    sys.exit(0)

if val == 9223372036854775807 or val == -9223372036854775808:
    print("Never expires")
    sys.exit(0)

# Negative = relative duration (policy attributes)
if val < 0:
    minutes = val / -600000000
    hours = minutes / 60
    days = hours / 24
    if days >= 1:
        print(f"{days:.1f} days ({hours:.1f} hours)")
    elif hours >= 1:
        print(f"{hours:.1f} hours ({minutes:.0f} minutes)")
    else:
        print(f"{minutes:.0f} minutes")

# Positive = absolute timestamp (100-nanosecond intervals since 1601-01-01)
else:
    epoch = datetime(1601, 1, 1) + timedelta(microseconds=val // 10)
    age = datetime.now() - epoch
    print(f"{epoch.strftime('%Y-%m-%d %H:%M:%S UTC')} ({age.days} days ago)")
