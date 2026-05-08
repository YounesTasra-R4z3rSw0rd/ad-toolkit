#!/usr/bin/env python3
import sys, re, argparse, struct, subprocess
from impacket.smbconnection import SMBConnection
from impacket.smb3structs import FILE_READ_DATA

# Well-known SIDs
KNOWN_SIDS = {
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests",
    "S-1-5-32-548": "BUILTIN\\Account Operators",
    "S-1-5-32-549": "BUILTIN\\Server Operators",
    "S-1-5-32-550": "BUILTIN\\Print Operators",
    "S-1-5-32-551": "BUILTIN\\Backup Operators",
    "S-1-5-32-552": "BUILTIN\\Replicators",
    "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
    "S-1-5-32-559": "BUILTIN\\Performance Log Users",
    "S-1-1-0": "Everyone",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-18": "SYSTEM",
    "S-1-5-19": "LOCAL SERVICE",
    "S-1-5-20": "NETWORK SERVICE",
}

def read_smb_file(smb, tid, path):
    """Read a file from SMB share with read-only access"""
    fid = smb.openFile(tid, path, desiredAccess=FILE_READ_DATA)
    data = smb.readFile(tid, fid)
    smb.closeFile(tid, fid)
    return data

def resolve_sid_simple(ldap_url, bind_dn, password, base_dn, sid):
    """Resolve a SID using a fresh LDAP search via impacket"""
    if sid in KNOWN_SIDS:
        return KNOWN_SIDS[sid]
    try:
        import subprocess
        result = subprocess.run(
            ["ldapsearch", "-x", "-H", ldap_url, "-D", bind_dn, "-w", password,
             "-b", base_dn, f"(objectSid={sid})", "sAMAccountName"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.split("\n"):
            if line.startswith("sAMAccountName:"):
                return line.split(":")[1].strip()
    except:
        pass
    return sid

def get_gpo_displaynames(ldap_url, bind_dn, password, base_dn):
    """Get GPO GUID -> displayName mapping via ldapsearch"""
    gpo_names = {}
    try:
        import subprocess
        result = subprocess.run(
            ["ldapsearch", "-x", "-H", ldap_url, "-D", bind_dn, "-w", password,
             "-b", f"CN=Policies,CN=System,{base_dn}", "(objectClass=groupPolicyContainer)",
             "name", "displayName"],
            capture_output=True, text=True, timeout=15
        )
        current_name = None
        for line in result.stdout.split("\n"):
            if line.startswith("name:"):
                current_name = line.split(":")[1].strip()
            elif line.startswith("displayName:") and current_name:
                gpo_names[current_name] = line.split(":")[1].strip()
                current_name = None
    except:
        pass
    return gpo_names

def get_gpo_ou_links(ldap_url, bind_dn, password, base_dn, gpo_guid):
    """Find which OUs a GPO is linked to"""
    ous = []
    try:
        import subprocess
        # Strip braces for matching
        guid_clean = gpo_guid.strip("{}")
        result = subprocess.run(
            ["ldapsearch", "-x", "-H", ldap_url, "-D", bind_dn, "-w", password,
             "-b", base_dn, f"(&(objectClass=organizationalUnit)(gpLink=*{guid_clean}*))",
             "name", "distinguishedName"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.split("\n"):
            if line.startswith("dn:"):
                ous.append(line.split(":", 1)[1].strip())
    except:
        pass
    return ous

def get_ou_computers(ldap_url, bind_dn, password, ou_dn):
    """List computers in an OU"""
    computers = []
    try:
        import subprocess
        result = subprocess.run(
            ["ldapsearch", "-x", "-H", ldap_url, "-D", bind_dn, "-w", password,
             "-b", ou_dn, "(objectClass=computer)", "sAMAccountName", "dNSHostName"],
            capture_output=True, text=True, timeout=10
        )
        current = {}
        for line in result.stdout.split("\n"):
            if line.startswith("sAMAccountName:"):
                current["name"] = line.split(":")[1].strip()
            elif line.startswith("dNSHostName:"):
                current["dns"] = line.split(":")[1].strip()
            elif line == "" and current:
                if "name" in current:
                    computers.append(current)
                current = {}
    except:
        pass
    return computers

def parse_memberof(line):
    """Parse a __Memberof line and return the target SID"""
    match = re.match(r'\*?(S-[\d-]+)__Memberof\s*=\s*\*?(S-[\d-]+)', line)
    if match:
        return match.group(1), match.group(2), "Memberof"
    return None, None, None

def parse_members(line):
    """Parse a __Members line"""
    match = re.match(r'\*?(S-[\d-]+)__Members\s*=\s*(.*)', line)
    if match:
        return match.group(1), match.group(2).strip(), "Members"
    return None, None, None

def main():
    parser = argparse.ArgumentParser(
        description="Enumerate GPO security settings from SYSVOL — Restricted Groups, GPP passwords, scheduled tasks, scripts, and user rights",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s -u user -p pass -d domain.local -t dc01                    # Full enumeration
  %(prog)s -u user -p pass -d domain.local -t dc01 --restricted-only   # Only Restricted Groups with full resolution"""
    )
    parser.add_argument("-u", "--user", required=True, help="Username")
    parser.add_argument("-p", "--password", required=True, help="Password")
    parser.add_argument("-d", "--domain", required=True, help="Domain FQDN (e.g., us.techcorp.local)")
    parser.add_argument("-t", "--target", required=True, help="DC hostname or IP")
    parser.add_argument("--port", default=445, type=int, help="SMB port (default: 445)")
    parser.add_argument("--restricted-only", action="store_true", help="Only enumerate Restricted Groups with full SID resolution and GPO-to-OU mapping")
    args = parser.parse_args()

    ldap_url = f"ldap://{args.target}"
    bind_dn = f"{args.user}@{args.domain}"
    domain_parts = args.domain.split(".")
    base_dn = ",".join([f"DC={p}" for p in domain_parts])

    print(f"[*] Connecting to {args.target}...")
    smb = SMBConnection(args.target, args.target, sess_port=args.port)
    smb.login(args.user, args.password, args.domain)
    print(f"[+] Authenticated as {args.domain}\\{args.user}")

    tid = smb.connectTree("SYSVOL")

    # Get GPO display names via LDAP
    print(f"[*] Resolving GPO display names...")
    gpo_names = get_gpo_displaynames(ldap_url, bind_dn, args.password, base_dn)

    # List GPO folders in SYSVOL
    base_path = f"{args.domain}/Policies"
    try:
        gpo_dirs = smb.listPath("SYSVOL", f"{base_path}/*")
    except Exception as e:
        print(f"[-] Failed to list {base_path}: {e}")
        return

    found_restricted = False
    for entry in gpo_dirs:
        dirname = entry.get_longname()
        if not dirname.startswith("{"):
            continue

        inf_path = f"{base_path}/{dirname}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf"
        try:
            data = read_smb_file(smb, tid, inf_path)
            try:
                content = data.decode("utf-16-le")
            except:
                content = data.decode("utf-8", errors="ignore")
        except:
            continue

        # --- RESTRICTED GROUPS ---
        if "Group Membership" in content:
            found_restricted = True
            gpo_display = gpo_names.get(dirname, dirname)
            print(f"\n{'='*70}")
            print(f"[+] RESTRICTED GROUPS — GPO: {gpo_display} ({dirname})")
            print(f"{'='*70}")

            # Find which OUs this GPO is linked to
            linked_ous = get_gpo_ou_links(ldap_url, bind_dn, args.password, base_dn, dirname)

            # Parse the Group Membership section
            in_section = False
            memberof_entries = []
            for line in content.split("\n"):
                line = line.strip()
                if line == "[Group Membership]":
                    in_section = True
                    continue
                if in_section:
                    if line.startswith("[") or line == "":
                        break

                    source_sid, target_sid, rel_type = parse_memberof(line)
                    if source_sid and target_sid and rel_type == "Memberof":
                        memberof_entries.append((source_sid, target_sid))
                        continue

                    source_sid, members, rel_type = parse_members(line)
                    # Members line — skip if empty
                    continue

            # Resolve and display
            for source_sid, target_sid in memberof_entries:
                source_name = resolve_sid_simple(ldap_url, bind_dn, args.password, base_dn, source_sid)
                target_name = resolve_sid_simple(ldap_url, bind_dn, args.password, base_dn, target_sid)

                print(f"\n    [>] {source_name} ({source_sid})")
                print(f"        is pushed into → {target_name} ({target_sid})")

                if linked_ous:
                    print(f"\n        GPO is linked to:")
                    for ou_dn in linked_ous:
                        print(f"          OU: {ou_dn}")
                        computers = get_ou_computers(ldap_url, bind_dn, args.password, ou_dn)
                        if computers:
                            print(f"          Affected machines:")
                            for comp in computers:
                                dns = comp.get('dns', 'N/A')
                                print(f"            - {comp['name']} ({dns})")
                        else:
                            print(f"          (no computers in this OU)")

                    # Human-readable summary
                    print(f"\n    [!] SUMMARY: '{source_name}' has local admin on:", end="")
                    all_computers = []
                    for ou_dn in linked_ous:
                        all_computers.extend(get_ou_computers(ldap_url, bind_dn, args.password, ou_dn))
                    if all_computers:
                        comp_names = [c['name'] for c in all_computers]
                        print(f" {', '.join(comp_names)}")
                    else:
                        print(f" (no computers found in linked OUs)")

            print()

        # --- USER RIGHTS ASSIGNMENT ---
        if not args.restricted_only and "Privilege Rights" in content:
            gpo_display = gpo_names.get(dirname, dirname)
            print(f"\n[+] User Rights Assignment found in GPO: {gpo_display} ({dirname})")
            in_section = False
            for line in content.split("\n"):
                line = line.strip()
                if line == "[Privilege Rights]":
                    in_section = True
                    continue
                if in_section:
                    if line.startswith("[") or line == "":
                        break
                    print(f"    {line}")

    # --- GPP PASSWORDS ---
    if not args.restricted_only:
        print(f"\n[*] Checking for GPP Groups.xml (cpassword)...")
        for entry in gpo_dirs:
            dirname = entry.get_longname()
            if not dirname.startswith("{"):
                continue

            xml_path = f"{base_path}/{dirname}/MACHINE/Preferences/Groups/Groups.xml"
            try:
                data = read_smb_file(smb, tid, xml_path)
                content = data.decode("utf-8", errors="ignore")
                gpo_display = gpo_names.get(dirname, dirname)
                print(f"\n[+] Groups.xml found in GPO: {gpo_display} ({dirname})")
                if "cpassword" in content:
                    print(f"    [!] cpassword FOUND — potential cleartext credentials!")
                    for line in content.split("\n"):
                        if "cpassword" in line:
                            print(f"    {line.strip()}")
                else:
                    print(f"    (no cpassword)")
            except:
                continue

        # --- SCHEDULED TASKS ---
        print(f"\n[*] Checking for Scheduled Tasks via GPO...")
        for entry in gpo_dirs:
            dirname = entry.get_longname()
            if not dirname.startswith("{"):
                continue

            xml_path = f"{base_path}/{dirname}/MACHINE/Preferences/ScheduledTasks/ScheduledTasks.xml"
            try:
                data = read_smb_file(smb, tid, xml_path)
                content = data.decode("utf-8", errors="ignore")
                gpo_display = gpo_names.get(dirname, dirname)
                print(f"\n[+] ScheduledTasks.xml found in GPO: {gpo_display} ({dirname})")
            except:
                continue

        # --- LOGON/STARTUP SCRIPTS ---
        print(f"\n[*] Checking for logon/startup scripts...")
        script_paths = [
            "MACHINE/Scripts/Startup",
            "MACHINE/Scripts/Shutdown",
            "USER/Scripts/Logon",
            "USER/Scripts/Logoff",
        ]
        for entry in gpo_dirs:
            dirname = entry.get_longname()
            if not dirname.startswith("{"):
                continue

            for sp in script_paths:
                try:
                    scripts = smb.listPath("SYSVOL", f"{base_path}/{dirname}/{sp}/*")
                    for s in scripts:
                        sname = s.get_longname()
                        if sname in [".", ".."]:
                            continue
                        if sname.endswith((".ps1", ".bat", ".cmd", ".vbs")):
                            gpo_display = gpo_names.get(dirname, dirname)
                            print(f"[+] Script found: {gpo_display} → {sp}/{sname}")
                except:
                    continue

    if not found_restricted:
        print(f"\n[-] No Restricted Groups found in any GPO")

    smb.logoff()
    print(f"\n[*] Done")

if __name__ == "__main__":
    main()
