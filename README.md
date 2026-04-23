```
 ██████╗██╗   ██╗██╗  ██╗███╗   ███╗
██╔════╝╚██╗ ██╔╝██║  ██║████╗ ████║
██║      ╚████╔╝ ███████║██╔████╔██║
██║       ╚██╔╝  ██╔══██║██║╚██╔╝██║
╚██████╗   ██║   ██║  ██║██║ ╚═╝ ██║
 ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚═╝     ╚═╝
    N O T E S  //  C Y H M  &  B E Y O N D
```

> A living, battle-tested Obsidian vault built over years of labs, CTFs, and Active Directory engagements.
> Commands are generic by default — set your target once, every note updates automatically.

These are the official notes behind the labs at **[canyouhack.me](https://canyouhack.me)** — a hands-on offensive security platform built for people who learn by doing. If you want an environment to actually use these notes in, check it out.

---

<video src="GlobalVarDemo.mp4" controls width="100%"></video>

---

## ⚡ Killer Feature — Live Command Injection

Open `Global Variables.md` and fill in your target details:

```yaml
Target-IP: 10.10.10.X
Username: administrator
Password: Passw0rd!
Domain: corp.local
DC Name: DC01
Password Hash: aabbccdd11223344aabbccdd11223344
Local IP: 10.10.14.X
```

Every note with a command block instantly updates to your target. No more find-and-replacing IPs across 400 files mid-engagement.

> Powered by the [Obsidian Dataview](https://github.com/blacksmithgu/obsidian-dataview) plugin — included in `.obsidian/`.

---

## 📂 What's Inside

| Section | Coverage |
|---|---|
| **AD** | Port recon, ADCS (ESC1/4/7/9), Kerberoasting, AS-REP Roasting, BloodHound paths, DCSync, Delegation, Shadow Creds, NTLM Relaying, Group abuse |
| **Port Enumeration** | 30+ ports — FTP, SSH, SMB, RDP, WinRM, LDAP, MSSQL, Oracle, Redis, NFS, SNMP and more |
| **Priv Esc — Windows** | Group abuse (Account Operators, Backup Operators, Server Operators, DNS Admins, Print Operators, LAPS, GPO), SeImpersonate, DLL hijacking, unquoted paths, kernel exploits |
| **Priv Esc — Linux** | SUID, cron abuse, sudo -l, writeable root files, service exploitation, restricted shell escapes |
| **Shells** | PHP, Python, Bash, PowerShell, Perl, Ruby, NC, ASPX, WAR, DLL, SO, BOF shellcode, Meterpreter |
| **Pivoting** | Chisel, Ligolo-ng, SSH tunnelling, proxychains |
| **Post Exploitation** | Windows & Linux enumeration, credential hunting, AV evasion, WinRM enabling |
| **BOF** | Windows and Linux buffer overflow notes |
| **Tools & Tricks** | Netexec, Hashcat, Wfuzz, Responder, Steghide, username generation, sed/awk/grep one-liners |

---

## 🚀 Setup

**Requirements:** [Obsidian](https://obsidian.md) (free)

```
1. Clone the repo
2. Open Obsidian → "Open folder as vault" → select PenTest-Notes-main/
3. Allow community plugins when prompted
4. Open Global Variables.md → set your target details
5. Watch every command in every note update live
```

---

## 🗂 Structure

Notes are organised by **scope**, not technique:

```
PenTest-Notes-main/
├── AD/                         # Active Directory — recon → domain admin
│   ├── 1. Ports/               # Per-port AD enumeration
│   ├── 2. Techniques/          # NTLM relay, Kerberos attacks, poisoning
│   ├── 3. Privilege Esc/       # BloodHound paths, manual enum
│   └── 4. Tools/               # Mimikatz, Netexec, Validate hashes
├── port enumeration/           # Per-port playbooks (30+ ports)
├── Priv Esc/
│   ├── Windows/                # Group abuse, token abuse, kernel exploits
│   └── Linux/                  # SUID, cron, sudo, services
├── Shells/                     # Every shell type you'll ever need
├── Pivoting & Port Forwarding/ # Chisel, Ligolo, SSH
├── Post Explotation/           # Windows & Linux post-shell enum
├── BOF/                        # Buffer overflows
├── Evasion/                    # AV/EDR evasion
├── Tools & Tricks/             # CLI tools and one-liners
└── Global Variables.md         # ← Set this first
```

---

## 🔑 AD Group Abuse Coverage

Windows group privilege escalation — each with full tool links and step-by-step flows:

- **Account Operators** — add users to privileged groups
- **Backup Operators** — dump SAM/NTDS via SeBackupPrivilege
- **Server Operators** — service binary hijacking → SYSTEM
- **Print Operators** — SeLoadDriverPrivilege → EoPLoadDriver → SYSTEM
- **Group Policy Creator Owners** — SharpGPOAbuse → scheduled task → SYSTEM
- **DNS Admins** — malicious DLL via dnscmd → SYSTEM
- **LAPS Readers** — read local admin passwords from AD
- **Exchange Windows Permissions** — WriteDACL → DCSync
