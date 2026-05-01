# HackTheBox — Busqueda

![OS: Linux](https://img.shields.io/badge/OS-Linux-blue)
![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-brightgreen)

> 🚧 **[incomplete — original notes only contain reconnaissance]**
> The TL;DR and attack chain need to be filled in once the foothold and privesc steps are written.

---

## Reconnaissance

### Nmap Scan

```bash
sudo nmap -sSCV -p- --min-rate=5000 -oN nmap.txt <target>
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://searcher.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

| Port | Service | Version |
|------|---------|---------|
| 22   | SSH     | OpenSSH 8.9p1 (Ubuntu) |
| 80   | HTTP    | Apache 2.4.52 (redirects to `searcher.htb`) |

Add to `/etc/hosts`:

```bash
echo "<target> searcher.htb" | sudo tee -a /etc/hosts
```

---

## /etc/passwd (collected during enumeration)

<details>
<summary>Click to expand</summary>

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
... (system users) ...
svc:x:1000:1000:svc:/home/svc:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
fwupd-refresh:x:113:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```

</details>

Notable entries:
- **`svc`** (uid 1000) — only human user; SSH-able (`/bin/bash`).
- **`_laurel`** — Linux audit log forwarder. Suggests detailed auditing is enabled on this box.

---

## Web Enumeration

> 🚧 **[incomplete]** — needs documentation of the `searcher.htb` web app, what it runs, and how the foothold was obtained.

---

## Initial Foothold

> 🚧 **[incomplete]** — exploitation path not documented in original notes.

---

## User Flag

> 🚧 **[incomplete]**

---

## Privilege Escalation

> 🚧 **[incomplete]**

---

## Root Flag

> 🚧 **[incomplete]**

---

## Lessons Learned

> 🚧 **[incomplete]** — to be filled in once the full chain is written up.

---

## Tools Referenced

| Tool | Purpose |
|------|---------|
| [`nmap`](https://nmap.org/) | Port and service discovery |
