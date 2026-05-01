# HackTheBox — {MachineName}

<!--
  TEMPLATE USAGE:
  1. Copy this file into retired/{difficulty}/{machinename}.md (lowercase) — or
     into retired/{difficulty}/{machinename}/{machinename}.md if you have
     supporting scripts/files alongside the writeup.
  2. Find-and-replace {Placeholders}.
  3. Delete sections you don't need (Attack Chain diagram is optional for
     simple boxes; Lateral Movement, Pivot, etc. only when relevant).
  4. Delete this comment block before publishing.

  Conventions baked into this template:
    - Lowercase filenames                          → busqueda.md, monitorstwo.md
    - Lowercase code-fence languages               → ```bash not ```Bash
    - Hash fingerprints with colons                → 48:ad:d5:b8:...
    - <details> for verbose output                 → full nmap dumps, /etc/passwd
    - Callouts use blockquote + emoji prefix
    - Every CVE and tool linked the first time it appears
    - All commands in fenced code blocks (no `>` quoted commands)
-->

![OS: {Linux|Windows}](https://img.shields.io/badge/OS-{Linux|Windows}-blue)
![Difficulty: {Easy|Medium|Hard|Insane}](https://img.shields.io/badge/Difficulty-{Easy|Medium|Hard|Insane}-{brightgreen|yellow|red|purple})
![Tags: {primary} · {secondary} · {tertiary}](https://img.shields.io/badge/Tags-{Primary}%20%7C%20{Secondary}%20%7C%20{Tertiary}-orange)

> **TL;DR** — One paragraph. Cover the whole chain in plain prose: how the foothold lands, the lateral pivot if any, and the privesc primitive. The reader should know whether they want to read the full writeup after this paragraph alone.

---

<!--
  ATTACK CHAIN DIAGRAM
  Optional but recommended for any box with two or more pivots. For very
  simple chains (foothold → user → privesc with no twists) it's overkill;
  delete the section in that case.
-->

## Attack Chain at a Glance

```
nmap → {how the surface narrows to one service}
   → {foothold mechanism} → {landing user}
   → {lateral pivots, each on its own line if any}
   → user.txt
   → {privesc mechanism} → root.txt
```

---

## Table of Contents

<!-- Optional. Keep for writeups longer than ~300 lines; delete for shorter ones. -->

- [Reconnaissance](#reconnaissance)
- [Initial Foothold — {primary technique}](#initial-foothold--primary-technique)
- [User Flag](#user-flag)
- [Privilege Escalation — {primary technique}](#privilege-escalation--primary-technique)
- [Root Flag](#root-flag)
- [Lessons Learned](#lessons-learned)
- [Tools Referenced](#tools-referenced)

---

## Reconnaissance

### Nmap Scan

```bash
sudo nmap -sSCV -p- --min-rate=5000 -oN nmap.txt {TARGET_IP}
```

<details>
<summary>Click to expand full output</summary>

```
{paste full nmap output here}
```

</details>

| Port | Service | Notes |
|------|---------|-------|
| 22   | SSH     | {version + observation} |
| 80   | HTTP    | {server + observation} |

<!-- If the box uses hostnames, document the /etc/hosts addition. -->

```bash
echo "{TARGET_IP} {hostname}" | sudo tee -a /etc/hosts
```

<!--
  OPTIONAL SUBSECTIONS
  Add any of the following as needed. Each gets its own ### subsection.

  - Directory Brute-Force        (gobuster / feroxbuster / ffuf)
  - Subdomain / Vhost Enumeration
  - SMB Enumeration              (smbclient / enum4linux / smbmap)
  - LDAP Enumeration             (ldapsearch / windapsearch)
  - SNMP / RPC / NFS             (less common but document if used)
-->

---

## Initial Foothold — {primary technique}

<!--
  STRUCTURE
  - State the bug class plainly first ("CVE-XXXX-YYYYY", "second-order SQLi",
    "Imagick MSL race condition")
  - Reference the original writeup / disclosure if there's a public one
  - Then walk through it: trigger condition, payload, observed effect

  CALLOUTS
  Use sparingly — at most 1-2 per major section.
    > 💡 Insight — explains WHY a step works, not just what
    > ⚠️ Gotcha — common mistake or platform-specific footgun
    > 📚 Reference — pointer to deeper reading on a primitive
-->

### {Step 1 — descriptive name}

```bash
{command or payload}
```

{One-paragraph explanation of what this does and what comes back.}

> 💡 **{One-line insight}**  
> {2-3 sentences explaining the underlying mechanism. The reader should be able to recognize the same pattern on a different box after reading this.}

### {Step 2 — descriptive name}

{...}

### Stable Reverse Shell

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl-Z, stty raw -echo; fg, export TERM=xterm
```

---

## User Flag

```bash
{user}@{host}:~$ id
uid={ID}({user}) gid={ID}({user}) groups={...}

{user}@{host}:~$ cat ~/user.txt
{flag if you want to publish it, or "[redacted]"}
```

🚩 **User flag captured.**

---

<!--
  OPTIONAL: LATERAL MOVEMENT
  Use when getting from foothold-user to flag-user requires its own chain
  (cred recovery, second exploitation, etc.). Delete if not applicable.
-->

## Lateral — {from-user → to-user}

{Narrative.}

---

## Privilege Escalation — {primary technique}

### {What gives it away}

```bash
{enumeration command — sudo -l, find / -perm /4000, getcap, pspy, etc.}
```

```
{output that reveals the primitive}
```

### The Vulnerability

{2-4 sentences explaining the bug class, ideally linking to a writeup or CVE.}

### Exploitation

```bash
{step-by-step commands}
```

> 💡 **{Why this works}**  
> {The non-obvious part of the technique — what assumption the dev made that's wrong, what default config opens the door, etc.}

---

## Root Flag

```bash
# id
uid=0(root) gid=0(root) groups=0(root)

# cat /root/root.txt
{flag value or [redacted]}
```

🚩 **Root flag captured.**

<!--
  OPTIONAL: BONUS PERSISTENCE
  E.g. SUID-bash via reverse shell, recovered SSH keys that persist across
  resets, etc. Delete if not relevant.
-->

---

## Lessons Learned

<!--
  These are GENERALIZABLE — what would the reader take from this box to a
  different engagement? Avoid restating the chain in narrative form; that's
  what the body of the writeup is for.

  Aim for 4-7 bullets. Each one should be transferable to other boxes /
  real-world targets.
-->

- **{Generalizable principle 1}** — {one or two sentences explaining when this applies and why}.
- **{Generalizable principle 2}** — {...}.
- **{Generalizable principle 3}** — {...}.

---

## Tools Referenced

| Tool | Purpose |
|------|---------|
| [`nmap`](https://nmap.org/) | Initial port scan |
| [`{tool}`]({link}) | {what it was used for on this box} |
| [{CVE / writeup}]({link}) | {what primitive it documents} |

---

<!--
  OPTIONAL: SUPPORTING FILES
  Only include this section if your writeup references files that live in
  the same directory (exploit scripts, decompiled source, manifests, etc.).
-->

## Supporting Files

This writeup directory also contains:

- `{filename.py}` — {one-line description}
- `{filename.java}` — {decompiled from {.war / .jar / .apk}}

---

*Thanks for reading — feedback welcome.*
