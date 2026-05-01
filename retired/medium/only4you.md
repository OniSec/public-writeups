# HackTheBox — Only4You

![OS: Linux](https://img.shields.io/badge/OS-Linux-blue)
![Difficulty: Medium](https://img.shields.io/badge/Difficulty-Medium-yellow)
![Tags: ssrf, lfi, flask](https://img.shields.io/badge/Tags-SSRF%20%7C%20LFI%20%7C%20Flask-orange)

> 🚧 **[partial — original has reconnaissance and source code of the production app, but stops before exploitation]**

---

## Attack Chain at a Glance

```
nmap → 80/tcp nginx (only4you.htb) → contact form
   → SSRF / LFI to read app source (/var/www/dev/...)
   → 🚧 [foothold mechanism not documented]
   → 🚧 [user]
   → 🚧 [privesc — likely involves Neo4j given _laurel + neo4j users in /etc/passwd]
   → 🚧 [root]
```

---

## Reconnaissance

### Nmap Scan

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 e8:83:e0:a9:fd:43:df:38:19:8a:aa:35:43:84:11:ec (RSA)
|   256 83:f2:35:22:9b:03:86:0c:16:cf:b3:fa:9f:5a:cd:08 (ECDSA)
|_  256 44:5f:7a:a3:77:69:0a:77:78:9b:04:e0:9f:11:db:80 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://only4you.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

| Port | Service | Notes |
|------|---------|-------|
| 22   | SSH     | OpenSSH 8.2p1 |
| 80   | HTTP    | nginx 1.18.0 (`only4you.htb`) |

### /etc/passwd (extracted later via LFI)

<details>
<summary>Click to expand</summary>

```
... (system users) ...
john:x:1000:1000:john:/home/john:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:117:MySQL Server,,,:/nonexistent:/bin/false
neo4j:x:997:997::/var/lib/neo4j:/bin/bash
dev:x:1001:1001::/home/dev:/bin/bash
fwupd-refresh:x:114:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
_laurel:x:996:996::/var/log/laurel:/bin/false
```

</details>

Notable accounts:
- **`john`** (uid 1000) — likely the user-flag owner.
- **`dev`** (uid 1001) — probably an intermediate pivot.
- **`neo4j`** — graph database service, likely involved in privesc.
- **`_laurel`** — audit log forwarder, indicates auditing is on.

---

## Initial Foothold — LFI on Production App

The contact form on the production app eventually surfaces an LFI primitive that reads `/var/www/.../app.py`:

```python
from flask import Flask, render_template, request, flash, redirect
from form import sendmessage
import uuid

app = Flask(__name__)
app.secret_key = uuid.uuid4().hex

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']
        ip = request.remote_addr

        status = sendmessage(email, subject, message, ip)
        if status == 0:
            flash('Something went wrong!', 'danger')
        elif status == 1:
            flash('You are not authorized!', 'danger')
        else:
            flash('Your message was successfuly sent! We will reply as soon as possible.', 'success')
        return redirect('/#contact')
    else:
        return render_template('index.html')

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_errorerror(error):
    return render_template('500.html'), 500

@app.errorhandler(400)
def bad_request(error):
    return render_template('400.html'), 400

@app.errorhandler(405)
def method_not_allowed(error):
    return render_template('405.html'), 405

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=80, debug=False)
```

Key observation: `app.run(host='127.0.0.1', port=80, debug=False)` — the production Flask app binds to `127.0.0.1`. This is a **dev/prod split** box: there's a separate dev instance (presumably on a different vhost) that may be running with `debug=True` (Werkzeug debugger → unauthenticated RCE).

> 🚧 **[gap]** — how the LFI was found (file-fetch parameter? template injection? SSRF chain?), what the dev subdomain looked like, and how the foothold lands on `john` or `dev`.

---

## User Flag

> 🚧 **[incomplete]**

---

## Privilege Escalation

> 🚧 **[incomplete]** — Neo4j on the target suggests Cypher injection or default `neo4j:neo4j` credentials; combined with `_laurel` auditing, this is a notable but unverified guess.

---

## Root Flag

> 🚧 **[incomplete]**

---

## Lessons Learned

> 🚧 **[incomplete]**. Candidate themes:
> - Flask apps deployed with `debug=True` expose the Werkzeug debugger → unauthenticated RCE; check the dev/staging vhost when there's both.
> - LFI plus the `app.py` source is usually enough to find a second-stage primitive (template injection, deserialization, etc.) by reading code rather than guessing.
> - Neo4j with default credentials is common on CTF boxes; the REST API on `:7474` accepts Cypher queries that can include `apoc.*` procedures for arbitrary file write / shell.

---

## Tools Referenced

| Tool | Purpose |
|------|---------|
| [`nmap`](https://nmap.org/) | Port discovery |
