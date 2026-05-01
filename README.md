# OniSec — Public Writeups

A collection of HackTheBox writeups for retired machines. Notes were taken while the boxes were active and have since been cleaned up and standardized.

---

## Index

Click any box name to jump directly to its writeup.

### 🟢 Easy

| Machine | Tags | Notes |
|---|---|---|
| [Busqueda](retired/easy/busqueda.md) | — | 🚧 reconnaissance only |
| [Inject](retired/easy/inject.md) | LFI · CVE · Spring · Ansible | |
| [MonitorsTwo](retired/easy/monitorstwo.md) | Cacti · CVE · Docker · overlay2 | |
| [PC](retired/easy/pc.md) | gRPC · SQLi · CVE · pyLoad | |
| [Pilgrimage](retired/easy/pilgrimage.md) | LFI · CVE · ImageMagick · binwalk | |
| [Sau](retired/easy/sau.md) | SSRF · CSRF · Command Injection | 🚧 partial |
| [Stocker](retired/easy/stocker.md) | NoSQLi · SSRF · sudo | 🚧 partial |
| [Topology](retired/easy/topology.md) | LaTeX Injection · Hash Cracking · gnuplot | 🚧 partial |

### 🟡 Medium

| Machine | Tags | Notes |
|---|---|---|
| [Agile](retired/medium/agile.md) | Werkzeug Debug · IDOR · LFI · Flask | 🚧 partial |
| [Authority](retired/medium/authority.md) | AD · Ansible Vault · ESC1 · PassTheCert | Windows |
| [Download](retired/medium/download/download.md) | Express · Cookie Forging · Postgres RCE | 🚧 partial · supporting script |
| [Format](retired/medium/format.md) | Redis Injection · PHP RCE · Python Format String | 🚧 partial |
| [Jupiter](retired/medium/jupiter.md) | Grafana · SQLi · Postgres RCE | 🚧 reconnaissance only |
| [Only4You](retired/medium/only4you.md) | SSRF · LFI · Flask | 🚧 partial |
| [Sandworm](retired/medium/sandworm/sandworm.md) | SSTI · PGP · firejail · Rust | supporting script |
| [Socket](retired/medium/socket.md) | WebSocket · SQLi · PyInstaller | 🚧 partial |

### 🟠 Hard

| Machine | Tags | Notes |
|---|---|---|
| [Gofer](retired/hard/gofer.md) | SMB · SSRF · Gopher · LibreOffice · Binary Exploitation | |
| [Intentions](retired/hard/intentions/intentions.md) | 2nd-Order SQLi · Pass the Hash · Imagick RCE · `cap_dac_read_search` | supporting scripts |

### 🔴 Insane

| Machine | Tags | Notes |
|---|---|---|
| [Derailed](retired/insane/derailed.md) | Rails · XSS · CSRF · Command Injection | 🚧 stops at foothold |
| [RegistryTwo](retired/insane/registrytwo/registrytwo.md) | Docker Registry · Tomcat · Java RMI · Deserialization | 🚧 partial · supporting source |

---

## How These Are Structured

Every writeup follows the same skeleton so once you've read one, you know where to find things in the others:

1. **TL;DR** — one paragraph summarizing the chain
2. **Attack Chain at a Glance** — ASCII diagram from nmap to root
3. **Reconnaissance** — nmap (collapsible), service triage table
4. **Initial Foothold** — vulnerability discovery and exploitation
5. **User Flag** — landing user, pivots if any
6. **Privilege Escalation** — root path
7. **Lessons Learned** — generalizable takeaways from the chain
8. **Tools Referenced** — table of every tool, CVE, and external PoC used

Conventions:
- `<details>` blocks collapse long output (full nmap, `/etc/passwd`, etc.) so you can scan the structure quickly
- Callouts: 💡 (insight), ⚠️ (gotcha), 🚧 (incomplete section)
- Every CVE and tool linked the first time it appears
- Flag values are preserved from the active-box notes; redact before adapting if your usage requires it

## A Note on `🚧` Markers

These notes were originally written while the boxes were active, sometimes during the rush of solving them. Some chains were never fully written up before retirement. Where that's the case, sections are marked `🚧 [incomplete]` rather than guessed at — the writeup is honest about what's documented and what isn't.

A few entries are reconnaissance-only and serve as starting points if you want to attempt the box yourself rather than as finished walkthroughs.

## Contact

[OniSecOps on HackTheBox](https://app.hackthebox.com/profile/1543354) · onisec@onisec.org

---

*Writeups are for educational purposes. Boxes referenced are retired HackTheBox machines that are no longer in active rotation.*
