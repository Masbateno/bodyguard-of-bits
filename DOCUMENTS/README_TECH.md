*[Lire en français](README_TECH_FR.md)* · *[Vue d'ensemble](../README.md)*

# BOB — Bodyguard Of Bits

![License](https://img.shields.io/badge/license-MIT-green)
![Release](https://img.shields.io/badge/version-v0.4.6-brightgreen)
![CI](https://github.com/Masbateno/bodyguard-of-bits/actions/workflows/tests.yml/badge.svg)
![Integration](https://github.com/Masbateno/bodyguard-of-bits/actions/workflows/integration.yml/badge.svg)
![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu%20%7C%20Mint%20%7C%20Kali%20%7C%20Fedora-informational)
![Language](https://img.shields.io/badge/language-Python%203.10%2B-yellow)

BOB is a Linux hardening auditor for sysadmins and power users. It runs 43 checks across 9 domains, maps findings to CIS benchmarks when applicable, and provides clear explanations with ready-to-run remediation commands.

---

## Features

### Core audit

- **ASCII banner** with system information — distro, hostname, UFW version, user, date
- **UFW status check** — active/inactive, default incoming policy
- **UFW rule analysis** — duplicate rules, unrestricted `allow from any`, IPv6 consistency
- **Contextual scoring** — network context detection (direct public IP vs NAT); penalties doubled on internet-exposed machines; firewall inactive caps score at 3/10
- **Security score** 0–10 with risk level: LOW / MEDIUM / HIGH / CRITICAL; findings split into *Action required* / *Possible improvements* / *Normal configuration*
- **Audit profiles** — `server` (default), `desktop`, `container`; `workstation` alias kept; active profile shown in the summary box
- **CIS compliance mapping inline** — each finding shows its CIS code `[CIS:X.Y.Z]` in the summary box; full reference text in `--verbose` mode; 137 entries (99 formal CIS, 34 best-practice, 4 Docker)
- **5 thematic group headers** — output organised into: FIREWALL & NETWORK / EXPOSURE & SERVICES / ACCESS CONTROL / SYSTEM HARDENING / DETECTION & HEALTH
- **`--target N`** — score target (1–10); shown in the summary box; returns exit code 4 when score < target (CI-ready)

### Network & firewall

- **32 known network services** detected with UFW exposure analysis and two-axis risk context (exposure + threat) for critical and high-risk services; installed but inactive CRITICAL/HIGH services emit ⚠ + risk context block
- **Services panorama** — compact table of all 32 known services after the audit: SERVICE / STATUS / PORT(S) / UFW; non-installed services shown dimmed
- **iptables/nftables audit** — when UFW is inactive: detects active backend (iptables vs nftables); checks INPUT and FORWARD default policies; verifies conntrack stateful filtering; WARN −1 pt per permissive policy
- **Docker analysis** — iptables bypass detection and list of ports exposed by running containers
- **Virtualisation analysis** — detects active hypervisors (libvirt/KVM, VirtualBox, VMware, LXD/LXC) and Snap network packages that may create bridge interfaces and bypass UFW
- **Listening ports analysis** — unified single-pass; ephemeral and system ports silently skipped; NetBIOS handled with contextual warning
- **DDNS / external exposure detection** — detects active DDNS clients (ddclient, inadyn, No-IP, DuckDNS); extracts configured domain; crosses with unrestricted UFW ALLOW rules to identify internet-exposed ports
- **Exposure classification** per service: `open to internet` / `local network only` / `blocked by UFW` / `no rule`
- **IPv6 consistency check** — detects IPv6 listeners not covered by a matching UFW v6 rule; conflict detection when IPv6 is disabled globally but listeners are present; link-local/ULA-only addresses downgraded to INFO
- **UFW logging level check** — `off` → ALERT −2 pts (no visibility into blocked traffic); `low`/`medium` → OK; `high`/`full` → INFO
- **Port exposure grouping** — groups exposed listening services by interface scope and risk level; system daemons on known OS ports classified separately from user-space apps

### System hardening

- **Hardening check** — unattended-upgrades, AppArmor mode, rp_filter, ICMP redirects, log_martians, ICMP broadcast echo; scored deductions for the most impactful settings
- **SSH security audit** — full `sshd_config` analysis (15 directives + weak Ciphers/MACs/KEX); private key audit (type, size, passphrase); `authorized_keys` inspection; `~/.ssh/config` client-side check; `known_hosts` entry count; distro-aware install hints
- **Sensitive files & sudoers** — permissions audit on `/etc/passwd`, `/etc/shadow`, `/etc/gshadow`, `/etc/group`, `/etc/sudoers`; SSH host private key permissions; `NOPASSWD:ALL` detection across sudoers and sudoers.d
- **System updates audit** — pending security packages via `apt-get -s upgrade` (−2 pts flat); absent `unattended-upgrades` combined with pending security updates (−1 pt compound); regular updates → INFO only
- **System umask audit** — reads umask from `/etc/login.defs`, PAM, `/etc/profile`, shell RC files, and current process; permissive umask (0002/0000) → WARN −1 pt; conflicting sources → WARN −1 pt
- **Secure Boot** — UEFI state via `mokutil --sb-state` / `efivars` / `bootctl`; WARN −1 pt if disabled on desktop; INFO if disabled on server/VM or BIOS/unknown
- **Firmware & microcode audit** — `fwupdmgr` pending device firmware; CPU microcode package (Intel/AMD); WARN −1 pt if absent or outdated
- **TLS/SSL certificate expiry** — scans Let's Encrypt, `/etc/ssl/private`, nginx/apache2/postfix config files; expired → ALERT −2 pts; <7 d → ALERT −2 pts; <30 d → WARN −1 pt; total capped at −4 pts; broken symlinks handled
- **Systemd timers security** — curl/wget piped to a shell in ExecStart → WARN −2 pts; world-writable scripts in ExecStart → WARN −1 pt; user-created root timers without `User=` → INFO

### Detection & monitoring

- **UFW log analysis** — parses `/var/log/ufw.log` over a configurable period (`--log-days=N`, default 7 days); total blocked attempts, top source IPs with geolocation, top targeted ports, bruteforce detection (>10 attempts/60 s), attempts on installed service ports
- **SSH auth.log analysis** — parses `/var/log/auth.log`; brute-force detection (>10 failed attempts from same IP within 60 s → ALERT −2 pts); last successful logins; top failed-login sources
- **IP geolocation** — source IPs enriched with country and operator via GeoIP2 (optional, `python3-geoip2` + GeoLite2 database); private ranges identified as local network; results cached per session
- **IoT/local source dominance** — detects when a single private IP accounts for ≥ 70 % of all blocked UFW traffic over ≥ 50 log entries (WARN, −1 pt); typical of LAN-scanning IoT devices
- **NTP time synchronisation** — systemd-timesyncd, chronyd, or ntpd; WARN −1 pt if disabled or not synchronised
- **Fail2ban intrusion prevention** — installation, service status, active jails, SSH jail detection; WARN −1 pt if inactive or no jails
- **Rootkit & integrity scan** — rkhunter/chkrootkit detection; WARN −1 pt for outdated database (≥7 days), missing or stale scan (>30 days)
- **Linux Audit Framework (auditd)** — installation, service status, loaded rules, coverage of `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`; WARN −1 pt each for inactive service, no rules, uncovered sensitive files (server profile only)
- **File integrity monitoring (AIDE/Tripwire)** — installation, database existence, last check recency; WARN −1 pt if no database or no recent check (>30 days)
- **Samba security audit** — SMB1 protocol (ALERT −2 pts); null passwords (ALERT −3 pts); server signing disabled (WARN −1 pt); guest-writable/readable shares; dedicated `samba` domain
- **ClamAV antivirus audit** — installation, virus database freshness via mtime (WARN/ALERT based on age), daemon status, last scan date parsed from standard log paths
- **SMTP local exposure** — detects MTA (Postfix, Exim, Sendmail) listening on all interfaces vs localhost only; WARN −1 pt when publicly exposed
- **Signal correlation engine** — 5 compound-risk rules (root+no-fail2ban, password-auth+brute-force, root+password, NOPASSWD+SUID, logging-off+no-fail2ban+no-auditd); evaluated post-audit on active ALERT+WARN findings
- **Recurring finding tracker** — consecutive-audit appearance counter per ALERT/WARN key; stored at `~/.config/bob/recurrence.json`
- **Desktop application detection** — known GUI apps (Steam, Discord, Zoom, Signal, VLC, Spotify, Slack, Telegram, Chrome, Firefox…) running as processes; INFO findings, no deduction

### Output & UX

- **Bilingual interface** — auto-detected from `$LC_ALL`/`$LC_MESSAGES`/`$LANG` (POSIX); falls back to English when locale is `C`/`POSIX` or unsupported. Override with `--french` or `--lang=en`
- **No-colour mode** — `--no-color` for clean output in pipes and log files
- **Fix mode** — interactive section after the summary; each automatable fix requires `[y/N]` confirmation; `--fix` alone shows a preview without executing; `--fix --apply --yes` auto-confirms all with audit trail
- **`--explain KEY`** — structured per-finding explanation (WHY IT IS A RISK / HOW TO FIX / CIS reference); 112 explainable keys in 26 groups; 17 keys show profile-specific sections; interactive TUI; no root required; `--explain list` shows all keys
- **Domain scores** — per-domain 0–10 sub-scores (SSH / Samba / Files & Access / Updates / Hardening / Disk Health / Firewall & Services); global score = mean of active domain scores (WARN/ALERT findings only — INFO-only domains excluded from the average); tool caps prevent double-penalty (rootkit, ClamAV, file integrity each capped at 1 pt deduction); bar chart after audit; included in JSON output and webhook payload
- **Webhooks** — `--webhook URL` POSTs audit result as JSON; generic and Slack formats (auto-detected by URL); `--webhook-format=auto|generic|slack`
- **`--html` HTML export** — self-contained HTML file (no JS, no external resources); colored score circle; ALERT/WARN/INFO/OK badges; deductions table; XSS-safe
- **`--format=FORMAT`** — unified output flag: `json | json-full | csv | markdown | html`; legacy flags kept as silent aliases
- **`--check LIST` / `--skip LIST`** — run only named checks (`--check=ssh,firewall`) or exclude them (`--skip=clamav,rootkit`); mutually exclusive; `--check=list` prints all 31 filterable section names
- **`--output-dir PATH`** — override report save directory for the current run; no persist
- **Comparative report** — baseline saved after each audit (`~/.config/bob/last_baseline.json`); next run shows score delta, alert/warn changes, new/closed ports, started/stopped services; new and resolved ALERT+WARN finding keys tracked separately
- **Score history** — `--history` displays last N audit scores as a sparkline (▁▂▃▄▅▆▇█) with dates; automatic 90-entry rotation
- **Ignore list** — `--ignore KEY` adds a finding key to `ignore.yml`; `--show-ignored` lists active exceptions; silences matching findings without scoring
- **`--diff` mode** — runs audit silently and displays only the baseline delta (score, alerts, warnings, info)
- **`--breakdown` / `-B`** — runs audit silently and displays the full score computation path: all deductions (key · domain · points · context), tool caps, engine cap, raw score, per-domain scores with progress bars, domain-average override, final score color-coded by severity
- **Plugin check API** — drop a Python file in `~/.config/bob/checks.d/` to add a custom audit check; fail-safe (exceptions never abort the audit); ANSI-sanitized

### Automation

- **Detailed report** — timestamped log file with ASCII art header, system info, findings, and recommendations; created with `-d`; filename: `bob_YYYYMMDD_HHMMSS.log`
- **`--manage-logs`** — interactive UI to list, preview, and delete saved report files; scrollable preview with full/summary toggle
- **`--install-cron`** — schedule wizard: name the job, choose schedule type (daily / specific days / custom cron expression), set time and optional email; MTA auto-detection (Postfix, Exim, msmtp, ssmtp) — warns when no `sendmail` found; natural-language preview; curses TUI with plain fallback; named cron jobs in `/etc/cron.d/bob-{name}`
- **`--manage-cron`** — looping TUI: list installed cron jobs, edit schedule or notification email, delete; email address book accessible from the menu even without any cron installed

---

## Detected services

| Service                          | Default port         | Risk     | Context                                                                              |
|----------------------------------|----------------------|----------|--------------------------------------------------------------------------------------|
| SSH Server                       | 22/tcp               | Critical | Heavily targeted by automated scanners; full shell access if compromised             |
| VNC Server                       | 5900/tcp             | Critical | Often unencrypted, weak auth; equivalent to physical machine access                  |
| Samba (Windows file sharing)     | 445/tcp, 139/tcp     | Critical | LAN-only by design; ransomware vector (EternalBlue/WannaCry) if exposed              |
| FTP Server                       | 21/tcp               | Critical | Unencrypted protocol; credentials and files transmitted in plain text                |
| MySQL / MariaDB                  | 3306/tcp             | Critical | Password auth, CVE history; full database exfiltration if exposed                    |
| PostgreSQL                       | 5432/tcp             | Critical | Configurable auth; RCE possible via pg_execute_server_program                        |
| Redis                            | 6379/tcp             | Critical | No auth by default historically; documented RCE — actively exploited                 |
| Cockpit (web admin)              | 9090/tcp             | High     | Web admin interface; full system control if compromised                              |
| WireGuard VPN                    | 51820/udp            | High     | Intentional internet exposure; full internal network access if keys stolen           |
| Home Assistant                   | 8123/tcp             | High     | Controls physical devices (locks, alarms); local network access via automations      |
| Nextcloud                        | 80/tcp, 443/tcp      | High     | Personal file server; full file/contact/calendar access if compromised               |
| Mosquitto (MQTT)                 | 1883/tcp, 8883/tcp   | High     | No auth by default; anyone can control IoT devices if exposed                        |
| Apache Web Server                | 80/tcp, 443/tcp      | Medium   | Standard web exposure; risk depends on hosted content                                |
| Nginx Web Server                 | 80/tcp, 443/tcp      | Medium   | Standard web exposure; risk depends on hosted content                                |
| Jellyfin                         | 8096/tcp             | Medium   | Media library access; no critical system data                                        |
| Plex Media Server                | 32400/tcp            | Medium   | Media library access; no critical system data                                        |
| Transmission (web UI)            | 9091/tcp             | Medium   | Download control; file access limited to torrent directory                           |
| qBittorrent (web UI)             | 8080/tcp             | Medium   | Download control; file access limited to torrent directory                           |
| Gitea                            | 3000/tcp             | Medium   | Git forge; disable public registration if not needed                                 |
| Avahi (local network discovery)  | 5353/udp             | Low      | LAN-only mDNS; no data access, discovery only                                        |
| CUPS (network printing)          | 631/tcp              | Low      | Listens on localhost by default; negligible if not exposed                           |
| Syncthing                        | 8384/tcp, 22000/tcp  | Low      | Web UI on localhost by default; sync port may be internet-facing                     |
| Telnet Server                    | 23/tcp               | Critical | Cleartext protocol; credentials and traffic fully visible on the network             |
| RDP / xRDP                       | 3389/tcp             | Critical | Remote desktop; targeted by brute-force and BlueKeep-type exploits                  |
| MongoDB                          | 27017/tcp            | Critical | No auth by default in older versions; full DB access if exposed                      |
| Elasticsearch                    | 9200/tcp             | Critical | No auth by default; REST API exposes full index data                                 |
| Memcached                        | 11211/tcp+udp        | Critical | No auth; used in DDoS amplification attacks if internet-facing                       |
| SMTP / Postfix                   | 25/tcp               | High     | Open relay risk; spam source or pivot if misconfigured                               |
| NFS Server                       | 2049/tcp+udp         | High     | LAN-only by design; full filesystem access if exposed without auth                  |
| Jenkins                          | 8080/tcp             | High     | CI/CD console; RCE risk via script console; admin panel often unauthenticated        |
| OpenVPN                          | 1194/udp             | Medium   | Intentional internet exposure; full internal network access if keys stolen           |
| Squid Proxy                      | 3128/tcp             | Medium   | Open proxy risk if not restricted; can expose internal services                      |

> **ℹ Note on service coverage:** Detection and classification for the following services has been validated through real-world testing: SSH, Samba, Avahi, CUPS, Redis, WireGuard, Docker, Mosquitto, Syncthing, Nginx. Other services are implemented but not yet validated by a formal test protocol. If you run one of these services and notice incorrect behaviour, please open an issue on GitHub.

---

## Requirements

- Linux — daily-driven on Linux Mint 22.3 + Debian 13.4.0; CI-validated on Debian 12/13, Ubuntu 22.04/24.04/25.04, Kali Rolling, Fedora 41
- Python 3.10+
- `ss` recommended (`iproute2` package) — available by default on modern systems
- `python3-geoip2` + GeoLite2 database recommended for IP geolocation (optional): `sudo apt install python3-geoip2 geoip-database`
- `docker` CLI for Docker analysis (optional)

---

## Installation

### Prerequisites

- Linux — daily-driven on Linux Mint 22.3 + Debian 13.4.0; CI-validated on Debian 12/13, Ubuntu 22.04/24.04/25.04, Kali Rolling, Fedora 41
- pipx *(isolated Python app installer)*:

```bash
sudo apt install pipx && pipx ensurepath
```

> Open a new terminal after `pipx ensurepath` to activate the PATH.

### Install

```bash
pipx install bodyguard-of-bits
```

### Enable sudo + bash completion

pipx installs the binary in `~/.local/bin/`, which is not in sudo's restricted PATH.
`--install-completion` creates the symlink `/usr/local/bin/bob` and installs the bash completion script:

```bash
sudo ~/.local/bin/bob --install-completion
source /etc/bash_completion.d/bob
```

After this step, `sudo bob` works normally and `bob --<TAB>` completes options.

---

## Uninstall

```bash
pipx uninstall bodyguard-of-bits
```

---

## Usage

```bash
# Standard audit
sudo bob

# Audit in French
sudo bob --french

# Verbose mode — technical details and port table
sudo bob -v

# Detailed mode — generate a full report file
sudo bob -d

# Fix mode — propose and apply corrections interactively
sudo bob -f

# Fix mode — apply all corrections without confirmation
sudo bob -f -y

# No-colour output (useful for pipes and redirection)
sudo bob -n > audit.txt

# Analyse logs over 14 days instead of 7
sudo bob --log-days=14

# Reconfigure custom ports
sudo bob -r

# Quiet mode — no output, use exit code to detect issues
sudo bob -q; echo $?   # 0=clean, 1=warnings, 2=alerts, 3=error

# Skip external IP lookup (air-gapped or restricted machines)
sudo bob --offline
sudo bob -o

# Show version (no sudo required)
bob -V

# Show help (no sudo required)
bob -h

# Manage saved report files interactively
sudo bob --manage-logs

# Set up an automated audit (schedule wizard)
sudo bob --install-cron

# List, edit or delete installed cron jobs
sudo bob --manage-cron

# Install bash completion and create sudo PATH symlink (run once after pipx install)
sudo bob --install-completion
```

> Email notifications require a working Postfix setup. See [AUTOMATION.md](AUTOMATION.md) for step-by-step configuration (installation, SMTP relay, sender rewriting, testing).

Options can be combined:

```bash
sudo bob -v -d --fix
```

---

## Custom port configuration

When a service is detected on a non-standard port (e.g. SSH on port 2222), the script offers to save the port once. The answer is saved to `~/.config/bob/config.conf` and reused on subsequent audits. To reconfigure:

```bash
sudo bob --reconfigure
```

---

## Example output

Example (trimmed for readability):

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                         ██████╗   ██████╗  ██████╗                          ║
║                         ██╔══██╗ ██╔═══██╗ ██╔══██╗                         ║
║                         ██████╔╝ ██║   ██║ ██████╔╝                         ║
║                         ██╔══██╗ ██║   ██║ ██╔══██╗                         ║
║                         ██████╔╝ ╚██████╔╝ ██████╔╝                         ║
║                         ╚═════╝   ╚═════╝  ╚═════╝                          ║
║                                                                              ║
║                           — Bodyguard Of Bits —                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  BOB v0.3.3  │  Linux hardening auditor                                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  System        : Ubuntu 24.04 LTS                                            ║
║  Host          : my-machine                                                  ║
║  UFW           : v0.36.2                                                     ║
║  User          : alice                                                       ║
║  Date          : 27/03/2026 10:00                                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

┌──────────────────────────────────────────────────────────────────────────────┐
│  FIREWALL STATUS                                                             │
└──────────────────────────────────────────────────────────────────────────────┘

✔ [OK] UFW is installed
✔ [OK] UFW firewall is active
✔ [OK] Default policy: incoming connections blocked (recommended)

┌──────────────────────────────────────────────────────────────────────────────┐
│  UFW RULES ANALYSIS                                                          │
└──────────────────────────────────────────────────────────────────────────────┘

✔ [OK] No duplicate UFW rules detected
✔ [OK] No 'allow from any' rule without port restriction detected
✔ [OK] IPv6 configuration consistent with UFW rules

┌──────────────────────────────────────────────────────────────────────────────┐
│  NETWORK SERVICES ANALYSIS                                                   │
└──────────────────────────────────────────────────────────────────────────────┘

  ▶ SSH Server
    ┄ Risk context — CRITICAL
    Exposure : Heavily targeted by automated scanners and brute-force attacks
    Potential threat   : Full shell access to the machine, privilege escalation

✖ [ALERT] Port 22/tcp — open to internet — no source restriction in UFW

  ▶ Nginx Web Server
✔ [OK] Service active and set to start automatically at boot
⚠ [WARNING] Port 80/tcp — open to internet — no source restriction in UFW

  ▶ Redis
    ┄ Risk context — CRITICAL
    Exposure : No authentication by default historically, very frequently misconfigured
    Potential threat   : Read/write access to all data, remote code execution (RCE)

✔ [OK] Service active and set to start automatically at boot
ℹ [INFO] Port 6379/tcp — covered by default deny policy (no explicit UFW rule needed)

┌──────────────────────────────────────────────────────────────────────────────┐
│  SERVICES PANORAMA                                                           │
└──────────────────────────────────────────────────────────────────────────────┘

  SERVICE                           STATUS         PORT(S)               UFW
  ────────────────────────────────  ─────────────  ────────────────────  ───
  SSH Server                        ACTIVE         22/tcp                ✖
  Nginx Web Server                  ACTIVE         80/tcp, 443/tcp       ⚠
  Redis                             ACTIVE         6379/tcp              ✖
  ...

┌──────────────────────────────────────────────────────────────────────────────┐
│  LISTENING PORTS ANALYSIS                                                    │
└──────────────────────────────────────────────────────────────────────────────┘

ℹ [INFO] Internal system port — no risk: 53/udp (DNS)
ℹ [INFO] Port 25/tcp — bound to localhost only — no external exposure
✔ [OK] All ports listening on 0.0.0.0 are covered by a UFW rule

┌──────────────────────────────────────────────────────────────────────────────┐
│  UFW LOG ANALYSIS                                                            │
└──────────────────────────────────────────────────────────────────────────────┘

  Period analysed : 7 day(s) — 7 day(s) of logs available

✔ [OK] Normal activity — 47 blocked attempt(s) over 7 day(s), no threat detected
ℹ [INFO] Top source IPs : 203.0.113.42 (US, Virginia) — 18 attempt(s)
ℹ [INFO] Top targeted ports : 22/tcp — 31 attempt(s)

╔══════════════════════════════════════════════════════════════════════════════╗
║  Security score : 6/10                                                       ║
║  Risk level : ✖ MEDIUM                                                       ║
║  Network context : 🌐 Exposed to internet                                    ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  ✖ Action required                                                           ║
║    ✖  Port 22/tcp — open to internet — no source restricti…                  ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  ⚠ Possible improvements                                                     ║
║    ⚠  Port 80/tcp — open to internet — no source restricti…                  ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Score breakdown                                                             ║
║    -2  SSH Server 22/tcp exposed to internet                                 ║
║    -1  Nginx Web Server 80/tcp exposed to internet                           ║
║    -1  SSH Server 22/tcp exposed to internet                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

  Corrections are needed. Address items marked 'Action required' first.
```

---

## Report files

With `-d`, a timestamped report is created in a configurable directory (prompted on first use, saved to `config.conf`):

```
bob_20260323_100000.log
```

The report opens with a 62-char ASCII art header and contains: system information, all timestamped findings, complete listening port list, detailed log analysis (top IPs with geolocation, top ports, bruteforce, hits on installed service ports), risk context for critical/high services, score summary.

---

## Options reference

| Option                  | Description                                                        |
|-------------------------|--------------------------------------------------------------------|
| *(no option)*           | Standard audit                                                     |
| `-v`, `--verbose`       | Show technical details (port table, per-port exposure)             |
| `-d`, `--detailed`      | Generate a full report file                                        |
| `-q`, `--quiet`         | Suppress all output — use exit code to detect issues               |
| `-f`, `--fix`           | Propose and apply corrections interactively                        |
| `-y`, `--yes`           | Apply all corrections without confirmation (use with `-f`)         |
| `-r`, `--reconfigure`   | Reconfigure all custom ports                                       |
| `-n`, `--no-color`      | Disable ANSI colour output                                         |
| `--format=FORMAT`       | Unified output flag: `json \| json-full \| csv \| markdown \| html` |
| `--json`                | Export summary as JSON (alias for `--format=json`)                |
| `--json-full`           | Export full audit details as JSON (alias for `--format=json-full`)|
| `--explain=KEY`         | Print structured explanation for a finding key (`--explain list` shows all) |
| `-B`, `--breakdown`     | Silent audit — show full score computation path (deductions, tool caps, domain scores, final) |
| `--diff`                | Silent audit — show only the baseline delta                        |
| `--webhook=URL`         | POST audit result as JSON to URL after each audit                  |
| `--webhook-format=FMT`  | Webhook payload format: `auto` (default), `generic`, or `slack`   |
| `--log-days=N`          | Analyse logs over N days (default: 7)                              |
| `-o`, `--offline`       | Skip external IP lookup and webhook call (no HTTP calls)           |
| `--manage-logs`         | Interactive UI to list, preview, and delete saved report files     |
| `--install-cron`        | Set up an automated nightly audit (cron)                           |
| `--install-completion`  | Install bash completion and create sudo PATH symlink               |
| `--french`              | Switch interface to French                                         |
| `-V`, `--version`       | Show version and exit (no sudo required)                           |
| `-h`, `--help`          | Show help and exit (no sudo required)                              |

---

## Files

| File                                     | Description                                                          |
|------------------------------------------|----------------------------------------------------------------------|
| `~/.local/bin/bob`                 | pipx entry point                                                     |
| `/usr/local/bin/bob`               | Symlink for sudo access (created by `--install-completion`)          |
| `/etc/bash_completion.d/bob`       | Bash completion (created by `--install-completion`)                  |
| `/usr/local/bin/bob-nightly`       | Nightly wrapper script (created by `--install-cron`)                 |
| `/etc/cron.d/bob-{name}`           | Named system cron entry (created by `--install-cron`)                |
| `~/.config/bob/config.conf`        | User configuration (custom ports, log directory; permissions 600)    |
| `~/.config/bob/services.d/*.json`  | User plugin directory — custom service definitions (see note below)  |
| `bob_YYYYMMDD_HHMMSS.log`          | Detailed report (created with `-d`, in the configured directory)     |

> **Plugin directory and `sudo`:** since v0.3.6 BOB resolves `~/.config/bob/` against the
> invoking user's home (via `SUDO_USER`), so plugins dropped in `/home/<you>/.config/bob/services.d/`
> are loaded correctly under `sudo bob`. Files written by BOB under sudo are auto-chowned back to the user.
>
> **Plugin file shape:** each `*.json` plugin file is a JSON array of service objects.
> The formal contract is published as `bob/data/schemas/service.schema.json` (Draft 2020-12 JSON Schema)
> and `bob/data/schemas/services-list.schema.json` for the array wrapper. See "Service plugin schema" below.
>
> **Future `.deb` packaging:** the system-wide directory `/etc/bob/services.d/` will be added as an
> additional load path (without removing the per-user one) for the standard Debian convention.

### Service plugin schema

Service definitions are validated against `bob/data/schemas/service.schema.json` (Draft 2020-12, shipped with the package). Both the bundled `services.json` and user plugins follow the same per-entry shape:

```json
{
  "id":         "myservice",
  "label":      "My Service",
  "packages":   ["mypackage"],
  "services":   ["myservice"],
  "ports":      ["8080/tcp"],
  "risk":       "medium",
  "config_key": "fixed",
  "detection": {
    "binary":       ["/usr/local/bin/myapp"],
    "snap":         ["myapp-snap"],
    "config_files": ["/etc/myapp/config.yml"]
  }
}
```

**Required fields:** `id`, `label`, `packages`, `services`, `ports`, `risk`, `config_key`. **Optional:** `detection`. `risk` ∈ `{"low", "medium", "high", "critical"}`. `config_key` is `"fixed"`, `"ask"`, `"auto"`, or a Python identifier. **Port range 1–65535** (strict).

**Business constraints enforced by the schema:**

- `config_key="fixed"` requires at least one port.
- `config_key="auto"` requires non-empty `detection.config_files` (the auto-resolver needs files to parse).
- A service must be detectable: at least one of `packages`, `services`, or `detection.{binary|snap}` must be non-empty.
- An empty `detection: {}` block is rejected (it adds no signal).

**Plugin file shape.** A user plugin file under `~/.config/bob/services.d/*.json` may use either of two equivalent forms:

1. **Raw array** (legacy / current default) — a bare JSON array of service objects.
2. **Wrapped object** (forward-compat) — `{"schema_version": 1, "services": [ ... ]}`. The wrapper exists so future schema migrations can be gated explicitly via `schema_version`. Only `schema_version: 1` is accepted today; reserved fields like `metadata`, `disabled` are earmarked for future versions.

See `bob/data/schemas/plugin-file.schema.json` for the wrapper meta-schema. Validate externally with any JSON Schema 2020-12 tool (e.g. `check-jsonschema`, `ajv`).

**Schema scope.** The schema validates structure and syntactic shape. It does **not** enforce: cross-service uniqueness of `id` (runtime check) and Python reserved-keyword exclusion for `config_key` (runtime check). A document that validates against the schema may still be rejected at load time if those runtime invariants are violated — the canonical source of truth remains `bob.registry.Service.from_dict()`.

---

## Exit codes

> **Stable public API** — these codes are part of BOB's contract. They will not change within a major version (no removal, no semantic shift). New codes may be added at the end if needed.

When using `--quiet`, the exit code tells you the audit result:

| Code | Constant | Meaning |
|------|----------|---------|
| `0`  | `EXIT_OK`            | Clean audit — no alerts, no warnings |
| `1`  | `EXIT_WARNINGS`      | Warnings detected (improvements suggested) |
| `2`  | `EXIT_ALERTS`        | Alerts detected — action required |
| `3`  | `EXIT_ERROR`         | Technical error (CLI parsing, IO, internal) |
| `4`  | `EXIT_TARGET_MISSED` | `--target N` specified and score < N |

The constants are exposed in `bob.__main__` for programmatic access:

```python
from bob.__main__ import EXIT_OK, EXIT_WARNINGS, EXIT_ALERTS, EXIT_ERROR, EXIT_TARGET_MISSED
```

Example cron job — daily audit at 6am, email on issues:

```bash
0 6 * * * sudo bob --quiet -d || echo "bob exit $? on $(hostname)" | mail -s "UFW Alert" admin@example.com
```

---

## JSON output schema

> **Stable public API** — the structure produced by `--json` / `--json-full` (or `--format=json`) is part of BOB's contract. Backwards-compatibility rules:
>
> - Top-level keys never disappear, never get renamed, never change semantics within a given major `schema_version`.
> - New top-level keys MAY be added in any release; clients must ignore unknown keys.
> - Nested dicts follow the same rule (additions OK, removals/renames = breaking).
> - Breaking changes bump `schema_version` to a new major (`"2"`, `"3"`…).

### Top-level keys (always present)

| Key | Type | Description |
|---|---|---|
| `schema_version` | string | Major schema version (currently `"1"`) |
| `version` | string | BOB version producing the output |
| `host` | string | Hostname (`uname -n`) |
| `timestamp` | string | UTC ISO 8601 timestamp |
| `score` | int (0–10) | Overall security score |
| `score_max` | int | Always `10` |
| `risk` | string | Risk level: `"low"`, `"medium"`, `"high"`, `"critical"` |
| `network_context` | string | `"local"`, `"private"`, or `"public"` |
| `public_ip` | string | Public IP (empty if behind NAT) |
| `alerts` | int | Number of ALERT-level findings |
| `warnings` | int | Number of WARN-level findings |
| `deductions` | array | Score deductions (see below) |
| `domain_scores` | object | Per-domain sub-scores (see below) |

### `deductions[]` structure

```json
{ "reason": "UFW logging is off", "points": 2, "key": "firewall.logging_off" }
```

The `key` field is a **stable dotted i18n key** (`<domain>.<finding>`) — match on this rather than on the localized `reason` for stable client logic across locales.

### `domain_scores` structure

```json
{
  "firewall_services": { "score": 10, "label": "Firewall & Services" },
  "ssh":               { "score": 7,  "label": "SSH" },
  "hardening":         { "score": 6,  "label": "System hardening" }
}
```

Domain keys are stable (`firewall_services`, `ssh`, `hardening`, `detection`, `disk`, `auth`, `cron`).

### Full mode (`--json-full`) additional keys

| Key | Type | Description |
|---|---|---|
| `findings` | array | All findings with `{ key, level, message, nature, cmd, note }` |
| `services` | array | Installed network services with `{ name, installed, active, risk, ports }` |
| `open_ports` | array | Listening ports on `0.0.0.0` with `{ port, address, process }` |
| `firewall_stack` | object | UFW bypass detection: docker, libvirt, nftables, ip_forward, etc. |
| `hardening` | object | Sysctl/AppArmor flags (only when hardening data is collected) |
| `ipv6` | object | IPv6 stack consistency (only when IPv6 data is collected) |

### Stable matching example (locale-independent)

```bash
# Match a specific finding by key, regardless of locale
sudo bob --json | jq '.deductions[] | select(.key == "firewall.logging_off")'
```

The `findings[*].key` and `deductions[*].key` are part of the `--explain` key set — they will not change without a major schema bump.

---

## Python support policy

> **Stable public commitment** — these rules govern when BOB drops support for an older Python.

BOB supports the **N and N-2** Python versions, where **N** is the current upstream stable. As of v0.4.2:

| Python | Status |
|---|---|
| 3.13 | ✅ supported (when released — to be tested) |
| 3.12 | ✅ supported (current development target, CI default) |
| 3.11 | ✅ supported |
| 3.10 | ✅ supported (oldest currently supported) |
| 3.9  | ❌ end of life (dropped in v0.2.3) |

When Python 3.14 ships upstream (~late 2025), Python 3.10 enters a deprecation window:
- **+ 1 minor BOB release** with both 3.10 and 3.14 in CI to validate.
- **+ 1 minor BOB release** announcing 3.10 deprecation in the changelog and `--help`.
- **+ 1 minor BOB release** drops 3.10 from CI and bumps `python_requires` in `pyproject.toml`.

The intent: at least 6 months of advance notice before any drop, mirrored to distros (Debian stable freezes etc.). Packagers can rely on this policy to plan rebuilds.

## Packaging (since v0.4.2)

The repository ships everything a distro maintainer needs to package BOB:

- **`man/bob.1`, `man/bob.conf.5`, `man/bob-profile.5`** — manual pages.
- **`SECURITY.md`** — threat model + vulnerability disclosure policy.
- **`debian/`** — Debian source package (3 binaries: `bob-core`, `bob-tui`, `bob` meta-package). Tested with `debhelper-compat (= 13)` and `pybuild-plugin-pyproject`. Lintian-clean target (one info-level override possible for `binary-without-manpage` on `bob` meta-package which has no executable of its own).
- **`debian/apparmor.d/bob`** — AppArmor profile (shipped in `complain` mode by default, opt-in `enforce`).
- **`packaging/rpm/bob.spec`** — Fedora / RHEL RPM spec built on `pyproject-rpm-macros`. Targeted at Fedora COPR for the initial distribution.

Packaging contributions welcome — see `SECURITY.md` for the disclosure process if you find a security-relevant issue in the package itself.

---

## Important note

BOB is an audit and diagnostic tool, not a security shield. It analyses your configuration and flags problems — but it does not apply corrections automatically without your consent, and it cannot detect everything. Some software like Docker can bypass UFW by manipulating iptables directly: bob detects this specific case and flags it, but other similar vectors exist that fall outside the current scope of the project. In short: bob helps you see more clearly — it does not replace good general security hygiene.

---

## License

MIT License — © 2026 Cédric Clauzel. See `LICENSE` for details.

---

## Author

Cédric Clauzel
