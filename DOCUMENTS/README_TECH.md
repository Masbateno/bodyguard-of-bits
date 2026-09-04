*[Lire en français](README_TECH_FR.md)* · *[Vue d'ensemble](../README.md)*

# BOB — Bodyguard Of Bits

![License](https://img.shields.io/badge/license-MIT-green)
![Release](https://img.shields.io/badge/version-v0.16.1-brightgreen)
![CI](https://github.com/Masbateno/bodyguard-of-bits/actions/workflows/tests.yml/badge.svg)
![Integration](https://github.com/Masbateno/bodyguard-of-bits/actions/workflows/integration.yml/badge.svg)
![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu%20%7C%20Mint%20%7C%20Kali%20%7C%20Fedora-informational)
![Language](https://img.shields.io/badge/language-Python%203.10%2B-yellow)

BOB is a Linux hardening auditor for sysadmins and power users. It runs 38 check sections across 7 score domains, maps findings to CIS benchmarks when applicable, and provides clear explanations with ready-to-run remediation commands.

---

## Features

### Core audit

- **ASCII banner** with system information — distro, hostname, UFW version, user, date
- **UFW status check** — active/inactive, default incoming policy
- **UFW rule analysis** — duplicate rules, unrestricted `allow from any`, IPv6 consistency
- **Contextual scoring** — network context detection (direct public IP vs NAT); penalties doubled on internet-exposed machines; firewall inactive caps score at 3/10
- **Security score** 0–10 with risk level: LOW / MEDIUM / HIGH / CRITICAL; findings split into *Action required* / *Possible improvements* / *Normal configuration*
- **Audit profiles** — `server` (default), `desktop`, `workstation`, `container`; active profile shown in the summary box. **v0.8.1 BREAKING**: `workstation` is no longer an alias for `desktop` and ships its own business-tier overrides (backup / auditd / mac_policy kept at WARN while desktop relaxes them to INFO)
- **CIS compliance mapping inline** — each finding shows its CIS code `[CIS:X.Y.Z]` in the summary box; full reference text in `--verbose` mode; 174 entries (107 formal CIS, 60 best-practice, 7 Docker)
- **5 thematic group headers** — output organised into: FIREWALL & NETWORK / EXPOSURE & SERVICES / ACCESS CONTROL / SYSTEM HARDENING / DETECTION & HEALTH
- **`--target N`** — score target (1–10); shown in the summary box; returns exit code 4 when score < target, **and since v0.16.0 whenever the score is an upper bound** — a gate cannot be satisfied by a ceiling (CI-ready)

### Network & firewall

- **38 known network services** detected with UFW exposure analysis and two-axis risk context (exposure + threat) for critical and high-risk services; installed but inactive CRITICAL/HIGH services emit ⚠ + risk context block
- **Services panorama** — compact table of all 38 known services after the audit: SERVICE / STATUS / PORT(S) / UFW; non-installed services shown dimmed
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
- **Service hardening (`systemd-analyze security`)** — surfaces the systemd exposure score of running services (NoNewPrivileges, ProtectSystem, capability bounding, namespacing…); INFO-only summary (counts by predicate + least-hardened running services + pointer to `systemd-analyze security <unit>`), **no deduction** — a high default exposure is the normal state of a Linux host, not a chosen misconfiguration (v0.13.0)
- **Container security posture** — when BOB runs *inside* a container, reads the container's own isolation from kernel interfaces (capability bounding set → privileged / CAP_SYS_ADMIN detection, seccomp mode, user namespace mapping, writable rootfs); the whole section is suppressed on a non-container host. the fast-follow promised in v0.13.0 landed in **v0.15.4**, validated against four real podman containers: privileged −3, CAP_SYS_ADMIN −2, seccomp switched off −1. Runtime defaults (writable rootfs, root without a user namespace) stay INFO — an operator choice is penalised, an editor default is not (v0.13.0, teeth v0.15.4)
- **Systemd socket units** — flags `.socket` units that are still active while their backing service is gone (masked / not-found) or that are in a failed state — a listening socket with no working consumer, usually the leftover of a removed/renamed package; marks ones bound to a non-loopback address. Empty-trigger systemd internals are never flagged. **v0.15.4**: an orphan bound to a non-loopback address deducts −1 — the port answers and then fails the connection; the same breakage on loopback stays INFO (v0.13.1, teeth v0.15.4)
- **Cloud context (host-side)** — only on a cloud instance (conservative detection: a SMBIOS/DMI-identified provider, or cloud-init corroborated by an on-link metadata route — a bare cloud-init install on a Proxmox/VMware/homelab VM is *not* treated as cloud): surfaces host-visible cloud exposure — instance metadata service reachable on-link (IMDSv2 reminder), world-readable persisted user-data — strictly host-side, no cloud API/credentials. **v0.15.4**: world-readable user-data deducts −2 (cloud-init writes it 0600, so any other mode is a choice). IMDS reachability stays INFO: whether IMDSv2 is enforced is a property of the instance's metadata options and cannot be read from the host (v0.13.1, teeth v0.15.4)

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
- **Signal correlation engine** — 6 compound-risk rules (root+no-fail2ban, password-auth+brute-force, root+password, NOPASSWD+SUID, security-updates-pending+no-fail2ban, logging-off+no-fail2ban+no-auditd); evaluated post-audit on active ALERT+WARN findings
- **Recurring finding tracker** — consecutive-audit appearance counter per ALERT/WARN key; stored at `~/.config/bob/recurrence.json`
- **Desktop application detection** — known GUI apps (Steam, Discord, Zoom, Signal, VLC, Spotify, Slack, Telegram, Chrome, Firefox…) running as processes; INFO findings, no deduction

### Output & UX

- **Bilingual interface** — auto-detected from `$LC_ALL`/`$LC_MESSAGES`/`$LANG` (POSIX); falls back to English when locale is `C`/`POSIX` or unsupported. Override with `--french` / `--english` (or `--lang=fr` / `--lang=en`)
- **Colour handling** — auto-detected since v0.14.0: ANSI is emitted only when stdout is a terminal, so redirecting to a file or a pipe is clean without any flag. `--no-color` (or `NO_COLOR=1`) forces it off; `FORCE_COLOR=1` forces it on for `less -R` or a deliberately coloured log
- **Fix mode** — interactive section after the summary; each automatable fix requires `[y/N]` confirmation; `--fix` alone shows a preview without executing; `--fix --apply --yes` auto-confirms all with audit trail
- **`--explain KEY`** — structured per-finding explanation (WHY IT IS A RISK / HOW TO FIX / CIS reference); 187 explainable keys across 49 prefixes; 70 keys show profile-specific sections; interactive TUI; no root required; `--explain list` shows all keys
- **Domain scores** — per-domain 0–10 sub-scores (SSH / Samba / Files & Access / Updates / Hardening / Disk Health / Firewall & Services); global score = mean of active domain scores (a domain becomes active as soon as any check from it emits `OK`, `WARN`, or `ALERT` — `INFO`-only domains stay hidden; `OK` was added to the active set in v0.4.6 to fix a scoring inversion after remediation); tool caps prevent double-penalty (rootkit, ClamAV, file integrity each capped at 1 pt deduction); bar chart after audit; included in JSON output and webhook payload
- **Webhooks** — `--webhook URL` POSTs audit result as JSON; generic and Slack formats (auto-detected by URL); `--webhook-format=auto|generic|slack`
- **`--html` HTML export** — self-contained HTML file (no JS, no external resources); colored score circle; ALERT/WARN/INFO/OK badges; deductions table; XSS-safe
- **`--format=FORMAT`** — unified output flag: `json | json-full | csv | markdown | html`; legacy flags kept as silent aliases
- **`--check LIST` / `--skip LIST`** — run only named checks (`--check=ssh,firewall`) or exclude them (`--skip=clamav,rootkit`); mutually exclusive; `--check=list` prints all 34 filterable section names
- **`--output-dir PATH`** — override report save directory for the current run; no persist
- **Comparative report** — baseline saved after each audit (`~/.config/bob/last_baseline.json`); next run shows score delta, alert/warn changes, new/closed ports, started/stopped services; new and resolved ALERT+WARN finding keys tracked separately
- **Score history** — `--history` displays last N audit scores as a sparkline (▁▂▃▄▅▆▇█) with dates; automatic 1000-entry rotation
- **Ignore list** — `--ignore KEY` adds a finding key to `ignore.yml`; `--show-ignored` runs the audit and displays suppressed findings in grey alongside the normal output (it is not a listing command); silences matching findings without scoring
- **`--diff` mode** — runs audit silently and displays only the baseline delta (score, alerts, warnings, info)
- **`--breakdown` / `-B`** — runs audit silently and displays the full score computation path: all deductions (key · domain · points · context), tool caps, engine cap, raw score, per-domain scores with progress bars, domain-average override, final score color-coded by severity
- **Plugin check API** — drop a Python file in `~/.config/bob/checks.d/` to add a custom audit check; fail-safe (exceptions never abort the audit); ANSI-sanitized

### Automation

- **Detailed report** — timestamped log file with ASCII art header, system info, findings, and recommendations; created with `-d`; filename: `bob_YYYYMMDD_HHMMSS.log`
- **`--manage-logs`** — interactive UI to list, preview, and delete saved report files; scrollable preview with full/summary toggle
- **`--install-cron`** — schedule wizard: name the job, choose schedule type (daily / specific days / custom cron expression), set time and optional email, then pin the audit's profile, language and outbound-probe stance (v0.16.1 — a cron runs as root, so without these it would read root's saved profile and cron's bare `$LANG`); MTA auto-detection (Postfix, Exim, msmtp, ssmtp) — warns when no `sendmail` found; natural-language preview; resulting command line shown before writing; curses TUI with plain fallback; named cron jobs in `/etc/cron.d/bob-{name}`
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

# Delete the saved configuration (asks first)
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

## Saved configuration

`~/.config/bob/config.conf` (mode `0600`) holds the audit profile, the webhook URL and format, the SUID whitelist and the log directories chosen through `--manage-logs`. Nothing else is persisted: **service ports are not saved and never were** — BOB reads each service's own configuration files at audit time (`sshd_config`, `nginx.conf`, `smb.conf`, …) and falls back to the well-known port when no directive is found. Earlier revisions of this page described a prompt that offered to remember a non-standard port; no such prompt exists in the code.

To delete the saved configuration and start from defaults (asks for confirmation):

```bash
sudo bob --reconfigure
```

---

## Plugin checks — `~/.config/bob/checks.d/*.py`

BOB supports custom audit checks written in Python. Drop a `*.py` file under `~/.config/bob/checks.d/` and BOB picks it up at the next run. Each plugin is executed inside a **sandboxed subprocess** (introduced in v0.7.0 T3) — RLIMIT_AS 256 MiB, RLIMIT_CPU 10 s wall clock, restricted import allowlist, denied filesystem writes, blocked reads on sensitive paths (`/etc/shadow`, `~/.ssh/id_*`, `/dev/mem`, …). A misbehaving plugin **cannot** abort the audit, and any output is ANSI-sanitised.

> **Threat model note:** in-process Python sandboxing is defence-in-depth, not a hard security boundary (PEP 416 consensus). Use the shipped AppArmor profile for actual isolation. See SECURITY.md → "Plugin checks" section.

### Contract

Each plugin file must expose a function:

```python
def run_check(t=None) -> CheckResult:
    ...
```

`t` is the bound i18n callable (rarely needed in a plugin — write your messages in English directly). The return value is a `bob.scoring.CheckResult`. Optionally, define a module-level `CHECK_NAME` to override the section title in the report.

### Minimal working example

Save this as `~/.config/bob/checks.d/motd_check.py`:

```python
"""Check that /etc/motd contains a banner."""
from pathlib import Path
from bob.scoring import CheckResult

CHECK_NAME = "MOTD BANNER CHECK"

def run_check(t=None) -> CheckResult:
    result = CheckResult()
    motd = Path("/etc/motd")
    if motd.exists() and motd.read_text().strip():
        result.ok(message="Custom MOTD banner present")
    else:
        result.info(
            message="No MOTD banner configured",
            key="custom.motd_empty",
        )
    return result
```

### Result methods

`CheckResult` exposes the same emit methods used by built-in checks:

- `result.ok(message=...)` — green checkmark, no score impact
- `result.info(message=..., key=...)` — neutral notice, no deduction
- `result.warn(message=..., key=..., points=..., nature=...)` — yellow warning
- `result.alert(message=..., key=..., points=..., nature=...)` — red alert
- `result.warn_with_deduction(...)` / `result.alert_with_deduction(...)` — combined helpers

Use `key=` so your finding can be silenced with `bob --ignore custom.my_key` if needed. Choose `key` strings under a `custom.*` prefix so they cannot collide with BOB's built-in keys (the `_KNOWN_PREFIXES` invariant test rejects unknown prefixes for built-in EXPLAIN_KEYS but not for plugin output).

### What plugins CANNOT do

Inside the sandbox child:

- No subprocess (`subprocess.run`, `os.popen`, `os.exec*` — all stripped or denied).
- No filesystem writes (`open(... 'w')`, `os.write`, `Path.write_*`, `pathlib.Path` write methods are monkey-patched).
- No reads on `/etc/shadow`, `~/.ssh/id_*`, `/dev/mem`, `/proc/kcore`, similar sensitive paths.
- No `__import__` of arbitrary modules — only an allowlist (bob.scoring, pathlib, json, etc.).
- No network I/O.

If a plugin attempts any of the above, it raises in the sandbox child, the parent records a `plugin.sandbox.error` WARN finding, and the audit continues unaffected.

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
║  BOB v0.13.2  │  Linux hardening auditor                                     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  System        : Ubuntu 24.04 LTS                                            ║
║  Host          : my-machine                                                  ║
║  UFW           : v0.36.2                                                     ║
║  User          : alice                                                       ║
║  Date          : 17/05/2026 10:00                                            ║
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
bob_20260517_100000.log
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
| `-r`, `--reconfigure`   | Delete the saved configuration and exit (asks first)               |
| `-n`, `--no-color`      | Force ANSI colour off (colour is auto-detected from the TTY)       |
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
| `--english`             | Switch interface to English (symmetry with `--french`, v0.12.1)    |
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
| `~/.config/bob/config.conf`        | User configuration (profile, webhook, log directory; permissions 600)|
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
  "detection": {
    "binary":       ["/usr/local/bin/myapp"],
    "snap":         ["myapp-snap"],
    "config_files": ["/etc/myapp/config.yml"]
  }
}
```

**Required fields:** `id`, `label`, `packages`, `services`, `ports`, `risk`. **Optional:** `detection`. `risk` ∈ `{"low", "medium", "high", "critical"}`. `config_key` is `"fixed"`, `"ask"`, `"auto"`, or a Python identifier. **Port range 1–65535** (strict).

**Business constraints enforced by the schema:**

- A service must declare at least one port **or** a `detection.config_files` entry to parse ports from. Declaring neither is refused: its ports could never be determined.
- `config_key` was retired in v0.15.4. It is still accepted so existing `~/.config/bob/services.d/*.json` keep validating, but it is ignored.
- A service must be detectable: at least one of `packages`, `services`, or `detection.{binary|snap}` must be non-empty.
- An empty `detection: {}` block is rejected (it adds no signal).

**Plugin file shape.** A user plugin file under `~/.config/bob/services.d/*.json` may use either of two equivalent forms:

1. **Raw array** (legacy / current default) — a bare JSON array of service objects.
2. **Wrapped object** (forward-compat) — `{"schema_version": 1, "services": [ ... ]}`. The wrapper exists so future schema migrations can be gated explicitly via `schema_version`. Only `schema_version: 1` is accepted today; reserved fields like `metadata`, `disabled` are earmarked for future versions.

See `bob/data/schemas/plugin-file.schema.json` for the wrapper meta-schema. Validate externally with any JSON Schema 2020-12 tool (e.g. `check-jsonschema`, `ajv`).

**Schema scope.** The schema validates structure and syntactic shape. It does **not** enforce: cross-service uniqueness of `id` (runtime check) and the requirement that a service declare either a port or a config file to read one from (runtime check). A document that validates against the schema may still be rejected at load time if those runtime invariants are violated — the canonical source of truth remains `bob.registry.Service.from_dict()`.

---

## Environment variables

All are opt-in; none is required for normal operation.

| Variable | Effect |
|---|---|
| `NO_COLOR` | Any non-empty value forces colour off, like `--no-color`. An empty value is ignored ([no-color.org](https://no-color.org)). |
| `FORCE_COLOR` | Any non-empty value forces colour **on** even when stdout is not a terminal — for `bob \| less -R`, or to capture a coloured log on purpose. Added in v0.14.0 alongside TTY auto-detection. |
| `BOB_DEBUG` | Diagnostics: prints the full Python traceback on an `EXIT_ERROR` exit, and installs a real logging handler so the internal `logger.debug` / `logger.warning` records become visible (notably `_run()`'s per-subprocess failure trace). |
| `BOB_SHARE` | Overrides the auto-detected package data directory (`bob/data/`). For distro packagers shipping the data files outside the Python package tree. |

Precedence for colour, first match wins: `--no-color` → `NO_COLOR` → `FORCE_COLOR` → `stdout.isatty()`.

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
| `4`  | `EXIT_TARGET_MISSED` | `--target N` specified and score < N, **or the score is an upper bound** (v0.16.0): a check could not read its input, so "at least N" was never established. A gate fails closed. |
| `130`| *(signal convention)* | Interrupted with Ctrl-C. Since v0.14.1 `main()` catches `KeyboardInterrupt` and prints one localised line instead of a Python traceback. Not a `bob.__main__` constant — it is the shell's `128 + SIGINT`. |

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

### Schema versions

Schema **v3** is the only version emitted by `bob.json_output.build_json_data()`:

| Version | Status | Selection |
|---|---|---|
| **v3** | **Default and only schema since v0.12.0** | `--json` / `--json-full` |
| v2 | v0.7.0 schema — **retired in v0.12.0** (F9 count-key rename) | (no longer available) |
| v1 | Legacy v0.6.x schema — **retired in v0.9.0** | (no longer available) |

v1 (and its opt-in `--json-v1` flag) was retired in v0.9.0; **v2 was retired in v0.12.0** when F9 renamed the integer count keys `alerts`→`alert_count` and `warnings`→`warning_count` for symmetry with `info_count` — a breaking rename, so the major bumped v2→v3 rather than mutating v2 in place. Consumers pinned to v2 must re-pin to v3 and rename those two keys:

```bash
sudo bob --json | jq '.schema_version'   # → "3"
```

### v3 — Top-level keys (always present)

| Key | Type | Description |
|---|---|---|
| `schema_version` | string | `"3"` |
| `version` | string | BOB version producing the output |
| `host` | string | Hostname (`uname -n`) |
| `timestamp_utc` | string | UTC ISO 8601 timestamp (renamed from `timestamp` in v1) |
| `score` | int (0–10) | Overall security score |
| `score_max` | int | Always `10` |
| `risk` | string | **Effective** risk level (includes posture escalation): `"low"`, `"medium"`, `"high"`, `"critical"` |
| `network_context` | object | `{ "context": "local" \| "private" \| "public" \| "ddns" }` in short mode; extended with `interfaces`, `connections_count`, `top_remote_ips` in `--json-full` |
| `public_ip` | string | Public IP (empty if behind NAT) |
| `alert_count` | int | Number of ALERT-level findings (renamed from `alerts` in v0.12.0) |
| `warning_count` | int | Number of WARN-level findings (renamed from `warnings` in v0.12.0) |
| `info_count` | int | Number of INFO-level findings (new in v2) |
| `profile` | string | The audit profile that produced this result (`server` / `desktop` / `workstation` / `container`). New in v0.14.1, additive within v3. Since v0.14.0 the profile changes finding severities, `warning_count` and therefore the exit code, so two payloads for the same host can legitimately disagree — this field is what explains the difference. |
| `degraded_sections` | array | Section names whose check raised and was degraded in place rather than aborting the audit (new in v0.14.1, additive within v3). Empty on a healthy run. Each also appears as a `<section>.unavailable` INFO finding. Lets a consumer tell "score 9 with every section evaluated" from "score 9 with two sections never run". |
| `score_is_upper_bound` | bool | **New in v0.16.0.** True when a check could not read its input, so the deductions it did not make are *unknown, not zero* and `score` is a ceiling rather than a measurement. Masking `/etc/ssh/sshd_config` removes four deductions and moves the score from 7 to **8** — up, on a host BOB can see less of. `score` stays an integer so existing consumers are unaffected; this says what it is worth. |
| `unverified` | array | **New in v0.16.0.** The finding keys that mean a section could not be fully read (`ssh.config_unreadable`, `suid_audit.ok_partial`, …). Empty on a fully privileged run. Alert on `score_is_upper_bound` rather than counting this list: one unreadable section is enough to make the score a ceiling. |
| `deductions` | array | Score deductions (filtered: `points > 0`) |
| `domain_scores` | object | Per-domain sub-scores |
| `posture_escalation` | object | Posture-driven risk-level adjustment context (new in v2) |

### v3 — `posture_escalation` structure (new)

```json
{
  "applied":     false,
  "reason_key":  null,
  "score_level": "low"
}
```

| Field | Type | Description |
|---|---|---|
| `applied` | bool | `true` when the displayed `risk` was raised by a posture trigger |
| `reason_key` | string \| null | i18n key when applied, e.g. `"scoring.posture.firewall_inactive"` |
| `score_level` | string | The risk level computed from the score alone, before posture escalation |

Triggers (first match wins):

1. `firewall_inactive` → floor `high`
2. `iptables_input_accept` → floor `high`
3. `firewall_domain_score ≤ 3` → floor `medium`

Phase 1 (commit `e3d998f`) introduced the posture concept internally; v2 surfaces it in JSON so consumers can distinguish "low risk because clean" from "low risk dominated by good but non-firewall domains".

### v3 — `deductions[]` structure

```json
{
  "reason": "UFW logging is off",
  "points": 2,
  "key":    "firewall.logging_off",
  "template_vars": {}
}
```

The `key` field is a **stable dotted i18n key** (`<prefix>.<finding_id>`) — match on this rather than on the localized `reason` for stable client logic across locales. See the EXPLAIN_KEYS audit below for the convention.

### v3 — `domain_scores` structure

```json
{
  "ssh":        { "score": 10, "label": "SSH",                "deductions": 0, "active": true,  "reason": null },
  "samba":      { "score": 10, "label": "Samba Security",     "deductions": 0, "active": false, "reason": "not_installed" },
  "file_perms": { "score": 10, "label": "Files & Access",     "deductions": 0, "active": true,  "reason": null },
  "updates":    { "score": 10, "label": "Updates",            "deductions": 0, "active": false, "reason": "info_only" },
  "hardening":  { "score": 9,  "label": "Hardening",          "deductions": 1, "active": true,  "reason": null },
  "disk":       { "score": 10, "label": "Disk Health",        "deductions": 0, "active": false, "reason": "profile_skipped" },
  "firewall":   { "score": 10, "label": "Firewall & Services","deductions": 0, "active": true,  "reason": null }
}
```

Domain keys are stable: `ssh`, `samba`, `file_perms`, `updates`, `hardening`, `disk`, `firewall` (7 total — defined in `bob.domain_scores.DOMAINS`). Each entry has `score` (int 0–10), `label` (English display name), `deductions` (int — total points deducted in this domain, new in v2), and **`active` / `reason` (new in v0.12.1)**.

`active` (bool) is `true` when the domain contributed an actionable (OK/WARN/ALERT) finding — **only active domains are averaged into the global `score`**. When `active` is `false`, `reason` (string) explains why the domain was shown but not scored:

| `reason` | Meaning |
|---|---|
| `info_only` | The checks ran and reported, but only informational notices — nothing to act on. |
| `profile_skipped` | The active audit profile skips every section feeding this domain (e.g. `disk` under the `container` profile). |
| `filtered` | Excluded by a `--check` / `--skip` filter on this run. |
| `not_installed` | The checks ran and found the component absent. |

For an active domain, `reason` is `null`. This lets a consumer **reproduce the headline**: `score = round(mean(score for active domains))`, capped at 9 when any deduction exists (the F1 "10 means a flawless audit" rule — see v0.12.0).

### v3 — Full mode (`--json-full`) additional keys

| Key | Type | Description |
|---|---|---|
| `findings` | array | All findings with `{ key, level, message, detail, nature, cmd, note, template_vars, qualified_by }`. `detail` has been present since v0.8.1 and was missing from this list. **`qualified_by`** (new in v0.15.5, additive) holds the keys of findings from the same audit that qualify this one — for instance `ssh.config_newer_than_service`, which says the SSH findings describe the config file rather than the running service. A consumer matching on `key` alone cannot tell a qualified finding from an unqualified one; it is normally empty. |
| `services` | array | Installed network services with `{ name, installed, active, risk, ports }` |
| `open_ports` | array | Listening ports on `0.0.0.0` with `{ port, address, process }` (filtered) |
| `open_ports_all` | array | All listening ports, including localhost-bound (new in v2) |
| `firewall_stack` | object | UFW bypass detection: docker, libvirt, nftables, ip_forward, etc. |
| `deductions_raw` | array | All deductions, including synthetic zero-point caps (new in v2) |
| `hardening` | object | Sysctl/AppArmor flags (only when hardening data is collected) |
| `ipv6` | object | IPv6 stack consistency (only when IPv6 data is collected) |

In full mode, `network_context` additionally carries `interfaces` / `connections_count` / `top_remote_ips` — an **additive** extension of the object, not a type swap.

### Retired schemas (v1, v2) — what changed vs current v3

v1 (v0.6.x, opt-in `--json-v1`) was retired in v0.9.0; v2 (v0.7.0) was retired in v0.12.0. Notable differences vs the current **v3** layout:

| Field | v1 | v2 | v3 (current) |
|---|---|---|---|
| `schema_version` | `"1"` | `"2"` | `"3"` |
| `timestamp` | present | renamed `timestamp_utc` | `timestamp_utc` |
| `alerts` / `warnings` | present (int counts) | present (int counts) | renamed `alert_count` / `warning_count` |
| `info_count` | absent | present | present |
| `network_context` | string in short mode; dict in full | always dict | always dict |
| `posture_escalation` | absent | present | present |
| `deductions_raw` / `open_ports_all` | absent | present (full only) | present (full only) |
| `domain_scores[d]` | `{ score, label }` | `{ score, label, deductions }` | `{ score, label, deductions, active, reason }` |

### Migration guide (→ v3)

For most consumers the migration is mechanical:

| If your older code reads… | …in v3 use |
|---|---|
| `data["alerts"]` (v1/v2 int count) | `data["alert_count"]` |
| `data["warnings"]` (v1/v2 int count) | `data["warning_count"]` |
| `data["timestamp"]` (v1) | `data["timestamp_utc"]` |
| `data["network_context"]` (v1 string) | `data["network_context"]["context"]` |
| `data["domain_scores"]["ssh"]["score"]` | unchanged |
| (anything else) | unchanged — v3 is additive beyond the renames above |

Pin to the current major explicitly:

```bash
sudo bob --json | jq 'if .schema_version == "3"
  then { alerts: .alert_count, warnings: .warning_count, score }
  else error("unsupported schema_version \(.schema_version) — expected 3")
  end'
```

### Stable matching example (locale-independent)

```bash
# Match a specific finding by key, regardless of locale and schema version
sudo bob --json | jq '.deductions[] | select(.key == "firewall.logging_off")'
```

The `findings[*].key` and `deductions[*].key` are part of the `--explain` key set — they will not change without a major schema bump.

### EXPLAIN_KEYS audit

As of v0.11.x, the `--explain` key set contains **187 keys** across **49 prefixes**. The canonical naming convention is enforced by `tests/test_explain_naming_convention.py`:

- **Pattern:** `<prefix>.<finding_id>` (single dot, snake_case)
- **Exceptions:** `file_perms.<path>.<finding_id>` (path-segment middles) and `services.{exposure,state}.<finding_id>` (two-tier taxonomy), both resolved by `bob.explain.normalize_key`
- **No removal:** once published, a key stays callable for the lifetime of the major `schema_version`
- **Aliases:** key renames go through `EXPLAIN_KEY_ALIASES` for backward compatibility
- **Additions:** new keys may be added in any minor release
- **Coverage guard:** every WARN/ALERT finding emitted by `bob/checks/*.py` must have an `EXPLAIN_KEYS` entry or be listed in `tests/test_explain_coverage.py::_KNOWN_GAPS` (currently empty — v0.8.0 drift batch backfilled 51 missing entries)

Prefix vocabulary (alphabetically): `auditd, auth_log, backup, clamav, cron_audit, ddns, disk, docker, docker_audit, fail2ban, file_integrity, file_perms, firewall, firewall_stack, firmware, hardening, iptables_nft, ipv6, kernel_hardening, kernel_modules, log_rotation, logs, mac_policy, memory, network_context, ntp, password_policy, ports, prerequisites, risk, rootkit, rules, samba, secure_boot, services, services_state, smtp, ssh, ssl_certs, suid_audit, systemd_timers, umask, updates, user_accounts, virt`.

Adding a new prefix in a future release fails `TestExplainPrefixDiscipline::test_key_prefix_is_known` until the maintainer explicitly updates `KNOWN_PREFIXES` — surfacing the addition as a deliberate decision in code review.

Baseline history: v0.7.0 audit = 117 keys / 30 prefixes / 100 % naming conformance. v0.8.0 drift batch (this release) added 51 explain entries for previously-uncovered WARN/ALERT findings, introducing 15 new prefixes (`backup, ddns, docker, fail2ban, firewall_stack, iptables_nft, log_rotation, logs, mac_policy, network_context, ntp, ports, rootkit, services, smtp`).

---

## Python support policy

> **Stable public commitment** — these rules govern when BOB drops support for an older Python.

BOB supports the **N and N-2** Python versions, where **N** is the current upstream stable. As of v0.7.0:

| Python | Status |
|---|---|
| 3.14 | ✅ supported (added in v0.7.0 — ladder step 1 for 3.10 drop) |
| 3.13 | ✅ supported |
| 3.12 | ✅ supported (current development target, CI default) |
| 3.11 | ✅ supported |
| 3.10 | ✅ supported (oldest — drop planned post-upstream EOL 2026-10) |
| 3.9  | ❌ end of life (dropped in v0.2.3) |

Python 3.10 deprecation ladder (in progress as of v0.7.0):
- **v0.7.0 — Ladder step 1** ✓ : both 3.10 and 3.14 in CI for forward-compatibility validation.
- **Next minor BOB release — Ladder step 2** : announce 3.10 deprecation in the changelog and `--help` banner.
- **Following minor BOB release (post-2026-10) — Ladder step 3** : drop 3.10 from CI, bump `requires-python` in `pyproject.toml`.

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

---

© 2026 Cédric Clauzel
