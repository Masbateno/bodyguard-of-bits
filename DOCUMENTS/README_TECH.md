*[Lire en français](README_TECH_FR.md)* · *[Vue d'ensemble](../README.md)*

# BOB — Bodyguard Of Bits

![License](https://img.shields.io/badge/license-MIT-green)
![Release](https://img.shields.io/badge/version-v0.1.0-brightgreen)
![CI](https://github.com/Masbateno/bodyguard-of-bits/actions/workflows/tests.yml/badge.svg)
![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu%20%7C%20Mint-informational)
![Language](https://img.shields.io/badge/language-Python%203.9%2B-yellow)

Linux hardening auditor for sysadmins and power users. CIS benchmark mapping, 46 checks across 9 domains, plain-language explanations and ready-to-run remediation commands.

BOB analyses your UFW configuration, detects exposed network services, classifies risks per service, and provides plain-language explanations with ready-to-run remediation commands.

---

## Features

- **ASCII banner** with system information (distro, host, UFW version, user, date)
- **UFW status check** — active/inactive, default incoming policy
- **UFW rule analysis** — duplicate rules, unrestricted `allow from any`, IPv6 consistency
- **Contextual scoring** — network context detection (direct public IP vs NAT); penalties doubled on internet-exposed machines; firewall inactive caps score at 3/10
- **Detection of 32 common network services** with UFW exposure analysis and two-axis risk context (exposure + threat) for critical and high-risk services; CRITICAL/HIGH services installed but inactive emit ⚠ + risk context block
- **iptables/nftables audit** — when UFW is inactive, audits the underlying firewall layer: detects active backend (iptables vs nftables); checks INPUT and FORWARD default policies; verifies conntrack stateful filtering (RELATED,ESTABLISHED ACCEPT); WARN −1 pt per permissive policy; gated on `not fw_status.active`
- **Docker analysis** — iptables bypass detection and list of ports exposed by running containers
- **Virtualisation analysis** — detects active hypervisors (libvirt/KVM, VirtualBox, VMware, LXD/LXC) and Snap network packages that may create bridge interfaces and manipulate iptables directly, bypassing UFW — same risk pattern as Docker
- **Listening ports analysis** — unified single-pass analysis; ephemeral and system ports silently skipped; NetBIOS handled with contextual warning
- **UFW log analysis** — parses `/var/log/ufw.log` over a configurable period (`--log-days=N`, default 7 days); total blocked attempts, top source IPs with geolocation, top targeted ports, bruteforce detection (>10 attempts/60s), attempts on installed service ports
- **IP geolocation** — source IPs enriched with country and operator via GeoIP2 (optional, `python3-geoip2` + GeoLite2 database); private ranges identified as local network; results cached per session
- **DDNS / external exposure detection** — detects active DDNS clients (ddclient, inadyn, No-IP, DuckDNS); extracts the configured domain; crosses with unrestricted UFW ALLOW rules to identify internet-exposed ports
- **Exposure classification** per service: `open to internet` / `local network only` / `blocked by UFW` / `no rule`
- **Fix mode** — interactive section after the summary; each automatable fix requires `[y/N]` confirmation; manual-only items displayed without execution; `-y / --yes` auto-fix mode displays a prominent warning banner and prints a full command summary after applying
- **Categorised summary** — findings split into three blocks: *Action required* / *Possible improvements* / *Normal configuration*; auto-generated interpretation phrase
- **Implicit policy note** — flags when high-risk services rely on the default `deny` policy rather than explicit rules
- **Security score** (0–10) with risk level: LOW / MEDIUM / HIGH / CRITICAL
- **Services panorama** — compact table of all 32 known services after the services audit (SERVICE / STATUS / PORT(S) / UFW), non-installed services shown dimmed
- **Bilingual interface** — English by default, French with `--french`
- **No-colour mode** — `--no-color` for clean output in pipes and log files
- **Optional detailed report** — timestamped log file with ASCII art header, system info, findings, and recommendations
- **`--manage-logs`** — interactive UI to list saved reports (name, size, date) and delete them by index or all at once; Enter opens a scrollable log preview (`s` toggles full/summary mode; `g`/`G` jump to top/bottom)
- **`--install-cron`** — schedule wizard: name the job, choose schedule type (daily / specific week days / specific month days / custom cron expression), set time, set optional notification email; preview in natural language before confirmation; named cron jobs (`/etc/cron.d/bob-{name}`)
- **`--manage-cron`** — looping TUI: list installed cron jobs, edit schedule or notification email, delete; `m` command opens the email address book (add / delete saved addresses) accessible even without any cron installed
- **Hardening check** — system hardening audit: unattended-upgrades, AppArmor mode, rp_filter, ICMP redirects, log_martians, ICMP broadcast echo; scored deductions for the most impactful settings
- **IPv6 consistency check** — detects IPv6 listeners not covered by a matching UFW v6 rule; conflict detection when IPv6 is disabled globally but listeners are present
- **Comparative report** — baseline saved after each audit (`~/.config/bob/last_baseline.json`); next run displays score delta, alert/warn changes, new/closed ports, started/stopped services
- **Plugin check API** — drop a Python file in `~/.config/bob/checks.d/` to add a custom audit check; plugins are fail-safe (exceptions never abort the audit) and ANSI-sanitized
- **SSH security audit** — full `sshd_config` analysis (15 directives + weak Ciphers/MACs/KEX); private key audit (type, size, passphrase); `authorized_keys` inspection; `~/.ssh/config` client-side check; `known_hosts` entry count; targets `SUDO_USER`'s home; distro-aware install hints
- **Sensitive files & sudoers** — permissions audit on `/etc/passwd`, `/etc/shadow`, `/etc/gshadow`, `/etc/group`, `/etc/sudoers` (world-writable → ALERT, too-permissive → WARN); SSH host private key permissions under `/etc/ssh/`; `NOPASSWD:ALL` detection across sudoers and sudoers.d
- **System updates audit** — detects pending security packages via `apt-get -s upgrade` (−2 pts flat); absent `unattended-upgrades` combined with pending security updates (−1 pt compound); regular updates → INFO only
- **Desktop application detection** — detects known GUI applications (Steam, Discord, Zoom, Signal, VLC, Spotify, Slack, Telegram, Chrome, Firefox…) running as processes; INFO findings, no deduction; section only shown when at least one app is detected
- **NTP time synchronisation** — checks whether systemd-timesyncd, chronyd, or ntpd is active and synchronised; WARN −1 pt if NTP is disabled or the clock is not yet synchronised
- **Fail2ban intrusion prevention** — dedicated standalone check; detects installation, service status, active jails, and presence of an SSH jail; WARN −1 pt if service inactive or no jails configured
- **Rootkit & integrity scan** — rkhunter/chkrootkit detection; WARN −1 pt for outdated rkhunter database (≥7 days), missing scan, or stale last scan (>30 days)
- **Linux Audit Framework (auditd)** — detects installation, service status, loaded rules, and coverage of sensitive files (/etc/passwd, /etc/shadow, /etc/sudoers); WARN −1 pt each for inactive service, no rules, uncovered sensitive files (server profile only)
- **Secure Boot** — UEFI Secure Boot state via `mokutil --sb-state` → `/sys/firmware/efi/efivars/` → `bootctl status`; WARN −1 pt if disabled on desktop; INFO if disabled on server/VM or BIOS/unknown
- **File integrity monitoring (AIDE/Tripwire)** — detects tool installation, database initialisation, and last check date; AIDE preferred over Tripwire; WARN −1 pt if no database or no recent check (>30 days); `_check_age_days` uses UTC-aware datetimes
- **`--explain KEY`** — structured per-finding explanation (WHY IT IS A RISK / HOW TO FIX / CIS Ubuntu 22.04 reference); 112 explainable keys in 26 groups; 17 keys show profile-specific sections (`[ server ]` / `[ desktop ]` / `[ container ]`); keys with no profile difference show a uniform yellow note; `--explain list` shows all keys with group headers; interactive TUI with ESC delay reduced to 25 ms; no root required
- **Domain scores** — per-domain security sub-scores (SSH / Samba Security / Files & Access / Updates / Hardening / Disk Health / Firewall & Services); 7 domains; displayed as bar chart after audit; included in JSON output and webhook payload
- **Webhooks** — `--webhook URL` POSTs audit result as JSON after each audit; generic (Grafana/automation) and Slack formats (auto-detected by URL); non-fatal; `--webhook-format=auto|generic|slack`
- **Samba security audit** — full `smb.conf` analysis: SMB1 protocol detection (ALERT, −2 pts); null passwords enabled (ALERT, −3 pts); server signing disabled (WARN, −1 pt); guest-writable shares (ALERT, −2 pts/share); guest-readable shares (WARN, −1 pt/share); `map to guest = bad user` (WARN, −1 pt); bind interfaces check (INFO); dedicated **samba** domain
- **ClamAV antivirus audit** — installation detection (`clamscan`/`clamdscan`/`freshclam`); virus database freshness via mtime (WARN −1 pt > 7 days, ALERT −2 pts > 30 days); clamd daemon status with socket-file fallback for containers; last scan date parsed from standard log paths (WARN −1 pt > 30 days, −1 pt > 90 days); deductions route to **hardening** domain
- **IoT/local source dominance** — detects when a single private IP accounts for ≥ 70% of all blocked UFW traffic over ≥ 50 log entries (WARN, −1 pt, `logs.local_dominance`); typical of LAN-scanning IoT devices or misconfigured servers
- **SMTP local exposure** — detects MTA (Postfix, Exim, Sendmail) listening on all interfaces (`0.0.0.0:25` or `:::25`) vs. localhost only; `SmtpSnapshot.from_system()` uses `ps -eo comm` + `ss -tlnp`/`netstat` fallback; WARN −1 pt when publicly exposed
- **`--fix` dry-run** — `--fix` alone shows a preview of all available corrections with `→ cmd` without executing; `--fix --apply` enables the interactive apply flow; `--fix --apply --yes` auto-confirms all with audit trail
- **`--target N`** — score target (1–10); shown in the summary box as `✔ reached` (green) or `▲ +N pt(s) needed` (yellow); returns exit code 4 when score < target (CI-ready, takes priority over codes 1/2)
- **5 thematic group headers** — audit output reorganised into five named groups: FIREWALL & NETWORK / EXPOSURE & SERVICES / ACCESS CONTROL / SYSTEM HARDENING / DETECTION & HEALTH; each group introduced by a full-width `━` cyan separator with the title centred in the line
- **`--diff` mode** — runs audit silently and displays only the comparative delta (what changed since last audit); tracks score, alert count, warn count, and info count (so INFO-level changes are detected)
- **`cmd_type` on findings** — `Finding` dataclass has `cmd_type: str = "fix"` / `"check"`; summary box uses `→` for fix commands and `ℹ` for check commands
- **Audit profiles** — `server` (default), `desktop` (replaces `workstation`), `container`; `workstation` alias kept for backward compatibility; active profile shown in the summary box
- **UFW logging level check** — detects UFW logging level (`ufw status verbose`); `off` → ALERT −2 pts (no visibility into blocked traffic); `low`/`medium` → OK; `high`/`full` → INFO (verbose mode, no deduction)
- **System umask audit** — `UmaskSnapshot` reads umask from `/etc/login.defs`, PAM, `/etc/profile`, shell RC files, and current process; permissive umask (0002/0000) → WARN −1 pt; conflicting sources → WARN −1 pt; `_fix_cmd()` proposes `/etc/profile.d/umask.conf`
- **SSH auth.log login analysis** — `AuthLogSnapshot` parses `/var/log/auth.log`; brute-force detection (>10 failed attempts from same IP within 60 s → ALERT −2 pts); last successful logins shown; top failed-login sources listed; `days=0` (just-rotated log) handled with dedicated no-range message
- **Score history** — JSONL at `~/.config/bob/history.jsonl`; `--history` displays last N audit scores as a sparkline (▁▂▃▄▅▆▇█) with date; automatic 90-entry rotation
- **Ignore list** — `--ignore KEY` adds a finding key to `ignore.yml`; `--show-ignored` lists all active exceptions; `ScoreEngine.ignore_keys` frozenset silences matching findings without scoring; hint shown in output; `{check_key}` placeholder used in locale key to avoid `t()` signature conflict
- **Process-aware system port classification** — `_SYSTEM_DAEMONS` frozenset in `checks/ports.py`; ports in `_SYSTEM_PORTS` (DNS, DHCP, mDNS, UPnP…) are classified `SYSTEM_INTERNAL` only when the owning process is a known OS daemon; user-space apps (e.g. Spotify on `1900/udp`) fall through to standard exposure checks
- **TLS/SSL certificate expiry audit** — scans Let's Encrypt (`/etc/letsencrypt/live/*/fullchain.pem`), `/etc/ssl/private/*.{pem,crt,cert}`, nginx `ssl_certificate`, apache2 `SSLCertificateFile`, postfix `smtpd_tls_cert_file`; expired → ALERT −2 pts; <7 d → ALERT −2 pts; <30 d → WARN −1 pt; total capped at −4 pts; `_MAX_CERTS=30`; quoted paths and broken symlinks handled
- **Systemd timers security audit** — `systemctl list-timers --all --no-pager`; curl/wget piped to a shell in ExecStart → WARN −2 pts (flat); world-writable `.sh` scripts in ExecStart → WARN −1 pt (flat); user-created timers in `/etc/systemd/system/` without `User=` → INFO; two-part regex prevents false negatives on `/bin/bash`/`bash -c`; `lstrip("-@")` handles systemd prefixes; `_MAX_TIMERS=100`
- **Firmware & microcode audit** — `fwupdmgr get-updates` (cached, no forced network); pending device firmware → WARN −1 pt; CPU microcode package via `dpkg -l`; Intel → `intel-microcode`; AMD → `amd64-microcode`; non-Intel/AMD → INFO; missing → WARN −1 pt; exact column match prevents false positives on arch-qualified packages; error and updates decoupled
- **`--html` HTML export** — `build_html_output()` produces a self-contained HTML file (no JS, no external resources); embedded CSS; colored score circle; ALERT/WARN/INFO/OK badges; deductions table; `_h()` applies `html.escape(quote=True)` to all user data — XSS-safe
- **`--check LIST` / `--skip LIST`** — run only named checks (`--check=ssh,firewall`) or exclude them (`--skip=clamav,rootkit`); mutually exclusive; `_section_enabled()` helper in `runner.py`; `validate_check_filters()` warns on unknown names; profile `skip_sections` respected; `--check=list` prints all 31 filterable section names (no sudo required)
- **`--output-dir PATH`** — override report save directory for the current run; `get_or_prompt_log_dir()` prioritises this over saved config; no persist
- **Signal correlation engine** — `correlation.py`: 5 compound-risk rules (root+no-fail2ban → ALERT; password-auth+brute-force → ALERT; root+password → ALERT; NOPASSWD+SUID → WARN; stale+no-fail2ban → WARN; logging-off+no-fail2ban+no-auditd → WARN); `CorrelationRule` with `all_of`/`any_of` frozensets; evaluated post-finalize on ALERT+WARN finding keys; `triggered_by` list identifies contributing findings
- **Recurring finding tracker** — `recurrence.py`: consecutive-audit appearance counter per ALERT/WARN key; `~/.config/bob/recurrence.json`; atomic write; corrupted/negative values normalised; empty-key entries filtered on load
- **Port exposure analysis** — `exposure.py`: groups exposed listening services by interface scope and risk level; `fw_policy not in ("deny", "reject")` allowlist; direct `lp.port` attribute for ephemeral-port filter
- **Comparative report — finding-key diff** — `AuditBaseline.finding_keys` persists active ALERT+WARN keys; `AuditDelta` adds `new_finding_keys` / `resolved_finding_keys`; migration guard prevents false-positive flood on first run after upgrade; `display_delta()` shows each appeared/resolved key
- **IPv6 link-local false-positive fix** — `_read_global_ipv6()` parser; `has_global_ipv6` field; WARN −2 pts downgraded to INFO when only link-local (fe80::/10) or ULA (fc/fd::/7) addresses assigned — machine not internet-reachable via IPv6
- **Kernel obsolete message fix** — `kernels_obsolete_same` locale key; suppresses redundant "(running: X, latest: X)" parenthetical when running kernel equals most-recent installed
- **Snakeoil cert filter** — `ssl-cert-snakeoil.pem` excluded from `/etc/ssl/private` scan; prevents Debian/Ubuntu system test cert from triggering TLS audit
- **`--explain`** — 87→112 keys (+25 across 7 new groups: Authentication Logs, Umask, Firewall Logging, TLS / SSL Certificates, Systemd Timers, Firmware, Docker)
- **`--format=FORMAT`** — unified output flag: `json | json-full | csv | markdown | html`; legacy flags (`-j`, `-J`, `--output csv`, `--html`) kept as silent aliases; mutually exclusive with each other
- **`--check=list`** — prints all 31 filterable section names with a prefix-matching note; no sudo required
- **`--install-cron` curses TUI** — `run_install_cron()` wraps `curses.wrapper()` for a full curses TUI with inline readline, Esc-to-cancel on every prompt, live schedule preview; falls back to the plain wizard when curses is unavailable; `run_manage_cron()` upgraded with the same curses/fallback pattern
- **`bob/_tty.py`** — raw-mode line reader (`read_line()`): standalone Esc returns `None` (cancel); arrow-key sequences drained via 50 ms `select` window; graceful `input()` fallback in non-TTY environments (tests, pipes)
- **Risk context scope qualifier** — `[CRITICAL • LAN]` (or `[CRITIQUE • LAN]` in French) appended to service labels when the network context is local; prevents confusion between local risk and internet exposure
- **TUI help bar harmonization** — consistent hints across `--explain`, `--manage-logs`, and log preview: `↑↓: move` for list navigation, `↑↓ / PgUp/PgDn: scroll` for content, `Esc: back` for sub-screens
- **CIS compliance mapping inline** — each finding in the summary box shows its machine-readable CIS code `[CIS:X.Y.Z]` (dimmed); full CIS reference text shown dimmed in `--verbose` mode after each WARN/ALERT finding; refs served from `cis_refs.json` (133 entries: 99 formal CIS, 34 best-practice, 4 Docker), language-independent; `get_cis_ref()` / `get_cis_code()` public API
- **5 new services (v0.1.0)** — SMTP/Postfix (25/tcp, high), NFS Server (2049/tcp+udp, high), Jenkins (8080/tcp, high), OpenVPN (1194/udp, medium), Squid Proxy (3128/tcp, medium); registry now covers 32 services

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

- Linux system — Debian, Ubuntu, Linux Mint, or derivative
- UFW installed: `sudo apt install ufw`
- Python 3.9+
- `ss` recommended (`iproute2` package) — available by default on modern systems
- `python3-geoip2` + GeoLite2 database recommended for IP geolocation (optional): `sudo apt install python3-geoip2 geoip-database`
- `docker` CLI for Docker analysis (optional)

---

## Installation

### Prerequisites

- Linux: Debian, Ubuntu, Mint or derivative
- UFW: `sudo apt install ufw`
- pipx: `sudo apt install pipx && pipx ensurepath`

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
║  BOB v0.1.0  │  Linux hardening auditor                                      ║
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

> **Plugin directory and `sudo`:** bob runs as root. Under `sudo`, `Path.home()` resolves to `/root`,
> so the active plugin directory is `/root/.config/bob/services.d/`, not the calling user's home.
> Place plugin files there to have them loaded at runtime.
>
> **Future `.deb` packaging:** this will change to the system-wide `/etc/bob/services.d/`,
> which is the standard Debian convention for system-level configuration and removes the `sudo`/home ambiguity.

---

## Exit codes

When using `--quiet`, the exit code tells you the audit result:

| Code | Meaning |
|------|---------|
| `0`  | Clean audit — no alerts, no warnings |
| `1`  | Warnings detected |
| `2`  | Alerts detected — action required |
| `3`  | Technical error |
| `4`  | Score below `--target N` threshold |

Example cron job — daily audit at 6am, email on issues:

```bash
0 6 * * * sudo bob --quiet -d || echo "bob exit $? on $(hostname)" | mail -s "UFW Alert" admin@example.com
```

---

## Important note

BOB is an audit and diagnostic tool, not a security shield. It analyses your configuration and flags problems — but it does not apply corrections automatically without your consent, and it cannot detect everything. Some software like Docker can bypass UFW by manipulating iptables directly: bob detects this specific case and flags it, but other similar vectors exist that fall outside the current scope of the project. In short: bob helps you see more clearly — it does not replace good general security hygiene.

---

## License

MIT License — © 2026 Cédric Clauzel. See `LICENSE` for details.

---

## Author

Cédric Clauzel