*[Lire en français](README_FR.md)*

# BOB — Bodyguard Of Bits

**Linux hardening auditor for sysadmins who read the output.**

BOB is a CLI security audit and hardening tool for Linux systems. It runs 46 checks across 9 domains, maps findings to CIS benchmark sections when applicable, and shows not just *what* is wrong — but *why it matters* and *how to fix it with concrete commands*.

---

## Who it's for

- Sysadmins running periodic hardening reviews
- Power users who want more than a score and a list of flags
- Anyone tired of noisy, unactionable audit tools

BOB is not a scanner. It does not exploit, probe, or guess. It deterministically evaluates your configuration against CIS benchmarks and established best practices.

---

## Why BOB?

Lynis and OpenSCAP are solid, well-established tools — if you need broad compliance coverage or formal certification workflows, they're the right choice.

BOB serves a different purpose: **practical hardening for sysadmins who need to act on findings, not file them**. Every result comes with a plain-language explanation and a ready-to-run remediation command. The security score is context-aware — a machine directly exposed to the internet is held to a stricter standard than one behind NAT. Output is structured to be read in a terminal, not archived.

If you already run Lynis, BOB is not a replacement — it's a different lens, one that tells you what to do next.

---

## Install

```
pipx install bodyguard-of-bits
sudo bob
```

Bash completion:
```
sudo bob --install-completion
```

---

## Quick start

```
sudo bob                          # full audit, server profile
sudo bob --verbose                # add CIS refs and remediation commands per finding
sudo bob -d                       # French output
sudo bob --profile workstation    # workstation profile
sudo bob --check ssh,hardening    # run only selected domains
sudo bob --format json > out.json # machine output
bob --explain ssh.password_auth   # explain a finding (no sudo)
```

---

## Security checks — 46 checks, 9 domains

| Domain | What it covers |
|--------|----------------|
| **Firewall** | UFW rules, iptables/nftables (when UFW inactive), IPv6 consistency, port exposure |
| **SSH** | sshd_config hardening — PermitRootLogin, key strength, timeouts, forwarding |
| **Kernel hardening** | sysctl parameters, kernel modules, Secure Boot, firmware/microcode |
| **Services** | 32 known services with risk classification; Docker firewall bypass detection |
| **File permissions** | SUID/SGID audit, sensitive files, sudoers |
| **User accounts** | Expired accounts, password policy, login.defs, PAM |
| **System** | apt updates, log rotation, auth.log analysis, NTP, Fail2ban, auditd, ClamAV, AppArmor/SELinux, SMART, TLS cert expiry, systemd timers, Samba, cron jobs |
| **Network** | Public IP context, network type detection (server/LAN/VPN), GeoIP optional |
| **Docker** | Daemon hardening, privileged containers, sensitive mounts |

---

## CIS benchmark mapping

133 entries: **99 CIS Ubuntu 22.04 · 4 CIS Docker · 34 best-practice**.

Each finding with a formal CIS code displays `[CIS:X.Y.Z]` inline in the summary box.  
Full reference text is shown in `--verbose` mode.  
`--explain KEY` returns the WHY, the HOW, and the CIS section — in plain English.

---

## --explain

```
bob --explain                     # interactive TUI — navigate findings with ↑↓, Enter to view
bob --explain ssh.password_auth   # direct lookup
bob --explain list                # list all explainable keys
```

No sudo required. Fully offline — no external calls or data collection.

---

## Audit profiles

| Profile | Use case |
|---------|----------|
| `server` | Default — strict on SSH, firewall, services |
| `workstation` | Relaxed SSH, desktop apps not flagged |
| `desktop` | Workstation + GUI-specific checks |
| `docker` | Container-optimised, skips irrelevant checks |

```
sudo bob --profile workstation
```

User-defined profiles: `~/.config/bob/profiles/`

---

## Output formats

```
sudo bob                          # terminal (default)
sudo bob --format json            # JSON
sudo bob --format csv             # CSV
sudo bob --format markdown        # Markdown
sudo bob --html                   # standalone HTML report
sudo bob --output-dir /var/reports --format json
```

---

## Automation

**Cron scheduling:**
```
sudo bob --install-cron           # interactive wizard
sudo bob --manage-cron            # manage installed jobs
```
Jobs live in `/etc/cron.d/bob-{name}`. Email notification on exit code > 0.

**Webhooks** (generic JSON or Slack):
```
sudo bob --webhook https://hooks.slack.com/...
```

**Score history and trends:**
```
sudo bob --history                # sparkline of past scores
```

**Diff mode:**
```
sudo bob --diff                   # show only changes since last baseline
```

**Watch mode:**
```
sudo bob --watch=60               # rerun every 60 seconds
```

---

## Custom services

Drop a `.json` file into `~/.config/bob/services.d/` to extend the service registry:

```json
{
  "id": "my_app",
  "name": "My App",
  "port": "9000/tcp",
  "risk": "medium"
}
```

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Score ≥ 7 — no significant issues |
| `1` | Score 4–6 — warnings present |
| `2` | Score 1–3 — alerts present |
| `3` | Score 0 — critical issues |
| `4` | Score below `--target N` threshold |

---

## Requirements

- Linux — tested on Linux Mint 22.3, Debian 13.4.0
- Python 3.9+
- Root (`sudo`)
- `ss`, `systemctl` — standard on most Debian-based systems

Optional: `geoip2` for IP geolocation (`pipx inject bodyguard-of-bits geoip2`)

---

## See also

- [Full technical reference](DOCUMENTS/README_TECH.md)
- [Changelog](CHANGELOG.md)
- [Developer guide](DOCUMENTS/README_DEV.md)
- [Automation guide](DOCUMENTS/AUTOMATION.md)
