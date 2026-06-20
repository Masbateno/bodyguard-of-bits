*[Lire en français](README_FR.md)*

# BOB — Bodyguard Of Bits

**Linux hardening auditor for sysadmins who read the output.**

BOB is a CLI security audit and hardening tool for Linux systems. It runs 36 check sections across 7 score domains, maps findings to CIS benchmark sections when applicable, and shows not just *what* is wrong — but *why it matters* and *how to fix it with concrete commands*.

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

## What BOB is — and is not

**BOB is** a hardening auditor. It evaluates configuration hygiene against CIS benchmarks and established best practices, **modulated by the active audit profile and detected network context**. The score reflects *configuration hygiene under the stated assumptions* — not an absolute security verdict.

**BOB is not:**

- a vulnerability scanner — it does not probe CVE databases, fingerprint software versions for known exploits, or test exploitation paths (use OpenVAS, Nessus, etc.);
- a threat-modeling engine — it does not enumerate attacker paths, test reachability from outside the host, or simulate compromise scenarios (use external scanners, red-team tooling, security teams);
- an autonomous verdict system — a clean score means *"hygienically configured for the chosen profile in the detected network context"*, not *"impossible to compromise"*. Human interpretation is required to translate the verdict into operational risk.

**Concrete consequences:**

- A 10/10 score on a desktop in a LAN does **not** mean a 10/10 on the same host moved to a public cloud — re-audit with the appropriate profile.
- A finding flagged as `improvement` rather than `action` reflects the network context (e.g. SSH password auth is acceptable hygiene on a LAN-only host, but should be tightened before exposing the host directly to the internet).
- The audit profile (`server` / `workstation` / `container`) encodes the threat model. Changing profile changes the verdict — that is the design.
- BOB's network-context detection (NAT / public IP / interface state) is **heuristic**, not active reachability probing. It tells you what BOB infers from the local system, not what an attacker would observe from outside.

A pure CIS-strict mode (no contextual modulation) is on the roadmap.

---

## Install

> **Safety**: BOB is audit-only. It executes only read-only commands (`ss`, `dpkg-query`, `systemctl status`, `sysctl -n`, `ufw status`, etc.) and never writes outside `~/.config/bob` and its log directory. The optional `--fix --apply` mode prompts before each remediation; nothing else modifies system state. A typical audit completes in under 5 seconds.

### Prerequisites

`pipx` (the isolated Python app installer):

```bash
sudo apt install pipx && pipx ensurepath
```

> Open a new terminal after `pipx ensurepath` so the `PATH` change takes effect.

### Install BOB

```bash
pipx install bodyguard-of-bits
```

---

## Enable `sudo bob` + bash completion

pipx installs the `bob` binary into `~/.local/bin/`, which is **not** in sudo's restricted `PATH`. Run `--install-completion` once with the absolute path — it creates the symlink `/usr/local/bin/bob` and installs the bash completion script:

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

## Sample output

```
$ sudo bob

╔══════════════════════════════════════════════════════════════════════════════╗
║                            — Bodyguard Of Bits —                             ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  BOB v0.6.2  │  Linux hardening auditor                                      ║
║  System        : Linux Mint 22.3                                             ║
║  Kernel        : 6.17.0-23-generic                                           ║
║  UFW           : v0.36.2                                                     ║
╚══════════════════════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━ SYSTEM HARDENING ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✔ [OK]    SYN flood protection active (tcp_syncookies=1)
✔ [OK]    ASLR fully enabled (randomize_va_space=2)
⚠ [WARN]  System sends ICMP redirects — exploitable for MITM on a non-router
   → sudo sysctl -w net.ipv4.conf.all.send_redirects=0
   [CIS:3.3.2]
   ? bob --explain hardening.send_redirects

╔══════════════════════════════════════════════════════════════════════════════╗
║  Security score   : 8/10  ↑ +1                                               ║
║  Risk level       : ✔ LOW                                                    ║
║  Firewall & Services  10/10  ██████████                                      ║
║  SSH                   7/10  ███████░░░                                      ║
║  System Hardening      4/10  ████░░░░░░                                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

Every WARN/ALERT shows a CIS reference (when applicable), a copy-paste remediation command, and an `--explain` hint linking to the longer rationale.

---

## Security checks — 36 check sections, 7 score domains

| Domain | What it covers |
|--------|----------------|
| **Firewall** | UFW rules, iptables/nftables (when UFW inactive), IPv6 consistency, port exposure |
| **SSH** | sshd_config hardening — PermitRootLogin, key strength, timeouts, forwarding |
| **Kernel hardening** | sysctl parameters, kernel modules, Secure Boot, firmware/microcode |
| **Services** | 38 known services with risk classification; Docker firewall bypass detection |
| **File permissions** | SUID/SGID audit, sensitive files, sudoers |
| **User accounts** | Expired accounts, password policy, login.defs, PAM |
| **System updates & detection** | apt updates, auditd rules, Fail2ban, ClamAV, AppArmor/SELinux, AIDE/Tripwire integrity, rkhunter, SMART, firmware/microcode |
| **Operations** | Log rotation, auth.log analysis, NTP sync, TLS cert expiry, systemd timers, Samba, cron jobs |
| **Network** | Public IP context, network type detection (server/LAN/VPN), GeoIP optional |
| **Docker** | Daemon hardening, privileged containers, sensitive mounts |

---

## CIS benchmark mapping

174 entries: **107 CIS Ubuntu 22.04 · 7 CIS Docker · 60 best-practice**.

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
| `desktop` | Relaxed for desktop systems — SSH password auth tolerated, GUI apps not flagged, manual update mechanisms accepted (~11 overrides extending `server`) |
| `workstation` | First-class business-tier profile since v0.8.1 (no longer an alias to `desktop`) — keeps backup / auditd / MAC-enforce findings at WARN while relaxing the same SSH / clamav / rootkit / file-integrity ergonomics as `desktop` |
| `container` | Extends `desktop` and skips host-level checks (kernel modules, kernel hardening, secure boot, auditd, suid_audit, docker_audit, file integrity, rootkit) |

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

**Score breakdown:**
```
sudo bob --breakdown              # full score computation path (-B shorthand)
sudo bob -B
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

## SUID whitelist

On Kali and other security-focused distributions, legitimate tools ship with the SUID bit set. Declare approved basenames or glob patterns in `~/.config/bob/config.conf` to suppress them from the "unexpected SUID" warning:

```
# ~/.config/bob/config.conf
suid_whitelist = kismet_cap_*, my_enterprise_tool
```

Patterns are matched against the binary basename using `fnmatch`. Suppressed binaries are reported as INFO so the whitelist is always visible.

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Score ≥ 7 — no significant issues |
| `1` | Score 4–6 — warnings present |
| `2` | Score 1–3 — alerts present |
| `3` | Score 0 — critical issues |
| `4` | Score below `--target N` threshold (custom gate, e.g. `bob --target 8` fails CI if score < 8) |

---

## Requirements

- Python 3.10+
- Root (`sudo`)
- `ss`, `systemctl` — standard on most Linux systems

Optional: `geoip2` for IP geolocation (`pipx inject bodyguard-of-bits geoip2`)

---

## Distribution support

| Tier | Distros | Status |
|------|---------|--------|
| **Tier 1** (daily-driven) | Linux Mint 22.x, Debian 13 | Full feature set, validated on production hardware |
| **Tier 2** (CI-validated) | Debian 12, Ubuntu 22.04/24.04/25.04, Kali Rolling, Fedora 41 | Smoke + offline audit run on every PR; no locale sentinels, no Python tracebacks |
| **Tier 3** (works but untested) | Other Debian/RHEL/SUSE/Arch-family Linux | Best-effort; checks degrade gracefully |

On non-apt distributions (Fedora, RHEL, openSUSE, Arch), checks that rely on `apt` (e.g. pending security updates) emit INFO instead of WARN — BOB does not currently consume `dnf`/`zypper`/`pacman` metadata. CIS Ubuntu 22.04 references are still emitted when the underlying control (sysctl flags, SSH config, file permissions) is OS-agnostic.

---

## See also

- [Tutorial — getting started](DOCUMENTS/TUTORIAL.md)
- [Full technical reference](DOCUMENTS/README_TECH.md)
- [Changelog](CHANGELOG.md)
- [Developer guide](DOCUMENTS/README_DEV.md)
- [Automation guide](DOCUMENTS/AUTOMATION.md)

---

## License

MIT — see [LICENSE](LICENSE).

---

## Contributing

Issues and pull requests are welcome at [github.com/Masbateno/bodyguard-of-bits](https://github.com/Masbateno/bodyguard-of-bits/issues). For substantial features, opening an issue first to discuss scope is appreciated.

---

© 2026 Cédric Clauzel
