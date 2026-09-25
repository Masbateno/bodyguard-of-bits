<p align="center">
  <img src="https://raw.githubusercontent.com/Masbateno/bodyguard-of-bits/main/assets/logo_bob.png" alt="BOB — Bodyguard Of Bits" width="180">
</p>

*[Lire en français](README_FR.md)*

# BOB — Bodyguard Of Bits

![License](https://img.shields.io/badge/license-MIT-green)
![Release](https://img.shields.io/badge/version-0.21.1-brightgreen)
![PyPI](https://img.shields.io/pypi/v/bodyguard-of-bits?label=pypi&color=blue)
![Downloads](https://img.shields.io/pypi/dm/bodyguard-of-bits?label=downloads&color=blue)
![CI](https://github.com/Masbateno/bodyguard-of-bits/actions/workflows/tests.yml/badge.svg)
![Integration](https://github.com/Masbateno/bodyguard-of-bits/actions/workflows/integration.yml/badge.svg)
![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)
![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu%20%7C%20Mint%20%7C%20Kali%20%7C%20Fedora%20%7C%20openSUSE%20%7C%20Alpine%20%7C%20Raspberry%20Pi-informational)
![Python](https://img.shields.io/pypi/pyversions/bodyguard-of-bits)

**Linux hardening auditor for sysadmins who read the output.**

BOB is a CLI security audit and hardening tool for Linux systems. It runs 47 check sections across 6 score domains, maps findings to CIS benchmark sections when applicable, and shows not just *what* is wrong — but *why it matters* and *how to fix it with concrete commands*.

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
- The audit profile (`server` / `desktop` / `workstation` / `container`) encodes the threat model. Changing profile changes the verdict — that is the design.
- BOB's network-context detection (NAT / public IP / interface state) is **heuristic**, not active reachability probing. It tells you what BOB infers from the local system, not what an attacker would observe from outside.

A pure CIS-strict mode (no contextual modulation) is on the roadmap.

---

## Install

> **Safety**: BOB is audit-only. It executes only read-only commands (`ss`, `dpkg-query`, `systemctl status`, `sysctl -n`, `ufw status`, etc.) and never writes outside `~/.config/bob` and its log directory. The optional `--fix --apply` mode prompts before each remediation, and only for commands BOB can run unattended — a diagnostic like `smartctl -a` is shown, never executed. Adding `--yes` skips the prompts; nothing else modifies system state. An audit takes a few seconds and **reports its own duration** since v0.16.4, so you need not take that on trust — the exact figure depends on the host and how many checks are active.

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

> **On a Raspberry Pi?** See the [Raspberry Pi guide](DOCUMENTS/RASPBERRY_PI.md) — install and usage specifics, the boot-partition credential checks, and exactly what was validated on a real Pi Zero W.

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
sudo bob --french                 # French output
sudo bob -d                       # save the full report to a log file
sudo bob --profile workstation    # workstation profile (SAVED as your default)
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
║  BOB 0.21.1  │  Linux hardening auditor                                     ║
║  System        : Linux Mint 22.3                                             ║
║  Kernel        : 6.17.0-23-generic                                           ║
║  UFW           : 0.36.2                                                      ║
╚══════════════════════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━ SYSTEM HARDENING ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✔ [OK]    SYN flood protection active (tcp_syncookies=1)
✔ [OK]    ASLR fully enabled (randomize_va_space=2)
⚠ [WARN]  System sends ICMP redirects — exploitable for MITM on a non-router
   → sudo sysctl -w net.ipv4.conf.all.send_redirects=0
   [CIS:3.3.2]
   ? bob --explain hardening.send_redirects_enabled

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

## Security checks — 47 check sections, 6 score domains

| Domain | What it covers |
|--------|----------------|
| **Firewall** | UFW rules, iptables/nftables (when UFW inactive), IPv6 consistency, port exposure |
| **SSH** | sshd_config hardening — PermitRootLogin, key strength, timeouts, forwarding |
| **Kernel hardening** | sysctl parameters, kernel modules, Secure Boot, firmware/microcode |
| **Boot & storage** | GRUB password/config permissions, mount options (nodev/nosuid/noexec), LUKS disk encryption, core-dump policy, kexec/kernel lockdown |
| **Services** | 38 known services with risk classification; Docker firewall bypass detection; CUPS print-service network exposure |
| **File permissions** | SUID/SGID audit, sensitive files, sudoers, polkit rule permissions |
| **User accounts** | Expired accounts, password policy, login.defs, PAM, account lockout (pam_faillock) |
| **System updates & detection** | apt updates, auditd rules, Fail2ban, ClamAV, AppArmor/SELinux, AIDE/Tripwire integrity, rkhunter, SMART, firmware/microcode |
| **Operations** | Log rotation, auth.log analysis, NTP sync, TLS cert expiry, systemd timers, Samba, cron jobs |
| **Network** | Public IP context, network type detection (server/LAN/VPN), GeoIP optional |
| **Docker** | Daemon hardening, privileged containers, sensitive mounts |

---

## CIS benchmark mapping

205 entries: **110 CIS Ubuntu 22.04 · 7 CIS Docker 1.6 · 1 CIS Red Hat 8/9 · 87 best-practice**, plus **163 cross-benchmark citations** on 58 keys (CIS Debian 12/13 and CIS Ubuntu 24.04), sourced from [ComplianceAsCode/content](https://github.com/ComplianceAsCode/content) so every control number is verifiable rather than invented.

Each finding with a formal CIS code displays `[CIS:X.Y.Z]` inline in the summary box.  
Full reference text is shown in `--verbose` mode.  
`--explain KEY` returns the WHY, the HOW, the CIS section, and an **Also cited in** block naming the same control's number in every other benchmark that covers it. `--explain list` and the wizard group all keys as a folder tree — CIS distribution → benchmark version → type.

---

## --explain

```
bob --explain                     # interactive TUI — ↑↓/jk PgUp/PgDn g/G to navigate, Enter to view, l to switch language
bob --explain ssh.password_auth   # direct lookup
bob --explain list                # list all explainable keys
```

No sudo required. Fully offline — no external calls or data collection.

---

## Audit profiles

| Profile | Use case |
|---------|----------|
| `server` | Default — strict on SSH, firewall, services |
| `desktop` | Relaxed for desktop systems — SSH password auth tolerated, GUI apps not flagged, manual update mechanisms accepted (~35 overrides extending `server`) |
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

> **Stable public API** — these codes will not change within a major version.

The code reflects the *findings*, not the score:

| Code | Constant | Meaning |
|------|----------|---------|
| `0` | `EXIT_OK` | Clean audit — no alerts, no warnings |
| `1` | `EXIT_WARNINGS` | Warnings detected (improvements suggested) |
| `2` | `EXIT_ALERTS` | Alerts detected — action required |
| `3` | `EXIT_ERROR` | Technical error (CLI parsing, IO, internal) |
| `4` | `EXIT_TARGET_MISSED` | `--target N` specified and score < N, **or anything could not be read** (v0.16.2, widened from "is an upper bound"): a score nothing verified cannot satisfy a gate, so it fails closed |

Note that `3` is a **technical error**, not a bad score: a failing audit never
exits 3. Use `--target N` if you want a score threshold to gate CI.

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
| **Tier 1** (validated on real hardware) | Linux Mint 22.3, Debian 13, Ubuntu Server 26.04, Fedora 44 Server, openSUSE Leap 16, Alpine 3.24 (OpenRC, no systemd), Kali Rolling | Full feature set, each stress-tested on a real machine during the v0.20.x cycle — exhaustive multi-angle passes covering firewalld and SELinux (Fedora, openSUSE), AppArmor (Kali), socket-activated services, cross-distro updates, and remediation round-trips. Mint and Debian are daily-driven; the rest are dedicated test machines — Ubuntu 26.04 on Python 3.14, Fedora 44 (SELinux enforcing, firewalld), openSUSE Leap 16 (zypper, SELinux), Kali Rolling (AppArmor, no-security-channel updates; also exercised in CI on every PR) |
| **Tier 2** (validated in CI on every PR) | Debian 12, Ubuntu 22.04/24.04/25.04, Fedora 41 · **Debian Bookworm arm64** (emulated) | CI runs a smoke + offline audit on every PR; no locale sentinels, no Python tracebacks, and the arm64 job additionally asserts that x86 firmware concepts degrade and that the Raspberry Pi section fires. Earlier releases were also hand-audited on throwaway VMs (Fedora 43, openSUSE Leap 15.6, Alpine 3.22) — that pass is where the v0.17.1 and v0.18.0 defects were found — but those OS families are now covered by real hardware in Tier 1, so the per-release VM pass has been retired |
| **Tier 3** (works, not validated on hardware) | Other Debian/RHEL/SUSE/Arch-family Linux · **Raspberry Pi OS** (Bookworm, arm64) | Best-effort; checks degrade gracefully. The Raspberry Pi *section* is covered by the arm64 CI job above; the *board* has been audited once on physical hardware (a Pi Zero W, trixie, v0.18.1) — see below |

**Raspberry Pi** is recognised as of v0.17.0. BOB reads the board name from the device tree and reports what a PC does not have: provisioning credentials left on the FAT boot partition — the Imager's `userconf.txt` on Bookworm, and on trixie the cloud-init seed, whose `user-data` holds the account's password hash and `network-config` the Wi-Fi key, on a filesystem that carries no ownership of its own — the first-boot `ssh` marker, and the distribution's historical `pi` account when it can actually log in. x86 firmware concepts degrade instead of deducting: microcode is not applicable, and Secure Boot reports that no UEFI was found rather than claiming a BIOS the board does not have. BOB does **not** test whether the `pi` account still has the default password: that needs `crypt`, which Python removed from the standard library in 3.13. The section was field tested on emulated `aarch64` (qemu-user): the board is read from the device tree, the boot partition resolves to Bookworm's `/boot/firmware`, the imager's yescrypt hash is recognised, and the `--fix --apply` round trip removes the file and clears the finding. Emulation is not hardware, and it is not silently equivalent either — `setrlimit(RLIMIT_AS)` returns success and applies nothing under qemu-user, which is how the plugin sandbox was caught claiming a memory cap it never got. An arm64 job runs on every PR: it refuses to pass unless `uname -m` really says `aarch64`, then asserts the audit exits cleanly, that microcode degrades, that no UEFI is not announced as a BIOS, and that the Raspberry Pi section fires on a simulated board. **v0.18.1 is the first release audited on a physical Pi** — a Zero W on Raspbian 13 trixie — and it found what emulation never could: the boot-partition check was looking for a file trixie no longer writes, while the cloud-init seed next to it held the sudo account's current hash, and SSH brute-force detection was blind to OpenSSH ≥ 9.8. One board is not a matrix: reports from other models are still worth more than any number of emulated runs.

On non-apt distributions (Fedora, RHEL, openSUSE, Arch, Alpine), checks that rely on `apt` metadata (e.g. pending security updates) emit INFO instead of WARN — BOB does not consume `dnf`/`zypper`/`pacman` update metadata. CIS Ubuntu 22.04 references are still emitted when the underlying control (sysctl flags, SSH config, file permissions) is OS-agnostic.

**Remediation commands are chosen for your package manager** since v0.17.0. Before that every "install this" finding read `sudo apt install …` on every host, and the package names were Debian's — `sudo dnf install auditd` installs nothing, because Fedora calls it `audit`. The names were measured in containers rather than recalled, and where BOB has no measured name for your manager it says so instead of inventing a command: an instruction that installs nothing is worse than an admission, because you have no reason to doubt it.

The same release fixed a query that answered yes to everything on the whole RPM family. `rpm -q nosuchpackage` prints *"package nosuchpackage is not installed"* on **stdout** and exits 1; BOB counted any output as proof of installation, so on Fedora, RHEL and openSUSE every package read as installed — including names that exist nowhere. The visible effect was an audit reporting on services that were not there, and a microcode verdict of "OK" that had checked nothing. **If you run BOB on an RPM-based distribution, v0.17.0 is not optional.**

The same release stopped BOB reading Debian's filenames to decide. `/etc/pam.d/common-password` is Debian's name for the PAM password stack, and the password-policy check deducted a point on every Fedora, RHEL, openSUSE and Arch host having read nothing — Fedora's `system-auth` carries `pam_pwquality.so` on line 13. Alpine, which has no PAM at all, now gets "could not establish" rather than a deduction, and the score says it is a ceiling.

---

## See also

- [Tutorial — getting started](DOCUMENTS/TUTORIAL.md)
- [Raspberry Pi guide](DOCUMENTS/RASPBERRY_PI.md)
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
