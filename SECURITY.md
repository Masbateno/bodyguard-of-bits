# BOB — Security Policy

*[Lire en français](SECURITY_FR.md)*

## Supported versions

Security patches are issued for the latest minor release line only. Older minors
are not backported.

| Version   | Supported          |
|-----------|--------------------|
| 0.4.x     | ✅ current          |
| 0.3.x     | ❌ end of life      |
| < 0.3.0   | ❌ end of life      |

Patches release as `0.4.x+1`. A breaking change bumps the minor (`0.5.0`).

## Reporting a vulnerability

**Do not file a public GitHub issue for a security report.**

Report security issues by email to:

```
cedricclauzel@mailo.com
```

with the subject prefix `[BOB security]`. Include:

  - BOB version (`bob --version`)
  - Platform (distro + version, kernel version)
  - Minimal reproduction (commands, expected vs observed behavior)
  - Impact assessment as you see it

You will receive an acknowledgement within **7 days**. A fix or remediation
plan will be communicated within **30 days** for high-severity issues
(arbitrary code execution, privilege escalation, sensitive data leak).
Lower-severity issues (denial of service against the audit itself,
information disclosure of public sysctl values, etc.) are handled
best-effort on the public issue tracker once acknowledged.

This is a solo-maintained project. Please be patient; a CVE assignment is
not guaranteed for every report.

## Threat model

This section is the authoritative source for "what BOB defends against and
what it does not". Read it before integrating BOB into a security pipeline.

### What BOB is

BOB is an **audit-only** tool. It inspects local Linux system state and
reports findings to the terminal, a log file, and optionally a JSON output
or an outbound webhook. It is invoked by a privileged user (`sudo bob`) on
a system the user already controls.

BOB is **not**:

  - a daemon that listens on a network port (no inbound network surface);
  - a remote agent (no remote command-and-control connection);
  - an active defense tool (BOB does not block traffic, kill processes,
    or modify firewall rules on its own — the `--fix` mode prompts the
    user for each command);
  - a forensics tool (no chain-of-custody, no immutable evidence storage).

### Adversary model

BOB makes three assumptions about its operating environment:

  1. **The invoking user is trusted.** `sudo bob` runs as root by design.
     A user with sudo access already has full system control; BOB is not
     a privilege firewall against them.
  2. **The local filesystem layout is sane.** BOB reads `/etc/`, `/proc/`,
     `/var/log/`, `~/.ssh/`, etc. If those paths have been tampered with
     by an attacker who already has root, BOB's findings may be misleading.
     BOB is part of the post-compromise audit toolchain, not pre-compromise
     detection.
  3. **The host package manager is intact.** Checks like `apt-cache policy`,
     `fwupdmgr get-updates`, `systemctl is-active` rely on legitimate system
     binaries. A compromised package manager that lies will mislead BOB.

### Trust boundaries

BOB crosses three trust boundaries during a run:

| Boundary                       | Inbound to BOB                       | BOB-side defense                                                 |
|--------------------------------|--------------------------------------|------------------------------------------------------------------|
| **User-controlled config**     | `~/.config/bob/config.conf`, `services.d/*.json`, `checks.d/*.py`, `profiles/*.conf` | Strict JSON Schema validation (`bob/data/schemas/`), ANSI sanitization (`bob.plugin_checks`), file size limits, Python identifier check on `config_key` |
| **System file content**        | `/etc/ssh/sshd_config`, `/var/log/auth.log`, cron files, sudoers… | Bounded reads (`errors='replace'`, size caps, max-line counts), regex never anchors on user content, `_C_LOCALE_ENV` for subprocess to avoid locale-dependent parsing |
| **Subprocess output**          | `ufw status`, `ss -tulnp`, `iptables -L`, `journalctl`, `openssl x509` … | All subprocess calls have `timeout=`, capture mode (no shell=True except in `--fix` where commands are explicitly user-approved), output never `eval`'d or interpolated into another command |

### Out of scope

  - **Pre-existing root compromise.** BOB cannot detect a rootkit that has
    replaced the binaries it relies on (`ss`, `iptables`, …). Use a separate
    integrity scanner (AIDE, Tripwire — BOB recommends installing them).
  - **Kernel-level attacks.** BOB reads `/proc/sys` and trusts it. A
    malicious kernel module can lie about every sysctl value.
  - **Application-level vulnerabilities.** BOB audits the OS hardening
    surface, not the security of arbitrary user applications.

### `--fix` mode

The `--fix` mode displays remediation commands and runs them only after the
user types `y`. BOB **never** writes to system files outside of `~/.config/bob/`
and the user-chosen log directory without explicit user confirmation. Even
in `--apply` mode (auto-fix), only the commands listed in BOB's own remediation
text are eligible — there is no eval of finding messages or shell expansion
of dynamic data.

### Plugin checks (`~/.config/bob/checks.d/*.py`)

Custom Python plugins are loaded with **size limits and ANSI sanitization**
on their output but they are **NOT sandboxed**: a plugin runs with the same
privileges as BOB itself (typically root). Trust your plugin sources as you
would any other code you `sudo`-execute.

A future major version may introduce a restricted-mode plugin runner (no
filesystem write, no subprocess), but it is out of scope for the 0.4.x line.

## Network surface

By default, BOB makes **two** outbound HTTPS calls:

  1. **Public IP lookup** at audit start (default providers: `api.ipify.org`,
     `icanhazip.com`, `ifconfig.me`). Used to classify the network context
     (local vs. public). Each provider has a 3-second timeout.
  2. **Webhook POST** if `--webhook=URL` is given. POST `application/json`
     payload to the user-supplied URL.

Both can be disabled with `--offline` (or `-o`). In `--offline` mode, BOB
makes **zero** outbound network connections. This is the recommended setting
for distro CI / build sandboxes / air-gapped environments.

No telemetry, no analytics, no automatic update check, no remote logging:
BOB never phones home.

## Data handling

  - **Reports**: Detailed `-d` reports are written to the user-configured
    log directory (default: `~/.local/share/bob/logs/`). File permissions
    are `0644` (readable by the owning user; root if invoked under sudo and
    no log dir is overridden).
  - **Config**: `~/.config/bob/config.conf` is `0600` (owner-only).
  - **Baseline**: `~/.config/bob/last_baseline.json` is `0600`. Contains
    only finding keys, scores, and port lists — no secrets, no file
    contents, no PII other than the hostname.
  - **History**: `~/.config/bob/history.jsonl` is `0600`. One line per
    audit: timestamp + score + level. Rotated at 1000 entries.

When BOB is invoked via `sudo`, files in `~/.config/bob/` are automatically
chowned back to `$SUDO_USER` (since v0.3.6) so they remain readable/editable
without sudo afterwards.

## Defense-in-depth recommendations (for packagers)

If BOB is packaged for a distro that supports MAC (AppArmor on Ubuntu/Debian,
SELinux on RHEL/Fedora):

  - Ship the optional AppArmor profile (`debian/apparmor.d/bob` once
    packaged) in `complain` mode by default; offer `enforce` as an opt-in
    so adventurous users help shake out false positives.
  - The profile MUST allow read on `/etc/`, `/proc/`, `/sys/`, `/var/log/`,
    `~/.config/bob/`, `~/.ssh/`, and exec on the system tools BOB invokes
    (~58 binaries spanning firewall, systemd/journal, audit framework, MAC
    policy, kernel hardening, antivirus, rootkit scanning, NTP, Secure Boot,
    package manager). The **canonical and exhaustive list** is the bundled
    `debian/apparmor.d/bob` profile — adapt paths for the distro layout.
    A representative sample: `ufw`, `ss`, `iptables`, `ip6tables`, `nft`,
    `systemctl`, `journalctl`, `openssl`, `smartctl`, `fwupdmgr`,
    `aa-status`, `sestatus`, `mokutil`, `bootctl`, `sysctl`, `ip`,
    `swapon`, `timedatectl`, `chronyc`, `rkhunter`, `chkrootkit`,
    `clamscan`, `freshclam`, `aide`, `auditctl`, `fail2ban-client`,
    `postconf`, `snap`, `dpkg`, `apt-cache`.
  - Network outbound (HTTPS) must be allowed for the public IP lookup
    and webhook delivery, unless deployments rely exclusively on
    `--offline` mode.
  - Recommend installing BOB with `pipx` (default upstream install path) so
    it lives in `~/.local/pipx/venvs/bodyguard-of-bits/` rather than a
    shared system Python environment.

## Disclosure policy

  - Coordinated disclosure preferred.
  - Embargo length: 30 days from acknowledgement to public fix, extensible
    by mutual agreement.
  - Credit: reporters are credited in the changelog unless they request
    anonymity.

## Acknowledgements

Cryptography or security researchers who have reported vulnerabilities to
BOB will be listed here.

*(none yet — be the first)*

---

© 2026 Cédric Clauzel
