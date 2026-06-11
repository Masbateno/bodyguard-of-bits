# BOB — Security Policy

*[Lire en français](SECURITY_FR.md)*

## Supported versions

Security patches are issued for the latest minor release line only. Older minors
are not backported.

| Version   | Supported          |
|-----------|--------------------|
| 0.8.x     | ✅ current          |
| 0.7.x     | ❌ end of life      |
| 0.6.x     | ❌ end of life      |
| 0.5.x     | ❌ end of life      |
| 0.4.x     | ❌ end of life      |
| < 0.4.0   | ❌ end of life      |

Patches release as `0.8.x+1`. A breaking change bumps the minor (`0.9.0`).

**v0.7.x is end-of-life as of 2026-06-05** (the day v0.8.1 ships and the EOL is
formally declared, mirroring the pattern that retired v0.6.x in v0.7.2). No
security fixes will be backported to v0.7.x. Users on v0.7.x must
`pipx upgrade bodyguard-of-bits` to v0.8.x to receive security patches. The
v0.8.x line is largely backwards-compatible with v0.7.x via `__init__.py`
re-exports (the `--json-v1` legacy JSON flag was later retired in v0.9.0), but **one
behavioural BREAKING change** lands in v0.8.1: the `workstation` audit profile
is no longer a silent alias for `desktop` — it's a first-class business-tier
profile that keeps `backup.no_backup` / `auditd.*` /
`mac_policy.apparmor_no_enforce` at WARN while relaxing the same SSH / clamav /
rootkit / file_integrity / log_rotation / secure_boot ergonomics as `desktop`.
Users on `bob -p workstation` who want the pre-v0.8.1 semantics can drop a copy
of `bob/data/profiles/desktop.conf` at
`~/.config/bob/profiles/workstation.conf`.

**v0.6.x is end-of-life as of 2026-06-01** (same day v0.7.0 shipped). No
security fixes will be backported to v0.6.x. Users on v0.6.x must
`pipx upgrade bodyguard-of-bits` to v0.8.x to receive security patches.
The v0.7.x → v0.8.x upgrade chain is backwards-compatible with the v0.6.x
public API via `__init__.py` re-exports (the `--json-v1` legacy JSON flag was
later retired in v0.9.0).

v0.5.x was declared EOL on the same day v0.6.0 shipped (2026-05-25). The
v0.6.0 release is backwards-compatible with the full v0.5.x public API via
`__init__.py` re-exports — upgrading is a `pipx upgrade bodyguard-of-bits`
with no source-code changes required on the user side.

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
  - a forensics tool (no chain-of-custody, no immutable evidence storage);
  - a vulnerability scanner (no CVE database probing, no exploit testing,
    no version-fingerprinting against known issues — use OpenVAS, Nessus,
    Wazuh, etc.);
  - a threat-modeling engine (no attacker-path enumeration, no active
    reachability probing from outside the host, no compromise-scenario
    simulation — use external scanners or red-team tooling);
  - an autonomous verdict system. BOB's score reflects **configuration
    hygiene under the active audit profile and detected network context**
    — not an absolute security verdict. A clean score means "hygienically
    configured for the chosen profile in the detected context", not
    "impossible to compromise". Human interpretation is required to
    translate the verdict into operational risk. See README.md
    "What BOB is — and is not" for the user-facing scope statement.

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

Since **v0.7.0**, plugins run in a **restricted in-process sandbox**:

  - Process isolation via `multiprocessing.get_context("spawn")` (separate
    Python interpreter, no shared memory with the audit).
  - 5-second wall-clock timeout + `RLIMIT_AS = 256 MiB` + `RLIMIT_CPU = 10 s`
    enforced in the worker.
  - Import allowlist (only `bob.scoring` and a curated stdlib subset —
    `json`, `re`, `pathlib`, `datetime`, …).
  - Restricted `__builtins__` (no `eval` / `exec` / `compile` / `__import__` /
    `input` / `breakpoint`) installed as an `_ImmutableBuiltins` dict
    subclass that overrides `__setitem__`/etc. to raise TypeError. This
    blocks the natural-Python mutation path `bins["eval"] = ...`. A
    determined attacker can still bypass via
    `dict.__setitem__(bins, "eval", ...)` (unbound base method); fully-
    immutable alternatives (`MappingProxyType`, `frozendict`) trigger
    `SystemError` from CPython's C-level dict fast paths that `exec()`
    requires, so the subclass approach is the best Python allows here.
  - `open()` wrapper that rejects write modes AND denies reads on a small
    list of well-known-secret paths (`/etc/shadow`, `~/.ssh/id_*`,
    `/dev/mem`, …).
  - `pathlib.Path` write methods monkey-patched to `PermissionError`.
  - Extensive strip of dangerous `os` module attributes
    (subprocess/spawn, raw fd I/O, FS writes, privilege changes,
    env mutations, …).
  - CheckResult shipped from worker to parent via a JSON-safe dict round-trip
    (not pickle of the plugin-controlled object) so a malicious `__reduce__`
    in `template_vars` cannot trigger code execution in the parent.
  - The parent never `exec`s plugin source — `_load_one` is AST-read-only
    (size + syntax + `run_check` presence + `CHECK_NAME` extraction).

#### Threat model — what the sandbox does and does NOT protect against

**In-process Python sandboxing is not a security boundary** — this is a
defence-in-depth layer. The Python community has converged on this
position since 2012 (PEP 416, retracted): a determined attacker can
always reach the unrestricted builtins via any allowlisted stdlib
module's `__globals__["__builtins__"]` chain, and no Python-level
mitigation can close that without breaking legitimate use of those
modules. RestrictedPython hardens bytecode-level attribute access but
does not catch the `__globals__` chain (public attribute lookups +
dict access only).

What the sandbox **does** stop:

  - **Accidents** — a buggy plugin calling `os.unlink`, looping forever,
    allocating 2 GiB, leaking handles.
  - **Naïve attacks** — `import subprocess; subprocess.run(...)` at module
    level, `open("/etc/passwd", "w")`, `eval(...)`.
  - **Confused-deputy reads** — accidental `open("/etc/shadow")` because
    the user forgot BOB runs as root.

What it does **NOT** stop:

  - A determined attacker who knows the Python escape playbook
    (`json.dumps.__globals__["__builtins__"]["__import__"]` is reachable
    by any plugin — this is *expected* and tested at
    `TestKnownInProcessLimitation::test_real_builtins_reachable_via_stdlib_globals`).
  - `dict.__setitem__(bins, "eval", real_eval)` unbound bypass of the
    restricted-builtins subclass — also pinned as known limitation in
    `TestKnownInProcessLimitation::test_i1_known_limitation_unbound_dict_setitem_bypass`.
  - Side-channel attacks via timing, scheduling, or shared resources.
  - Attacks that exploit BOB's own input-parsing surface (a malicious
    `sshd_config` BOB tries to audit).

**Real adversarial isolation requires an OS-level boundary.** BOB ships
an AppArmor profile (`packaging/apparmor/bob.profile`) that confines the
BOB process itself; this is the actual boundary against malicious
plugins. Distros that ship BOB inside a confined runtime (snap, flatpak,
container) inherit their runtime's isolation.

If you are running BOB unconfined under `sudo`, **you must code-review
your plugins before installing them**. The sandbox raises the bar
against accidents and naïve attacks; it does not replace trust.

~~`BOB_SANDBOX_LEGACY=1`~~ (retired in v0.9.0 TD-1) used to opt out of
the sandbox entirely and run the plugin in the parent process — surfaced
a CRITICAL log entry + flashy stderr WARNING on every run. The env var
is now ignored; plugins always execute in the spawn'd sandbox child.

## Environment variables

BOB reads the following environment variables. All are opt-in; none are
required for normal operation.

| Variable | Default | Effect |
|---|---|---|
| `BOB_SHARE` | unset | Override the auto-detected package data dir (`bob/data/`). Used by distro packagers when the data files ship outside the Python package tree. |
| `BOB_WEBHOOK_ALLOW_INSECURE=1` | unset | Allow `http://` webhook URLs (default rejects them). The audit payload leaks hostname + public IP + score + alerts in plaintext — only use on a trusted private network or for local lab testing. |
| ~~`BOB_SANDBOX_LEGACY=1`~~ | retired in v0.9.0 (TD-1) | Pre-v0.9.0, ran plugins in the parent process instead of the spawn'd sandbox child. Removed; the env var is now ignored. Plugins always execute in the spawn'd sandbox child. |
| `BOB_DEBUG=1` | unset | Print the full Python traceback on `EXIT_ERROR=3` exits. Without it, errors print a one-line summary + the hint to set this variable. Useful for diagnosing crashes; never required in production. |

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
