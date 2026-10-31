# BOB — Security Policy

*[Lire en français](SECURITY_FR.md)*

## Release chain check: emSign CA incident

> [!NOTE]
> **Checked on 23 October 2026: no difference found between BOB's published
> packages and the source tagged in this repository.** All 105 releases on PyPI
> (wheels and sdists) and the 104 wheels piwheels built were compared file by
> file with their git tag. BOB is published without any stored PyPI token.
> Two steps of the 0.26.0 publication ran with tools that still trusted the
> affected certificate authorities; 0.26.1 closes that.

On 20 October 2026 a security incident affecting eMudhra / emSign certificate
authorities was publicly disclosed ([Python Discourse thread](https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576)):
their private keys were trivially weak, so a TLS client that still trusted them
could be served a forged certificate — for pypi.org among others. pip below
26.2.2, and `pypa/gh-action-pypi-publish` below v1.14.3
([GHSA-5xjx-3w67-w9x9](https://github.com/pypa/gh-action-pypi-publish/security/advisories/GHSA-5xjx-3w67-w9x9)),
still trusted them.

### What was checked

| Check | Result |
|---|---|
| **Content.** All 105 releases (0.1.0 to 0.26.0): wheel and sdist downloaded from PyPI, SHA-256 checked against PyPI's index, every file compared with `git archive <tag>` | No difference. Only the metadata generated at build time (`*.dist-info/`, `*.egg-info/`, `PKG-INFO`, `setup.cfg`) is not in git; in it, the command entry point is `bob = bob.__main__:main` in every wheel, and no wheel holds a `.pth` file or a compiled module |
| **piwheels.** The 104 wheels built for Raspberry Pi (0.1.0 to 0.25.1), compared the same way | No difference. 0.26.0 is still queued on piwheels' side |
| **Credentials.** How BOB is published | GitHub Actions, PyPI Trusted Publishing (OIDC), `.github/workflows/publish.yml`, environment `release`. No PyPI API token exists — none could leak, none to rotate. The build job's GitHub token is read-only |
| **Provenance.** PyPI attestations (PEP 740) | All 105 releases carry them, with `Masbateno/bodyguard-of-bits`, workflow `publish.yml`, as publisher and the file's digest as subject |

What each check establishes, and no more: the comparison shows the published
code is the tagged source; the attestations tie each file to this repository's
publish workflow — they say who published it, not that the workflow or its
tools were sound.

### What this does not cover

- **The 0.26.0 publication (20 October 2026, the day of the public disclosure).** Its
  build ran with pip 26.2.1 to fetch its build tools (`build`, `setuptools`),
  and its upload used `pypa/gh-action-pypi-publish` v1.14.2 — both still
  trusting the affected authorities; v1.14.3 came out the same day, a few hours later. The
  comparison found the published files identical to the tagged source; it does
  not by itself prove that the build environment was uncompromised, or that
  nothing else happened during the build or the upload.
- **The repository itself is the reference.** Commits and tags are pushed over
  SSH, which does not rely on certificate authorities.
- **Your own machine** is yours to check: upgrade pip to 26.2.2 or later (and
  uv, certifi) as the Python thread describes, and keep your system's
  `ca-certificates` up to date.

The whole chain — workflows, rights, pins, repository settings and what is
not covered — is described in [DOCUMENTS/CI.md](DOCUMENTS/CI.md).

### What changed in 0.28.2

The CI/CD was audited end to end (details and limits in
[DOCUMENTS/CI.md](DOCUMENTS/CI.md)):

- a publication waits for `Tests` and `Integration` to have passed on the
  tagged commit, pushed to `main` — "tag only a green commit" was a rule, it
  is now a lock;
- the container the PyPI upload action starts, which holds the OIDC token, was
  pulled by tag; it is now pulled by digest before the action runs, and
  checked again after it;
- the files attached to the GitHub Release are compared, by SHA-256, with the
  files PyPI lists for the version;
- `scripts/check_repo_settings.py` reads the 13 repository settings the chain
  relies on, which no file holds;
- the release is created by GitHub's own CLI instead of a third-party action
  that held `contents: write`;
- the test builds install pip 26.2.2 and setuptools by hash too, in every
  container and on arm64 — the 0.28.1 limit is closed;
- each workflow says its token is read-only; no checkout leaves the token in
  `.git/config`; every job has a timeout; no expression is expanded into a
  script; the QEMU image, run privileged, is pinned by digest and not cached;
- the repository requires actions pinned by commit, and secret scanning, push
  protection and Dependabot alerts are on;
- CI runs only supported releases — Ubuntu 25.04 and Fedora 41 replaced,
  Alpine 3.24 and openSUSE Leap 16 added — and a test fails when one reaches
  its end of support.

### What changed in 0.28.1

The build backend is pinned by hash. `python -m build` creates an isolated
environment and installs `setuptools` there from `pyproject.toml`'s `requires =
["setuptools>=77"]`; until 0.28.0 that was whichever release was current that
day (84.2.1 for 0.28.0, from its build log), with no hash. The publish workflow
now hands `requirements-build.txt` — `setuptools==84.2.1` and its two SHA-256 —
to that environment through `PIP_CONSTRAINT`. Measured with pip 26.2.2 and build
1.6.1: the pinned file builds, an altered hash fails the build, and the wheel
built this way holds the same 155 files, byte for byte, as the 0.28.0 wheel on
PyPI. What this pins is the backend: a setuptools file with another hash is
refused. It does not make the whole build environment reproducible — the
runner image, its Python and its system are GitHub's.

Not covered: the test jobs (`pip install -e .`, and `pip install .` in the
integration containers) still build BOB with an unpinned setuptools. They
publish nothing.

### What changed in 0.27.0

- every action the workflows use is pinned by commit, with its version beside
  it, and Dependabot proposes their updates;
- the test, lint and build tools — pytest, beautifulsoup4, ruff, build and
  what they pull in — are installed with `pip install --require-hashes` from
  `requirements-ci.txt`, which pins each by version and SHA-256: a file not
  listed fails the job instead of being installed;
- the build refuses any tag other than a bare `MAJOR.MINOR.PATCH` equal to the
  version in `pyproject.toml`;
- the `release` environment the PyPI upload runs in requires a reviewer's
  approval and admits only tags matching `[0-9]*.[0-9]*.[0-9]*` (a repository
  setting).

### What changed in 0.26.1

In the publish workflow, before any build dependency is installed:

- pip is installed from a wheel pinned by its SHA-256 (the method of the
  Python thread), not upgraded by the pip in place — which would fetch it over
  the very connection at risk;
- the job fails if pip is older than 26.2.2, and logs the versions it built
  with;
- the upload action is pinned by commit to `pypa/gh-action-pypi-publish`
  v1.14.3 (`7245906…`), no longer to a moving branch.

## Supported versions

Security patches are issued for the latest minor release line only. Older minors
are not backported.

| Version        | Supported          |
|----------------|--------------------|
| 0.29.x         | ✅ current          |
| 0.28.x         | ❌ end of life      |
| 0.27.x         | ❌ end of life      |
| 0.26.x         | ❌ end of life      |
| 0.25.x         | ❌ end of life      |
| 0.24.x         | ❌ end of life      |
| 0.23.x         | ❌ end of life      |
| 0.22.x         | ❌ end of life      |
| 0.21.x         | ❌ end of life      |
| 0.20.x         | ❌ end of life      |
| 0.19.x         | ❌ end of life      |
| 0.18.x         | ❌ end of life      |
| 0.17.x         | ❌ end of life      |
| 0.16.x         | ❌ end of life      |
| 0.15.x         | ❌ end of life      |
| 0.14.x         | ❌ end of life      |
| 0.13.x         | ❌ end of life      |
| 0.12.x         | ❌ end of life      |
| 0.8.x – 0.11.x | ❌ end of life      |
| 0.7.x          | ❌ end of life      |
| 0.6.x          | ❌ end of life      |
| ≤ 0.5.x        | ❌ end of life      |

Patches release as `0.29.x+1`. A breaking change bumps the minor (`0.30.0`).

**v0.28.x is end-of-life as of the day 0.29.0 ships**, per the "latest minor
line only" policy above. No security fixes will be backported. Users on v0.28.x
must `pipx upgrade bodyguard-of-bits` to v0.29.x.

The upgrade changes what the score *means* when BOB cannot read part of the
host. Until v0.16.0 the score was a sum over the checks that ran, and a check
that could not read its input contributed nothing — so masking
`/etc/ssh/sshd_config` moved the score from 7 to **8**, up, on a host BOB could
see less of. The number is now rendered as the ceiling it is (`≤ 8/10`), the
risk level derived from it reads as a best case, and a summary line names how
many sections could not be fully read.

**v0.16.2 adds a third state.** The ceiling holds while the blinded check's
domain is still scored; when blindness removes a *whole* domain from the score
average the denominator changes and the number can move either way, so it
renders as `~ 8/10` beside the span it is known to lie in (`between 6 and 8`).
A `--target` gate fails closed in both cases: it consults whether anything went
unread, not which direction the error points. `score` stays an integer in JSON;
`score_is_upper_bound`, `unverified`, `score_low`, `score_high` and
`unscored_domains` are additive. `--diff` no longer reports a finding as
resolved when its section was not re-evaluated, nor calls a score movement an
improvement or a degradation when the run read less than the one before it.

**v0.14.x is end-of-life as of 2026-08-31** (the day v0.15.0 ships, per the
"latest minor line only" policy above). No security fixes will be backported.
Users on v0.14.x must `pipx upgrade bodyguard-of-bits` to v0.15.x.

The upgrade carries **behavioural** changes, and one of them broke the usual
versioning discipline deliberately. v0.15.4 shipped scoring changes under a
patch number — a documented exception, taken to empty a backlog that had been
deferring them for several releases — so a host's score can move on that
upgrade without any change to the host:

* container isolation now costs points where it is an operator choice:
  `--privileged` (−3), a lone `CAP_SYS_ADMIN` (−2), seccomp switched off (−1).
  A container started with no flags still scores zero;
* the nftables path reached parity with iptables. This mostly *removes* a false
  deduction: a correctly hardened nftables host was losing a point for a
  loopback rule it had, because only the `iif` spelling was matched and not
  `iifname`;
* world-readable cloud-init user-data (−2) and an orphan socket unit bound to a
  non-loopback address (−1) were promoted from INFO.

v0.15.x also states more, and asserts less, where BOB cannot see: a check that
could not read its input now says so instead of substituting a default. That
direction only ever *removes* deductions.

**v0.13.x is end-of-life as of 2026-08-29** (the day v0.14.0 ships, per the
"latest minor line only" policy above). No security fixes will be backported.
Users on v0.13.x must `pipx upgrade bodyguard-of-bits` to v0.14.x. The upgrade
carries two **behavioural** changes: audits under the `desktop` / `workstation`
profiles report fewer warnings (their profile overrides were silently inert
before, so a host could never return exit 0), and output redirected to a file
or a pipe no longer contains ANSI colour codes — set `FORCE_COLOR=1` to restore
the previous behaviour.

**v0.12.x is end-of-life as of 2026-06-20** (the day v0.13.0 ships and the EOL
is formally declared, per the "latest minor line only" policy above). No
security fixes will be backported to v0.12.x. Users on v0.12.x must
`pipx upgrade bodyguard-of-bits` to v0.13.x to receive patches — the upgrade is
fully backwards-compatible (v0.13.0 only *adds* two INFO-only checks; no
existing output field or exit code changed). The v0.8.x – v0.11.x lines are
likewise end-of-life, each superseded by the next minor; v0.13.x is the only
supported line.

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
| **Subprocess output**          | `ufw status`, `ss -tulnp`, `iptables -L`, `journalctl`, `openssl x509` … | All subprocess calls have `timeout=`, capture mode, no `shell=True` anywhere — `--fix` runs each command as an argv list and refuses one that needs a shell — output never `eval`'d or interpolated into another command |

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

Since **v0.16.4** the eligible set is narrower still, and narrowed where the
commands are *classified* rather than where they are run. A command is
executed only if it is declared `cmd_type="fix"` — a diagnostic such as
`smartctl -a` is a finding's evidence, not its remediation, and was being
executed and reported as applied — and only if BOB can run it unattended: no
shell operators, no interactive editor. Everything else is displayed with its
command and never run, so the count shown above the confirmation prompt is a
promise BOB can keep. Paths interpolated into a command go through
`shlex.quote`, and execution is `shlex.split` without a shell.

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
  - **Loader hardening** (v0.14.1): a plugin must be a *regular file*, and
    the source is read through a bounded read. The 64 KB cap used to be
    enforced via `stat().st_size`, which is `0` for a character device — so
    `ln -s /dev/zero ~/.config/bob/checks.d/p.py` sailed through the cap and
    was read until the OOM killer intervened.
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
position since 2012 (PEP 416, rejected): a determined attacker can
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

**Real adversarial isolation requires an OS-level boundary.** The Debian
package ships an AppArmor profile (`debian/apparmor.d/bob`) that confines the
BOB process itself once enforced. It is in complain mode by default (it logs and
does not block), so the boundary against malicious plugins exists only after
`aa-enforce`. Distros that ship BOB inside a confined runtime (snap, flatpak,
container) inherit their runtime's isolation.

If you are running BOB unconfined under `sudo`, **you must code-review
your plugins before installing them**. The sandbox raises the bar
against accidents and naïve attacks; it does not replace trust.

~~`BOB_SANDBOX_LEGACY=1`~~ (retired in v0.9.0 TD-1) used to opt out of
the sandbox entirely and run the plugin in the parent process — surfaced
a CRITICAL log entry + flashy stderr WARNING on every run. The env var
is now ignored; plugins always execute in the spawn'd sandbox child.

## Rendering untrusted text

Finding messages interpolate values BOB reads from the system — file names,
unit names, process names, cron commands, package names, certificate subjects.
An attacker who can name a process or write a cron entry on the audited host can
therefore put arbitrary text into the report. Two separate defences apply, and
they are separate on purpose.

**Layer 1 — control characters, at construction.** Since **v0.14.1** every
finding's `message`, `detail` and `note` is stripped of ANSI escapes and control
characters in `Finding.__post_init__()`, the single point through which all
findings are built. That one guarantee reaches every output. (`cmd` keeps its
newlines — remediation blocks are legitimately multi-line — and loses everything
else.)

This is not cosmetic. A world-writable script in `/etc/cron.daily` whose
*filename* carried `\033]0;…\007` had the sequence rendered verbatim to the
operator's terminal: it rewrote the window title and corrupted the summary box.
With cursor-movement sequences the same vector can overwrite audit lines already
printed — that is, make the report lie about *other* findings, which matters
rather more in a security auditor than in most tools.

**Layer 2 — markup, at render time, per format.** Layer 1 removes control bytes;
it does not and cannot remove markup, because what counts as markup depends
entirely on where the text is going. Escaping at construction would corrupt the
terminal and the JSON, which need the characters as typed. Each writer therefore
escapes for its own format:

| Output | Treatment |
|---|---|
| Terminal, JSON | none needed beyond layer 1 — neither interprets markup |
| HTML | `html.escape(..., quote=True)` on every interpolated value |
| Markdown | `<` to an entity, `[` and `]` escaped so links and images do not render, `\|` so the table survives; `cmd` goes in a code span with a fence sized to its content |
| Slack | `&`, `<` and `>` escaped per Slack's own rules |
| CSV | a cell beginning with `=`, `+`, `-` or `@` is prefixed with a single quote, so content that merely passed *through* BOB cannot execute when the operator opens the export |
| HTML email report | `html.escape` plus `_safe_url`, which reduces `javascript:`, `data:` and `vbscript:` URLs to `#`. This is `bob/report_markdown.py`, reached by `--install-cron` when an address is given — the scheduled audit mails its report as HTML. **Not** the `-d` report, which this row named until v0.16.0: `-d` writes a plain-text `.log` and interprets no markup. |

**v0.15.0 found this layer missing in two writers.** The Markdown report escaped
only the table separator, so `<img src=x onerror=…>` executed in any renderer
that passes HTML through, `[click](javascript:…)` rendered as a live link, and
`![x](https://…)` made the auditor's own machine fetch a remote image on open.
The Slack payload was sent verbatim, where `<!channel>` notifies an entire
workspace and `<http://elsewhere|looks legitimate>` renders as a link whose
visible text is under the same control as its destination. Both are fixed; both
are pinned by tests. The lesson worth keeping is that layer 1's single choke
point was read, for a while, as covering more than it did.

## Environment variables

BOB reads the following environment variables. All are opt-in; none are
required for normal operation.

| Variable | Default | Effect |
|---|---|---|
| `BOB_SHARE` | unset | Override the auto-detected package data dir (`bob/data/`). Used by distro packagers when the data files ship outside the Python package tree. |
| `BOB_WEBHOOK_ALLOW_INSECURE=1` | unset | Allow `http://` webhook URLs (default rejects them). The audit payload leaks hostname + public IP + score + alerts in plaintext — only use on a trusted private network or for local lab testing. |
| ~~`BOB_SANDBOX_LEGACY=1`~~ | retired in v0.9.0 (TD-1) | Pre-v0.9.0, ran plugins in the parent process instead of the spawn'd sandbox child. Removed; the env var is now ignored. Plugins always execute in the spawn'd sandbox child. |
| `BOB_DEBUG=1` | unset | Diagnostics switch, two effects. (1) Prints the full Python traceback on `EXIT_ERROR=3` exits (since v0.6.1) — without it, errors print a one-line summary + the hint to set this variable. (2) Since **v0.13.3**, installs a real logging handler on the `bob` logger at DEBUG level, surfacing the internal `logger.debug` / `logger.warning` records that are otherwise swallowed (notably `_run()`'s per-subprocess failure trace). Useful for diagnosing crashes and checks that silently return nothing; never required in production. |
| `FORCE_COLOR=1` | unset | Force ANSI colour even when stdout is not a TTY. Added in v0.14.0, when colour became auto-detected (`--no-color` → `NO_COLOR` → `FORCE_COLOR` → `isatty()`) and redirected output stopped carrying escape codes. Documented in the v0.13.x end-of-life note above but missing from this table until v0.16.0. |
| `NO_COLOR` | unset | Disables all ANSI colour output, equivalent to `--no-color`. Follows the [no-color.org](https://no-color.org) convention: **any non-empty value** disables colour, an empty value is ignored. Honoured since **v0.13.3**. |

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
    are `0600` (owner-only; chowned back to `$SUDO_USER` when invoked under
    sudo, or `$DOAS_USER` under doas since 0.25.1). The report name is fully predictable (`bob_%Y%m%d_%H%M%S.log`)
    and the file is created as root under sudo, so since **v0.14.1** it is
    opened with `O_NOFOLLOW` and chowned through the descriptor already held
    (`os.fchown`) rather than by name: without that, anyone able to write in
    the target directory — reachable when an operator points `--output-dir`
    at a shared location — could pre-plant a symlink and have root truncate,
    then hand ownership of, an arbitrary file.
  - **Report writes are best-effort** (v0.14.1). The report is a side
    artifact and must never take the audit down with it: on the first I/O
    error the report disables itself, says so once on stderr, and the audit
    completes normally. Before v0.14.1 a full filesystem cost the entire
    run — exit 3 with no audit at all.
  - **Config**: `~/.config/bob/config.conf` is `0600` (owner-only).
  - **Baseline**: `~/.config/bob/last_baseline.json` is `0600`. Contains
    only finding keys, scores, and port lists — no secrets, no file
    contents, no PII other than the hostname.
  - **History**: `~/.config/bob/history.jsonl` is `0600`. One line per
    audit: timestamp + score + level. Rotated at 1000 entries.
  - **All state reads are bounded** (v0.14.1). Every state file, and the
    operator-supplied `--diff=PATH`, is read through
    `bob._atomic.read_text_capped()`, which refuses anything that is not a
    regular file and caps the read. Before that, a path resolving to a
    character device (`--diff=/dev/zero`, or `ignore.yml` symlinked to it)
    exhausted memory, and a FIFO blocked the process **forever** — a cron
    job that hangs instead of failing, on every subsequent run.

When BOB is invoked via `sudo` (or `doas`, since 0.25.1), files in `~/.config/bob/` are automatically
chowned back to `$SUDO_USER` (since v0.3.6) or `$DOAS_USER` so they remain readable/editable
without sudo afterwards. Since 0.26.1 nothing BOB writes there as root goes through a
symlink to somewhere outside the user's home — the history, baseline, recurrence
counters, configuration, ignore list, log directory and `-d` report alike. Every write
goes through a descriptor of its directory, checked first: a directory under the
user's home that resolved outside it (a symlinked `~/.config/bob`, `~/.config` or log
directory) is refused — nothing created, replaced, re-moded or handed over there — and
the refusal is said on stderr at the end of the audit; `--manage-logs` lists, deletes and
moves no report there. The file's own name is guarded as well: the history and the report
are opened with `O_NOFOLLOW`, the other state files renamed over their name. Every
hand-over goes through a descriptor opened with `O_NOFOLLOW`, checked the same way. A link that stays inside the
home is the user's own, and a run without `sudo` or `doas` is not judged. Before — every release
from 0.1.0 to 0.26.0, measured on ten of them — root followed such a link — writing to its target, re-moding it, creating it through a
dangling link and handing it to the invoking user, creating BOB's state files and report
in a linked directory and setting it to 0700 — so an account running as that user,
without root, could have had a file such as `/etc/shadow` or `/etc/ld.so.preload` handed
over by the next `sudo bob`, or `/etc` made unreadable to every other account.

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
