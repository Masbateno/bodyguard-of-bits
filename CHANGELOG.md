*[Lire en français](CHANGELOG_FR.md)* · *[Full changelog](DOCUMENTS/CHANGELOG_FULL.md)*

# BOB — Changelog

| Version | Date | Summary |
|---------|------|---------|
| [v0.2.1](#v021) | 2026-05-02 | Hotfix — defensive programming pass: crash fix in `--manage-logs` · 8 bare `except Exception` narrowed · 5 regex moved to module level · email regex deduplicated · `getattr` removed from domain scoring |
| [v0.2.0](#v020) | 2026-05-01 | Scoring refactoring (domain average · tool caps) · cron MTA detection · kernel `-unsigned` false positive fix · IoT log dominance WARN · orange banner · 4238/4238 tests |
| [v0.1.1](#v011) | 2026-04-29 | Hotfix — fwupd tree-format parser · `--install-completion` guidance · panorama column rename · 4206/4206 tests |
| [v0.1.0](#v010) | 2026-04-26 | Initial release — 46 checks · 9 domains · 32 services · CIS benchmark mapping · EN/FR · 4200/4200 tests |

---

## [v0.2.1] — 2026-05-02

Defensive programming hotfix — 17 targeted improvements found by dual-agent code audit. No new features, no behavior changes. 4238/4238 tests unchanged.

### Crash fix — `--manage-logs` plain-text mode (`bob/manage_logs.py`)

**Problem:** `.stat()` calls on log file paths were unguarded in the plain-text rendering loop. If a file disappeared between directory scan and display, `--manage-logs` crashed with `OSError`. The curses mode already had the correct `try/except OSError` guard; the plain-text mode did not.

**Fix:** both loops (`cur_logs` and `extra_sections`) now wrap `.stat()` in `try/except OSError` with fallback values `(size_kb=0, mtime="?")`, matching the curses implementation.

### Exception handling narrowed (8 locations)

All `except Exception` handlers replaced with the specific exceptions that can actually be raised:

| File | Function | Before | After |
|------|----------|--------|-------|
| `bob/cis_refs.py` | `_load()` | `Exception` | `(OSError, json.JSONDecodeError)` |
| `bob/manage_logs.py` | `_get_extra_dirs()` | `Exception` | `(json.JSONDecodeError, ValueError, TypeError)` |
| `bob/manage_logs.py` | curses fallback | `Exception` | `(curses.error, OSError)` |
| `bob/explain.py` | curses fallback | `Exception` | `(curses.error, OSError)` |
| `bob/cron.py` | `run_install_cron()` | `Exception` | `(_curses.error, OSError)` |
| `bob/cron.py` | `run_manage_cron()` | `Exception` | `(_curses.error, OSError)` |
| `bob/checks/ssh.py` | `_rsa_bits_from_blob()` | `Exception` | `(struct.error, ValueError)` |
| `bob/checks/ssh.py` | `_has_passphrase()` | `Exception` | `(binascii.Error, ValueError)` |

### Regex patterns moved to module level (3 files)

Patterns that were re-compiled on every function call are now module-level constants:

| File | Constants |
|------|-----------|
| `bob/checks/firewall.py` | `_OPEN_ANY_RE`, `_ALLOW_IN_RE`, `_PORT_PROTO_RE` |
| `bob/checks/cron_audit.py` | `_PATH_RE` |
| `bob/checks/firmware.py` | `_FLAT_SKIP_RE` |

### Code quality (3 fixes)

- **Email regex deduplicated** (`bob/cron.py`) — `_EMAIL_RE` was defined identically inside 3 local functions; now a single module-level constant.
- **`_resolve_path()` helper extracted** (`bob/manage_logs.py`) — `Path(raw).expanduser().resolve() if raw else default` was duplicated at two call sites.
- **Direct attribute access in `domain_scores.py`** — `getattr(engine, "findings", [])` / `getattr(deduction, "key", None)` etc. replaced with direct access. `ScoreEngine` always initializes these attributes.

### Observability (2 fixes)

- **`recurrence.py`** — `except … pass` replaced with `_log.debug()` so load failures are visible under `--debug`.
- **`__main__.py`** — webhook failures now emit `_log.warning()` in addition to the stderr print.

### Tests

4238/4238 (unchanged — no new tests; no behavior changes introduced)

---

## [v0.2.0] — 2026-05-01

Five improvements: scoring refactoring, cron MTA detection, kernel false positive fix, IoT log dominance fix, and orange ASCII banner.

### Scoring refactoring (`bob/scoring.py`, `bob/domain_scores.py`)

**Problem:** the global score was the raw sum of all deductions from 10. Eight minor hardening issues on an otherwise well-configured machine (SSH 10/10, firewall 10/10, updates 10/10) could produce 2/10 CRITICAL — a score that did not reflect the real security posture.

Two targeted fixes:

- **Tool caps** — `rootkit`, `clamav`, and `file_integrity` each contribute at most 1 deduction point to their domain, regardless of how many individual findings exist. Eliminates the double-penalty pattern "stale rkhunter database + no recorded scan = −2".
- **Global score = mean of active domain scores** — the global score is now the rounded average of all domain scores that have at least one finding (domains with no installed service excluded). A degraded Hardening domain no longer collapses the global score when SSH, firewall, and updates are all 10/10.

**Effect on the Debian 13 reference case:** 8 deductions → was 2/10 CRITICAL, now reflects the real range of 6–9/10 depending on active domains.

New API: `ScoreEngine.set_global_score()`, `compute_global_from_domains()`, `apply_domain_score_override()`.

### Cron MTA detection (`bob/cron.py`)

**Problem:** the cron setup wizard warned `'mail' not available — install mailutils` when `mail` was missing, but actual delivery uses `sendmail`, not `mail`. The advice was incorrect and incomplete.

New helper `_detect_mta()`:
- Checks for `sendmail` (the binary actually used for delivery)
- Identifies the provider: Postfix, Exim, msmtp, ssmtp
- Displays `✔ Mail transport: Postfix` when available
- Displays clear install instructions when absent: `sudo apt install postfix` (local MTA) or `sudo apt install msmtp-mta` (relay via Gmail/SMTP)

### Kernel `-unsigned` false positive fix (`bob/checks/kernel_modules.py`)

**Problem:** on Debian with Secure Boot enabled, `linux-image-X-amd64` (signed) and `linux-image-X-amd64-unsigned` are both installed. The system boots the signed kernel correctly, but BOB flagged `-unsigned` as "newer installed" and warned "reboot required".

New helper `_strip_unsigned()`: the `-unsigned` suffix is stripped before version comparison. Running the signed kernel while only the unsigned variant of the same version is also installed no longer triggers the warning.

### IoT log dominance: WARN −1 pt (`bob/checks/logs.py`)

**Problem:** when a single private IP accounted for ≥ 70 % of blocked UFW traffic (≥ 50 entries), BOB emitted an INFO finding with no score deduction. The feature was documented as WARN −1 pt but the implementation used `result.info()` without calling `add_deduction()`.

**Fix:** `result.info()` replaced by `result.warn()` + `result.add_deduction(points=1, key="logs.local_dominance")`. New locale key `deduction.local_dominance` added in `en.json` and `fr.json`. Three existing tests in `tests/test_logs.py` corrected to assert WARN level and a 1-point deduction (total unchanged).

### Orange ASCII banner (`bob/output.py`)

The `BOB` ASCII art in the terminal banner is now rendered in orange bold (`\033[1;38;5;208m`). Border characters remain blue.

### Tests

4238/4238 (3 tests corrected in `tests/test_logs.py` — IoT dominance: INFO→WARN + deduction assertion; total unchanged)

| File | New tests | Coverage |
|------|-----------|----------|
| `tests/test_kernel_modules.py` | +6 | `_strip_unsigned` helper · Debian signed/unsigned variants · genuine reboot still detected |
| `tests/test_cron.py` | +6 | `_detect_mta` — no sendmail, Postfix, Exim, msmtp, ssmtp, unknown |
| `tests/test_scoring.py` | +6 | `set_global_score` — override, clamp, level, raw score unchanged |
| `tests/test_domain_scores.py` | +14 | Tool caps (rootkit/clamav/file_integrity) · `compute_global_from_domains` · `apply_domain_score_override` · Debian 13 scenario |
| `tests/test_logs.py` | 0 (+3 corrected) | IoT dominance: WARN level · 1 pt deduction · below threshold unchanged |

---

## [v0.1.1] — 2026-04-29

Three targeted fixes found during first runs on Ubuntu 26.04 LTS and Debian 13.

### Fixes

- **fwupd tree-format parser** (`bob/checks/firmware.py`) — fwupd 1.9+ (Ubuntu 26.04+) changed its output format to a tree structure using `├─`, `└─`, `│` drawing characters. The previous parser captured these as device names, producing garbled output like `│, ├─UEFI CA: (+7)`. Device names are now correctly extracted from `├─`/`└─` lines only.
- **`--install-completion` error message** (`bob/__main__.py`) — users who ran `sudo bob --install-completion` saw `sudo: 'bob': command not found` because sudo uses a restricted PATH that excludes pipx binaries. The error message now explicitly warns that `sudo bob` will not work and instructs to copy-paste the exact full-path command shown.
- **Services panorama column header** (`bob/locales/en.json`, `bob/locales/fr.json`) — renamed `UFW` → `SCOPE` (EN) / `PORTÉE` (FR). The column reflects whether a service has internet exposure, not whether an active UFW rule exists — the previous label created a false impression.

### Tests

4206/4206 (+4 regression tests for fwupd tree-format parser in `tests/test_firmware.py`)

---

## [v0.1.0] — 2026-04-26

Initial release of **BOB — Bodyguard Of Bits**.

Linux hardening auditor with CIS benchmark mapping. Runs as root, requires no agent or daemon.

### Security checks

46 checks across 9 domains:

- **Firewall** — UFW rules audit, iptables/nftables audit (when UFW inactive), IPv6 consistency, firewall stack analysis, port exposure analysis
- **SSH** — 12+ configuration parameters (PermitRootLogin, PasswordAuthentication, key strength, etc.)
- **Kernel hardening** — 20+ sysctl parameters; kernel module audit; Secure Boot; firmware/microcode
- **Services** — 32 known services with risk classification; service state audit; Docker firewall bypass detection
- **File permissions** — SUID/SGID audit; sensitive files; sudoers
- **User accounts** — expired accounts; password policy; login.defs; PAM
- **System** — apt security updates; unattended-upgrades; UFW logging level; log rotation; auth.log analysis; NTP sync; Fail2ban; rootkit scan; auditd; file integrity (AIDE/Tripwire); ClamAV; AppArmor/SELinux; backup; disk health (SMART); memory/swap; TLS/SSL cert expiry; systemd timers; desktop apps; Samba; cron jobs; DDNS
- **Network** — public IP context; network type detection (server/LAN/VPN); GeoIP optional
- **Docker** — daemon configuration; privileged containers; host mounts

### CIS benchmark mapping

133 entries: 99 CIS Ubuntu 22.04 · 4 CIS Docker · 34 best-practice.
Each finding with a formal CIS code displays `[CIS:X.Y.Z]` inline. Full reference shown in `--verbose`.
`--explain KEY` shows WHY the finding matters, HOW to fix it, and its CIS reference.

### Output formats

Terminal (colored) · JSON · CSV · Markdown · HTML

### Audit profiles

`server` · `workstation` · `desktop` · `docker` — tune severity and skip irrelevant checks per environment.

### Automation

- **Cron** — `--install-cron` wizard; `--manage-cron` TUI; named jobs in `/etc/cron.d/bob-{name}`
- **Webhooks** — generic JSON + Slack (auto-detected by URL)
- **Score history** — sparkline trend across runs (`--history`)
- **Domain scores** — per-domain 0–10 scores (firewall · SSH · hardening · updates · file_perms)
- **Diff mode** — `--diff` shows only changes since last baseline
- **Watch mode** — `--watch[=N]` reruns every N seconds

### CLI highlights

```
sudo bob [OPTIONS]
bob --explain [KEY]   # no sudo required
```

Key options: `--verbose` · `-d` (French) · `--offline` · `--fix` · `--apply` · `--check=LIST` · `--skip=LIST`
`--output-dir` · `--format` · `--target N` · `--min-level LEVEL`

Bash completion: `sudo bob --install-completion`

### i18n

English and French (`--french` / `-d`).

### Install

```
pipx install bodyguard-of-bits
sudo bob
```
