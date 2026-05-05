*[Lire en français](CHANGELOG_FR.md)* · *[Full changelog](DOCUMENTS/CHANGELOG_FULL.md)*

# BOB — Changelog

| Version | Date | Summary |
|---------|------|---------|
| [v0.2.4](#v024) | 2026-05-05 | Debian -unsigned kernel UX · deduction_total None sentinel · TranslationFunc alias (42 signatures) · _has_shell_ops() via shlex · profile fallback warning · 4274/4274 tests (+12) |
| [v0.2.3](#v023) | 2026-05-03 | Multi-VM audit fixes: NOT_LISTENING WARN→INFO · IoT deduction removed · heredoc display · completion symlink guard · Python 3.9 dropped · compare deduction delta · SSH exposure label split · active_disabled label · 4262/4262 tests (+1) |
| [v0.2.2](#v022) | 2026-05-02 | Scoring refinements: `ScoreCap.key` · INFO domains excluded · ClamAV 1pt · logging uniformity · contract documented · orphan-rule fix · domain cap fix (UFW inactive) · SSH detail locale fix · scoring invariant tests · 4261/4261 tests (+23) |
| [v0.2.1](#v021) | 2026-05-02 | Hotfix — defensive programming pass: crash fix in `--manage-logs` · 8 bare `except Exception` narrowed · 5 regex moved to module level · email regex deduplicated · `getattr` removed from domain scoring |
| [v0.2.0](#v020) | 2026-05-01 | Scoring refactoring (domain average · tool caps) · cron MTA detection · kernel `-unsigned` false positive fix · IoT log dominance WARN · orange banner · 4238/4238 tests |
| [v0.1.1](#v011) | 2026-04-29 | Hotfix — fwupd tree-format parser · `--install-completion` guidance · panorama column rename · 4206/4206 tests |
| [v0.1.0](#v010) | 2026-04-26 | Initial release — 46 checks · 9 domains · 32 services · CIS benchmark mapping · EN/FR · 4200/4200 tests |

---

## [v0.2.4] — 2026-05-05

Post-audit codebase hardening pass: two Debian `-unsigned` kernel UX bugs, `deduction_total` None sentinel, `TranslationFunc` type alias across all check signatures, shlex-based shell operator detection, and profile fallback visibility. No new features. 4274/4274 tests (+12).

### Bug fixes — Debian kernel UX (`bob/checks/kernel_modules.py`)

**Fix 1 — `kernels_up_to_date` names running kernel, not -unsigned sibling** — When running `6.12.74+deb13+1-amd64` with its `-unsigned` sibling also installed as the most recently sorted kernel, the "kernel up to date" message displayed the `-unsigned` variant's name instead of the running kernel's name. Root cause: `version=most_recent` was passed to the i18n key instead of `version=running`. Fixed: `version=running`. New test: `test_up_to_date_names_running_kernel_not_unsigned_sibling`.

**Fix 2 — Correct message template for unsigned pair** — When the running kernel and the most recently sorted kernel form a signed/unsigned pair, the cleanup message should use `kernels_obsolete_same` (no "running / latest" pair in text) rather than `kernels_obsolete`. The comparison `running == most_recent` was literal, returning `False` for the pair. Fixed: `_strip_unsigned(running) == _strip_unsigned(most_recent)`. New test: `test_debian_signed_unsigned_pair_uses_obsolete_same_message`.

### Regression fix — `deduction_total` sentinel (`bob/compare.py`)

**Fix 3 — False "+N pt(s)" on first run after upgrade** — v0.2.3 added `deduction_total: int = 0` to `AuditBaseline`. Pre-v0.2.3 baselines lack the field; `raw.get("deduction_total", 0)` returned `0`, then `deduction_delta = curr − 0` displayed "Déductions variables +N pt(s)" on the very next audit even though nothing had changed. Fixed: `int | None = None` (mirrors the existing `finding_keys` sentinel). `load_baseline()` returns `None` when the field is absent; `compute_delta()` skips delta computation when either side is `None`. +10 new tests in `TestDisplayDelta` and `TestDeductionTracking`.

### Code quality — codebase audit pass

**Type hygiene — `TranslationFunc` alias** (`bob/checks/_run.py`, 40 check files, `bob/history.py`, `bob/plugin_checks.py`) — `TranslationFunc = Callable[..., str]` defined in `_run.py` (already imported by all checks). All 42 `check_*` function signatures updated: `t=None` → `t: TranslationFunc | None = None`.

**Shell safety — `_has_shell_ops()` via `shlex`** (`bob/fixes.py`) — Shell operator detection replaced naive substring matching (`any(op in cmd for op in _SHELL_OPS)`) with tokenization via `shlex.split()`. The old method would falsely match `>` inside argument values or file paths. `_has_shell_ops()` checks tokens against a frozenset, treating only standalone tokens as operators. Malformed quoting safely returns `True` (treat as shell).

**UX — profile fallback now visible** (`bob/__main__.py`, locales) — When `--profile=X` was given but profile X did not exist, `load_profile()` silently fell back to `server`. Users had no indication the requested profile was not found. Fixed: `output.print_warn(t("audit.profile_not_found", …))` added when the loaded profile name differs from the requested one. New i18n keys `audit.profile_not_found` in EN and FR.

### Tests

4274/4274 (+12 new):

| File | Change |
|------|--------|
| `tests/test_kernel_modules.py` | +2: `test_up_to_date_names_running_kernel_not_unsigned_sibling` · `test_debian_signed_unsigned_pair_uses_obsolete_same_message` |
| `tests/test_compare.py` | +10: 4 in `TestDisplayDelta` (variable deduction show/suppress cases) · 6 in new `TestDeductionTracking` (None sentinel, load/save, delta computation) |

---

## [v0.2.3] — 2026-05-03

Eight fixes identified during a multi-VM audit round (Linux Mint, Debian 13, Kali, Ubuntu 26.04). Three behavioural bug fixes, two infrastructure fixes, three UX precision fixes. 4262/4262 tests (+1).

### Bug fixes — multi-VM audit (`bob/checks/services.py`, `bob/checks/logs.py`, `bob/display.py`)

**Fix 1 — NOT_LISTENING always INFO** — Ports in the service registry but not actively listening (e.g. Mosquitto 8883 when only 1883 is bound) were shown as `⚠ [ATTENTION]` for HIGH/CRITICAL services, appearing in the summary box. Fixed: `NOT_LISTENING` now always emits `result.info()` regardless of service severity. Tests renamed: `test_not_listening_critical_adds_info`, `test_not_listening_high_adds_info`.

**Fix 2 — IoT local dominance: deduction removed** — When a single private IP dominated UFW block logs (typical of IoT devices), the tool emitted `result.warn(nature="improvement")` and deducted 1 point. Benign traffic from a known private source should not reduce the security score. Fixed: demoted to `result.info()` with no deduction. Tests: `test_finding_is_info_level`, `test_no_score_deduction`.

**Fix 3 — Heredoc commands no longer mangled** — Multi-line commands (heredoc blocks in `auditd` remediation steps) were passed to `_wrap_for_box()` via `text.split()`, which stripped all newlines. Fixed: `_add_finding_lines()` now iterates `item.cmd.splitlines()` and calls `_wrap_for_box()` per line, preserving the heredoc structure visually.

### Infrastructure

**`bob/completion.py` — circular symlink guard** — `--install-completion` created a circular symlink (`~/.local/bin/bob → itself`) when pipx was installed system-wide and the user path was already a link into the system path. Fixed: `candidate.resolve() != dst_bin.resolve()` guard added. `exists()` already returns `False` for broken symlinks; the resolve check prevents the circular case.

**Python 3.9 dropped** (`pyproject.toml`, `.github/workflows/tests.yml`, `.github/workflows/publish.yml`) — Python 3.9 reached EOL in October 2025. `requires-python` bumped to `">=3.10"`. Classifier and CI matrix entries removed.

### UX precision fixes — cross-distro testing

**Compare: variable deduction delta** (`bob/compare.py`) — When a score changed between audits without new/resolved finding keys (e.g. log activity varying between runs), the CHANGEMENTS section showed only "Score dégradé de N point(s)" with no further context. Added `deduction_total: int` to `AuditBaseline` and `deduction_delta: int` to `AuditDelta`. When `deduction_delta != 0` and no structural changes (alert/warn count, finding keys) explain the score move, displays "Déductions variables ±N pt(s) (logs, trafic réseau)". Old baselines (field absent) default to `deduction_total=0` and produce no false delta. Found on: Debian 13 VM, Kali VM.

**Exposure: SSH state label split** (`bob/exposure.py`) — The attack-surface table used a single i18n key (`ssh_not_running` = "non installé / non démarré") for both "SSH not installed" and "SSH installed but stopped". When SSH was installed but inactive (e.g. Kali), the label was factually incorrect. Split into `ssh_not_installed` ("non installé") and `ssh_stopped` ("installé — non démarré"), used by the respective code branches. New test: `test_not_active_shows_stopped_text`. Found on: Kali VM.

**Services: `active_disabled` message now includes service label** (`bob/checks/services.py`) — "Le service est actif en ce moment, mais ne redémarrera pas automatiquement." appeared in the summary box without identifying which service. The service name is clear in the full audit under the `▶ Service` section header, but is lost when the finding is promoted to the summary. Fixed: `{label}` added to the i18n string; `label=snap.label` passed at the call site. Found on: Linux Mint test VM (Redis).

### Tests

4262/4262 (+1 new, 4 renamed/updated):

| File | Change |
|------|--------|
| `tests/test_services.py` | Renamed: `test_not_listening_critical_adds_warn` → `_adds_info` · `test_not_listening_high_adds_warn` → `_adds_info` · assertions updated to `info` level |
| `tests/test_logs.py` | Renamed: `test_finding_is_warn_level` → `_info_level` · `test_score_deduction_one_point` → `test_no_score_deduction` · assertions updated |
| `tests/test_exposure.py` | Updated `test_not_installed_info_is_ok` and `test_not_installed_overrides_password_auth` to assert `ssh_not_installed` key · +1 new `test_not_active_shows_stopped_text` |

---

## [v0.2.2] — 2026-05-03

Five targeted scoring fixes, a locale fix, logging uniformity pass, test coverage for the v0.2.1 race condition fix, scoring invariant tests, equal-weight domain documentation, and a firewall orphan-rule fix. 4261/4261 tests (+23).

### Scoring fixes (`bob/scoring.py`, `bob/domain_scores.py`, `bob/checks/clamav.py`)

**Fix 1 — `ScoreCap.key` propagation** — `ScoreCap` gains `key: str = ""`. The `set_cap()`, `cap()`, `apply()`, and `finalize()` methods all propagate it. The synthetic `Deduction` emitted when a cap fires now carries `key=self._cap.key` instead of `key=""`, enabling correct domain attribution for cap-triggered deductions. Updated: `bob/checks/firewall.py` passes `key="firewall.inactive"` to `result.set_cap()`.

**Fix 2 — INFO findings no longer inflate active domain set** — `active_domains_from_engine()` now counts only WARN and ALERT findings when determining which domains are "active" for the global average. An INFO-only domain (service installed, nothing actionable) is no longer pulled into the average. `FindingLevel` imported directly from `bob.scoring`.

**Fix 3 — `clamav.db_very_outdated` 2pt → 1pt** — Deduction was 2 pts but the `clamav` tool cap is 1 pt. The excess point only affected `engine._raw_score`, creating a silent asymmetry between raw and domain scores. Lowered to 1 pt to eliminate the ghost point.

### Observability — logging uniformity (`bob/history.py`, `bob/ignore.py`, `bob/sysinfo.py`)

Bare `except … pass` replaced with `_log.debug()` in 6 locations across 3 modules. `import logging` + `_log = logging.getLogger(__name__)` added to each. Failures remain non-fatal; visible under `--debug`.

| Module | Function | Exception | Message |
|--------|----------|-----------|---------|
| `bob/history.py` | `save_score()` | `OSError` | `"Failed to save score to history: …"` |
| `bob/history.py` | `_rotate_if_needed()` | `OSError` | `"Failed to rotate history file: …"` |
| `bob/ignore.py` | `load_ignore_keys()` | `OSError` | `"Cannot read ignore file …: …"` |
| `bob/sysinfo.py` | `get_user_home()` | `KeyError` | `"SUDO_USER … not found in password database, falling back to Path.home()"` |
| `bob/sysinfo.py` | `collect_system_info()` | `OSError` | `"Cannot read /etc/os-release: …"` |
| `bob/sysinfo.py` | `detect_network_type()` ×2 | `subprocess.TimeoutExpired / FileNotFoundError / OSError` | `"ip route failed …"` / `"ip addr failed …"` |

### Scoring contract documented (`bob/scoring.py`)

`finalize()` docstring documents the required orchestrator sequence: `engine.finalize()` → `apply_domain_score_override(engine)`. `set_global_score()` marked "do not call directly". Clarifies that `engine._raw_score` is accessible for debugging.

### Fix 4 — Domain score cap not applied when global raw score is already below threshold (`bob/domain_scores.py`)

`compute_domain_scores()` computes each domain's score from the list of deductions in `engine.breakdown`. When a cap fires (e.g. `firewall.inactive` → max 3/10), `finalize()` appends a delta deduction to `breakdown` **only if** `raw_global_score > cap.maximum`. On systems with many deductions across domains, the global raw score can already be below the cap threshold — the delta is never appended, so the target domain score is not capped and the score bar shows the pre-cap value (e.g. 6/10 instead of 3/10 for firewall when UFW is inactive).

Fix: after accumulating domain deductions from the breakdown, `compute_domain_scores()` now explicitly reads `engine.cap_info` and, if its key maps to a domain, enforces the cap directly on that domain's deduction total. The fix is idempotent (if the delta was already in the breakdown, the domain score already equals the cap and the guard condition `raw_domain > cap.maximum` is false).

Found by running the tool on an Ubuntu 26.04 VM with UFW inactive and several hardening issues: the score detail showed "Score plafonné à 3 (pare-feu inactif)" but the domain bar still displayed 6/10.

### Fix 5 — Orphan-rule check misses protocol-unspecified UFW rules (`bob/checks/firewall.py`)

`_check_orphan_rules()` used `_PORT_PROTO_RE` (`\d{1,5}/(?:tcp|udp)`) to parse the "To" field of UFW rules. A rule written without explicit protocol (e.g. `57621 ALLOW IN 192.168.1.0/24`) didn't match and was silently skipped with the incorrect comment "open-any rules". UFW applies protocol-unspecified port rules to both TCP and UDP.

New constant `_PORT_BARE_RE` (`^\[\s*\d+\]\s+(\d{1,5})\s`) handles the fallback case: if neither `port/tcp` nor `port/udp` is in the listening set, the rule is flagged as an orphan. Found by running the tool on a real machine where `57621` (Spotify Connect) was flagged for `41681/tcp` but not for its sibling rule `57621`.

### Fix 6 — SSH "not running" detail duplicated the remediation command (`bob/locales/fr.json`, `bob/locales/en.json`)

`ssh.not_active_detail` was `"Activer avec : sudo systemctl enable --now ssh"` (FR) / `"Enable with: sudo systemctl enable --now ssh"` (EN). Since the `cmd` field separately displays the same command as a `→` line, the "Que faire?" block showed the command twice. Fixed: the detail now provides context (`"Le service est désactivé — activez-le si l'accès SSH est nécessaire."`) and the `cmd` line displays the command alone. Found by running the tool on Kali Linux where SSH is installed but intentionally stopped.

### Scoring invariants — new test classes (`tests/test_scoring.py`, `tests/test_domain_scores.py`)

`TestScoringInvariants` added to both files — 12 new tests covering properties that must hold regardless of input:

| Class | File | Invariants |
|-------|------|------------|
| `TestScoringInvariants` | `test_scoring.py` | Score floor = 0 · Score ceiling = MAX · Deductions monotone · Cap above score is no-op · Domain override in range |
| `TestScoringInvariants` | `test_domain_scores.py` | INFO findings don't activate domain · WARN/ALERT do · Deduction alone activates · Global avg ∈ [min, max] of active · All domain scores in [0, 10] · Global avg always in [0, 10] |

### Tests

4261/4261 (+23 new, 2 updated):

| File | Change | Coverage |
|------|--------|----------|
| `tests/test_domain_scores.py` | +6 `TestEngineLevelDomainCap` | Cap applied when few deductions · cap applied when many global deductions (delta not in breakdown) · no over-cap when already at cap · score never exceeds cap · cap doesn't bleed to other domains · all scores in range |
| `tests/test_firewall.py` | +3 `TestOrphanRules` | Bare-port rule flagged when nothing listening · not flagged when TCP listening · not flagged when UDP listening |
| `tests/test_scoring.py` | +5 `TestScoringInvariants` | Score floor/ceiling · monotone deductions · cap no-op · domain override in range |
| `tests/test_domain_scores.py` | +7 `TestScoringInvariants` | INFO/WARN/ALERT activation · deduction path · global avg bounds · domain scores in range |
| `tests/test_manage_logs.py` | +2 `TestStatFallback` | `.stat()` `OSError` in `cur_logs` loop → `(0, "?")` fallback · `.stat()` `OSError` in `extra_sections` loop → `(0, "?")` fallback |
| `tests/test_clamav.py` | renamed + updated | `test_db_very_outdated_deducts_1` (was `_deducts_2`) · `test_worst_case`: 3 pts total (was 4) |

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
