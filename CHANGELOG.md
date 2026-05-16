*[Lire en français](CHANGELOG_FR.md)* · *[Full changelog](DOCUMENTS/CHANGELOG_FULL.md)*

# BOB — Changelog

| Version | Date | Summary |
|---------|------|---------|
| [v0.4.4](#v044) | 2026-05-15 | Cross-distro terrain hardening — **critical `updates.py` bug** (4/4 Debian-family VMs: 21 Ubuntu LTS security updates undetected): `apt-get -s upgrade` → `dist-upgrade` · stale APT cache detection · cross-check vs `apt list --upgradable` · "Surface d'attaque" propagates `updates_unknown` instead of false "à jour" · AppArmor "0 profil chargé" dedicated key · SMART skip on all-virtual disks · DDNS ports inline in WARN · S4 redesign `_is_safe_user_path` home-bounded · M4 refactor `_parse_ufw_covered_ports` (1 parse + O(1) lookup) · I2 wave-2 `key=` on services/virtualization · new locale-coverage test (catches `[xxx.yyy]` sentinel regressions) · 4489/4489 tests (+21) |
| [v0.4.3](#v043) | 2026-05-15 | Doc catch-up + post-audit hardening pass — 4 firewall keys promoted to `EXPLAIN_KEYS` · `--json --json-full` crash fix (5 dead HardeningSnapshot attrs) · `strptime("%b…")` made locale-independent (ssl_certs + logs) · `_is_covered_by_ufw` false-positive killed · email markdown links no longer escaped · cron range validator now rejects out-of-bounds · `key=` on ~30 findings (docker, firewall_stack, network_context, ports) · 7 dead locale keys removed · i18n concat anti-pattern resolved (ddns, logs) · CIS refs added · CHANGELOG short corrected for v0.4.2 · 4468/4468 tests (+4 regression) |
| [v0.4.1](#v041) | 2026-05-14 | Phase 2 distro-ready (architectural decoupling) — `bob/tui/` extracted (curses optional) · `Finding.template_vars` / `Deduction.template_vars` additive fields for locale-independent reconstruction · new `bob.formatter` module + post-review hardening pass (`lang=` removed, `i18n.try_t()`, narrowed `except KeyError`) · 3 pilot checks migrated (ssh, hardening, firewall) · template_vars exposed in JSON output · `--offline` mode verified + integration tests · 4449/4449 tests (+19) |
| [v0.4.0](#v040) | 2026-05-14 | Phase 1 distro-ready — exit codes / locale auto-detect (POSIX `$LANG`) / JSON output contract (`schema_version`, `key` fields) / `--explain` alias map / `services.json` formal JSON Schema (with post-review hardening pass #1: strict 1–65535 port regex · `$defs` factorization · `if/then` business constraints · plugin-file `schema_version` wrapper) · pass #2: schema descriptions, `services-list.minItems`, real-class fixtures replacing MagicMock, RefResolver→referencing compat shim · `= N` redundant suffix on stable score removed · 4430/4430 tests (+82) |
| [v0.3.6](#v036) | 2026-05-09 | Code-review pass — `Path.home()` → `get_user_home()` (sudo-aware) in 7 modules · IPv6 ULA/link-local in `_is_private_or_loopback` · SSH `AllowTcpForwarding local` accepted · UFW logging header skipped when UFW inactive · `NOTIFY_EMAIL` legacy regex · 22 unused imports cleaned · 47 dead locale keys removed · 4348/4348 tests |
| [v0.3.5](#v035) | 2026-05-08 | Refactoring — `runner.py` `_sec` closure (−295L) · `ssh.py` `_check_weak_algo` helper · locale fix 4× `UFW-AUDIT` → `BOB` · 4348/4348 tests |
| [v0.3.4](#v034) | 2026-05-08 | Hotfix — `user_config` not passed to `run_checks()` → `NameError` at end of every audit (v0.3.2 regression) · 4348/4348 tests |
| [v0.3.3](#v033) | 2026-05-07 | Architectural refactoring — `cron.py` split · `compute_domain_scores()` pure tuple return · `domain_scores` public API · `_draw`/`_read_key` curses helpers · 4348/4348 tests (+1) |
| [v0.3.2](#v032) | 2026-05-06 | User-configurable SUID whitelist in `config.conf` · 14 code-review fixes (i18n, quiet mode, engine idempotency, dead code) · 4347/4347 tests (+19) |
| [v0.3.1](#v031) | 2026-05-06 | Banner version fix · DDNS context propagation · `was_capped` on Deduction · engine cached properties · 4328/4328 tests (+6) |
| [v0.3.0](#v030) | 2026-05-06 | `--breakdown` score transparency · score-aware `--explain` · kernel -unsigned retention fix · report header relics removed · score delta display · 4322/4322 tests (+48) |
| [v0.2.4](#v024) | 2026-05-05 | Debian -unsigned kernel UX · deduction_total None sentinel · TranslationFunc alias (42 signatures) · _has_shell_ops() via shlex · profile fallback warning · 4274/4274 tests (+12) |
| [v0.2.3](#v023) | 2026-05-03 | Multi-VM audit fixes: NOT_LISTENING WARN→INFO · IoT deduction removed · heredoc display · completion symlink guard · Python 3.9 dropped · compare deduction delta · SSH exposure label split · active_disabled label · 4262/4262 tests (+1) |
| [v0.2.2](#v022) | 2026-05-02 | Scoring refinements: `ScoreCap.key` · INFO domains excluded · ClamAV 1pt · logging uniformity · contract documented · orphan-rule fix · domain cap fix (UFW inactive) · SSH detail locale fix · scoring invariant tests · 4261/4261 tests (+23) |
| [v0.2.1](#v021) | 2026-05-02 | Hotfix — defensive programming pass: crash fix in `--manage-logs` · 8 bare `except Exception` narrowed · 5 regex moved to module level · email regex deduplicated · `getattr` removed from domain scoring |
| [v0.2.0](#v020) | 2026-05-01 | Scoring refactoring (domain average · tool caps) · cron MTA detection · kernel `-unsigned` false positive fix · IoT log dominance WARN · orange banner · 4238/4238 tests |
| [v0.1.1](#v011) | 2026-04-29 | Hotfix — fwupd tree-format parser · `--install-completion` guidance · panorama column rename · 4206/4206 tests |
| [v0.1.0](#v010) | 2026-04-26 | Initial release — 46 checks · 9 domains · 32 services · CIS benchmark mapping · EN/FR · 4200/4200 tests |

---

## [v0.4.4] — 2026-05-15

Cross-distro terrain hardening release. Four fresh VM tests (Debian 13, Kali Rolling, Linux Mint 22.3, Ubuntu 26.04 LTS — all installed from PyPI via `pipx upgrade`) surfaced **one critical bug, three minor bugs, and confirmed the v0.4.3 fixes work in the wild**. All fixes plus the audit-deferred items from v0.4.3 are bundled here.

### 🔴 Critical — `updates.py` reports "0 pending" on every fresh Debian-family install

Reproduced on **4/4** vanilla VMs:

| Distro | apt-reported pending | of which security | BOB v0.4.3 |
|---|---|---|---|
| Debian 13 | 59 | unknown | 0 |
| Kali Rolling | 868 | unknown | 0 |
| Mint 22.3 (test VM) | 33 | unknown | 0 |
| **Ubuntu 26.04 LTS** | **23** | **21 LTS security** | **0** |

Two compounding causes:

1. **Conservative `apt-get -s upgrade`.** `upgrade` (not `dist-upgrade`) refuses any pending package that would require installing a new one or removing another. On Debian/Ubuntu this hides every security update bundled with a kernel transition or a new soname.
2. **Stale APT cache.** BOB reads `/var/cache/apt/pkgcache.bin`; if `apt update` hasn't run recently the cache reports an outdated state.

Three layered fixes:

- Switched `apt-get -s upgrade` → `apt-get -s dist-upgrade` in [`bob/checks/updates.py:_collect_pending_updates`](bob/checks/updates.py).
- Added `apt_cache_age_days` to `UpdatesSnapshot`. When > 7 days old → new WARN `updates.apt_cache_stale` with `cmd="sudo apt update"`.
- Added `upgradable_count` (from `apt list --upgradable`) cross-check. When `dist-upgrade` returns 0 but `apt list` returns N > 0 → new WARN `updates.dist_upgrade_inconsistent`.

**Cascade** to [`bob/exposure.py`](bob/exposure.py) — the "Surface d'attaque" summary previously displayed `✔ Mises à jour sécurité à jour` even when the snapshot was unreliable. Now displays `⚠ état inconnu — cache APT obsolète ou incohérent` when either of the two new WARNs is present. False reassurance on a security check is worse than admitting we don't know.

### 🟡 Minor — three cosmetic regressions from cross-distro VMs

- **AppArmor "0 profile loaded" case** (Kali). v0.4.3 emitted `AppArmor active but no profiles in enforce mode (0 in complain)` — the parenthetical contradicted itself when Kali had literally 0 profiles total. New dedicated path in [`bob/checks/mac_policy.py`](bob/checks/mac_policy.py): when enforce == 0 AND complain == 0 → new key `mac_policy.apparmor_no_profiles` with message "AppArmor active but no profiles loaded — the framework is running with nothing to enforce" and recommendation to install `apparmor-profiles` / `apparmor-profiles-extra`.
- **SMART "all passed" on VM-only systems** (Kali). On a VM with `/dev/vda`, BOB displayed `ℹ /dev/vda — SMART not applicable` immediately followed by `✔ All disks passed SMART`. Misleading — no real SMART read had been performed. [`bob/checks/disk.py`](bob/checks/disk.py) now only emits `disk.ok` when at least one **real** (non-virtual) SMART check actually ran.
- **DDNS open-ports list rendered as orphan sub-items** (Mint test VM). The `→ 22/tcp` / `→ 80/tcp` lines appeared visually as actions of the INFO advice, but they were the list of ports targeted by the WARN. Now interpolated inline in the WARN message: `DDNS actif avec port(s) ouverts sans restriction (22/tcp, 80/tcp) — ...`. The display-side print loop in [`bob/runner.py`](bob/runner.py) is gone.

### Items deferred from the v0.4.3 audit pass

These were flagged by the agent audit on v0.4.2 and explicitly deferred. All applied here:

- **S4 redesign — symlink-safe ssh reads.** v0.4.3 deliberately did NOT apply `_is_safe_config_path()` to `~/.ssh/authorized_keys` or `~/.ssh/config` because that would break legitimate dotfile setups (configs symlinked from a git repo). New helper [`_is_safe_user_path(path, owner_home)`](bob/checks/_run.py) accepts symlinks that resolve **inside** the owner's home, rejects those pointing outside. Applied in [`bob/checks/ssh.py`](bob/checks/ssh.py) to `authorized_keys`, `~/.ssh/config`, and `known_hosts`. Closes the SECURITY.md trust-boundary gap on user-controlled config files.
- **M4 refactor — `_parse_ufw_covered_ports`.** Previously `_is_covered_by_ufw` recompiled a regex for every port checked against the same UFW rules text. Now [`bob/checks/ports.py`](bob/checks/ports.py) parses the rules **once** into a `set[(port, proto)]`, and lookups are O(1). Carries the v0.4.3 I4 fix (anchored "To"-column matching) cleanly. The old text-based API is preserved for backward compatibility.
- **I2 wave 2 — `key=` on remaining findings.** v0.4.3 covered `docker.py`, `firewall_stack.py`, `network_context.py`, `ports.py` (4 files). This release finishes the pattern on [`bob/checks/services.py`](bob/checks/services.py) (10 added) and [`bob/checks/virtualization.py`](bob/checks/virtualization.py) (2 added). `disk.py`, `docker_audit.py`, `desktop_apps.py`, `memory.py`, `suid_audit.py` were already at 100% coverage.
- **i18n coverage test.** v0.4.3 had a near-miss when `logs.attempts` was removed from both locales but still referenced by 7 sites in `display.py`. Only the terrain test caught the resulting `[logs.attempts]` sentinel. New [`tests/test_locale_coverage.py`](tests/test_locale_coverage.py) scans all `bob/**/*.py` for `t("KEY")` / `_t("KEY")` calls and asserts each resolves in **both** en.json and fr.json, plus EN/FR structural parity. Any future removal of a still-referenced key fails CI.

### Skipped from the v0.4.3 audit report

- **M3** (`os.path` → `pathlib` in 4 files). Cosmetic, no impact.
- **M7** (lazy `_PLUGIN_DIR` resolution). Already discarded in v0.4.3 — the gotcha was speculative and the attempt broke 20 tests. **Decision permanent.**

### Tests

4485/4485 — +17 vs v0.4.3:
- +10 in [`tests/test_updates.py`](tests/test_updates.py) — 5 cache-stale cases, 5 dist-upgrade-inconsistency cases.
- +2 in [`tests/test_mac_policy.py`](tests/test_mac_policy.py) — desktop INFO and server WARN paths for the new `apparmor_no_profiles` key.
- +9 in [`tests/test_locale_coverage.py`](tests/test_locale_coverage.py) — full corpus scan, EN+FR locale resolution, parity, dynamic-prefix coverage, sanity baseline (5 tests); plus exhaustive `explain.*` coverage generated from `EXPLAIN_KEYS` + non-empty-string check (3 tests, closes a blind spot the previous bypass had) and placeholder parity between EN/FR (1 test, guards against the `{count}` vs `{cnt}` runtime crash class).

### Validated cross-distro

The v0.4.3 fixes confirmed working in the wild on **5 different systems**:
- Linux Mint 22.3 (dev box + test VM): UFW active, DDNS scenario, full audit
- Debian 13 (VM): minimal, smoke test
- Kali Rolling (VM): 15 unexpected SUID (kismet_cap_*), NOPASSWD:ALL, COMPOUND risk detection
- Ubuntu 26.04 LTS (VM): UFW inactive → `firewall.inactive` ALERT correctly triggered with CIS ref + `--explain` link (validates the v0.4.2 C1 + v0.4.3 EXPLAIN_KEYS chain in production)

### Deferred to a later release

- M3 cosmetic cleanup (`os.path` → `pathlib`) — to be included in an eventual "consistency pass" release.
- Phase 2 Option A — systematic `Finding.template_vars` migration on the ~37 remaining checks. Still on track for v0.5.0+.
- Multi-distro CI matrix and AUR PKGBUILD (still community-contribution-welcome).

---

## [v0.4.3] — 2026-05-15

Doc catch-up release that grew into a hardening pass. A fresh agent audit on top of the v0.4.2 codebase found **1 critical + 5 important + 8 minor + 6 suggestion** issues — all applied here. Highlights:

- **C1 (critical)** — `bob --json --json-full` crashed with `AttributeError` whenever a `HardeningSnapshot` was passed. Five field reads in `bob/json_output.py` (`fail2ban_active`, `auto_updates_enabled`, `apparmor_mode`, `apparmor_enforced`, `apparmor_complain`) targeted attributes that had migrated to `mac_policy.py`. The dead reads were removed and the JSON output now exposes the actual fields of the dataclass. **A regression test covers the full+snapshot path.**
- **I1** — `datetime.strptime("%b ...")` is locale-dependent on the **Python process** itself (subprocess `LC_ALL=C` doesn't help). Under `LC_TIME=fr_FR.UTF-8`, `strptime("May 14 ...")` raised `ValueError`, so `_read_cert_expiry` returned "could not parse notAfter" for every cert and `_parse_timestamp` silently dropped every syslog UFW log line. New helper `_parse_english_month_day()` in `bob/checks/_run.py` is locale-independent.
- **I4** — `_is_covered_by_ufw` regex matched the port number anywhere on a UFW status line, so an IP source like `192.168.1.22` "covered" port 22. Anchored the match to the "To" column (right after `[ N]`).
- **I3** — HTML email reports rendered `[label](url)` markdown links as **literal `<a>` tags escaped**. Order of operations reversed in `_inline_format()`.
- **I5** — `_validate_custom_cron` only sanity-checked plain-integer fields. `0-1000 * * * *` and `*/200 * * * *` slipped through silently and were rejected later by cron, losing the schedule. Now validates ranges, lists, and step values across all 5 fields.
- **I2** — Roughly 30 `result.alert()/.warn()/.info()/.ok()/.add_deduction()` calls in `docker.py`, `firewall_stack.py`, `network_context.py`, `ports.py` lacked `key=`. Without it, `--ignore` / audit profiles / JSON consumers cannot match the findings. Same class of bug as the v0.4.2 C1 fix, but generalised to the next 4 most-affected files.

Plus the originally-planned doc catch-up:

1. **4 firewall keys promoted to `EXPLAIN_KEYS`** — `prerequisites.ufw_missing`, `firewall.inactive`, `firewall.policy_open`, `firewall.policy_unknown` were wired as `Finding.key` in v0.4.2 (so `--ignore` / profiles / JSON consumers matched them) but `bob --explain firewall.policy_open` still returned "not found". This release writes the full title / why / how content in both `en.json` and `fr.json` plus CIS references.

2. **CHANGELOG.md (short) corrected for v0.4.2** — the section had read "**No code changes** · 4449/4449 tests (unchanged)" which was wrong: the hardening pass shipped with v0.4.2 modified 11 Python files and added 3 tests. The section has been rewritten with the full hardening pass detail (C1, C2, I1-I5, M1-M5, S1-S3).

### Minor + suggestions

- **M1** — Removed 7 dead locale keys (vestiges of the AppArmor migration from `hardening.py` to `mac_policy.py`, plus `services.port_auto`, `services.port_from_config`, `services.state.inactive_enabled`).
- **M2** — `ntp.py:103` `subprocess.run(["ntpstat"])` now passes `env=_C_LOCALE_ENV` for consistency with the rest of the codebase.
- **M5** — `disk.py` dropped the redundant `_SKIP_TYPES_RE` (already covered by `not device.startswith("/dev/")`).
- **M6** — Replaced i18n concatenation anti-pattern in `ddns.py` (`_t("ddns.found") + f": {client}"`) and `logs.py` (`_t("logs.brute_found") + ...`) with proper `{placeholder}` keys. `_identity_t` now performs placeholder substitution to mirror production behaviour in tests.
- **M8** — `services_state.py` now strips `@instance` from systemd unit names so future template units like `auditd@daily.service` map to `auditd`.
- **S1+S2** — `bob/sysinfo.py` 3 subprocess calls (`ufw --version`, `ip route`, `ip addr`) now pass `env=_C_LOCALE_ENV` for consistency.
- **S3** — `bob/checks/cron_audit.py` `_read_cron_file()` now skips symlinks under user-controlled directories (SECURITY.md trust boundary — prevents an attacker with write access to `/var/spool/cron/crontabs/` from materialising arbitrary file contents in audit reports).
- **S5** — `bob/domain_scores.py` `_domain_for_key()` now logs at DEBUG when falling back to "firewall" for unmapped prefixes (helps catch new check keys missing from `_PREFIX_TO_DOMAIN`).
- **S6** — `bob/__init__.py` defines `__all__`.

### Skipped from the audit report

- **M3** — `os.path` → `pathlib` cleanup in 4 files. Pure cosmetic, no impact.
- **M4** — Regex compilation in `_is_covered_by_ufw` per call. Python `re` module caches the last 512 patterns, so negligible.
- **M7** — Lazy `_PLUGIN_DIR` resolution. Reverted because converting the module-level constant to a function broke 20 tests that `patch("bob.registry._PLUGIN_DIR", ...)`. The "gotcha" was speculative; BOB runs one-shot per audit.
- **S4** — Symlink check on `~/.ssh/authorized_keys` and `~/.ssh/config`. Users may legitimately use symlinks in `~/.ssh/`. Deferred pending design discussion.

### Verified

- `bob --explain firewall.inactive` (EN + FR) — title, WHY IT IS A RISK, HOW TO FIX, CIS ref all present.
- `bob --explain firewall.policy_open` / `firewall.policy_unknown` / `prerequisites.ufw_missing` — same.
- `bob --explain firewall.logging_off` — unchanged (pre-existing key, regression-tested).
- `bob --explain list` — shows "Firewall" group with all 5 keys.
- `LC_TIME=fr_FR.UTF-8 python3 -c "from datetime import datetime; ..."` — `_parse_english_month_day` succeeds where `strptime("%b ...")` failed.
- `_is_covered_by_ufw(22, "tcp", ...)` — returns `False` when port 22 only appears inside an IP source like `192.168.1.22`.
- `build_json_data(full=True, hardening_snapshot=HardeningSnapshot())` — no longer raises `AttributeError`.

### Tests

4468/4468 — +16 vs v0.4.2:
- +12 parametrised invocations from the 4 new EXPLAIN_KEYS entries (3 parametrised checks × 4 keys: title, WHY/HOW headers, CIS reference).
- +4 new regression tests in `tests/test_json_schema.py::TestFullModeWithOptionalSnapshots` covering the `full=True` + `hardening_snapshot`/`ipv6_snapshot` paths (the lacuna that let C1 slip into v0.4.2).

### Deferred to a later release

- Systematic migration of the remaining ~37 non-pilot checks to `Finding.template_vars` (Phase 2 Option A). Still on track for **v0.5.0+** per the original roadmap.
- Multi-distro CI matrix and AUR PKGBUILD (still community-contribution-welcome).
- `~/.ssh/*` symlink protection (S4 above).

---

## [v0.4.2] — 2026-05-14

Phase 3 of the distro-ready roadmap — packaging discipline. Ships packaging artefacts and policy documents that downstream distro maintainers need, plus a pre-release hardening pass that closed 2 critical + 5 important + 4 minor + 1 suggestion findings from an agent audit. 4452/4452 tests (+3 from `tests/test_template_vars_migration.py`).

The repository now contains everything a packager needs to produce a distribution-ready BOB without patching the source.

### New artefacts

- **`SECURITY.md`** — formal threat model and vulnerability disclosure policy. Documents what BOB defends against, what's out of scope (pre-existing root compromise, kernel-level attacks), the three trust boundaries (user-controlled config, system file content, subprocess output) and their respective defenses, the network surface (2 outbound HTTPS calls disabled by `--offline`), and the data handling guarantees (file permissions, auto-chown to `SUDO_USER`).
- **`man/bob.1`** (~280 lines) — the main user-facing man page. Documents every CLI option grouped by purpose (audit control, output formats, configuration, comparison, remediation, network, periodic audits, filters), exit codes as stable public API, the JSON output contract, file paths under `~/.config/bob/`, environment variables (`SUDO_USER`, `LC_ALL/LC_MESSAGES/LANG`), and the security model with a `SEE ALSO` cross-reference to companion pages.
- **`man/bob.conf(5)`** (~80 lines) — config file format reference (`~/.config/bob/config.conf`): custom service ports, `log_dir`, `suid_whitelist` patterns, webhook defaults, email address book.
- **`man/bob-profile(5)`** (~100 lines) — audit profile file format: `[profile]` metadata, `[overrides]` per-key severity (`info`/`warn`/`alert`/`skip`), the `extends` chain, profile discovery order, and the three shipped profiles (`server` / `desktop` / `container`).
- **`debian/`** — full Debian source package directory:
  - `control` — 3 binary packages: `bob-core` (audit engine, no curses), `bob-tui` (curses TUI), `bob` (meta-package). Build-Depends on `debhelper-compat (= 13)` and `pybuild-plugin-pyproject`. Rules-Requires-Root: no.
  - `copyright` — DEP-5 format, MIT throughout, distinct stanzas for `bob/data/`, `bob/locales/`, `bob/data/schemas/`, `debian/`.
  - `changelog` — initial Debian changelog entry `0.4.2-1`.
  - `rules` — pybuild-based, installs man pages and `SECURITY.md` into `bob-core`.
  - `source/format` — `3.0 (quilt)`.
  - `bob-core.install` / `bob-tui.install` — explicit file lists per binary package (curses confined to `bob-tui`, everything else under `bob-core`).
  - `bob-core.docs` / `bob-core.manpages` — doc installations.
- **`debian/apparmor.d/bob`** — AppArmor profile (~140 lines). Shipped in `complain` mode by default with an opt-in `enforce` path. Allows read on `/etc/`, `/proc/`, `/sys/`, `/var/log/`, `~/.config/bob/`, `~/.ssh/`. Whitelists ~30 system binaries that BOB exec's (`ufw`, `ss`, `iptables`, `systemctl`, `journalctl`, `openssl`, `smartctl`, `fwupdmgr`, `apt-cache`, `aa-status`, etc.). Outbound TCP allowed but gated at the application level by `--offline`.
- **`packaging/rpm/bob.spec`** — Fedora COPR / RHEL RPM spec built on `pyproject-rpm-macros`. Single binary `bob` package (no split bob-core/bob-tui — Fedora typically doesn't split that way for Python packages). `%check` runs the full pytest suite. Man pages and `SECURITY.md` installed.

### Policy documentation

- **`DOCUMENTS/README_TECH.md` + FR** — new "Python support policy" section formalizing the **N and N-2** support window. As of v0.4.2: Python 3.10 / 3.11 / 3.12 (and 3.13 when released). 3.9 is end-of-life since v0.2.3. The drop procedure is documented: a Python version drop spans at least 3 minor BOB releases (validate / announce / remove) for a minimum 6-month notice — packagers can rely on this to plan rebuilds.
- **`DOCUMENTS/README_TECH.md` + FR** — new "Packaging (since v0.4.2)" section pointing distro maintainers at the relevant artefacts.

### Roadmap context — Phase 3 status

| Item | Status |
|---|---|
| `SECURITY.md` threat model | ✅ done |
| Man pages (`bob(1)`, `bob.conf(5)`, `bob-profile(5)`) | ✅ done |
| `debian/` source package | ✅ done |
| RPM spec (Fedora COPR) | ✅ done |
| AppArmor profile (complain mode) | ✅ done |
| Python support policy | ✅ done |
| Multi-distro CI matrix | ⏳ deferred (v0.4.x) |
| AUR PKGBUILD | ⏳ deferred — community contribution welcome |
| Lintian-clean + rpmlint-clean verification | ⏳ ongoing (initial pass clean, real packaging test pending) |

### Distro readiness assessment after v0.4.2

- **AUR / COPR community packaging** — viable now (was viable since v0.4.0, this release makes it trivial).
- **Debian unstable** — target window opens: source package builds with `dpkg-buildpackage`; remaining work is lintian-clean verification and an upstream maintainer sponsorship.
- **Fedora COPR official** — same: spec builds; remaining work is COPR account + rpmlint clean.
- **Debian main / Fedora main** — still 12–18 months minimum, as the policy commits to 12 months of contract stability before request.

### Hardening pass (pre-release audit)

A full pre-release code audit surfaced 2 critical + 5 important + 4 minor + 1 suggestion issues — all fixed in the same release:

- **C1** — `firewall.py`: 4 `result.alert()` / `result.add_deduction()` calls lacked `key=`. Without it, `--ignore` / profiles / JSON consumers could not match the most critical alerts. Fixed with `key="prerequisites.ufw_missing"`, `"firewall.inactive"`, `"firewall.policy_open"` on the relevant calls.
- **C2** — `debian/apparmor.d/bob`: 10 binaries BOB actually exec's were missing from the profile (`df`, `lsblk`, `dpkg-query`, `getenforce`, `apt-get`, `find`, `ps`, `netstat`, `ntpstat`, `docker`) + line declared `/usr/local/sbin/bob-*` rw whereas `cron.py` writes to `/usr/local/bin/bob-{slug}`. Both fixed.
- **I1+I2** — `ssl_certs.py` + `virtualization.py`: 3 subprocess calls missing `env=_C_LOCALE_ENV`, breaking date parsing on French locale.
- **I3** — `bob/_paths.py`: renamed `UFW_AUDIT_SHARE` → `BOB_SHARE` env var (legacy name still honored).
- **I4** — RPM spec: `Recommends: firewalld` was wrong (BOB only reads ufw). Fixed to `Recommends: ufw`. **M5** adds `Suggests: apparmor`.
- **I5** — `bob/watch.py`: `run_checks()` called without `user_config=`, silently losing user's SUID whitelist on every `--watch` tick.
- **M1** — Removed untracked `microsoft.gpg` (residue).
- **M2** — `bob/formatter.py` docstring clarified (public API, no internal caller in v0.4.x).
- **M4** — Exposed `bob.compare.BASELINE_PATH` as public symbol.
- **S1** — New `tests/test_template_vars_migration.py` (3 tests) makes Phase 2 migration debt visible.
- **S2** — Documented the timeout policy block at the top of `bob/checks/_run.py`.
- **S3** — Sorted imports in `bob/cron.py` (PEP 8 grouping).

Note: 4 keys are referenced by Findings (`prerequisites.ufw_missing`, `firewall.inactive`, `firewall.policy_open`) but not yet in `EXPLAIN_KEYS` — adding them requires writing full title/why/how/CIS content, deferred to v0.4.3.

### Tests

4452/4452 (+3 from `tests/test_template_vars_migration.py`). Validated:
- All 3 man pages render with `man -l` and `groff -man -Tutf8` without errors.
- 3 schema JSON files remain valid (only the `$id` URL was version-bumped from `v0.4.1` → `v0.4.2`).
- The 3 ChatGPT-style external reviews of Phase 2 still hold (no contract changes).

---

## [v0.4.1] — 2026-05-14

Phase 2 of the distro-ready roadmap — architectural decoupling. Three zones tackled: `--offline` mode finalization, curses isolation via `bob/tui/`, and locale-independent representation of findings via additive `template_vars`. Plus a post-review hardening pass on `bob/formatter.py` (4 edge-case tests + tightened API). All changes are non-breaking (additive). 4449/4449 tests (+19).

### Zone 2.1 — `--offline` strict mode verified

The `-o` / `--offline` flag (already present since v0.4.0) was audited end-to-end: all network-touching sites are either already gated (HTTP `get_public_ip`, webhook POST) or are local-only (apt-cache, fwupdmgr get-updates, journalctl, openssl x509). Added 2 integration tests in `tests/test_webhook.py` that pin the offline contract: webhook is NOT sent when `config.offline=True` even with a webhook URL set, and `get_public_ip(offline=True)` short-circuits before any `urllib` call.

### Zone 2.2 — `bob/tui/` curses subpackage

`bob/cron_ui.py` (952 lines) moved to `bob/tui/cron.py` under a new `bob.tui` subpackage. Curses imports were already lazy (inside functions) — this release makes the separation physical. The 2 call sites in `bob/cron.py` updated to `from bob.tui.cron import ...`. The rest of `bob.*` (audit pipeline, checks, scoring, JSON output) remains importable on systems without curses, which is the prerequisite for a future `bob-core` Debian package separate from `bob-tui`.

### Zone 2.3 — Locale-independent findings (additive)

Two new optional fields on `Finding` and `Deduction`:

```python
@dataclass
class Finding:
    ...
    key:           str  = ""    # already since v0.3.7
    template_vars: dict = field(default_factory=dict)   # new in v0.4.1
```

`template_vars` is the mapping of variables that the check passed to its i18n template (e.g. `{"ciphers": "aes128-cbc, des-cbc"}` for `ssh.weak_ciphers`). When non-empty, an external client can rebuild the localized message from `(key, template_vars, locale)` without depending on the pre-formatted `message` string.

New module `bob.formatter` exposes `format_finding(finding, lang=None)` and `format_deduction(deduction, lang=None)`. Resolution order: `key + template_vars` → `key` alone → fallback to pre-formatted `message` (legacy path, fully backward compatible).

`CheckResult.warn/alert/info/ok/add_finding/add_deduction` helpers accept an optional `template_vars=` kwarg. The 3 pilot checks (`bob/checks/ssh.py`, `hardening.py`, `firewall.py`) demonstrate the migration: same `message=_t("key", **vars)` is kept (legacy compat) and `template_vars={...vars...}` is added in parallel. JSON output now exposes `template_vars` on every deduction and finding (additive field — empty dict for legacy checks).

### Roadmap context

This release closes Zone 2.1 + 2.2 + 2.3 (Option B additive) of the Phase 2 plan. Three pilot checks demonstrate the pattern; the remaining 40 checks can be migrated incrementally without breaking changes. Option A (full breaking refactor — `Finding.message` removed in favor of `Finding.template_vars` mandatory) is deferred to v0.5.0+ together with the schema v2 plugin contracts.

### Tests

4449/4449 (+19):
- 3 new in `tests/test_webhook.py` for offline mode (skip POST, urllib short-circuit, CLI compat)
- 14 new in `tests/test_formatter.py` (10 base: resolution order, locale roundtrip, backward compat; +4 post-review edge cases: partial template_vars, mismatch key/message, empty inputs)
- 2 new in `tests/test_json_schema.py` (`template_vars` exposed in JSON for every deduction and finding)

### Field validation

End-to-end audit on so6desktop: `bob.tui.cron` loads cleanly, the 3 pilot checks emit `template_vars` correctly, `bob --json` exposes the new field on every entry, `--offline` skips the webhook.

---

## [v0.4.0] — 2026-05-14

Phase 1 of the distro-ready roadmap — five public-API contracts frozen so that scripts, dashboards and downstream packagers can rely on stable behavior. No new features, no breaking changes (additive only). 4405/4405 tests (+57).

### Stable contract — Exit codes documented as public API (`bob/__main__.py`, `bob/cli.py`, `DOCUMENTS/README_TECH.md`)

The 5 exit codes (`EXIT_OK=0`, `EXIT_WARNINGS=1`, `EXIT_ALERTS=2`, `EXIT_ERROR=3`, `EXIT_TARGET_MISSED=4`) are now formally promoted to BOB's public API: their values and semantics will not change within a major version. Documented in `--help` (with the missing exit-code 4 mention added) and in a dedicated section of README_TECH. Constants exported from `bob.__main__` for programmatic access.

### Stable contract — Locale auto-detection from POSIX `$LANG` (`bob/i18n.py`, `bob/cli.py`, `tests/conftest.py`)

`bob.i18n.detect_system_lang()` (new) probes `$LC_ALL` / `$LC_MESSAGES` / `$LANG` in standard POSIX order and resolves to `"fr"` for `fr_*` locales or `"en"` otherwise (incl. `C`, `POSIX`, `C.UTF-8`, unsupported languages). `parse_args()` calls it as the default when neither `--lang=` nor `--french` is passed; explicit flags always override. New autouse fixture in `tests/conftest.py` forces `LANG=C` for deterministic tests regardless of host locale.

### Stable contract — JSON output schema documented + `key` field exposed (`bob/json_output.py`, `bob/scoring.py`)

`schema_version="1"` was already present; this release formalizes the contract: top-level keys never disappear/rename within v1, additions are free, breaking changes bump to v2. New constants `SCHEMA_V1_REQUIRED_KEYS` and `SCHEMA_V1_FULL_KEYS` make the contract testable. `Finding.key` and `Deduction.key` are now serialized as `key` field on each entry — clients can match findings via stable dotted keys without depending on the localized `message`/`reason`. Full schema reference added to README_TECH (table of every top-level key, structure of nested objects, locale-independent matching example).

### Stable contract — `--explain` alias map + freeze policy (`bob/explain.py`)

`EXPLAIN_KEY_ALIASES: dict[str, str]` introduced (empty for now) so future renames have a documented migration path: old name → new name, alias never expires within the same major schema version. `normalize_key()` consults the map after path-segment stripping. Module docstring states the freeze policy explicitly: no removal, no rename, no semantic shift, additions free. 16 load-bearing keys explicitly tested as frozen.

### Stable contract — Plugin services formal JSON Schema (`bob/data/schemas/`, `pyproject.toml`)

Two Draft 2020-12 JSON Schema files (`service.schema.json`, `services-list.schema.json`) describe the shape of `services.json` and user `*.json` plugins. Bundled list (`bob/data/services.json`) is verified to validate against the schema. Schemas are shipped via `package_data` so distro packagers can validate user plugins externally with `check-jsonschema` / `ajv`. Python validation in `Service.from_dict()` remains the runtime source of truth (zero added runtime dependency); the JSON Schema mirrors it for external tooling.

### Bonus UX — `= N` redundant suffix on unchanged score removed (`bob/display.py`)

When the score was unchanged vs the previous audit, the summary box showed `Security score : 8/10  = 8` — the `= 8` was a vestige of an earlier delta marker. Removed: stable score now displays simply `8/10` (the score is already shown). Test renamed `test_stable_shows_equal` → `test_stable_shows_no_annotation`.

### Tests

4405/4405 (+57): 16 new in `test_i18n.py` (12 `detect_system_lang` + 4 CLI integration), 15 in new `test_json_schema.py` (top-level invariants, field types, stable-key exposure), 6 in `test_explain.py` (alias map + freeze policy), 20 in new `test_services_schema.py` (schema valid, bundled services match, sample valid/invalid plugins, Python ↔ Schema parity).

### Field validation

End-to-end audit on so6desktop (Linux Mint 22.3) — score 8/10, all sections render correctly, locale auto-detected as French via `$LANG=fr_FR.UTF-8`.

---

## [v0.3.6] — 2026-05-09

Code-review pass following a deep audit of the codebase. No new features, no behaviour changes — bug fixes, hygiene, and consistency. 4348/4348 tests.

### Fix — `Path.home()` resolves to `/root` under sudo (`bob/config.py`, `bob/recurrence.py`, `bob/history.py`, `bob/registry.py`, `bob/compare.py`, `bob/profiles.py`, `bob/plugin_checks.py`, `bob/ignore.py`)

Seven modules used `Path.home()` at module import to compute config/plugin/baseline directories. Under `sudo`, this resolves to `/root/.config/bob/` instead of the invoking user's home — silently breaking user profiles, service plugins, check plugins, baseline, and recurrence/history persistence. The correct helper `bob.sysinfo.get_user_home()` (which honours `SUDO_USER`) already existed but was used in only two places. All seven modules now import and use `get_user_home()`. `bob/ignore.py` had its own duplicated logic — replaced with a call to the shared helper.

To complete the fix, a new helper `bob.sysinfo.chown_to_sudo_user(path)` is called after each user-config directory/file is created or written under sudo, so the invoking user retains read/write access in non-sudo sessions (no-op when not running under sudo). Applied in `config.py`, `compare.py`, `recurrence.py`, `history.py`, `ignore.py` after `mkdir(parents=True)` and after each atomic `replace`/`write_text`. The `registry.py`, `profiles.py`, and `plugin_checks.py` lookups gain a `PermissionError` guard so a directory inaccessible at read time (legacy state from a pre-fix sudo run) gracefully falls back to "no plugin found" instead of crashing.

### Fix — `AllowTcpForwarding local` flagged as a warning (`bob/checks/ssh.py`)

The check accepted only `AllowTcpForwarding no` as safe. Setting `local` (which is more restrictive than the default `yes` and explicitly recommended in BOB's own remediation text) was incorrectly counted as an issue and deducted 1 point. Now both `no` and `local` are accepted.

### Fix — UFW logging section header shown when UFW inactive (`bob/runner.py`)

When UFW was inactive, `check_ufw_logging()` returned an empty `CheckResult` but `runner.py` still printed the section header (`UFW LOGGING`), producing a header followed by no findings. The header is now only printed when `fw_status.active`.

### Fix — IPv6 ULA and link-local treated as external (`bob/checks/network_context.py`)

`_is_private_or_loopback()` covered IPv4 loopback, RFC-1918, and IPv6 `::1` but missed `fc00::/7` (Unique Local Addresses) and `fe80::/10` (link-local). Connections within those ranges were classified as external, producing spurious warnings. Rewritten using `ipaddress.ip_network()` with the same network list as `bob/checks/auth_log.py`.

### Fix — `NOTIFY_EMAIL` legacy regex silently skipped (`bob/cron.py`, `bob/locales/{en,fr}.json`)

`edit_cron_email()` matched only `NOTIFY_EMAILS=` (plural — current format) but not `NOTIFY_EMAIL=` (singular — pre-v0.x scripts). Old scripts saw a "successful" email update that didn't actually patch anything. Now matches both `NOTIFY_EMAILS?=` and warns when no line was matched (new locale key `manage_cron.email_not_found_in_script`).

### Refactor — `_check_weak_algo` moved to sub-check section (`bob/checks/ssh.py`)

The helper was placed in the `# Parsing helpers` section but is logically a sub-check (writes to `result`, calls `_t`). Moved next to the other `_check_*` functions for consistency with project convention.

### Cleanup — 22 unused imports removed (pyflakes)

Vestiges from successive refactorings: `dataclasses.field` in 6 modules where no field defaults exist; `typing.Optional` in 4 modules; `pathlib.Path` in 2; `bob.scoring.{ScoreEngine, Finding, FindingLevel}` in `report.py`; `shutil`, `_C_LOCALE_ENV`, `prompt_emails`, `WebhookError`, etc. Variable shadowing of `dataclasses.field` by parameter `field` in `_extract_field()` resolved by renaming to `field_name`. Dead variable `found_issue` in `check_hardening()` (never read) removed along with all 8 assignments.

### Cleanup — 47 dead locale keys removed (`bob/locales/{en,fr}.json`)

Audit of every key against actual `t()` and `_t()` call sites (including dynamic `f"prefix.{var}"` patterns). Removed: entire `cli.help_*` (14 keys, replaced by hardcoded `print_help` in `cli.py`), entire `errors.*`, `geo.*`, `profile.*` objects, plus orphans in `report`, `manage_cron`, `install_cron`, `prerequisites`, `network_context`, `ddns`, `logs`, `ports`, `summary`, `fixes`, `risk_context`, `log_dir`, `config`, `deduction`, `status`. Both files stay key-synchronised: 1435 → 1388 keys (−47), 2049 → 1994 lines per file.

### Tests

4348/4348 (no change vs v0.3.5). All fixes covered by existing tests; no regression introduced. Validated end-to-end on so6desktop (Linux Mint 22.3) — full audit completes with score 8/10 and renders all sections correctly.

---

## [v0.3.5] — 2026-05-08

Pure internal refactoring and locale fix — no new features, no behaviour changes. 4348/4348 tests.

### Refactoring — `runner.py` `_sec` closure (`bob/runner.py`)

`run_checks()` (951L) contained ~29 identical 7–13 line blocks: `_section_enabled` guard + `print_section` + `report.write_section` + `check_fn` call + `apply_profile` + `engine.apply` + `display_result` + trailing `print()`. Extracted as a `_sec(section, snapshot, check_fn, **kwargs)` closure that captures `config`, `profile`, `engine`, `report`, `t`, `_pr` from the outer scope. All standard sections use `_sec`; exceptions kept manual: firewall/network headers, ports, logs, DDNS, docker, virtualisation, samba, docker_audit, desktop_apps, iptables_nft, disk (extra display call). Net: 951L → 656L (−295 lines). `_pname` pre-computed for the 8 sections that accept `profile_name=`.

`auth_log` previously omitted `apply_profile` — now consistent with all other sections (no-op in practice as no profile currently defines auth_log overrides).

### Refactoring — `ssh.py` `_check_weak_algo` helper (`bob/checks/ssh.py`)

`_check_sshd_config()` had three structurally identical 16-line blocks for weak Ciphers, MACs, and KexAlgorithms. Extracted as `_check_weak_algo(cfg, result, _t, cfg_key, weak_set, t_key, param, points) -> bool`. The three blocks collapse to three one-liner calls. Net: −26 lines.

### Fix — locale strings `UFW-AUDIT` → `BOB` (`bob/locales/en.json`, `bob/locales/fr.json`)

Four translation keys still referenced the former tool name `UFW-AUDIT` instead of `BOB`: `install_cron.title`, `manage_cron.title`, `manage_cron.no_crons`, `report.title`. Replaced in both locale files.

---

## [v0.3.4] — 2026-05-08

Hotfix for a regression introduced in v0.3.2. `user_config` was referenced inside `run_checks()` but never passed as a parameter — every audit crashed with `Fatal error: name 'user_config' is not defined` immediately after the kernel hardening section. 4348/4348 tests.

### Fix — `user_config` not passed to `run_checks()` (`bob/runner.py`, `bob/__main__.py`)

`run_checks()` gained `user_whitelist=user_config.get_suid_whitelist()` in v0.3.2 but `user_config` was never added to the function signature. Fix: `user_config: UserConfig | None = None` parameter added; `__main__.py` passes `user_config=user_config` at the call site. Fallback is `[]` when `None` (no whitelist applied).

---

## [v0.3.3] — 2026-05-07

Pure internal refactoring — no new features, no behaviour changes. Four related cleanup tasks driven by a code-review pass on the codebase. 4348/4348 tests (+1).

### Refactoring — `cron.py` split (`bob/cron.py`, `bob/cron_ui.py`)

`bob/cron.py` (2181L) was split into two modules. `bob/cron.py` retains all data types, parsers, logic, and plain-text interactive flows. `bob/cron_ui.py` (new, 955L) holds all curses TUI code. Dispatchers `run_install_cron()` / `run_manage_cron()` use a lazy-import pattern: check `sys.stdout.isatty()` → plain-text flow; otherwise `curses.wrapper(curses_fn)` with `curses.error` fallback to plain-text.

`build_script_content(notify_email, log_dir) -> str` extracted from both install flows into `cron.py` as a pure function, eliminating a 40-line duplication.

### Refactoring — `compute_domain_scores()` pure return (`bob/scoring.py`, `bob/domain_scores.py`, `bob/breakdown.py`)

`Deduction.was_capped: bool` field removed. `compute_domain_scores()` now returns `tuple[dict[str, dict], frozenset[int]]` — the second element is the set of indices in `engine.breakdown` that were reduced by a tool cap. `ScoreEngine` caches these indices via `set_domain_scores()` (new `capped_indices` parameter) and exposes them through a `capped_indices` property. `breakdown.py` reads `engine.capped_indices` directly.

### Refactoring — `domain_scores.py` public API

`_LABELS → LABELS`, `_TOOL_CAPS → TOOL_CAPS`, `_key_to_domain → key_to_domain`. Callers updated: `breakdown.py`, `explain.py`, `tests/test_domain_scores.py`.

### Refactoring — `cron_ui.py` curses helpers

`_WizardEntry(name, hour=3, minute=0)` NamedTuple replaces `class _FakeEntry: pass` stub. `_draw(stdscr, row, col, text, attr=0)` absorbs 30+ `try: addstr(…) except curses.error: pass` blocks. `_read_key(stdscr) -> int` absorbs 9 `try: get_wch() / except curses.error: continue` + ch-normalisation blocks. Schedule type magic indices replaced by `_SCHEDULE_DAILY/WEEKDAYS/MONTHDAYS/CUSTOM` constants. Net reduction: 1104L → 955L (−149 lines).

### Tests

4348/4348 (+1 from v0.3.2): `TestWasCapped` replaced by `TestCappedIndices` (7 tests) covering the frozenset return contract of `compute_domain_scores()`.

---

## [v0.3.2] — 2026-05-06

User-configurable SUID whitelist: patterns declared in `~/.config/bob/config.conf` suppress known-legitimate binaries from the "unexpected SUID" warning. No new warnings — only noise reduction for environments like Kali that ship extra SUID tools. Plus 14 code-review fixes covering i18n labels, quiet-mode bypass, engine idempotency, dead code, and minor bad practices. 4347/4347 tests (+19).

### Feature — `suid_whitelist` in `config.conf` (`bob/config.py`, `bob/checks/suid_audit.py`, `bob/runner.py`)

Users can now declare glob patterns for approved SUID binaries directly in `~/.config/bob/config.conf`:

```
# ~/.config/bob/config.conf
suid_whitelist = kismet_cap_*, my_custom_tool
```

Patterns are matched against the **basename** of each detected SUID binary using `fnmatch`. Matched paths are removed from the "unexpected SUID" list, eliminating false positives on Kali (15+ Kismet capture binaries), enterprise environments, or systems with custom in-house tools.

When at least one binary is suppressed, an INFO finding `suid_audit.whitelisted` reports the count and paths, so users can confirm the whitelist is working without silently hiding everything.

Implementation: `UserConfig.get_suid_whitelist() -> list[str]` reads and parses the comma-separated key. `SuidSnapshot.from_system()` gains a `user_whitelist` parameter; the runner passes `user_config.get_suid_whitelist()` at call time. The suppressed paths are stored in `SuidSnapshot.whitelisted_suid` for transparent reporting.

### Fixes — code review (14 items)

| ID | File | Fix |
|----|------|-----|
| BUG-2 | `domain_scores.py` | `compute_domain_scores()` reset `was_capped=False` before recomputing — idempotent now |
| BUG-3 | `runner.py` | `"samba"` and `"desktop_apps"` added to `_ALL_SECTIONS` — visible to `--check`/`--skip`/`--list-checks` |
| BUG-4 | `output.py` | `_print_status()` and `print_risk_context()` use `_p()` — quiet mode now respected |
| BUG-1 | `output.py` | `[ATTENTION]`/`[ALERTE]` → `t("status.warn")`/`t("status.alert")` — i18n wired |
| BUG-5 | `scoring.py`, `logs.py`, `display.py` | `result._log_data` → proper `CheckResult.log_data` field (no more `# type: ignore`) |
| BUG-6 | `checks/logs.py` | Bruteforce `warn()` and `add_deduction()` gain `key="logs.brute_found"` — visible to `--ignore` and profiles |
| SF-1 | `checks/ssh.py` | `sshd_config` parse emits `ssh.match_block_skipped` INFO when a `Match` block truncates parsing |
| SF-2 | `__main__.py` | `curr_baseline = None` initialised before `with` block — no `UnboundLocalError` risk |
| SEC-1 | `fixes.py` | Raw `\033[...]` literals replaced by `output._c.*` — respects `--no-color` |
| BP-2 | `scoring.py`, `domain_scores.py` | `engine.set_domain_scores()` public method — no more direct `_private` attribute writes |
| BP-3 | `checks/ssh.py` | `f.level.value in (...)` → `f.level != FindingLevel.OK` — enum-safe comparison |
| BP-1 | `__main__.py` | `open(os.devnull, "w", encoding="utf-8")` — explicit encoding |
| INC-2 | `runner.py` | `SambaSnapshot`/`DesktopAppsSnapshot.from_system()` moved inside `_section_enabled()` guard — no subprocess on `--skip` |
| DC-1 | `checks/suid_audit.py` | `_is_root_owned()` deleted — private dead code duplicating inline logic |

### Tests

4347/4347 (+19 net from v0.3.1):

| File | Change |
|------|--------|
| `tests/test_suid_audit.py` | +21 across `TestFromSystemUserWhitelist` (8), `TestGetSuidWhitelist` (7), `TestGlobMatching` (7) — −2 `TestIsRootOwned` (deleted with DC-1) |
| `tests/test_logs.py` | 3 assertions updated `_log_data` → `log_data` (BUG-5) |

---

## [v0.3.1] — 2026-05-06

Two targeted bug fixes found during multi-VM validation, plus two architectural refactors in the score breakdown pipeline. No new features. 4328/4328 tests (+6).

### Fix — `__version__` banner stuck at `0.2.4` (`bob/__init__.py`)

After the v0.3.0 release, `bob/__init__.py` still declared `__version__ = "0.2.4"`. The banner and `bob -V` both displayed the wrong version on all platforms. Fixed.

### Fix — DDNS network context not propagated to score header (`bob/runner.py`, `bob/__main__.py`)

When DDNS was active and open ports were detected, `run_checks()` upgraded `network_context` from `"local"` to `"ddns"` internally — but `ChecksResult` (a NamedTuple) did not include a `network_context` field, so the caller always saw `"local"`. The score summary header showed "Local network only" even on machines with an active DDNS client. Fix: `network_context: str = "local"` added to `ChecksResult`; `__main__.py` reads `result.network_context` immediately after `run_checks()`.

### Refactor — `was_capped: bool` on `Deduction` (`bob/scoring.py`, `bob/domain_scores.py`, `bob/breakdown.py`)

`breakdown.py` previously re-simulated the tool-cap accounting to determine which deductions were absorbed by a cap — duplicating logic from `compute_domain_scores()` and violating the module's "nothing is computed here" contract. Fix: `Deduction` gains `was_capped: bool = False`; `compute_domain_scores()` sets it when a deduction is partially or fully absorbed. `breakdown.py` reads `d.was_capped` directly.

### Refactor — `engine.domain_scores` / `engine.active_domains` cached properties (`bob/scoring.py`, `bob/domain_scores.py`)

Display modules (`__main__.py`, `breakdown.py`) previously called `compute_domain_scores()` and `active_domains_from_engine()` independently, risking double computation. Fix: `apply_domain_score_override()` caches results on the engine; two `@property` methods expose them as `engine.domain_scores` and `engine.active_domains`. All callers read from the cache.

### Tests

4328/4328 (+6 new):

| File | Change |
|------|--------|
| `tests/test_domain_scores.py` | +6 `TestWasCapped`: uncapped / fully absorbed / partially absorbed deductions · non-tool-cap keys never marked · cached domain scores on engine · engine state before override |

---

## [v0.3.0] — 2026-05-06

Scoring transparency milestone: `--breakdown` (`-B`) shows the full score computation path — deductions, tool caps, engine cap, raw score, per-domain scores, domain-average override, and final score. `--explain <key>` gains a SCORING section showing domain membership and tool cap. Three targeted fixes: kernel `-unsigned` asymmetry in retention logic, orphan `→` in the score delta line, and "UFW-AU" ASCII art relics in the detailed report. 4322/4322 tests (+48).

### Feature — `--breakdown` / `-B` flag (`bob/breakdown.py`, `bob/cli.py`, `bob/__main__.py`, locales)

New post-audit view that prints the complete score computation path without re-running checks. Shows: all deductions (key · domain · points · context), which deductions were absorbed by tool caps, whether the engine cap applied, raw score before domain averaging, per-domain scores with progress bars, whether the domain-average override fired, and the final score color-coded by severity.

Implemented using `_silent_mode`: audit output is redirected to `/dev/null` via `redirect_stdout`, then breakdown is displayed after stdout is restored. This suppresses all bare `print()` calls (not just `output.*` calls), giving a clean view.

i18n: `breakdown.*` keys added to both `bob/locales/en.json` and `bob/locales/fr.json`.

### Feature — Score-aware `--explain` (`bob/explain.py`)

`bob --explain <key>` now appends a SCORING section after the remediation text, showing the key's domain and any applicable tool cap. Ends with a hint to run `sudo bob --breakdown` to see the live score contribution.

### Fix — Kernel `-unsigned` retention asymmetry (`bob/checks/kernel_modules.py`)

On Debian systems with signed/unsigned kernel pairs (e.g. `6.12.74+deb13+1-amd64` and `6.12.74+deb13+1-amd64-unsigned`), the unsigned variant sorted alphabetically last and consumed one retention slot, leaving the signed variant incorrectly marked as obsolete. Fixed: after the retention loop, the keep-set is expanded to include both signed and unsigned variants of every kept base version. The obsolete detail message also now uses `recent=running` instead of `recent=most_recent` so the boot-verification hint always names the kernel the system is actually running.

### Fix — Score delta orphan arrow (`bob/display.py`)

When the score was identical between two consecutive audits, the score line showed `6/10  →` with no value after the arrow. Changed to `6/10  = 6` (equals sign + repeated score) for clarity.

### Fix — "UFW-AU" relics in detailed report (`bob/report.py`, `bob/report_markdown.py`)

The detailed report file opened with `--detailed` contained an ASCII art banner spelling "UFW-AU" (from the former tool name "ufw-audit") and a header field "UFW: v...". Replaced with BOB ASCII art (same style as the terminal banner) and "Firewall: ufw ...". Markdown report updated: "UFW:" → "Firewall (UFW):".

### Tests

4322/4322 (+48 new):

| File | Change |
|------|--------|
| `tests/test_breakdown.py` | New file — 16 tests: bar helper, clean engine, deductions, tool cap, engine cap, domain override, French labels |
| `tests/test_golden_scenarios.py` | New file — 32 tests: end-to-end scoring scenarios across 9 test classes (clean, hardened, desktop, poorly configured, firewall inactive, Debian minimal, tool caps, stability, multi-domain) |
| `tests/test_min_level.py` | Renamed `test_stable_shows_right_arrow` → `test_stable_shows_equal` to match `= N` format |

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
