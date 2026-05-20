# BOB — Project snapshot

> **Purpose.** A single-page bird's-eye view of the codebase as of **v0.4.6** (2026-05-17). Designed to be loaded once before a refactor pass or an audit so you don't have to re-discover the structure module by module. Stats are derived from the actual source files; conventions and contracts are observable in the code, not aspirational.

---

## Vue 1-écran

```
┌─────────────────────────────────────────────────────────────────────────┐
│  bob v0.4.6     ~18 kLoC Python · 0 runtime deps outside stdlib         │
│                 4500 unit tests · 16 doc files · 7 distros CI-validated │
└─────────────────────────────────────────────────────────────────────────┘

LAYER (top→bottom = imports flow down)

    bob/__main__.py  ← orchestrator (411 L)
        │
        ▼
    bob/runner.py  ← audit engine, run_checks() + _sec (657 L)
        │
        ├──► bob/cli.py            ← AuditConfig + parse_args() (662 L)
        ├──► bob/config.py         ← UserConfig + EmailStore
        ├──► bob/profiles.py       ← server/desktop/container + user
        ├──► bob/scoring.py        ← ScoreEngine + Finding + Deduction
        ├──► bob/domain_scores.py  ← per-domain averaging, 7 domains
        │
        ▼
    bob/checks/*.py  ← 43 check modules · Snapshot+check_xxx pattern
        │  ├ firewall/ports/services/logs/ddns  (network)
        │  ├ docker / docker_audit              (containers)
        │  ├ ssh / file_perms / suid_audit / user_accounts / password_policy / umask  (access)
        │  ├ hardening / kernel_hardening / kernel_modules / mac_policy / secure_boot  (kernel)
        │  ├ updates / firmware / cron_audit / services_state             (system)
        │  ├ disk / memory / backup                                       (hardware)
        │  ├ auditd / file_integrity / rootkit / clamav / fail2ban / auth_log  (security tools)
        │  └ ssl_certs / systemd_timers / ntp / desktop_apps / virtualization / samba / smtp / iptables_nftables / ipv6 / log_rotation
        │
        ▼
    bob/display.py + bob/output.py + bob/panorama.py + bob/breakdown.py
        ← terminal rendering
    bob/json_output.py + html_output.py + csv_output.py + markdown_output.py + report_markdown.py
        ← export formatters
    bob/formatter.py + bob/i18n.py + bob/locales/{en,fr}.json
        ← locale-independent reconstruction + i18n (1401 keys per language)

DATA (read-only at runtime, shipped in the package)

    bob/data/services.json        ← 32 services (id+ports+risk+detection)
    bob/data/cis_refs.json        ← 137 CIS references
    bob/data/profiles/*.conf      ← server/desktop/container/workstation
    bob/data/schemas/*.json       ← service / services-list / plugin-file (Draft 2020-12)
    bob/data/bob.bash-completion  ← shipped, installed via --install-completion

EXTERNAL CONTRACTS (frozen, do not break without major bump)

    schema_version = "1"          ← JSON output top-level
    EXIT CODES 0/1/2/3/4          ← stable public API
    EXPLAIN_KEYS                  ← 116 keys in 29 groups, frozen alias map
    7 domain keys                 ← ssh, samba, file_perms, updates, hardening, disk, firewall
    34 --check/--skip section names ← stable filter surface
    services.json schema v1        ← plugin contract for users
```

---

## Project structure (annotated)

```
bodyguard-of-bits/
├── bob/                       ← Python package (the tool)
│   ├── __init__.py            ← __version__ string only
│   ├── __main__.py            ← orchestrator, 411 L, 28 outgoing imports
│   ├── runner.py              ← run_checks(), 657 L, _sec closure (29 sections)
│   ├── cli.py                 ← parse_args() + AuditConfig, 662 L
│   ├── config.py              ← UserConfig, EmailStore, ~/.config/bob/
│   ├── profiles.py            ← audit profile loader (3 built-in + user)
│   ├── scoring.py             ← ScoreEngine, Finding, Deduction, FindingLevel
│   ├── domain_scores.py       ← 7-domain attribution, active set, capping
│   ├── checks/                ← 43 check modules, see Module index below
│   ├── tui/                   ← optional curses subpackage (v0.4.1 extraction)
│   │   ├── __init__.py
│   │   └── cron.py            ← curses wizard for --install-cron / --manage-cron (952 L)
│   ├── display.py             ← terminal output helpers, 792 L
│   ├── output.py              ← low-level terminal primitives, 574 L
│   ├── panorama.py            ← services panorama table builder
│   ├── breakdown.py           ← --breakdown score computation transparency
│   ├── exposure.py            ← port exposure grouping
│   ├── formatter.py           ← locale-independent reconstruction (v0.4.1)
│   ├── i18n.py                ← t(key, **vars), 1401 keys per locale
│   ├── locales/
│   │   ├── en.json            ← English translation keys
│   │   └── fr.json            ← French translation keys (strict parity)
│   ├── data/
│   │   ├── services.json      ← 32 known services (declarative registry)
│   │   ├── cis_refs.json      ← 137 CIS references
│   │   ├── profiles/          ← server.conf, desktop.conf, container.conf
│   │   ├── schemas/           ← 3 JSON Schemas (Draft 2020-12)
│   │   └── bob.bash-completion ← bash completion script
│   ├── explain.py             ← --explain TUI, EXPLAIN_KEYS (116), 736 L
│   ├── cis_refs.py            ← lookup get_cis_ref() / get_cis_code()
│   ├── compare.py             ← AuditBaseline + AuditDelta + diff
│   ├── correlation.py         ← 6 compound-risk rules
│   ├── recurrence.py          ← consecutive-audit finding tracker
│   ├── history.py             ← --history sparkline, rotates at 1000 entries
│   ├── ignore.py              ← persistent ignore list
│   ├── fixes.py               ← --fix interactive remediation UI
│   ├── cron.py                ← cron management (1201 L — biggest non-check)
│   ├── manage_logs.py         ← --manage-logs curses TUI (999 L)
│   ├── completion.py          ← --install-completion installer
│   ├── webhook.py             ← --webhook generic + Slack
│   ├── watch.py               ← --watch=N live monitoring
│   ├── plugin_checks.py       ← user plugin loader (size-limited, ANSI-sanitized)
│   ├── registry.py            ← ServiceRegistry.load()
│   ├── report.py              ← AuditReport, NullReport, file output
│   ├── report_markdown.py     ← MarkdownReport, HTML email (778 L)
│   ├── json_output.py         ← --json / --json-full builder
│   ├── csv_output.py          ← --format csv
│   ├── html_output.py         ← --html standalone export
│   ├── markdown_output.py     ← --format markdown
│   ├── sysinfo.py             ← system info, network context, get_user_home()
│   ├── _paths.py              ← BOB_SHARE / UFW_AUDIT_SHARE (legacy) resolution
│   └── _tty.py                ← raw-mode line reader (Esc-to-cancel)
├── tests/                     ← 84 test files, 3973 test functions, 4500 collected
├── DOCUMENTS/                 ← public technical documentation
├── debian/                    ← Debian source package (bob-core/bob-tui/bob meta)
├── packaging/rpm/             ← Fedora COPR RPM spec
├── man/                       ← 3 man pages (bob.1, bob.conf.5, bob-profile.5)
├── .github/workflows/         ← CI (tests.yml, integration.yml, publish.yml)
├── pyproject.toml             ← build config + classifiers + metadata
├── SECURITY.md / SECURITY_FR.md
├── README.md / README_FR.md
├── CHANGELOG.md / CHANGELOG_FR.md
└── LICENSE                    ← MIT
```

---

## Module index — bob/ root (38 modules) + bob/tui/cron.py

| Module | LoC | Role |
|---|---:|---|
| `__main__.py` | 411 | Orchestrator: argv → AuditConfig → snapshots → run_checks() → display |
| `runner.py` | 657 | Audit engine: `run_checks()`, `_sec` closure factory (29 sections), `_section_enabled()` |
| `cli.py` | 662 | `parse_args()`, `AuditConfig` dataclass, `--help` text, CLIError |
| `config.py` | — | `UserConfig` + `EmailStore` + suid_whitelist + log_dir prompts |
| `profiles.py` | — | Profile loader: server/desktop/container + ~/.config/bob/profiles/*.conf |
| `scoring.py` | — | `ScoreEngine`, `Finding`, `Deduction`, `FindingLevel`, `ScoreCap` |
| `domain_scores.py` | 343 | `compute_domain_scores()`, `active_domains_from_engine()`, `apply_domain_score_override()` — 7 domains |
| `explain.py` | 736 | `--explain` TUI + `EXPLAIN_KEYS` (116 keys, 29 groups) + alias map |
| `cis_refs.py` | — | CIS lookup with `lru_cache(maxsize=1)`, reads `data/cis_refs.json` (137 entries) |
| `display.py` | 792 | Terminal output: section boxes, finding emission, summary box, score bar |
| `output.py` | 574 | Low-level primitives: `print_ok/warn/alert/info/section/banner` |
| `panorama.py` | — | Services panorama table builder (after-audit summary) |
| `breakdown.py` | — | `--breakdown` / `-B` score computation transparency display |
| `exposure.py` | — | Port exposure grouping (interface scope + risk level) |
| `formatter.py` | — | `format_finding()`, `format_deduction()` — locale-independent via `template_vars` |
| `i18n.py` | — | `t(key, **vars)`, locale auto-detect (POSIX), 1401 keys EN/FR |
| `compare.py` | — | `AuditBaseline`, `AuditDelta`, `build_baseline()`, `compute_delta()`, `display_delta()` |
| `correlation.py` | — | 6 compound-risk rules (`CorrelationRule` with frozensets) |
| `recurrence.py` | — | Recurring finding tracker: consecutive-audit counters |
| `history.py` | — | `--history` sparkline, JSONL append at `~/.config/bob/history.jsonl`, rotate@1000 |
| `ignore.py` | — | Persistent ignore list `~/.config/bob/ignore.yml` |
| `fixes.py` | — | `--fix` interactive UI with [y/N] prompts |
| `cron.py` | **1201** | Cron management: `CronEntry`, schedule parsing, plain-text + TUI dispatch |
| `tui/cron.py` | 952 | Curses TUI for `--install-cron` / `--manage-cron` |
| `manage_logs.py` | 999 | `--manage-logs` curses TUI with score history chart |
| `completion.py` | — | `--install-completion` → writes `/etc/bash_completion.d/bob` |
| `webhook.py` | — | Generic JSON / Slack payload + send (10s timeout) |
| `watch.py` | — | `--watch=N` live monitoring loop |
| `plugin_checks.py` | — | `PluginCheck`, size-limited + ANSI-sanitized user plugin loader |
| `registry.py` | — | `ServiceRegistry.load()`: bundle services.json + ~/.config/bob/services.d/ |
| `report.py` | — | `AuditReport` + `NullReport`, immediate flush, ASCII art header |
| `report_markdown.py` | 778 | `MarkdownReport` + `send_html_email()` (multipart/alternative) |
| `json_output.py` | — | `build_json_data()` (short + full mode), `schema_version="1"` |
| `csv_output.py` | — | `--format csv` formatter |
| `html_output.py` | — | `build_html_output()` standalone HTML (no JS, XSS-safe) |
| `markdown_output.py` | — | `--format markdown` formatter |
| `sysinfo.py` | — | `collect_system_info()`, `detect_network_context()`, `get_user_home()` (sudo-aware) |
| `_paths.py` | — | `resolve_share_dir()`: BOB_SHARE → UFW_AUDIT_SHARE (legacy) → in-package |
| `_tty.py` | — | `read_line(prompt) → str|None`, Esc returns None, TTY fallback to input() |

## Module index — bob/checks/ (43 checks)

> All follow the same shape: `XxxSnapshot.from_system()` collects raw data (only place with subprocess calls); `check_xxx(snapshot, t)` is pure logic, testable without mocks. The active domain for each check is decided by `domain_scores._PREFIX_TO_DOMAIN`.

| Check | LoC | Domain (scoring) | Notes |
|---|---:|---|---|
| `firewall.py` | 501 | firewall | UFW state, `check_rules()` for duplicates / open-any |
| `firewall_stack.py` | — | firewall | Docker iptables bypass, nftables parallel rules |
| `iptables_nftables.py` | — | firewall | Fallback audit when UFW inactive (INPUT/FORWARD policy) |
| `ipv6.py` | — | firewall | IPv6 listener vs UFW v6 rule consistency |
| `network_context.py` | — | firewall | Interface table, established TCP, sensitive remote ports |
| `services.py` | 614 | firewall | 32 known services, risk context, exposure classification |
| `services_state.py` | — | hardening | Boot-enabled but currently inactive security services |
| `ports.py` | 506 | firewall | Listening ports analysis, `_parse_ufw_covered_ports()` (v0.4.4 refactor) |
| `logs.py` | 648 | hardening | UFW log analysis, brute-force, top IPs (GeoIP optional) |
| `log_rotation.py` | — | hardening | logrotate, journald persistence, SystemMaxUse |
| `auth_log.py` | — | ssh | SSH connection log, brute-force detection |
| `ddns.py` | — | firewall | DDNS client + crossed with open UFW ports |
| `docker.py` | — | firewall | iptables bypass detection, container port exposure |
| `docker_audit.py` | — | firewall | daemon.json hardening, privileged containers, sensitive mounts |
| `virtualization.py` | — | firewall | KVM/VirtualBox/VMware/LXC + Snap network packages |
| `samba.py` | — | samba | SMBv1, signing, map-to-guest, bind interfaces |
| `smtp.py` | — | firewall (catch-all) | MTA exposure (Postfix/Exim/Sendmail) — prefix `smtp` not in `_PREFIX_TO_DOMAIN` |
| `hardening.py` | — | hardening | sysctl net.* / fs.* (rp_filter, send_redirects, syncookies…) |
| `kernel_hardening.py` | — | hardening | sysctl kernel.* (ASLR, ptrace_scope, kptr_restrict…) |
| `kernel_modules.py` | 501 | hardening | risky modules + apt kernel updates + installed listing (dpkg `ii` filter since v0.4.6) |
| `mac_policy.py` | — | hardening | AppArmor / SELinux state, 0-profile case |
| `updates.py` | — | updates | `apt-get -s dist-upgrade`, stale cache, cross-check (since v0.4.4) |
| `ssh.py` | **1392** | ssh | Biggest check: sshd_config, host keys, user keys, authorized_keys, known_hosts |
| `file_perms.py` | — | file_perms | /etc/passwd, /etc/shadow, sudoers, SSH host keys |
| `suid_audit.py` | — | hardening | SUID/SGID with whitelist (config.conf), targeted-roots scan |
| `user_accounts.py` | — | file_perms | UID 0 non-root, empty passwords, expired accounts |
| `password_policy.py` | — | hardening | PAM pam_pwquality/pam_cracklib, PASS_MAX_DAYS, login.defs |
| `umask.py` | — | hardening | login.defs, common-session, profile, current process |
| `cron_audit.py` | — | hardening | Pipe-to-shell, world-writable, range validator |
| `disk.py` | — | disk | SMART (skip all-virtual since v0.4.4), partition usage, NVMe |
| `backup.py` | — | disk | borgmatic / restic / timeshift / duplicati / rclone |
| `memory.py` | — | hardening | SSD wear, unjustified swap, swappiness |
| `desktop_apps.py` | — | firewall (catch-all) | GUI app process detection (Brave, VSCode, ExpressVPN…) — prefix `desktop_apps` not in `_PREFIX_TO_DOMAIN` |
| `ntp.py` | — | hardening | systemd-timesyncd/chronyd/ntpd active + synced |
| `auditd.py` | — | hardening | Linux Audit Framework, loaded rules, sensitive file watches |
| `secure_boot.py` | — | hardening | UEFI state via mokutil/efivars/bootctl |
| `fail2ban.py` | — | firewall (catch-all) | Service state, jails, SSH jail detection — prefix `fail2ban` not in `_PREFIX_TO_DOMAIN` |
| `clamav.py` | — | hardening | DB freshness via mtime, last scan, daemon status |
| `file_integrity.py` | — | hardening | AIDE/Tripwire installation, DB existence, last check |
| `rootkit.py` | — | hardening | rkhunter / chkrootkit, DB age, scan age |
| `ssl_certs.py` | — | hardening | Let's Encrypt, /etc/ssl/private, nginx/apache2/postfix configs |
| `systemd_timers.py` | — | hardening | pipe-to-shell, world-writable scripts, user-created root timers |
| `firmware.py` | — | hardening | fwupd pending updates, CPU microcode package |

---

## Dependency graph

### Centrality — modules most depended upon (top 15 in-degree)

These are the **stability anchors**. Refactoring them needs care because many modules read from them.

| In-degree | Module | Why central |
|---:|---|---|
| 60 | `scoring` | Every check returns `CheckResult`; `Finding`, `Deduction` types touched everywhere |
| 47 | `checks._run` | Shared subprocess helper with `_C_LOCALE_ENV`, used by every check |
| 12 | `sysinfo` | `collect_system_info()`, `detect_network_context()`, `get_user_home()` (sudo-aware) |
| 7 | `report` | `AuditReport` + `NullReport` used by orchestrator + plugin checks |
| 6 | `domain_scores` | `apply_domain_score_override()`, `key_to_domain()`, etc. |
| 5 | `output`, `config`, `checks.ports`, `checks.services` | UI primitives + user config + 2 core checks reused by display/exposure |

### Out-degree — modules with most outgoing imports (top 5)

These are the **integration points**. They're the entry/orchestration layer.

| Out-degree | Module | Why fan-out |
|---:|---|---|
| 54 | `runner.py` | Imports every check + scoring + display |
| 29 | `__main__.py` | Orchestrator wires runner + cli + report + i18n + sysinfo |
| 9 | `display.py` | Renders findings from many sub-modules |
| 9 | `json_output.py` | Builds full payload from many snapshots |
| 9 | `watch.py` | Wraps the full audit loop |

### Refactoring implication

- **scoring.py** and **checks/_run.py** are bedrock — touching them = risk of broad regression. Cover with extra tests before changing.
- **runner.py** has 54 outgoing imports → if you change a check's signature (e.g. `Finding.template_vars` migration), the impact lands here first.
- The orchestration layer (`__main__.py` + `runner.py`) is the **only place with heavy fan-out**. Everything else is a focused module → safe to refactor in isolation.

---

## Hotspots

### Biggest source files (top 10)

| LoC | File | Hotspot reason |
|---:|---|---|
| 1392 | `bob/checks/ssh.py` | Many sub-checks: 15+ sshd_config directives + key audit + authorized_keys + ~/.ssh/config + known_hosts |
| 1201 | `bob/cron.py` | Schedule parsing + cron file format + MTA detection + email book + plain-text wizards |
| 999 | `bob/manage_logs.py` | Full curses TUI: list + preview + score chart + multi-directory view |
| 952 | `bob/tui/cron.py` | Curses TUI for cron wizards (extracted v0.4.1) |
| 792 | `bob/display.py` | Renders all sections + risk context blocks + summary box |
| 778 | `bob/report_markdown.py` | Markdown report + HTML email (MIME multipart) |
| 736 | `bob/explain.py` | EXPLAIN_KEYS (116) + alias map + interactive TUI |
| 662 | `bob/cli.py` | `parse_args()` covers ~35 options |
| 657 | `bob/runner.py` | `_sec()` closure + 29 section invocations |
| 648 | `bob/checks/logs.py` | UFW log parser + bruteforce + GeoIP + IoT detection |

### Biggest test files (top 10)

| LoC | File | Coverage focus |
|---:|---|---|
| 1022 | `tests/test_ssh.py` | sshd_config + host keys + user keys |
| 920 | `tests/test_kernel_modules.py` | risky modules + apt kernel + dpkg ii filter (v0.4.6) |
| 882 | `tests/test_manage_logs.py` | curses TUI flows (heavy fixturing) |
| 875 | `tests/test_services.py` | 32 services × detection paths × risk classification |
| 855 | `tests/test_domain_scores.py` | per-domain attribution + ScoreCap + TestActiveDomainsIncludesOK (v0.4.6) |
| 741 | `tests/test_cli.py` | argv parsing + AuditConfig + alias maps |
| 699 | `tests/test_profiles.py` | profile inheritance + overrides + extends chain |
| 682 | `tests/test_samba.py` | SMBv1 + signing + map-to-guest + bind interfaces |
| 680 | `tests/test_logs.py` | UFW log parser + bruteforce + IoT dominance |
| 626 | `tests/test_explain.py` | EXPLAIN_KEYS + alias + freeze policy |

### Tests-to-code ratio (rough proxy for risk)

| Check / module | Source LoC | Test LoC | Ratio | Verdict |
|---|---:|---:|---:|---|
| `checks/ssh.py` | 1392 | 1022 | 0.73× | Tight coverage; SSH is critical so tested heavily |
| `checks/services.py` | 614 | 875 | 1.42× | Over-tested? Or service registry is genuinely complex |
| `checks/kernel_modules.py` | 501 | 920 | 1.84× | Heavily tested — Bug 1 fix (v0.4.6) added 5 tests on top |
| `domain_scores.py` | 343 | 855 | 2.49× | Scoring engine — critical, very tested |
| `cron.py` | 1201 | 382 (test_cron) + 344 (test_cron_audit) | 0.60× | **Under-tested for its size** — refactor candidate? |
| `manage_logs.py` | 999 | 882 | 0.88× | Curses UI — hard to test, decent coverage |
| `tui/cron.py` | 952 | (covered by test_cron) | low | **Under-tested** — same caveat as cron.py |

---

## Patterns & conventions (snapshot of "how the code is shaped")

### 1. Snapshot + check_xxx separation (every check follows this)

```python
@dataclass
class XxxSnapshot:
    field_a: str
    field_b: int

    @classmethod
    def from_system(cls) -> "XxxSnapshot":
        # ONLY place where subprocess.run() / open() happen
        return cls(field_a=..., field_b=...)


def check_xxx(snapshot: XxxSnapshot, t: TranslationFunc | None = None) -> CheckResult:
    # Pure logic — no system calls, fully testable
    _t = t if t is not None else _identity_t
    result = CheckResult()
    if snapshot.field_a == "bad":
        result.warn(message=_t("xxx.bad_a"), key="xxx.bad_a")
        result.add_deduction(reason=_t("xxx.bad_a"), points=1, key="xxx.bad_a")
    return result
```

> Note: 37 of 43 checks use positional `, t` as above. The 6 newer checks (`cron_audit`, `disk`, `file_perms`, `password_policy`, `services_state`, `user_accounts`) use keyword-only `, *, t`. Both forms are valid — the codebase is mid-convergence, no decision yet on which becomes canonical.

**Why it matters**: pulls the I/O side effects to a single function (`from_system`), making `check_xxx` deterministic for unit tests. **Do not break this contract during refactoring** — it's the foundation for the 4500-test suite running with no mocks.

### 2. Subprocess via `_run()` helper (every check uses this)

```python
from bob.checks._run import _run, _C_LOCALE_ENV

out = _run("ufw", "status", timeout=10)  # captures, no shell=True, no exception propagation
```

`_C_LOCALE_ENV` is required for any subprocess whose output is parsed with `strptime("%b ...")` (v0.4.3 lesson — `LC_TIME=fr_FR.UTF-8` broke month parsing).

### 3. `result.add_deduction(..., key=...)` mandatory

Every `add_deduction` and (where appropriate) every `warn/alert` carries a stable dotted `key=`. This is the contract for `--ignore`, audit profiles, JSON consumers, and `--explain` lookups. v0.4.2 fixed the last 4 missing keys (firewall.py); v0.4.3 + v0.4.4 covered the rest.

### 4. i18n via `t(key, **template_vars)`

```python
# Real example from bob/checks/ssh.py (a pilot since v0.4.1)
result.warn(
    message=_t("ssh.host_key_rsa_short", name=name, bits=hk.rsa_bits),
    key="ssh.host_key_rsa_short",
    template_vars={"name": name, "bits": hk.rsa_bits},   # pilot v0.4.1
)
```

`template_vars` is **additive** since v0.4.1 — three pilot checks (ssh, hardening, firewall) populate it. The remaining ~37 checks ship without it and rely on `message` being pre-rendered. **Phase 2 Option A** is to migrate all checks to set `template_vars`, enabling fully locale-independent JSON output. Deferred to v0.5.0+.

### 5. The active domain set (v0.4.6 fix)

```python
# bob/domain_scores.py::active_domains_from_engine
_actionable = (FindingLevel.OK, FindingLevel.WARN, FindingLevel.ALERT)  # v0.4.6: OK added
```

A domain enters the global score average as soon as any check emits `OK`, `WARN`, or `ALERT`. `INFO`-only domains intentionally stay hidden. **This filter changed in v0.4.6** to fix a scoring inversion after remediation (Bug 2): when `apt upgrade` resolved a WARN, the domain went from "WARN at 8/10" to "OK at 10/10", and the old filter dropped it from the average → score *decreased*. The new filter keeps the now-clean 10/10 in the denominator.

### 6. ScoreEngine usage contract

```python
engine = ScoreEngine()
engine.apply(check_result_1)
engine.apply(check_result_2)
engine.cap(maximum=3, key="firewall.inactive")  # optional per-domain cap
engine.finalize()                                # must come first
apply_domain_score_override(engine)              # then override global with domain average

score = engine.score        # int 0–10
level = engine.level        # RiskLevel.LOW / MEDIUM / HIGH / CRITICAL
```

**Critical ordering**: `finalize()` must run before `apply_domain_score_override()`. `engine.set_global_score()` should never be called directly — use the override helper.

---

## Frozen contracts (DO NOT BREAK)

### 1. JSON schema version `"1"`

`build_json_data(full=False)` and `build_json_data(full=True)` emit the contract documented in [`README_TECH.md` § JSON output schema](README_TECH.md). Within `schema_version="1"`:

- Top-level keys cannot disappear, be renamed, or change semantics
- New top-level keys MAY be added (clients ignore unknowns)
- Nested dicts follow the same rule
- Breaking changes bump to `"2"` (new major)

Top-level always-present keys: `schema_version`, `version`, `host`, `timestamp`, `score`, `score_max`, `risk`, `network_context`, `public_ip`, `alerts`, `warnings`, `deductions`, `domain_scores`.

`--json-full` additionally emits: `findings`, `services`, `open_ports`, `firewall_stack`, `hardening`, `ipv6`.

### 2. Exit codes (stable public API)

| Code | Constant | Meaning |
|---|---|---|
| `0` | `EXIT_OK` | Clean audit |
| `1` | `EXIT_WARNINGS` | Warnings present |
| `2` | `EXIT_ALERTS` | Alerts present |
| `3` | `EXIT_ERROR` | Technical error (CLI parsing, IO, internal) |
| `4` | `EXIT_TARGET_MISSED` | `--target N` specified, score < N |

Codes only added, never removed/renamed within a major. Exposed in `bob.__main__`.

### 3. EXPLAIN_KEYS (116 keys, 29 groups)

`bob.explain.EXPLAIN_KEYS` is a frozen canonical list. Adding a new key = additive (no breaking change). Renaming a key = breaking, must go through the alias map (`EXPLAIN_KEY_ALIASES`). Removing a key = major bump.

The `--explain KEY` interactive TUI shows: title, WHY it matters, HOW to fix, CIS reference. Every key has all 4 in **both** `en.json` and `fr.json` (validated by `test_locale_coverage.py::TestExplainNamespaceCoverage`).

### 4. 7 domain keys

`bob.domain_scores.DOMAINS`: `['ssh', 'samba', 'file_perms', 'updates', 'hardening', 'disk', 'firewall']`. These are stable JSON keys; the human labels (`'SSH'`, `'Samba Security'`, etc.) live in `LABELS` and may change.

### 5. 34 filterable section names (`--check` / `--skip`)

`bob --check=list` prints the canonical list. New sections may be added; renaming = breaking. Verified by `test_cli.py`.

### 6. services.json plugin schema v1

`bob/data/schemas/service.schema.json` + `services-list.schema.json` + `plugin-file.schema.json` (Draft 2020-12). User plugins at `~/.config/bob/services.d/*.json` are validated at load time. Schema bumps from v1 to v2 = breaking change with explicit migration path via the `plugin-file.schema.json` `schema_version` wrapper.

### 7. CIS references (137 entries)

`bob/data/cis_refs.json`: stable mapping from finding key → `{ref, code}`. Adding new refs = additive. Removing/renaming = breaking (clients matching on `code` would break).

---

## CLI surface — 35 options (alphabetical)

| Option | Section | Purpose |
|---|---|---|
| `--apply` | Remediation | Auto-confirm `--fix` (use with caution) |
| `--breakdown`, `-B` | Display | Show full score computation path |
| `--check=A,B,...` | Filters | Run only named sections |
| `--detailed`, `-d` | Audit | Write full report file (`~/.local/share/bob/logs/bob_*.log`) |
| `--diff` | Comparison | Show only baseline delta |
| `--explain=KEY`, `-e` | Inspection | Structured per-finding explanation; `--explain list` for all |
| `--fix`, `-f` | Remediation | Interactive fix mode with [y/N] prompts |
| `--format=FMT` | Output | `text` (default) / `json` / `json-full` / `csv` / `markdown` / `html` |
| `--french` | i18n | Force French; auto-detected from `$LANG` otherwise (shortcut for `--lang=fr`) |
| `--help`, `-h` | Misc | Print help and exit (no sudo required) |
| `--history` | Comparison | Sparkline of last scores |
| `--html` | Output | Standalone HTML export |
| `--ignore=KEY` | Filters | Persistently ignore a finding key |
| `--install-completion` | Setup | Install bash completion + sudo symlink |
| `--install-cron` | Automation | Cron wizard (curses TUI + plain fallback) |
| `--json`, `-j` | Output | JSON short form (alias for `--format=json`) |
| `--json-full`, `-J` | Output | JSON full form (alias for `--format=json-full`) |
| `--lang=CODE` | i18n | Force language (`en` / `fr`); else POSIX auto-detect |
| `--log-days=N`, `-l N` | Audit | UFW log analysis window (default 7) |
| `--manage-cron` | Automation | TUI to edit/delete cron jobs + email book |
| `--manage-logs` | Automation | TUI to list/preview/delete reports |
| `--min-level=LEVEL` | Filters | Hide findings below severity (`info`/`warn`/`alert`) |
| `--no-color`, `-n` | Output | Disable ANSI escapes |
| `--offline`, `-o` | Network | No outbound HTTP (public IP lookup + webhook off) |
| `--output-dir=PATH` | Audit | Override log dir for this run (non-persistent) |
| `--profile=NAME` | Audit | Apply profile (`server`/`desktop`/`container` + user) |
| `--quiet`, `-q` | Output | Suppress all output, use exit code |
| `--reconfigure`, `-r` | Setup | Re-run first-launch config wizard |
| `--reset-baseline` | Comparison | Wipe `last_baseline.json` |
| `--show-ignored` | Filters | List persistent ignore-list entries |
| `--skip=A,B,...` | Filters | Inverse of `--check` |
| `--target=N` | Audit | Score gate; exit code 4 if score < N |
| `--verbose`, `-v` | Output | Show detailed port exposure per service |
| `--version`, `-V` | Misc | Print version |
| `--watch=N` | Comparison | Re-run every N seconds |
| `--webhook=URL`, `-w` | Network | POST audit to webhook (Slack auto / generic) |
| `--webhook-format=FMT` | Network | Force webhook format (`auto`/`slack`/`generic`) |
| `--yes`, `-y` | Remediation | Auto-confirm all prompts |

> Note on `--check=list`: BOB has no separate `--list-checks` flag — pass `list` as the value of `--check` (`bob --check=list`) to print the 34 filterable section names. See `man bob(1)` for the full short-option table.

---

## File paths & env vars (external surface)

### Files (read/write at runtime)

| Path | Mode | Purpose | Lifecycle |
|---|---|---|---|
| `~/.config/bob/config.conf` | `0600` | User config (custom ports, log dir, suid_whitelist, email book, webhook defaults) | Created on first run; reconfigure with `--reconfigure` |
| `~/.config/bob/services.d/*.json` | r | User plugin services (extends `services.json`) | Created manually by user |
| `~/.config/bob/checks.d/*.py` | r | User plugin checks (Python files) | Created manually; NOT sandboxed (runs as root) |
| `~/.config/bob/profiles/*.conf` | r | User audit profiles | Created manually |
| `~/.config/bob/ignore.yml` | umask | Persistent ignore list — `path.write_text()` uses default mode (typically `0644`) | Built with `--ignore=KEY` |
| `~/.config/bob/last_baseline.json` | `0600` | Baseline for `--diff` | Auto-rewritten after each audit; `--reset-baseline` clears |
| `~/.config/bob/history.jsonl` | `0600` | Score history (rotates at 1000) | Append-only after each audit |
| `~/.config/bob/recurrence.json` | umask | Consecutive-audit finding counter — `tmp.open("w")` uses default mode (typically `0644`) | Updated each audit |
| `~/.local/share/bob/logs/bob_YYYYMMDD_HHMMSS.log` | `0600` | Detailed audit report (`-d`) — `os.open(..., 0o600)` | One per `-d` run; managed via `--manage-logs` |
| `/usr/local/bin/bob` | exec | Sudo PATH symlink to pipx venv binary | Created by `--install-completion` |
| `/etc/bash_completion.d/bob` | r | Bash completion script | Created by `--install-completion` |
| `/usr/local/bin/bob-{name}` | exec | Cron wrapper script | Created by `--install-cron` |
| `/etc/cron.d/bob-{name}` | r | Cron entry (system) | Created by `--install-cron`; managed by `--manage-cron` |

> When BOB runs under `sudo`, all writes to `~/.config/bob/` are auto-`chown`-ed back to `$SUDO_USER` (since v0.3.6).

### Environment variables

| Var | Effect |
|---|---|
| `BOB_SHARE` | Override package data dir (locales/, data/) — for distro packaging (`/usr/share/bob/`) |
| `UFW_AUDIT_SHARE` | Legacy alias, pre-v0.4.2 — kept for compat. `BOB_SHARE` takes precedence if both set |
| `SUDO_USER` | Auto-detected — controls config path resolution and chown-back |
| `LC_ALL` / `LC_MESSAGES` / `LANG` | POSIX locale detection (`fr_*` → French, else English fallback) |
| `LC_TIME` | Subprocess locale via `_C_LOCALE_ENV` to avoid `strptime` regressions (v0.4.3 fix) |
| `NO_COLOR` | Honors the [NO_COLOR](https://no-color.org/) standard |

---

## Tests-to-source mapping (~80 test files cover ~80 modules)

Naming convention: `tests/test_<module_basename>.py` mirrors `bob/<module>.py` or `bob/checks/<module>.py`. Some shared tests:

| Test file | Covers |
|---|---|
| `test_scoring.py` | `bob/scoring.py` (engine, Finding, Deduction, FindingLevel) |
| `test_domain_scores.py` | `bob/domain_scores.py` + active set + TestActiveDomainsIncludesOK (v0.4.6) |
| `test_breakdown.py` | `bob/breakdown.py` (score transparency display) |
| `test_golden_scenarios.py` | End-to-end scoring scenarios (32 fixtures from v0.3.0) |
| `test_json_schema.py` | JSON output contract — frozen + drift detection |
| `test_services_schema.py` | Plugin services JSON Schema (Draft 2020-12) |
| `test_locale_coverage.py` | All `t()`/`_t()` keys exist in both `en.json` and `fr.json` (AST-based since v0.4.5) |
| `test_template_vars_migration.py` | Phase 2 migration debt visibility (v0.4.2) |
| `test_compare.py` | Baseline + delta logic |
| `test_correlation.py` | 6 compound-risk rules |
| `test_recurrence.py` | Consecutive-audit counter |
| `test_exit_codes.py` | Exit code public API |
| `test_explain.py` | EXPLAIN_KEYS, alias map, freeze policy |
| `test_cis_refs.py` | 137 CIS references mapping |
| `test_degraded.py` | Graceful behavior when `ss` / `iptables` / `journalctl` absent |
| `test_html_output.py`, `test_csv_output.py`, `test_markdown_output.py` | Output formatters |
| `test_webhook.py` | Generic + Slack payload, `--offline` strict mode |
| `test_formatter.py` | Locale-independent reconstruction via `template_vars` (v0.4.1) |

---

## Architectural decisions (active, do not undo without discussion)

### Kept

- **Audit-only by default** (no auto-fix without explicit `--fix --apply`). Foundational security stance.
- **Zero runtime deps outside stdlib**. Atout énorme for distro packaging; preserve at all costs.
- **Snapshot + check_xxx separation**. Enables 4500 tests with no mocks.
- **Equal-domain weighting** in global score. All active domains contribute equally — intentional, retained through v0.4.x. The "main architectural question for v0.3.0" was answered: keep equal weighting.
- **JSON schema_version="1"** frozen since v0.4.0. Any breaking change = `"2"` + major bump.
- **EXPLAIN_KEYS frozen** with alias map for renames. 116 keys as of v0.4.6.
- **`OK` in active domain set** (Bug 2 fix in v0.4.6). `INFO`-only domains stay hidden by design — terrain-validated boundary.

### Discarded (do not re-attempt)

- **M7 — Lazy `_PLUGIN_DIR` resolution.** Attempted in v0.4.3, broke 20 tests that patch `bob.registry._PLUGIN_DIR`. The "SUDO_USER changes mid-process" scenario doesn't happen in practice (BOB is one-shot per audit). Decision **permanent** (figée 2026-05-15).

### Deferred to v0.5.0+

- **Phase 2 Option A — full `Finding.template_vars` migration** on the ~37 non-pilot checks. Currently `template_vars` is additive on 3 pilots (ssh, hardening, firewall). Full migration would allow `Finding.message` to be derived from `(key, template_vars)` entirely, enabling locale-independent JSON output. **Largest single chunk of refactor work pending.**
- **M3 cosmetic** — `os.path` → `pathlib` in 4 files (`manage_logs.py`, `suid_audit.py`, `secure_boot.py`, `ssh.py`). Pure cosmetic.
- **AUR PKGBUILD** — community contribution welcome.
- **Tighter AppArmor lock-down** — read-only on /etc/, /proc/, /sys/; deny exec of non-whitelisted; restrict network egress to known endpoints. Deferred to a future hardening pass.

### Known dette

- `bob/cron.py` (1201 LoC) is the biggest non-check file with the lowest tests/source ratio. Refactor candidate but works.
- `bob/checks/ssh.py` (1392 LoC) is the biggest check — handles many sshd_config directives. Possible split by concern (sshd_config vs key audit vs known_hosts).
- `bob/manage_logs.py` + `bob/tui/cron.py` (~2000 LoC combined of curses code) — UI heavy, low tests/source ratio for the curses parts. Hard to test, accept the coverage gap or invest in fixture infra.
- `bob/runner.py` `_sec()` closure pattern works but adds an extra layer of indirection. Was a refactor in v0.3.5 (-295L from previous form). Could potentially flatten further, but not urgent.

---

## CI matrix (validated cross-distro on every PR)

`.github/workflows/integration.yml` runs BOB inside containers of:
- Debian 12 (bookworm), Debian 13 (trixie)
- Ubuntu 22.04, 24.04, 25.04
- Kali Rolling
- Fedora 41

Each job asserts: exit code ≤ 3, no locale sentinel keys `[xxx.yyy]`, no Python tracebacks. Shipped 2026-05-17, currently 7/7 green.

`.github/workflows/tests.yml` runs the full pytest suite on Python 3.10 / 3.11 / 3.12 / 3.13 (matching the support policy declared in `pyproject.toml` classifiers).

`.github/workflows/publish.yml` triggers on `v*` tag push: full tests + sdist/wheel build + PyPI publish via Trusted Publishing (OIDC, no token).

---

## Quick references

- **Add a service**: edit `bob/data/services.json` (32 entries, schema in `bob/data/schemas/`). No Python code change. See [README_DEV.md § Adding a service](README_DEV.md).
- **Add a language**: copy `bob/locales/en.json` → `bob/locales/de.json`, translate all 1401 values keeping the exact key tree, then append `"de"` to `SUPPORTED_LANGS` in `bob/i18n.py` (currently `("en", "fr")`). `cli.py` itself does not whitelist languages — `--lang=` accepts any value and `i18n.init()` falls back to `DEFAULT_LANG` if the file is missing.
- **Add a check**: create `bob/checks/foo.py` with `FooSnapshot.from_system()` + `check_foo(snapshot, t)`. Wire in `bob/runner.py` via `_sec("foo", foo_snapshot, check_foo)`. Add test `tests/test_foo.py`. Optional: add prefix `"foo"` to `bob/domain_scores.py::_PREFIX_TO_DOMAIN`.
- **Add an explain key**: append to `EXPLAIN_KEYS` in `bob/explain.py` + write title/why/how/CIS in both `en.json` and `fr.json`. `test_locale_coverage.py::TestExplainNamespaceCoverage` enforces parity.
- **Bump a version** — files to touch (verified `grep -l "0.4.6"`):
  - **Source/build** : `bob/__init__.py::__version__` · `pyproject.toml::version` · 3 schema `$id` URLs in `bob/data/schemas/*.schema.json`
  - **READMEs (ASCII banners)** : `README.md` · `README_FR.md` · `DOCUMENTS/README_TECH.md` · `DOCUMENTS/README_TECH_FR.md`
  - **shields.io badges** : `DOCUMENTS/README_TECH.md` and `DOCUMENTS/README_TECH_FR.md` (`![Release](https://img.shields.io/badge/version-vX.Y.Z-...`)
  - **Changelogs (short + full, EN + FR — 4 files)** : `CHANGELOG.md` · `CHANGELOG_FR.md` · `DOCUMENTS/CHANGELOG_FULL.md` · `DOCUMENTS/CHANGELOG_FULL_FR.md`
  - **Test journal** : `DOCUMENTS/TESTING.md` and `DOCUMENTS/TESTING_FR.md` (new release row + section)
  - **Man pages `.TH` lines (3 files)** : `man/bob.1` · `man/bob.conf.5` · `man/bob-profile.5`
  - **Distro packaging** : `debian/changelog` · `packaging/rpm/bob.spec` (`Version:` field)
  - Then `git tag vX.Y.Z && git push --tags` triggers PyPI publish via OIDC.

---

## Numbers at a glance

| Metric | Value | Source |
|---|---:|---|
| Python source (bob/) | 28,382 LoC | `wc -l bob/*.py bob/checks/*.py bob/tui/*.py` |
| Tests | 34,663 LoC across 84 files, 3973 functions, **4500 collected** | `wc -l tests/test_*.py` + `pytest --collect-only -q` |
| Runtime deps outside stdlib | **0** | `pyproject.toml` |
| Optional runtime deps | `geoip2` (IP geolocation) | `pipx inject bodyguard-of-bits geoip2` |
| Distro CI matrix | 7 distros | `.github/workflows/integration.yml` |
| Python versions tested | 3.10, 3.11, 3.12, 3.13 | `.github/workflows/tests.yml` |
| Locale keys | 1401 EN ↔ 1401 FR | `bob/locales/{en,fr}.json` |
| EXPLAIN_KEYS | 116 (in 29 groups) | `bob.explain.EXPLAIN_KEYS` |
| CIS references | 137 (99 Ubuntu 22.04 + 4 Docker + 34 best-practice) | `bob/data/cis_refs.json` |
| Known services | 32 | `bob/data/services.json` |
| Score domains | 7 | `bob.domain_scores.DOMAINS` |
| Filterable sections (`--check` / `--skip`) | 34 | `bob --check=list` |
| Audit profiles | 4 built-in (server / desktop / container + workstation alias) + user | `bob/data/profiles/` |
| CLI options | ~35 | `bob.cli.parse_args` |
| Doc files | 16 public markdown + 3 man pages | `DOCUMENTS/` + `man/` |
| Public version | v0.4.6 | `pyproject.toml::version` |
| First release | v0.1.0 (2026-04-26) | `CHANGELOG.md` |

---

© 2026 Cédric Clauzel
