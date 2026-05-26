# BOB — Project snapshot

> **Purpose.** A single-page bird's-eye view of the codebase as of **v0.6.0** (2026-05-25, refreshed from the v0.4.6 baseline). Designed to be loaded once before a refactor pass or an audit so you don't have to re-discover the structure module by module. Stats are derived from the actual source files; conventions and contracts are observable in the code, not aspirational.

> **Snapshot history.** v0.4.6 → v0.6.0 drift, in one paragraph: the v0.5.x branch ran a deep-audit campaign on 25 modules + ~25 spot-checks (4 phases of refactor v0.5.0–v0.5.4, then 4 hardening releases v0.5.5–v0.5.8), introduced `CheckResult.{warn,alert}_with_deduction` helpers (~120 call sites migrated, net −519 LoC across `bob/checks/*.py`), unified private-IP detection to `sysinfo._is_private_or_loopback_ipv4/_ipv6`, added the `_atomic_write(path, content, mode=)` contract with explicit mode parameter, split `_BadDirective` / `_LEVEL_DISPATCH` declarative tables, and added AST-based locale parity tests. **v0.6.0** then landed two architectural splits: `bob/checks/ssh.py` (1296 L monolith) → `bob/checks/ssh/` package with 4 submodules, `bob/cron.py` (1204 L monolith) → `bob/cron/` package with 4 submodules — both contract-preserving via `__init__.py` re-exports. The `UFW_AUDIT_SHARE` legacy env var was removed (deprecation chain v0.4.2 → v0.5.4 → v0.6.0). See `DOCUMENTS/CHANGELOG_FULL.md` for the full per-release breakdown.

---

## One-screen view

```
┌─────────────────────────────────────────────────────────────────────────┐
│  bob v0.6.0     ~28 kLoC Python · 0 runtime deps outside stdlib         │
│                 4583 unit tests · 16 doc files · 7 distros CI-validated │
└─────────────────────────────────────────────────────────────────────────┘

LAYER (top→bottom = imports flow down)

    bob/__main__.py  ← orchestrator (411 L)
        │
        ├──► bob/cli.py             ← AuditConfig + parse_args() (662 L)
        ├──► bob/runner.py          ← run_checks(), _sec closure (628 L)
        ├──► bob/scoring.py         ← ScoreEngine + Finding + Deduction
        ├──► bob/domain_scores.py   ← per-domain averaging, 7 domains
        │                              (called AFTER run_checks via
        │                               apply_domain_score_override)
        ├──► bob/sysinfo.py         ← collect_system_info, network ctx
        └──► bob/{display,i18n,output,history,...}  (direct output-layer
                                                     imports — see grep
                                                     `^from bob\.` for
                                                     the full ~17 deps)
             (bob/report.py is *not* a direct import of __main__ —
              accessed via runner.init_report's return value)

    bob/runner.py
        │
        ├──► bob/cli.py        (AuditConfig type hint)
        ├──► bob/config.py     (UserConfig)
        ├──► bob/profiles.py   (server/desktop/container + user)
        ├──► bob/scoring.py    (ScoreEngine)
        └──► bob/checks/*.py   (43 check modules — ssh is a sub-package since v0.6.0)

    bob/checks/*.py  ← 43 check modules · Snapshot+check_xxx pattern
        │  ├ firewall/firewall_stack/network_context/ports/services/logs/ddns  (network — 7)
        │  ├ docker / docker_audit              (containers — 2)
        │  ├ ssh / file_perms / suid_audit / user_accounts / password_policy / umask  (access — 6)
        │  ├ hardening / kernel_hardening / kernel_modules / mac_policy / secure_boot  (kernel — 5)
        │  ├ updates / firmware / cron_audit / services_state             (system — 4)
        │  ├ disk / memory / backup                                       (hardware — 3)
        │  ├ auditd / file_integrity / rootkit / clamav / fail2ban / auth_log  (security tools — 6)
        │  └ ssl_certs / systemd_timers / ntp / desktop_apps / virtualization / samba / smtp / iptables_nftables / ipv6 / log_rotation  (misc — 10)
        │  Total: 7+2+6+5+4+3+6+10 = 43 ✓
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
    EXPLAIN_KEYS                  ← 116 keys in 32 groups, frozen alias map
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
│   ├── runner.py              ← run_checks(), 628 L, _sec closure (34 sections)
│   ├── cli.py                 ← parse_args() + AuditConfig, 662 L
│   ├── config.py              ← UserConfig, EmailStore, ~/.config/bob/
│   ├── profiles.py            ← audit profile loader (3 built-in + user)
│   ├── scoring.py             ← ScoreEngine, Finding, Deduction, FindingLevel, warn_with_deduction/alert_with_deduction (v0.5.x)
│   ├── domain_scores.py       ← 7-domain attribution, active set, capping
│   ├── checks/                ← 43 check modules, see Module index below
│   │   └── ssh/               ← split package since v0.6.0 (was 1296 L monolith)
│   │       ├── __init__.py    ← public re-exports for backwards-compat (64 L)
│   │       ├── _directives.py ← _BadDirective table + _BAD_DIRECTIVES + _WEAK_* sets (165 L)
│   │       ├── _snapshot.py   ← 5 dataclasses + SSHSnapshot + from_system (198 L)
│   │       ├── _parsers.py    ← pure parsers, key-type helpers, collect_host_keys (446 L)
│   │       └── _subchecks.py  ← check_ssh entry point + per-area _check_* helpers (529 L)
│   ├── cron/                  ← split package since v0.6.0 (was 1204 L monolith)
│   │   ├── __init__.py        ← public re-exports incl. datetime + _EMAIL_RE (101 L)
│   │   ├── _parse.py          ← CronEntry + parsing + listing + validators + MTA + constants (330 L)
│   │   ├── _io.py             ← _atomic_write + build_script_content + apply_cron_* (164 L)
│   │   ├── _install.py        ← prompt_emails/prompt_email + plain wizard + run_install_cron (319 L)
│   │   └── _manage.py         ← edit_cron_email/schedule + plain wizard + run_manage_cron (445 L)
│   ├── tui/                   ← optional curses subpackage (v0.4.1 extraction)
│   │   ├── __init__.py
│   │   └── cron.py            ← curses wizard for --install-cron / --manage-cron (946 L)
│   ├── display.py             ← terminal output helpers, 815 L
│   ├── output.py              ← low-level terminal primitives, 630 L
│   ├── panorama.py            ← services panorama table builder
│   ├── breakdown.py           ← --breakdown score computation transparency
│   ├── exposure.py            ← attack-surface table (compute_exposure)
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
│   ├── manage_logs.py         ← --manage-logs curses TUI (1040 L)
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
│   ├── sysinfo.py             ← system info, network context, get_user_home(), _is_private_or_loopback_ipv4/_ipv6 (single source of truth since v0.5.x)
│   ├── _paths.py              ← BOB_SHARE resolution (UFW_AUDIT_SHARE removed in v0.6.0)
│   └── _tty.py                ← raw-mode line reader + prompt_wizard() (Esc-to-cancel)
├── tests/                     ← 86 test files, 4056 test functions, 4583 collected
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

## Module index — bob/ root (37 modules) + bob/cron/ + bob/checks/ssh/ + bob/tui/cron.py

| Module | LoC | Role |
|---|---:|---|
| `__main__.py` | 411 | Orchestrator: argv → AuditConfig → snapshots → run_checks() → display |
| `runner.py` | 628 | Audit engine: `run_checks()`, `_sec` closure factory (34 sections), `_section_enabled()` |
| `cli.py` | 662 | `parse_args()`, `AuditConfig` dataclass, `--help` text, CLIError |
| `config.py` | — | `UserConfig` (key/value config store) + `EmailStore` (email book) + `get_suid_whitelist()` accessor. Interactive prompts live in `manage_logs.py`, not here. |
| `profiles.py` | — | Profile loader: server/desktop/container + ~/.config/bob/profiles/*.conf |
| `scoring.py` | — | `ScoreEngine`, `Finding`, `Deduction`, `FindingLevel`, `ScoreCap` |
| `domain_scores.py` | 350 | `compute_domain_scores()`, `active_domains_from_engine()`, `apply_domain_score_override()` — 7 domains; `_PREFIX_TO_DOMAIN` explicit mapping (32 prefixes since v0.5.x, fail2ban→ssh / virt→hardening / docker_audit→hardening now mapped) |
| `explain.py` | 741 | `--explain` TUI + `EXPLAIN_KEYS` (116 keys, 32 groups) + alias map (additive layer for service-state migration) |
| `cis_refs.py` | — | CIS lookup with `lru_cache(maxsize=1)`, reads `data/cis_refs.json` (137 entries) |
| `display.py` | 815 | Terminal output: section boxes, finding emission, summary box, score bar; `_LEVEL_DISPATCH` table + `print_audit_summary` split into 3 helpers (v0.5.x) |
| `output.py` | 630 | Low-level primitives: `print_ok/warn/alert/info/section/banner` |
| `panorama.py` | — | Services panorama table builder (after-audit summary) |
| `breakdown.py` | — | `--breakdown` / `-B` score computation transparency display |
| `exposure.py` | — | `compute_exposure()` — attack-surface table for the audit summary (synthesises firewall state + ports + network context + finding keys) |
| `formatter.py` | — | `format_finding()`, `format_deduction()` — locale-independent via `template_vars` |
| `i18n.py` | — | `t(key, **vars)`, locale auto-detect (POSIX), 1401 keys EN/FR |
| `compare.py` | — | `AuditBaseline`, `AuditDelta`, `build_baseline()`, `compute_delta()`, `display_delta()` |
| `correlation.py` | — | 6 compound-risk rules (`CorrelationRule` with frozensets) |
| `recurrence.py` | — | Recurring finding tracker: consecutive-audit counters |
| `history.py` | — | `--history` sparkline, JSONL append at `~/.config/bob/history.jsonl`, rotate@1000 |
| `ignore.py` | — | Persistent ignore list `~/.config/bob/ignore.yml` |
| `fixes.py` | — | `--fix` interactive UI with [y/N] prompts |
| `cron/` (package) | **1359** | Split in v0.6.0 from 1204 L monolith. `__init__.py` (101) re-exports the public surface incl. `datetime` + `_EMAIL_RE` · `_parse.py` (330) CronEntry + parsing + validators + MTA detection + day helpers · `_io.py` (164) `_atomic_write` + `build_script_content` + `apply_cron_schedule` / `apply_cron_email` · `_install.py` (319) prompt_emails/prompt_email + plain wizard + `run_install_cron` · `_manage.py` (445) `_manage_email_store` + edit_cron_email/schedule + plain wizard + `run_manage_cron` |
| `tui/cron.py` | 946 | Curses TUI for `--install-cron` / `--manage-cron`; `_Schedule(IntEnum)` (DAILY/WEEKDAYS/MONTHDAYS/CUSTOM) + `_is_printable_input_char` helper (v0.5.x) |
| `manage_logs.py` | 1040 | `--manage-logs` curses TUI with score history chart; `_is_finding_continuation` helper + 3 bare `input()` now catch EOFError (v0.5.x) |
| `completion.py` | — | `--install-completion` → writes `/etc/bash_completion.d/bob` |
| `webhook.py` | — | Generic JSON / Slack payload + send (10s timeout) |
| `watch.py` | — | `--watch=N` live monitoring loop |
| `plugin_checks.py` | — | `PluginCheck`, size-limited + ANSI-sanitized user plugin loader |
| `registry.py` | — | `ServiceRegistry.load()`: bundle services.json + ~/.config/bob/services.d/ |
| `report.py` | — | `AuditReport` + `NullReport`, immediate flush, ASCII art header. `NullReport` is the canonical Protocol type since v0.5.x (`bob/watch.py:_NullReport` removed) |
| `report_markdown.py` | 777 | `MarkdownReport` + `send_html_email()` (multipart/alternative); XSS fix in `_safe_url` (html.escape with quote=True, v0.5.x) |
| `json_output.py` | — | `build_json_data()` (short + full mode), `schema_version="1"` |
| `csv_output.py` | — | `--format csv` formatter |
| `html_output.py` | — | `build_html_output()` standalone HTML (no JS, XSS-safe) |
| `markdown_output.py` | — | `--format markdown` formatter |
| `sysinfo.py` | 259 | `collect_system_info()`, `detect_network_context()`, `get_user_home()` (sudo-aware); `_is_private_or_loopback_ipv4/_ipv6` single source of truth since v0.5.x |
| `_paths.py` | 53 | `resolve_share_dir()`: BOB_SHARE only — `UFW_AUDIT_SHARE` legacy alias **removed in v0.6.0** after the v0.4.2 → v0.5.4 deprecation chain |
| `_tty.py` | 113 | `read_line(prompt) → str|None`, Esc returns None, TTY fallback to input(); `prompt_wizard()` helper added v0.5.x |
| `config.py` | 371 | Adds `bob.config._EMAIL_RE` single source of truth (v0.5.x) |

## Module index — bob/checks/ (43 checks)

> All but one follow the same shape: `XxxSnapshot.from_system()` collects raw data (only place with subprocess calls); `check_xxx(snapshot, t)` is pure logic, testable without mocks. **Exception: `services.py`** — `ServiceSnapshot` uses `.collect(registry, ufw_rules=..., ...)` / `.collect_all(registry, ...)` instead of `from_system()`, because it builds one snapshot *per service* from a registry rather than one snapshot of system-wide state. The active domain for each check is decided by `domain_scores._PREFIX_TO_DOMAIN`.

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
| `logs.py` | 726 | hardening | UFW log analysis, brute-force, top IPs (GeoIP optional); hand-rolled private-IP regex retired — now delegates to `sysinfo._is_private_or_loopback_ipv4/_ipv6` (v0.5.6) |
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
| `kernel_modules.py` | 481 | hardening | risky modules + apt kernel updates + installed listing (dpkg `ii` filter since v0.4.6) |
| `mac_policy.py` | — | hardening | AppArmor / SELinux state, 0-profile case |
| `updates.py` | 359 | updates | `apt-get -s dist-upgrade`, stale cache, cross-check (since v0.4.4); cache-age INFO option C when no security/regular finding (v0.5.3+) |
| `ssh/` (package) | **1402** | ssh | **Split in v0.6.0** from 1296 L monolith. `__init__.py` (64) re-exports for backwards-compat · `_directives.py` (165) `_BadDirective` + `_BAD_DIRECTIVES` + `_apply_bad_directive` + `_WEAK_*` · `_snapshot.py` (198) 5 dataclasses (HostKeyInfo, PrivateKeyInfo, AuthorizedKeyEntry, KnownHostEntry, ClientConfigEntry) + SSHSnapshot · `_parsers.py` (446) pure parsers + RSA-bits + collect_host_keys + install probe · `_subchecks.py` (529) `check_ssh` + all `_check_*` helpers |
| `file_perms.py` | — | file_perms | /etc/passwd, /etc/shadow, sudoers, SSH host keys |
| `suid_audit.py` | — | hardening | SUID/SGID with whitelist (config.conf), targeted-roots scan |
| `user_accounts.py` | — | file_perms | UID 0 non-root, empty passwords, expired accounts |
| `password_policy.py` | — | hardening | PAM pam_pwquality/pam_cracklib, PASS_MAX_DAYS, login.defs |
| `umask.py` | — | hardening | login.defs, common-session, profile, current process |
| `cron_audit.py` | — | hardening | Pipe-to-shell (`curl/wget \| sh`), world-writable scripts, unexpected users with root crontabs. The cron *range* validator (`_validate_custom_cron`) lives in `bob/cron/_parse.py`, not here. |
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

> Since v0.6.0, the two former 1k+ L monoliths (`bob/checks/ssh.py`, `bob/cron.py`) are split packages. The biggest *single file* is now the curses TUI at 1040 L.

| LoC | File | Hotspot reason |
|---:|---|---|
| 1040 | `bob/manage_logs.py` | Full curses TUI: list + preview + score chart + multi-directory view |
| 946 | `bob/tui/cron.py` | Curses TUI for cron wizards (extracted v0.4.1) |
| 815 | `bob/display.py` | Renders all sections + risk context blocks + summary box |
| 777 | `bob/report_markdown.py` | Markdown report + HTML email (MIME multipart) |
| 741 | `bob/explain.py` | EXPLAIN_KEYS (116) + alias map + interactive TUI |
| 726 | `bob/checks/logs.py` | UFW log parser + bruteforce + GeoIP + IoT detection |
| 662 | `bob/cli.py` | `parse_args()` covers ~40 options |
| 630 | `bob/output.py` | Low-level terminal primitives (grew with v0.5.x helpers) |
| 628 | `bob/runner.py` | `_sec()` closure + 34 section invocations |
| 598 | `bob/checks/services.py` | 32 services × detection paths × risk classification |
| 548 | `bob/scoring.py` | ScoreEngine + Finding + Deduction + `{warn,alert}_with_deduction` helpers (v0.5.x) |
| 529 | `bob/checks/ssh/_subchecks.py` | Biggest submodule of the ssh/ package (check_ssh + per-area helpers) |

> The biggest *split package* totals: `bob/checks/ssh/` at 1402 L (across 5 files, largest sub 529) and `bob/cron/` at 1359 L (across 5 files, largest sub 445). Both are net-larger than the pre-split monolith because the split added docstrings and re-export boilerplate, but per-file LoC is now well under the 1000-L soft ceiling.

### Biggest test files (top 10)

| LoC | File | Coverage focus |
|---:|---|---|
| 1108 | `tests/test_manage_logs.py` | curses TUI flows (heavy fixturing) |
| 1022 | `tests/test_ssh.py` | sshd_config + host keys + user keys (covers the new ssh/ package via re-exports) |
| 920 | `tests/test_kernel_modules.py` | risky modules + apt kernel + dpkg ii filter (v0.4.6) |
| 875 | `tests/test_services.py` | 32 services × detection paths × risk classification |
| 855 | `tests/test_domain_scores.py` | per-domain attribution + ScoreCap + TestActiveDomainsIncludesOK (v0.4.6) |
| 848 | `tests/test_cron.py` | massive growth post-split (was 382 L) — covers cron/ package via re-exports + new helpers |
| 807 | `tests/test_logs.py` | UFW log parser + bruteforce + IoT dominance |
| 741 | `tests/test_cli.py` | argv parsing + AuditConfig + alias maps |
| 699 | `tests/test_profiles.py` | profile inheritance + overrides + extends chain |
| 681 | `tests/test_samba.py` | SMBv1 + signing + map-to-guest + bind interfaces |
| 635 | `tests/test_explain.py` | EXPLAIN_KEYS + alias + freeze policy |

### Tests-to-code ratio (rough proxy for risk)

| Check / module | Source LoC | Test LoC | Ratio | Verdict |
|---|---:|---:|---:|---|
| `checks/ssh/` (package) | 1402 | 1022 | 0.73× | Tight coverage; SSH is critical so tested heavily. Post-v0.6.0 split, the test file still exercises the public `check_ssh` surface via `bob.checks.ssh.__init__` re-exports — no test churn needed |
| `checks/services.py` | 598 | 875 | 1.46× | Over-tested? Or service registry is genuinely complex |
| `checks/kernel_modules.py` | 481 | 920 | 1.91× | Heavily tested — Bug 1 fix (v0.4.6) added 5 tests on top |
| `domain_scores.py` | 350 | 855 | 2.44× | Scoring engine — critical, very tested |
| `cron/` (package) | 1359 | 848 (test_cron) + 344 (test_cron_audit) | 0.88× | **Refactor done (v0.6.0)** — was 0.60× before split. test_cron jumped from 382 → 848 L during the v0.5.x → v0.6.0 cycle as the now-modular surface became easier to target |
| `manage_logs.py` | 1040 | 1108 | 1.07× | Curses UI — hard to test, but test_manage_logs grew significantly (882 → 1108) through the v0.5.x audit |
| `tui/cron.py` | 946 | (covered by test_cron) | low | **Still under-tested** — soft-ceiling candidate remaining after v0.6.0 splits; curses code dominates |

---

## Patterns & conventions (snapshot of "how the code is shaped")

### 1. Snapshot + check_xxx separation (every check follows this — except `services.py`, see notes in the check index)

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
        # v0.5.x: prefer the fused helper instead of warn() + add_deduction() pair
        result.warn_with_deduction(
            message=_t("xxx.bad_a"), key="xxx.bad_a", points=1,
        )
    return result
```

> Note: 37 of 43 checks use positional `, t` as above. The 6 newer checks (`cron_audit`, `disk`, `file_perms`, `password_policy`, `services_state`, `user_accounts`) use keyword-only `, *, t`. Both forms are valid — the codebase is mid-convergence, no decision yet on which becomes canonical.
>
> Note (v0.5.x): `CheckResult.warn_with_deduction()` and `.alert_with_deduction()` fuse the two-step `warn/alert(...) + add_deduction(...)` pattern into a single call. ~120 sites in `bob/checks/*.py` were migrated during the v0.5.0–v0.5.4 refactor (net −519 LoC). The two-step pattern still works (additive change), but new code should use the fused helpers.

**Why it matters**: pulls the I/O side effects to a single function (`from_system`), making `check_xxx` deterministic for unit tests. **Do not break this contract during refactoring** — it's the foundation for the 4583-test suite running with no mocks.

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
# Real example from bob/checks/ssh/_subchecks.py (a pilot since v0.4.1; package split v0.6.0)
result.warn(
    message=_t("ssh.host_key_rsa_short", name=name, bits=hk.rsa_bits),
    key="ssh.host_key_rsa_short",
    template_vars={"name": name, "bits": hk.rsa_bits},   # pilot v0.4.1
)
```

`template_vars` is **additive** since v0.4.1 — three pilot checks (ssh, hardening, firewall) populate it. The remaining 40 checks ship without it and rely on `message` being pre-rendered. **Phase 2 Option A** is to migrate all checks to set `template_vars`, enabling fully locale-independent JSON output. Deferred to v0.5.0+.

### 5. The active domain set (v0.4.6 fix)

```python
# bob/domain_scores.py::active_domains_from_engine
_actionable = (FindingLevel.OK, FindingLevel.WARN, FindingLevel.ALERT)  # v0.4.6: OK added
```

A domain enters the global score average as soon as any check emits `OK`, `WARN`, or `ALERT`. `INFO`-only domains intentionally stay hidden. **This filter changed in v0.4.6** to fix a scoring inversion after remediation (Bug 2): when `apt upgrade` resolved a WARN, the domain went from "WARN at 8/10" to "OK at 10/10", and the old filter dropped it from the average → score *decreased*. The new filter keeps the now-clean 10/10 in the denominator.

### 6. ScoreEngine usage contract

```python
engine = ScoreEngine()
engine.apply(check_result_1)   # CheckResult may carry ScoreCap(s) via result.set_cap(...)
engine.apply(check_result_2)
engine.finalize()              # processes any caps registered, must come first
apply_domain_score_override(engine)  # then override global with domain average

score = engine.score           # int 0–10
level = engine.level           # RiskLevel.LOW / MEDIUM / HIGH / CRITICAL
```

> Caps are global ceilings (not per-domain) and are typically attached to a `CheckResult` from inside the check via `result.set_cap(maximum=N, reason=..., key="...")` — see `bob/checks/firewall.py:173` where firewall-inactive caps the global score at 3. `engine.cap(...)` exists too but is discouraged in orchestrators because it scatters cap logic away from the check.

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

`--json-full` additionally emits: `findings`, `services`, `open_ports`, `firewall_stack` (always when full=True), plus `hardening` and `ipv6` (only when the respective `hardening_snapshot` / `ipv6_snapshot` parameters are passed to `build_json_data` — in practice via the normal audit path, both are present, but unit-test callers may pass `None`). **Caveat**: in `--json-full`, `network_context` changes type from a string (`"public"` / `"private"`) to a richer dict containing `interfaces` (list of interface objects). Clients that read `network_context` from `--json` and `--json-full` interchangeably need to type-check first.

### 2. Exit codes (stable public API)

| Code | Constant | Meaning |
|---|---|---|
| `0` | `EXIT_OK` | Clean audit |
| `1` | `EXIT_WARNINGS` | Warnings present |
| `2` | `EXIT_ALERTS` | Alerts present |
| `3` | `EXIT_ERROR` | Technical error (CLI parsing, IO, internal) |
| `4` | `EXIT_TARGET_MISSED` | `--target N` specified, score < N |

Codes only added, never removed/renamed within a major. Exposed in `bob.__main__`.

### 3. EXPLAIN_KEYS (116 keys, 32 groups)

`bob.explain.EXPLAIN_KEYS` is a frozen canonical list. Adding a new key = additive (no breaking change). Renaming a key = breaking, must go through the alias map (`EXPLAIN_KEY_ALIASES`). Removing a key = major bump.

The `--explain KEY` interactive TUI shows: **title**, **WHY** it matters, **HOW** to fix, and a **CIS reference**. The first three (title/why/how) live in `en.json` and `fr.json` under `explain.{key}.{title,why,how}` and are validated for cross-locale parity by `test_locale_coverage.py::TestExplainNamespaceCoverage`. The CIS reference is sourced separately from `bob/data/cis_refs.json` (137 entries) via `bob/cis_refs.py::get_cis_ref(key)` — not stored in the locale files.

### 4. 7 domain keys

`bob.domain_scores.DOMAINS`: `['ssh', 'samba', 'file_perms', 'updates', 'hardening', 'disk', 'firewall']`. These are stable JSON keys; the human labels (`'SSH'`, `'Samba Security'`, etc.) live in `LABELS` and may change.

### 5. 34 filterable section names (`--check` / `--skip`)

`bob --check=list` prints the canonical list. New sections may be added; renaming = breaking. Verified by `test_cli.py`.

### 6. services.json plugin schema v1

`bob/data/schemas/service.schema.json` + `services-list.schema.json` + `plugin-file.schema.json` (Draft 2020-12). User plugins at `~/.config/bob/services.d/*.json` are validated at load time. Schema bumps from v1 to v2 = breaking change with explicit migration path via the `plugin-file.schema.json` `schema_version` wrapper.

### 7. CIS references (137 entries)

`bob/data/cis_refs.json`: stable mapping from finding key → `{ref, code}`. Adding new refs = additive. Removing/renaming = breaking (clients matching on `code` would break).

---

## CLI surface — ~40 options (alphabetical)

| Option | Section | Purpose |
|---|---|---|
| `--apply` | Remediation | Auto-confirm `--fix` (use with caution) |
| `--breakdown`, `-B` | Display | Show full score computation path |
| `--check=A,B,...` | Filters | Run only named sections |
| `--detailed`, `-d` | Audit | Write full report file (`~/.local/share/bob/logs/bob_*.log`) |
| `--diff`, `-D` | Comparison | Show only baseline delta |
| `--explain=KEY`, `-e` | Inspection | Structured per-finding explanation; `--explain list` for all |
| `--fix`, `-f` | Remediation | Interactive fix mode with [y/N] prompts |
| `--format=FMT` | Output | One of `json`/`json-full`/`csv`/`markdown`/`html`. Text is the default output when no format flag is set — it is not a valid value of `--format=`. |
| `--french` | i18n | Force French; auto-detected from `$LANG` otherwise (shortcut for `--lang=fr`) |
| `--help`, `-h` | Misc | Print help and exit (no sudo required) |
| `--history` | Comparison | Sparkline of last scores |
| `--html` | Output | Standalone HTML export |
| `--ignore=KEY` | Setup | Add a finding key to `~/.config/bob/ignore.yml` and exit (does not run the audit) |
| `--install-completion` | Setup | Install bash completion + sudo symlink |
| `--install-cron`, `-c` | Automation | Cron wizard (curses TUI + plain fallback) |
| `--json`, `-j` | Output | JSON short form (alias for `--format=json`) |
| `--json-full`, `-J` | Output | JSON full form (alias for `--format=json-full`) |
| `--lang=CODE` | i18n | Force language (`en` / `fr`); else POSIX auto-detect |
| `--log-days=N`, `-l N` | Audit | UFW log analysis window (default 7) |
| `--manage-cron`, `-C` | Automation | TUI to edit/delete cron jobs + email book |
| `--manage-logs`, `-m` | Automation | TUI to list/preview/delete reports |
| `--min-level=LEVEL` | Filters | Hide findings below severity. Valid values: `warn` or `alert` only (NOT `info` — `info` is the implicit floor). |
| `--no-color`, `-n` (alias `--no-colour`) | Output | Disable ANSI escapes |
| `--offline`, `-o` | Network | No outbound HTTP (public IP lookup + webhook off) |
| `--output=FMT` | Output | Alias for `--format=` accepting `csv`/`json`/`markdown` only (no html, no json-full) |
| `--output-dir=PATH` | Audit | Override log dir for this run (non-persistent) |
| `--profile=NAME`, `-p NAME` | Audit | Apply profile (`server`/`desktop`/`container` + user) |
| `--quiet`, `-q` | Output | Suppress all output, use exit code |
| `--reconfigure`, `-r` | Setup | Re-run first-launch config wizard |
| `--reset-baseline` | Comparison | Wipe `last_baseline.json` |
| `--show-ignored` | Display | Show previously-ignored findings as dimmed lines during the audit (doesn't list `ignore.yml` entries — for that, read the file directly) |
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
| `/usr/local/bin/bob-{slug}` | exec | Cron wrapper script. `{slug}` is the slugified user-entered name via `bob/cron/_parse.py::make_slug(name)` (re-exported from `bob.cron`) — lowercased, non-alphanum → `-`, stripped | Created by `--install-cron` |
| `/etc/cron.d/bob-{slug}` | r | Cron entry (system) — same `{slug}` rule | Created by `--install-cron`; managed by `--manage-cron` |

> When BOB runs under `sudo`, all writes to `~/.config/bob/` are auto-`chown`-ed back to `$SUDO_USER` (since v0.3.6).

### Environment variables

| Var | Effect |
|---|---|
| `BOB_SHARE` | Override package data dir (locales/, data/) — for distro packaging (`/usr/share/bob/`) |
| ~~`UFW_AUDIT_SHARE`~~ | **Removed in v0.6.0** after v0.4.2 → v0.5.4 deprecation chain. Installers still setting it will see no effect — update them to `BOB_SHARE`. |
| `SUDO_USER` | Auto-detected — controls config path resolution and chown-back |
| `LC_ALL` / `LC_MESSAGES` / `LANG` | POSIX locale detection (`fr_*` → French, else English fallback) |
| `LC_TIME` | Not read directly, but forced to C through `LC_ALL=C` in `_C_LOCALE_ENV` for subprocesses — avoids `strptime("%b ...")` regressions under `LC_TIME=fr_FR.UTF-8` (v0.4.3 fix) |

> **NOT honored**: `NO_COLOR` env var. BOB currently respects only the `--no-color`/`-n` CLI flag. Honoring `NO_COLOR` would require reading it in `bob/output.py::init()` — open improvement.

---

## Tests-to-source mapping (~86 test files cover ~94 modules)

Naming convention: `tests/test_<module_basename>.py` mirrors `bob/<module>.py` or `bob/checks/<module>.py`. Some shared tests:

| Test file | Covers |
|---|---|
| `test_scoring.py` | `bob/scoring.py` (engine, Finding, Deduction, FindingLevel, warn_with_deduction/alert_with_deduction helpers v0.5.x) |
| `test_domain_scores.py` | `bob/domain_scores.py` + active set + TestActiveDomainsIncludesOK (v0.4.6) |
| `test_domain_scores_mapping_complete.py` | AST-based parity check: every check prefix has a `_PREFIX_TO_DOMAIN` entry (v0.5.x) |
| `test_breakdown.py` | `bob/breakdown.py` (score transparency display) |
| `test_golden_scenarios.py` | End-to-end scoring scenarios — 32 tests across 9 classes (clean, hardened, desktop, poorly configured, firewall inactive, Debian minimal, tool caps, stability, multi-domain), introduced v0.3.0 |
| `test_json_schema.py` | JSON output contract — frozen + drift detection |
| `test_services_schema.py` | Plugin services JSON Schema (Draft 2020-12) |
| `test_locale_coverage.py` | All `t()`/`_t()` keys exist in both `en.json` and `fr.json` (AST-based since v0.4.5; AST-coverage hardened in v0.5.x) |
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
- **Zero runtime deps outside stdlib**. Major asset for distro packaging; preserve at all costs.
- **Snapshot + check_xxx separation**. Enables 4583 tests with no mocks.
- **Equal-domain weighting** in global score. All active domains contribute equally — intentional, retained through v0.6.x. The "main architectural question for v0.3.0" was answered: keep equal weighting.
- **JSON schema_version="1"** frozen since v0.4.0. Any breaking change = `"2"` + major bump.
- **EXPLAIN_KEYS frozen** with alias map for renames. 116 keys as of v0.6.0 (groups grew from 29 → 32 as the additive layer absorbed the service-state migration without renaming).
- **`OK` in active domain set** (Bug 2 fix in v0.4.6). `INFO`-only domains stay hidden by design — terrain-validated boundary.
- **`_atomic_write(path, content, mode=)` contract** (v0.5.x). Every persistent write goes through a tmp + `os.replace` rename + explicit mode (no umask surprises). The mode parameter exists specifically to support the cron wrapper script (0o755) regression seen in v0.5.7. Sites: `bob/cron/_io.py`, `bob/manage_logs.py`, anywhere config is rewritten.
- **Private-IP detection unified** to `sysinfo._is_private_or_loopback_ipv4/_ipv6` (v0.5.6). Single source of truth — the hand-rolled regex in `bob/checks/logs.py` was the last duplicate and is now retired. Do not re-introduce ad-hoc CIDR matching.

### Discarded (do not re-attempt)

- **M7 — Lazy `_PLUGIN_DIR` resolution.** Attempted in v0.4.3, broke 20 tests that patch `bob.registry._PLUGIN_DIR`. The "SUDO_USER changes mid-process" scenario doesn't happen in practice (BOB is one-shot per audit). Decision **permanent** (frozen 2026-05-15).

### Deferred (still open after v0.6.0)

- **Phase 2 Option A — full `Finding.template_vars` migration** on the 40 non-pilot checks. Currently `template_vars` is additive on 3 pilots (ssh, hardening, firewall). Full migration would allow `Finding.message` to be derived from `(key, template_vars)` entirely, enabling locale-independent JSON output. **Largest single chunk of refactor work pending.** Did not land in v0.5.x or v0.6.0.
- **M3 cosmetic** — `os.path` → `pathlib` in remaining files. Pure cosmetic; partially absorbed during v0.5.x audits, but not driven to completion.
- **AUR PKGBUILD** — community contribution welcome.
- **Tighter AppArmor lock-down** — read-only on /etc/, /proc/, /sys/; deny exec of non-whitelisted; restrict network egress to known endpoints. Deferred to a future hardening pass.

### Known debt (post-v0.6.0)

- `bob/tui/cron.py` (946 LoC) is now the largest single-file curses unit. Soft-ceiling candidate but works — touching curses code is high-risk-for-low-reward, and the v0.5.7 targeted audit already swept it.
- `bob/manage_logs.py` (1040 LoC) — UI heavy, curses, but tests/source ratio jumped to 1.07× during v0.5.x. Accept as-is.
- ~~`bob/checks/ssh.py` (1392 LoC)~~ **Done in v0.6.0** — split into the `bob/checks/ssh/` package (5 files, largest 529 L). Contract preserved via `__init__.py` re-exports.
- ~~`bob/cron.py` (1201 LoC)~~ **Done in v0.6.0** — split into the `bob/cron/` package (5 files, largest 445 L). Test file grew from 382 → 848 L over the cycle.
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
- **Add a check** (full checklist):
  1. Create `bob/checks/foo.py` with `FooSnapshot.from_system()` + `check_foo(snapshot, t)` (follow the pattern of an existing simple check, e.g. `ntp.py`).
  2. Wire in `bob/runner.py`: add the import at the top, add the section name `"foo"` to `_ALL_SECTIONS` tuple (line ~74), and invoke via `_sec("foo", foo_snapshot, check_foo)` in the appropriate GROUP block.
  3. Add locale keys to `bob/locales/{en,fr}.json`: at minimum a `sections.foo` title plus any `t("foo.xxx")` keys your check emits (validated by `test_locale_coverage.py`).
  4. Add the test file `tests/test_foo.py` (the suite will auto-discover it).
  5. Optional: add the prefix `"foo"` to `bob/domain_scores.py::_PREFIX_TO_DOMAIN` for scoring (else the check's findings fall into the `firewall` catch-all).
  6. Optional: add EXPLAIN_KEYS entries in `bob/explain.py` if you want `--explain foo.xxx` support.
- **Add an explain key**: append to `EXPLAIN_KEYS` in `bob/explain.py` + write title/why/how/CIS in both `en.json` and `fr.json`. `test_locale_coverage.py::TestExplainNamespaceCoverage` enforces parity.
- **Bump a version** — files to touch (verified `grep -l "0.6.0"` at refresh time):
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
| Python source (bob/) | 28,321 LoC across 94 files | `wc -l bob/*.py bob/checks/*.py bob/checks/ssh/*.py bob/cron/*.py bob/tui/*.py` |
| Tests | 35,887 LoC across 86 test files, 4056 functions, **4583 collected** | `wc -l tests/test_*.py` + `pytest --collect-only -q` |
| Runtime deps outside stdlib | **0** | `pyproject.toml` |
| Optional runtime deps | `geoip2` (IP geolocation) | `pipx inject bodyguard-of-bits geoip2` |
| Distro CI matrix | 7 distros | `.github/workflows/integration.yml` |
| Python versions tested | 3.10, 3.11, 3.12, 3.13 | `.github/workflows/tests.yml` |
| Locale keys | 1400 EN ↔ 1400 FR | `bob/locales/{en,fr}.json` |
| EXPLAIN_KEYS | 116 (in 32 groups) | `bob.explain.EXPLAIN_KEYS` |
| CIS references | 137 (99 Ubuntu 22.04 + 4 Docker + 34 best-practice) | `bob/data/cis_refs.json` |
| Known services | 32 | `bob/data/services.json` |
| Score domains | 7 | `bob.domain_scores.DOMAINS` |
| `_PREFIX_TO_DOMAIN` mappings | 32 (since v0.5.x explicit table) | `bob.domain_scores._PREFIX_TO_DOMAIN` |
| Filterable sections (`--check` / `--skip`) | 34 | `bob --check=list` |
| Audit profiles | 4 built-in (server / desktop / container + workstation alias) + user | `bob/data/profiles/` |
| CLI options | ~40 long-form + ~17 short | `bob.cli.parse_args` |
| Doc files | 16 public markdown + 3 man pages | `DOCUMENTS/` + `man/` |
| Public version | v0.6.0 (shipped 2026-05-25) | `pyproject.toml::version` |
| Supported branch | v0.6.x (v0.5.x is EOL) | `SECURITY.md` |
| First release | v0.1.0 (2026-04-26) | `CHANGELOG.md` |

---

© 2026 Cédric Clauzel
