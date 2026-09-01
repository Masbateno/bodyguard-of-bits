# BOB — Project snapshot

> **Purpose.** A single-page bird's-eye view of the codebase as of **v0.14.1** (2026-08-30, surgically refreshed from the v0.10.2 baseline across the v0.11.x → v0.13.x arc — header, counters, module inventories and dependency graph. **Every LoC figure in this document was recomputed against `wc -l` at v0.14.1** and the two hotspot tables were re-sorted; they are exact as of that date, not indicative. Designed to be loaded once before a refactor pass or an audit so you don't have to re-discover the structure module by module. Stats are derived from the actual source files; conventions and contracts are observable in the code, not aspirational.

> **Snapshot history.** v0.4.6 → v0.6.0 drift, in one paragraph: the v0.5.x branch ran a deep-audit campaign on 25 modules + ~25 spot-checks (4 phases of refactor v0.5.0–v0.5.4, then 4 hardening releases v0.5.5–v0.5.8), introduced `CheckResult.{warn,alert}_with_deduction` helpers (~120 call sites migrated, net −519 LoC across `bob/checks/*.py`), unified private-IP detection to `sysinfo._is_private_or_loopback_ipv4/_ipv6`, added the `_atomic_write(path, content, mode=)` contract with explicit mode parameter, split `_BadDirective` / `_LEVEL_DISPATCH` declarative tables, and added AST-based locale parity tests. **v0.6.0** then landed two architectural splits: `bob/checks/ssh.py` (1296 L monolith) → `bob/checks/ssh/` package with 4 submodules, `bob/cron.py` (1204 L monolith) → `bob/cron/` package with 4 submodules — both contract-preserving via `__init__.py` re-exports. The `UFW_AUDIT_SHARE` legacy env var was removed (deprecation chain v0.4.2 → v0.5.4 → v0.6.0).
>
> **v0.6.0 → v0.7.4 drift, in one paragraph:** v0.6.1 extracted `bob/_atomic.py` as the single source of truth for atomic file writes (consolidates 5 duplicate sites + adds 3 missing ones) and uniformised `safe_input` EOFError handling. v0.6.2 was a packaging hotfix (wheels v0.6.0/v0.6.1 were missing `bob/checks/ssh/` and `bob/cron/`: `pyproject.toml` find-list was frozen since v0.4.x — fixed with glob `["bob*"]` + non-editable smoke install on CI). v0.7.0 opened the next stable branch with three majors: T1 = posture escalation API (`set_posture` / `effective_level` / `posture_escalation` / `unpack_posture_escalation` / `set_posture_from_engine` — lifts displayed risk when firewall is structurally broken even though score is high), T2 = JSON schema v2 dispatch (`DEFAULT_SCHEMA_VERSION = "2"`, legacy `"1"` opt-in via `--json-v1`, frozen + audited EXPLAIN_KEYS surface), T3 = plugin sandbox (`bob/_sandbox.py` ~960 L SandboxRunner, Tier 2 restrictions, threat-model recadré post sub-agent audit: in-process sandbox is defence-in-depth not a security boundary, see `BOB_SANDBOX_LEGACY` trap door), plus 4 release-engineering CI guards (integration-first / smoke-after-commit / version-consistency / smoke-plugin). Then v0.7.1 (4I + 3M same-day hardening: webhook HTTPS-only + `BOB_WEBHOOK_ALLOW_INSECURE` env var, ignore-key canonical regex, fsync on `_atomic`), v0.7.2 (6/6 deferred minors + v0.6.x EOL: `tempfile.mkstemp` for tmp atomic collision, M-10 `_compute_posture_annotation` single helper, i18n on markdown_output.py + html_output.py), v0.7.3 (full deep-audit pass: 6I + 8M shipped — **BREAKING**: CSV column `section` → `nature` to match actual data, `set_posture_from_engine` helper extracted into scoring.py, M-5 report.py field labels i18n), v0.7.4 (4th hardening pass: `_VALUE_TAKING_OPTS` frozenset cli.py, services.py `_PRIVATE_ADDR` constant retired, sandbox WARN `key=` enrichment + threading hardening, M-7 `json_output` uses `engine.domain_scores` cache when populated). See `DOCUMENTS/CHANGELOG_FULL.md` for the full per-release breakdown.
>
> **v0.7.4 → v0.9.2 drift, in one paragraph:** **v0.8.0** = drift batch + framing + silent-feature-gap audit (closes v0.7.x): 11-item drift sweep + 8 silent-feature-gap tiers (T1 = +51 `--explain` entries opening 15 new prefixes, EXPLAIN_KEYS 117/30 → 168/45; T2 = services.json 32 → 38 with 6 modern services; T3 = `warn_with_deduction` backfill on 4 previously-flat findings; T9 = Markdown/HTML format parity for Finding.detail+note) + 2 framing actions (A1 = hypotheses footer in summary box, A2 = "what BOB is/is NOT" README+SECURITY section) + 5th CI guard `test_doc_version_consistency.py`. **v0.8.1** = 3 sub-agent audit passes (6/7/8) closing 26 gap tiers including T57 `--unignore`, T60 `_t_or_hardcoded` helper, T74 webhook URL credential redaction, **workstation alias retrait BREAKING**. **v0.8.2** = conservative-bundle: bash completion v0.8.2 sync + `bob/_i18n_safe.py` consolidation + `--test-webhook` smoke + `--check=list` section descriptions + D-3 deprecation warning + locale linter. **v0.8.3** hotfix `UnboundLocalError` audit path (v0.8.2 shadowed `UserConfig` module import inside `main()`). **v0.8.4** = final v0.8.x: cleanup `is_unit_enabled` dead code (7-month monitoring) + new `DOCUMENTS/TUTORIAL{,_FR}.md` (269 L × 2). **v0.9.0** = BREAKING bundle closing the v0.7.0-deferred items: D-1 (7 section renames with fatal `_RENAMED_SECTIONS_V090` migration error: `cron_audit→cron`, `docker_audit→docker_hardening`, `services_state→services_health`, `ports_analysis→ports`, `rules→firewall_rules`, `iptables_nft→firewall_iptables`, `firewall_stack→firewall_drivers`) + D-2 (fusion `_SECTIONS` tuple with `_Section(name, always_on)`, back-compat derived views) + D-3 (retrait `EXPLAIN_KEY_ALIASES` source-side drift fix) + TD-1 (retrait `BOB_SANDBOX_LEGACY=1` trap door) + F-3 (retrait `--json-v1` legacy schema) + F-2 (NEW `--diff [PATH]` cross-machine compare with `AuditBaseline.hostname` + `BaselineLoadError`) + bash completion `cur="="` companion fix. **v0.9.1** hotfix F-3 message UX (`i18n.t()` pre-init bracketed-fallback — fixed by inlining EN string + 2 ast guard tests). **v0.9.2** closes 2 v0.9.1 deferred items: `BaselineLoadError` i18n (4 new `compare.baseline_load.*` locale keys via `t_or_hardcoded`) + cross-version baseline migration shim (new `bob/_v090_renames.py::SECTION_RENAMES_V090` + `remap_finding_key` helper extracted to break circular import + wired into `load_baseline` to remap legacy finding keys at load, killing the "resolved+new" diff noise observed on Ubuntu 26.04 during the v0.9.0 field test). Test count: 5466 (v0.7.0) → 5521 (v0.7.4) → 6008 (v0.8.0) → 6198 (v0.8.1) → 6244 (v0.8.2) → 6246 (v0.8.3/0.8.4) → 6210 (v0.9.0, net −36) → 6212 (v0.9.1) → 6242 (v0.9.2) → 6242 (v0.10.0, no behaviour change) → 6261 (v0.10.1) → 6268 (v0.10.2).
>
> **v0.10.x branch (this snapshot).** **v0.10.0** was a **preparation release** that opened the v0.10.x branch with the D-4 migration shim foundation (`bob/_v100_subcheck_renames.py` + `ScoreEngine.apply` ignore.yml back-compat wiring — legacy v0.9.x entries continue to suppress findings via `fnmatch` glob match against `SUBCHECK_RENAMES_V100`). The actual D-4 sub-check splits (8 ranked candidates per sub-agent audit) and the F-1 parallel-check refactor (Option B per F-1 thread-safety audit: Phase 0 sequential firewall/ports/network_context + Phase 1 `ThreadPoolExecutor` snapshot+check fan-out + Phase 2 sequential merge in canonical `_SECTIONS` order) were intentionally deferred — both audits ran by sub-agents on 2026-06-08 with concrete file:line citations + effort estimates (~20 h D-4, ~6-8 h F-1). **v0.10.1** shipped only **D-4 Rank 1** through the conservative "gain × risque = STOP" filter: `ssh.x11_forwarding` split into server-side (`ssh.x11.forwarding.server`) + a NEW client-side `ForwardX11` detection (`ssh.x11.forwarding.client`), first live use of the `EXPLAIN_KEY_ALIASES` map (after v0.9.0 D-3 emptied it) and of the `SUBCHECK_RENAMES_V100` shim; EXPLAIN_KEYS 168 → 169. The other 7 D-4 ranks + F-1 stay deferred without user signal. **v0.10.2** (same-day after v0.10.1) shipped **I-1 only** from a deep hardening audit (4 findings, 1I + 3M): `set_posture_from_engine` (then at `bob/scoring.py:739`, today line 790) was still comparing against the retired `iptables_nft.input_accept` literal — the v0.9.0 D-1 rename had moved the canonical key to `firewall_iptables.input_accept`, so the iptables-only posture escalation had been **silently dead since v0.9.0** (3 majors), masked in practice by the `firewall_inactive` branch (UFW-active hosts with a legacy iptables ACCEPT passthrough silently regressed HIGH → LOW). Fix + a static AST-style guard (`tests/test_v0102_posture_iptables_key.py`) forbidding live comparisons against the legacy literal. **F-1 is now tranché DEFER indéfiniment — do not re-propose each cycle.**
>
> **v0.10.2 → v0.13.1 drift, in one paragraph (surgical refresh — all shipped).** **v0.11.0** = the planned BREAKING hygiene bundle: M-3 ssh client `Host`-scope semantics (forwarding directives inside a restricted `Host` block are now scope-aware → INFO without deduction, BREAKING), D-4 Rank 2–8 KILL (13 inert shim entries removed, behaviour-preserving), a CI literal-drift guard (generalises the v0.10.2 AST guard) + an 8-cell posture matrix test. **v0.11.1** = i18n template fix + `--test-webhook --offline` + 3 UX-audit fixes + a doc-accuracy pass (DOC-A→G). **v0.11.2** = i18n completeness (60 best-practice refs → locale-aware `get_cis_ref`). **v0.12.0** = BREAKING UX bundle: F1 headline cap to 9 on deduction + F2 per-severity symbol + F4 `--explain` exit-3 + fuzzy + F6 validate-before-root + F9 `alert_count`/`warning_count` **+ JSON schema v2 → v3**. **v0.12.1** = domain-display completeness (all 7 domains shown with reason) + naive/advanced audit fixes. **v0.12.2** = branch-closing deep-audit (0C/0I) + `_DOMAIN_SECTIONS` prefix→section fix + cron-name defence-in-depth. **v0.13.0** = first real scope growth (end of the internal-hardening cycle): two INFO-only runtime checks — `systemd_hardening` (systemd-analyze security of running services) + `container_security` (caps/seccomp/userns/rootfs via `/proc`, suppressed off-container); v0.12.x declared EOL. **v0.13.1 (this snapshot)** = additive runtime-context checks, INFO-only: `socket_units` (orphan/failed systemd sockets at the systemd × listening-sockets intersection) + `cloud_context` (host-side cloud exposure — IMDS-on-link / world-readable user-data, suppressed off-cloud, conservative detection: DMI provider or cloud-init + on-link IMDS, strictly no cloud API) + `ddns` + `ssh` robustness fixes (`_config_present()` / guarded `~/.ssh` probe degrade an unreadable `/root` path under userns instead of crashing or leaking — the latter surfaced by the v0.13.1 live field test). **v0.13.2 (this snapshot, same-day)** = finding-command safety/coherence patch from a sub-agent semantic-coherence pass: docker `userns_not_configured` remediation no longer overwrites `daemon.json` (create-if-absent only); kernel `apt purge` re-typed `check`→`fix` (renders under "What to do? →", not "Verify:"); invalid `cmd_type="action"`→`fix`; + a contract guard in `CheckResult.add_finding` rejecting any `cmd_type` outside `("fix","check")`. The **teeth** — operator-choice deductions (privileged container, nftables scoring parity) — are reserved for the planned **v0.14.0** BREAKING bundle (do not open without user signal; see `project_v0140_backlog.md`). Test count: 6268 (v0.10.2) → 6336 (v0.11.0) → 6362 (v0.11.1) → 6381 (v0.11.2) → 6401 (v0.12.0) → 6437 (v0.12.1) → 6442 (v0.12.2) → 6461 (v0.13.0) → 6504 (v0.13.1) → 6511 (v0.13.2) → 6533 (v0.13.3) → 6545 (v0.13.4) → 6590 (v0.14.0) → **6719 (v0.14.1)**. Counters: filterable sections 34 → **38**, check modules 43 → **47**, EXPLAIN_KEYS unchanged at **169/45** (the four new sections are INFO-only), services.json **38**, **~34.3 kLoC**.
>
> **v0.13.3 (this snapshot).** Hardening patch, additive and non-BREAKING — no score, output field or exit code changed. Five items, all self-audit rather than user report. **(1) Logging** — the package never configured logging, so all ~45 `logger.warning`/`logger.error` sites fell through Python's *lastResort* handler onto stderr, bypassing `--quiet`, skipping i18n, and doubling the `--profile=typo` message. `bob/__init__.py` now installs a `NullHandler` on the `bob` logger (kills lastResort, keeps propagation — `caplog` and downstream handlers verified unaffected) plus an opt-in `BOB_DEBUG=1` real handler, deliberately placed in `__init__.py` because `i18n.py`/`registry.py` call `resolve_share_dir()` at import time. **(2) Filtered-run performance** — snapshots were built at the `_sec` call site, i.e. *before* `_section_enabled`, so `--check`/`--skip`/profile filtering saved nothing. `_sec` now also accepts a factory unwrapped after the gate and before `skip_if`; the 5 costliest snapshots (`updates`, `services_health`, `socket_units`, `systemd_hardening`, `disk`) converted → **`--check=ssh` 5.40 s → 2.57 s**, full audit unchanged, structural finding signature `(key, level, nature)` proven identical across 4 filter combos. `hardening_snapshot` + `ipv6_snapshot` **must stay eager** — they feed the `--json-full` `sysctl` block via `ChecksResult`. 29 sites deferred (planned for v0.13.4 at the time; actually closed in v0.14.1, when the fault barrier made lazy collection a correctness requirement rather than a performance one — see the v0.14.1 entry below). **(3) `NO_COLOR`** honoured in `output.init()` (spec semantics; strictly additive). The TTY auto-detection `supports_color()` was written for stays BREAKING → v0.14.0 with `FORCE_COLOR`. **(4) Doc-counter drift** — five counters stale, one by six minors (correlation rules 5→**6**, explain keys 116→**169**, groups 29→**45** prefixes, runner sections 29→**38+10**, locale keys 1401→**2008**); fixed in README_TECH + README_DEV (EN+FR) and pinned by a new counter-drift guard that skips lines narrating past releases. **(5) Lint** — new `.ruff.toml` + CI job `ruff check bob/` at **zero**, correctness-only (`E9`/`F`/`B`, no style rules), scoped to `bob/` (tests carry ~140 churn findings); `B904`/`B905` documented as deferred, not waived. Three `_run` imports removed as "unused" were **restored** — they are `monkeypatch.setattr` seams, caught by the suite, now annotated.
>
> **v0.13.4 (this snapshot).** Documentation accuracy pass — factual corrections only, no audit behaviour change (one `--help` addition aside). A machine audit of the whole corpus (19 public markdown files, 3 man pages) against the code found **7 defects, 2 of them introduced by v0.13.3** (which updated only this header and the changelog, not the document bodies). **(1) `SECURITY_FR.md` "Plugin checks" was factually inverted**, not merely abridged (83 words vs 562 EN): it claimed plugins are **NOT** sandboxed and referenced "la ligne 0.6.x" — the sandbox shipped in **v0.7.0**, so the French security policy contradicted reality for seven minors, and the entire threat model (defence-in-depth ≠ security boundary, PEP 416, AppArmor is the real boundary, code-review your plugins) existed only in English. Fully translated, 15% → 121%. **(2) Five working CLI flags absent from `--help`**: `--json`, `--json-full`, `--html`, `--output=FORMAT`, `--no-colour`. **(3) 29 broken/leaked markdown links** — 17 `](bob/…)` instead of `](../bob/…)` in `CHANGELOG_FULL.md` (FR twin had zero, hence invisible to symmetry), 8 pointing at Claude's internal memory store, 4 stale targets. **(4) This document contradicted itself** on `NO_COLOR` (header vs line 633) — resolved, with the still-unwired TTY auto-detection stated explicitly. **(5) `BOB_DEBUG`** documented as traceback-only in SECURITY EN+FR despite v0.13.3 adding the logging handler. **(6)** `README_DEV{,_FR}` missing the four v0.13.x check modules. **(7)** `--english` absent from README_TECH + man. **Three guards** (`tests/test_v0134_docs_accuracy.py`): link resolution, **per-section** EN/FR word ratio ≥ 55% (a whole-file ratio misses defect 1 — `SECURITY_FR.md` was at 92% overall), and CLI-surface coverage both ways. **Verified healthy, do not re-audit:** 5 of 6 doc pairs at 106–113% EN/FR ratio, `CHANGELOG_FULL` carrying all 65 releases in both locales, `README_DEV`'s module inventory otherwise complete (it is organised by *filename*, which is correct — the v0.9.0 D-1 renames are section names, an internal surface).
>
> **v0.14.0 (this snapshot).** BREAKING contract-fix bundle. The **teeth stay deferred** — calibrating a privileged-container or nftables deduction needs a real container and a real cloud instance, neither available; the backlog rule is *ne pas deviner*. **(1) The audit profile reached only 2 of the 14 `engine.apply()` paths.** Callers had to invoke `apply_profile()` themselves; only `_sec` and the plugin path did, so the 12 hand-rolled always-on sections never applied it and **8 shipped desktop/workstation overrides were inert** (`ddns.warn`, `services.exposed.avahi`, `services.exposure.open_local`, `firewall_drivers.ip_forward_enabled`). Because `warning_count` counts by *level* and maps to `EXIT_WARNINGS`, a LAN host with Samba behind a UFW rule — the recommended setup — could never return **exit 0**, a documented stable-API value. `ScoreEngine` now carries `profile=` and applies it inside `apply()`, the single choke point; repeating the call per site was rejected as the design that drifted. Live: desktop/workstation warn 4 → 2, server 13 → 13, score unchanged. **The full suite passed before the fix too** — `apply_profile` was tested only in isolation, never its wiring. **(2) Colour is auto-detected**: `--no-color` → `NO_COLOR` → `FORCE_COLOR` (new) → `isatty()`. `supports_color()` existed all along, called from nowhere. `print_help` hardcoded `\033[1m` and now obeys the same decision. **(3)** the ambiguous `NO_COLOR=` help wording, **(4)** B904/B905 — `.ruff.toml` ignores nothing now, **(5)** 8 wrong weekdays in the debian/rpm changelogs. **+43 guards**, all mutation-tested; the profile ones are behavioural, not structural, because the old design was "correct" at every site that remembered.
>
> **v0.14.0 — validation limits and two open findings.** A second validation pass covered the interaction paths the first had missed (profile `skip`, downgrade-drops-deduction, profile × ignore ordering, `--watch` iterations, plugin findings, machine-output purity on TTY and pipe, `--breakdown` colour) and found **no defect**. Regression vs v0.13.4 is surgical: `server` byte-identical, and on the other three profiles the only key whose (key, level, nature) changes is `services.exposure.open_local` (`container` inherits it via `extends = desktop`). **Not validated, do not read as validated:** cloud *runtime* findings (`cloud_context.imds_reachable`, world-readable user-data) have never fired — only DMI provider detection was exercised, through fixtures authored for the test, so it proves the matcher works *given* those values, not that Hetzner/Linode/Alibaba publish them; three of the four resurrected overrides (`ddns.warn`, `services.exposed.avahi`, `firewall_drivers.ip_forward_enabled`) are covered by targeted tests against the real `.conf` files (8/8, no skip) but this host emits none of them, so only `open_local` was seen live; `docker` / `docker_hardening` remain unexercised because the field-test runtime is **podman** (chosen deliberately — Docker would add a daemon, iptables rules and a bridge, altering the host posture used as the comparison baseline). **Two findings recorded, not fixed:** (1) `container_security.privileged` is *defined* as "CAP_SYS_ADMIN present" (`container_security.py:75`) and its detail says so correctly, but its **headline claims "full Linux capability set available"** — false for `--cap-add SYS_ADMIN` (measured cap_bnd 2149844475 vs 2199023255551 for a real privileged container, seccomp still enforcing). The backlog lists `privileged` and `CAP_SYS_ADMIN` as distinct conditions while the code conflates them, so a deduction keyed on `privileged` as computed today would punish a FUSE-scoped container as hard as a fully privileged one — **fix the semantics before adding the teeth**. (2) **nftables scoring parity was never actually blocked**: the backlog filed it behind field-test hardware, but that blocker was containers and cloud instances; `nft` and `iptables-nft` are present on an ordinary workstation.
>
> **v0.14.1 (this snapshot).** Correctness patch, INFO-only surface. `container_security.privileged` was computed as `cap_bnd & (1 << CAP_SYS_ADMIN)` — literally "CAP_SYS_ADMIN present" — so `--cap-add SYS_ADMIN` (a targeted grant, seccomp still enforcing) was reported PRIVILEGED under the headline *"full Linux capability set available"*. Measured on podman: 2149844475 for the targeted grant vs **2199023255551** = `(1 << 41) - 1` for a real one (`cap_last_cap = 40`). `privileged` now means the **full** set, read from `/proc/sys/kernel/cap_last_cap` with a bounds-checked fallback; a lone CAP_SYS_ADMIN gets the new additive key `container_security.cap_sys_admin`. **This gates the v0.15.0 teeth** — the container deduction was to be keyed on `privileged`, which under the old semantics would have punished a FUSE-scoped container as hard as a fully privileged one. **Why it survived:** the tests set `privileged=` by hand and never derived it from a bounding set. The first draft of the new guards fell into the same trap — it reimplemented the mask logic in the test and passed when the buggy line was restored; rewritten to drive the real `from_system()`, now mutation-tested against both a reverted classification and a removed emission branch. Also: the v0.14.0 release surfaces were dated 28 Aug but it shipped on the 29th (publish workflow stamped `2026-08-29T16:46:08Z`) — corrected on the v0.14.0 surfaces only, v0.13.3/v0.13.4 genuinely shipped on the 28th. Also in v0.14.1, a **robustness batch** from a local stress campaign: `runner._sec` had no exception handling, so one failing check cost the operator the ENTIRE audit (exit 3, zero bytes of stdout) — reproduced with a latin-1 byte in an `/etc/passwd` GECOS field. A failing section is now degraded in place (`<section>.unavailable` INFO finding + new additive JSON field `degraded_sections`, no schema bump; exit codes deliberately unchanged), which required converting **29 eager `_sec` snapshot call sites to lazy factories** — closing the lazy-snapshot reliquat deferred since v0.13.3. The always-on firewall core stays deliberately unguarded: it is a data pipeline, not independent sections. Plus `UnicodeDecodeError` escaping 33 `except OSError` guards (it is a `ValueError`), `load_history` dying on a JSON-valid non-object line, `--lang` accepting an absolute path into `i18n.init()`, report files opened without `O_NOFOLLOW`, CSV formula injection, and the missing v0.7.3 M-4 dash guard on `--profile`/`--check`/`--skip`. A **second stress campaign** then attacked those fixes: the barrier could be defeated from inside its own handler (rendering outside the inner try — it now records first, renders best-effort); report writes had no error handling at all, so a full disk under `-d` cost the whole audit; `--ignore` silenced the score but not the terminal (`display_result` renders the raw `CheckResult`); terminal escape sequences from system-derived values reached the terminal, now sanitized in `Finding.__post_init__` — every construction path, plugin-supplied findings included; and unbounded reads on non-regular files (plugin symlinked to `/dev/zero` → OOM; `--diff=<fifo>` → **hung forever**) — the state-file half closed by the shared `_atomic.read_text_capped()`, the plugin half by an `is_file()` guard plus a bounded `fh.read(_MAX_PLUGIN_SIZE + 1)` in `plugin_checks.py`. A **third campaign** targeted what the tool reports: the active audit profile appeared only in the terminal despite changing severities and the exit code since v0.14.0 (now an additive `profile` field in JSON v3 + Markdown/HTML headers; CSV deliberately untouched), `-p NAME` silently persists as the operator's default (undocumented since v0.12.1, now in `--help` and both READMEs), and both READMEs documented `-d` as "French output". Verified clean: the entire i18n key space (966 literal + 637 runtime-built expansions resolve in both locales), scoring invariants over 6 000 random engine states, the profile loader against circular / deep / malformed / `/dev/zero` profiles, and JSON schema conformance over 16 payloads.

---

## One-screen view

```
┌─────────────────────────────────────────────────────────────────────────┐
│  bob v0.14.1    ~34.3 kLoC Python · 0 runtime deps outside stdlib        │
│                 7557 unit tests · 19 doc files · 5+ distros field-tested │
└─────────────────────────────────────────────────────────────────────────┘

LAYER (top→bottom = imports flow down)

    bob/__main__.py  ← orchestrator (708 L)
        │
        ├──► bob/cli.py             ← AuditConfig + parse_args() (915 L)
        ├──► bob/runner.py          ← run_checks(), _sec closure (940 L)
        ├──► bob/scoring.py         ← ScoreEngine + Finding + Deduction + posture API + v0.10.0 D-4 legacy-ignore shim + v0.10.2 I-1 firewall_iptables literal fix (839 L)
        ├──► bob/domain_scores.py   ← per-domain averaging, 7 domains
        │                              (called AFTER run_checks via
        │                               apply_domain_score_override)
        ├──► bob/sysinfo.py         ← collect_system_info, network ctx
        └──► bob/{display,i18n,output,history,...}  (direct output-layer
                                                     imports — see grep
                                                     `^from bob\.` for
                                                     the full 30 deps)
             (bob/report.py is *not* a direct import of __main__ —
              accessed via runner.init_report's return value)

    bob/runner.py
        │
        ├──► bob/cli.py        (AuditConfig type hint)
        ├──► bob/config.py     (UserConfig)
        ├──► bob/profiles.py   (server/desktop/workstation/container + user)
        ├──► bob/scoring.py    (ScoreEngine + posture escalation API)
        └──► bob/checks/*.py   (47 check modules — ssh + cron are sub-packages since v0.6.0)

    bob/checks/*.py  ← 47 check modules · Snapshot+check_xxx pattern
        │  > Note: section *names* are v0.9.0 D-1 canonical (`cron`, `docker_hardening`,
        │  > `services_health`, `ports`, `firewall_rules`, `firewall_iptables`, `firewall_drivers`).
        │  > The bob/checks/ *filenames* still use the legacy spellings (cron_audit.py,
        │  > docker_audit.py, services_state.py, ports.py, firewall.py, iptables_nftables.py,
        │  > firewall_stack.py) — internal API, not user-visible.
        │  ├ firewall/firewall_drivers/network_context/ports/services/logs/ddns  (network — 7)
        │  ├ docker / docker_hardening          (containers — 2)
        │  ├ ssh / file_perms / suid_audit / user_accounts / password_policy / umask  (access — 6)
        │  ├ hardening / kernel_hardening / kernel_modules / mac_policy / secure_boot  (kernel — 5)
        │  ├ updates / firmware / cron / services_health                  (system — 4)
        │  ├ disk / memory / backup                                       (hardware — 3)
        │  ├ auditd / file_integrity / rootkit / clamav / fail2ban / auth_log  (security tools — 6)
        │  └ ssl_certs / systemd_timers / ntp / desktop_apps / virtualization / samba / smtp / firewall_iptables / ipv6 / log_rotation  (misc — 10)
        │  ├ systemd_hardening / container_security / socket_units / cloud_context  (runtime posture — 4, v0.13.x)
        │  Total: 7+2+6+5+4+3+6+10+4 = 47 ✓
        │
        ▼
    bob/display.py + bob/output.py + bob/panorama.py + bob/breakdown.py
        ← terminal rendering
    bob/json_output.py + html_output.py + csv_output.py + markdown_output.py + report_markdown.py
        ← export formatters
    bob/formatter.py + bob/i18n.py + bob/_i18n_safe.py + bob/locales/{en,fr}.json
        ← locale-independent reconstruction + i18n (2014 keys per language;
          _i18n_safe.py since v0.8.2 = shared make_fallback_t + t_or_hardcoded)

DATA (read-only at runtime, shipped in the package)

    bob/data/services.json        ← 38 services (id+ports+risk+detection)
    bob/data/cis_refs.json        ← 174 CIS references
    bob/data/profiles/*.conf      ← server/desktop/container/workstation
    bob/data/schemas/*.json       ← service / services-list / plugin-file (Draft 2020-12)
    bob/data/bob.bash-completion  ← shipped, installed via --install-completion

EXTERNAL CONTRACTS (frozen, do not break without major bump)

    schema_version = "3" only       ← JSON output top-level (v1 retired v0.9.0 F-3, v2 retired v0.12.0 F9)
    EXIT CODES 0/1/2/3/4            ← stable public API
    EXPLAIN_KEYS                    ← 169 keys / 45 prefixes; alias map emptied v0.9.0 D-3, first live alias v0.10.1 (ssh.x11)
    7 domain keys                   ← ssh, samba, file_perms, updates, hardening, disk, firewall
    38 --check/--skip section names ← stable filter surface (filterable; D-1 renames v0.9.0)
    10 always-on section names      ← firewall/firewall_rules/ports/… (recognised by --check since v0.7.0 M-7)
    services.json schema v1         ← plugin contract for users
    CSV column = "nature" (BREAKING ← was "section" pre-v0.7.3; rename to match Finding.nature semantics)

INTERNAL CONTRACTS (load-bearing — do not re-introduce the legacy patterns)

    bob/_atomic.py::atomic_write    ← single source of truth, fsync(fd) + fsync(dir_fd) since v0.7.1
    bob/_atomic.py::read_text_capped ← v0.14.1 read side: regular files only, bounded
    sysinfo._is_private_or_loopback_ipv4/_ipv6  ← single source of truth for private-IP detection
    bob/_tty.py::safe_input         ← single EOFError-swallowing wrapper around input()
    bob/_sandbox.py::SandboxRunner  ← single plugin execution path (Tier 2); trap door removed v0.9.0 TD-1
    bob/_i18n_safe.py               ← shared make_fallback_t + t_or_hardcoded helpers (v0.8.2)
    bob/_v090_renames.py            ← SECTION_RENAMES_V090 + remap_finding_key (v0.9.0 D-1 + v0.9.2 shim)
    bob/_v100_subcheck_renames.py   ← SUBCHECK_RENAMES_V100 + any_legacy_ignore_matches (v0.10.0 D-4 shim)
```

---

## Project structure (annotated)

```
bodyguard-of-bits/
├── bob/                       ← Python package (the tool)
│   ├── __init__.py            ← __version__ + NullHandler / BOB_DEBUG logging setup (v0.13.3, 31 L)
│   ├── __main__.py            ← orchestrator, 708 L, 30 outgoing bob.* imports
│   ├── runner.py              ← run_checks(), 940 L, _sec closure (38 filterable + 10 always-on sections via unified `_SECTIONS` tuple, v0.9.0 D-2)
│   ├── cli.py                 ← parse_args() + AuditConfig + _VALUE_TAKING_OPTS (v0.7.4) + --diff/--reset-baseline wiring (v0.9.0 F-2); --json-v1 retired (v0.9.0 F-3 — now hits CLIError with hardcoded EN fallback per v0.9.1) — 915 L
│   ├── config.py              ← UserConfig, EmailStore, ~/.config/bob/
│   ├── profiles.py            ← audit profile loader (**4 built-in** + user); v0.8.1 BREAKING retired the *alias* — workstation is now first-class
│   ├── scoring.py             ← ScoreEngine, Finding, Deduction, FindingLevel, warn_with_deduction/alert_with_deduction (v0.5.x), set_posture/effective_level/posture_escalation/set_posture_from_engine (v0.7.0+); ScoreEngine.apply consults `any_legacy_ignore_matches` for v0.9.x ignore.yml back-compat (v0.10.0 D-4); `set_posture_from_engine` matches canonical `firewall_iptables.input_accept` (v0.10.2 I-1 — was stale `iptables_nft.*` literal dead since v0.9.0 D-1) — 839 L
│   ├── domain_scores.py       ← 7-domain attribution, active set, capping
│   ├── _atomic.py             ← **v0.6.1** single source atomic_write(path, content, mode=) with fsync(fd)+fsync(dir_fd) (v0.7.1 M-2), tempfile.NamedTemporaryFile unique tmp (v0.7.2 M-7) + **v0.14.1** read_text_capped() — 139 L
│   ├── _sandbox.py            ← **v0.7.0 T3** SandboxRunner (Tier 2) for plugin_checks; **BOB_SANDBOX_LEGACY trap door removed v0.9.0 TD-1**; threat-model recadré post-audit (defence-in-depth, not security boundary) — 881 L
│   ├── _i18n_safe.py          ← **NEW v0.8.2** shared `make_fallback_t(labels)` factory + `t_or_hardcoded(key, fallback)` helper; consolidates the 4 pre-v0.8.2 private `_fallback_t` sites (config/webhook/markdown_output/html_output) into a single contract — 89 L
│   ├── _v090_renames.py       ← **NEW v0.9.2** `SECTION_RENAMES_V090` dict (7 D-1 renames) + `remap_finding_key()` shim; extracted from `bob/runner.py` to break the circular import with `bob/compare.py::load_baseline` (cross-version baseline migration) — 66 L
│   ├── _v100_subcheck_renames.py ← **v0.10.0** `SUBCHECK_RENAMES_V100` dict (**1** live entry since the v0.11.0 D-4 KILL removed the 13 inert ones) + `matches_legacy_ignore` / `any_legacy_ignore_matches` helpers; ignore.yml-only back-compat (NOT baseline diff — see module docstring) — 126 L
│   ├── checks/                ← 47 check modules, see Module index below
│   │   ├── _run.py            ← shared subprocess helper with _C_LOCALE_ENV (centrality anchor — see Dependency graph)
│   │   └── ssh/               ← split package since v0.6.0 (was 1296 L monolith)
│   │       ├── __init__.py    ← public re-exports for backwards-compat (64 L)
│   │       ├── _directives.py ← _BadDirective table + _BAD_DIRECTIVES + _WEAK_CIPHERS/_WEAK_MACS/_WEAK_KEX sets (202 L)
│   │       ├── _snapshot.py   ← 5 dataclasses + SSHSnapshot + from_system (207 L)
│   │       ├── _parsers.py    ← pure parsers, key-type helpers, collect_host_keys (446 L)
│   │       └── _subchecks.py  ← check_ssh entry point + per-area _check_* helpers, incl. v0.10.1 client-side ForwardX11 detection (605 L)
│   ├── cron/                  ← split package since v0.6.0 (was 1204 L monolith)
│   │   ├── __init__.py        ← public re-exports incl. datetime + _EMAIL_RE (101 L)
│   │   ├── _parse.py          ← CronEntry + parsing + listing + validators + MTA + constants (369 L)
│   │   ├── _io.py             ← atomic-write delegation (bob/_atomic.py) + build_script_content + apply_cron_* (158 L)
│   │   ├── _install.py        ← prompt_emails/prompt_email + plain wizard + run_install_cron (327 L)
│   │   └── _manage.py         ← edit_cron_email/schedule + plain wizard + run_manage_cron (452 L)
│   ├── tui/                   ← optional curses subpackage (v0.4.1 extraction)
│   │   ├── __init__.py
│   │   └── cron.py            ← curses wizard for --install-cron / --manage-cron (949 L)
│   ├── display.py             ← terminal output helpers + _compute_posture_annotation single helper (v0.7.2 M-10), 903 L
│   ├── output.py              ← low-level terminal primitives, 675 L
│   ├── panorama.py            ← services panorama table builder
│   ├── breakdown.py           ← --breakdown score computation transparency
│   ├── exposure.py            ← attack-surface table (compute_exposure)
│   ├── formatter.py           ← locale-independent reconstruction (v0.4.1)
│   ├── i18n.py                ← t(key, **vars), 2014 keys per locale (strict parity)
│   ├── locales/
│   │   ├── en.json            ← English translation keys
│   │   └── fr.json            ← French translation keys (strict parity)
│   ├── data/
│   │   ├── services.json      ← 38 known services (declarative registry)
│   │   ├── cis_refs.json      ← 174 CIS references
│   │   ├── profiles/          ← server.conf, desktop.conf, workstation.conf, container.conf
│   │   ├── schemas/           ← 3 JSON Schemas (Draft 2020-12)
│   │   └── bob.bash-completion ← bash completion script
│   ├── explain.py             ← --explain TUI, EXPLAIN_KEYS (169 keys, 45 prefixes), v0.8.0 backfill of 51 WARN/ALERT gaps + v0.10.1 `ssh.x11.forwarding.client`; `EXPLAIN_KEY_ALIASES` dict emptied (v0.9.0 D-3 — drift fix at source) then first live entry v0.10.1 (ssh.x11 D-4 Rank 1 split migration path)
│   ├── cis_refs.py            ← lookup get_cis_ref() / get_cis_code()
│   ├── compare.py             ← AuditBaseline + AuditDelta + diff; **v0.9.0 F-2** added `AuditBaseline.hostname` + `BaselineLoadError` + `--diff [PATH]` strict-mode loader for cross-machine compare; **v0.9.2** wired `bob/_v090_renames.remap_finding_key` into `load_baseline` (kills "resolved+new" diff noise post-upgrade) + i18n on BaselineLoadError via `_i18n_safe.t_or_hardcoded` (4 new `compare.baseline_load.*` locale keys) — 482 L
│   ├── correlation.py         ← 6 compound-risk rules
│   ├── recurrence.py          ← consecutive-audit finding tracker
│   ├── history.py             ← --history sparkline, rotates at 1000 entries
│   ├── ignore.py              ← persistent ignore list; canonical key regex validation (v0.7.1 M-3); v0.10.0 D-4 back-compat handled in `scoring.py::ScoreEngine.apply`, not here
│   ├── fixes.py               ← --fix interactive remediation UI
│   ├── manage_logs.py         ← --manage-logs curses TUI (1037 L)
│   ├── completion.py          ← --install-completion installer; bash completion sync to v0.8.2 + `cur="="` companion fix (v0.9.0)
│   ├── webhook.py             ← --webhook generic + Slack; HTTPS-only + BOB_WEBHOOK_ALLOW_INSECURE env var (v0.7.1 I-4); webhook URL credential redaction (v0.8.1 T74) — 455 L
│   ├── watch.py               ← --watch=N live monitoring; watch posture stickiness + ignore handling (v0.7.1 I-1, I-2)
│   ├── plugin_checks.py       ← user plugin loader (size-limited, ANSI-sanitized); delegates execution to _sandbox.SandboxRunner since v0.7.0 T3 (single path — trap door removed v0.9.0 TD-1)
│   ├── registry.py            ← ServiceRegistry.load()
│   ├── report.py              ← AuditReport, NullReport, file output; field labels i18n (v0.7.3 M-5); posture annotation propagation
│   ├── report_markdown.py     ← MarkdownReport, HTML email (816 L); Markdown signature drift fix (v0.7.1 I-5)
│   ├── json_output.py         ← --json / --json-full builder; **schema v3 only** (v1 retired v0.9.0 F-3, v2 retired v0.12.0 F9 — `SCHEMA_V3_*` + `_build_v3` are the only survivors) — posture_escalation block (v0.7.0 T1); per-domain `active`/`reason` (v0.12.1); uses engine.domain_scores cache (v0.7.4 M-7)
│   ├── csv_output.py          ← --format csv; **BREAKING v0.7.3 I-3**: column renamed "section" → "nature"
│   ├── html_output.py         ← --html standalone export; i18n via t (v0.7.2 M-4); section descriptions (v0.8.2 T39)
│   ├── markdown_output.py     ← --format markdown; i18n via t + level emoji prefixes (v0.7.2 M-4)
│   ├── sysinfo.py             ← system info, network context, get_user_home(), _is_private_or_loopback_ipv4/_ipv6 (single source of truth since v0.5.x)
│   ├── _paths.py              ← BOB_SHARE resolution (UFW_AUDIT_SHARE removed in v0.6.0)
│   └── _tty.py                ← safe_input + raw-mode read_line() + prompt_wizard() (Esc-to-cancel); EOFError swallow contract uniform (v0.6.1 I-2)
├── .ruff.toml                 ← v0.13.3 correctness-only lint gate (E9/F/B); nothing ignored since v0.14.0
├── scripts/lint_locales.py    ← v0.8.2 locale linter (EN/FR parity + placeholder sanity)
├── tests/                     ← 173 test files, ~5215 functions, 7557 collected (v0.15.2)
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

## Module index — bob/ root (43 `.py` files; 42 rows below — `__init__.py` is covered in the tree instead) + bob/cron/ + bob/checks/ssh/ + bob/tui/cron.py

| Module | LoC | Role |
|---|---:|---|
| `__main__.py` | 708 | Orchestrator: argv → AuditConfig → snapshots → run_checks() → display |
| `runner.py` | 940 | Audit engine: `run_checks()`, `_sec` closure factory (38 filterable + 10 always-on sections via unified `_SECTIONS: tuple[_Section, ...]` since v0.9.0 D-2; `_ALL_SECTIONS` + `_ALWAYS_ON_SECTIONS` kept as back-compat derived views), `_section_enabled()`, `validate_check_filters()` (v0.7.0 M-7 recognises always-on tokens; v0.9.0 D-1 raises fatal migration error via `_RENAMED_SECTIONS_V090 = SECTION_RENAMES_V090` re-import from `bob/_v090_renames.py`) |
| `cli.py` | 915 | `parse_args()`, `AuditConfig` dataclass, `--help` text, CLIError, `_VALUE_TAKING_OPTS` frozenset (v0.7.4 M); `--diff [PATH]` flag (v0.9.0 F-2); `--json-v1` retired (v0.9.0 F-3) — typing the flag now hits a hardcoded EN CLIError (`v0.9.1 hotfix`: inline string instead of pre-init `t()` to dodge bracketed-fallback `[cli.error.json_v1_retired]`); test guards `test_v091_cli_i18n_safety.py` pin both AST and emitted content |
| `config.py` | 427 | `UserConfig` (key/value config store) + `EmailStore` (email book) + `get_suid_whitelist()` accessor. `bob.config._EMAIL_RE` single source of truth (v0.5.x). Uses `_i18n_safe.make_fallback_t` since v0.8.2. Interactive prompts live in `manage_logs.py`, not here. |
| `profiles.py` | 424 | Profile loader: server/desktop/**workstation**/container + ~/.config/bob/profiles/*.conf. v0.8.1 BREAKING retired the `workstation → desktop` *alias*; `workstation.conf` is a first-class profile with its own overrides. A valid `-p NAME` is persisted as the operator's default (v0.12.1). |
| `scoring.py` | 839 | `ScoreEngine`, `Finding`, `Deduction`, `FindingLevel`, `ScoreCap`, `warn_with_deduction/alert_with_deduction` (v0.5.x), `set_posture/effective_level/posture_escalation` (v0.7.0 T1), `unpack_posture_escalation/set_posture_from_engine` helpers (v0.7.3); `ScoreEngine.apply` consults `bob._v100_subcheck_renames.any_legacy_ignore_matches` so v0.9.x ignore.yml umbrella entries (`ssh.x11_forwarding`, …) keep silencing the post-D-4 split sub-keys (v0.10.0); **v0.10.2 I-1**: `set_posture_from_engine` now matches `firewall_iptables.input_accept` (the v0.9.0 D-1 rename had left a stale `iptables_nft.input_accept` literal → iptables-only posture escalation silently dead 3 majors, masked by `firewall_inactive` branch) |
| `domain_scores.py` | 552 | `compute_domain_scores()`, `active_domains_from_engine()`, `apply_domain_score_override()` — 7 domains; `_PREFIX_TO_DOMAIN` (36 prefixes) explicit mapping (~32 prefixes since v0.5.x, fail2ban→ssh / virt→hardening / docker_audit→hardening now mapped) |
| `_atomic.py` | 139 | **v0.6.1** `atomic_write(path, content, *, mode=0o600)` — single source of truth. fsync(fd) + fsync(dir_fd) for crash-safety (v0.7.1 M-2), `tempfile.NamedTemporaryFile` unique tmp name (v0.7.2 M-7). **v0.14.1** adds the read side: `read_text_capped(path, *, max_bytes=8 MB)` refuses anything that is not a regular file (device / FIFO / directory) and bounds the read, after `--diff=/dev/zero` exhausted memory and `--diff=<fifo>` hung forever. Used by `_io.py`, `config.py`, `compare.py`, `history.py`, `recurrence.py`, `ignore.py`, `profiles.py`, `cron/_install.py`, `tui/cron.py` |
| `_sandbox.py` | 881 | **v0.7.0 T3** `SandboxRunner` — Tier 2 in-process restrictions for plugin execution (banned modules + bytes-limited stdout/stderr + timeout). **`BOB_SANDBOX_LEGACY=1` trap door removed v0.9.0 TD-1** (the `_run_legacy` path went with it — net −75 L). Threat-model recadré post sub-agent audit: sandbox is **defence-in-depth, not a security boundary** (real boundary = AppArmor / namespace). |
| `_i18n_safe.py` | 89 | **NEW v0.8.2** `make_fallback_t(labels)` returns a t-compatible callable for the 4 modules that needed pre-v0.8.2 `_fallback_t` (config/webhook/markdown_output/html_output); `t_or_hardcoded(key, fallback)` gates on `bob.i18n._initialized` for entry points that may fire pre-init (CLIError, catch-all `Exception` handler). Zero runtime side effects, cycle-free. |
| `_v090_renames.py` | 66 | **NEW v0.9.2** `SECTION_RENAMES_V090: dict[str, str]` (7 D-1 renames: `cron_audit`→`cron`, `docker_audit`→`docker_hardening`, `services_state`→`services_health`, `ports_analysis`→`ports`, `rules`→`firewall_rules`, `iptables_nft`→`firewall_iptables`, `firewall_stack`→`firewall_drivers`) + `remap_finding_key(key)`. Used by `runner.validate_check_filters` (fatal migration error path) AND `compare.load_baseline` (v0.9.2 — remaps `AuditBaseline.finding_keys` so v0.7.x/v0.8.x baselines compare cleanly against v0.9.0+ audits, kills the post-upgrade "resolved+new" diff noise). Extracted to break the `runner ↔ compare` circular import. |
| `_v100_subcheck_renames.py` | 126 | **v0.10.0** `SUBCHECK_RENAMES_V100: dict[str, str]` — **1** live entry since the v0.11.0 D-4 KILL removed the 13 inert ones; originally 14 covering Rank 1–8 D-4 splits (ssh x11/dsa/weak crypto, samba shares, kernel modules, auditd rules, journald, firewall duplicates). Helpers: `matches_legacy_ignore(finding_key, entry)` + `any_legacy_ignore_matches(finding_key, ignore_keys)`. **ignore.yml-only back-compat** — baseline diff for 1-to-N D-4 splits is NOT remapped (no defensible "1 → N expansion" semantics); first audit post-D-4 surfaces "1 resolved + N new", self-heals on the second audit. |
| `explain.py` | 1017 | `--explain` TUI + `EXPLAIN_KEYS` (169 keys, 45 prefixes) + `EXPLAIN_KEY_ALIASES` map (emptied v0.9.0 D-3; **first live entry v0.10.1** mapping the old `ssh.x11_forwarding` umbrella to the D-4 Rank 1 server/client split). v0.8.0 drift batch added 51 entries to cover WARN/ALERT findings previously emitted without --explain content; v0.10.1 added `ssh.x11.forwarding.client`. |
| `cis_refs.py` | 48 | CIS lookup with `lru_cache(maxsize=1)`, reads `data/cis_refs.json` (174 entries) |
| `display.py` | 903 | Terminal output: section boxes, finding emission, summary box, score bar; `_LEVEL_DISPATCH` table + `print_audit_summary` split into 3 helpers (v0.5.x); `_compute_posture_annotation` single helper (v0.7.2 M-10); A1 hypotheses footer in summary box (v0.8.0) |
| `output.py` | 675 | Low-level primitives: `print_ok/warn/alert/info/section/banner` |
| `panorama.py` | 66 | Services panorama table builder (after-audit summary) |
| `breakdown.py` | 187 | `--breakdown` / `-B` score computation transparency display |
| `exposure.py` | 202 | `compute_exposure()` — attack-surface table for the audit summary (synthesises firewall state + ports + network context + finding keys) |
| `formatter.py` | 119 | `format_finding()`, `format_deduction()` — locale-independent via `template_vars` |
| `i18n.py` | 306 | `t(key, **vars)`, locale auto-detect (POSIX), 2014 keys EN/FR |
| `compare.py` | 482 | `AuditBaseline`, `AuditDelta`, `build_baseline()`, `compute_delta()`, `display_delta()`. **v0.9.0 F-2**: `AuditBaseline.hostname` field + `BaselineLoadError` + strict-mode `load_baseline(path, strict=True)` for `--diff [PATH]` cross-machine compare. **v0.9.2**: `load_baseline` calls `bob._v090_renames.remap_finding_key` per entry to remap legacy section prefixes at load + `BaselineLoadError` raise sites use `_i18n_safe.t_or_hardcoded` for 4 new `compare.baseline_load.*` keys. |
| `correlation.py` | 134 | 6 compound-risk rules (`CorrelationRule` with frozensets) |
| `recurrence.py` | 102 | Recurring finding tracker: consecutive-audit counters |
| `history.py` | 191 | `--history` sparkline, JSONL append at `~/.config/bob/history.jsonl`, rotate@1000 |
| `ignore.py` | 201 | Persistent ignore list `~/.config/bob/ignore.yml`; canonical key regex validation (v0.7.1 M-3); `--unignore` symmetric helper (v0.8.1 T57). v0.10.0 D-4 back-compat for legacy umbrella entries is centralised in `scoring.py::ScoreEngine.apply`, not here. |
| `fixes.py` | 148 | `--fix` interactive UI with [y/N] prompts |
| `cron/` (package) | **1407** | Split in v0.6.0 from 1204 L monolith. `__init__.py` (101) re-exports the public surface incl. `datetime` + `_EMAIL_RE` · `_parse.py` (369) CronEntry + parsing + validators + MTA detection + day helpers · `_io.py` (158) delegates to `bob/_atomic.py` (v0.6.1) + `build_script_content` + `apply_cron_schedule` / `apply_cron_email` · `_install.py` (327) prompt_emails/prompt_email + plain wizard + `run_install_cron` · `_manage.py` (452) `_manage_email_store` + edit_cron_email/schedule + plain wizard + `run_manage_cron` |
| `tui/cron.py` | 949 | Curses TUI for `--install-cron` / `--manage-cron`; `_Schedule(IntEnum)` (DAILY/WEEKDAYS/MONTHDAYS/CUSTOM) + `_is_printable_input_char` helper (v0.5.x) |
| `manage_logs.py` | 1037 | `--manage-logs` curses TUI with score history chart; `_is_finding_continuation` helper + 3 bare `input()` now catch EOFError (v0.5.x) |
| `completion.py` | 74 | `--install-completion` → writes `/etc/bash_completion.d/bob`; v0.8.2 bash completion sync + v0.9.0 `cur="="` companion fix |
| `webhook.py` | 455 | Generic JSON / Slack payload + send (10s timeout); HTTPS-only + `BOB_WEBHOOK_ALLOW_INSECURE=1` escape hatch (v0.7.1 I-4; HTTPS:// prefix tolerance v0.7.3); URL credential redaction (v0.8.1 T74); `--test-webhook` smoke entry point (v0.8.2). Uses `_i18n_safe.make_fallback_t`. |
| `watch.py` | 171 | `--watch=N` live monitoring loop; posture stickiness + ignore key wiring (v0.7.1 I-1, I-2) |
| `plugin_checks.py` | 356 | `PluginCheck`, size-limited + ANSI-sanitized user plugin loader; **execution delegated to `_sandbox.SandboxRunner` since v0.7.0 T3** — single path now that the `BOB_SANDBOX_LEGACY` trap door is gone (v0.9.0 TD-1) |
| `registry.py` | 464 | `ServiceRegistry.load()`: bundle services.json + ~/.config/bob/services.d/ |
| `report.py` | 508 | `AuditReport` + `NullReport`, immediate flush, ASCII art header. `NullReport` is the canonical Protocol type since v0.5.x (`bob/watch.py:_NullReport` removed); field labels i18n (v0.7.3 M-5); posture annotation propagation (v0.7.0 I-3) |
| `report_markdown.py` | 816 | `MarkdownReport` + `send_html_email()` (multipart/alternative); XSS fix in `_safe_url` (html.escape with quote=True, v0.5.x); Markdown signature drift fix (v0.7.1 I-5); uses `_i18n_safe.make_fallback_t` since v0.8.2 |
| `json_output.py` | 386 | `build_json_data(..., schema_version=DEFAULT_SCHEMA_VERSION="3")` — **v3-only** (v1 retired v0.9.0 F-3, v2 retired v0.12.0 F9); `posture_escalation` block (v0.7.0 T1); per-domain `active`/`reason` (v0.12.1, ADV-1); uses `engine.domain_scores` cache when populated (v0.7.4 M-7). Module validates `schema_version` and raises `ValueError` for any value other than `"3"`. |
| `csv_output.py` | 112 | `--format csv` formatter; **BREAKING v0.7.3 I-3**: column renamed `section` → `nature` to match the Finding field it actually carries |
| `html_output.py` | 289 | `build_html_output()` standalone HTML (no JS, XSS-safe); i18n via `t` (v0.7.2 M-4); section descriptions (v0.8.2 T39); uses `_i18n_safe.make_fallback_t` |
| `markdown_output.py` | 246 | `--format markdown` formatter; i18n via `t` + level emoji prefixes (v0.7.2 M-4); uses `_i18n_safe.make_fallback_t` |
| `sysinfo.py` | 286 | `collect_system_info()`, `detect_network_context()`, `get_user_home()` (sudo-aware); `_is_private_or_loopback_ipv4/_ipv6` single source of truth since v0.5.x |
| `_paths.py` | 53 | `resolve_share_dir()`: BOB_SHARE only — `UFW_AUDIT_SHARE` legacy alias **removed in v0.6.0** after the v0.4.2 → v0.5.4 deprecation chain |
| `_tty.py` | 137 | `safe_input(prompt)` thin EOFError-swallowing wrapper around `input()` (v0.6.1 I-2), `read_line(prompt) → str|None`, Esc returns None, TTY fallback; `prompt_wizard()` helper added v0.5.x |

## Module index — bob/checks/ (47 checks)

> All but one follow the same shape: `XxxSnapshot.from_system()` collects raw data (only place with subprocess calls); `check_xxx(snapshot, t)` is pure logic, testable without mocks. **Exception: `services.py`** — `ServiceSnapshot` uses `.collect(registry, ufw_rules=..., ...)` / `.collect_all(registry, ...)` instead of `from_system()`, because it builds one snapshot *per service* from a registry rather than one snapshot of system-wide state. The active domain for each check is decided by `domain_scores._PREFIX_TO_DOMAIN`.

| Check | LoC | Domain (scoring) | Notes |
|---|---:|---|---|
| `firewall.py` | 479 | firewall | UFW state, `check_rules()` for duplicates / open-any (section name `firewall_rules` since v0.9.0 D-1; file still `firewall.py`) |
| `firewall_stack.py` | 242 | firewall | Docker iptables bypass, nftables parallel rules (section name `firewall_drivers` since v0.9.0 D-1) |
| `iptables_nftables.py` | 246 | firewall | Fallback audit when UFW inactive (INPUT/FORWARD policy) (section name `firewall_iptables` since v0.9.0 D-1) |
| `ipv6.py` | 318 | firewall | IPv6 listener vs UFW v6 rule consistency |
| `network_context.py` | 325 | firewall | Interface table, established TCP, sensitive remote ports |
| `services.py` | 615 | firewall | 38 known services, risk context, exposure classification; `_PRIVATE_ADDR` constant retired (v0.7.4 M) — now delegates to `sysinfo._is_private_or_loopback_ipv4`; +6 modern services in v0.8.0 T2 (32 → 38) |
| `services_state.py` | 220 | hardening | Boot-enabled but currently inactive security services (section name `services_health` since v0.9.0 D-1) |
| `ports.py` | 508 | firewall | Listening ports analysis, `_parse_ufw_covered_ports()` (v0.4.4 refactor) (section name `ports` since v0.9.0 D-1, was `ports_analysis`) |
| `logs.py` | 727 | hardening | UFW log analysis, brute-force, top IPs (GeoIP optional); hand-rolled private-IP regex retired — now delegates to `sysinfo._is_private_or_loopback_ipv4/_ipv6` (v0.5.6) |
| `log_rotation.py` | 337 | hardening | logrotate, journald persistence, SystemMaxUse |
| `auth_log.py` | 280 | ssh | SSH connection log, brute-force detection |
| `ddns.py` | 467 | firewall | DDNS client + crossed with open UFW ports |
| `docker.py` | 357 | firewall | iptables bypass detection, container port exposure |
| `docker_audit.py` | 295 | firewall | daemon.json hardening, privileged containers, sensitive mounts (section name `docker_hardening` since v0.9.0 D-1) |
| `virtualization.py` | 212 | firewall | KVM/VirtualBox/VMware/LXC + Snap network packages |
| `samba.py` | 339 | samba | SMBv1, signing, map-to-guest, bind interfaces |
| `smtp.py` | 193 | firewall (catch-all) | MTA exposure (Postfix/Exim/Sendmail) — prefix `smtp` not in `_PREFIX_TO_DOMAIN` |
| `hardening.py` | 275 | hardening | sysctl net.* / fs.* (rp_filter, send_redirects, syncookies…) |
| `kernel_hardening.py` | 193 | hardening | sysctl kernel.* (ASLR, ptrace_scope, kptr_restrict…) |
| `kernel_modules.py` | 487 | hardening | risky modules + apt kernel updates + installed listing (dpkg `ii` filter since v0.4.6) |
| `mac_policy.py` | 297 | hardening | AppArmor / SELinux state, 0-profile case |
| `updates.py` | 363 | updates | `apt-get -s dist-upgrade`, stale cache, cross-check (since v0.4.4); cache-age INFO option C when no security/regular finding (v0.5.3+) |
| `ssh/` (package) | **1524** | ssh | **Split in v0.6.0** from 1296 L monolith. `__init__.py` (64) re-exports for backwards-compat · `_directives.py` (202) `_BadDirective` + `_BAD_DIRECTIVES` + `_apply_bad_directive` + `_WEAK_CIPHERS/_WEAK_MACS/_WEAK_KEX` · `_snapshot.py` (207) 5 dataclasses (HostKeyInfo, PrivateKeyInfo, AuthorizedKeyEntry, KnownHostEntry, ClientConfigEntry) + SSHSnapshot · `_parsers.py` (446) pure parsers + RSA-bits + collect_host_keys + install probe · `_subchecks.py` (605) `check_ssh` + all `_check_*` helpers + v0.10.1 D-4 Rank 1 client-side `ForwardX11` detection (`ssh.x11.forwarding.client`) |
| `file_perms.py` | 303 | file_perms | /etc/passwd, /etc/shadow, sudoers, SSH host keys |
| `suid_audit.py` | 291 | hardening | SUID/SGID with whitelist (config.conf), targeted-roots scan |
| `user_accounts.py` | 238 | file_perms | UID 0 non-root, empty passwords, expired accounts |
| `password_policy.py` | 239 | hardening | PAM pam_pwquality/pam_cracklib, PASS_MAX_DAYS, login.defs |
| `umask.py` | 217 | hardening | login.defs, common-session, profile, current process |
| `cron_audit.py` | 304 | hardening | Pipe-to-shell (`curl/wget \| sh`), world-writable scripts, unexpected users with root crontabs (section name `cron` since v0.9.0 D-1). The cron *range* validator (`_validate_custom_cron`) lives in `bob/cron/_parse.py`, not here. |
| `disk.py` | 472 | disk | SMART (skip all-virtual since v0.4.4), partition usage, NVMe |
| `backup.py` | 266 | disk | borgmatic / restic / timeshift / duplicati / rclone |
| `memory.py` | 321 | hardening | SSD wear, unjustified swap, swappiness |
| `desktop_apps.py` | 152 | firewall (catch-all) | GUI app process detection (Brave, VSCode, ExpressVPN…) — prefix `desktop_apps` not in `_PREFIX_TO_DOMAIN` |
| `ntp.py` | 159 | hardening | systemd-timesyncd/chronyd/ntpd active + synced |
| `auditd.py` | 239 | hardening | Linux Audit Framework, loaded rules, sensitive file watches |
| `secure_boot.py` | 180 | hardening | UEFI state via mokutil/efivars/bootctl |
| `fail2ban.py` | 163 | firewall (catch-all) | Service state, jails, SSH jail detection — prefix `fail2ban` not in `_PREFIX_TO_DOMAIN` |
| `clamav.py` | 324 | hardening | DB freshness via mtime, last scan, daemon status |
| `file_integrity.py` | 210 | hardening | AIDE/Tripwire installation, DB existence, last check |
| `rootkit.py` | 233 | hardening | rkhunter / chkrootkit, DB age, scan age |
| `ssl_certs.py` | 317 | hardening | Let's Encrypt, /etc/ssl/private, nginx/apache2/postfix configs |
| `systemd_timers.py` | 282 | hardening | pipe-to-shell, world-writable scripts, user-created root timers |
| `firmware.py` | 277 | hardening | fwupd pending updates, CPU microcode package |
| `systemd_hardening.py` | 151 | hardening | **v0.13.0** `systemd-analyze security` exposure of running services; INFO-only, no deduction |
| `container_security.py` | 263 | hardening | **v0.13.0** container self-posture (CapBnd/seccomp/userns/rootfs via `/proc`); suppressed off-container; INFO-only |
| `socket_units.py` | 236 | hardening | **v0.13.1** orphan/failed `.socket` units (backing service gone/masked **or** `ActiveState=failed`, any of several triggers; merely-inactive is healthy); empty-`Triggers` internals never flagged; INFO-only |
| `cloud_context.py` | 225 | hardening | **v0.13.1** host-side cloud exposure (IMDS-on-link / world-readable user-data); conservative detection (DMI provider, or cloud-init + on-link IMDS); suppressed off-cloud, no cloud API; INFO-only |

---

## Dependency graph

### Centrality — modules most depended upon (top in-degree; recomputed at v0.14.1)

These are the **stability anchors**. Refactoring them needs care because many modules read from them.

| In-degree | Module | Why central |
|---:|---|---|
| 66 | `scoring` | Every check returns `CheckResult`; `Finding`, `Deduction` types touched everywhere |
| 53 | `checks._run` | Shared subprocess helper with `_C_LOCALE_ENV`, used by every check |
| 15 | `sysinfo` | `collect_system_info()`, `detect_network_context()`, `get_user_home()` (sudo-aware) |
| 14 | `output` | Terminal primitives + `sanitize()` / `sanitize_multiline()`. **Count with care**: 7 of the 14 importers use `from bob import output`, a form that a `from bob.output import` grep misses — that undercount briefly put this row at 10. `scoring.py` took a hard dependency in v0.14.1 (`Finding.__post_init__` sanitises through it), so `output.py` is bedrock too. |
| 9 | `_atomic` | `atomic_write()` + `read_text_capped()` (v0.14.1) — the file-I/O choke point |
| 8 | `report` | `AuditReport` + `NullReport` used by orchestrator + plugin checks |
| 8 | `domain_scores` | `apply_domain_score_override()`, `key_to_domain()`, etc. |
| 8 | `i18n` | `t(key, **vars)` + locale detection — imported by `__main__`, `runner`, `cli`, `output`, `formatter`, `history`, `cis_refs`, `_i18n_safe`. (This row was missing from the table until the v0.14.1 audit, despite outranking the three below it.) |
| 7 | `registry` | `ServiceRegistry` + `service_label_to_subkey` — consumed by runner, checks, display, explain |
| 7 | `config` | `UserConfig` + `EmailStore` — read by the orchestrator, cron, webhook and manage_logs |
| 6 | `_i18n_safe` | `make_fallback_t` / `t_or_hardcoded` — the English-fallback helper (v0.8.2) |
| 5 | `checks.ports`, `checks.services` | 2 core checks reused by display/exposure |

### Out-degree — modules with most outgoing imports (top 5)

These are the **integration points**. They're the entry/orchestration layer.

| Out-degree | Module | Why fan-out |
|---:|---|---|
| 59 | `runner.py` | Imports every check + scoring + display |
| 30 | `__main__.py` | Orchestrator wires runner + cli + report + i18n + sysinfo |
| 12 | `watch.py` | Wraps the full audit loop |
| 10 | `display.py` | Renders findings from many sub-modules |
| 9 | `json_output.py` | Builds full payload from many snapshots |

### Refactoring implication

- **scoring.py** and **checks/_run.py** are bedrock — touching them = risk of broad regression. Cover with extra tests before changing.
- **runner.py** has 59 outgoing imports → if you change a check's signature (e.g. `Finding.template_vars` migration), the impact lands here first.
- The orchestration layer (`__main__.py` + `runner.py`) is the **only place with heavy fan-out**. Everything else is a focused module → safe to refactor in isolation.

---

## Hotspots

### Biggest source files (top 15 — recomputed and re-sorted at v0.14.1)

> Since v0.6.0, the two former 1k+ L monoliths (`bob/checks/ssh.py`, `bob/cron.py`) are split packages. The biggest *single file* is still the curses TUI at 1037 L.

| LoC | File | Hotspot reason |
|---:|---|---|
| 1037 | `bob/manage_logs.py` | Full curses TUI: list + preview + score chart + multi-directory view |
| 1017 | `bob/explain.py` | EXPLAIN_KEYS (169 keys / 45 prefixes after v0.8.0 backfill + v0.10.1 client x11) + alias map (emptied v0.9.0 D-3, first live entry v0.10.1) + interactive TUI |
| 949 | `bob/tui/cron.py` | Curses TUI for cron wizards (extracted v0.4.1) |
| 940 | `bob/runner.py` | `_sec()` closure + unified `_SECTIONS` tuple (v0.9.0 D-2) + v0.9.0 D-1 fatal migration error path via `SECTION_RENAMES_V090` |
| 915 | `bob/cli.py` | `parse_args()` covers 43 long-form + 21 short options + `_VALUE_TAKING_OPTS` frozenset (v0.7.4) + `--diff [PATH]` (v0.9.0 F-2); `--json-v1` rejection branch with hardcoded EN fallback (v0.9.1 hotfix) |
| 903 | `bob/display.py` | Renders all sections + risk context blocks + summary box + posture annotation helper (v0.7.2 M-10) + A1 hypotheses footer (v0.8.0) |
| 881 | `bob/_sandbox.py` | v0.7.0 T3 plugin SandboxRunner (Tier 2 in-process restrictions); net −75 L vs v0.7.4 after v0.9.0 TD-1 retired `_run_legacy` + `BOB_SANDBOX_LEGACY` trap door |
| 839 | `bob/scoring.py` | ScoreEngine + Finding + Deduction + posture API (v0.7.0 T1) + v0.10.0 D-4 legacy-ignore shim wiring + v0.10.2 I-1 firewall_iptables literal fix |
| 816 | `bob/report_markdown.py` | Markdown report + HTML email (MIME multipart) |
| 727 | `bob/checks/logs.py` | UFW log parser + bruteforce + GeoIP + IoT detection |
| 708 | `bob/__main__.py` | Orchestrator: argv → AuditConfig → snapshots → run_checks() → display |
| 675 | `bob/output.py` | Low-level terminal primitives (grew with v0.5.x helpers) |
| 615 | `bob/checks/services.py` | 38 services × detection paths × risk classification (32 → 38 via v0.8.0 T2) |
| 605 | `bob/checks/ssh/_subchecks.py` | Biggest submodule of the ssh/ package (check_ssh + per-area helpers + v0.10.1 client x11 detection) |
| 552 | `bob/domain_scores.py` | Per-domain sub-scores + `_PREFIX_TO_DOMAIN` (36) + inactive-domain reason codes (v0.12.1) |

> The biggest *split package* totals: `bob/checks/ssh/` at 1524 L (across 5 files, largest sub 605 — grew with the v0.10.1 D-4 Rank 1 client x11 detection) and `bob/cron/` at 1407 L (across 5 files, largest sub 452). Both are net-larger than the pre-split monolith because the split added docstrings and re-export boilerplate, but per-file LoC is now well under the 1000-L soft ceiling.
>
> Notable shrink: `bob/json_output.py` dropped 545 L → 350 L in v0.9.0 F-3 when `--json-v1` and the entire v1 builder path (`_build_v1`, `_populate_v1_full_blocks`, `SCHEMA_V1_REQUIRED_KEYS`, `SCHEMA_V1_FULL_KEYS`) were retired. Cleanest "schema retrait" in the v0.7.x → v0.9.x cycle.

### Biggest test files (top 10 — recomputed and re-sorted at v0.14.1)

| LoC | File | Covers |
|---:|---|---|
| 1108 | `tests/test_manage_logs.py` | curses TUI flows (heavy fixturing) |
| 1043 | `tests/test_ssh.py` | sshd_config + host keys + user keys (covers the new ssh/ package via re-exports) |
| 974 | `tests/test_cron.py` | massive growth post-split (was 382 L) — covers cron/ package via re-exports + new helpers |
| 932 | `tests/test_kernel_modules.py` | risky modules + apt kernel + dpkg ii filter (v0.4.6) |
| 930 | `tests/test_cli.py` | argv parsing + AuditConfig + alias maps |
| 879 | `tests/test_services.py` | 38 services × detection paths × risk classification |
| 855 | `tests/test_domain_scores.py` | per-domain attribution + ScoreCap + TestActiveDomainsIncludesOK (v0.4.6) |
| 807 | `tests/test_logs.py` | UFW log parser + bruteforce + IoT dominance |
| 738 | `tests/test_scoring.py` | ScoreEngine invariants, caps, posture API, F1 headline rule |
| 725 | `tests/test_profiles.py` | profile inheritance + overrides + extends chain |

### Tests-to-code ratio (rough proxy for risk)

| Check / module | Source LoC | Test LoC | Ratio | Verdict |
|---|---:|---:|---:|---|
| `checks/ssh/` (package) | 1524 | 1043 | 0.68× | Tight coverage; SSH is critical so tested heavily. Post-v0.6.0 split, the test file still exercises the public `check_ssh` surface via `bob.checks.ssh.__init__` re-exports — no test churn needed; v0.10.1 client x11 split added dedicated cases |
| `checks/services.py` | 615 | 879 | 1.43× | Over-tested? Or service registry is genuinely complex |
| `checks/kernel_modules.py` | 487 | 932 | 1.91× | Heavily tested — Bug 1 fix (v0.4.6) added 5 tests on top |
| `domain_scores.py` | 552 | 855 | 1.55× | Scoring engine — critical, well tested |
| `cron/` (package) | 1407 | 974 (test_cron) + 344 (test_cron_audit) | 0.94× | **Refactor done (v0.6.0)** — was 0.60× before split. test_cron jumped from 382 → 848+ L during the v0.5.x → v0.6.0 cycle as the now-modular surface became easier to target |
| `manage_logs.py` | 1037 | 1108 | 1.07× | Curses UI — hard to test, but test_manage_logs grew significantly (882 → 1108) through the v0.5.x audit |
| `_sandbox.py` | 881 | (covered by test_plugin_sandbox.py) | tracked | v0.7.0 T3 plugin runner — tests pin Tier 2 restrictions + known-bad plugin suite; v0.9.0 TD-1 retired the legacy bypass path (−75 L) |
| `scoring.py` (posture API) | 839 | (covered by test_scoring.py + posture-specific cases) | high | v0.7.0 T1 + v0.7.3 helpers; posture escalation contract tested across consumers; v0.10.0 D-4 back-compat shim covered by `test_v092_baseline_i18n_and_shim.py` + D-4 ignore.yml tests; v0.10.2 I-1 iptables literal fix pinned by `test_v0102_posture_iptables_key.py` (7 tests + static AST guard forbidding live `iptables_nft.input_accept` comparisons) |
| `tui/cron.py` | 949 | (covered by test_cron) | low | **Still under-tested** — soft-ceiling candidate remaining after v0.6.0 splits; curses code dominates |

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

> Note: **36 of 47** checks use positional `, t` as above (incl. the four v0.13.x additions `systemd_hardening`, `container_security`, `socket_units`, `cloud_context`). The **11** keyword-only checks (`backup`, `cron_audit`, `disk`, `file_perms`, `kernel_modules`, `mac_policy`, `memory`, `password_policy`, `services_state`, `updates`, `user_accounts`) use `, *, t`. No module mixes the two forms. Both forms are valid — the codebase is mid-convergence, no decision yet on which becomes canonical.
>
> Note (v0.5.x): `CheckResult.warn_with_deduction()` and `.alert_with_deduction()` fuse the two-step `warn/alert(...) + add_deduction(...)` pattern into a single call. ~120 sites in `bob/checks/*.py` were migrated during the v0.5.0–v0.5.4 refactor (net −519 LoC). The two-step pattern still works (additive change), but new code should use the fused helpers.

**Why it matters**: pulls the I/O side effects to a single function (`from_system`), making `check_xxx` deterministic for unit tests. **Do not break this contract during refactoring** — it's the foundation for the ~6719-test suite running with no mocks.

### 2. Subprocess via `_run()` helper (every check *module* uses this)

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

`template_vars` is **additive** since v0.4.1 — three pilot checks (ssh, hardening, firewall) populate it. The remaining 44 checks ship without it and rely on `message` being pre-rendered. **Phase 2 Option A** is to migrate all checks to set `template_vars`, enabling fully locale-independent JSON output. Deferred to v0.5.0+.

### 5. The active domain set (v0.4.6 fix)

```python
# bob/domain_scores.py::active_domains_from_engine
_actionable = (FindingLevel.OK, FindingLevel.WARN, FindingLevel.ALERT)  # v0.4.6: OK added
```

A domain enters the global score average as soon as any check emits `OK`, `WARN`, or `ALERT`. `INFO`-only domains intentionally stay hidden. **This filter changed in v0.4.6** to fix a scoring inversion after remediation (Bug 2): when `apt upgrade` resolved a WARN, the domain went from "WARN at 8/10" to "OK at 10/10", and the old filter dropped it from the average → score *decreased*. The new filter keeps the now-clean 10/10 in the denominator.

### 6. ScoreEngine usage contract

```python
# v0.14.0: the engine carries the audit profile and applies its severity
# overrides inside apply(). A bare ScoreEngine() applies none — which is what
# left 8 shipped overrides dead until v0.14.0.
engine = ScoreEngine(profile=active_profile)
engine.apply(check_result_1)   # CheckResult may carry ScoreCap(s) via result.set_cap(...)
engine.apply(check_result_2)
engine.finalize()              # processes any caps registered, must come first
apply_domain_score_override(engine)  # then override global with domain average

score = engine.score           # int 0–10
level = engine.level           # RiskLevel.LOW / MEDIUM / HIGH / CRITICAL
```

> Caps are global ceilings (not per-domain) and are typically attached to a `CheckResult` from inside the check via `result.set_cap(maximum=N, reason=..., key="...")` — see `bob/checks/firewall.py:158` where firewall-inactive caps the global score at 3. `engine.cap(...)` exists too but is discouraged in orchestrators because it scatters cap logic away from the check.

**Critical ordering**: `finalize()` must run before `apply_domain_score_override()`. `engine.set_global_score()` should never be called directly — use the override helper.

---

## Frozen contracts (DO NOT BREAK)

### 1. JSON schema version `"3"` only (legacy `"1"` retired v0.9.0 F-3, `"2"` retired v0.12.0 F9)

`build_json_data(..., schema_version=DEFAULT_SCHEMA_VERSION)` dispatches on the version string. `DEFAULT_SCHEMA_VERSION = "3"` since v0.12.0 F9 (was `"2"` v0.7.0→v0.11.x). **v0.9.0 F-3 retired `--json-v1` and the entire v1 builder path** (`_build_v1`, `_populate_v1_full_blocks`, `SCHEMA_V1_*` removed, net −195 L); **v0.12.0 F9 bumped v2→v3** for the breaking count-key rename (`alerts`→`alert_count`, `warnings`→`warning_count`, for symmetry with `info_count`) — following the clean-cut rule, the v2 constants/builder became v3 in place and the module raises `ValueError` for any `schema_version` other than `"3"`. Within a major:

- Top-level keys cannot disappear, be renamed, or change semantics
- New top-level keys MAY be added (clients ignore unknowns)
- Nested dicts follow the same rule
- Breaking changes bump to `"4"` (next major)

Top-level always-present keys (v3): `schema_version`, `version`, `host`, `timestamp_utc`, `score`, `score_max`, `risk`, `network_context` (object `{context: …}`), `public_ip`, `alert_count`, `warning_count`, `info_count`, `deductions`, `posture_escalation` (object `applied`/`reason_key`/`score_level`), `domain_scores` (object; per domain `score` + `label` + `deductions` + **`active` + `reason`** — the last two new in v0.12.1 so a machine consumer can tell scored from shown-but-not-scored domains and reproduce the headline average). The v3 surface is pinned in `tests/test_json_schema_v2.py`. **Plus, since v0.14.x: `profile`** (the audit profile that produced the result — it changes severities and therefore the exit code) **and `degraded_sections`** (sections whose check raised and were degraded in place; empty list on a healthy run). `SCHEMA_V3_REQUIRED_KEYS` holds 17 keys.

`--json-full` additionally emits: `findings`, `services`, `open_ports`, `open_ports_all`, `deductions_raw`, `firewall_drivers` (always when full=True), plus `hardening` and `ipv6` (only when the respective snapshot is passed in). `firewall_stack` was renamed `firewall_drivers` by the v0.9.0 D-1 section rename. `network_context` is a dict in BOTH modes — the A-2 fix (v0.7.0) made it always an object; full mode only *enriches* it with `interfaces` / `connections_count` / `top_remote_ips`, it never changes its type.

### 2. Exit codes (stable public API)

| Code | Constant | Meaning |
|---|---|---|
| `0` | `EXIT_OK` | Clean audit |
| `1` | `EXIT_WARNINGS` | Warnings present |
| `2` | `EXIT_ALERTS` | Alerts present |
| `3` | `EXIT_ERROR` | Technical error (CLI parsing, IO, internal) |
| `4` | `EXIT_TARGET_MISSED` | `--target N` specified, score < N |

Codes only added, never removed/renamed within a major. Exposed in `bob.__main__`.

### 3. EXPLAIN_KEYS (169 keys, 45 prefixes)

`bob.explain.EXPLAIN_KEYS` is a frozen canonical list. Adding a new key = additive (no breaking change). Renaming a key = breaking, must go through the alias map (`EXPLAIN_KEY_ALIASES`). Removing a key = major bump. Audited against the locale namespace + canonical naming convention in `tests/test_explain.py` and `tests/test_explain_naming_convention.py` (v0.7.0 T2 Sub-scope C).

The `--explain KEY` interactive TUI shows: **title**, **WHY** it matters, **HOW** to fix, and a **CIS reference**. The first three (title/why/how) live in `en.json` and `fr.json` under `explain.{key}.{title,why,how}` and are validated for cross-locale parity by `test_locale_coverage.py::TestExplainNamespaceCoverage`. The CIS reference is sourced separately from `bob/data/cis_refs.json` (174 entries) via `bob/cis_refs.py::get_cis_ref(key)` — not stored in the locale files.

### 4. 7 domain keys

`bob.domain_scores.DOMAINS`: `['ssh', 'samba', 'file_perms', 'updates', 'hardening', 'disk', 'firewall']`. These are stable JSON keys; the human labels (`'SSH'`, `'Samba Security'`, etc.) live in `LABELS` and may change.

### 5. Section names: 38 filterable + 10 always-on (48 total)

`bob --check=list` prints the canonical lists. Filterable sections (`_ALL_SECTIONS` in `runner.py`) gate via `--check` / `--skip`. Always-on sections (`_ALWAYS_ON_SECTIONS`: firewall, firewall_rules, ufw_logging, firewall_drivers, network_context, services, ports, ddns, docker, virtualization — canonical v0.9.0 D-1 names) **run unconditionally** but `--check=firewall` no longer raises "matches no known section" since v0.7.0 M-7 — `validate_check_filters` recognises the token and warns that `--skip` on an always-on section is a no-op. New sections may be added; renaming = breaking. Verified by `test_cli.py`.

### 6. services.json plugin schema v1

`bob/data/schemas/service.schema.json` + `services-list.schema.json` + `plugin-file.schema.json` (Draft 2020-12). User plugins at `~/.config/bob/services.d/*.json` are validated at load time. Schema bumps from v1 to v2 = breaking change with explicit migration path via the `plugin-file.schema.json` `schema_version` wrapper.

### 7. CIS references (174 entries)

`bob/data/cis_refs.json`: stable mapping from finding key → `{ref, code}`. Adding new refs = additive. Removing/renaming = breaking (clients matching on `code` would break).

### 8. CSV column header (`--format csv`) — **BREAKING in v0.7.3**

Pre-v0.7.3 the column was labelled `section` but carried `Finding.nature` strings (`"action"` / `"improvement"` / `"structural"` / `""`) — not audit section names. v0.7.3 I-3 renamed the column header to `nature` to match the actual semantics. `nature` is **column 8** of 12 (`host, timestamp, score, risk, alerts, warnings, level, nature, message, detail, fix_cmd, note`) — and it was column 8 as `section` before the rename, so consumers parsing by *position* are unaffected; consumers parsing by *header name* break at upgrade. (Column 5 is `alerts`.)

### 9. Webhook URL scheme — HTTPS-only by default (v0.7.1 I-4)

`bob/webhook.py` rejects `http://` URLs unless `BOB_WEBHOOK_ALLOW_INSECURE=1` is set in the environment. Pre-v0.7.1 BOB happily POSTed audit content (host, IP, finding keys) over plaintext HTTP. v0.7.3 added `HTTPS://` prefix tolerance (case-insensitive scheme check) — pre-v0.7.3 a tool that uppercased the scheme got bogus "must start with https://" rejections.

### 10. Plugin sandbox boundary (`bob/_sandbox.py`) — **defence-in-depth, not security boundary**

v0.7.0 T3 introduced `SandboxRunner` (Tier 2 restrictions) as the **single execution path** for user plugins from `~/.config/bob/checks.d/*.py`. After a sub-agent threat-model audit, the public docs now state explicitly: in-process Python sandboxing in CPython is **not a security boundary** (PEP 416 frozen 2012 — see also the v0.7.0 T3 threat-model note). 3 PoCs documented escape vectors (pathlib.os smuggle / pickle RCE / real `__import__` via stdlib `__globals__`). Real boundary = AppArmor or namespace isolation (open improvement). The `BOB_SANDBOX_LEGACY=1` trap door that bypassed the sandbox **was removed in v0.9.0 TD-1** — there is now no opt-out of the SandboxRunner path.

---

## CLI surface — 43 long-form + 21 short options (alphabetical)

| Option | Section | Purpose |
|---|---|---|
| `--apply` | Remediation | **Execute** the fixes, interactively with a [y/N] prompt each. Requires `--fix`. |
| `--breakdown`, `-B` | Display | Show full score computation path |
| `--check=A,B,...` | Filters | Run only named sections |
| `--detailed`, `-d` | Audit | Write full report file (`~/.local/share/bob/logs/bob_*.log`) |
| `--diff[=PATH]`, `-D` | Comparison | Show only baseline delta; the value is optional — with a path, compares against an arbitrary baseline file (v0.9.0 F-2, cross-machine) |
| `--explain[=KEY]`, `-e` | Inspection | Structured per-finding explanation; `--explain list` for all |
| `--fix`, `-f` | Remediation | **Dry run** — preview the available fixes; nothing is executed without `--apply` |
| `--format=FMT` | Output | One of `json`/`json-full`/`csv`/`markdown`/`html`. Text is the default output when no format flag is set — it is not a valid value of `--format=`. |
| `--french` | i18n | Force French; auto-detected from `$LANG` otherwise (shortcut for `--lang=fr`) |
| `--help`, `-h` | Misc | Print help and exit (no sudo required) |
| `--history` | Comparison | Sparkline of last scores |
| `--html` | Output | Standalone HTML export |
| `--ignore=KEY` | Setup | Add a finding key to `~/.config/bob/ignore.yml` and exit (does not run the audit) |
| `--install-completion` | Setup | Install bash completion + sudo symlink |
| `--install-cron`, `-c` | Automation | Cron wizard (curses TUI + plain fallback) |
| `--json`, `-j` | Output | JSON short form (alias for `--format=json`); emits schema v3 (v2 retired in v0.12.0 F9) |
| `--json-full`, `-J` | Output | JSON full form (alias for `--format=json-full`); emits schema v3 (v2 retired in v0.12.0 F9) |
| ~~`--json-v1`~~ | Output | **Retired in v0.9.0 F-3** — passing it now raises a CLIError (hardcoded EN fallback per v0.9.1 hotfix). Schema v3 is the only emitted format. |
| `--lang=CODE` | i18n | Force language (`en` / `fr`); else POSIX auto-detect |
| `--log-days=N`, `-l N` | Audit | UFW log analysis window (default 7) |
| `--manage-cron`, `-C` | Automation | TUI to edit/delete cron jobs + email book |
| `--manage-logs`, `-m` | Automation | TUI to list/preview/delete reports |
| `--min-level=LEVEL` | Filters | Hide findings below severity. Valid values: `warn` or `alert` only (NOT `info` — `info` is the implicit floor). |
| `--no-color`, `-n` (alias `--no-colour`) | Output | Disable ANSI escapes |
| `--offline`, `-o` | Network | No outbound HTTP (public IP lookup + webhook off) |
| `--output=FMT` | Output | Full alias of `--format=` — accepts `csv` / `json` / `json-full` / `markdown` / `html`, case-insensitive (v0.12.1 E-fix + ADV-D2) |
| `--output-dir=PATH` | Audit | Override log dir for this run (non-persistent) |
| `--profile=NAME`, `-p NAME` | Audit | Apply profile (`server`/`desktop`/`workstation`/`container` + user). **A valid name is persisted** as the operator's default for later runs (v0.12.1); an invalid one warns and leaves the saved profile untouched |
| `--quiet`, `-q` | Output | Suppress all output, use exit code |
| `--reconfigure`, `-r` | Setup | Re-run first-launch config wizard |
| `--english` | Config | Force English output (symmetric counterpart of `--french`; overrides `$LANG` detection) |
| `--reset-baseline` | Comparison | Wipe `last_baseline.json` |
| `--test-webhook` | Integrations | POST a minimal smoke payload to the configured webhook and exit — no audit runs |
| `--unignore=KEY` | Filters | Remove a key from `ignore.yml` (counterpart of `--ignore`) |
| `--show-ignored` | Display | Show previously-ignored findings as dimmed lines during the audit (doesn't list `ignore.yml` entries — for that, read the file directly) |
| `--skip=A,B,...` | Filters | Inverse of `--check` |
| `--target=N` | Audit | Score gate; exit code 4 if score < N |
| `--verbose`, `-v` | Output | Show detailed port exposure per service |
| `--version`, `-V` | Misc | Print version |
| `--watch[=N]` | Comparison | Re-run every N seconds; the value is optional (default 60), minimum 10 |
| `--webhook=URL`, `-w` | Network | POST audit to webhook (Slack auto / generic) |
| `--webhook-format=FMT` | Network | Force webhook format (`auto`/`slack`/`generic`) |
| `--yes`, `-y` | Remediation | Auto-confirm all prompts |

> Note on `--check=list`: BOB has no separate `--list-checks` flag — pass `list` as the value of `--check` (`bob --check=list`) to print the 38 filterable + 10 always-on section names, each with a one-line description, plus the prefix-matching note — the 38 filterable section names. See `man bob(1)` for the full short-option table.

---

## File paths & env vars (external surface)

### Files (read/write at runtime)

| Path | Mode | Purpose | Lifecycle |
|---|---|---|---|
| `~/.config/bob/config.conf` | `0600` | User config (custom ports, log dir, suid_whitelist, email book, webhook defaults) | Created on first run; reconfigure with `--reconfigure` |
| `~/.config/bob/services.d/*.json` | r | User plugin services (extends `services.json`) | Created manually by user |
| `~/.config/bob/checks.d/*.py` | r | User plugin checks (Python files) | Created manually; **executed inside the `SandboxRunner` spawn child** (v0.7.0 T3) — see frozen contract #10. The parent never `exec`s plugin source. Since v0.14.1 the loader also rejects non-regular files and bounds the read. |
| `~/.config/bob/profiles/*.conf` | r | User audit profiles | Created manually |
| `~/.config/bob/ignore.yml` | `0600` | Persistent ignore list — written via `atomic_write(..., mode=0o600)` since v0.6.1 I-6 | Built with `--ignore=KEY` |
| `~/.config/bob/last_baseline.json` | `0600` | Baseline for `--diff` | Auto-rewritten after each audit; `--reset-baseline` clears |
| `~/.config/bob/history.jsonl` | `0600` | Score history (rotates at 1000) | Append-only after each audit |
| `~/.config/bob/recurrence.json` | `0600` | Consecutive-audit finding counter — `atomic_write(..., mode=0o600)`; relying on umask would leave it world-readable | Updated each audit |
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
| `BOB_DEBUG` | Set to any non-empty value to install a real logging handler (`bob/__init__.py`, v0.13.3) and print the full traceback on a fatal error |
| `NO_COLOR` | Any non-empty value disables colour ([no-color.org](https://no-color.org) semantics) — honoured since v0.13.3 |
| `FORCE_COLOR` | Any non-empty value forces colour ON even when stdout is not a terminal — the v0.14.0 escape hatch for the new TTY auto-detection |
| `BOB_WEBHOOK_ALLOW_INSECURE` | Set to `"1"` to permit `http://` webhook URLs. Default behaviour rejects plaintext to avoid leaking audit metadata (added v0.7.1 I-4). |
| ~~`BOB_SANDBOX_LEGACY`~~ | **Removed in v0.9.0 TD-1.** Previously bypassed the v0.7.0 T3 plugin sandbox; no longer honored — the `SandboxRunner` is now the only execution path. |
| `SUDO_USER` | Auto-detected — controls config path resolution and chown-back |
| `LC_ALL` / `LC_MESSAGES` / `LANG` | POSIX locale detection (`fr_*` → French, else English fallback) |
| `LC_TIME` | Not read directly, but forced to C through `LC_ALL=C` in `_C_LOCALE_ENV` for subprocesses — avoids `strptime("%b ...")` regressions under `LC_TIME=fr_FR.UTF-8` (v0.4.3 fix) |

> **Honoured since v0.13.3**: `NO_COLOR` env var — read in `bob/output.py::init()`, reaching the same state as the `--no-color`/`-n` CLI flag ([no-color.org](https://no-color.org) semantics: any non-empty value disables, empty is ignored). **Honoured since v0.14.0**: TTY auto-detection — `output.supports_color()` is now wired into `init()`, with resolution order `--no-color` → `NO_COLOR` → `FORCE_COLOR` (new escape hatch) → `isatty()`. Redirected output no longer carries ANSI; set `FORCE_COLOR=1` to restore the old behaviour. This was the BREAKING change flagged here as reserved for v0.14.0.

---

## Tests-to-source mapping (136 test files cover ~98 non-`__init__` modules)

Naming convention: `tests/test_<module_basename>.py` mirrors `bob/<module>.py` or `bob/checks/<module>.py`. Some shared tests:

| Test file | Covers |
|---|---|
| `test_scoring.py` | `bob/scoring.py` (engine, Finding, Deduction, FindingLevel, warn_with_deduction/alert_with_deduction helpers v0.5.x) |
| `test_domain_scores.py` | `bob/domain_scores.py` + active set + TestActiveDomainsIncludesOK (v0.4.6) |
| `test_domain_scores_mapping_complete.py` | AST-based parity check: every check prefix has a `_PREFIX_TO_DOMAIN` entry (v0.5.x) |
| `test_breakdown.py` | `bob/breakdown.py` (score transparency display) |
| `test_golden_scenarios.py` | End-to-end scoring scenarios — 32 tests across 9 classes (clean, hardened, desktop, poorly configured, firewall inactive, Debian minimal, tool caps, stability, multi-domain), introduced v0.3.0 |
| `test_json_schema_v2.py` | JSON output contract — frozen + drift detection (name kept from the v2 era; it pins the current v3 schema) |
| `test_services_schema.py` | Plugin services JSON Schema (Draft 2020-12) |
| `test_locale_coverage.py` | All `t()`/`_t()` keys exist in both `en.json` and `fr.json` (AST-based since v0.4.5; AST-coverage hardened in v0.5.x) |
| `test_template_vars_migration.py` | Phase 2 migration debt visibility (v0.4.2) |
| `test_compare.py` | Baseline + delta logic |
| `test_correlation.py` | 6 compound-risk rules |
| `test_recurrence.py` | Consecutive-audit counter |
| `test_exit_codes.py` | Exit code public API |
| `test_explain.py` | EXPLAIN_KEYS, alias map, freeze policy |
| `test_cis_refs.py` | 174 CIS references mapping |
| `test_degraded.py` | Graceful behavior when `ss` / `iptables` / `journalctl` absent |
| `test_html_output.py`, `test_csv_output.py`, `test_markdown_output.py` | Output formatters |
| `test_webhook.py` | Generic + Slack payload, `--offline` strict mode |
| `test_formatter.py` | Locale-independent reconstruction via `template_vars` (v0.4.1) |

---

## Architectural decisions (active, do not undo without discussion)

### Kept

- **Audit-only by default** (no auto-fix without explicit `--fix --apply`). Foundational security stance.
- **Zero runtime deps outside stdlib**. Major asset for distro packaging; preserve at all costs.
- **Snapshot + check_xxx separation**. Enables ~7557 tests with no mocks.
- **Equal-domain weighting** in global score. All active domains contribute equally — intentional, retained through v0.10.x. The "main architectural question for v0.3.0" was answered: keep equal weighting.
- **JSON schema_version dispatch** (v0.7.0 T2). `DEFAULT_SCHEMA_VERSION="3"` since v0.12.0 F9; the `"1"` legacy path and `--json-v1` were retired in v0.9.0 F-3, `"2"` in v0.12.0 (any non-`"3"` value now raises `ValueError`). Breaking changes = `"4"` + major bump.
- **EXPLAIN_KEYS frozen** with alias map for renames. 169 keys / 45 prefixes as of v0.10.1 (v0.7.0 baseline was 117 / 30; v0.8.0 drift batch backfilled 51 missing WARN/ALERT findings → 168 / 45; v0.10.1 D-4 Rank 1 added `ssh.x11.forwarding.client` → 169 and registered the first live `EXPLAIN_KEY_ALIASES` entry since v0.9.0 D-3 emptied it — see `tests/test_explain_coverage.py` whitelist for the closed-gap ledger).
- **`OK` in active domain set** (Bug 2 fix in v0.4.6). `INFO`-only domains stay hidden by design — terrain-validated boundary.
- **`bob/_atomic.py::atomic_write(path, content, *, mode=)` single source of truth** (v0.6.1). Every persistent write goes through a tmp + `os.replace` rename + explicit mode (no umask surprises) + `fsync(fd)` + `fsync(dir_fd)` for crash-safety (v0.7.1 M-2) + `tempfile.NamedTemporaryFile` unique tmp name (v0.7.2 M-7). The mode parameter exists specifically to support the cron wrapper script (0o755) regression seen in v0.5.7. Used by `_io.py`, `config.py`, `compare.py`, `history.py`, `recurrence.py`, `ignore.py`, `cron/_install.py`, `tui/cron.py`. **Do not re-introduce hand-rolled `open(tmp, 'w')` + `os.replace` snippets.**
- **`bob/_tty.py::safe_input` single EOFError-swallowing wrapper** (v0.6.1 I-2). Replaces every bare `input()` in non-curses contexts so that piped/non-TTY invocation never crashes with an uncaught EOFError. Do not call `input()` directly in new code.
- **Private-IP detection unified** to `sysinfo._is_private_or_loopback_ipv4/_ipv6` (v0.5.6 + v0.7.4 M for services.py). Single source of truth — the hand-rolled regex in `bob/checks/logs.py` and the `_PRIVATE_ADDR` constant in `bob/checks/services.py` were the last duplicates and are now retired. Do not re-introduce ad-hoc CIDR matching.
- **Posture escalation API** (v0.7.0 T1). `ScoreEngine.set_posture` records firewall-broken state; `effective_level` lifts the displayed risk; `posture_escalation` returns the floor + reason. Consumer outputs (text, JSON v3, HTML, Markdown, history, report.txt) all propagate via the `unpack_posture_escalation` defensive unpacker + `_compute_posture_annotation` display helper (v0.7.2 M-10). Decouples posture from raw score so a high-scoring host with `ufw inactive` still shows HIGH.
- **`SandboxRunner` as single plugin execution path** (v0.7.0 T3). `plugin_checks.py` delegates to `bob/_sandbox.py::SandboxRunner` — no direct `exec(plugin_src)`. The `BOB_SANDBOX_LEGACY=1` trap door was **removed in v0.9.0 TD-1** (no opt-out remains). Threat-model recadré (defence-in-depth, not security boundary).
- **HTTPS-only webhook by default** (v0.7.1 I-4). `bob/webhook.py` rejects `http://` URLs unless `BOB_WEBHOOK_ALLOW_INSECURE=1`. Prevents plaintext leak of host + IP + finding keys.

### Discarded (do not re-attempt)

- **M7 — Lazy `_PLUGIN_DIR` resolution.** Attempted in v0.4.3, broke 20 tests that patch `bob.registry._PLUGIN_DIR`. The "SUDO_USER changes mid-process" scenario doesn't happen in practice (BOB is one-shot per audit). Decision **permanent** (frozen 2026-05-15).
- **`registry.py` SUDO_USER import-time capture** — **kept, deliberately.** `_PLUGIN_DIR = get_user_home() / ".config" / "bob" / "services.d"` is resolved once at import (`registry.py:48`). BOB runs one-shot per audit, so "SUDO_USER changes mid-process" does not arise, and ~20 tests patch `bob.registry._PLUGIN_DIR` directly. This is the same decision as the M7 bullet above — the two must not be read as contradicting each other. (Before v0.14.1 this bullet said the opposite and would have led a maintainer to re-attempt exactly what M7 froze.)
- **`formatter.py` legacy API path** with optional positional `template_vars` — discarded; keyword-only since v0.4.1.
- **In-process Python sandbox as security boundary** — explicitly discarded after v0.7.0 T3 sub-agent threat-model audit (3 PoCs of escape: pathlib.os smuggle / pickle RCE / real `__import__` via stdlib `__globals__`). `bob/_sandbox.py` is defence-in-depth only; real boundary = AppArmor or namespace isolation (open improvement). Do not claim cryptographic isolation from the SandboxRunner in user-facing docs.
- **Pre-v0.7.3 CSV column header `"section"`** carrying `Finding.nature` strings — discarded as a misleading label. Header is now `"nature"` (breaking, audited via `test_csv_output.py`).
- **Hand-rolled IPv4/IPv6 private-range matching** in checks — discarded; delegate to `sysinfo._is_private_or_loopback_ipv4/_ipv6`.

### Deferred (still open after v0.14.1)

- **Phase 2 Option A — full `Finding.template_vars` migration** on the 44 non-pilot checks. Currently `template_vars` is additive on 3 pilots (ssh, hardening, firewall). Full migration would allow `Finding.message` to be derived from `(key, template_vars)` entirely, enabling locale-independent JSON output. **Largest single chunk of refactor work pending.** Did not land across v0.5.x → v0.10.x.
- **F-1 parallel checks** — `ThreadPoolExecutor` snapshot+check fan-out (Option B per the v0.10.0 thread-safety audit). **Tranché DEFER indéfiniment in the v0.11.0 plan — do not re-propose each cycle.**
- ~~**D-4 Rank 2–8 sub-check splits**~~ — **KILLED in v0.11.0**: the 13 inert shim entries were removed (behaviour-preserving); `SUBCHECK_RENAMES_V100` keeps the single live Rank 1 entry. Original note: — the remaining 7 ranked candidates (ssh dsa/weak crypto, samba shares, kernel modules, auditd rules, journald, firewall duplicates) after Rank 1 (ssh.x11) shipped in v0.10.1. Planned as a KILL bundle in v0.11.0. The `SUBCHECK_RENAMES_V100` shim already covers all 8 ranks for ignore.yml back-compat.
- ~~**M-3 ssh client `Host`-scope semantics**~~ — **SHIPPED in v0.11.0** (BREAKING): directives inside a restricted `Host` block are now scope-aware and emit `ssh.x11.forwarding.client_scoped` as INFO without deduction. Original note: — `_check_client_config` ignores `entry.host`, so directives in restricted `Host` blocks fire as if global (a contract leak surfaced by the v0.10.1 explain text recommending per-`Host` restriction). Needs design (which `Host` scopes WARN vs INFO?), applies to 4 directives at once. Planned for v0.11.0.
- **M3 cosmetic** — `os.path` → `pathlib` in remaining files. Pure cosmetic; partially absorbed during v0.5.x audits, but not driven to completion.
- **AUR PKGBUILD** — community contribution welcome.
- **Tighter AppArmor lock-down** — read-only on /etc/, /proc/, /sys/; deny exec of non-whitelisted; restrict network egress to known endpoints. Deferred to a future hardening pass — also the **real boundary** for plugin sandbox (see Discarded above).
- ~~**v0.8.0 deferred contract (D-1 to D-4)**~~ — D-1/D-2/D-3 shipped in v0.9.0; D-4 shim foundation v0.10.0, Rank 1 shipped v0.10.1, Rank 2–8 KILLED in v0.11.0. Contract fully closed.
- ~~**Compare breakdown diff**~~ — killed in v0.8.4 (zero user signal after 5 majors).

### Known debt (post-v0.14.1)

- `bob/manage_logs.py` (1037 LoC) — UI heavy, curses, but tests/source ratio is 1.07×. Accept as-is.
- `bob/_sandbox.py` (881 LoC, down from 956 after v0.9.0 TD-1 dropped the legacy bypass) — single-file sandbox runner. Soft-ceiling candidate but cohesive (single responsibility); split would scatter the in-process restriction policy. Accept as-is for now.
- `bob/tui/cron.py` (949 LoC) is the largest single-file curses unit after the v0.6.0 splits. Soft-ceiling candidate but works — touching curses code is high-risk-for-low-reward, and the v0.5.7 targeted audit already swept it.
- ~~`bob/checks/ssh.py` (1296 LoC)~~ **Done in v0.6.0** — split into the `bob/checks/ssh/` package (5 files, largest `_subchecks.py` at 605 L). Contract preserved via `__init__.py` re-exports.
- ~~`bob/cron.py` (1204 LoC)~~ **Done in v0.6.0** — split into the `bob/cron/` package (5 files, largest 452 L). Test file grew from 382 → ~850 L over the cycle.
- `bob/runner.py` `_sec()` closure pattern works but adds an extra layer of indirection. Was a refactor in v0.3.5 (-295L from previous form). Could potentially flatten further, but not urgent.

---

## CI matrix (validated cross-distro on every PR)

`.github/workflows/integration.yml` runs BOB inside containers of:
- Debian 12 (bookworm), Debian 13 (trixie)
- Ubuntu 22.04, 24.04, 25.04
- Kali Rolling
- Fedora 41

Each job asserts: exit code ≤ 3, no locale sentinel keys `[xxx.yyy]`, no Python tracebacks. Shipped 2026-05-17, currently 7/7 green.

`.github/workflows/tests.yml` runs the full pytest suite on Python 3.10 / 3.11 / 3.12 / 3.13 / 3.14 (matching the support policy declared in `pyproject.toml` classifiers), plus a separate `lint` job running the ruff correctness gate over `bob/` (v0.13.3; `.ruff.toml` ignores nothing since v0.14.0).

`.github/workflows/publish.yml` triggers on `v*` tag push: full tests + sdist/wheel build + PyPI publish via Trusted Publishing (OIDC, no token). PEP 440 pre-release tags (`v0.7.0b1`, `v0.7.0a*`, `v0.7.0rc*`) are handled since v0.7.0b1 cycle.

### Release-engineering CI guards (5 permanent + the ruff gate)

1. **integration-first** — the distro matrix is expected green before a release tag is pushed. This is a **convention, not an enforced edge**: `integration.yml` triggers on push/PR, `publish.yml` on `v*` tags with `needs: test → build → publish`; no dependency links the two workflows.
2. **smoke-after-commit** — `pip install .` non-editable + smoke import on CI (closes the v0.6.0/v0.6.1 wheel-missing-subpackage class — see `pyproject.toml::find = ["bob*"]` glob).
3. **version-consistency** — guards `bob/__init__.py::__version__` vs `pyproject.toml::version` vs `CHANGELOG.md` (closes the v0.7.0b1→b2 `__version__` drift).
4. **doc-version-consistency** — `tests/test_doc_version_consistency.py` (v0.8.0) pins **11 files** against `pyproject.toml::version` through 6 test functions (3 man pages, both `README_TECH`, `debian/changelog`, the rpm spec, and all 4 changelogs), so a release cannot ship with a doc still naming the previous version.
5. **smoke-plugin** — runs a known-good user plugin under `SandboxRunner` on `tests.yml` + `integration.yml` (closes the 4th release-engineering bug class identified during T3).

---

## Quick references

- **Add a service**: edit `bob/data/services.json` (38 entries, schema in `bob/data/schemas/`). No Python code change. See [README_DEV.md § Adding a service](README_DEV.md).
- **Add a language**: copy `bob/locales/en.json` → `bob/locales/de.json`, translate all 2014 values keeping the exact key tree, then append `"de"` to `SUPPORTED_LANGS` in `bob/i18n.py` (currently `("en", "fr")`). `cli.py` validates the *shape* since v0.14.1 (`_LANG_RE = ^[A-Za-z]{2,3}([_-][A-Za-z]{2,4})?$`, enforced by `_validate_lang`) — a well-formed but unsupported code still falls back to English, while a path-shaped value is rejected outright and `i18n.init()` falls back to `DEFAULT_LANG` if the file is missing.
- **Add a check** (full checklist):
  1. Create `bob/checks/foo.py` with `FooSnapshot.from_system()` + `check_foo(snapshot, t)` (follow the pattern of an existing simple check, e.g. `ntp.py`).
  2. Wire in `bob/runner.py`: add the import at the top, add a `_Section` entry to the `_SECTIONS` tuple (`bob/runner.py`, v0.9.0 D-2) — `_ALL_SECTIONS` is *derived* from it (`tuple(s.name for s in _SECTIONS if not s.always_on)`) and cannot be appended to, and invoke via `_sec("foo", foo_snapshot, check_foo)` in the appropriate GROUP block.
  3. Add locale keys to `bob/locales/{en,fr}.json`: at minimum a `sections.foo` title plus any `t("foo.xxx")` keys your check emits (validated by `test_locale_coverage.py`).
  4. Add the test file `tests/test_foo.py` (the suite will auto-discover it).
  5. Optional: add the prefix `"foo"` to `bob/domain_scores.py::_PREFIX_TO_DOMAIN` for scoring (else the check's findings fall into the `firewall` catch-all).
  6. Optional: add EXPLAIN_KEYS entries in `bob/explain.py` if you want `--explain foo.xxx` support.
- **Add an explain key**: append to `EXPLAIN_KEYS` in `bob/explain.py` + write title/why/how/CIS in both `en.json` and `fr.json`. `test_locale_coverage.py::TestExplainNamespaceCoverage` enforces parity.
- **Bump a version** — files to touch (verified with `grep -rl "<previous version>"` at each refresh; the CI `version-consistency` guard added in v0.7.0 catches drift across the source files but **not** the docs/changelogs/man pages — those still need manual touch):
  - **Source/build** : `bob/__init__.py::__version__` · `pyproject.toml::version` · *(the 3 schema `$id` URLs in `bob/data/schemas/*.schema.json` are deliberately **not** bumped — pinned at `v0.6.2` for eight minors; a `$id` is a published identifier, not a version stamp)*
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
| Python source (bob/) | 34,251 LoC across 103 files | `find bob -name '*.py' | xargs wc -l` |
| Tests | 173 test files, ~5215 functions, **7557 collected** (v0.15.2) | `pytest --collect-only -q` |
| Runtime deps outside stdlib | **0** | `pyproject.toml` |
| Optional runtime deps | `geoip2` (IP geolocation) | `pipx inject bodyguard-of-bits geoip2` |
| Distro CI matrix | 7 distros | `.github/workflows/integration.yml` |
| Python versions tested | 3.10, 3.11, 3.12, 3.13, 3.14 | `.github/workflows/tests.yml` + `pyproject.toml` classifiers |
| Locale keys | 2014 EN ↔ 2014 FR (strict parity) | `bob/locales/{en,fr}.json` |
| EXPLAIN_KEYS | 169 (in 45 prefixes) | `bob.explain.EXPLAIN_KEYS` |
| CIS references | 174 (106 CIS Ubuntu 22.04 + 7 CIS Docker + **1 CIS Red Hat 8/9** + 60 BOB-authored best-practice) | `bob/data/cis_refs.json` |
| Known services | 38 | `bob/data/services.json` |
| Score domains | 7 | `bob.domain_scores.DOMAINS` |
| `_PREFIX_TO_DOMAIN` mappings | 36 (since v0.5.x explicit table) | `bob.domain_scores._PREFIX_TO_DOMAIN` |
| Filterable sections (`--check` / `--skip`) | 38 | `bob --check=list` |
| Always-on sections (recognised by `--check` since v0.7.0 M-7) | 10 | `bob.runner._ALWAYS_ON_SECTIONS` |
| Audit profiles | 4 built-in (server / desktop / workstation / container — all first-class) + user | `bob/data/profiles/` |
| CLI options | 43 long-form + 21 short | `bob.cli.parse_args` |
| Doc files | 19 public markdown (13 in `DOCUMENTS/` + 6 at the repo root) + 3 man pages | `DOCUMENTS/` + `man/` |
| JSON schema_version | `"3"` only (v1 retired v0.9.0 F-3, v2 retired v0.12.0 F9) | `bob.json_output.DEFAULT_SCHEMA_VERSION` |
| Release-engineering CI guards | 5 — 3 workflow-level (integration-first / smoke-after-commit / smoke-plugin) + 2 pytest guards (`tests/test_version_consistency.py`, `tests/test_doc_version_consistency.py`) **plus the ruff correctness gate** (v0.13.3, `bob/` only, nothing ignored since v0.14.0) | `.github/workflows/*.yml` |
| Version | v0.14.1, released 2026-08-30. The container/nftables "teeth" remain deferred, but see the v0.14.1 finding above: nftables parity was never actually hardware-blocked | `pyproject.toml::version` |
| Supported branch | v0.14.x (everything ≤ v0.13.x is EOL — latest-minor-only policy) | `SECURITY.md` |
| First release | v0.1.0 (2026-04-26) | `CHANGELOG.md` |

---

© 2026 Cédric Clauzel
