*[Lire en français](CHANGELOG_FR.md)* · *[Full changelog](DOCUMENTS/CHANGELOG_FULL.md)*

# BOB — Changelog

| Version | Date | Summary |
|---------|------|---------|
| [v0.7.0b2](#v070b2) | 2026-05-31 | **Release-engineering hotfix for v0.7.0b1.** No code/contract/audit change — but `bob/__init__.py::__version__` was not bumped alongside `pyproject.toml` in the v0.7.0b1 ship commit, so the wheel correctly identified as `bodyguard-of-bits-0.7.0b1` on PyPI while every running-code output (terminal banner, `--version`, JSON `version` field, webhook payload, report header) reported `BOB v0.6.2` — exactly the lie the new banner was supposed to fix. Caught on the so6 Debian 13 VM during v0.7.0b1 beta validation (2026-05-31). PyPI does not allow re-uploading the same version → ship as v0.7.0b2 with both files in sync. New invariant test `tests/test_version_consistency.py::test_init_version_matches_pyproject_version` reads both values on every CI run + every local pre-ship pytest, asserting equality — any future single-file bump fails the suite before tag push. This is the 3rd release-engineering bug on v0.7.x after the v0.6.2 packaging discovery (wheels missing ssh/+cron/ subpackages) and the Phase 1 4ed2e3b crash (dict-vs-int from `engine.domain_scores`), and the third complementary guard pattern: integration-first + smoke-after-commit + version-consistency. Testers on v0.7.0b1: `pipx upgrade --pip-args="--pre" bodyguard-of-bits-beta` to get v0.7.0b2; `sudo bob-beta --version` should print `0.7.0b2`. All v0.7.0b1 testing observations remain valid — the misreport was UX-only, the audit logic was already v0.7.0 code. |
| [v0.7.0b1](#v070b1) | 2026-05-31 | **First pre-release of v0.7.0** — opt-in via `pipx install --pip-args="--pre" bodyguard-of-bits`. Stable users on v0.6.2 are NOT impacted. Bundles 15 commits across **Phase 1** (Python 3.14 ladder step 1; M-1 `parse_cron_file` time_simple flag + log; M-7 `--check`/`--skip` recognise always-on sections; **posture escalation** = new `ScoreEngine.set_posture()` + `effective_level` + `posture_escalation` property — a host with UFW OFF + score 8/10 now displays `HIGH risk (raised by posture: firewall inactive)` instead of misleading `LOW`; new EXPLAIN key `risk.escalated_posture`; CI publish.yml handles PEP 440 pre-release tags), **Phase 2** (**JSON schema v2 dispatch** = `build_json_data(..., schema_version="2")` is the new default, `--json-v1` flag preserves the legacy v0.6.x layout exactly; v2 fixes `network_context` type inconsistency P1, renames `timestamp`→`timestamp_utc`, adds `info_count`, `posture_escalation` block `{applied, reason_key, score_level}`, `deductions_raw`/`open_ports_all` in full mode, `domain_scores[d].deductions`; new file `tests/test_json_schema_v2.py` (30 tests written before impl per integration-first rule); **EXPLAIN_KEYS audit baseline** = 117 keys / 30 prefixes / 100% conformance with canonical `<prefix>.<finding_id>` snake_case pattern pinned by `tests/test_explain_naming_convention.py` (+710 parametrized assertions); B-2 retired during Step 1 of T2 because integration-first writing of the test revealed `firewall_stack.input_bypasses`/`forward_bypasses` are `list[str]` of rule descriptions and the plural naming was already correct; `DOCUMENTS/README_TECH.md` rewritten with v2 + v1 documentation + migration guide), and **Phase 2.1 hotfix** (sub-agent pre-T3 audit surfaced 5 important + 6 minor findings; 5/5 important + 4/6 minor shipped: **I-1+I-4** `effective_level` propagation to HTML, Markdown, history.jsonl was incomplete after Phase 1 — added the 3 missed sinks + `level_score_only` field in `history.jsonl` for trend analysis; **I-2** extracted `bob.scoring.unpack_posture_escalation` helper consolidating the defensive `getattr`+`try/except` pattern that was duplicated in display and missing in json_output — single source of truth ready for T3 plugin runner; **I-3** `set_posture` now rejects bool explicitly with a clear TypeError message (`isinstance(x, int)` returned True for bool, slipping through); **I-5** vacuous `assert ... or True` in `test_v2_posture_escalation_consistent_with_top_level_risk` rewritten to assert the explicit divergence shape; **M-4** dead `_SCHEMA_VERSION` alias removed (zero consumers via grep); **M-5** v1 risk test now pins the post-Phase-1 silent semantic shift against accidental revert; **M-1** `--check=list` output now lists the 10 always-on section names so the help text matches what M-7 accepts as input; **M-3** `report.write_summary` (.txt on-disk report) now surfaces the same posture annotation as the terminal summary box). 5391 → 5409 tests across the 15 commits, 0 regression. Smoke validated on so6desktop (Linux Mint 22.3) — audit completes end-to-end with score 8/10 + posture clean (UFW active), JSON v2 shows `posture_escalation.applied=false`, JSON v1 (`--json-v1`) preserves legacy layout exactly. Phase 3 (T3 plugin sandbox runner) is the next chunk and will bundle into v0.7.0 final ship. **Deferred to v0.8.0**: D-1 sections renumbering, D-2 fusion `_ALL_SECTIONS`+`_ALWAYS_ON_SECTIONS`, D-3 retrait aliases EXPLAIN_KEYS obsolètes, D-4 sub-checks granulaires. Beta testers welcome — `pipx install --pip-args="--pre" --suffix=-beta bodyguard-of-bits` keeps your stable v0.6.2 intact. |
| [v0.6.2](#v062) | 2026-05-29 | **Critical packaging hotfix.** Every wheel shipped since v0.6.0 was missing `bob/checks/ssh/` and `bob/cron/` — the two subpackages introduced by the v0.6.0 splits. Anyone who `pipx upgrade`d to v0.6.0 or v0.6.1 hit `ModuleNotFoundError: No module named 'bob.checks.ssh'` at startup. Root cause: `[tool.setuptools.packages.find].include` was a literal list `["bob", "bob.checks", "bob.tui"]` from a v0.4.x packaging audit — when v0.6.0 added `bob.checks.ssh` and `bob.cron`, the list wasn't updated. The wheel built but excluded both packages silently. Why undetected: tests + the pre-ship `sudo python3 -m bob` smoke ran from the working tree (where the source directories are visible regardless of packaging config); the `.github/workflows/integration.yml` step used `pip install -e .` (editable mode) which puts the repo root on `sys.path` and bypasses the packaging discovery entirely. Fix: changed `include` to the glob `["bob*"]` so any future subpackage is auto-discovered. CI hardened: integration jobs now use `pip install .` (non-editable, builds + installs a real wheel) AND a new explicit smoke step `python3 -c "import bob.checks.ssh; from bob.cron import CronEntry; from bob._atomic import atomic_write; from bob._tty import safe_input"` that fails fast if any v0.6.x-added module is missing from the wheel. No code changes other than the packaging config + workflow guard. 4600 tests unchanged. **Anyone running v0.6.0 or v0.6.1 via pipx must `pipx upgrade bodyguard-of-bits` to v0.6.2 to get a working install.** |
| [v0.6.1](#v061) | 2026-05-26 | First hardening release on the v0.6.x branch. Deep audit sub-agent surfaced 14 findings (0 critical + 6 important + 8 minor); 6 important + 4 minor shipped. **Atomic-write contract enforcement**: extracted `bob/_atomic.py::atomic_write(path, content, *, mode=)` as the single source of truth; migrated `bob/config.py` (2 sites), `bob/compare.py`, `bob/history.py`, `bob/recurrence.py` from their 5 hand-rolled implementations; **I-1** fixed the cron install paths (`bob/cron/_install.py`, `bob/tui/cron.py`) that were using raw `os.open(O_WRONLY \| O_CREAT \| O_TRUNC) + fdopen.write` on fresh installs — power-loss between truncate and write left the cron file empty (v0.5.7 #I-3 had closed the mutation path but missed the creation path); **I-6** fixed `bob/ignore.py` writing non-atomically — power-loss / OOM corrupted ignore.yml. `bob/cron/_io.py::_atomic_write` kept as a backwards-compat alias for the test patch target. **I-2 EOF contract completion**: new `bob/_tty.safe_input(prompt)` wrapper + `prompt_wizard()` now catches `EOFError` (was raising); 11 bare `input()` sites in `bob/cron/_install.py` (5), `bob/cron/_manage.py` (5), and `bob/fixes.py` (1) migrated to `safe_input`. **I-3** `bob/cron/_parse.py::_validate_cron_field` now rejects step values exceeding the field range (`*/200` for minute 0-59 was previously accepted → cron interpreted as "every 200 minutes" = never fires). **I-4** `shlex.quote()` applied to 8 `cmd=f"..."` sites in `bob/checks/ssh/_subchecks.py` (4) + `bob/checks/file_perms.py` (3) + `bob/checks/firmware.py` (1) where paths from `pwd.getpwnam(SUDO_USER).pw_dir`, filesystem scans, or `dpkg-query` output could contain spaces and silently mis-target `--fix --apply`. **I-5** `bob/history.py::save_score` first-write now creates `history.jsonl` with explicit mode `0o600` via `os.open(O_WRONLY \| O_APPEND \| O_CREAT)` instead of inheriting the default umask (typically 0o644 → world-readable score timestamps). **Minor fixes shipped**: M-2 redundant double-`.lower()` in `_apply_bad_directive`; M-3 `MaxAuthTries=-1` now falls back to default 6 (was accepted); M-6 `bob/__main__.py` fatal-error handler now hints "Set BOB_DEBUG=1 for full traceback" and prints traceback when set; M-8 `--watch=N` error wording aligned ("integer ≥ 10" instead of misleading "positive integer"). +17 regression tests in `tests/test_atomic_v061.py` (12) + `tests/test_cron.py::TestStepBoundedToFieldRange` (5). 4583 → 4600. JSON contract, EXPLAIN_KEYS, keybindings, no-curses fallback, exit codes — all preserved. |
| [v0.6.0](#v060) | 2026-05-25 | **Major bump** — opens the v0.6.x branch. Two architectural splits + one sunset, all contract-preserving via package re-exports. **#13 split `bob/checks/ssh.py` (1296 LoC monolith) → `bob/checks/ssh/` package** with 4 modules: `_directives` (165L: `_BadDirective` table + `_BAD_DIRECTIVES` + `_apply_bad_directive` + weak crypto reference sets), `_snapshot` (198L: 5 dataclasses + `SSHSnapshot` + `SSHSnapshot.from_system`), `_parsers` (446L: pure parsers for sshd_config / authorized_keys / known_hosts / client config + key-type / RSA-bits helpers + `_collect_host_keys` + `_detect_ssh_install_cmd` + `_parse_time_seconds`), `_subchecks` (529L: `check_ssh` entry point + all `_check_*` per-area helpers). **#14 split `bob/cron.py` (1204 LoC monolith) → `bob/cron/` package** with 4 modules: `_parse` (330L: `CronEntry` + `parse_cron_file` + `list_installed_crons` + `cron_to_human` + `build_schedule_expr` + validators + day helpers + MTA detection + constants), `_io` (164L: `_atomic_write` + `build_script_content` + `apply_cron_schedule` + `apply_cron_email`), `_install` (319L: `prompt_emails` / `prompt_email` + `_run_install_cron_plain` + `run_install_cron` + `_CronQuit` exception), `_manage` (445L: `_manage_email_store` + `edit_cron_email` + `edit_cron_schedule` + `_run_manage_cron_plain` + `run_manage_cron`). Both packages preserve the full v0.5.x public API via `__init__.py` re-exports — `from bob.checks.ssh import check_ssh, SSHSnapshot, …` and `from bob.cron import CronEntry, run_install_cron, _EMAIL_RE, datetime, …` continue to work unchanged. **Sunset: `UFW_AUDIT_SHARE` legacy env var removed** (announced "REMOVED in v0.6.0" in v0.5.4 deprecation warning — honored). Only `BOB_SHARE` is now accepted; installers still setting the legacy alias will see no effect. Two AST-scanning tests (`tests/test_template_vars_migration.py`, `tests/test_domain_scores_mapping_complete.py`) updated to recurse into check packages (one-line `glob` → `rglob` shift). One regression test (`TestApplyCronScheduleAtomic`) updated to patch the new `bob.cron._io._atomic_write` site instead of the package-level re-export. 4583 tests inchangés (zero net delta — splits + sunset are wire-equivalent). LoC: ssh.py 1296L → 4 modules (max 529L), cron.py 1204L → 4 modules (max 445L). Largest check module is now `ssh/_subchecks.py` at 529L, well below the project's soft 1000-LoC ceiling. JSON contract (`schema_version="1"`), 116 EXPLAIN_KEYS, keybindings, no-curses fallback, exit codes — all preserved. **Closes the deferred architectural roadmap from v0.5.x.** |
| [v0.5.8](#v058) | 2026-05-25 | Cleanup of the 5 cosmetic minors explicitly deferred by v0.5.7. **M-2** `manage_logs.py` cursor shift after delete now only counts deletions ≤ cursor (pre-fix: `cursor -= deleted` shifted by the full count even when most deleted items sat AFTER the cursor — visible cursor displacement on multi-selection deletes mixing items before+after the active position). **M-5** schedule wizard constants promoted from local `_, _SCHEDULE_WEEKDAYS, _SCHEDULE_MONTHDAYS, _SCHEDULE_CUSTOM = 1, 2, 3, 4` tuple unpack to a module-level `_Schedule(IntEnum)` with explicit `DAILY`/`WEEKDAYS`/`MONTHDAYS`/`CUSTOM` names — 3 call sites updated, IntEnum preserves `choice == _Schedule.WEEKDAYS` semantics so wire-equivalent. **M-6** `_extract_summary_view` `summary_start: int \| None = None` sentinel replaces `summary_start = 0` falsy check — handles the (unreachable in practice but semantically wrong) edge case where the SEP62 separator sits at line 0. **M-7** new `_is_finding_continuation(line)` helper stops the 4-space-indent grouping at any boundary that obviously belongs to a different finding (`[ALERT]`/`[WARN]`/`[OK]`/`[INFO]` markers) or a section delimiter (`┌`/`└`/`│`/`━`/`╔`/`╠`/`╚`/`║`) — defends against over-greedy grouping of subsequent indented content. **M-8** `from datetime import datetime` lifted to module-level in both `bob/cron.py` and `bob/tui/cron.py`; 3 local imports removed (`_run_install_cron_plain`, `build_script_content`, install cron curses path). +12 regression tests across `tests/test_cron.py` (TestScheduleIntEnum, TestDatetimeImportLifted) and `tests/test_manage_logs.py` (TestCursorShiftAfterDelete, TestSummaryStartSentinel, TestIsFindingContinuation). 4571 → 4583 tests. JSON wire format unchanged, EXPLAIN_KEYS unchanged, keybindings unchanged, no public API removals. **Closes the v0.5.x deep-audit campaign — branch fully audited (25 modules deep-audit + ~25 spot-checked, 0 critical findings outstanding).** Next minor (v0.6.0) reserved for #13 (ssh.py split) and #14 (cron.py split) — the two deliberately-deferred architectural refactors. |
| [v0.5.7](#v057) | 2026-05-24 | Targeted hardening pass on curses TUI (`bob/manage_logs.py` 999 LoC + `bob/tui/cron.py` 920 LoC = ~1920 LoC) — the bucket explicitly deferred by the v0.5.5 / v0.5.6 audits. 11 findings from a focused sub-agent: 0 critical, 3 important (I-1 `_curses_readline` accepted curses `KEY_*` keypad codes via `chr(ch_i)` — pressing arrows or function keys inserted Greek/Unicode glyphs like `Ι` / `Ω` into name/email/days/time/custom-expression input buffers; no security impact thanks to downstream `_EMAIL_RE` / `_validate_custom_cron` / digit-only filtering, but visibly corrupted UX. New `_is_printable_input_char(ch_i)` helper bounds inputs to printable Latin-1 only · I-2 three `input()` sites in `prompt_path` + move-logs confirmation + delete-all confirmation didn't catch `EOFError` so Ctrl-D dumped a Python traceback on cancel — now matches the `_rl()` convention treating EOF as empty input · I-3 `apply_cron_schedule` used raw `os.open(O_WRONLY \| O_CREAT \| O_TRUNC) + fdopen.write` instead of the project's `_atomic_write` helper. Power loss or `SIGKILL` between `open(O_TRUNC)` and `write` would leave the cron file empty → cron silently drops the entry, no notification. Asymmetric with `apply_cron_email` which already used `_atomic_write`. Same `mode=0o640` enforced), 3 minor (M-1 status `manage_logs.deleted_one` displayed `pending_delete[0].name` even when index 0 failed to delete and only a different index succeeded under selective permission errors — now tracks the first successfully-deleted name · M-3 dead-code `if ch_i == ord("1"): chosen = 0 elif chosen = 1` inside `_curses_edit_sub` simplified, elif guard rewritten with explicit parentheses · M-4 duplicate `from bob.cron import apply_cron_schedule, apply_cron_email` consolidated into the main import block). +11 regression tests across `tests/test_cron.py` (TestApplyCronScheduleAtomic, TestIsPrintableInputChar) and `tests/test_manage_logs.py` (TestEOFErrorOnPromptPath, TestEOFErrorOnMoveConfirm, TestEOFErrorOnDeleteAllConfirm, TestDeletedOneCorrectName). 4560 → 4571 tests. JSON wire format unchanged, EXPLAIN_KEYS unchanged, no public API additions. UX-visible deltas: clean Ctrl-D exit (no traceback), arrow/function keys no longer print garbage into TUI prompts. Deferred to v0.5.8 (5 cosmetic findings not worth churn now): M-2 cursor-shift assumes deletions sit before cursor · M-5 schedule wizard local-scoped constants → module-level / IntEnum · M-6 `summary_start` falsy check misses index 0 (unreachable in practice) · M-7 over-greedy continuation grouping in `_extract_summary_view` · M-8 local `from datetime import` lifted to module top. After v0.5.7, v0.5.x branch fully audited (22 core + logs.py + 2 TUI = 25 modules deep-audited + ~25 spot-checked). |
| [v0.5.6](#v056) | 2026-05-24 | Targeted hardening pass on `bob/checks/logs.py` (662 LoC UFW log parser) — module explicitly deferred by the v0.5.5 audit because of regex density. 10 findings from a focused sub-agent: 0 critical, 2 important (I-1 private-IP regex inconsistent with `sysinfo.py` — missed CGNAT 100.64/10 + IPv6 link-local fe80::/10 + false positives on any string starting with `fc`/`fd`; I-2 year-rollover silently dropped near-realtime syslog events 1s ahead of wall-clock by rolling back a full year), 8 minor (M-1 `[UFW BLOCK6]` IPv6 variant silently ignored — anchored regex now catches both; M-2 `_count_available_days` regex restricted to English month names; M-3 GeoIP path order City-before-Country across all dirs; M-4 `geoip2_status()` accepts symlinks like `_geo_via_geoip2` does; M-5 `_GEO_CACHE` bounded at 2048 with FIFO eviction; M-6 binary-mode `tell()`/`seek()` arithmetic (TextIOBase opaque-cookie compliance); M-7 redundant `subprocess.TimeoutExpired` dropped from except tuple; M-8 `proto` normalised to upper at parse time so a downstream lowercase build can't silently split a bruteforce campaign). +15 regression tests in `tests/test_logs.py` covering each fix class. Single-module pass, single commit. 4545 → 4560 tests. JSON contract preserved. Wire output unchanged on hosts with standard UFW configs; visible only on hosts emitting `[UFW BLOCK6]` (previously dropped — now counted) or with non-English locale syslog logs (previously inflated days_available — now accurate). |
| [v0.5.5](#v055) | 2026-05-24 | Hardening pass — 4 real bugs (C-1 to C-4) + 4 security smells (I-1 to I-4) + 11 minor cleanups (M-1 to M-11) from a deep audit sub-agent. **C-1**: `apply_cron_email()` was rewriting wrapper scripts via `_atomic_write()` which forced mode `0o600` — scripts lost their `0o755` executable bit and cron silently stopped running the audit. `_atomic_write()` now takes `mode=` explicitly; cron file rewrites pass `0o640`, scripts pass `0o755`. **C-2 + C-3 + M-11**: 3 finding `cmd=` values contained `&&` (shell operator rejected by `_has_shell_ops`) or a decorative Unicode arrow → `--fix --apply` rejected them silently. Demoted `password_policy.no_quality_module` + `password_policy.weak_minlen` from `nature="action"` to `nature="improvement"` (visible in summary box under "Améliorations possibles" instead of "À corriger") + split `services_state.service_inactive` cmd to drop the `&&` chained `journalctl` (moved to `note=` guidance). **C-4**: `bob/checks/services_state.py` emits `services_state.service_inactive` but `EXPLAIN_KEYS` declared `services_state.enabled_inactive` — `bob --explain` returned "key not found". Fixed via `EXPLAIN_KEY_ALIASES` (conservative — preserves JSON output contract). **I-1**: `recurrence.py` + `ignore.py` wrote state files with process umask (typically world-readable `0o644`) instead of `0o600` like every other `~/.config/bob/` file. **I-2**: post-`finalize()` calls to `_apply_deduction` silently bypassed score caps — now logs WARNING and discards. **I-3**: `_safe_url` in markdown email HTML didn't re-escape attribute context — a crafted URL containing `"` could break out of `href=""`. Now uses `html.escape(..., quote=True)`. **I-4**: `sysinfo._PRIVATE_IPV4_RE` brittle regex (with `removeprefix("^")` hack) replaced by explicit `ipaddress.ip_network` membership checks; works around Python 3.12+ widening `is_private` to include documentation ranges. **M-1**: 3 duplicate email regex sites unified via `bob.config._EMAIL_RE`. **M-2**: `bob/watch.py:_NullReport` removed in favour of canonical `bob.report.NullReport` (Protocol type introduced in v0.5.0 #10). **M-3**: 3 dead locale keys removed (`_meta.lang`, `_meta.version`, `ignored.hint`). **M-4**: `corr.fully_blind` rule was asymmetric — required `fail2ban.not_installed` but ignored equally-blind `fail2ban.service_inactive`. Widened to fire when any detection layer is blind. **M-7**: extract `_has_actionable_findings()` helper in `updates.py` (clearer than inline-key-blacklist of `apt_cache_age`). **M-8 + M-9**: clarifying comments in ssh.py (Match block Include skip) and ports.py (process/iface empty semantics). **M-10**: `apply_cron_schedule` regex tightened with first-field cron-token anchor so comment lines containing "root /path" are no longer rewritten. **M-6 (separate commit)**: `Optional[X]` / `List[X]` → `X \| None` / `list[X]` sweep across 18 modules — Python 3.10+ syntax. 4538 → 4545 tests (+7 regression coverage). Net diff: 23 code files, +312 / −112 = +200 LoC. Score on dev host unchanged (8/10); the password_policy `nature` change visibly shrinks the "À corriger" block on hosts without pwquality. |
| [v0.5.4](#v054) | 2026-05-22 | Refactor v0.5.x Phase 5 of 5 (final) — **#6 + #9 + #15b + cache APT option C**. **#6 `prompt_wizard()` helper** in `bob/_tty.py` (translation-agnostic wrapper around `input()` with uniform `q`/`quit` cancel + default-on-Enter) replaces 10 raw `input()` sites in `bob/cron.py` install + edit wizards. **#9 UFW_AUDIT_SHARE sunset** — `bob/_paths.py:resolve_share_dir()` upgraded `logger.info(...)` → `logger.warning(...)` with explicit "DEPRECATED since v0.5.4, will be REMOVED in v0.6.0" message; legacy env var still functional today. **#15b explicit `_PREFIX_TO_DOMAIN` mapping** — three v0.4.x silent catch-all fallbacks moved out of the firewall catch-all: `fail2ban` → `ssh` (primary purpose is SSH anti-bruteforce), `virt` → `hardening` (KVM/bridge bypass is kernel/system surface), `docker_audit` → `hardening` (container hardening / daemon.json security). `smtp` and `desktop_apps` stay catch-all by design (no clean domain fit). **Cache APT option C** (new metier feature) — `bob/checks/updates.py` adds an INFO `updates.apt_cache_age` line when no security/regular updates are pending AND the cache age is below the stale threshold, giving permanent transparency about how fresh the "system is up to date" verdict actually is. Surfaced by Ubuntu VM terrain testing on 2026-05-22 where a dormant VM returned "à jour" despite 8 pending LTS security updates upstream. **#13 (ssh.py split, 1324 LoC) and #14 (cron.py split, 1223 LoC) deferred to v0.6.0** — per conservative-refactor principle, splitting >1000-LoC files for marginal readability gain doesn't pass the gain × risk test in a contract-preserving release. Net diff: 12 files changed, +118 / −69 = +49 lines (cron.py +1 net, _tty.py +24, updates.py +20, domain_scores.py +10, _paths.py +5, locales +4 keys, tests −6 net). 4538/4538 tests unchanged. Wire output diff vs v0.5.3 is intentional: new INFO line in section MISES À JOUR SYSTÈME on hosts with cache + no pending updates, and per-domain score reshuffle on hosts emitting `fail2ban.*` / `virt.*` / `docker_audit.*` findings. Closes the v0.5.x audit (15/15 findings addressed, 2 deferred with justification). |
| [v0.5.3](#v053) | 2026-05-22 | Refactor v0.5.x Phase 4 — **#5 + #12 + #8**. **#5 `_LEVEL_DISPATCH` table** in `bob/display.py` collapses the 4-branch OK/WARN/ALERT/INFO cascade in `display_result()` to a single dispatch loop driven by a frozen `_LevelTraits(report_label, threshold_key, print_fn, has_recurrence, has_body, detail_unconditional, show_note, show_cis)` dataclass. The 4-row table captures per-level behaviour declaratively; the special-case ALERT path that prints detail unconditionally (even without `--verbose`) is now expressed as `detail_unconditional=True` rather than an imperative branch. **#12 `print_audit_summary` split** — the 142-line function is broken into 3 focused helpers (`_summary_header_lines`, `_summary_findings_lines`, `_summary_breakdown_lines`) plus `_add_finding_lines` extracted from inner-function to module-level. The orchestrator becomes a 3-line assembler. **#8 `CheckResult.log_data` removed** — the typed-dict escape hatch on `CheckResult` is replaced by a tuple return from `check_logs(...) -> (CheckResult, LogReportData | None)`. New frozen dataclass `LogReportData(log_days, days_available, total, brute_hits, top_ips, top_ports, svc_hits)` in `bob/checks/logs.py`. `runner.py` unpacks the tuple; `display_log_results` takes the report as an explicit arg. **Net diff: 5 files changed, +109 / −69 = +40 lines** (display.py +23 for explicit helper signatures, logs.py +19 for `LogReportData`, scoring.py −1 for removed field). 4538/4538 tests unchanged — 3 tests renamed (`test_log_data_*` → `test_report_data_*`), ~20 test sites use tuple unpack. Wire output bit-identical to v0.5.2. |
| [v0.5.2](#v052) | 2026-05-22 | Refactor v0.5.x Phase 3 — **#4 + #3**. **#4 SSH directive table** : nouvelles `_BadDirective` dataclass + `_BAD_DIRECTIVES` table (8 entrées) + helper `_apply_bad_directive()` dans `bob/checks/ssh.py`. Migre les 8 directives `sshd_config` uniformes (PermitEmptyPasswords, X11Forwarding, IgnoreRhosts, HostbasedAuthentication, PermitUserEnvironment, StrictModes, AllowTcpForwarding, PubkeyAuthentication) d'une cascade de `if value == "yes"`/`"no"` blocs vers une boucle `for rule in _BAD_DIRECTIVES`. Le helper expose deux styles de prédicats (`bad_values` tuple ou `safe_values` tuple) — `safe_values` couvre le cas AllowTcpForwarding où `"local"` est acceptable en plus de `"no"`. Cas spéciaux préservés en impératif : PermitRootLogin (4-way branch avec sous-états OK), PasswordAuthentication (dépend de `ssh_exposed`), MaxAuthTries (seuil entier), LoginGraceTime (INFO-only), AllowUsers/AllowGroups (info-only), Match block (info-only), weak ciphers/macs/kex (helper `_check_weak_algo` séparé). Net `_check_sshd_config` : ~180 → ~50 LoC, ssh.py total +56 (cost de la dataclass + 8 entrées). **#3 runner._sec extension** avec keyword-only params `skip_if=Callable[[snapshot], bool]` et `post_display=Callable[[snapshot, result], None]`. Permet de remplacer 4 blocs inline par des appels `_sec` 1-liner : `samba` (`skip_if=not s.installed`), `docker_audit` (`skip_if=not s.docker_installed`), `desktop_apps` (`skip_if=not s.detected`), `disk` (`post_display=display_disk_partitions`). Net runner.py : −29 lignes. **#13 (ssh.py split) déféré à Phase 5** — estimation audit (-150 LoC pour #4) trop optimiste, ssh.py reste à 1324 LoC (cible <1000 non atteinte). Tests 4538/4538 inchangés — comportement bit-identique à v0.5.1, c'est purement un re-shape interne. |
| [v0.5.1](#v051) | 2026-05-21 | Refactor v0.5.x Phase 2 — **the big LoC win** (audit finding #1). New `CheckResult.warn_with_deduction(key, *, message, points, reason=None, ...)` and `.alert_with_deduction(...)` helpers in `bob/scoring.py` collapse the paired `result.warn(...) + result.add_deduction(...)` idiom that recurred across ~130 sites in `bob/checks/*.py`. **120 sites migrated** in 27 files: firewall (4), fail2ban (2), clamav (5), ntp (2), ddns (1), updates (2), ssh (24 — the big one), backup (1), log_rotation (3), auditd (3), file_integrity (3), kernel_hardening (3), rootkit (3), hardening (8), samba (6), mac_policy (6), disk (5), iptables_nftables (5), firewall_stack (4), file_perms (1), suid_audit (1), smtp (1), memory (1), network_context (1), cron_audit (2), docker_audit (2), kernel_modules (2), umask (2), user_accounts (2), password_policy (2), secure_boot (2), systemd_timers (2), logs (1), firmware (2), ipv6 (1), ports (1). **13 sites intentionally not migrated** — patterns where the deduction is conditional on a different predicate than the finding (caps via local counter: `services_state`, `ssl_certs` x3, `file_perms` x3, `ipv6.port_no_v6_rule`), or where finding-level branches `warn`/`alert` on a separate condition than the deduction (`docker` x2, `services.exposure`, `ports.uncovered_public`). The `reason=` override handles cases where the deduction uses a `_reason` suffix translation key distinct from the finding message (e.g. `ssh.host_key_dsa_reason` ≠ `ssh.host_key_dsa`). **Net diff: 37 files changed, +483 / −1002 = −519 lines.** Tests unchanged: 4538/4538 pass (helpers are additive, no behaviour change). JSON `schema_version="1"`, the 7 score domains, the 116 EXPLAIN_KEYS, and the 34 filterable sections are all preserved. |
| [v0.5.0](#v050) | 2026-05-21 | Refactor v0.5.x Phase 1 (opens the v0.5.x branch) — **6 audit findings from refactor pass + 1 latent bug found via new test coverage**. **#7** new `is_unit_active()`/`is_unit_enabled()` helpers in `bob.checks._run` migrate 9 sites (`auditd`, `fail2ban`, `clamav`, `ntp`, `ddns`, `updates`, `ssh`, `backup`, `log_rotation`) replacing the repeated `_run("systemctl", "is-active", ...).strip() == "active"` idiom; defensive `.lower()` added centrally to guard against non-canonical distro output. **#2** new `bob.output.print_titled_box(title, width=62)` migrates 4 sites (3× `cron.py` + 1× `manage_logs.py`) and **closes the `--no-color` leak** where those sites bypassed `_c` and printed raw `\033[1;34m` literals. **#10** new `bob.report.Report` `typing.Protocol` (PEP 544 structural type) captures the shared write-method contract between `AuditReport`, `NullReport`, and `MarkdownReport` (which were two duck-typed implementations); `runner.run_checks` now type-hints `report: Report`. **#11** new `emit_section()` + `emit_group()` closures in `runner.py` collapse the `if not config.quiet: print_section(t(...)); report.write_section(t(...))` 3-line idiom into 1-line calls at 20 sites (5 group headers + 15 section headers); `_sec()` itself dogfoods the helper. **#15a** new `tests/test_domain_scores_mapping_complete.py` (+4 tests) AST-scans `bob/checks/*.py` for every literal `key="X.Y"` and asserts each prefix is either explicit in `_PREFIX_TO_DOMAIN` or whitelisted in `_CATCH_ALL_BY_DESIGN` with a justification (the v0.4.x state — `smtp`/`fail2ban`/`desktop_apps`/`virt`/`docker_audit`/`ddns` etc. still fall to the firewall catch-all, deferred to Phase 5 #15b). **Cron coverage pass** (+35 tests) covering the 5 pure helpers untouched by previous test sweeps: `_validate_cron_field` (out-of-range, reversed range, steps, list, empty entry), `_validate_custom_cron` (full 5-field with bounds per field), `build_script_content` (shebang, shlex quoting), `apply_cron_schedule`, `apply_cron_email` (legacy `NOTIFY_EMAIL=` parity). **Latent bug fixed (found by the new cron tests):** `apply_cron_schedule()` called `_os.open(...)` — but `_os` is only locally aliased in 3 *other* functions, never at module level. The v0.4.8 cron-deduplication extraction missed renaming this. The helper had been silently dead since v0.4.8 ship. Fix: `_os` → `os`. 4499 → **4538 tests** (+39: +4 mapping / +35 cron). |
| [v0.4.8](#v048) | 2026-05-21 | Code-quality audit pass 4 (sub-agent) — **I4 real bug** `sudo bob -d` log files were `root:root 0600` and unreadable to the invoking user afterwards (now chowned back via `chown_to_sudo_user` in `bob/report.py` + `bob/manage_logs.py::get_or_prompt_log_dir`, same pattern as the 7 already-chowned config modules) · **dead-field cleanup** 8 dataclass fields removed across 5 checks (`SSHSnapshot.config_source_files`, `FirewallStatus.ipv4_rules_count`+`ipv6_rules_count`, `SambaSnapshot.min_protocol`, `ClamAVSnapshot.last_scan_log_path`+`db_path`, `SecureBootSnapshot.method`) all populated but never read — same bug class as v0.4.3 C1 · `_C_LOCALE_ENV` added to 3 stray `subprocess.check_output` sites (`desktop_apps.py::ps`, `smtp.py::ps`, `smtp.py::ss/netstat`) for locale-consistency · `log_rotation._service_active` inlined to `_run("systemctl", "is-active", ...)` (was an 11-line reinvention) · `apply_cron_schedule()` + `apply_cron_email()` promoted from private helpers to `bob.cron` public API, `bob/tui/cron.py` now imports them — fixes the asymmetric `NOTIFY_EMAIL=` legacy support that was plain-only · `SCORE_BAR_WIDTH = 10` exported from `bob.output` (de-duplicates the `_BAR_WIDTH` constant across `breakdown.py` + `domain_scores.py`) · auth_log 90-day `max_days` documented as intentional (independent of `--log-days` which is for UFW logs) · **pyproject.toml hardening**: `Development Status :: 4 - Beta` → `5 - Production/Stable`, `authors` + `maintainers` added (PyPI was showing UNKNOWN), `[project.optional-dependencies] geoip = ["geoip2>=4.0"]` for `pipx install "bodyguard-of-bits[geoip]"`, `wheel` dropped from build-system requires (auto-resolved since setuptools 70), Source + Documentation URLs added, explicit `dependencies = []` and `include = ["bob", "bob.checks", "bob.tui"]` · 4499/4499 tests (-1: removed `test_default_method_is_none` from test_secure_boot since `method` field is gone) |
| [v0.4.7](#v047) | 2026-05-21 | Doc audit pass + cosmetic gauges + release automation — exhaustive cross-doc audit (24 corrections across 8 files: README/FR · README_TECH/FR · README_DEV/FR · SECURITY_FR · `man/bob.1` · `man/bob-profile.5` · AUTOMATION/FR) · `DOCUMENTS/SNAPSHOT.md` added (~640L internal cartography, 20 correction passes) · gauge bars harmonized via `bob.output.score_bar()` (green ≥8, yellow 5–7, red 0–4 — same colour logic as the disk partition bars) · bash completion comprehensive overhaul (function rename, dead code removed, **critical fix** to `--check=`/`--skip=`/`--format=`/etc. value completion that was silently failing due to `COMP_WORDBREAKS` `=` split) · `publish.yml` auto-creates GitHub Release from `CHANGELOG_FULL.md` on tag push · 4500/4500 tests (unchanged) |
| [v0.4.6](#v046) | 2026-05-17 | Terrain test pass v0.4.5 fixes — **Bug 1** `kernel_modules.py` dpkg-query did not filter on `ii` (installed) state, so kernels removed by `apt remove` / `autoremove` (left in `rc` config-files state) were still listed as "installé". Reproduced on Mint test VM + so6desktop production. Now uses `${db:Status-Abbrev}` and keeps only lines whose 2nd char is `i` (covers `ii`, `hi`). **Bug 2** scoring inversion: after `apt upgrade` resolved a `updates.security_pending` WARN, the only finding left was `updates.ok` → `active_domains_from_engine` dropped the domain → global score *decreased* (denominator shrank). Reproduced on Debian 13 VM (7/10 → 6/10 after remediation). `_actionable` widened from `(WARN, ALERT)` to `(OK, WARN, ALERT)`; INFO-only domains stay hidden by design. 4500/4500 tests (+11) |
| [v0.4.5](#v045) | 2026-05-16 | Test infrastructure hardening — `tests/test_locale_coverage.py` switched from regex scanning to **AST parsing** (`ast.walk` + `ast.Call` + `ast.Name` checks) · eliminates three classes of false positive that the regex form could produce (docstring matches, multi-line call site misparses, `obj._t(...)` attribute calls) · `_KEY_EXCLUSIONS` allowlist deleted entirely · same 9 tests, same external contract, more robust foundation · 4489/4489 tests (unchanged) |
| [v0.4.4](#v044) | 2026-05-15 | Cross-distro terrain hardening — **critical `updates.py` bug** (4/4 Debian-family VMs: 21 Ubuntu LTS security updates undetected): `apt-get -s upgrade` → `dist-upgrade` · stale APT cache detection · cross-check vs `apt list --upgradable` · "Surface d'attaque" propagates `updates_unknown` instead of false "à jour" · AppArmor "0 profil chargé" dedicated key · SMART skip on all-virtual disks · DDNS ports inline in WARN · S4 redesign `_is_safe_user_path` home-bounded · M4 refactor `_parse_ufw_covered_ports` (1 parse + O(1) lookup) · I2 wave-2 `key=` on services/virtualization · new locale-coverage test (catches `[xxx.yyy]` sentinel regressions) · 4489/4489 tests (+21) |
| [v0.4.3](#v043) | 2026-05-15 | Doc catch-up + post-audit hardening pass — 4 firewall keys promoted to `EXPLAIN_KEYS` · `--json --json-full` crash fix (5 dead HardeningSnapshot attrs) · `strptime("%b…")` made locale-independent (ssl_certs + logs) · `_is_covered_by_ufw` false-positive killed · email markdown links no longer escaped · cron range validator now rejects out-of-bounds · `key=` on ~30 findings (docker, firewall_stack, network_context, ports) · 7 dead locale keys removed · i18n concat anti-pattern resolved (ddns, logs) · CIS refs added · CHANGELOG short corrected for v0.4.2 · 4468/4468 tests (+4 regression) |
| [v0.4.2](#v042) | 2026-05-14 | Phase 3 distro-ready (packaging discipline) — `SECURITY.md` threat model · 3 man pages (`bob(1)`, `bob.conf(5)`, `bob-profile(5)`) · `debian/` folder with pybuild + DEP-5 + 3 binary packages (`bob-core`, `bob-tui`, `bob` meta) · `packaging/rpm/bob.spec` Fedora COPR-ready · AppArmor complain profile (`debian/apparmor.d/bob`) · pre-release hardening pass: 2 critical + 5 important + 4 minor + 1 suggestion fixes from agent audit · 4452/4452 tests (+3 in new `test_template_vars_migration.py`) |
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

## [v0.6.2] — 2026-05-29

**Critical packaging hotfix.** Every wheel shipped since v0.6.0 (so v0.6.0 + v0.6.1) was missing `bob/checks/ssh/` and `bob/cron/` — the two subpackages introduced by the v0.6.0 splits. Users who `pipx upgrade`d hit a hard crash at startup:

```
$ sudo bob -v -d --french
Traceback (most recent call last):
  File "/usr/local/bin/bob", line 3, in <module>
    from bob.__main__ import main
  File ".../bob/__main__.py", line 38, in <module>
    from bob.runner import (
  File ".../bob/runner.py", line 46, in <module>
    from bob.checks.ssh import SSHSnapshot, check_ssh
ModuleNotFoundError: No module named 'bob.checks.ssh'
```

### Root cause

`pyproject.toml::[tool.setuptools.packages.find]` had a literal `include = ["bob", "bob.checks", "bob.tui"]` inherited from a v0.4.x packaging audit. When v0.6.0 split `bob/checks/ssh.py` → `bob/checks/ssh/` package and `bob/cron.py` → `bob/cron/` package, this list was not updated. setuptools' `find_packages()` therefore EXCLUDED both subpackages from the wheel — they exist in the source tree but never make it into the distribution.

### Why three test layers missed it

1. **Unit tests** import from the source tree (`from bob.checks.ssh import …` resolves via `sys.path` containing the repo root). The packaging config is irrelevant.
2. **Pre-ship `sudo python3 -m bob` smoke** ran from the working tree (`~/github/bodyguard-of-bits/`). Same source-tree resolution — wheel never involved.
3. **CI `integration.yml`** used `pip install -e .` (editable mode), which adds the repo root to `site-packages` via a `.pth` file. Editable installs DELIBERATELY bypass `find_packages()` discovery for fast iteration — masking exactly this bug class.

The first signal came from a user `pipx upgrade` on a clean system, which builds and installs a real wheel.

### Fix

**`pyproject.toml`**:
```diff
 [tool.setuptools.packages.find]
 where = ["."]
-include = ["bob", "bob.checks", "bob.tui"]
+include = ["bob*"]
```

The glob `bob*` matches `bob`, `bob.checks`, `bob.checks.ssh`, `bob.cron`, `bob.tui`, and any future `bob.*` subpackage. It still excludes the original guard's target (top-level `bob_something/` non-bob dirs).

**`.github/workflows/integration.yml`**:
- Changed `pip install -e .` → `pip install .` (builds + installs a real wheel on each distro)
- Added explicit smoke step that imports every v0.6.x-added module:

```yaml
- name: Smoke — packaging includes all subpackages
  run: |
    python3 -c "import bob.checks.ssh; from bob.checks.ssh import check_ssh, SSHSnapshot"
    python3 -c "import bob.cron; from bob.cron import CronEntry, run_install_cron, _atomic_write"
    python3 -c "from bob._atomic import atomic_write"
    python3 -c "from bob._tty import safe_input, prompt_wizard, read_line"
```

This second guard fails fast on a missing module *at install-time on the CI*, not at runtime on a user system.

### Compatibility

- **JSON contract**, EXPLAIN_KEYS, all wire output — unchanged.
- **Code changes**: zero. Only `pyproject.toml` (1 line) and `.github/workflows/integration.yml` (~15 lines) modified.
- **Tests**: 4600 unchanged. (Test code didn't touch packaging; this bug is not unit-testable without spawning a venv build, which is the new CI step.)
- **Upgrade path**: `pipx upgrade bodyguard-of-bits` on any pipx-installed system to fix the broken install.

### Action required

If you upgraded to v0.6.0 or v0.6.1 via pipx, you currently have a broken install (the binary `bob` crashes on every invocation). Run:

```bash
pipx upgrade bodyguard-of-bits
```

to get the working v0.6.2 wheel.

### Lessons logged

- **Editable installs hide packaging bugs.** All future CI integration jobs use `pip install .` (non-editable).
- **Explicit import smoke step** for every new subpackage is now part of the integration matrix. Adding a new `bob/foo/` subpackage in the future requires adding it to the smoke list — visible in code review.
- **Memory note**: this bug class is a recurring risk for projects that pin package-discovery lists. Glob > literal list for `setuptools.packages.find.include`.

---

## [v0.6.1] — 2026-05-26

**First hardening release on the v0.6.x branch.** Deep audit sub-agent pass produced 14 findings (0 critical + 6 important + 8 minor); 6 important + 4 minor shipped. The audit revealed two **half-applied contracts** from v0.5.x — atomic-write (mutation paths fixed in v0.5.7 #I-3 but not creation paths) and EOF handling (`manage_logs.py` fixed in v0.5.7 #I-2 but not cron wizards or `fixes.py`) — plus one **untested validator branch** in the cron step parser. All addressed with localized fixes.

### Important (6)

**I-1 + atomic-write contract consolidation** — Extracted `bob/_atomic.py::atomic_write(path, content, *, mode=)` as the single source of truth for crash-safe persistence. Migrated 5 sites that were hand-rolling the temp+rename pattern (`bob/config.py:UserConfig._save` + `EmailStore._save`, `bob/compare.py:save_baseline`, `bob/history.py:_rotate_if_needed`, `bob/recurrence.py:save_recurrence`). Fixed 4 sites that were NOT atomic at all:
- `bob/cron/_install.py:261, 280` (script + cron file fresh install)
- `bob/tui/cron.py:731, 749` (same paths in curses install)
- `bob/ignore.py:93` (ignore.yml — I-6)
- `bob/history.py:58` (first-write mode 0o600 — I-5, see below)

`bob/cron/_io.py::_atomic_write` kept as an alias (`from bob._atomic import atomic_write as _atomic_write`) — the existing `TestApplyCronScheduleAtomic` test patches that name directly.

**I-2 — EOF contract completion** — `bob/_tty.py` gained a `safe_input(prompt)` wrapper that catches `EOFError` and returns `""`. `prompt_wizard()` now also catches `EOFError` and returns `None` (consistent with `read_line()`). Migrated 11 bare `input()` sites: `bob/cron/_install.py` (5), `bob/cron/_manage.py` (5), `bob/fixes.py` (1). Ctrl-D no longer crashes any plain-text wizard.

**I-3 — `_validate_cron_field` step bounds** — `*/200` for minute (0-59) was accepted by validation; cron then interpreted it as "every 200 minutes" → never fires (rolls over hourly). Added `if int(step_s) > (hi - lo + 1)` check after the existing `>= 1` validation. Now `*/200 minute` returns `"minute step '200' exceeds field range (60)"`.

**I-4 — `shlex.quote()` on `cmd=` paths** — 8 sites where `--fix --apply` would `shlex.split()` paths containing spaces and apply chmod to the wrong file:
- `bob/checks/ssh/_subchecks.py:117, 281, 306, 369` (host key removal, `~/.ssh` dir, private key, authorized_keys — paths from `pwd.getpwnam(SUDO_USER).pw_dir`)
- `bob/checks/file_perms.py:228, 238, 257` (world-writable / over-permissive / sensitive paths from filesystem scan)
- `bob/checks/firmware.py:186` (microcode package name)

`bob/checks/ssl_certs.py:176` was already quoted at the variable definition (`_cert_name = shlex.quote(...)`).

**I-5 — `history.jsonl` mode `0o600` on first write** — `_HISTORY_FILE.open("a")` used the process umask (typically `0o644` → world-readable). Score timestamps are privacy-sensitive on shared systems. Switched to `os.open(O_WRONLY | O_APPEND | O_CREAT, 0o600)` which sets mode only on creation; existing-file mode is preserved.

**I-6 — `ignore.py` atomic write** — `bob/ignore.py:93` wrote `ignore.yml` via raw `os.open(O_TRUNC)`. Power-loss / OOM corrupted the file. Migrated to `atomic_write(path, content, mode=0o600)` (single helper from I-1 consolidation).

### Minor (4 shipped)

| # | Fix |
|---|---|
| **M-2** | `bob/checks/ssh/_directives.py::_apply_bad_directive` was calling `.lower()` twice (`is_bad` already lower-cases internally). Dropped the outer call. |
| **M-3** | `bob/checks/ssh/_subchecks.py` `MaxAuthTries=-1` / `=0` was previously accepted. Now treated as the default 6 (sshd treats `<=0` as "no retry" which is also misconfiguration). |
| **M-6** | `bob/__main__.py:405` `Fatal error: …` one-line print made bug reports useless. Now hints `Set BOB_DEBUG=1 for full traceback` and prints the traceback when the env var is set. |
| **M-8** | `bob/cli.py` `--watch=N` error wording: `"positive integer"` → `"integer ≥ 10"` (matches the actual constraint). |

### Minor (4 deferred / judgment-call)

- **M-1** `parse_cron_file` silent downgrade of non-numeric hour/minute to `0` — only used as wizard default, low-impact, kept as-is
- **M-4** Module-level path constants computed at import time — DOCUMENTED as intentional (M7 lazy resolution discarded in SNAPSHOT.md)
- **M-5** fd leak window in install paths — addressed transitively by I-1 atomic_write migration
- **M-7** `--check/--skip` warning vs always-on sections mismatch — judgment call, deferred to a UX review pass

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4600 passed in ~7s
```

**4583 → 4600 (+17).** New test class structure:

`tests/test_atomic_v061.py` (12 tests):
- `TestAtomicWritePublicAPI` (4) — pins the `atomic_write(path, content, *, mode=)` contract (mode preserved, content overwritten cleanly, original survives on simulated failure)
- `TestCronLegacyAliasStillWorks` (1) — `bob.cron._io._atomic_write is bob._atomic.atomic_write`
- `TestHistoryFileMode` (2) — I-5 first-write 0o600, mode preserved on append
- `TestIgnoreAtomic` (2) — I-6 atomic write + crash-safety
- `TestSafeInput` (3) — I-2 `safe_input()` + `prompt_wizard()` EOFError handling

`tests/test_cron.py::TestStepBoundedToFieldRange` (5 tests) — I-3 step bounds for minute / hour / boundary / zero / full expression.

### Compatibility

- **JSON contract**: `schema_version="1"`, the 116 EXPLAIN_KEYS — unchanged.
- **Per-domain score**: unchanged. Global score unchanged.
- **Wire output**: unchanged. `--watch=N` error wording is the only user-visible string change.
- **External Python API**: `bob._atomic.atomic_write` is a new module-level helper (semi-public via `_` prefix on module name). `bob._tty.safe_input` is new public. Both additive.
- **Backwards-compat**: `bob.cron._io._atomic_write` still exists as an alias — existing test patches keep working. The 5 migrated atomic-write sites preserve the exact same wire-output (just routed through the central helper).
- **Keybindings**, **no-curses fallback**, **exit codes** — unchanged.

### Audit campaign tracking

| Release | Findings | Tests |
|---|---|---|
| v0.5.5 | 19 (4C + 4I + 11M) | +7 |
| v0.5.6 | 10 (0C + 2I + 8M) | +15 |
| v0.5.7 + v0.5.8 | 11 (0C + 3I + 8M) | +23 |
| **v0.6.1** | **14 (0C + 6I + 8M)** | **+17** |

**Cumulative**: 30 modules deep-audited, 0 critical findings outstanding. Two contracts (atomic-write, EOF handling) now uniformly enforced across the codebase.

---

## [v0.6.0] — 2026-05-25

**Major bump opening the v0.6.x branch.** Two architectural splits (#13 + #14) deliberately deferred across the entire v0.5.x cycle, plus one sunset honored. All three changes are contract-preserving via package `__init__.py` re-exports — every `from bob.checks.ssh import …` or `from bob.cron import …` call site in the codebase and in user scripts continues to work unchanged.

### #13 — `bob/checks/ssh.py` → `bob/checks/ssh/` package

The 1296-line SSH check module split into 4 focused submodules:

| Module | LoC | Content |
|---|---|---|
| `_directives.py` | 165 | `_BadDirective` declarative table + `_BAD_DIRECTIVES` tuple + `_apply_bad_directive` helper + weak crypto reference sets (`_WEAK_CIPHERS`, `_WEAK_MACS`, `_WEAK_KEX`) |
| `_snapshot.py` | 198 | 5 dataclasses (`HostKeyInfo`, `PrivateKeyInfo`, `AuthorizedKeyEntry`, `KnownHostEntry`, `ClientConfigEntry`) + `SSHSnapshot` + `SSHSnapshot.from_system` |
| `_parsers.py` | 446 | Pure parsers: `_parse_config_file`, `_collect_private_keys`, `_detect_private_key_type`, `_key_type_from_algo`, `_rsa_bits_from_*`, `_has_passphrase`, `_parse_authorized_keys`, `_parse_client_config`, `_parse_known_hosts`, `_collect_host_keys`, `_detect_ssh_install_cmd`, `_parse_time_seconds` |
| `_subchecks.py` | 529 | `check_ssh` entry point + all `_check_*` per-area helpers (`_check_host_keys`, `_check_sshd_config`, `_check_weak_algo`, `_check_ssh_dir`, `_check_private_keys`, `_check_authorized_keys`, `_check_client_config`, `_check_known_hosts`) |
| `__init__.py` | 64 | Public re-exports |

**Cycle break**: `_parsers` imports dataclasses from `_snapshot` at module level; `_snapshot.SSHSnapshot.from_system` uses a function-local `from . import _parsers` import to avoid the otherwise-circular dep. Clean and intention-revealing.

### #14 — `bob/cron.py` → `bob/cron/` package

The 1204-line cron module split into 4 focused submodules:

| Module | LoC | Content |
|---|---|---|
| `_parse.py` | 330 | `CronEntry` dataclass + `parse_cron_file` + `list_installed_crons` + `cron_to_human` + `build_schedule_expr` + `make_slug` + `suggest_name` + `_validate_cron_field` + `_validate_custom_cron` + `_parse_day_names` + `_parse_dom` + `_ordinal` + `_detect_mta` + constants (`CRON_DIR`, `SCRIPT_DIR`, `LEGACY_*`, `_DAYS_EN`, `_DAYS_FR`, `_CRON_FIELD_BOUNDS`) |
| `_io.py` | 164 | `_atomic_write` + `build_script_content` + `apply_cron_schedule` + `apply_cron_email` (all file-mutation helpers) |
| `_install.py` | 319 | `prompt_emails` + `prompt_email` + `_run_install_cron_plain` + `run_install_cron` + `_CronQuit` exception (shared with `_manage`) |
| `_manage.py` | 445 | `_manage_email_store` + `edit_cron_email` + `edit_cron_schedule` + `_run_manage_cron_plain` + `run_manage_cron` |
| `__init__.py` | 101 | Public re-exports incl. `datetime` + `_EMAIL_RE` for backwards-compat |

**Note on `build_script_content` path resolution**: the function uses `Path(__file__).parent.parent.parent` to derive `PYTHONPATH` for the generated cron script — post-split `__file__` resolves to `bob/cron/_io.py` so we now walk THREE parents (`_io.py` → `cron/` → `bob/` → repo root) instead of two. Verified by the existing smoke test (`tests/test_cron.py::TestDatetimeImportLifted::test_build_script_content_still_stamps_date`).

### Sunset: `UFW_AUDIT_SHARE` legacy env var

Announced "REMOVED in v0.6.0" by the deprecation warning shipped in v0.5.4 (`bob/_paths.py:60`). Honored. Only `BOB_SHARE` is now accepted by `resolve_share_dir()`. Installers still setting `UFW_AUDIT_SHARE` will see no effect — update them to use `BOB_SHARE`. The deprecation chain:

- v0.4.2: `BOB_SHARE` becomes the documented contract; `UFW_AUDIT_SHARE` accepted as legacy alias
- v0.5.4: `logger.info(...)` upgraded to `logger.warning(...)` with explicit "REMOVED in v0.6.0" message
- **v0.6.0**: Removed (this release)

3-line drop in `bob/_paths.py` (the `_ENV_LEGACY` constant, the fallback read, and the legacy warning branch) plus 2 docstring updates in `bob/i18n.py` and `bob/registry.py`.

### Backwards compatibility

Every public symbol from the v0.5.x monoliths is re-exported by the new packages' `__init__.py`:

```python
# Still works in v0.6.0:
from bob.checks.ssh import SSHSnapshot, check_ssh, AuthorizedKeyEntry  # and 8+ more
from bob.cron import CronEntry, run_install_cron, apply_cron_schedule, _EMAIL_RE, datetime, _CronQuit
```

This was the deciding factor for the conservative split — the alternative (forcing user-visible import-path changes) would be a true breaking change and is not warranted for an internal refactor. The packaging keeps the option open for v0.7+ if a deeper API redesign is wanted later.

### Test infrastructure updates (2 trivial AST scan fixes)

The check-module discovery in two introspection tests needed to recurse into the new package directories:

- **`tests/test_template_vars_migration.py`**: `_check_modules()` (now `_module_paths()`) walks `iterdir()` and returns either single `.py` files or package directories; `_module_has_template_vars(path)` does `rglob("*.py")` for package targets. Pilot list converted from `frozenset({"ssh.py", "hardening.py", "firewall.py"})` to module-name form `frozenset({"ssh", "hardening", "firewall"})`.
- **`tests/test_domain_scores_mapping_complete.py`**: single-line change — `_CHECKS_DIR.glob("*.py")` → `_CHECKS_DIR.rglob("*.py")` with `__pycache__` filter, so the AST scan picks up `bob/checks/ssh/_subchecks.py` and all sibling submodule key emissions.

One regression test (`tests/test_cron.py::TestApplyCronScheduleAtomic`) was updated to spy on `bob.cron._io._atomic_write` rather than the package-level re-export — because `apply_cron_schedule` now lives in `_io.py` and calls the local `_atomic_write` directly. The spy needs to be set on the module where the call site reads it.

### Compatibility

- **JSON contract**: `schema_version="1"`, the 116 EXPLAIN_KEYS — unchanged.
- **Per-domain score**: unchanged. Global score unchanged.
- **Wire output**: unchanged.
- **External Python API**: all v0.5.x public symbols re-exported from the new packages. No removals.
- **Environment variables**: `UFW_AUDIT_SHARE` removed (announced for 12+ months). Only `BOB_SHARE` accepted.
- **Keybindings**, **no-curses fallback**, **exit codes** — unchanged.

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4583 passed in ~7s
```

**4583 unchanged.** No new tests, no removed tests — the splits + sunset are structural and don't change behaviour. The 3 test files updated (template_vars_migration, domain_scores_mapping_complete, test_cron) shift assertion targets to accommodate the new module layout but keep the same coverage scope.

### Net diff

| File | Delta |
|---|---|
| `bob/checks/ssh.py` (deleted) | −1296L |
| `bob/checks/ssh/__init__.py` + 4 submodules | +1402L (165 + 198 + 446 + 529 + 64) |
| `bob/cron.py` (deleted) | −1204L |
| `bob/cron/__init__.py` + 4 submodules | +1359L (330 + 164 + 319 + 445 + 101) |
| `bob/_paths.py` | −20L (legacy alias path + warning) |
| `bob/i18n.py`, `bob/registry.py` | −2L (docstring updates) |
| 2 test file updates | +20L net (rglob + path-not-stem migration) |
| 1 test patch-target fix | +2L net (cron_io vs cron_mod) |
| Version bump + changelogs | standard ~17 files |

Overhead: +261L total across both packages vs the monolithic equivalent. That's the cost of `__init__.py` re-exports + module-level imports + per-file docstrings. Worth it for the modularity.

### Roadmap

v0.6.0 closes the architectural-split backlog from v0.5.x. The v0.6.x branch will host:
- **Maintenance** of the now-modular structure
- **Field bug reports** from cross-distro testing
- **TUI prompt unification** (`_curses_readline` / `prompt_wizard` / `_rl` → flatter hierarchy) — was listed as v0.6.0 candidate but punted to maintain release focus
- **JSON schema v2 cadence planning** (preparation for breaking changes in v1.0)
- **Python 3.10 EOL preparation** (will become minimum-version bump candidate in v0.7+)

No deep-audit campaign planned for v0.6.x — the v0.5.x campaign closed comprehensively (25 modules deep-audited + ~25 spot-checked, 0 critical findings outstanding).

---

## [v0.5.8] — 2026-05-25

**Cleanup release.** Clears the 5 cosmetic minors explicitly deferred by v0.5.7 (M-2, M-5, M-6, M-7, M-8). All five are layout / readability / explicit-naming improvements with zero behaviour change in normal operation. **This closes the v0.5.x deep-audit campaign.**

### Fixes (5)

**M-2 — `manage_logs.py` cursor shift after delete**

`cursor = max(0, cursor - deleted)` assumed all deletions sat at or before the cursor. With multi-selection where some marked items were AFTER the active cursor position, the cursor still shifted left by the full deletion count → it ended up on the wrong file. Now:

```python
deleted_before_cursor = 0
for li in sorted(pending_delete, reverse=True):
    ...
    if li <= cursor:
        deleted_before_cursor += 1
...
cursor = max(0, cursor - deleted_before_cursor)
```

**M-5 — Schedule wizard constants → module-level `IntEnum`**

The wizard had a local tuple-unpack `_, _SCHEDULE_WEEKDAYS, _SCHEDULE_MONTHDAYS, _SCHEDULE_CUSTOM = 1, 2, 3, 4` (note the throwaway `_` for DAILY = 1). Promoted to:

```python
class _Schedule(IntEnum):
    DAILY = 1
    WEEKDAYS = 2
    MONTHDAYS = 3
    CUSTOM = 4
```

`IntEnum` preserves `choice == _Schedule.WEEKDAYS` semantics where `choice` is a plain int derived from menu position. Three call sites updated (`if choice == _Schedule.WEEKDAYS:` etc.).

**M-6 — `_extract_summary_view` sentinel `None`**

`summary_start = 0` + `if summary_start: break` treated index 0 as "not found". If the `SEP62` separator sat on line 0 (unreachable in practice — logs always start with header lines), the loop would mis-detect. Replaced with:

```python
summary_start: int | None = None
...
if summary_start is not None:
    break
```

**M-7 — `_extract_summary_view` over-greedy continuation grouping**

`while ... lines[j].startswith("    ")` swallowed ANY 4-space-indented line as continuation of the previous ALERT/WARN finding, including unrelated body lines from other sections. Extracted helper:

```python
def _is_finding_continuation(line: str) -> bool:
    if not line.startswith("    "):
        return False
    stripped = line.lstrip()
    if any(m in stripped for m in ("[ALERT]", "[WARN]", "[OK]", "[INFO]")):
        return False
    if stripped[:1] in ("┌", "└", "│", "━", "╔", "╠", "╚", "║"):
        return False
    return True
```

Stops on finding markers and on section delimiters even if the line happens to be 4-space indented. Layout-only fix; no security impact.

**M-8 — `from datetime import datetime` lifted to module top**

Three local imports inside function bodies (`bob/cron.py:_run_install_cron_plain`, `bob/cron.py:build_script_content`, `bob/tui/cron.py:_run_install_cron_curses`) → one module-level import in each file. Also removes a redundant local `import os` and `from pathlib import Path` (both already imported at top of `bob/cron.py`).

### Tests

`tests/test_cron.py`:
- `TestScheduleIntEnum` (2) — values match menu indices; IntEnum compares equal to plain int (preserves existing call-site semantics).
- `TestDatetimeImportLifted` (3) — `bob.cron.datetime` and `bob.tui.cron.datetime` are exposed at module level + smoke test `build_script_content` still stamps today's date.

`tests/test_manage_logs.py`:
- `TestCursorShiftAfterDelete` (2) — mixed before/after deletion shifts cursor only by the before-count; all-after deletions leave cursor unchanged.
- `TestSummaryStartSentinel` (1) — synthetic SEP62-at-index-0 edge case correctly detected.
- `TestIsFindingContinuation` (4) — accepts indented body lines; rejects non-indented; rejects indented `[ALERT]`/`[WARN]`/`[OK]`/`[INFO]` markers; rejects indented section delimiters.

4571 → **4583 tests** (+12).

### Compatibility

- **JSON contract**: `schema_version="1"`, the 116 EXPLAIN_KEYS — unchanged.
- **Score**: unchanged. No score-engine changes.
- **Wire output**: unchanged.
- **External API**: `_Schedule(IntEnum)` and `_is_finding_continuation()` are new module-level symbols in `bob.tui.cron` and `bob.manage_logs` respectively. No removals. Three local `from datetime import datetime` statements deleted from function bodies (not part of any public surface).
- **Keybindings**: unchanged.

### v0.5.x deep-audit campaign — CLOSED

After v0.5.8, the v0.5.x branch is at its final maintenance state:

| Release | Scope | Findings shipped |
|---|---|---|
| v0.5.5 | 22 core modules (deep) + ~15 spot-checked | 19 (4C + 4I + 11M) |
| v0.5.6 | `bob/checks/logs.py` (662L) | 10 (0C + 2I + 8M) |
| v0.5.7 | `bob/manage_logs.py` + `bob/tui/cron.py` (~1920L) | 6 shipped + 5 deferred |
| **v0.5.8** | **The 5 v0.5.7-deferred minors** | **5 (all minor)** |

**Total**: 25 modules deeply audited + ~25 spot-checked. 0 critical findings outstanding on the branch.

### What's next

- **v0.6.0** (major bump) reserved for the deliberately-deferred architectural refactors:
  - **#13**: split `bob/checks/ssh.py` (1324 LoC after the v0.5.2 `_BadDirective` table consolidation)
  - **#14**: split `bob/cron.py` (1223 LoC after the v0.4.8 file-patching helper extraction + v0.5.8 import lift)
  - Other architectural decisions (TUI prompt unification, JSON schema v2 cadence, etc.)

Both files exceed the project's soft 1000-LoC ceiling. The splits were deferred because gain × risk did not justify the churn in a contract-preserving minor release.

---

## [v0.5.7] — 2026-05-24

**Targeted hardening pass on curses TUI.** The v0.5.5 and v0.5.6 audits explicitly deferred `bob/manage_logs.py` (999 LoC) and `bob/tui/cron.py` (920 LoC) — the two main interactive curses modules — to a dedicated future pass. This release closes that bucket. A focused sub-agent produced 11 findings; 6 ship in v0.5.7 (3 important + 3 trivial minors), 5 cosmetic minors are documented for v0.5.8.

### Important (3)

**I-1 — `_curses_readline` accepted curses `KEY_*` codes as input characters**

`_read_key` collapses `stdscr.get_wch()` output into a single int regardless of whether the underlying type was `str` (printable) or `int` (keypad). Downstream, `_curses_readline` filtered on `ch_i >= ord(" ")` — but special keys like `curses.KEY_UP = 259`, `KEY_F1 = 265`, `KEY_RIGHT = 261` all pass that gate. `chr(259)` is `Ι` (Greek capital iota), `chr(265)` is `Ω`. Pressing arrow keys or function keys in name/email/days/time/custom-expression prompts inserted Greek glyphs into the input buffer.

No security impact — every downstream consumer validates: `_EMAIL_RE` rejects garbage, `_validate_custom_cron` rejects malformed cron expressions, `re.split` + `isdigit()` filtering drops non-digits, `make_slug` whitelist-regex strips everything outside `[a-z0-9]`. But UX-visibly corrupted (`Mon Audit│Ι Ω`).

Fix: extracted `_is_printable_input_char(ch_i)` helper at module scope bounding inputs to `32 <= ch_i < 256 and chr(ch_i).isprintable()`. Pure Latin-1 printable range; explicitly rejects all `curses.KEY_*` constants (all ≥ 256).

**I-2 — Bare `input()` sites raised on Ctrl-D**

Three `input()` calls inside `manage_logs.py` propagated `EOFError` directly: the path prompt in `prompt_path()` (line 104), the move-logs `[y/N]` confirmation in the change-location branch (line 360), and the delete-all `[y/N]` confirmation (line 378). All other interactive read sites in the codebase route through `bob._tty.read_line` which already maps `EOFError` to empty string. Ctrl-D at any of these three prompts dumped a Python traceback to the user.

Fix: wrapped each `input()` in `try/except EOFError` matching the `_rl()` convention — EOF treated as empty string, which falls through to "use default" for path prompts and "no" for confirmations. `KeyboardInterrupt` deliberately not caught (Python's default exit 130 is correct).

**I-3 — `apply_cron_schedule` not atomic**

Lives in `bob/cron.py` (technically out of the TUI scope strictly speaking) but the curses cron-edit flow is its primary caller via `_apply_cron_schedule` (`bob/tui/cron.py:135`). The function did:

```python
fd = os.open(str(entry.cron_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
with os.fdopen(fd, "w") as fh:
    fh.write(new_text)
```

Power loss, `SIGKILL`, or process crash between `open(O_TRUNC)` and `write` completing would leave the cron file empty. `cron` and `crond` then silently drop the entry — no warning, no failed notification, the scheduled audit just stops running. Asymmetric with the sister function `apply_cron_email` which already used `_atomic_write` (introduced in v0.5.5 #C-1).

Fix: switched to `_atomic_write(entry.cron_path, new_text, mode=0o640)`. Mode `0o640` preserved (cron skips files with wrong mode). One-line change; existing `TestApplyCronSchedule` tests still pass.

### Minor (3 shipped + 5 deferred to v0.5.8)

| # | Status | Fix |
|---|---|---|
| **M-1** | shipped | `manage_logs.deleted_one` status flashed `pending_delete[0].name` even when index 0 failed to unlink (permission denied) and only a different index succeeded — visible filename mismatched the deletion. Now tracks the FIRST successfully-deleted name explicitly |
| **M-3** | shipped | Dead-code elif body in `_curses_edit_sub` (`if ch_i == ord("1"): chosen = 0 elif ord("2"): chosen = 1` — guard already constrained `chosen == sel`). Simplified to single `chosen = sel`, elif rewritten with explicit parentheses for readability |
| **M-4** | shipped | Duplicate `from bob.cron import apply_cron_schedule, apply_cron_email` at line 132 (after a section comment) consolidated into the main import block at the top. Section comment trimmed |
| **M-2** | deferred v0.5.8 | Cursor shift after delete assumes all deletions sit before cursor — cosmetic |
| **M-5** | deferred v0.5.8 | Local-scoped schedule wizard constants (`_, _SCHEDULE_WEEKDAYS, _SCHEDULE_MONTHDAYS, _SCHEDULE_CUSTOM = 1, 2, 3, 4`) → promote to module-level `IntEnum` |
| **M-6** | deferred v0.5.8 | `_extract_summary_view` `summary_start` falsy check misses index 0 (unreachable in practice; sentinel `None` would be cleaner) |
| **M-7** | deferred v0.5.8 | Continuation-line grouping in `_extract_summary_view` over-greedy — swallows any 4-space-indented line, including unrelated body lines from other sections. Layout-only artifact |
| **M-8** | deferred v0.5.8 | Local `from datetime import datetime` inside cron build block — lift to module top |

### Cross-cutting observations (informational, not findings)

- **No `datetime.now()` comparison vulnerabilities** found across the 1920 LoC scope — only one `datetime.now()` site exists (cron header timestamp generation, no comparison). The v0.5.6 #I-2 bug class is contained to `logs.py`.
- **No `os.system`, `shell=True`, or unsanitized subprocess calls** in either module. Cron generation in `bob/cron.py::build_script_content` already uses `shlex.quote` for all user-controlled fields (notify_email, log_dir, audit_bin, bob_path).
- **No path-traversal opening** — `prompt_path` calls `_resolve_path` which does `Path(raw).expanduser().resolve()` (normalizes `..`, follows symlinks once).
- **`raw_name` cannot inject crontab lines** despite being written verbatim into `# name: {raw_name}` cron header comments: `_curses_readline` filters `\n`/`\r`/`\t` (< 32), and terminal pasting collapses multi-line input to single-line.

### Bug class lineage

- **I-3** mirrors **v0.5.5 #C-1** (`_atomic_write` mode regression) and **v0.5.5 #I-1** (`recurrence.py` / `ignore.py` mode 0o600 enforcement) — atomic-write contract enforcement is now uniform across all file mutations in the codebase.
- **I-2** mirrors **v0.5.5 #C-2/C-3** (defensive UX) — Ctrl-D / Ctrl-C handling is now uniform across all interactive read sites (`_rl`, `prompt_path`, both confirm prompts).

### Test coverage

- `tests/test_cron.py`: +6 tests (`TestApplyCronScheduleAtomic`, `TestIsPrintableInputChar`)
- `tests/test_manage_logs.py`: +5 tests (`TestEOFErrorOnPromptPath`, `TestEOFErrorOnMoveConfirm`, `TestEOFErrorOnDeleteAllConfirm`, `TestDeletedOneCorrectName`)
- 4560 → **4571 tests** (+11)

### What's NOT in this release

- The 5 deferred minors (M-2, M-5, M-6, M-7, M-8) — explicitly tracked for v0.5.8
- No man-page changes (TUI keybindings unchanged)
- No locale changes (no user-facing string churn)
- No `bob/data/services.json` changes
- No score-engine changes
- No new public APIs

### Roadmap

After v0.5.7, the v0.5.x branch has been deeply audited end-to-end (22 core modules in v0.5.5 + `checks/logs.py` in v0.5.6 + the 2 curses TUI modules in v0.5.7 = 25 modules deep-audit + ~25 others spot-checked). v0.5.8 will clear the 5 deferred TUI minors. The next minor-version cap (v0.6.0) is reserved for #13 (`ssh.py` 1324 LoC split) and #14 (`cron.py` 1223 LoC split), the two deliberately-deferred architectural refactors from the v0.5.x roadmap.

---

## [v0.5.6] — 2026-05-24

**Targeted hardening pass on `bob/checks/logs.py`.** The v0.5.5 audit explicitly deferred this module ("not deeply audited") because of its regex density — UFW log parser + systemd-journald fallback + GeoIP2 integration + bruteforce detection in 662 LoC. A focused sub-agent audit produced 10 findings: 0 critical, 2 important, 8 minor. All ship in this single-module release.

### Important (2)

**I-1 — `_PRIVATE_IP` regex inconsistent with `sysinfo.py`**

The hand-rolled `^(10\.|172\.…|192\.168\.|127\.|::1$|fc|fd)` regex had three problems vs the canonical `sysinfo._is_private_or_loopback_ipv4/_ipv6` helpers (rewritten in v0.5.5 #I-4):
- **Missed CGNAT** (`100.64.0.0/10`, RFC 6598) — sources behind carrier-grade NAT got GeoIP-looked-up instead of labelled "local"
- **Missed IPv6 link-local** (`fe80::/10`) — local IoT noise mis-classified as public
- **False positive on any string starting `fc`/`fd`** — e.g. `"fcsa"`, `"fdgarbage"` matched as "local" (lucky harmless today because the SRC field is always an IP, but inconsistent with the model)

Same finding class as v0.5.5 #I-4 (`sysinfo._PRIVATE_IPV4_RE`). Fix: new `_is_private_ip(ip)` helper in `logs.py` dispatches by `:` and delegates to `sysinfo._is_private_or_loopback_ipv4/_ipv6`. Single source of truth across the codebase.

**I-2 — Year-rollover dropped near-realtime syslog events**

`_parse_timestamp` falls back to `current_year` for syslog format (no year in the line). The rollback heuristic was:
```python
if ts > datetime.now():
    ts = ts.replace(year=ts.year - 1)
```

A syslog event timestamped `12:00:01` parsed at wall-clock `12:00:00` (1s in the future from NTP jitter / log buffer flush / clock skew) was rolled back a full year → fell outside `cutoff_dt = now - timedelta(days=log_days)` → **silently dropped**. Real impact on busy systems with high UFW BLOCK rates.

Bonus subtle bug: `current_year` and `datetime.now()` are called at different points in the parse loop, so the year-rollover decision could disagree with `current_year` if the parse straddles midnight Dec 31.

Fix: snapshot `now` once at the top of `_parse_log`, pass it to `_parse_timestamp`, and use `if ts > now + timedelta(minutes=5)` to absorb skew while still catching genuine year-end Dec entries parsed in Jan.

### Minor (8)

| # | Fix |
|---|---|
| **M-1** | Anchored `r"\[UFW BLOCK6?\]"` matcher — accepts the `[UFW BLOCK6]` IPv6 variant (silently dropped pre-v0.5.6) and rejects substring spoofing |
| **M-2** | `_count_available_days` regex restricted to English month names — was inflated by non-date leading tokens (e.g. `"mai 23"`, kernel boot facility names) |
| **M-3** | `_GEOIP2_DB_PATHS` reordered: all City entries first across all dirs, then all Country — `_geo_via_geoip2` returns on first hit, so City always wins richer data when both DBs exist |
| **M-4** | `geoip2_status()` now accepts symlinks (`Path.resolve(strict=True)`) — matching `_geo_via_geoip2` which already does. Fixes contradictory "no database installed" notice on `geoipupdate` setups using symlinks |
| **M-5** | `_GEO_CACHE` bounded at 2048 entries with FIFO eviction via `_geo_cache_put()` helper — prevents unbounded growth in long-lived embedders |
| **M-6** | `LogsSnapshot.from_system` reads in binary mode (`open("rb")` + `.decode("utf-8", errors="ignore")`) — `TextIOBase.tell()` returns an opaque number per docs; the byte-offset arithmetic worked by accident on CPython |
| **M-7** | `except (OSError, subprocess.SubprocessError)` — dropped redundant `subprocess.TimeoutExpired` (subclass of SubprocessError) |
| **M-8** | `proto.upper()` at parse time — a downstream patched UFW emitting lowercase `proto` would silently split a single bruteforce campaign into two sub-groups under threshold |

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4560 passed in ~6s
```

**4545 → 4560 (+15).** New `tests/test_logs.py` classes:
- `TestPrivateIPDispatch` (8 tests) — pins CGNAT, IPv6 link-local, ULA, public IPv4, invalid-string edge cases (I-1)
- `TestParseTimestampYearRollover` (3 tests) — current-year, 1s-skew, genuine December rollback (I-2)
- `TestBlockPrefixMatcher` (3 tests) — `[UFW BLOCK]`, `[UFW BLOCK6]`, `[UFW ALLOW]` rejection (M-1)
- `TestProtoNormalisation` (1 test) — lowercase proto upper-cased at parse (M-8)

### Compatibility

- **JSON contract**: `schema_version="1"`, the 116 EXPLAIN_KEYS — unchanged.
- **Wire output**: unchanged on standard UFW configs. Visible delta only on:
  - Hosts emitting `[UFW BLOCK6]` (previously silently dropped — now counted in `total` and `top_ips`)
  - Hosts with mixed-locale syslog content (previously inflated `days_available` count — now accurate)
- **External API**: `_is_private_ip(ip)` is a new semi-public helper. `_PRIVATE_IP` constant removed (was undocumented; one downstream `pipx`-installed user might import it — unlikely).
- **Per-domain score**: unchanged. Global score unchanged.
- **i18n**: no locale key changes.

### Coverage

Single-module pass: `bob/checks/logs.py` audited in full. No other module touched.

Remaining queue (per audit roadmap): **v0.5.7** = `manage_logs.py` + `bob/tui/cron.py` curses TUI (~1920 LoC combined). After that, the v0.5.x line is fully audited.

---

## [v0.5.5] — 2026-05-24

**Hardening pass — post-v0.5.4 audit by a deep sub-agent.** 4 real bugs + 4 security smells + 11 minor cleanups = **19 findings** addressed (17 with code/test changes, 2 with doc comments). Companion cosmetic commit migrates `Optional[X]` / `List[X]` typing on 18 modules.

### Critical bugs (4)

**C-1 — `apply_cron_email()` silently broke scheduled audits**
`bob/cron.py:apply_cron_email()` rewrote both cron files and wrapper scripts via `_atomic_write()`, which always opened the temp file with mode `0o600`. After `os.replace()` the new file inherited that mode — so the wrapper script (originally `0o755`) lost its executable bit. Cron continued reading the cron file but **could no longer exec the script**, and the scheduled audit silently never ran. Anyone who used `bob --manage-cron` to change their notification email entered this state.

`_atomic_write(path, content, mode=0o600)` now takes an explicit mode. Callers in `apply_cron_email` pass `0o640` (cron file) and `0o755` (script). Regression test added to `tests/test_cron.py::TestApplyCronEmail::test_preserves_script_executable_mode`.

**C-2 — `password_policy.no_quality_module` cmd unfixable**
`cmd="sudo apt install libpam-pwquality && sudo pam-auth-update"` emitted with `nature="action"` → `--fix --apply` rejected it via `fixes._has_shell_ops` (the `&&` is correctly flagged as unsafe shell syntax). User saw the cmd in the summary but pressing `y` did nothing.

Fix: demoted to `nature="improvement"`. The cmd still appears in the audit output as guidance — it just doesn't enter the fix-mode queue. Two-step `apt install … && pam-auth-update` isn't safely chainable in a single exec anyway.

**C-3 — `password_policy.weak_minlen` cmd is decorative, not executable**
`cmd="sudo nano /etc/security/pwquality.conf  →  minlen = 8"` — the Unicode arrow makes `shlex.split` tokenize this into junk arguments. Like C-2, demoted to `nature="improvement"`.

**C-4 — `EXPLAIN_KEYS` drift for `services_state`**
`bob/checks/services_state.py` emits findings with `key="services_state.service_inactive"`, but `EXPLAIN_KEYS` (in `bob/explain.py`) declared the canonical name `services_state.enabled_inactive`. `bob --explain services_state.service_inactive` returned "key not found".

Fix: added `"services_state.service_inactive": "services_state.enabled_inactive"` to `EXPLAIN_KEY_ALIASES`. The JSON output contract is preserved (still emits `service_inactive`), and `--explain` lookups resolve via the alias. Option (b) over option (a) (renaming the emitted key would have been a JSON output breaking change — reserved for v0.6.0).

### Important issues (4)

**I-1 — `recurrence.json` + `ignore.yml` written with default umask**
Both files relied on process umask (typically `0o644` on Debian/Ubuntu — world-readable). Every other persistent state file in BOB (`config.conf`, audit reports, score history) opens with explicit `0o600`. Fixed both to use `os.open(..., 0o600)` + `os.fdopen()`.

**I-2 — `_apply_deduction` bypassed score cap after `finalize()`**
The orchestrator contract is one-way: `finalize()` bakes in the cap then sets `_finalized=True`. A late `engine.apply(result)` would mutate `_raw_score` after the cap was applied — silently bypassing it. Added defensive guard with WARNING log; the deduction is discarded.

**I-3 — `_safe_url` allowed `"` injection in HTML email href attributes**
The pipeline html-escapes text first (with default `quote=False`), then re-substitutes `[label](url)` into `<a href="url">label</a>`. The URL was inserted into attribute context without re-escaping — a crafted `[label](https://x.com" onclick="alert(1))` could break out of the href. `_safe_url` now calls `html.escape(url, quote=True)` to encode `"`/`'`/`<`/`>`.

Realistic attack surface is narrow (a malicious `services.d/*.json` plugin emitting markdown links with crafted strings, rendered in user mail clients) but the fix is cheap and the email report is unparseable XSS-safe ground.

**I-4 — `sysinfo._PRIVATE_IPV4_RE` brittle + Python 3.12+ break**
Two problems: (1) the call site at line 192 did `re.search(r"via\s+" + _PRIVATE_IPV4_RE.pattern.removeprefix("^"), …)` — manipulating a compiled pattern's `.pattern` attribute and dropping flags; (2) `ipaddress.IPv4Address.is_private` widened in Python 3.12.4+ to include documentation/reserved ranges like `203.0.113.0/24`, so a naive switch to stdlib would mis-classify those as "private" and break `detect_network_context()`.

Fix: explicit `_PRIVATE_IPV4_NETS` + `_PRIVATE_IPV6_NETS` tuples of `ipaddress.ip_network` objects, with `_is_private_or_loopback_ipv4()` / `_is_private_or_loopback_ipv6()` helpers using `addr in net` membership. Covers RFC 1918, loopback (127/8 + ::1), link-local (169.254/16 + fe80::/10), CGNAT (100.64/10), and IPv6 ULA (fc00::/7). Documentation ranges stay "public" so they don't trigger "local" context.

### Minor cleanups (11)

| # | Fix | Files |
|---|---|---|
| **M-1** | Email regex unified via `bob.config._EMAIL_RE` (was duplicated 3×) | `bob/cron.py` |
| **M-2** | `bob/watch.py:_NullReport` removed → use `bob.report.NullReport` (Report Protocol from v0.5.0 #10) | `bob/watch.py`, `tests/test_watch.py` |
| **M-3** | 3 dead locale keys removed: `_meta.lang`, `_meta.version`, `ignored.hint` | `bob/locales/{en,fr}.json`, `tests/test_ignore.py` |
| **M-4** | `corr.fully_blind` rule widened: fail2ban-stopped or auditd-stopped both qualify as "blind" (was asymmetric — only fired when both layers fully missing) | `bob/correlation.py`, `tests/test_correlation.py` |
| **M-7** | Extract `_has_actionable_findings()` helper in `updates.py` (replaces fragile inline `f.key != "updates.apt_cache_age"` filter) + `_TRANSPARENCY_KEYS` frozenset for future-proofing | `bob/checks/updates.py` |
| **M-8** | Comment-only — clarifies why `_parse_config_file` stops at Match blocks (also skips subsequent Include directives, intentional) | `bob/checks/ssh.py` |
| **M-9** | Comment-only — clarifies `ListeningPort.process`/`iface` empty fields mean "unknown" not "no process" (when `ss -p` lacks privilege) | `bob/checks/ports.py` |
| **M-10** | `apply_cron_schedule` regex tightened: first field must be a cron-token (`[0-9*,\-/]…`) so comment lines starting with `#` aren't matched | `bob/cron.py`, `tests/test_cron.py` |
| **M-11** | `services_state.service_inactive` cmd: dropped `&& sudo journalctl …` shell chain (moved to `note=` guidance) so `--fix --apply` accepts it | `bob/checks/services_state.py` |

### M-6 (separate commit) — `Optional[X]` / `List[X]` → `X | None` / `list[X]`

Mechanical sweep across 18 modules. Python 3.10+ syntax. Pure cosmetic, zero behaviour change. Isolated commit for revert-chirurgical-on-typo safety.

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4545 passed in ~7s
```

**4538 → 4545 (+7).** Regression coverage for C-1 (cron mode), C-2 + C-3 (`nature` assertion), C-4 (alias resolution), I-2 (post-finalize guard), I-3 (XSS attr-escape, 9 tests in new `tests/test_report_markdown_safety.py`), M-4 (fail2ban-only blind), M-10 (cron comment-line skipped). 8 tests deleted (obsolete `_NullReport.__getattr__` magic from M-2, dead `ignored.hint` test from M-3). 2 tests renamed for clarity (`test_nature_is_action` → `test_nature_is_improvement` on `password_policy`).

### Compatibility

- **JSON contract**: `schema_version="1"`, the 116 EXPLAIN_KEYS — **unchanged**. C-4 uses `EXPLAIN_KEY_ALIASES` (additive) to preserve the emitted key while routing `--explain` to the canonical name.
- **Wire output**: Visible delta on hosts without `pam_pwquality` installed — the password_policy finding moves from "À corriger" (action) to "Améliorations possibles" (improvement) in the summary box. Global score unchanged.
- **i18n**: 3 keys removed (`_meta.lang`, `_meta.version`, `ignored.hint`). Locale-coverage test still green.
- **External API**: no breaking change. `prompt_wizard` (v0.5.4 #6) and `_atomic_write` (now takes `mode`) gain optional parameters.

---

## [v0.5.4] — 2026-05-22

**Refactor v0.5.x — Phase 5 of 5 (final).** Three audit findings closed (`#6`, `#9`, `#15b`) + one user-requested metier feature (cache APT option C). Two findings (`#13` ssh.py split, `#14` cron.py split) explicitly deferred to v0.6.0.

### #6 — `prompt_wizard()` helper for plain-text wizards

`bob/_tty.py` exposes a new `prompt_wizard(label, *, default="")` helper that wraps `input()` with the wizard-step boilerplate every plain-text wizard had to repeat:

```python
def prompt_wizard(label: str, *, default: str = "") -> "str | None":
    """Plain-text wizard prompt with uniform cancel + default handling.

    Returns:
        None — user typed 'q' or 'quit' (case-insensitive).
        str  — trimmed input, or default when Enter was pressed bare.
    """
    raw = input(label).strip()
    if raw.lower() in ("q", "quit"):
        return None
    return raw or default
```

10 sites migrated in `bob/cron.py`:

- `_run_install_cron_plain()` (5 sites): name, schedule type, weekdays, monthdays, custom expr, time
- `edit_cron_schedule()` (4 sites): weekdays, monthdays, custom expr, time
- (the schedule-type prompt in `edit_cron_schedule` keeps `read_line()` for raw-mode Esc support — intentional asymmetry between the two wizards)

Yes/no confirmation prompts (4 sites in `prompt_emails`, 1 in install_cron overwrite, 1 in email_store_enter) are NOT migrated — they don't fit the `default-on-Enter` semantic of `prompt_wizard` (they need explicit `y` vs anything-else).

### #9 — `UFW_AUDIT_SHARE` env var deprecation

`bob/_paths.py:resolve_share_dir()` previously logged an `INFO` when only the legacy `UFW_AUDIT_SHARE` env var was set (without `BOB_SHARE`). The message politely said "the legacy name will be dropped in a future major release" without committing to a version.

v0.5.4 commits to a sunset version:

- Level bumped `logger.info(...)` → `logger.warning(...)`
- Message rewritten: "Using legacy env var %s — DEPRECATED since v0.5.4, will be REMOVED in v0.6.0. Update your installer to %s …"
- Module docstring updated to match.

`SECURITY.md` / `SECURITY_FR.md` (updated in v0.5.3) already declared the support matrix that v0.4.x is end-of-life. Packagers seeing the warning have a clear timeline to update installer scripts.

### #15b — Explicit `_PREFIX_TO_DOMAIN` mapping (medium-risk re-attribution)

`bob/domain_scores.py:_PREFIX_TO_DOMAIN` gains three new explicit entries that were previously silent catch-all fallbacks to the `firewall` domain:

| Prefix | Old (catch-all) | New (explicit) | Rationale |
|---|---|---|---|
| `fail2ban` | firewall | **ssh** | Primary purpose is SSH anti-bruteforce — most jails target the sshd jail |
| `virt` | firewall | **hardening** | KVM/libvirt bridge can insert iptables rules bypassing UFW FORWARD — that's a kernel/system attack-surface concern, not a firewall config concern |
| `docker_audit` | firewall | **hardening** | Container hardening (daemon.json iptables=false setting, running container audit) is system hardening, not network surface |

`smtp` and `desktop_apps` stay in the firewall catch-all: no clean domain fit (smtp local exposure has some firewall semantics; desktop_apps is INFO-only inventory).

Per-domain score impact: on hosts emitting findings under these prefixes, the score breakdown shifts. The **global score is unchanged** (deductions are the same, just re-bucketed). Observed on the dev host: virt.bypass_risk WARN moved from `Pare-feu & Services` (3/10 → 10/10 with other intra-firewall finding clean-up) to `Durcissement` (6/10 → 5/10).

`tests/test_domain_scores_mapping_complete.py:_CATCH_ALL_BY_DESIGN` updated to remove the 3 migrated entries; the remaining `smtp` / `desktop_apps` / `prerequisites` entries get refreshed justifications (no longer "review in v0.5.4" — that's done).

### Cache APT option C — Permanent INFO on cache age

User-requested metier feature. Surfaces the APT cache age when the audit reports "system is up to date" so the user knows whether that verdict reflects a fresh read or a stale snapshot:

```python
if (
    cache_age is not None
    and not security
    and not regular
    and cache_age * 86400 < _APT_CACHE_STALE_THRESHOLD
):
    result.info(
        message=_t("updates.apt_cache_age", days=cache_age),
        detail=_t("updates.apt_cache_age_detail"),
        key="updates.apt_cache_age",
    )
```

Triggered when:
- APT available
- No security packages pending
- No regular packages pending
- Cache age known
- Cache age below the 7-day stale threshold (the stale-cache WARNING already covers the > 7-day case; this INFO covers the silent "fresh-enough but not zero" range)

New locale keys (EN + FR):
- `updates.apt_cache_age`: "APT cache age: {days} day(s) — run `sudo apt update` for a fresher read"
- `updates.apt_cache_age_detail`: explains BOB is read-only by design, points to unattended-upgrades.

Surfaced by Ubuntu VM terrain testing on 2026-05-22 where a dormant VM returned "à jour" despite 8 pending LTS security updates upstream. The cache wasn't stale enough to trigger the `apt_cache_stale` WARNING (< 7 days), but was old enough to be desynchronized from upstream. The new INFO closes that observability gap.

### Deferrals: `#13` (ssh.py split) and `#14` (cron.py split) → v0.6.0

The original v0.5.x audit (2026-05-21) flagged both files as candidates for split:
- `ssh.py`: 1387 LoC at audit time. Targeted < 1000 after Phases 2 + 3. Actual end of v0.5.x: **1324 LoC** (target missed by 32%).
- `cron.py`: 1223 LoC at audit time. Stays at **1223 LoC** end of v0.5.x.

Decision: defer both to v0.6.0. Per [`feedback_conservative_refactor`](memory) — splitting a file is medium-risk for marginal reader gain; doing it inside a contract-preserving release line adds noise without clear payoff. v0.6.0 is the natural place: a major-version bump typically already perturbs imports and tests, so the split lands alongside other structural shifts.

`#15a` test coverage (added in v0.5.0) still pins all current key prefixes against `_PREFIX_TO_DOMAIN` and `_CATCH_ALL_BY_DESIGN`; whatever the v0.6.0 split decision is, the test will catch unhandled prefixes before they regress.

### Net diff

| File | Delta | Notes |
|---|---|---|
| `bob/_tty.py` | +24 | `prompt_wizard()` + docstring rewrite |
| `bob/cron.py` | +1 | 10 `input()` sites migrated to `prompt_wizard` |
| `bob/checks/updates.py` | +20 | Cache APT option C logic + commentary |
| `bob/domain_scores.py` | +10 | 3 new entries in `_PREFIX_TO_DOMAIN` + 6-line comment block |
| `bob/_paths.py` | +5 | log level bump + DEPRECATED message + docstring update |
| `bob/locales/{en,fr}.json` | +4 | 2 new keys × 2 locales |
| `tests/test_domain_scores_mapping_complete.py` | −6 | 3 entries removed from `_CATCH_ALL_BY_DESIGN` + simplified comments |

**Net +49 LoC across 12 code files.** All changes are contract-preserving (no new score domains, no new finding levels, no breaking signature change). Wire output gains 1 new INFO line on idle hosts (cache APT C) and reshuffles per-domain scores on hosts with `fail2ban.*` / `virt.*` / `docker_audit.*` findings — the **global score is unchanged**.

### v0.5.x audit closure: 13/15 findings shipped, 2 deferred

| # | Phase | Outcome |
|---|---|---|
| #1 | v0.5.1 | `warn_with_deduction()` / `alert_with_deduction()` — 120 sites |
| #2 | v0.5.0 | `print_titled_box()` — 4 sites + `--no-color` leak fix |
| #3 | v0.5.2 | `_sec()` skip_if= / post_display= — 4 sites |
| #4 | v0.5.2 | `_BAD_DIRECTIVES` table for sshd_config — 8 directives |
| #5 | v0.5.3 | `_LEVEL_DISPATCH` table for `display_result` |
| #6 | **v0.5.4** | `prompt_wizard()` helper — 10 sites in cron.py |
| #7 | v0.5.0 | `is_unit_active()` / `is_unit_enabled()` — 9 sites |
| #8 | v0.5.3 | `CheckResult.log_data` escape hatch removed — tuple return |
| #9 | **v0.5.4** | `UFW_AUDIT_SHARE` sunset (REMOVED in v0.6.0) |
| #10 | v0.5.0 | `bob.report.Report` `typing.Protocol` |
| #11 | v0.5.0 | `emit_section()` / `emit_group()` — 20 sites |
| #12 | v0.5.3 | `print_audit_summary` split into 3 helpers |
| #13 | **deferred v0.6.0** | ssh.py split (1324 LoC) |
| #14 | **deferred v0.6.0** | cron.py split (1223 LoC) |
| #15a | v0.5.0 | `test_domain_scores_mapping_complete.py` AST scan |
| #15b | **v0.5.4** | `_PREFIX_TO_DOMAIN` explicit mapping for `fail2ban` / `virt` / `docker_audit` |

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4538 passed in ~6s
```

**4538 → 4538 (unchanged).** Phase 5 is contract-preserving — all changes either internal helper extraction (#6) or display-only refinements (cache APT C, #15b score re-bucketing) or non-functional log messaging (#9).

### Compatibility

- **JSON contract**: `schema_version="1"`, the 116 EXPLAIN_KEYS — **unchanged**.
- **Per-domain score**: re-bucketed on hosts with `fail2ban.*` / `virt.*` / `docker_audit.*` findings. **Global score unchanged.**
- **Wire output**: 1 new INFO line on idle hosts (cache APT C). Reshuffle of per-domain breakdown when `#15b` prefixes are emitted. WARNING on hosts using legacy `UFW_AUDIT_SHARE` (previously was INFO).
- **External API**: no breaking change.
- **i18n**: 2 new locale keys (`updates.apt_cache_age` + `..._detail`) in EN + FR.

---

## [v0.5.3] — 2026-05-22

**Refactor v0.5.x — Phase 4 of 5.** Three audit findings: **#5 dispatch table**, **#12 summary helpers**, **#8 `log_data` escape hatch removal**. Zero behaviour change — 4538/4538 tests unchanged, wire output bit-identical to v0.5.2.

### #5 — `_LEVEL_DISPATCH` table for `display_result`

`display_result()` in `bob/display.py` had a 4-branch OK/WARN/ALERT/INFO cascade. Each branch repeated the same pattern (write to report, check threshold, print the message, optionally print recurrence/detail/cmd/note/CIS) with subtle per-level variations that drifted over time.

New `_LevelTraits` frozen dataclass + 4-row dispatch dict expresses each variation as a boolean trait:

```python
@dataclass(frozen=True)
class _LevelTraits:
    report_label:         str
    threshold_key:        str
    print_fn:             Callable[[str], None]
    has_recurrence:       bool
    has_body:             bool
    detail_unconditional: bool   # ALERT-only: prints detail without --verbose
    show_note:            bool   # ALERT only
    show_cis:             bool   # WARN + ALERT
```

The single trait that captures the ALERT specialness (detail prints even without `--verbose`) is `detail_unconditional=True`, replacing an opaque `elif detail: print_recommendation(detail)` branch that lived under the `if finding.cmd and verbose:` chain. `_emit_finding_body()` is a new module-level helper that consumes the traits.

### #12 — `print_audit_summary` split into 3 helpers

The 142-line `print_audit_summary()` mixed three responsibilities (header lines, finding block lines, breakdown lines) with an inner `_add_finding_lines()` closure. Now:

- `_summary_header_lines(engine, network_context, config, t, profile_name, prev_score)` — score/level/network/profile/target lines + the score trend arrow.
- `_summary_findings_lines(engine, t, inner)` — the action + improvement blocks (with the disclaimer line).
- `_summary_breakdown_lines(engine, t, inner)` — deductions + cap_info.
- `_add_finding_lines(icon_prefix, item, inner)` — promoted from inner closure to module-level helper, returns a list of `(content, val)` tuples instead of mutating the enclosing `lines` list.

`print_audit_summary` becomes a 3-line `lines.extend(...)` assembler, then `print_summary_box(lines)`, then the footer (verdict line + implicit_svcs + scope lines + `report.write_summary()`).

One side-fix: the original `report.write_summary(score=score, risk_level=level_str, network_context=ctx_str, ...)` referenced local variables that were no longer in scope after the header extraction. Replaced with direct expressions on `engine.score` and re-evaluated `t(f"scoring.level.{engine.level.value}")` / `t(f"scoring.context.{network_context}")`.

### #8 — `CheckResult.log_data` escape hatch removed

`CheckResult` had a `log_data: dict | None = field(default=None)` field used only by `bob/checks/logs.py` to attach structured aggregations (top IPs, top ports, brute hits, svc hits) for the orchestrator to display. Untyped, single-use, and indistinguishable from regular finding output in the dataclass surface.

Replaced by:

- New frozen `LogReportData` dataclass in `bob/checks/logs.py`:
  ```python
  @dataclass(frozen=True)
  class LogReportData:
      log_days:       int
      days_available: int
      total:          int
      brute_hits:     list[BruteforceHit]
      top_ips:        list[tuple[str, int]]
      top_ports:      list[tuple[str, int]]
      svc_hits:       dict[str, int]
  ```
- `check_logs(...)` now returns `tuple[CheckResult, LogReportData | None]`. `None` when no log file was found or the log was empty (the result still carries an info/ok finding).
- `bob/runner.py:408` unpacks the tuple: `logs_result, logs_report = check_logs(...)`.
- `display_log_results(logs_result, snapshot, log_report, config, t, report)` — `log_report` is now an explicit positional arg instead of being read from `logs_result.log_data`.
- `CheckResult.log_data` field deleted from `bob/scoring.py`.

Test churn: 3 tests renamed (`test_log_data_attached` → `test_report_data_attached`, `test_top_ips_in_log_data` → `test_top_ips_in_report_data`, `test_service_hits_in_log_data` → `test_service_hits_in_report_data`) and rewritten to read `report_data.total` / `report_data.top_ips` / `report_data.svc_hits` instead of dict-key access. ~20 other test sites in `tests/test_logs.py` + `tests/test_degraded.py` use `result, _ = check_logs(...)` tuple unpack since they don't care about the report data.

### Net diff

| File | Delta | Notes |
|---|---|---|
| `bob/display.py` | +23 | `_LevelTraits` + `_emit_finding_body` + 3 summary helpers + `_add_finding_lines` module-level |
| `bob/checks/logs.py` | +19 | `LogReportData` dataclass + tuple return |
| `bob/runner.py` | 0 | 1 line migrated to tuple unpack |
| `bob/scoring.py` | −1 | `log_data` field removed |
| `tests/test_logs.py` + `tests/test_degraded.py` | +3 | tuple unpack + 3 renamed tests |

**Net +40 LoC.** Like Phases 2–3, the LoC delta on its own undersells the structural win: the 4-branch display cascade becomes a single declarative loop, the 142-line summary function becomes a 3-line assembler, and the `dict | None` escape hatch is replaced by a typed frozen dataclass.

### #13 / #14 / #15b still deferred to Phase 5

ssh.py reaches 1324 LoC at v0.5.3 entry, unchanged from v0.5.2. cron.py + `_PREFIX_TO_DOMAIN` re-attribution untouched in Phase 4. All three decisions stay queued for v0.5.4 with explicit `wc -l` re-check.

### Garde-fou observable diff

`sudo python3 -m bob -v --french -n` and `sudo python3 -m bob --format=json --french` snapshots captured before Phase 4 implementation, diffed at intermediate (#5 + #12) and final (#5 + #12 + #8) milestones. All deltas confined to state drift (timestamps, UFW block counts, ephemeral VSCode TCP ports, rkhunter age). Zero structural change to the rendered audit, the JSON tree, or the score breakdown.

---

## [v0.5.2] — 2026-05-22

**Refactor v0.5.x — Phase 3 of 5.** Two audit findings (#4 SSH directive table + #3 `runner._sec` callbacks). Zero behaviour change — 4538/4538 tests unchanged, wire output bit-identical to v0.5.1.

### #4 — `_BAD_DIRECTIVES` table for `sshd_config`

`_check_sshd_config` had ~9 near-identical if-blocks: read directive from `cfg.get()`, check value against a "bad" enum, emit finding + deduction with fixed points/key/nature. Now collapsed into a declarative table.

New in `bob/checks/ssh.py`:

```python
@dataclass(frozen=True)
class _BadDirective:
    name: str          # cfg key (lowercase)
    default: str       # default value if missing
    level: str         # "warn" or "alert"
    key: str           # i18n key
    points: int
    bad_values: tuple[str, ...] = ()    # values that trigger finding
    safe_values: tuple[str, ...] = ()   # alternative: anything not in this set is bad
    nature: str = ""
    detail_key: str = ""
```

`bad_values` and `safe_values` are mutually exclusive — `safe_values` style covers cases like `AllowTcpForwarding` where multiple values (`"no"`, `"local"`) are acceptable. Wrong combinations are caught at class instantiation by `__post_init__`.

Migrated directives (8): `PermitEmptyPasswords`, `X11Forwarding`, `IgnoreRhosts`, `HostbasedAuthentication`, `PermitUserEnvironment`, `StrictModes`, `AllowTcpForwarding`, `PubkeyAuthentication`.

Sites kept imperative (5+ patterns that don't fit):
- **`PermitRootLogin`** — 4-way branch with OK sub-states (`no`/`prohibit-password`/`forced-commands-only` are all OK with different messages)
- **`PasswordAuthentication`** — depends on the orchestrator-level `ssh_exposed` flag (warn vs info)
- **`MaxAuthTries`** — integer threshold (`>3`), not enum
- **`LoginGraceTime`**, **`AllowUsers/AllowGroups`**, **Match block** — INFO-only, no deduction
- **Weak Ciphers/MACs/KexAlgorithms** — set-intersection logic handled by `_check_weak_algo`

`_check_sshd_config` body: ~180 → ~50 LoC. The dataclass + table + helper add ~130 LoC, so net ssh.py +56. The audit's estimate (-150 LoC) was overly optimistic — Python dataclass verbosity offsets the deduplication gain. The win is structural (declarative > imperative cascade), not LoC.

### #3 — `runner._sec` extension with `skip_if=` and `post_display=` callbacks

`_sec` previously couldn't handle two orthogonal cases:
- **Snapshot-conditional gating** — `if samba_snapshot.installed`, `if docker_audit.docker_installed`, `if desktop_snapshot.detected`. Forced inline blocks duplicating the `_sec` body.
- **Post-check display calls** — `display_disk_partitions(snapshot, ...)`, `display_ports_overview(...)` etc.

Now `_sec` accepts two keyword-only callbacks:

```python
def _sec(
    section: str,
    snapshot,
    check_fn,
    *,
    skip_if=None,           # Callable[[snapshot], bool] — skip without emitting header
    post_display=None,      # Callable[[snapshot, result], None] — after display_result
    **check_kwargs,
) -> None: ...
```

4 inline blocks migrated:

| Section | Inline pattern | After |
|---|---|---|
| `samba` | `if samba_snapshot.installed:` then 8 lines | `_sec("samba", ..., skip_if=lambda s: not s.installed)` |
| `docker_audit` | `if docker_audit_snapshot.docker_installed:` then 8 lines | `_sec("docker_audit", ..., skip_if=lambda s: not s.docker_installed)` |
| `desktop_apps` | `if desktop_snapshot.detected:` then 8 lines | `_sec("desktop_apps", ..., skip_if=lambda s: not s.detected)` |
| `disk` | `_sec`-shaped block + `display_disk_partitions` call after | `_sec("disk", ..., post_display=lambda snap, _r: display_disk_partitions(snap, t, output))` |

Net runner.py: −29 LoC.

### #13 (ssh.py split) — deferred to Phase 5

The audit's prediction (#4 saves ~150 LoC → ssh.py descends under 1000 LoC → #13 becomes unnecessary) didn't hold. Phase 2 (#1) saved 119 LoC on ssh.py; Phase 3 (#4) added 56 net. ssh.py is at 1324 LoC, well above the 1000-LoC threshold. Per the [conservative-refactor](memory) principle, ssh.py split is medium-risk surgery — to be decided in Phase 5 alongside #14 (cron.py split) once final state is known.

### Tests

```
$ python3 -m pytest tests/ -q
4538 passed in ~6s
```

`4538 → 4538` (unchanged). Both #4 and #3 are pure structural refactors. The full `test_ssh.py` suite (122 tests) passed before, during, and after the `_BAD_DIRECTIVES` migration — the table produces bit-identical `Finding` and `Deduction` entries to the previous if-blocks.

### Compatibility

- **JSON contract**: `schema_version="1"`, 116 EXPLAIN_KEYS, 34 filterable sections — **unchanged**.
- **Wire output**: bit-identical to v0.5.1. Identical messages, deduction reasons, points, levels.
- **Per-domain scores**: unchanged.
- **External API**: no breaking change. `_BadDirective` and `_BAD_DIRECTIVES` are module-private (underscore prefix); the `_sec` signature change is keyword-only (existing call sites unaffected).

### Files changed

- `bob/checks/ssh.py` — +`_BadDirective` dataclass + `_BAD_DIRECTIVES` table + `_apply_bad_directive` helper; `_check_sshd_config` body rewritten
- `bob/runner.py` — `_sec` signature extended with keyword-only params; 4 inline blocks migrated
- `bob/__init__.py`, `pyproject.toml`, schemas, man pages, READMEs — version bump
- `CHANGELOG.md`, `CHANGELOG_FR.md`, `DOCUMENTS/CHANGELOG_FULL.md`, `DOCUMENTS/CHANGELOG_FULL_FR.md`, `DOCUMENTS/TESTING.md`, `DOCUMENTS/TESTING_FR.md` — this entry
- `debian/changelog`, `packaging/rpm/bob.spec` — packaging stanzas

---

## [v0.5.1] — 2026-05-21

**Refactor v0.5.x — Phase 2 of 5.** The biggest LoC win in the refactor roadmap. Audit finding #1: the paired `result.warn(...) + result.add_deduction(...)` idiom that recurred ~130 times across `bob/checks/*.py` is now centralised behind two helper methods. **No behaviour change** — the helpers compose the existing `warn`/`alert` and `add_deduction` methods one-to-one. Tests stay at 4538/4538 because the wire output (findings + deductions emitted by `CheckResult`) is bit-identical.

### New API

Two methods added to `CheckResult` in `bob/scoring.py`:

```python
def warn_with_deduction(
    self,
    key: str,
    *,
    message: str,
    points: int,
    reason: str | None = None,
    context: str = "local",
    detail: str = "",
    nature: str = "improvement",
    cmd: str = "",
    cmd_type: str = "fix",
    note: str = "",
    template_vars: dict | None = None,
) -> None: ...

def alert_with_deduction(self, ...) -> None: ...   # mirror, nature default = "action"
```

The `reason=` override handles the cases where the finding message uses one translation key and the deduction reason uses a `_reason` suffix variant (e.g. `ssh.host_key_dsa_reason` differs from `ssh.host_key_dsa`).

### Sites migrated (120 across 27 files)

| File | Sites | Notes |
|---|---|---|
| `bob/checks/ssh.py` | 24 | The big one — sshd_config directives (PermitRootLogin, PasswordAuthentication, X11Forwarding, PermitEmptyPasswords, MaxAuthTries, IgnoreRhosts, HostbasedAuthentication, PermitUserEnvironment, StrictModes, AllowTcpForwarding, PubkeyAuthentication), host keys, weak algos (`_check_weak_algo`), `~/.ssh` dir, private keys, authorized_keys, client config, known_hosts. ssh.py: −146 lines. |
| `bob/checks/hardening.py` | 8 | All sysctl branches: rp_filter, ICMP redirects (v4 + v6), tcp_syncookies, accept_source_route, send_redirects, protected_hardlinks, protected_symlinks. |
| `bob/checks/samba.py` | 6 | SMB1, null passwords, server signing, map_to_guest, guest writable/readonly shares. |
| `bob/checks/mac_policy.py` | 6 | AppArmor (no profiles, no enforce, inactive), SELinux (permissive, disabled), no_mac. |
| `bob/checks/clamav.py` | 5 | freshclam_missing, db_not_found, db_very_outdated, db_outdated, scan_very_old/scan_old. |
| `bob/checks/disk.py` | 5 | smart_failed, reallocated_sectors, pending_sectors, uncorrectable_errors, partition_critical. |
| `bob/checks/iptables_nftables.py` | 5 | no_backend, input_accept, no_loopback, no_conntrack, forward_accept. |
| `bob/checks/firewall.py` | 4 | duplicate_found x2 (regex + proto-less), ipv6_missing, logging_off. (5e site `open_any_found` non migré — `rule=""` ≠ `rule=clean` entre finding et reason.) |
| `bob/checks/firewall_stack.py` | 4 | iptables_bypass, iptables_forward_bypass, nftables_parallel, ip_forward_enabled. |
| `bob/checks/log_rotation.py` | 3 | logrotate_missing, journald_volatile x2 (volatile + unknown). |
| `bob/checks/auditd.py` | 3 | service_inactive, no_rules (server), missing_sensitive_rules (server). |
| `bob/checks/file_integrity.py` | 3 | no_db, no_check, check_old. |
| `bob/checks/kernel_hardening.py` | 3 | aslr_disabled, ptrace_unrestricted, suid_dump_all. |
| `bob/checks/rootkit.py` | 3 | db_outdated, no_scan, scan_old. |
| Other files | 35 | fail2ban, ntp, ddns, updates, backup, smtp, memory, network_context, cron_audit, docker_audit, kernel_modules, umask, user_accounts, password_policy, secure_boot, systemd_timers, logs, firmware, ipv6, ports, suid_audit, file_perms — each with 1-2 site migrations. |
| **Total** | **120** | |

### Sites intentionally not migrated (13)

These patterns don't fit the 1:1 helper API:

| Case | Files | Why |
|---|---|---|
| Capped deduction (local counter) | `services_state` (1), `ssl_certs` (3), `file_perms` (2 of 3), `ipv6.port_no_v6_rule` (1) | The finding always emits; the deduction is gated on `if X_deductions < CAP`. Cannot collapse to one helper call. |
| Branching level (warn OR alert) | `services.exposure` (1), `ports.uncovered_public` (1), `docker.exposed_port`/`exposed_bypass_ufw` (2) | The `result.warn(...)` vs `result.alert(...)` choice depends on a snapshot field, while the `add_deduction` runs unconditionally afterwards. The helper merges level + deduction, so the branching has to stay in the caller. |
| Conditional deduction with different predicate | `docker.iptables_bypass` (1), `firewall.rules.open_any_found` (1) | The deduction has a `points = 0 or 1` calculation, or different `template_vars` between finding (`rule=clean`) and reason (`rule=""`). |

For each skip, the audit's recommendation was "keep the old 2-call form" — covered.

### Why this is low-risk

- **Helpers are additive on `CheckResult`.** The existing `warn`/`alert`/`add_deduction` methods are unchanged; the helpers are thin wrappers that call them in sequence.
- **No test changes required.** Every test still asserts on `len(result.findings)`, `len(result.deductions)`, and finding/deduction attributes — the helper produces a `Finding` and a `Deduction` per call, identical to the pre-migration sequence. 4538 → 4538 tests.
- **No behaviour change in the audit pipeline.** Field-tested on 5 distros (Mint, Debian 13, Kali Rolling, Ubuntu 26.04 LTS) for v0.5.0 — the same scoring logic, the same key prefixes, the same `template_vars`.
- **Migration was per-file, with full test suite run after each wave.** Each of the 6 waves (1-site files → 2-site → 3-site → 4-6 site → hardening → ssh.py) passed 4538/4538 before moving on.

### Net diff

```
37 files changed, 483 insertions(+), 1002 deletions(-)
```

**−519 lines net** — a ~5% reduction in `bob/checks/*.py` total LoC. Per the original audit estimate ("~800 LoC removed"), this is conservative because of the 13 skipped sites and because the helper signature is verbose (keyword-only kwargs) — but the goal was eliminating the drift surface, not minimising line count, and that's achieved.

### Tests

`4538 → 4538` (unchanged). Full suite passes in ~6s on Python 3.12 / Linux Mint 22.3.

### Compatibility

- **JSON contract**: `schema_version="1"`, all 116 EXPLAIN_KEYS, all 34 filterable sections — **unchanged**.
- **CLI surface**: no flag added, no flag removed.
- **Per-domain score breakdown**: unchanged.
- **Wire output** (terminal + report file + JSON): bit-identical to v0.5.0.

---

## [v0.5.0] — 2026-05-21

**Refactor v0.5.x — Phase 1 of 5.** This release opens the v0.5.x branch with 6 low-risk, additive refactor findings from a sub-agent audit (general-purpose) briefed with `DOCUMENTS/SNAPSHOT.md`. **Zero behaviour change in the audit pipeline:** JSON `schema_version="1"` contract preserved, 7 score domains unchanged, 116 EXPLAIN_KEYS frozen, 34 filterable sections intact.

The remaining 4 phases (v0.5.1–v0.5.4) will tackle the bigger LoC wins (`warn_with_deduction` helper across ~130 sites), the SSH directive table, the display refactor, the cron wizard refactor, and the `UFW_AUDIT_SHARE` sunset.

### Audit findings addressed

**#7 — `is_unit_active()` / `is_unit_enabled()` centralized.** Added to `bob/checks/_run.py`. Migrates the 9 sites that repeated `out = (_run("systemctl", "is-active", X) or "").strip(); if out == "active"`: `auditd.py`, `clamav.py`, `fail2ban.py`, `ntp.py`, `ddns.py`, `updates.py`, `ssh.py`, `backup.py`, `log_rotation.py` (the last one keeps its explicit `timeout=5`). `services.py::_detect_single_unit_state` keeps its richer enum return per the audit recommendation. Defensive `.lower()` added to the helper (canonical systemd output is always `"active\n"` but a downstream fork could theoretically emit `"Active\n"` — restored after review).

**#2 — `bob.output.print_titled_box()` extracted.** A 3-line ASCII box header was open-coded 4 times across `cron.py` (install wizard, manage wizard, email store sub-menu) and `manage_logs.py` (plain-text fallback). All 4 sites bypassed `_c` (the colour palette respecting `--no-color`) by inlining `\033[1;34m` literals — **this leak is now closed**. `fixes.py` was *not* migrated: its box is a streaming `╔ ║ ╠` continuation, different shape, and already routes through `_c`.

**#10 — `bob.report.Report` Protocol.** PEP 544 structural type with 12 method/attribute members. Captures the shared contract between `AuditReport` (plain-text), `NullReport` (no-op), and `MarkdownReport` (separately implemented, not in the inheritance tree). `runner.run_checks(report: Report, ...)` now type-hints the abstract Protocol; concrete classes still expose richer methods (`MarkdownReport.write_services_panorama` is unique to Markdown). No `@runtime_checkable` — static type-checking only, no runtime overhead.

**#11 — `emit_section()` + `emit_group()` closures in `runner.py`.** The 3-line `if not config.quiet: print_section(t(...)); report.write_section(t(...))` motif collapses to 1 line at 20 sites: 5 group headers (firewall_network, exposure_services, access_control, system_hardening, detection_health) + 15 section headers. `_sec()` itself is refactored to use `emit_section` internally. Net: runner.py shrinks 65 lines / +37 lines = **−28 lines**, single source of truth for section emission. Two sites intentionally NOT migrated: `print_section(t("sections.logs"))` at line 373 (no matching `report.write_section` — pre-existing anomaly out of scope) and the plugin loop at line 648 (`plugin.name` is not a translation key).

**#15a — `tests/test_domain_scores_mapping_complete.py`.** AST-scans `bob/checks/*.py` for every literal `key="X.Y"` argument to emitting methods (`add_deduction`, `warn`, `alert`, `info`, `ok`). Extracts unique prefixes and asserts each is either explicit in `_PREFIX_TO_DOMAIN` (bob/domain_scores.py) or whitelisted in `_CATCH_ALL_BY_DESIGN` with a one-line justification. The whitelist captures the v0.4.x state: `smtp`, `fail2ban`, `desktop_apps`, `virt`, `docker_audit`, `ddns`, and the legitimate firewall-domain prefixes (`firewall`, `rules`, `ports`, `services`, `ipv6`, `iptables_nft`, `firewall_stack`, `network_context`, `docker`). Re-attribution to more semantic domains is deferred to Phase 5 #15b (medium risk: changes scoring outputs). +4 tests. The test will fail on any new check that adds a prefix without explicit handling — closes the silent miscategorization class noted by the audit.

### Cron coverage pass (preliminary for Phase 5)

cron.py had the worst test ratio of the codebase per SNAPSHOT (0.60×). Phase 5 will refactor the wizards (#6: extract `_prompt` helper, dedupe 3 wizards) — adding coverage *before* the refactor is the safety net. **+35 tests** across 5 new classes:

- `TestValidateCronField` (13 tests) — wildcard, integer, range, step, list, out-of-range, reversed range, empty entry, garbage
- `TestValidateCustomCron` (7 tests) — 5-field discipline, per-field bounds (minute 0-59, hour 0-23, etc.)
- `TestBuildScriptContent` (7 tests) — shebang, `shlex.quote()` behaviour for email + log_dir, `--quiet --detailed` invocation
- `TestApplyCronSchedule` (3 tests) — schedule replacement + email-comment preservation + OSError surfacing
- `TestApplyCronEmail` (5 tests) — email comment + `NOTIFY_EMAILS=` script line + **legacy `NOTIFY_EMAIL=` (no S) regex parity** + missing-script tolerance + `shlex.quote()` quoting

### Latent bug fixed — `_os.open` in `apply_cron_schedule` (discovered by the new tests)

The v0.4.8 cron deduplication promoted `apply_cron_schedule()` from a curses-TUI private helper to a public `bob.cron` API. The extraction missed renaming `_os.open(...)` to `os.open(...)`. `_os` is a local alias used only inside three *other* functions in `cron.py` (line 649, 931, 1215 — each does `import os as _os`); at the module level, only `os` is imported. The bug was masked because the public helper was wired to the curses TUI which was not exercised by automated tests. **The new `TestApplyCronSchedule` tests surfaced the `NameError: name '_os' is not defined` immediately.** Fix: `_os.open` / `_os.fdopen` / `_os.O_*` → `os.*` (3 references on 2 lines).

### Monitoring list (release-watch)

Two APIs were added without immediate consumers — kept for symmetry / future flexibility, monitored at each release:

- `bob.checks._run.is_unit_enabled(name, timeout)` — mirror of `is_unit_active`. `services.py::_detect_single_unit_state` keeps its own `_run` call for the active/enabled state machine and is not migrated.
- `bob.output.print_titled_box(title, width=62)` — `width` parameter not exercised at any call site (all 4 sites pass the default 62).

If neither is consumed by v0.5.4, remove them.

### Tests

`4499 → 4538` (+39). Full suite passes in 7.77s on Python 3.12 / Linux Mint 22.3 / `so6desktop`.

### Compatibility notes

- **JSON contract:** `schema_version="1"`, all 116 EXPLAIN_KEYS, all 34 filterable sections — **unchanged**.
- **CLI surface:** no new flags, no flag removals.
- **Per-domain score breakdown:** unchanged (no `_PREFIX_TO_DOMAIN` modifications in this release — see #15b deferred to Phase 5).
- **Config files (`config.conf`, `services.json`, profiles):** unchanged.
- **Locale keys:** unchanged.

---

## [v0.4.8] — 2026-05-21

Code-quality audit pass 4 — performed by a `general-purpose` sub-agent briefed with `DOCUMENTS/SNAPSHOT.md` as primary cartography. The pass focused on four bug patterns from previous audits: dead dataclass fields, reinvented helpers, timeout inconsistencies, and dead code from refactors. **4 IMPORTANT + 5 MINOR + 3 SUGGESTION findings** — all addressed in this release. 4499/4499 tests passing.

### Real bug fixed (I4) — `sudo bob -d` log files were root-owned

**Reproduced**: running `sudo bob -d` on any Linux box creates the detailed audit report at `~/.local/share/bob/logs/bob_YYYYMMDD_HHMMSS.log` with mode `0o600` (already correct — confidential audit output) but owned by `root:root` because the `open()` happens inside the sudo context. The invoking user can neither `cat` nor `rm` their own audit reports afterwards. Same applies to the `logs/` directory itself when first created via `mkdir(parents=True)`.

**Why it survived**: the chown-back pattern (`bob.sysinfo.chown_to_sudo_user(path)`) was already established in 7 modules covering `~/.config/bob/` (`bob/config.py`, `bob/history.py`, `bob/ignore.py`, `bob/compare.py`, `bob/recurrence.py`, `bob/profiles.py`, `bob/registry.py`) — but the report file and log directory in `~/.local/share/bob/logs/` were never wired up. The user impact only becomes visible after the audit finishes and the user tries to read their own report.

**Fix**: 
- `bob/report.py::AuditReport.__init__` calls `chown_to_sudo_user(path)` right after `os.open(..., 0o600)`.
- `bob/manage_logs.py::get_or_prompt_log_dir` calls `chown_to_sudo_user(d)` after each of the 4 `d.mkdir(parents=True, exist_ok=True)` branches.

When BOB is not running under sudo, `chown_to_sudo_user` is a silent no-op (`os.environ.get("SUDO_USER", "")` returns `""`) — zero behavior change in non-sudo contexts.

### Dead dataclass fields removed (I1-I3 + M4-M5)

Eight dataclass fields populated by `from_system()` but never read by any consumer — same bug class as the v0.4.3 C1 fix (5 dead `HardeningSnapshot` attrs that crashed `--json-full`).

| Check / dataclass | Removed field(s) | Detection |
|---|---|---|
| `bob/checks/ssh.py::SSHSnapshot` | `config_source_files: List[str]` | Set by `_parse_config_file` recursive Include-chain walker; never read by `check_ssh`, `display`, `json_output`, or any test |
| `bob/checks/firewall.py::FirewallStatus` | `ipv4_rules_count: int` + `ipv6_rules_count: int` | Computed via `sum(1 for ln in ...)` regex passes on every audit; only consumers were test fixtures setting them to satisfy the dataclass constructor |
| `bob/checks/samba.py::SambaSnapshot` | `min_protocol: str` | Captured from `min protocol` smb.conf directive; `check_samba` consumes only the derived `smb1_enabled` bool |
| `bob/checks/clamav.py::ClamAVSnapshot` | `last_scan_log_path: str` + `db_path: str` | `_find_last_scan_date()` returned `(date, log_path)` tuple but only `date` was used; `db_path` set in the DB-existence loop but unused |
| `bob/checks/secure_boot.py::SecureBootSnapshot` | `method: str` | "mokutil" / "efivars" / "bootctl" / "none" — detection method internal to `from_system`; only `state` is consumed |

`_find_last_scan_date()` simplified to return `Optional[str]` instead of `(Optional[str], str)`. `_parse_config_file()` in ssh.py loses its now-unused `sources` parameter.

Tests updated to stop passing the removed kwargs. `tests/test_secure_boot.py::test_default_method_is_none` removed (it tested only that the field exists). Net: -1 test (4500 → 4499).

### Reinvented helpers consolidated (M1 + M3)

**M1 — `_C_LOCALE_ENV` consistency**. Three subprocess sites in `bob/checks/desktop_apps.py` (line 111: `ps -eo comm`) and `bob/checks/smtp.py` (line 58: `ps -eo comm`; line 102: `ss -tlnp` / `netstat -tlnp`) called `subprocess.check_output` without passing `env=_C_LOCALE_ENV`. Today this is benign because the output happens to be locale-independent on tested systems, but a future `ss` localising "LISTEN" or `ps` localising column headers would silently break detection. Every other subprocess site in BOB passes `env=_C_LOCALE_ENV` — fixed for consistency.

**M3 — `log_rotation._service_active` was a 12-line reinvention** of `_run("systemctl", "is-active", name)`. The other checks (clamav, fail2ban, auditd, ssh) use the one-liner form. Replaced; the local `subprocess` and now-unused `_C_LOCALE_ENV` imports also cleaned up.

### Cron management de-duplication (M2 + S2)

`bob/cron.py::edit_cron_schedule` (plain-text wizard) and `bob/tui/cron.py::_apply_cron_schedule` (curses TUI) duplicated the same regex `r"^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+root\s+\S+.*$"` + atomic-write pattern `os.open(..., O_WRONLY|O_CREAT|O_TRUNC, 0o640)`. Same for `edit_cron_email` vs `_apply_cron_email_str`, with the additional asymmetry that the plain branch accepted the legacy `NOTIFY_EMAIL=` (no S) regex while the curses branch required `NOTIFY_EMAILS=` only — meaning users upgrading from pre-v0.3 BOB cron files could edit their email via the plain wizard but not via the curses TUI.

**Fix**: `apply_cron_schedule(entry, schedule_expr) -> str` and `apply_cron_email(entry, new_email) -> tuple[str, int]` promoted to public helpers in `bob/cron.py`. `bob/tui/cron.py` now imports them and exposes thin wrappers under the original private names for the existing call sites. The legacy `NOTIFY_EMAILS?=` regex is now shared — both branches handle pre-v0.3 cron files identically.

### Other minor changes (S1 + S3)

**S1**: `bob/checks/auth_log.py::_read_auth_from_journald` hardcodes `max_days=90` for SSH brute-force history. The audit flagged the asymmetry with `--log-days` (default 7, for UFW logs). This is **intentional** — SSH brute-force attempts can be slow and sporadic over months, while UFW logs are noisy and a narrow 7-day window avoids burying the report. Documented in the function docstring so future audits don't re-flag it.

**S3**: `_BAR_WIDTH = 10` was duplicated as a module-level constant in 3 places (`bob/breakdown.py`, `bob/domain_scores.py`, `bob/display.py`). Promoted `SCORE_BAR_WIDTH = 10` in `bob/output.py` (public; private alias kept for backward-compat). `breakdown.py` and `domain_scores.py` now import it. `display.py::_BAR_WIDTH` is left alone — it's for the disk percent-bar (different semantic unit) and happens to also be 10 by coincidence.

### pyproject.toml hardening (queued from v0.4.7 analysis, applied here)

A deep pyproject.toml audit done during v0.4.7 prep had identified 6 improvements that were deferred. All 6 applied + 1 bonus:

| # | Fix |
|---|---|
| 1 | `Development Status :: 4 - Beta` → `5 - Production/Stable` (4500 tests + 7 distros CI + production hardware audited — not Beta anymore) |
| 2 | `authors` + `maintainers` fields added (PyPI was displaying "Author: UNKNOWN") |
| 3 | `[project.optional-dependencies] geoip = ["geoip2>=4.0"]` added — enables `pipx install "bodyguard-of-bits[geoip]"` for the GeoIP IP geolocation in UFW log analysis |
| 4 | `wheel` removed from `build-system.requires` (setuptools.build_meta auto-resolves wheel since setuptools 70) |
| 5 | `Source` + `Documentation` URLs added (PyPI displays icons for these) |
| 6 | Explicit `dependencies = []` with a "zero runtime deps — preserve at all costs" comment |
| bonus | `include = ["bob", "bob.checks", "bob.tui"]` explicit package list (replaces the `bob*` glob — guards against accidental top-level `bob_*` directories leaking into the wheel) |

### Tests

4499 passing (net -1 vs v0.4.7's 4500). The removed test is `tests/test_secure_boot.py::TestSecureBootSnapshot::test_default_method_is_none` — it asserted only that the `method` field defaults to `"none"`, and `method` is gone. No test depended on the removed dataclass fields beyond fixture kwargs (cleaned up).

---

## [v0.4.7] — 2026-05-21

Maintenance release — cross-documentation audit, UI cosmetic harmonization, bash completion overhaul, and release automation. No behavior change in the audit pipeline; 4500/4500 tests unchanged.

### Cross-documentation audit (24 corrections across 8 files)

Exhaustive audit catching stale claims that drifted between code state and user-facing docs since v0.4.6:

- **`README.md` / `README_FR.md`** — "9 domains" → "7 score domains" (the 9-domain count was historical from v0.1.0 and stale since v0.2.x); profile table corrected: `docker` profile listed but doesn't exist (the real profile is `container`), and `workstation` is a backward-compat alias loading `desktop` (not a separate profile).
- **`DOCUMENTS/README_TECH.md` + FR** — same "9 domains" drift; "17 profile-specific explain keys" → 19 (verified by walking `en.json::explain.{key}.server.why`).
- **`DOCUMENTS/README_DEV.md` + FR** — same "17 keys × 3 profiles" → 19; "~1500 locale keys" → exactly 1401 (verified by Python flatten with strict EN ↔ FR parity).
- **`man/bob.1`** — `--list-checks` flag documented but **doesn't exist** (real form is `--check=list`); `--min-level=info` listed as valid but the CLI parser rejects `info` (only `warn`/`alert` accepted; `info` would be a no-op since INFO is the implicit floor); `--format=text` listed but `text` is the implicit default, not a valid value of `--format=` (rejected at CLI parse).
- **`man/bob-profile.5`** — `--list-profiles` flag references removed (doesn't exist); "Up to 5 levels of inheritance" → 8 (`_MAX_EXTENDS_DEPTH = 8` in `bob/profiles.py`); SHIPPED PROFILES section gained the `workstation` entry with explicit alias status note.
- **`DOCUMENTS/AUTOMATION.md` + FR** — JSON webhook sample was completely wrong: `alerts`/`warnings` shown as arrays of `{key, message}` objects, but the real JSON top-level has them as integer counts (`engine.alert_count` / `engine.warn_count`). `risk` field shown as `"LOW"` uppercase but `engine.level.value` returns `"low"` lowercase. Sample was missing the fields `version`, `score_max`, `network_context`, `public_ip`, `deductions`, `domain_scores` that the real payload includes. Behavior claim also wrong: "POSTed only if alerts/warnings present" → actually POSTed on every audit when a URL is configured (no count threshold; filter on the receiving side). Timeout "5 seconds" → 10 seconds (`_TIMEOUT_SECONDS = 10` in `bob/webhook.py`).
- **`SECURITY_FR.md`** — untranslated `## Threat model` header → `## Modèle de menace`.

### `DOCUMENTS/SNAPSHOT.md` — new internal cartography

New ~640-line internal document providing a single-page bird's-eye view of the codebase: ASCII architecture diagram, module index for `bob/` root + `bob/checks/` with LoC and roles, dependency graph (centrality, fan-out), hotspots, patterns/conventions, 7 frozen contracts (JSON schema, exit codes, EXPLAIN_KEYS, domains, sections, plugin schema, CIS refs), CLI surface, file paths & env vars, tests-to-source mapping, architectural decisions (kept / discarded / deferred), CI matrix, numbers at a glance.

Designed to be loaded once before a refactor pass or audit so the structure does not need to be re-discovered module-by-module. Underwent 20 correction passes against the actual code state. 100% English (internal doc, not user-facing — not shipped in `debian/bob-core.docs` or `bob.spec %doc`).

### Gauge bars cosmetic harmonization (`bob/output.py::score_bar`)

All score-based progress bars (the `--watch` live display, `--breakdown` score path, per-domain scores in the audit summary, history sparkline in `--manage-logs`) now use a shared `bob.output.score_bar(score)` helper with the same colour logic as `display._disk_bar`, inverted for "high score = good":

- score ≥ 8 → **green** (healthy)
- score 5–7 → **yellow** (moderate)
- score 0–4 → **red** (critical)

Previously these bars rendered as plain monochrome `█░░░░░░░░░`. The disk partition bars (already coloured by usage threshold) are unchanged — the new helper just brings the rest of the UI into line.

Affected renderers (one-line delegation each): `bob/watch.py::_score_bar`, `bob/breakdown.py::_bar`, `bob/domain_scores.py::render_domain_scores`, `bob/manage_logs.py::display_history`. The `--no-color` flag still neutralises colours (empty ANSI strings).

### Bash completion comprehensive overhaul (`bob/data/bob.bash-completion`)

**Critical fix — value completion was silently failing**: `bob --check=<TAB>` (and all other `--xxx=<TAB>` value completions: `--skip=`, `--min-level=`, `--format=`, `--profile=`, `--lang=`, `--target=`, `--webhook-format=`, `--output=`) returned no suggestions. The completion function read `${COMP_WORDS[COMP_CWORD]}` for the current word, but with the default `COMP_WORDBREAKS` containing `=`, bash splits `--check=` into words `[--check, =]` with `COMP_WORDS[CWORD]="="`. `compgen` filtered with `"="` matched nothing. **Fix**: use the bash-completion positional-argument convention — `$2` is the "clean" current word stripped of any `=` word-break prefix, `$3` is the previous word. The handlers `[[ "${prev}" == "--check" ]]` then match correctly.

Diagnosed via `set -x` tracing of the completion function in the user's interactive session (Bash 5.2.21 on Linux Mint 22.3).

**Other fixes bundled:**

- Function renamed `_ufw_audit` → `_bob` (legacy name from before the project rename; binding updated).
- Dead code removed: `_ufw_audit_install()` + `complete -F _ufw_audit_install install.sh` registered completion for an installer script (`install.sh`) that no longer exists in the repo.
- Section list factored to `_SECTIONS` variable matching `bob --check=list` output exactly (34 entries from `bob/runner.py::_ALL_SECTIONS`). The old list had `firewall` (a core check that always runs — not filterable, misleading suggestion) and was missing `iptables_nft`, `samba`, `desktop_apps`.
- Long-options list now matches `cli.py` exactly (parity verified by diff): added `--check=`, `--skip=`, `--output-dir=`, `--breakdown`, `--no-colour`. Short-options list adds `-B` (`--breakdown`). Total: 21 short, ~40 long options — full parity with `cli.py::parse_args`.
- New `--skip=` value handler (mirror of `--check=` minus the `list` special value).
- All value handlers now support both forms: `--xxx=value<TAB>` (equals split) and `--xxx value<TAB>` (space split).

### CI — automatic GitHub Release on tag push (`.github/workflows/publish.yml`)

Adds a fourth job `github-release` after PyPI publish. Pipeline becomes:

```
git push --tags
  → test (Python 3.10/3.11/3.12/3.13)
  → build (sdist + wheel)
  → publish (PyPI via OIDC Trusted Publishing)
  → github-release  ← NEW
       • Extract title from CHANGELOG.md table row (text before " — ")
       • Extract body from DOCUMENTS/CHANGELOG_FULL.md section
         between "## [vX.Y.Z]" and next "## [v"
       • Create release via softprops/action-gh-release@v2
       • Attach wheel + sdist as release assets
       • Mark as latest
```

If PyPI publish fails, the GitHub release is not created (`needs: publish` dependency). If `CHANGELOG_FULL.md` lacks the matching section, the workflow fails explicitly. Permission: `contents: write` only.

Previously the GitHub release was created manually with `gh release create` after each PyPI publish.

### Tests

No new tests. 3 tests in `tests/test_breakdown.py::TestBar` adapted to strip ANSI escape sequences before asserting visible bar content (the bars are now ANSI-coloured strings rather than plain `█░░░░░░░░░`). 4500/4500 tests still passing.

---

## [v0.4.6] — 2026-05-17

Terrain test pass v0.4.5 produced two reproducible bugs across 13 audits on 6 distinct systems (5 VMs + 1 production workstation). v0.4.6 fixes both — narrowly scoped hotfix, no behavior change outside the two reported scenarios.

### Bug 1 — Kernel listing included removed packages (`rc` state)

**Reproduced on**: Mint test VM after `apt dist-upgrade` + `apt autoremove`; production Linux Mint 22.3 workstation after the same workflow. Confirms this is not a VM edge case — it is the standard outcome of any user running `apt remove` (or its transitive form `apt dist-upgrade`) on an obsolete kernel image.

**What happened**: `bob/checks/kernel_modules.py` listed installed kernels via `dpkg-query -W -f='${Package}\n' linux-image-[0-9]*`. `dpkg-query` returns every package matching the pattern *regardless of installation state*, including those in `rc` state (removed but config files in `/etc` still present). `apt remove` (without `--purge`) leaves a package in `rc` — the kernel binary in `/boot` is gone, but the package name still appears in BOB's listing. Result: "Installés : …, 6.17.0-20-generic, …" for a kernel that was already uninstalled.

**Fix**: the dpkg-query format string is now `${db:Status-Abbrev}|${Package}\n`. `${db:Status-Abbrev}` is a two-character code describing desired action + current status (`ii` = installed, `rc` = remove-configfiles, `pn` = purge-not-installed, `iU` = install-unpacked, etc.). `_parse_installed_kernels` keeps only lines whose 2nd character is `i` (current status = installed), which covers `ii` and `hi` (held-installed) while excluding `rc`, `pn`, `un`, `iU`, and transient states where binaries may or may not exist. Backward compatibility preserved: the parser still accepts plain `linux-image-…` lines (no prefix, no `|`) for test fixtures and any caller that doesn't pre-prefix.

**Severity**: cosmetic in the BOB output — no scoring impact — but high reach (every Debian-family user who has ever cleaned an old kernel).

### Bug 2 — Score dropped after remediation (domain disappeared from active set)

**Reproduced on**: Debian 13 VM. Pre-`apt upgrade`: `updates.security_pending` WARN present → score 7/10. Post-`apt upgrade`: only `updates.ok` emitted → score *dropped* to 6/10. User-observed effect: making the system more secure produced a worse score, the exact opposite of intuition.

**Why**: `bob/domain_scores.py::active_domains_from_engine()` selected which domains contributed to the global average. The selection filter was `(WARN, ALERT)` only — domains where every finding was OK or INFO were excluded. When `apt upgrade` resolved the WARN, the `updates` domain switched to emitting only `updates.ok`, dropped out of `active_domains`, and the global average was recomputed over a smaller set:

```
Before remediation: avg(updates=8, hardening=4, …) / N        = 7
After  remediation: avg(            hardening=4, …) / (N-1)   = 6   ← BUG
With fix          : avg(updates=10, hardening=4, …) / N       = ~7+ ← CORRECT
```

**Fix**: `_actionable` widened from `(WARN, ALERT)` to `(OK, WARN, ALERT)`. A domain becomes active as soon as any check from it emits a recognisable signal (clean OK or actionable WARN/ALERT). INFO findings remain excluded from promotion — terrain Mint test confirms this is the correct line (INFO-only domains intentionally stay hidden, no transition observed there).

This widening cascades cleanly: domains with only OK findings now appear at 10/10 in the global average, so well-secured aspects of the system are visible in the score instead of being implicit.

### Test additions

- `tests/test_kernel_modules.py`: 5 new tests covering `ii` keep, `rc` exclude, mixed `ii`+`rc`+`pn`+`un`+`iU` filtering, `hi` (hold) keep, and legacy/prefixed format mixed parsing.
- `tests/test_domain_scores.py`: 6 new tests under `TestActiveDomainsIncludesOK`, including the exact Debian 13 remediation scenario asserting the global goes from 8 to 9 when the resolved domain stays visible.

### Verification

- 4500/4500 tests (+11 vs v0.4.5). No regression in the rest of the suite.
- Bug 1 reproduced and now fixed on Mint test VM (post-autoremove kernel listing accurate) and so6desktop (linux-image-6.17.0-20-generic no longer appears after `apt remove`).
- Bug 2 reproduced and now fixed on Debian 13 VM (score now goes up after `apt upgrade`).

---

## [v0.4.5] — 2026-05-16

Test infrastructure hardening release. The new locale-coverage test introduced in v0.4.4 worked correctly but rested on a regex scan of the source code, which has known structural limits. v0.4.5 replaces the regex pipeline with proper AST parsing, eliminating three classes of false positive in one go and removing the `_KEY_EXCLUSIONS` allowlist that was the symptom of the underlying limitation.

### What changed

`tests/test_locale_coverage.py` no longer reads source files as text. It uses `ast.parse` per `bob/**/*.py`, walks the tree, and treats only nodes matching `ast.Call(func=ast.Name(id="t" | "_t"), args=[ast.Constant(str), ...])` as translation call sites. The first positional argument is the literal key.

### What this fixes (vs the regex form)

- **Docstring matches.** The regex matched any `t("...")` literal in source text, including documentation examples. v0.4.4 had to allowlist `samba.open_world` and `log.blocked_attempts` because they appear as examples inside docstrings in `bob/i18n.py`. With AST parsing, docstrings are inert string constants without a calling site — they cannot produce a false positive. The allowlist is gone.
- **Multi-line call site misparses.** The regex required the opening parenthesis and the opening quote to be near each other on the same matched window. Calls split across lines or wrapped over `,` could occasionally trip the pattern. AST is whitespace-independent — the same `ast.Call` is recognised regardless of formatting.
- **Attribute call false positives.** `obj._t("foo.bar")` matched the regex (the negative lookbehind v0.4.4 added on `.` covered most but not all edge cases). With AST, `obj._t` resolves to `ast.Attribute`, not `ast.Name` — the type check rejects it cleanly.

### What's preserved

The external test contract is identical: same 9 tests (`TestLocaleCoverage` + `TestExplainNamespaceCoverage` + `TestPlaceholderParity`), same fixtures, same assertions. Only `_all_t_keys()` and its helpers were refactored. Test count stays at 4489.

### Performance note

AST parsing is ~5× slower than regex on this codebase (300 ms vs 60 ms for `tests/test_locale_coverage.py`). Negligible in absolute terms — the whole test suite still runs in ~6.5 s.

### Tests

4489/4489 — unchanged from v0.4.4. This release is pure refactoring of an existing test file. No source code in `bob/` was modified.

### Deferred to a later release

Items that were already on the roadmap remain there:

- Phase 2 Option A — `Finding.template_vars` migration on ~37 non-pilot checks (still tracked for v0.5.0+).
- M3 cosmetic cleanup (`os.path` → `pathlib`).
- Multi-distro CI matrix and AUR PKGBUILD.

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

4489/4489 — +21 vs v0.4.3:
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

4430/4430 (+82): 16 new in `test_i18n.py` (12 `detect_system_lang` + 4 CLI integration), 17 in new `test_json_schema.py` (top-level invariants, field types, stable-key exposure, strict-set + constants-drift defense-in-depth from post-review pass #2), 6 in `test_explain.py` (alias map + freeze policy), 43 in new `test_services_schema.py` (schema valid, bundled services match, sample valid/invalid plugins, Python ↔ Schema parity, plus `$defs` factorization / strict 1–65535 port regex / business `if/then` constraints / plugin-file `schema_version` wrapper / `minItems: 1` from post-review passes #1+#2).

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

---

© 2026 Cédric Clauzel
