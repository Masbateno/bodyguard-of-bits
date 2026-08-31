*[Lire en français](TESTING_FR.md)*

# BOB — Test plan and version test history

Two complementary parts:

- **Unit test history** (per-version table + detailed sections) — every release lists the tests added, removed, or corrected, with the platform and test count at the time. This is the audit trail of how the suite grew from v0.1.0 (4200 tests) to v0.6.0 (4583 tests). The +45 net growth across v0.5.5 → v0.5.8 came from the deep-audit campaign hardening regressions. v0.6.0 is contract-preserving — the ssh.py + cron.py splits and the UFW_AUDIT_SHARE sunset add zero test delta.
- **Manual UFW regression plan** (Categories A–E at the bottom) — deliberately dangerous UFW rules and the expected BOB behaviour for each. Used to validate detection + remediation on real systems.

---

## Unit test history

| Version | Tests | Notes |
|---------|-------|-------|
| v0.15.1 | 7231 | **A second hunt, to test the first one's result — in progress (branch `v0.15.x`).** New angles only: cross-checking overlapping checks against each other, which no module-by-module audit can see. Carries the documentation pass v0.15.0 deferred. |
| v0.15.0 | 7220 | **Verdict accuracy (2026-08-31).** Differential testing against the owning parser (`sshd -T`, `ssh -G`, `cvtsudoers -f json`) instead of hand-written expectations. One defect class dominates: patterns written against the tidy form of a line stopped matching once an operator added a trailing comment — a commented `allow from anywhere` UFW rule was undetected, and `NOPASSWD: ALL # temporary` was downgraded from WARN −2 to a scoreless INFO. Every fix is mutation-tested: the defect is re-injected and the guard must fail. |
| v0.14.1 | 6719 | **First v0.14.x patch — `privileged` semantics + three stress-test campaigns (2026-08-30).** **Semantics:** `container_security.privileged` was `cap_bnd & (1 << CAP_SYS_ADMIN)` — literally "CAP_SYS_ADMIN present" — so `--cap-add SYS_ADMIN` was reported PRIVILEGED under the headline *"full capability set"*. Measured on podman: 2149844475 vs **2199023255551** = `(1 << 41) - 1`. Now the full bounding set from `/proc/sys/kernel/cap_last_cap` (bounds-checked), plus the additive key `container_security.cap_sys_admin`. **Campaign 1 — resilience:** `runner._sec` had no exception handling, so one failing check cost the ENTIRE audit (exit 3, zero bytes of stdout) — reproduced with a latin-1 byte in an `/etc/passwd` GECOS field. Sections now degrade in place (`<section>.unavailable` INFO + new JSON `degraded_sections`); exit codes deliberately unchanged. Required converting 29 eager `_sec` snapshot sites to lazy factories (`--check=ssh` 2.60s → 1.91s). `UnicodeDecodeError` escaped 33 `except OSError` guards; `load_history` died on a JSON-valid non-object line; `--lang` accepted an absolute path; reports lacked `O_NOFOLLOW`; CSV formula injection; missing dash guard on `--profile`/`--check`/`--skip`. **Campaign 2 — the fixes themselves:** the barrier could be defeated from inside its own handler (rendering outside the inner try); report writes had no error handling at all (a full 64 KB tmpfs cost the whole audit); `--ignore` silenced the score but not the terminal (`display_result` renders the raw `CheckResult`); terminal escape sequences from system-derived values reached the terminal (a cron-script *filename* carrying `\033]0;…\007` rewrote the window title) — now sanitized in `add_finding`, one choke point for every format; unbounded reads on non-regular files (plugin symlinked to `/dev/zero` → OOM; `--diff=<fifo>` → **hung forever**) closed by `_atomic.read_text_capped()`; Ctrl-C printed a traceback. **Campaign 3 — what the tool says:** the active profile appeared only in the terminal (now a `profile` field in JSON/webhook + Markdown/HTML headers; CSV deliberately untouched); `-p NAME` silently persists as the default (undocumented since v0.12.1); both READMEs documented `-d` as "French output". **Verified clean:** 12000 argv combinations, 46 sections under a restricted userns, 8-way concurrency, the whole i18n key space (966 literal + 637 runtime expansions in both locales), scoring invariants over 6000 random engine states, JSON schema over 16 payloads, `--fix` dry run (0 subprocess calls), determinism, signals, a 34 MB UFW log. **6590 → 6719 (+129**: 17 privileged + 64 + 32 robustness + 16 contract surfaces). 0 regression. 20 mutations injected, 20 guards confirmed killing them. |
| v0.14.0 | 6590 | **First v0.14.x release — BREAKING contract-fix bundle (2026-08-29).** **🔴 The audit profile never reached 12 of the 14 check-result paths**: callers had to invoke `apply_profile()` before `engine.apply()`, and only `_sec` + the plugin path did — so 8 overrides shipped in `desktop.conf`/`workstation.conf` were inert, and a LAN host with Samba behind a UFW rule returned exit 1 permanently, making the documented `exit 0` unreachable. `ScoreEngine` now takes `profile=` and applies overrides inside `apply()`, the single choke point. BREAKING on desktop/workstation (`warning_count` 4 → 2 measured live); `server` untouched. **Colour was emitted unconditionally (BREAKING)**: `bob > file` wrote ANSI codes; `supports_color()` existed and was called from nowhere. Now wired with `--no-color` → `NO_COLOR` → `FORCE_COLOR` → `isatty()`. **`--help` wording** for the colour env vars. **Plus** B904/B905, 8 wrong packaging weekdays, and the root README's exit-code table (fabricated score bands → the real contract). **6547 → 6590 (+43**, mutation-tested; the profile guards are behavioural, not structural — the old design was "correct" at every call site that remembered, which is why the suite passed before the fix too). |
| v0.13.4 | 6545 | **Documentation-accuracy pass — factual corrections only (2026-08-28).** Machine audit of the whole doc corpus. The FR security section was **factually inverted** for 7 minor releases; 5 CLI options were undiscoverable; 29 broken or leaking links. Plus 3 guards (links, EN/FR per-section parity, CLI surface). **6533 → 6545 (+12).** |
| v0.13.3 | 6533 | **First v0.13.x hardening patch after the branch's scope growth (2026-08-28, additive, no score change).** Logging hygiene (`NullHandler` + `BOB_DEBUG`), filtered-run performance (−52 % on `--check`), a doc-counter drift guard, and a ruff correctness gate (E9/F/B, nothing ignored). **6511 → 6533 (+22).** |
| v0.13.2 | 6511 | **Same-day finding-command safety/coherence patch (2026-06-21, additive, no score change).** Sub-agent semantic-coherence pass over ~144 finding commands (triggered by a user noticing `apt purge` under a "Verify:" label). **docker `userns_not_configured` 🔴**: remediation `tee /etc/docker/daemon.json` overwrote the whole file (data loss) — now create-if-absent only (`test -f … \|\| {…}`, no human-language text), detail warns to back up + merge (EN+FR). **kernel `kernels_obsolete`**: destructive `apt purge` moved from `cmd_type="check"` (Verify ℹ) to `"fix"` (What to do →). **kernel `kernels_update_available`**: invalid `cmd_type="action"` → `"fix"`. **guard**: `add_finding` raises on cmd_type outside `("fix","check")`. Audit confirmed these are the only presentation bugs (all other check-cmds are reads, all fix-cmds are actions, EN/FR sense parity holds). **6504 → 6511 (+7**: 6 `test_v0132_cmd_semantics.py` + 1 `test_kernel_modules.py`). 0 regression. Validated live EN+FR. v0.12.x remains EOL; v0.13.x only supported line. |
| v0.13.1 | 6504 | **First v0.13.x hardening patch — additive runtime-context checks (2026-06-21, INFO-only, non-BREAKING, no score change).** Continues the runtime turn in-branch; teeth (container/nftables scoring) held for the planned v0.14.0 BREAKING bundle. **Orphan systemd socket units** (`socket_units`): flags a `.socket` still active while its backing `.service` is broken — gone (masked/not-found) or crashed (`ActiveState=failed`) — or the socket itself is `failed`; orphaned if any of several triggers is broken; merely-inactive backing service is healthy; marks non-loopback binds; empty-`Triggers` systemd internals never flagged. **Host-side cloud context** (`cloud_context`): suppressed off-cloud; conservative detection (DMI provider, or cloud-init corroborated by on-link IMDS — a bare cloud-init homelab VM is not flagged); surfaces IMDS reachable on-link (IMDSv2 reminder) + world-readable user-data — strictly host-side, no cloud API/credentials. **ddns + ssh robustness**: a path under an unsearchable dir (hardened `/root`, userns) raised `PermissionError` — in ddns it aborted the audit (`_config_present()` now degrades to "absent"); the live field test surfaced the same class in `ssh/_snapshot.py` (`~/.ssh` under an unsearchable home leaked the error string), now guarded too. Sections 36 → 38. **6461 → 6504 (+43**: 21 `test_socket_units.py` + 18 `test_cloud_context.py` + 3 `test_ddns.py` + 1 `test_ssh.py`). 0 regression. Validated live EN+FR (socket negative+positive; cloud negative live + positive crafted; ddns EACCES via mode-000 dir). v0.12.x remains EOL; v0.13.x the only supported line. |
| v0.13.0 | 6461 | **First v0.13.x release — scope expansion: two new INFO-only checks (2026-06-20).** First real coverage growth after the long internal-hardening cycle; both additive, non-BREAKING, no score deduction. **`systemd-analyze security`** (`systemd_hardening`): surfaces the systemd exposure score of running services (parsed from `--json=short`, scoped via `systemctl list-units`) — summary by predicate (UNSAFE/EXPOSED/OK) + least-hardened services + pointer to `systemd-analyze security <unit>`; no deduction (unhardened-by-default is normal, not a misconfig). **Container security posture** (`container_security`): runs only inside a container (suppressed on a host via `skip_if`); reads CapBnd → privileged/CAP_SYS_ADMIN detection, seccomp, userns (uid_map), writable rootfs from `/proc`; INFO-only (privileged-container WARN is a fast-follow). systemd field-tested live EN+FR; container validated against real kernel `/proc` data inside `unshare` user namespaces (privileged + non-privileged + the userns-suppresses-root-warning branch, EN+FR). Sections 35 → 36. **6442 → 6461 (+19**: 7 `test_systemd_hardening.py` + 12 `test_container_security.py`). 0 regression. **v0.12.x declared EOL** (latest-minor-only policy); v0.8.x–v0.11.x likewise EOL; v0.13.x the only supported line. v0.7.x / v0.6.x remain EOL. |
| v0.12.2 | 6442 | **Branch-closing hardening cleanup — whole-tool deep-audit + unexplored-angles sweep (2026-06-12). Closes the v0.12.x branch.** Audit verdict: 0 critical / 0 important. Verified clean: `_atomic` (mkstemp+fchmod+fsync), `webhook` (scheme guard + redaction + finite timeout), subprocess (no shell=True, LC_ALL=C, authorized_keys symlink guard), log/config parsers (anchored, no ReDoS), i18n 1975/1975 parity, no key-literal drift, profile `.conf` parser (extends bounded 8 + fallback). Two fixes: **M-1** `_DOMAIN_SECTIONS` held key prefixes `virt`/`logs` instead of real sections `virtualization`/`ufw_logging` (unreachable — both always-on — but inaccurate; remapped + drift guard asserting every entry is a real `runner._SECTIONS` name). **Cron name defense-in-depth**: name is slugged for the path but written verbatim into the `# name:` comment of the root cron file; `input()` is line-based so NOT an exploitable injection, but control chars are now stripped so a name can't inject a second cron line regardless of source (consistent with strict `_validate_custom_cron`). **6437 → 6442 (+5**: `test_v0122_branch_close.py`). 0 regression. v0.7.x remains EOL; v0.6.x remains EOL. |
| v0.12.1 | 6437 | **First v0.12.x hardening patch — domain-display completeness + naive/advanced audit fixes (2026-06-12, additive/non-BREAKING).** Show all 7 domains even when inactive, tagged with the precise reason (`not_installed` / `not_assessed (<profile> profile)` / `not_assessed (--check/--skip)` / `no action needed`); never counted in the average (preserves scores + F1 + v0.4.5 guard). `disk` is never wrongly "not installed". Surfaced in text + JSON + Markdown + HTML, EN+FR. Then a naive + 4-round advanced audit fixed: **A** `--check`/`--skip` mislabel → `filtered` reason via `_section_enabled`; **B** `--profile=typo` persisted the invalid name to config → only valid profiles saved; **C** unknown `--profile` reported before the root gate; **E** `--english`, `--output=html`, `--output=json-full`, case-insensitive `--check`/`--skip`/`--explain`/`--output`; **ADV-1** JSON `domain_scores[d]` gains `active`+`reason` (machine can reproduce the headline) — additive in schema v3; **ADV-G2** `history.jsonl` healed to 0600 on every write; **ADV-B1** domain breakdown added to Markdown + HTML. Audit also verified clean: determinism, scoring math (domain cap × F1 × posture), concurrency, `LC_ALL=C`, `--ignore`, `--no-color`. **6401 → 6437 (+36**: `test_v0121_domain_display.py` + history/JSON). 0 regression. Bilingual live field test clean. v0.7.x remains EOL; v0.6.x remains EOL. |
| v0.12.0 | 6401 | **First v0.12.x release — planned BREAKING UX bundle F1/F2/F4/F6/F9 (2026-06-11).** The five v0.11.x deep-bilingual-live-test findings that change a contract, exit code, or score. **F1** (BREAKING, score): the headline = mean of active domain scores, so one firmware deduction (raw 9) averaged `(6×10+9)/7=9.86 → 10/10` while the summary said "Action required". Now "10/10 = flawless audit" — when `raw_score < MAX_SCORE` the headline caps at 9; `--breakdown` shows average → cap (new `domain_average_precap` + key `breakdown.f1_cap`); JSON `score` reflects the cap. **F2** (presentation): summary per-item bullet now reflects severity (`⚠`/`✖`) to match the body (was hardcoded per nature-section); header still groups by nature. **F4** (BREAKING, exit): `--explain <unknown>` now exits 3 not 0 (`run_explain`→bool); adds a difflib "did you mean" suggestion (key `explain.ui.did_you_mean`). **F6**: `--check`/`--skip` validation moved before the root gate, so a bad token reports without demanding sudo (static AST order guard). **F9** (BREAKING, schema v2→v3): `alerts`/`warnings` int counts renamed `alert_count`/`warning_count` (symmetry with `info_count`); a key rename bumps `schema_version` "2"→"3" per the documented rule + clean-cut precedent (`SUPPORTED={"3"}`); webhook keeps `alerts`/`warnings` (separate flat contract). Test-isolation fix: watch score-bar tests force monochrome (`output.init(no_color=True)`) instead of a leaked global. Pre-ship sub-agent audit: 0 critical / 0 important → SHIP. **6381 → 6401 (+20**: 6 F1 + 3 F2 + 6 F4 + 2 F6 + 3 F9). 0 regression. v0.7.x remains EOL; v0.6.x remains EOL. |
| v0.11.2 | 6381 | **Second v0.11.x hardening patch — i18n completeness F8 + F8b (2026-06-11).** Closes the two remaining French-audit gaps found by a deep bilingual live test of v0.11.1. **F8**: the 60 BOB-authored "Best practice — …" reference lines in `bob/data/cis_refs.json` (code:null entries) were English-only → now each has a French `ref_fr`; `get_cis_ref()` is locale-aware (lazy `i18n.current_lang()`). The 114 CIS-coded entries keep canonical English titles by design. **F8b**: two inline `# …` comments in `cmd=` suggestions (`ipv6.py`, `log_rotation.py`) were hardcoded English (same class as the v0.11.1 disk.py fix, which was incomplete) → now locale keys. New anti-drift guard forbids hardcoded `  # <text>` in `cmd=` literals. Two deep-test observations verified as NON-bugs (left as-is): `--unignore` residual `ignore:` header (deliberate I-1 comment preservation) and box alignment (all lines 80 chars; visual offset = emoji display width). **6369 → 6381 (+12**: all in `test_v0112_i18n_refs_and_cmd_comments.py` — 9 F8 + 3 F8b). 0 regression. v0.7.x remains EOL; v0.6.x remains EOL. |
| v0.11.1 | 6369 | **First v0.11.x hardening patch — two deep-audit minors + three UX-audit polish fixes (2026-06-11).** 20th deep-audit pass: 0 critical + 0 important + 2 minor (cmd construction / atomic-write / HTML escaping / literal-key contracts all clean). **M-1**: `bob/i18n.py::t()` caught only `KeyError` from `str.format()` — a malformed locale template (unbalanced brace → `ValueError`, positional `{0}` → `IndexError`) crashed the audit for that locale. `t()` now degrades on `(KeyError, IndexError, ValueError)`; `try_t()` gains the IndexError/ValueError guard (preserving intentional KeyError propagation). New locale linter `TestTemplateWellFormed` rejects malformed templates at CI. **M-2**: `--test-webhook` now honors `--offline` (the audit path already did) — `bob --test-webhook --offline` skips the POST cleanly (stderr notice, EXIT_OK) instead of egressing; new key `cli.test_webhook.offline_skipped` (EN+FR). **Plus three trivially-safe polish fixes from a functional/perceived-quality (UX) audit** (no-contract-change subset; score-model F1 / presentation F2 / exit-code F4 / root-gate F6 → v0.12.0): **F3** fwupd device-name parsing leaked connector junk (`?`, `??UEFI dbx:`) when the tree degraded to `?` under `LC_ALL=C` — now runs fwupd under `C.UTF-8` (`_C_UTF8_LOCALE_ENV`) + a parser guard rejecting non-alphanumeric-leading names; **F5** the unknown-key explain hint wrongly said sudo (`--explain list` needs none), dropped EN+FR; **F7** protocol-unspecified UFW orphan rules now show `57621/tcp+udp` not a bare `57621` (delete cmd keeps the bare port). **Plus a documentation accuracy pass** (DOC-A…G): `--json-v1` (retired v0.9.0) removed from user docs; `workstation` profile reconciled to first-class + added to `--help`; EXPLAIN_KEYS counts → 169/45, "43 checks" → 34 sections; `UFW_AUDIT_SHARE` → `BOB_SHARE`; man dates → 06-11. **6336 → 6369 (+33**: 9 i18n/webhook + 2 locale-linter + 9 `test_v0111_ux_audit_fixes.py` + 6 `test_v0111_doc_accuracy.py` anti-drift). 0 regression. v0.7.x remains EOL; v0.6.x remains EOL. |
| v0.11.0 | 6336 | **First v0.11.x release — BREAKING bundle: hygiene + design fix (2026-06-10).** Opens v0.11.x. Two BREAKING items; F-1 parallel checks stay deferred indefinitely (zero perf signal). **M-3 ssh Host scope**: `_check_client_config` is now scope-aware — `ForwardX11 yes` / `ForwardAgent yes` scoped to a non-global `Host` block emit INFO with no deduction (`ssh.x11.forwarding.client_scoped` + `ssh.client_forward_agent_scoped`, EN+FR `{host}` placeholder); global keeps WARN+deduction; `StrictHostKeyChecking no` + `UserKnownHostsFile /dev/null` stay ALERT any scope. A multi-pattern line with a bare `*` (`Host gitlab *`) counts as global (`scoped = "*" not in entry.host.split()`, hardened by the pre-ship audit). BREAKING: scoped forwarding no longer deducts. **D-4 Rank 2-8 KILL**: `SUBCHECK_RENAMES_V100` reduced 14→1 (kept Rank 1 only); the 13 removed entries were inert (canonical patterns emitted by nothing; live monolithic keys covered by exact-match). Behaviour-preserving. **CI guard** `tests/test_v0110_legacy_key_drift_guard.py`: AST sweep forbidding production literals referencing a renamed-away key (generalises the v0.10.2 static guard). **Posture matrix** `tests/test_v0110_posture_matrix.py`: exhaustive 8-cell UFW×iptables×domain_score matrix + branch isolation + priority resolution (closes the masking-branch debt that hid v0.10.2 I-1). SNAPSHOT.md refreshed v0.10.0→v0.10.2. Pre-ship sub-agent audit: 1 important (multi-pattern Host evasion) fixed pre-tag, 2 minor deferred. **6268 → 6336 (+68**: 15 posture matrix + 4 drift guard + 37 D-4 kill pin + 12 ssh Host scope). 0 regression. v0.7.x remains EOL; v0.6.x remains EOL. |
| v0.10.2 | 6268 | **Second v0.10.x hardening patch (2026-06-10) — I-1 fix from the post-v0.10.1 deep hardening audit.** Same-day sub-agent pass on the post-v0.10.1 surface returned 4 findings (1 important + 3 minor); conservative workflow filter "gain × risque = STOP" selected I-1 only. **The bug**: `bob/scoring.py::set_posture_from_engine` looked for findings with the v0.7.x / v0.8.x legacy key `iptables_nft.input_accept` to flip the `iptables_input_accept` posture flag. The prefix was renamed `firewall_iptables.*` in v0.9.0 D-1, so the string-literal comparison stopped matching anything. **The iptables-only posture escalation has been silently dead since v0.9.0** (3 majors). Masked by the `firewall_inactive` branch on UFW-down hosts but UFW-active + iptables INPUT ACCEPT regressed from HIGH to LOW. **Fix**: update the literal to `firewall_iptables.input_accept` to match the v0.9.0+ canonical key emitted by `bob/checks/iptables_nftables.py:174`. Single source of truth (since v0.7.3 M-10) covers both `bob/__main__.py::audit` and `bob/watch.py:109`. **Tests** (`tests/test_v0102_posture_iptables_key.py`, NEW, 7 tests): `TestPostureIptablesKey` (4 — canonical triggers / legacy does not / sanity / firewall_inactive independent) + `TestNoLegacyKeyInLiveCheck` (2 static guards — scoring.py + full bob/ sweep with v0.9.2 migration shim allowlist) + 1 parametrize pinning `EXPLAIN_KEYS` contract. 6261 → 6268 (+7). 0 regression. **Conservative workflow**: M-1 (duplicate Host blocks triple-deduct, pre-existing 4 directives, no signal 5+ majors), M-2 (cosmetic hoist), M-3 (Host scope semantics, real v0.10.1 contract leak via explain-text mismatch, v0.11.x candidate) deferred. v0.7.x remains EOL; v0.6.x remains EOL. |
| v0.10.1 | 6261 | **First v0.10.x hardening patch (2026-06-10) — D-4 Rank 1 `ssh.x11_forwarding` split + NEW client-side ForwardX11 detection.** Conservative workflow: 1 curated D-4 split with measurable security gain (adds previously-missing detection), other 7 ranks + F-1 deferred until user signal per the "gain × risque = STOP" rule. **Server-side**: `ssh.x11_forwarding` renamed to `ssh.x11.forwarding.server` in `bob/checks/ssh/_directives.py` (`_BadDirective` row for `x11forwarding`). **Client-side (NEW)**: `_check_client_config` adds `elif k == "forwardx11" and v == "yes"` branch emitting `ssh.x11.forwarding.client` with full warn + detail + cmd remediation. Pre-v0.10.1 BOB had **zero** client-side X11 detection. **Back-compat**: pre-v0.10.1 `ignore.yml` entries with `ssh.x11_forwarding` cover both new sub-keys via the v0.10.0 `SUBCHECK_RENAMES_V100` shim (fnmatch glob `ssh.x11.forwarding.*`); `bob --explain ssh.x11_forwarding` resolves to server content via `EXPLAIN_KEY_ALIASES` (first live alias after the v0.9.0 D-3 retrait emptied the dict). Locale migration (EN + FR) + 6 new `explain.*` leaves with client-side risk wording. EXPLAIN_KEYS 168 → 169 (+1). CIS refs: server keeps CIS:5.2.6, client gets Best practice ref. Canonical_pattern regex extended with `_SSH_X11_FORWARDING_RE` exception covering the 4-segment form. 6242 → 6261 tests (+19: 10 dedicated in `tests/test_v0101_ssh_x11_client.py` across `TestServerSideRename` / `TestClientSideDetection` / `TestBackCompat` + 9 elsewhere from constant + regex + freeze + format + test_ssh + test_profiles updates). 0 regression. v0.7.x remains EOL; v0.6.x remains EOL. |
| v0.10.0 | 6242 | **First v0.10.x release (2026-06-09) — preparation release** opening the next BREAKING bundle window. Ships the D-4 sub-check migration shim foundation (`bob/_v100_subcheck_renames.py::SUBCHECK_RENAMES_V100` + `matches_legacy_ignore` + `any_legacy_ignore_matches`) + `ScoreEngine.apply` ignore.yml back-compat wiring (legacy v0.9.x entries continue to suppress findings via `fnmatch` glob match against `SUBCHECK_RENAMES_V100` when v0.10.1+ ships the actual splits). Both sub-agent audits (D-4 sub-check candidates + F-1 parallel-check thread-safety) ran on 2026-06-08 with concrete file:line citations + ranked candidate lists + effort estimates: D-4 ≈ 20 h across 8 ranked splits (Rank 1 ssh.x11 server/client, Rank 2 DSA family unification, Rank 3 auditd missing per-bucket, Rank 4 samba per-share wildcard, Rank 5 journald volatile vs storage_unknown, Rank 6 firewall_rules duplicate algos, Rank 7 kernel_modules per-name wildcard, Rank 8 SSH weak crypto per-algo wildcard), F-1 ≈ 6-8 h runner.py 3-phase Option B refactor + 4 new determinism test files. **D-4 splits + F-1 implementation deferred to v0.10.1+** as hardening patches. SNAPSHOT.md refreshed v0.7.4 → v0.9.2 + v0.10.0 prep paragraph. 6242 → 6242 tests (no delta — shim foundation does not change visible behavior on existing ignore.yml entries until v0.10.1 ships the first split). 0 regression. v0.7.x remains EOL; v0.6.x remains EOL. |
| v0.9.2 | 6242 | **Closes the two i18n / UX gaps documented in the v0.9.1 CHANGELOG as "deferred to v0.10.0+"**, both surfaced by the v0.9.0 cross-distro field test campaign. **BaselineLoadError i18n** (`bob/compare.py`): the 4 raise sites used hardcoded English messages even on FR systems. Wires 4 new locale keys `compare.baseline_load.{not_found, invalid_json, v1_schema, bad_shape}` (EN + FR) via the `bob._i18n_safe.t_or_hardcoded` helper. **Cross-version baseline migration shim** (`bob/_v090_renames.py::remap_finding_key`): a baseline written by v0.7.x / v0.8.x carried finding keys with prefixes renamed in v0.9.0 D-1 (`iptables_nft.*`, `cron_audit.*`, …); the v0.9.0+ audit emits the canonical prefixes (`firewall_iptables.*`, `cron.*`, …), so the diff surfaced the same physical issue as both *resolved* AND *new*. The shim remaps legacy → canonical at baseline load time, covering all 7 D-1 renames. Idempotent on canonical input — does not affect v0.9.0+ baselines. **Shared map extraction**: `SECTION_RENAMES_V090` extracted from `bob/runner.py` to `bob/_v090_renames.py` so `bob/compare.py` can consume it without a circular import. `bob/runner.py` keeps the legacy name `_RENAMED_SECTIONS_V090` as a back-compat re-export (object identity asserted by `test_v092_baseline_i18n_and_shim.py::TestV090RenamesSharedModule`). 6212 → 6242 tests (+30 across 4 classes: shared-map back-compat + 7-entry contract; remap_finding_key 8 legacy + 6 canonical + 4 edge cases; load_baseline shim v0.7.x / v0.8.x + v0.9.x pass-through + pre-v1.22 guard; BaselineLoadError FR rendering + locale-key presence). 0 regression. **v0.7.x remains EOL** (declared v0.8.1); **v0.6.x remains EOL** (declared v0.7.2). |
| v0.9.1 | 6212 | **Hotfix v0.9.0 F-3 message UX**. The `--json-v1` retrait path called `i18n.t()` from inside `parse_args()` which runs BEFORE `i18n.init()`, so the user saw `Error: [cli.error.json_v1_retired]` (bracketed-fallback) instead of an actionable message. Reproduced 5/5 distros × 2 locales during the v0.9.0 cross-distro field test campaign (Mint desktop, Debian 13, Kali Rolling, Mint server FR, Ubuntu 26.04 FR). Fix: inline plain English in the `CLIError` raise (matches the convention used by the 18 other `CLIError` raises in `bob/cli.py`). Removed dead locale keys `cli.error.json_v1_retired` (EN + FR). Regression guards (`tests/test_v091_cli_i18n_safety.py`, +2 tests): AST scan blocks any future `i18n.t()` call inside `parse_args`; direct guard pins the actionable message content (must contain "v0.9.0" + one of "json-v1"/"schema", must NOT be bracketed-fallback). 6210 → 6212 tests. 0 regression. **v0.9.0 NOT yanked** — F-3 only affects users explicitly passing the retired `--json-v1` flag; the golden audit path is unaffected. **Two i18n gaps documented but deferred** to v0.10.0+: (1) `BaselineLoadError` messages hardcoded EN (post-init, could be localized); (2) cross-version baseline diff noise on D-1 renamed finding keys (`iptables_nft.*` → `firewall_iptables.*` shows the same physical issues as both resolved and new). Both are zero-user-signal cosmetic UX warts. |
| v0.9.0 | 6210 | **First v0.9.x release — BREAKING bundle closing the v0.7.0 → v0.8.x deferred architectural cleanup.** **D-1 BREAKING**: 7 section renames with hard migration error path (`cron_audit` → `cron`, `docker_audit` → `docker_hardening`, `services_state` → `services_health`, `ports_analysis` → `ports`, `rules` → `firewall_rules`, `iptables_nft` → `firewall_iptables`, `firewall_stack` → `firewall_drivers`). Section header titles unchanged; the BREAKING surface is the script-visible token name only. Finding key prefixes, locale namespaces, EXPLAIN_KEYS, CIS refs, profile overrides, bash completion + ~167 test prefixes all migrated. **F-3 BREAKING**: `--json-v1` retired. v2 schema is the only supported format; `SUPPORTED_SCHEMA_VERSIONS = {"2"}`; `_build_v1` + `_populate_v1_full_blocks` (~170 lines) deleted; `tests/test_json_schema.py` removed entirely. **TD-1 BREAKING**: `BOB_SANDBOX_LEGACY=1` trap door retired; plugins always sandboxed. 2 retirement guards verify the helpers don't resurface. **D-3 cleanup**: `EXPLAIN_KEY_ALIASES` retired with the source-side drift fix (`services_state.py` emission name vs EXPLAIN_KEYS entry name aligned); v0.8.2 `_warn_alias_deprecation` machinery removed. **D-2 internal**: `_SECTIONS: tuple[_Section(name, always_on), ...]` is now the single source of truth; legacy `_ALL_SECTIONS` / `_ALWAYS_ON_SECTIONS` are derived views (back-compat preserved). **F-2 NEW**: `--diff [PATH]` cross-machine compare. New `AuditBaseline.hostname` field captured via `socket.gethostname`; `load_baseline(path, strict=True)` raises `BaselineLoadError` on missing/broken/v1-schema instead of silent None. Bare `--diff` keeps v0.8.x local-baseline behaviour. Unlocks audit on host A → save → `scp` to B → `sudo bob --diff hostA.json` on B. **Bug fix**: bash completion `cur="="` case (`bob --check=<TAB><TAB>` without sudo returned zero candidates) — companion to the v0.8.2 sudo-dispatcher walk-back. Validator semantic fix as D-1 side effect: `--skip=firewall` no-effect warning restored when `firewall_iptables` etc. were added to `_ALL_SECTIONS` (always-on exact match now precedes filterable prefix match). 6246 → 6210 tests (net −36: −53 v1 baseline + v0.8.2 deprecation tests retired; +17 new F-2 tests). 0 regression. **v0.7.x remains EOL** (declared v0.8.1); **v0.6.x remains EOL** (declared v0.7.2). Users with scripts using `--check=<legacy>`, `--json-v1`, or `BOB_SANDBOX_LEGACY=1` must migrate. |
| v0.8.4 | 6246 | **Final v0.8.x release — cleanup batch before the v0.9.0 BREAKING bundle.** **Dead code retirement** (`bob/checks/_run.py`): `is_unit_enabled(name, timeout)` was added in v0.5.0 (Phase 1 #7) as the symmetric mirror of `is_unit_active` and documented in the release-monitoring list as "no immediate consumer — to be reviewed each v0.5.x release". 7 months and 4 minor versions later, zero consumers in `bob/` or `tests/` and `services.py::_detect_single_unit_state` continues to use its own `_run` call as designed. Removed. Historical CHANGELOG entries preserved as accurate records. **New tutorial** (`DOCUMENTS/TUTORIAL{,_FR}.md`, 269 lines × 2 locales): end-to-end first-time-user walkthrough covering install → first audit → fixes → profiles → ignore → cron + webhook → diff/history/watch → machine formats → common scenarios. Linked from `README{,_FR}.md` "See also" as the first entry. The deferred `tutorial` item from the v0.9.0 backlog moved into v0.8.4 because it is pure docs with zero code surface. **Roadmap closures**: the v0.5.0 release-monitoring list is closed (both entries decided — `is_unit_enabled` DELETED, `width=62` KEPT off-monitor after 7 months of stability). The compare-breakdown-diff feature roadmap is killed — opened v0.3.0 (2026-05-08), zero user signal across 5 majeures. Pattern: 5-major-dormancy without signal = kill rather than keep indefinitely. 6246 → 6246 tests (no delta — the deleted helper had no test coverage to delete). 0 regression. **Next**: v0.9.0 BREAKING bundle (D-1 + D-2 + D-4 + BOB_SANDBOX_LEGACY retrait + parallel checks + --diff baseline.json cross-machine). v0.8.x is closed; further v0.8.x patches will only ship for security regressions. |
| v0.8.3 | 6246 | **HOTFIX — v0.8.2 audit path crashed with UnboundLocalError on every non `--test-webhook` invocation.** Root cause: the v0.8.2 `--test-webhook` handler did `from bob.config import UserConfig` *inside* `main()`, shadowing the module-level binding for the entire function body and crashing the audit path with `UnboundLocalError: cannot access local variable 'UserConfig' where it is not associated with a value`. Same shadowing pattern existed for `os` and `traceback` inside the top-level except handler. Fix: removed the redundant local imports of `UserConfig` + `os`; promoted `traceback` to a module-scope import. **Regression guard** (`tests/test_v083_main_scope_guard.py`, +2 tests): static `ast.walk` over `main()` body that asserts no local `from`/`import` re-binds a name already imported at module scope. The smoke-plugin-on-CI integration guard caught the live crash but only after v0.8.2 was already published on PyPI — unit tests didn't catch it because they either exercise `--test-webhook` (passes through local import, binds the name) or mock `UserConfig.load` (resolves via mock decorator). 6244 → 6246 tests. 0 regression. **v0.8.2 is broken on PyPI — users must `pipx upgrade bodyguard-of-bits` immediately.** |
| v0.8.2 | ~6244 | Conservative-bundle patch — 6 user-facing + DX items, no BREAKING. **Bash completion v0.8.2**: sync `_SECTIONS` + `_EXPLAIN_KEYS` with runtime, add `--unignore=KEY` / `--ignore=KEY` / `--explain KEY` value completions, `--json-v1` + `--test-webhook` in long_opts. Plus 21 sync-guard + functional tests (`test_v082_bash_completion.py`). **i18n consolidation**: new `bob/_i18n_safe.py` exposes `make_fallback_t(labels)` + `t_or_hardcoded(key, fallback)`, replaces 4 hand-rolled `_fallback_t` + 1 `_t_or_hardcoded` across config/webhook/markdown_output/html_output/__main__ (single source of truth, consistent format-or-keep-template semantics). **`--test-webhook` smoke command**: POST a tagged `bob_smoke_test` minimal payload to configured webhook URL and exit; reuses every URL-validation guard from `send_webhook` + 4 new locale keys EN+FR. **`--check=list` descriptions**: 44 sections × 2 languages = 88 one-line technical descriptions under new `sections.descriptions.*` namespace. **D-3 deprecation warning** on `EXPLAIN_KEY_ALIASES` resolution: one-shot `logger.warning` pointing at canonical name + v0.9.0 retrait timeline; logger-only so machine-readable outputs aren't polluted. **Locale linter** (`scripts/lint_locales.py`): dev tool catching strict EN/FR key parity (1941 × 2, 0 drift), placeholder-set parity, trailing-whitespace contract (I-2 pass 7), length sanity. **D-1 / D-2 / D-4 + BOB_SANDBOX_LEGACY retrait + parallel checks + `--diff <baseline.json>` + tutorial** deferred to v0.9.0 as BREAKING-bundle architectural cleanup. 6198 → 6244 tests. 0 regression. |
| v0.8.1 | ~6198 | Minor maintenance + deep-hardening audit cycle. Closes **26 gap tiers** across 3 sub-agent audit passes (6/7/8) + an initial drift / framing / silent-feature-gap sweep. **Initial cycle (12 tiers)**: T6 profile severity coverage (desktop +24 / workstation +28 overrides) ; T10 i18n exceptions in webhook/config/__main__ (14 new locale keys EN+FR + fallback dict pattern from v0.7.2 M-4) ; **workstation alias retrait BREAKING** (the v0.1.0 alias that silently redirected `bob -p workstation` to desktop has been retired — workstation.conf is now a first-class business-context profile that keeps backup/auditd/mac_policy at WARN while relaxing personal-use ergonomics) ; T11 Finding.detail field parity across CSV + JSON v1/v2 ; T26 explain dispatch for `services.exposed.<id>` via existing `service_risk.*` locale (38 services auto-explainable) ; T27 webhook payload `detail` + `note` parity (generic + Slack inline) ; T31/T37 nature backfill on 90 warn/alert sites (`bob --fix --apply` filtered by `f.nature == "action"` was silently invisible to 88% of actionable findings) ; T32 profile typo validation with `logger.warning` on unknown override keys ; T39 orphan `service_risk.ollama_llm_server` cleanup ; T57 --unignore CLI path + `remove_ignore_key` helper + 2 locale keys + man page entry ; T60 `_t_or_hardcoded` helper wires `cli.error.*` prefixes through main() catch-all + parse_args error path ; T74 webhook URL credential redaction (`redact_url_credentials` strips `user:pass@` before display on stdout / .log / WebhookError). **Audit pass 6 (5 findings)**: I-1 ignore.yml comment preservation (walk lines instead of canonical rewrite) ; M-1 T32 regex accepts digit-containing keys (`fail2ban.ssh_jail_active`, `ipv6.ufw_disabled_no_listeners`) + `file_perms.*` permissive prefix ; M-2 services.exposure canonical enum set + bogus `services.exposure.<svc_id>` rejection ; M-3 `service_label_to_subkey` transform consolidated in `bob/registry.py` (single source of truth, closes 3-way drift) ; M-4 --unignore documented in man/bob.1 + mutual-exclusion guard with --ignore. **Audit pass 7 (3 findings)**: I-1 `remove_ignore_key` regex match loader grammar (multi-space, tab now removable) ; **I-2 FR colon typography drift on T10/T60 prefixes** — colon-space now embedded in locale values so no more `"Avertissement : échec du webhook: …"` double-colon ; M-1 man/bob.1 `--show-ignored` description rewrite. **Audit pass 8 (5 findings)**: I-1 `_KEY_LINE_RE` unified (drop `\s*$` anchor so loader sees inline-commented entries ; pass-7 sibling regex was dead code masked by defensive guard) ; I-2 `runner.py` 3 hardcoded `Warning:` prefix sites i18n'd via `cli.error.warning_prefix` + `cli.runner.*` (6 new locale keys EN+FR) ; M-1 `--webhook-secret` phantom removed from `_VALUE_TAKING_OPTS` ; M-2 `_ufw_inactive` variants narrowed to `(no_rule, loopback_no_rule)` ; M-3 `t()` trailing-whitespace contract test pin (defends I-2 pass 7). **Plus**: `tests/conftest.py` autouse `_ensure_i18n_initialised_for_tests` mirrors production invariant. ~190 dedicated v0.8.1 tests across 8 files. 5521 → 6198 tests. 0 regression. |
| v0.8.0 | ~6008 | Minor major — drift batch + framing actions + silent-feature-gap audit. Closes v0.7.x cycle (4 hardening patches v0.7.1→v0.7.4) and opens v0.8.x. **Drift batch (11 items)** re-syncs every doc/packaging surface that fell behind: CHANGELOG FR backfill v0.7.0→v0.7.4 (5 entries), man pages bumped, shields bumped, debian/changelog + rpm %changelog backfilled, TESTING.md backfilled, README.md+README_FR.md Install section synced with README_TECH 4-substep flow, new `tests/test_runner.py` smoke on `_sec()` orchestrator, new 5th CI guard `tests/test_doc_version_consistency.py` (7 doc surfaces vs pyproject), orphan `__version__ = "1.14.0"` removed from `bob/checks/__init__.py`, `BOB_DEBUG` documented in `SECURITY.md`. **Framing actions** A1 = summary box leads with "Hypotheses: profile=X | context=Y | posture=Z" line (display.py); A2 = new "What BOB is / is NOT" callout in README{,_FR} + SECURITY{,_FR}. **Silent feature-gap audit (8 tiers)** — **T1** +51 `--explain` entries for previously-uncovered WARN/ALERT findings, opens 15 new prefixes (`backup, ddns, docker, fail2ban, firewall_stack, iptables_nft, log_rotation, logs, mac_policy, network_context, ntp, ports, rootkit, services, smtp`); EXPLAIN_KEYS baseline 117/30 → **168/45**. **T1bis** `_BadDirective.cmd_template` field added; 8 SSH directives now ship cmd= (PermitEmptyPasswords/X11Forwarding/IgnoreRhosts/HostbasedAuthentication/PermitUserEnvironment/StrictModes/AllowTcpForwarding/PubkeyAuthentication). **T2** services.json 32 → **38** with Tailscale/Caddy/AdGuard Home/Vaultwarden/Ollama/Authelia. **T3** `warn_with_deduction` backfill: `services.state.installed_inactive_critical` +1pt, `services.state.active_disabled` +1pt, `firewall.policy_unknown` +2pts, `virt.snap_network` capped 2pts cumulative. **T4** 5 `service_risk.*` locale backfills (SMTP/NFS/Jenkins/OpenVPN/Squid). **T7** profile key rename `hardening.auto_updates_missing` → `updates.unattended_not_configured` (the actually-emitted key). **T9** Markdown + HTML format parity for `Finding.detail` + `Finding.note` (terminal+JSON+text only previously). **Deferred to v0.8.1**: T6 profile severity coverage audit, T10 i18n 27 hardcoded EN exception messages. D-1..D-4 contract remains open for v0.8.x continuation. +487 tests across the bundle. 5521 → ~6008 tests. 0 regression. |
| v0.7.4 | 5521 | Fourth v0.7.x hardening patch — second deep-audit pass after v0.7.3. Bundle-aggressive (6 important + 8 minor shipped, zero defer). **I-1** `--quiet` output leaks gated in 4 display sites (Docker exposed_ports / `display_geoip_notice` / `display_ports_overview` / `display_log_results`). **I-2** `--explain` UI labels i18n (18 new `explain.ui.*` keys). **I-3** `__main__` CLI flows i18n (`--check=list` / `--ignore` / `--reset-baseline` / `--diff` no-baseline). **I-4** webhook scheme symmetry: `config.py::set_webhook_url` case-insensitive (mirror v0.7.3 I-5). **I-5** `services.py::_PRIVATE_ADDR` retired → delegates to sysinfo helpers (restores v0.5.6 invariant). **I-6** CSV `risk` aligned to JSON v1 (BREAKING wire format). **M-2** CLI value-missing UX (`_VALUE_TAKING_OPTS` frozenset). **M-3** cron PYTHONPATH trailing-colon footgun. **M-4** sandbox WARN i18n + `key=` (9 new `plugin.sandbox.*` keys, `--ignore` works). **M-5** `report.py::write_header` `labels=` dict (v0.7.3 M-5 pattern). **M-7** json_output uses `engine.domain_scores` cache. **M-8** `set_posture_from_engine` rejects bool subclass-of-int. +19 tests (1 CSV/JSON v1 parity, 1 webhook scheme symmetry, 4 display-quiet, 9 CLI value-missing UX, 1 cron PYTHONPATH, 3 set_posture pins). 5502 → 5521 tests. 0 regression. |
| v0.7.3 | 5502 | Third v0.7.x hardening patch — full deep-audit pass (sub-agent + 14 fixes + 5 justified skips). **I-1** FR locale "finding" → "découverte". **I-2** `completion.py` SUDO_USER not validated (KeyError on malformed value) → guarded via regex + `try/except`. **I-3** CSV column `section` → `nature` (BREAKING wire format). **I-4** 3 bare `input()` → `safe_input()` in manage_logs. **I-5** webhook URL scheme case-insensitive (RFC 3986). **I-6** markdown/html level guard idiom convergence. **M-2** `--lang VALUE` space-separated form accepted. **M-3** `bob -e ""` empty key rejected. **M-4** argv hardening (`-w` / `--ignore` / `--output-dir`). **M-5** `report.py` field labels i18n (OK/Warning/Alert/Score/Risk/Context). **M-6** `_inline_format` double-escape URL chars fix. **M-10** `set_posture_from_engine` helper extract. **M-11** `send_html_email` CRLF stripping defensive. **M-12** html_output risk label translated (FR badges). +12 tests (1 CSV rename, 3 webhook scheme case-insensitivity, 6 CLI argv hardening, 2 HTML risk-level translation). 5490 → 5502 tests. 0 regression. |
| v0.7.2 | 5490 | Second v0.7.x hardening patch — closes the 6 minors deferred by v0.7.1 + formalises v0.6.x EOL. **M-4** i18n extraction on Markdown / HTML exports (24+22 new locale keys with optional `t=None` English fallback). **M-6** sysinfo accepts IPv6 public IP (`ipaddress.ip_address()` replaces IPv4-only regex). **M-7** `_atomic.py` tmp-file collision under concurrent writers (`tempfile.mkstemp`). **M-8** `SCHEMA_*_KEYS` wired as enforced invariants. **M-9** `--json-full --json-v1` help text. **M-10** `display.py` posture-detection paths deduped (`_compute_posture_annotation` helper). v0.6.x officially declared EOL in `SECURITY.md` + `SECURITY_FR.md`. +11 tests (4 SCHEMA pins, 3 Markdown i18n, 4 HTML i18n). 5479 → 5490 tests. 0 regression. |
| v0.7.1 | 5479 | First v0.7.x hardening patch — same-day follow-up to v0.7.0 final. 4 important + 3 minor shipped. **I-1** watch-mode contract drift: `bob --watch` created a fresh `ScoreEngine()` per iteration but never called `set_posture()` and never set `ignore_keys`. **I-2** `MarkdownReport.write_summary` signature drift (`posture_annotation` kwarg added to Protocol + impl). **I-3** JSON v1 `risk` field wire-format break — v0.7.0 silently shifted from `engine.level` to `engine.effective_level`; reverted to preserve v0.6.x layout contract. **I-5** webhook plaintext URL accepted — `http://` rejected by default; opt-out via `BOB_WEBHOOK_ALLOW_INSECURE=1`. **M-1** unused `from typing import Any`. **M-2** `_atomic.py` fsync(fd) + fsync(dir_fd). **M-5** `--ignore=KEY` validates against canonical EXPLAIN_KEYS pattern before write. +13 tests (5 ignore-validation, 1 fsync spy, 2 webhook http rejection, 3 MarkdownReport parity, 2 watch propagation). 5466 → 5479 tests. 0 regression. |
| v0.7.0 | 5466 | Major bump — opens v0.7.x stable branch. Rolls up b1+b2+b3+b4 beta cycle with three thematic phases. **Phase 1 (T1 Foundation)**: Python 3.14 added to CI matrix; new `ScoreEngine.set_posture()` + `effective_level` property + `posture_escalation` block; new EXPLAIN key `risk.escalated_posture`. **Phase 2 (T2 Schema v2)**: `build_json_data(..., schema_version="2")` is the new default; `--json-v1` preserves v0.6.x layout exactly; EXPLAIN_KEYS baseline = 117 keys / 30 prefixes / 100% conformance. **Phase 3 (T3 Plugin Sandbox Runner)**: new `bob/_sandbox.py` (~900 LoC) — process isolation via mp spawn, 5s wall timeout + RLIMIT_AS=256MiB + RLIMIT_CPU=10s, import allowlist, restricted `__builtins__`, open() wrapper denying writes + sensitive-path reads, extensive os attribute strip (84 attrs), JSON-safe dict round-trip through mp.Queue. Threat model recadré honest in SECURITY.md — in-process Python sandboxing is NOT a security boundary (PEP 416); AppArmor profile is the real boundary. 4 release-engineering guards added in flight: integration-first, smoke-after-commit, version-consistency, smoke-plugin-on-CI. +75 tests across the cycle (15 betas + sandbox hardening pins + version-consistency + smoke-plugin). 5391 → 5466 tests. 0 regression. v0.6.x EOL. |
| v0.6.2 | 4600 | **Critical packaging hotfix.** Every wheel since v0.6.0 was missing `bob/checks/ssh/` and `bob/cron/` subpackages — the two splits introduced by v0.6.0. Users who `pipx upgrade`d hit `ModuleNotFoundError` on every invocation. Root cause: `pyproject.toml [tool.setuptools.packages.find].include` was a literal list `["bob", "bob.checks", "bob.tui"]` inherited from a v0.4.x packaging audit. The v0.6.0 splits added `bob.checks.ssh` and `bob.cron` but the list was not updated. Why undetected: unit tests + pre-ship smoke ran from the source tree (sys.path resolution bypasses packaging config); CI used `pip install -e .` (editable mode bypasses `find_packages` discovery entirely). Fix: `include = ["bob*"]` glob auto-discovers every current and future `bob.*` subpackage. CI hardened: `integration.yml` jobs now use `pip install .` (non-editable, builds and installs a real wheel) + new explicit smoke step that imports every v0.6.x-added module (`bob.checks.ssh`, `bob.cron`, `bob._atomic`, `bob._tty.safe_input`) so a missing-from-wheel module surfaces at CI install-time. No code changes other than packaging config (1 line) + workflow guard (~15 lines). **4600 tests unchanged.** JSON contract, EXPLAIN_KEYS, wire output — all preserved. Users on v0.6.0 / v0.6.1: `pipx upgrade bodyguard-of-bits` to v0.6.2 to fix the broken install. |
| v0.6.1 | 4600 | First hardening release on the v0.6.x branch. Deep-audit sub-agent surfaced 14 findings (0 critical + 6 important + 8 minor); 6 important + 4 minor shipped. **Atomic-write contract consolidation**: extracted `bob/_atomic.py::atomic_write(path, content, *, mode=)` as single source of truth; migrated 5 hand-rolled implementations + fixed 4 non-atomic sites (`bob/cron/_install.py`, `bob/tui/cron.py` install paths, `bob/ignore.py`, `bob/history.py` first-write). **EOF contract completion**: new `bob/_tty.safe_input()` + `prompt_wizard()` now catches EOFError; 11 bare `input()` sites migrated. **I-3** `_validate_cron_field` bounds step values (`*/200` for minute 0-59 was accepted). **I-4** `shlex.quote()` applied to 8 `cmd=` sites with user-controlled paths. **I-5** `history.jsonl` mode `0o600` on first write. Minors: M-2/M-3/M-6/M-8 (4 minors deferred to judgment-call). +17 regression tests across `tests/test_atomic_v061.py` (12: TestAtomicWritePublicAPI, TestCronLegacyAliasStillWorks, TestHistoryFileMode, TestIgnoreAtomic, TestSafeInput) and `tests/test_cron.py::TestStepBoundedToFieldRange` (5). 4583 → 4600 tests. JSON contract preserved. Wire output unchanged (only `--watch=N` error string differs). Two contracts uniformly enforced (atomic-write + EOF handling). |
| v0.6.0 | 4583 | **Major bump** opening the v0.6.x branch. Two architectural splits (`bob/checks/ssh.py` 1296L → `bob/checks/ssh/` 4-module package; `bob/cron.py` 1204L → `bob/cron/` 4-module package) deliberately deferred across the entire v0.5.x cycle, both contract-preserving via `__init__.py` re-exports. Plus the `UFW_AUDIT_SHARE` legacy env var sunset honored (announced "REMOVED in v0.6.0" in v0.5.4). Three trivial test-infrastructure updates: `tests/test_template_vars_migration.py` and `tests/test_domain_scores_mapping_complete.py` switched from `glob` to `rglob` so AST scanners pick up the new check-package submodules; `tests/test_cron.py::TestApplyCronScheduleAtomic` patch target shifted from `bob.cron._atomic_write` (package re-export) to `bob.cron._io._atomic_write` (where `apply_cron_schedule` actually calls it). 4583 tests inchangés (0 added, 0 removed — splits + sunset are wire-equivalent). Largest module post-split is `ssh/_subchecks.py` at 529L, well below the project's soft 1000-LoC ceiling. All v0.5.x public APIs preserved via re-exports. JSON contract, EXPLAIN_KEYS, keybindings, no-curses fallback, exit codes — all preserved. Closes the deferred architectural roadmap from v0.5.x. |
| v0.5.8 | 4583 | Cleanup of the 5 cosmetic minors explicitly deferred by v0.5.7 (M-2, M-5, M-6, M-7, M-8). **M-2** `manage_logs.py` cursor-shift after delete now tracks `deleted_before_cursor` separately so the cursor only shifts by deletions at-or-before the active position (pre-fix `cursor -= deleted` shifted by the full count even when most deleted items sat after the cursor). **M-5** schedule wizard local tuple unpack `_, _SCHEDULE_WEEKDAYS, _SCHEDULE_MONTHDAYS, _SCHEDULE_CUSTOM = 1, 2, 3, 4` promoted to a module-level `_Schedule(IntEnum)` with explicit `DAILY`/`WEEKDAYS`/`MONTHDAYS`/`CUSTOM` names — IntEnum preserves `choice == _Schedule.X` semantics so wire-equivalent. **M-6** `_extract_summary_view` sentinel `summary_start: int \| None = None` replaces falsy `summary_start = 0` check — handles the unreachable-in-practice edge case where SEP62 sits at line 0. **M-7** new `_is_finding_continuation(line)` helper stops the 4-space-indent grouping at finding markers (`[ALERT]`/`[WARN]`/`[OK]`/`[INFO]`) and section delimiters (`┌`/`└`/`│`/`━`/`╔`/`╠`/`╚`/`║`) — defends against over-greedy grouping of subsequent indented content. **M-8** `from datetime import datetime` lifted to module-level in both `bob/cron.py` and `bob/tui/cron.py`, 3 local imports removed (also dropped 2 redundant local `import os` / `from pathlib import Path` in `_run_install_cron_plain`). +12 regression tests across `tests/test_cron.py` (TestScheduleIntEnum, TestDatetimeImportLifted) and `tests/test_manage_logs.py` (TestCursorShiftAfterDelete, TestSummaryStartSentinel, TestIsFindingContinuation). Single-commit release. JSON contract preserved. Wire output unchanged. **Closes the v0.5.x deep-audit campaign — branch fully audited (25 modules deep + ~25 spot-checked, 0 critical findings outstanding).** Next minor (v0.6.0) reserved for #13 (ssh.py split) and #14 (cron.py split). |
| v0.5.7 | 4571 | Targeted hardening pass on curses TUI (`bob/manage_logs.py` 999 LoC + `bob/tui/cron.py` 920 LoC = ~1920 LoC) — bucket explicitly deferred by v0.5.5 / v0.5.6 audits. 11 findings from focused sub-agent: 0 critical, 3 important (I-1 `_curses_readline` accepted curses `KEY_*` keypad codes via `chr(ch_i)` inserting Greek glyphs into TUI input buffers — UX-corrupting only thanks to downstream validation; I-2 three bare `input()` sites in `manage_logs.py` didn't catch `EOFError` so Ctrl-D dumped a Python traceback; I-3 `apply_cron_schedule` used raw `os.open(O_TRUNC) + write` instead of `_atomic_write` — power-loss between truncate and write would silently empty the cron file and drop the entry, asymmetric with `apply_cron_email` which already used atomic write), 3 minor (M-1 `deleted_one` status flashed wrong filename under selective unlink failures, M-3 dead-code elif body simplified, M-4 duplicate `from bob.cron import` consolidated). +11 regression tests across `tests/test_cron.py` (TestApplyCronScheduleAtomic, TestIsPrintableInputChar) and `tests/test_manage_logs.py` (TestEOFErrorOnPromptPath, TestEOFErrorOnMoveConfirm, TestEOFErrorOnDeleteAllConfirm, TestDeletedOneCorrectName). Single-commit release. JSON contract preserved. UX-visible deltas only: clean Ctrl-D exit (no traceback), arrow/function keys no longer print Greek glyphs in TUI prompts. 5 cosmetic minors (M-2, M-5, M-6, M-7, M-8) explicitly deferred to v0.5.8. After v0.5.7, v0.5.x deep-audit campaign closed (25 modules audited + ~25 spot-checked). |
| v0.5.6 | 4560 | Targeted hardening pass on `bob/checks/logs.py` (662 LoC UFW log parser) — module explicitly deferred by the v0.5.5 audit because of regex density. 10 findings from focused sub-agent: 0 critical, 2 important (I-1 `_PRIVATE_IP` regex inconsistent with sysinfo — missed CGNAT 100.64/10 + IPv6 link-local fe80::/10 + false positives on `fc`/`fd` strings; I-2 year-rollover silently dropped near-realtime syslog events 1s ahead of wall-clock), 8 minor (M-1 `[UFW BLOCK6]` IPv6 variant silently ignored, M-2 `_count_available_days` regex restricted to English month names, M-3 GeoIP path order City-before-Country, M-4 `geoip2_status` symlink consistency, M-5 `_GEO_CACHE` bounded 2048 with FIFO eviction, M-6 binary `tell()`/`seek()` arithmetic, M-7 redundant `subprocess.TimeoutExpired` dropped, M-8 `proto.upper()` at parse time). +15 regression tests in `tests/test_logs.py` (4 new test classes: `TestPrivateIPDispatch`, `TestParseTimestampYearRollover`, `TestBlockPrefixMatcher`, `TestProtoNormalisation`). Single-module pass, single commit. JSON contract preserved. Wire output: narrow deltas only on hosts emitting `[UFW BLOCK6]` (now counted) or with non-English locale syslog (now accurate `days_available`). |
| v0.5.5 | 4545 | Hardening pass — post-v0.5.4 audit by a deep general-purpose sub-agent. **4 real bugs** (C-1 `apply_cron_email` mode bug breaking scheduled audits, C-2/C-3 `password_policy` cmds unfixable by `--fix --apply` due to `&&`/Unicode arrow, C-4 `EXPLAIN_KEYS` drift for `services_state`), **4 security smells** (I-1 `recurrence.json`+`ignore.yml` written world-readable instead of 0o600, I-2 post-`finalize()` deductions bypassing score caps silently, I-3 `_safe_url` not re-escaping HTML attribute context allowing XSS in email reports, I-4 `_PRIVATE_IPV4_RE` brittle + Python 3.12+ stdlib widening break), **11 minor cleanups** (M-1 email regex dedup, M-2 `_NullReport` → canonical `bob.report.NullReport`, M-3 3 dead locale keys, M-4 `corr.fully_blind` asymmetric fail2ban check, M-7 `_has_actionable_findings` helper extract, M-8/M-9 clarifying comments, M-10 cron regex anchor stricter, M-11 `services_state.service_inactive` cmd `&&` split). +7 regression tests covering each fix class. M-6 cosmetic commit migrates `Optional[X]` / `List[X]` typing on 18 modules. **Net diff: 23 code files, +312 / -112 = +200 LoC.** Visible wire change on hosts without pwquality: password_policy finding moves from "À corriger" to "Améliorations possibles" (nature='action' → 'improvement'). Global score unchanged. |
| v0.5.4 | 4538 | Refactor v0.5.x Phase 5 of 5 (final) — **#6 `prompt_wizard()` helper** in `bob/_tty.py` + 10 sites migrated in `bob/cron.py` (install + edit wizards) + **#9 `UFW_AUDIT_SHARE` sunset** (`logger.info` → `logger.warning` with explicit "REMOVED in v0.6.0" message) + **#15b `_PREFIX_TO_DOMAIN` explicit mapping** (`fail2ban` → ssh, `virt` → hardening, `docker_audit` → hardening) + **cache APT option C** (new metier feature: permanent INFO `updates.apt_cache_age` line when no security/regular pending and cache below stale threshold, closes the observability gap surfaced by the v0.5.3 Ubuntu VM terrain test). **Zero test deltas** — Phase 5 is contract-preserving like Phases 2-4. 3 test entries removed from `_CATCH_ALL_BY_DESIGN` in `tests/test_domain_scores_mapping_complete.py` (reflecting the #15b prefix migration), but no tests added or deleted. The `#15a` AST scan test continues to pin every emitted key prefix. **#13 (ssh.py split, 1324 LoC) and #14 (cron.py split, 1223 LoC) deferred to v0.6.0** per conservative-refactor principle. Net diff: 12 code files changed, +118 / −69 = +49 LoC. Closes the v0.5.x audit (13/15 findings shipped + 1 metier feature + 2 deferred with justification). |
| v0.5.3 | 4538 | Refactor v0.5.x Phase 4 — **#5 `_LEVEL_DISPATCH` dispatch table** in `display_result` (4-branch OK/WARN/ALERT/INFO cascade → declarative loop driven by `_LevelTraits` dataclass) + **#12 `print_audit_summary` split** into 3 module-level helpers (`_summary_header_lines`, `_summary_findings_lines`, `_summary_breakdown_lines`) + `_add_finding_lines` promoted from inner closure to module level + **#8 `CheckResult.log_data` removal** (dict escape hatch → tuple return `check_logs(...) -> (CheckResult, LogReportData | None)` with frozen `LogReportData` dataclass). **Zero test deltas** — pure structural refactor, wire output bit-identical to v0.5.2. 3 tests renamed (`test_log_data_*` → `test_report_data_*`) and rewritten for dataclass field access instead of dict-key access; ~20 test sites use `result, _ = check_logs(...)` tuple unpack. Side-fix during #12: `report.write_summary(score=score, risk_level=level_str, network_context=ctx_str, ...)` referenced locals that became dead after header extraction; replaced with direct expressions on `engine.score` / `t(f"scoring.level.{engine.level.value}")` — caught by `TestScoreTrend` (8 failures → 0 after fix). Net diff: display.py +23 LoC, logs.py +19 LoC, runner.py 0, scoring.py −1, tests +3 = **+40 LoC total**. |
| v0.5.2 | 4538 | Refactor v0.5.x Phase 3 — **#4 SSH directive table** (8 directives uniformes migrées vers `_BAD_DIRECTIVES` table) + **#3 runner._sec extension** avec callbacks `skip_if=` / `post_display=` (4 blocs inline migrés). **Zero test deltas** — refactor structurel pur. Le `_BadDirective` dataclass + table + helper `_apply_bad_directive()` produit des findings et déductions bit-identiques aux if-blocks impératifs précédents. `_sec` extension is keyword-only (call sites existants inaffectés). `test_ssh.py` (122 tests) a passé avant et après la migration `_BAD_DIRECTIVES`. Net diff : ssh.py +56 LoC (table verbose), runner.py −29 LoC. **#13 (ssh.py split) déféré Phase 5** — ssh.py reste à 1324 LoC (cible <1000 non atteinte). |
| v0.5.1 | 4538 | Refactor v0.5.x Phase 2 — big LoC win. New `CheckResult.warn_with_deduction()` + `.alert_with_deduction()` helpers collapse 120 paired `warn`+`add_deduction` sites across 27 check files. **Zero test deltas** — each helper call internally invokes the existing `warn`/`alert` + `add_deduction` sequence, producing bit-identical `Finding` + `Deduction` outputs. The 4538 tests pin the wire output (finding messages, deduction reasons, template_vars, key prefixes, CIS refs) — all preserved. Each of the 6 migration waves (1-site files → 2-site → 3-site → 4-6 site → hardening → ssh.py) passed `pytest tests/` before moving on. Net diff: 37 files changed, +483/−1002 = −519 lines. |
| v0.5.0 | 4538 | Refactor v0.5.x Phase 1 (+39 tests) — **+4** in new `tests/test_domain_scores_mapping_complete.py` (AST scan of `bob/checks/*.py` for unmapped key prefixes, guards the `_PREFIX_TO_DOMAIN` catch-all from silent drift). **+35** in `tests/test_cron.py` covering 5 previously-untested pure helpers: `TestValidateCronField` (13 — wildcard, integer, range, step, list, out-of-bounds, reversed range, empty entry, garbage), `TestValidateCustomCron` (7 — full 5-field), `TestBuildScriptContent` (7 — shlex.quote, shebang, exports), `TestApplyCronSchedule` (3), `TestApplyCronEmail` (5 — incl. legacy `NOTIFY_EMAIL=` parity). **Latent bug fixed**: `apply_cron_schedule()` referenced `_os.open` (undefined at module scope) — v0.4.8 cron-deduplication extraction missed the rename; the new tests surfaced the NameError on first run. Tests in `test_fail2ban.py` and `test_ntp.py` updated to patch `is_unit_active` alongside `_run` (refactor #7). |
| v0.4.8 | 4499 | Hardening release — sub-agent code-review pass 4 (4 important + 5 minor + 3 suggestion findings) + pyproject.toml deep audit (6 fixes). **−1 test (4500 → 4499):** removed `test_default_method_is_none` in `test_secure_boot.py` after dropping the dead `method: str` field from `SecureBootSnapshot`. Other dead-field removals (`ssh.config_source_files`, `firewall.ipv4_rules_count`/`ipv6_rules_count`, `samba.min_protocol`, `clamav.db_path`/`last_scan_log_path`) had their associated tests updated to drop the now-invalid kwargs. No new behaviour, contract-preserving cleanup. |
| v0.4.7 | 4500 | Maintenance release — cross-doc audit (24 corrections / 8 files) + UI gauges harmonization + bash completion overhaul (critical `--xxx=<TAB>` value completion fix via positional-arg convention) + GitHub Release CI automation. No new tests; 3 tests in `test_breakdown.py::TestBar` adapted to strip ANSI codes before comparing visible content (bars are now coloured strings, no longer plain `█░░░░░░░░░`). |
| v0.4.6 | 4500 | Terrain test pass v0.4.5 fixes (+11): `TestParseInstalledKernels` (+5 — `ii`/`rc`/`pn`/`un`/`iU` status filtering, `hi` hold kept, mixed legacy+prefixed format) · `TestActiveDomainsIncludesOK` (+6 in test_domain_scores — OK promotes, INFO doesn't, full Debian 13 remediation scenario asserted at global=9 instead of 8). Multi-distro integration CI added (purely additive, not counted as unit tests). |
| v0.4.5 | 4489 | Test infrastructure hardening (0 new tests, pure refactor of `tests/test_locale_coverage.py`): regex scanning → AST parsing (`ast.walk` + `ast.Call` + `ast.Name`). Eliminates docstring false positives, multi-line call site fragility, and `obj._t(...)` attribute call edge cases. `_KEY_EXCLUSIONS` allowlist deleted. Same 9 tests, same external contract. |
| v0.4.4 | 4489 | Cross-distro terrain hardening (+21): coverage for `updates.py` critical bug (`-s dist-upgrade` semantics, stale cache detection, cross-check vs `apt list --upgradable`); AppArmor 0-profile key; all-virtual SMART skip; DDNS ports inline; new `test_locale_coverage.py` in initial regex form (catches `[xxx.yyy]` sentinel regressions class). |
| v0.4.3 | 4468 | Doc catch-up + post-audit hardening pass (+16): firewall EXPLAIN_KEYS regression, `--json-full` HardeningSnapshot dead-attr coverage, `strptime("%b…")` locale independence (ssl_certs + logs), `_is_covered_by_ufw` IP false-positive, cron range validator out-of-bounds, email markdown not HTML-escaped. |
| v0.4.2 | 4452 | Phase 3 distro-ready (packaging discipline) + pre-release hardening pass — 2 critical + 5 important + 4 minor fixes from agent audit. +3 tests in new `test_template_vars_migration.py` |
| v0.4.1 | 4449 | Phase 2 distro-ready (+19): `bob/tui/cron` extraction (0 new tests — covered by existing) · `--offline` integration (+3 in `test_webhook.py`) · `test_formatter.py` (14 new — locale-independent reconstruction + 4 edge cases post-review) · `test_json_schema.py` (+2 — `template_vars` field exposure) |
| v0.4.0 | 4430 | Phase 1 distro-ready (+82): `TestDetectSystemLang` (12) · `TestExplainKeyAliases` + `TestExplainKeyFreezePolicy` (6) · `test_json_schema.py` (17 — incl. strict-set + constants-drift defense in depth) · `test_services_schema.py` (43 — incl. `$defs`, strict 1–65535 port regex, business constraints, plugin-file wrapper, `minItems: 1` on services-list) · 4 CLI locale integration |
| v0.3.6 | 4348 | No new tests — code-review pass (sudo-aware `Path.home()`, IPv6 ULA, SSH `local`, dead imports/locales) |
| v0.3.5 | 4348 | No new tests — pure refactoring (`runner.py` `_sec` closure, `ssh.py` `_check_weak_algo`) |
| v0.3.4 | 4348 | No new tests — hotfix only (`user_config` NameError) |
| v0.3.3 | 4348 | +7 new −6 removed (TestWasCapped → TestCappedIndices): `TestCappedIndices` in test_domain_scores |
| v0.3.2 | 4347 | +21 new (user whitelist) −2 removed (DC-1 dead code): `TestFromSystemUserWhitelist` · `TestGetSuidWhitelist` · `TestGlobMatching` in test_suid_audit |
| v0.3.1 | 4328 | +6 new tests: `TestWasCapped` in test_domain_scores · was_capped flag · engine cached properties |
| v0.3.0 | 4322 | +48 new tests: `--breakdown` display · golden scoring scenarios · 16 in test_breakdown · 32 in test_golden_scenarios · 1 renamed in test_min_level |
| v0.2.4 | 4274 | +12 new tests: Debian -unsigned kernel UX · deduction_total None sentinel · 2 in test_kernel_modules · 10 in test_compare |
| v0.2.3 | 4262 | +1 new · 4 renamed: NOT_LISTENING INFO · IoT no deduction · SSH stopped label split |
| v0.2.2 | 4255 | +17 new tests · 2 updated: `TestStatFallback` · `TestScoringInvariants` · orphan-rule bare-port fix · ClamAV 1pt · ScoreCap.key · INFO domains excluded |
| v0.2.0 | 4238 | +32 new tests · 3 corrected: scoring refactoring · cron MTA detection · kernel `-unsigned` false positive · IoT log dominance WARN |
| v0.1.1 | 4206 | +4 regression tests: fwupd 1.9+ tree-format output (`├─`/`└─` parser) — bug found on Ubuntu 26.04 LTS |
| post-v0.1.0 | 4202 | +2 regression tests: exposure surface INFO-level findings (`ssh.not_installed`, `fail2ban.not_installed`) — bugs found on Ubuntu 26.04 LTS |
| v0.1.0  | 4200  | Initial release — 65 test files; 39 new tests in `test_cis_refs.py` (CIS benchmark mapping); full coverage across all 46 checks |

---

### v0.6.1 — 4600/4600 (2026-05-26)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4600 passed in ~7s
```

**Net: +17 (4583 → 4600).** First hardening release on v0.6.x. Audit sub-agent produced 14 findings; 6 important + 4 minor shipped. All +17 tests pin regression coverage:

| Test class | Count | Pins finding |
|---|---|---|
| `TestAtomicWritePublicAPI` (test_atomic_v061.py) | 4 | atomic_write contract — mode preserved, content overwritten cleanly, atomicity on simulated failure |
| `TestCronLegacyAliasStillWorks` | 1 | `bob.cron._io._atomic_write is bob._atomic.atomic_write` (test patch backwards-compat) |
| `TestHistoryFileMode` | 2 | I-5 first-write 0o600 + mode preserved on append |
| `TestIgnoreAtomic` | 2 | I-6 atomic write + simulated os.replace failure leaves content intact |
| `TestSafeInput` | 3 | I-2 `safe_input()` returns "" on EOF + `prompt_wizard()` returns None on EOF |
| `TestStepBoundedToFieldRange` (test_cron.py) | 5 | I-3 step bounds for minute / hour / boundary / zero / full expression |

#### Test count timeline updated

```
v0.5.0  →  4538 tests
v0.5.5  →  4545 tests  (+7  — hardening regressions)
v0.5.6  →  4560 tests  (+15 — logs.py)
v0.5.7  →  4571 tests  (+11 — curses TUI)
v0.5.8  →  4583 tests  (+12 — deferred minors cleanup)
v0.6.0  →  4583 tests  (0   — splits + sunset are contract-preserving)
v0.6.1  →  4600 tests  (+17 — atomic-write + EOF contract + cron step bounds)
```

#### Field test

Standard cross-distro coverage approach. Wire output (plain-text + JSON) is bit-identical to v0.6.0 — only the `--watch=N` error string is different ("integer ≥ 10" instead of "positive integer"). All other changes are internal:
- Atomic-write migration is bit-identical to the pre-existing 5 implementations
- EOF handling is bit-identical for non-EOF inputs (only crash → clean exit)
- I-3 only rejects new inputs (`*/200`-style) that were previously accepted but produced broken cron
- I-4 affects only `--fix --apply` semantics on paths with spaces
- I-5 only changes first-time mode (existing `history.jsonl` files untouched)

Tested by sudo run on so6desktop pre-ship to verify the v0.5.x baseline score (9/10) is preserved.

All 4600 tests pass in ~7s on Python 3.12 / Linux Mint 22.3.

---

### v0.6.0 — 4583/4583 (2026-05-25)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4583 passed in ~7s
```

**Net: 0.** Major architectural bump opening the v0.6.x branch. Two package splits (#13 ssh.py → bob/checks/ssh/, #14 cron.py → bob/cron/) and one sunset (`UFW_AUDIT_SHARE`). All structural — no behaviour change, no new test classes, no removed tests.

Three test-infrastructure updates were required to accommodate the package layout (not coverage changes):

| Test file | Update | Reason |
|---|---|---|
| `tests/test_template_vars_migration.py` | `_check_modules()` → `_module_paths()` walks `iterdir()` + handles both files and package dirs; `_module_has_template_vars(path)` does `rglob("*.py")` for packages | The AST scanner needs to recurse into `bob/checks/ssh/` to find the 4 submodules' `template_vars=` call sites |
| `tests/test_domain_scores_mapping_complete.py` | `_CHECKS_DIR.glob("*.py")` → `_CHECKS_DIR.rglob("*.py")` + `__pycache__` filter | Same recursion need — the AST scanner must see every check submodule's emitted key prefixes |
| `tests/test_cron.py::TestApplyCronScheduleAtomic` | Patch target shifted from `bob.cron._atomic_write` to `bob.cron._io._atomic_write` | `apply_cron_schedule` lives in `_io.py` post-split and calls the local `_atomic_write` directly; the spy must be set where the call site reads |

These updates are mechanical — the assertions and coverage they enforce are unchanged.

#### Test count timeline updated

```
v0.5.0  →  4538 tests  (+39 vs v0.4.8: domain mapping AST scan + cron coverage)
v0.5.1  →  4538 tests  (no change — Phase 2 contract-preserving)
v0.5.2  →  4538 tests  (no change — Phase 3 contract-preserving)
v0.5.3  →  4538 tests  (no change — Phase 4 contract-preserving)
v0.5.4  →  4538 tests  (no change — Phase 5 contract-preserving)
v0.5.5  →  4545 tests  (+7 — post-cycle hardening regressions)
v0.5.6  →  4560 tests  (+15 — logs.py targeted hardening regressions)
v0.5.7  →  4571 tests  (+11 — curses-TUI targeted hardening regressions)
v0.5.8  →  4583 tests  (+12 — v0.5.7-deferred minors cleanup regressions)
v0.6.0  →  4583 tests  (0 — splits + sunset are contract-preserving)
```

**Branch summary v0.5.x: +45 net tests across 4 hardening releases (v0.5.5 → v0.5.8).** v0.6.0 opens v0.6.x without adding tests because it's a structural reorganisation.

#### Field test

Standard cross-distro coverage approach. Wire output is bit-identical to v0.5.8 (no behaviour change). Visible deltas to expect on user systems:
- **None on standard installs.** All v0.5.x imports continue to work.
- **Only on systems still setting `UFW_AUDIT_SHARE`**: the env var is now silently ignored. Update installers to use `BOB_SHARE`.

All 4583 tests pass in ~7s on Python 3.12 / Linux Mint 22.3.

---

### v0.5.8 — 4583/4583 (2026-05-25)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4583 passed in ~6s
```

**Net: +12 (4571 → 4583).** Cleanup of the 5 cosmetic minors deferred by v0.5.7. All +12 tests pin regression coverage:

| Test class | Count | Pins finding |
|---|---|---|
| `TestCursorShiftAfterDelete` | 2 | M-2 — mixed before/after deletion shifts cursor only by before-count; all-after deletions leave cursor unchanged |
| `TestScheduleIntEnum` | 2 | M-5 — enum values match menu indices (1-4); IntEnum-vs-int comparison parity preserved |
| `TestSummaryStartSentinel` | 1 | M-6 — synthetic SEP62-at-index-0 edge case correctly detected |
| `TestIsFindingContinuation` | 4 | M-7 — accepts indented body, rejects non-indented, rejects indented finding markers, rejects indented section delimiters |
| `TestDatetimeImportLifted` | 3 | M-8 — `bob.cron.datetime` and `bob.tui.cron.datetime` exposed at module level; `build_script_content` smoke still stamps date |

#### Test count timeline updated

```
v0.5.0  →  4538 tests  (+39 vs v0.4.8: domain mapping AST scan + cron coverage)
v0.5.1  →  4538 tests  (no change — Phase 2 contract-preserving)
v0.5.2  →  4538 tests  (no change — Phase 3 contract-preserving)
v0.5.3  →  4538 tests  (no change — Phase 4 contract-preserving)
v0.5.4  →  4538 tests  (no change — Phase 5 contract-preserving)
v0.5.5  →  4545 tests  (+7 — post-cycle hardening regressions)
v0.5.6  →  4560 tests  (+15 — logs.py targeted hardening regressions)
v0.5.7  →  4571 tests  (+11 — curses-TUI targeted hardening regressions)
v0.5.8  →  4583 tests  (+12 — v0.5.7-deferred minors cleanup regressions)
```

**Net growth over the v0.5.x hardening releases (v0.5.5 → v0.5.8): +45 tests** across 4 focused passes, while the structural refactor releases (v0.5.0 → v0.5.4) were contract-preserving (+39 in v0.5.0 only, all from new pure-helper test files).

#### Field test

Standard cross-distro coverage approach. Wire output (plain-text + JSON) is unchanged — the M-5 IntEnum migration produces bit-identical wizard behaviour; the M-7 helper is strictly stricter than the previous predicate but the over-greedy case it defends against doesn't surface in any current BOB output; M-6 sentinel handles an unreachable-in-practice edge case; M-2 cursor correction only changes display position after multi-selection deletes mixing items before+after the cursor; M-8 is a pure structural lift.

All 4583 tests pass in ~6s on Python 3.12 / Linux Mint 22.3.

---

### v0.5.7 — 4571/4571 (2026-05-24)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4571 passed in ~6s
```

**Net: +11 (4560 → 4571).** Targeted hardening pass on the curses TUI (`bob/manage_logs.py` + `bob/tui/cron.py`). All +11 tests pin regression coverage for fixes in this release:

| Test class | Count | Pins finding |
|---|---|---|
| `TestApplyCronScheduleAtomic` | 2 | I-3 — spy on `_atomic_write` to verify it's called; simulate failure to verify the original cron file content survives intact (atomicity contract) |
| `TestIsPrintableInputChar` | 4 | I-1 — printable ASCII accepted, printable Latin-1 accepted, control chars rejected (NUL/TAB/CR/LF/ESC), curses `KEY_*` keypad codes (≥ 256) rejected across the full range |
| `TestEOFErrorOnPromptPath` | 2 | I-2 — Ctrl-D at path prompt returns default (with and without `allow_cancel`), no `EOFError` propagation |
| `TestEOFErrorOnMoveConfirm` | 1 | I-2 — Ctrl-D at `[y/N]` move-logs confirmation cancels the move silently; log file NOT moved |
| `TestEOFErrorOnDeleteAllConfirm` | 1 | I-2 — Ctrl-D at `[y/N]` delete-all confirmation cancels the deletion silently; log file NOT deleted |
| `TestDeletedOneCorrectName` | 1 | M-1 — under selective unlink failures, displayed name is the FIRST successfully-deleted file, not `pending_delete[0]` (which could refer to a failed index) |

#### Why no tests for M-3 and M-4

- **M-3** (dead-code elif body simplified) — `chosen = sel` already produces identical behaviour in all branches the guard allows. No semantic change, covered by existing menu navigation tests.
- **M-4** (duplicate `from bob.cron import` consolidation) — pure import-source de-duplication. The imported names are still available; `python3 -c "from bob.tui.cron import apply_cron_schedule"` continues to work.

#### Test count timeline updated

```
v0.5.0  →  4538 tests  (+39 vs v0.4.8: domain mapping AST scan + cron coverage)
v0.5.1  →  4538 tests  (no change — Phase 2 contract-preserving)
v0.5.2  →  4538 tests  (no change — Phase 3 contract-preserving)
v0.5.3  →  4538 tests  (no change — Phase 4 contract-preserving)
v0.5.4  →  4538 tests  (no change — Phase 5 contract-preserving)
v0.5.5  →  4545 tests  (+7 — post-cycle hardening regressions)
v0.5.6  →  4560 tests  (+15 — logs.py targeted hardening regressions)
v0.5.7  →  4571 tests  (+11 — curses-TUI targeted hardening regressions)
```

#### Field test

Standard cross-distro coverage approach. Wire output (plain-text + JSON) is unchanged — only the TUI display changes (no Greek glyph leak on function-key press; clean exit on Ctrl-D). The atomic-write change in `apply_cron_schedule` produces bit-identical cron file content under normal operation; the difference is observable only under crash-during-write scenarios (testable in `tests/`, not on field VMs).

All 4571 tests pass in ~6s on Python 3.12 / Linux Mint 22.3.

---

### v0.5.6 — 4560/4560 (2026-05-24)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4560 passed in ~6s
```

**Net: +15 (4545 → 4560).** Single-module hardening pass on `bob/checks/logs.py`. All +15 tests are regression coverage for fixes in this release:

| Test class | Count | Pins finding |
|---|---|---|
| `TestPrivateIPDispatch` | 8 | I-1 — CGNAT (`100.64.5.1`), IPv6 link-local (`fe80::1`), ULA (`fc00::1`), loopback (`127.0.0.1`, `::1`), private (`10.0.0.1`, `192.168.1.1`), public (`8.8.8.8`), invalid input (`"fcsa"`, empty string) all classified correctly via `_is_private_ip` dispatch helper |
| `TestParseTimestampYearRollover` | 3 | I-2 — current-year past entry (no rollback), 1s-future entry (no rollback under 5-min tolerance), genuine December entry parsed in January (rollback applied) |
| `TestBlockPrefixMatcher` | 3 | M-1 — `[UFW BLOCK]` matched, `[UFW BLOCK6]` matched (was silently dropped), `[UFW ALLOW]` rejected |
| `TestProtoNormalisation` | 1 | M-8 — `proto="tcp"` normalised to `"TCP"` at parse time |

#### Why all I-1/I-2/M-1/M-8 are regression-pinned

These four were the only fixes with code-path-visible behaviour changes. The others are either:
- **Pure delegation** (M-3 path reorder, M-4 symlink-consistency, M-7 except cleanup) — covered by existing tests that exercise the changed code paths
- **Performance / safety boundary** (M-5 cache bound, M-6 binary read) — no behaviour change for the existing test inputs; would only show under contrived 10000+-IP fixtures (out of scope)
- **Locale-coverage adjustment** (M-2 regex restriction) — covered by `test_count_available_days` indirectly

The 4 pinned regressions cover the I-1/I-2/M-1/M-8 surface where future contributors could re-introduce the bugs.

#### Test count timeline updated

```
v0.5.0  →  4538 tests  (+39 vs v0.4.8: domain mapping AST scan + cron coverage)
v0.5.1  →  4538 tests  (no change — Phase 2 contract-preserving)
v0.5.2  →  4538 tests  (no change — Phase 3 contract-preserving)
v0.5.3  →  4538 tests  (no change — Phase 4 contract-preserving)
v0.5.4  →  4538 tests  (no change — Phase 5 contract-preserving)
v0.5.5  →  4545 tests  (+7 — post-cycle hardening regressions)
v0.5.6  →  4560 tests  (+15 — logs.py targeted hardening regressions)
```

#### Field test

Standard cross-distro coverage approach. Visible delta vs v0.5.5 expected on:
- Hosts emitting `[UFW BLOCK6]` (e.g. Debian backports with custom `before6.rules`) — these lines now count in the `total`/`top_ips` aggregation (previously dropped)
- Hosts with mixed-locale syslog content — `days_available` count may decrease (previously inflated by non-English month tokens)

Most VMs (default UFW configs, English locale) see **no visible change**.

All 4560 tests pass in ~6s on Python 3.12 / Linux Mint 22.3.

---

### v0.5.5 — 4545/4545 (2026-05-24)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4545 passed in ~7s
```

**Net: +7 (4538 → 4545).** First test delta on the v0.5.x line — the hardening pass surfaced 4 real bugs and 4 security smells, each pinned by a regression test to prevent re-introduction. Test changes summarised:

| Category | Added | Removed | Renamed | Net |
|---|---|---|---|---|
| Bug regression tests (C-1, C-2, C-3, C-4) | 4 | 0 | 2 (`test_nature_is_action` → `test_nature_is_improvement`) | +4 |
| Security regression (I-2, I-3) | 10 (9 in new `tests/test_report_markdown_safety.py` + 1 in `test_scoring.py`) | 0 | 0 | +10 |
| Behaviour change (M-4, M-10) | 3 | 1 (`test_no_fire_missing_auditd` removed — semantic change) | 0 | +2 |
| Dead-code cleanup (M-2 `_NullReport` removal, M-3 locale dead keys) | 1 (`test_enabled_flag_is_false`) | 9 (`TestNullReportIsolation` 5 + `test_any_method_returns_none` + `test_attribute_access_returns_callable` + `test_hint_key_en` + 1 more) | 0 | −8 |
| **Total** | **18** | **10** | **2** | **+7** |

#### New regression tests

**C-1: `tests/test_cron.py::test_preserves_script_executable_mode`** — pins that `apply_cron_email()` keeps the script at `0o755` (was breaking down to `0o600` and silently killing scheduled audits).

**C-2 + C-3: `tests/test_password_policy.py::test_nature_is_improvement`** (× 2 — `TestNoQualityModule` and `TestWeakMinlen`) — renamed from `test_nature_is_action` and inverted assertion. Locks the demotion that prevents `--fix --apply` from trying to exec un-execable cmds.

**C-4: `tests/test_explain.py::test_services_state_alias_routes_to_canonical`** — pins that `normalize_key("services_state.service_inactive")` resolves to `services_state.enabled_inactive` via `EXPLAIN_KEY_ALIASES`.

**I-2: `tests/test_scoring.py::test_post_finalize_deduction_is_discarded`** — uses `caplog` to verify both the discard and the WARNING log message. Covers `_apply_deduction` guard.

**I-3: `tests/test_report_markdown_safety.py`** — new file with 9 tests covering `_safe_url`:
- Plain URLs pass through (http/https)
- Unknown schemes blocked (javascript:, data:, file:, empty)
- Double-quote escape (`"` → `&quot;` in attribute context)
- Single-quote escape (`'` → `&#x27;`)
- Angle-bracket escape (`<` → `&lt;`)
- Plain text html-escape
- Link renders as anchor
- Full pipeline XSS attack-string test (asserts href closes correctly, no stray `"` injected)

**M-4: `tests/test_correlation.py::test_fires_with_only_fail2ban_inactive`** + `test_does_not_fire_when_firewall_logging_present` — pins the broadened semantic of `corr.fully_blind`.

**M-10: `tests/test_cron.py::test_comment_line_with_root_token_not_modified`** — pins that the tightened regex skips `# 0 3 * * * root /usr/bin/legacy-bob` comment lines.

#### Removed tests

`tests/test_watch.py::TestNullReportIsolation` (5 tests) + `TestNullReport::test_any_method_returns_none` + `test_attribute_access_returns_callable` — these tested the `__getattr__` magic of the old `bob.watch._NullReport`. M-2 replaces it with the explicit `bob.report.NullReport` (Report Protocol from v0.5.0 #10) which has typed `write_section` / `write_finding` / `_writeln` / `close` methods. Catch-all attribute access tests no longer applicable.

`tests/test_ignore.py::test_hint_key_en` — tested that `t("ignored.hint", ...)` resolves. M-3 deleted that locale key (orphan — never used by production code).

`tests/test_correlation.py::test_no_fire_missing_auditd` — pinned the pre-M-4 semantic (rule did NOT fire when fail2ban present but auditd missing). M-4 changed that semantic (now fires) so the assertion was inverted via two new tests above.

#### Test count timeline across v0.5.x

```
v0.5.0  →  4538 tests  (+39 vs v0.4.8: domain mapping AST scan + cron coverage)
v0.5.1  →  4538 tests  (no change — Phase 2 contract-preserving)
v0.5.2  →  4538 tests  (no change — Phase 3 contract-preserving)
v0.5.3  →  4538 tests  (no change — Phase 4 contract-preserving)
v0.5.4  →  4538 tests  (no change — Phase 5 contract-preserving)
v0.5.5  →  4545 tests  (+7 — first delta since v0.5.0; hardening regressions)
```

The 4538 plateau across Phases 2-5 confirms the contract-preservation guarantee held throughout the refactor. v0.5.5 grows the suite because it fixes real bugs — every fix gets a pin.

#### Field test

Same cross-distro coverage approach as v0.5.4 — pipx upgrade + `sudo bob -v -d` on each VM (so6desktop, debian13vm, kali, so6minttest, so6ubuntutest). Visible expected changes vs v0.5.4:

- **password_policy display shift**: on hosts without `pam_pwquality` installed (so6desktop, so6ubuntutest, others), the finding moves from "À corriger" (action block) to "Améliorations possibles" (improvement block) in the summary box. Global score unchanged. Verdict text changes from "Des corrections sont nécessaires" to "Configuration globalement saine".
- **`services_state.service_inactive` cmd shape change**: on hosts with inactive monitored services, the cmd no longer chains `&& sudo journalctl …` (which made it unfixable). The journalctl suggestion moves to `note=` for guidance.
- **No visible change** on hosts that don't trigger the above conditions (debian13vm, kali, so6minttest in their current state).

Cache APT INFO C continues to work as before (suppressed when security/regular updates pending).

All 4545 tests pass in ~7s on Python 3.12 / Linux Mint 22.3.

---

### v0.5.4 — 4538/4538 (2026-05-22)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4538 passed in ~6s
```

**Net: 0 (no new tests, no removals).** v0.5.4 closes the v0.5.x audit with Phase 5 (findings #6 + #9 + #15b + cache APT option C). All four changes are either contract-preserving refactors (#6, #9) or display-only refinements (cache APT C INFO line, #15b score re-bucketing). The existing test suite pins:

- All finding keys (via `test_locale_coverage.py` AST scan)
- All domain-score key prefixes (via `test_domain_scores_mapping_complete.py` AST scan, added in v0.5.0 — #15a)
- All scoring contracts (via `test_scoring.py`, `test_domain_scores.py`, `test_golden_scenarios.py`)

#### `_CATCH_ALL_BY_DESIGN` whitelist update (#15b consequence)

`tests/test_domain_scores_mapping_complete.py:_CATCH_ALL_BY_DESIGN` loses 3 entries that #15b migrated to explicit mappings:

| Removed entry | Where it went (in `_PREFIX_TO_DOMAIN`) |
|---|---|
| `fail2ban` | `ssh` |
| `virt` | `hardening` |
| `docker_audit` | `hardening` |

Remaining entries (`smtp`, `desktop_apps`, `prerequisites`) get refreshed justifications — they no longer point to "review in v0.5.4" since that review is now done. The block comment above `_CATCH_ALL_BY_DESIGN` updated to reflect closure (no more candidates flagged for tightening).

The test `test_every_emitted_prefix_is_mapped_or_whitelisted` continues to enforce that every emitted finding-key prefix is either in `_PREFIX_TO_DOMAIN` or `_CATCH_ALL_BY_DESIGN`. If a future contributor adds a check emitting a new prefix (e.g. `clamav_signatures.something`) without mapping it, the test fails at PR time.

#### Cache APT option C — locale coverage

The 2 new locale keys (`updates.apt_cache_age` + `updates.apt_cache_age_detail`) are picked up by `test_locale_coverage.py` (AST scan introduced in v0.4.5). The locale-coverage test enforces that every `t("foo.bar")` literal in the codebase has a corresponding entry in both `en.json` and `fr.json`. The 2 new entries pass the check.

#### #6 `prompt_wizard` — no new tests, mock compatibility preserved

`prompt_wizard()` in `bob/_tty.py` calls `input()` internally, so existing `tests/test_cron.py` mocks of `builtins.input` continue to work without modification. The 10 migrated sites in `bob/cron.py` each delegate to `prompt_wizard` instead of calling `input()` directly, but the underlying call stack still hits `input()` — so test setup like `patch("builtins.input", side_effect=["yes", "1", ""])` operates the same way.

The helper itself (`prompt_wizard`) is not directly unit-tested. Its behaviour is exercised end-to-end via the cron wizard tests that already mock `input()`.

#### Field testing

Cross-distro coverage approach unchanged from Phases 1-4 — pipx upgrade + `sudo bob -v -d` on each VM. Two observable changes are expected versus v0.5.3:

1. **Cache APT INFO line** in section MISES À JOUR SYSTÈME when the host has APT, no security/regular updates pending, and cache age below the 7-day stale threshold.
2. **Per-domain score reshuffle** on hosts emitting `fail2ban.*` / `virt.*` / `docker_audit.*` findings — the global score is unchanged.

On `so6desktop` dev host (Mint 22.3 + Docker installed + libvirt KVM), the reshuffle is observable: `Pare-feu & Services` jumped from 3/10 to 10/10 (`virt.bypass_risk` moved out of catch-all), `Durcissement` dropped from 6/10 to 5/10 (`virt.bypass_risk` now counted there). Global score stays at 8/10.

All 4538 tests pass in ~6s on Python 3.12 / Linux Mint 22.3.

---

### v0.5.3 — 4538/4538 (2026-05-22)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4538 passed in ~6s
```

**Net: 0 (no new tests, no removals).** v0.5.3 is the Phase 4 refactor (audit findings #5 + #12 + #8). All three are structural — the `_LEVEL_DISPATCH` table produces the same `print_ok` / `print_warn` / `print_alert` / `print_info` calls in the same order as the imperative cascade, the 3 `_summary_*_lines` helpers return the same `(content, val)` tuples as the previous inline sections, and the tuple return `(CheckResult, LogReportData)` doesn't change orchestrator semantics (`runner.py` unpacks the tuple and passes the report explicitly to `display_log_results`).

#### Renamed tests (#8)

3 tests in `test_logs.py` were directly dependent on the `log_data` field:

| Before (v0.5.2) | After (v0.5.3) | Change |
|---|---|---|
| `test_log_data_attached` | `test_report_data_attached` | `result.log_data is not None` → `report_data is not None`; `result.log_data["total"] == 1` → `report_data.total == 1` |
| `test_top_ips_in_log_data` | `test_top_ips_in_report_data` | `result.log_data["top_ips"]` → `report_data.top_ips` |
| `test_service_hits_in_log_data` | `test_service_hits_in_report_data` | `result.log_data["svc_hits"].get(...)` → `report_data.svc_hits.get(...)` |

#### `result, _ = check_logs(...)` test sites

~20 sites in `test_logs.py` (14) and `test_degraded.py` (8) now use tuple unpack. The tests only consult `result.findings` / `result.deductions` (scoring logic, levels), so the second tuple element is ignored via `_`. Purely mechanical migration pattern via `replace_all` Edit; no test-logic change.

#### Side-fix caught by existing tests

During the `print_audit_summary` split (#12), 8 tests failed on first run with `NameError: name 'score' is not defined`:

- `TestScoreTrend::test_no_prev_score_no_arrow`
- `TestScoreTrend::test_improved_shows_up_arrow`
- `TestScoreTrend::test_degraded_shows_down_arrow`
- `TestScoreTrend::test_stable_shows_no_annotation`
- `TestScoreTrend::test_improved_by_two`
- `TestScoreTrend::test_degraded_by_three`
- `TestExplainHintAbsent::test_explainable_alongside_non_explainable`
- `TestDuplicateFindings::test_two_identical_findings_produce_two_hints`

Root cause: `score`, `level_str`, `ctx_str` were computed at the top of the function, used in the header (extracted into `_summary_header_lines`), then re-used in `report.write_summary(...)` at the end of the function. After the extraction, the locals were no longer in scope.

Fix: replace with direct expressions:
```python
report.write_summary(
    score=engine.score,
    risk_level=t(f"scoring.level.{engine.level.value}"),
    network_context=t(f"scoring.context.{network_context}"),
    ...
)
```

All 8 tests passed after this fix. Good illustration of why having e2e coverage on display functions matters — a "purely cosmetic" refactor can break data paths through implicit references.

#### Field testing

Same cross-distro coverage approach as v0.5.0/v0.5.1/v0.5.2 — pipx upgrade + `sudo bob -v -d` on each VM. Expected output: bit-identical to v0.5.2 (modulo system state changes between runs).

All 4538 tests pass in ~6s on Python 3.12 / Linux Mint 22.3.

---

### v0.5.2 — 4538/4538 (2026-05-22)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4538 passed in ~6s
```

**Net: 0 (no new tests, no removals).** v0.5.2 is the Phase 3 refactor (audit findings #4 + #3). Both are structural — the `_BAD_DIRECTIVES` table-driven approach for sshd_config produces identical `Finding` and `Deduction` entries to the previous if-blocks, and the `_sec` extension is keyword-only (no impact on existing callers).

#### Why zero test deltas

`test_ssh.py` has 122 tests, including 30+ that pin sshd_config behaviour. None of them changed:
- Tests assert on `result.findings` and `result.deductions` lists (count, attributes, key matching) — the table-driven path produces the same entries in the same order.
- Tests use `SSHSnapshot(sshd_config={"x11forwarding": "yes", ...})` to construct snapshots — the loop `for rule in _BAD_DIRECTIVES` reads the same dict keys.
- The 4 imperative cases (PermitRootLogin, PasswordAuthentication, MaxAuthTries, LoginGraceTime) stayed untouched — tests on these continue to use the same code paths.

#### `_BAD_DIRECTIVES` test coverage breakdown

The 8 migrated directives each have between 2 and 6 tests in `test_ssh.py`. The migration was validated by:

| Directive | Pre-migration tests | Post-migration result |
|---|---|---|
| `PermitEmptyPasswords` | `test_permit_empty_passwords_yes`, `test_permit_empty_passwords_no_no_finding` | ✓ |
| `X11Forwarding` | `test_x11_forwarding_yes`, `test_x11_forwarding_default_no` | ✓ |
| `IgnoreRhosts` | `test_ignore_rhosts_no` | ✓ |
| `HostbasedAuthentication` | `test_host_based_auth_yes` | ✓ |
| `PermitUserEnvironment` | `test_permit_user_env_yes` | ✓ |
| `StrictModes` | `test_strict_modes_no` | ✓ |
| `AllowTcpForwarding` | `test_allow_tcp_forwarding_yes`, `test_allow_tcp_forwarding_no_ok`, `test_allow_tcp_forwarding_local_ok` | ✓ (incl. `safe_values=("no", "local")` case) |
| `PubkeyAuthentication` | `test_pubkey_auth_disabled` | ✓ |

All tests pass on the table-driven path. The `__post_init__` validation (mutual exclusion of `bad_values` and `safe_values`) is exercised at module load time — if any future contributor adds a malformed `_BadDirective` entry, the import fails with a clear error message.

#### `runner._sec` extension — no test impact

The 4 sites migrated to `skip_if=` / `post_display=` (`samba`, `docker_audit`, `desktop_apps`, `disk`) have no direct unit tests on the runner orchestration (`run_checks` is integration-tested via the audit pipeline as a whole). The keyword-only `*,` separator before the new params means existing positional-call patterns continue to compile.

#### Field testing

Same cross-distro coverage approach as v0.5.0/v0.5.1 — pipx upgrade + `sudo bob -v -d` on each VM. Expected output: bit-identical to v0.5.1 (modulo system state changes between runs). Specifically the section box order, the finding messages, the deduction reasons, and the per-domain score breakdown must all match.

All 4538 tests pass in ~6s on Python 3.12 / Linux Mint 22.3.

---

### v0.5.1 — 4538/4538 (2026-05-21)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4538 passed in ~6s
```

**Net: 0 (no new tests, no removals).** v0.5.1 is the big LoC-win refactor (audit finding #1). The migration is contract-preserving: each of the 120 paired `result.warn(...) + result.add_deduction(...)` sites collapses to a single `result.warn_with_deduction(...)` (or `.alert_with_deduction(...)`) call. The helper internally invokes the same `warn`/`alert` + `add_deduction` sequence, producing identical `Finding` and `Deduction` entries in `result.findings` and `result.deductions`.

#### Why zero test deltas

A grep across `tests/` confirmed that all tests on `CheckResult` instances assert on the resulting lists (`result.findings`, `result.deductions`, attribute access on individual entries, level counts via `result.warn_count`/`result.alert_count`/etc.). **No test** patched `CheckResult.warn` or `CheckResult.add_deduction` to count invocations. The helper preserves the wire output exactly, so the test suite is unaffected.

#### Migration discipline — 6 waves, full pytest between each

| Wave | Files | Sites | Test result |
|---|---|---|---|
| 1 (1-site files) | backup, ddns, logs, memory, network_context, smtp, suid_audit | 7 | 4538/4538 |
| 2 (2-site files) | cron_audit, docker_audit, fail2ban, firmware, ipv6, kernel_modules, ntp, password_policy, ports, secure_boot, systemd_timers, umask, updates, user_accounts | 16 | 4538/4538 |
| 3 (3-site files) | auditd, file_integrity, kernel_hardening, log_rotation, rootkit | 15 | 4538/4538 |
| 4 (4-6 site files) | file_perms, firewall_stack, firewall (pilot), disk, iptables_nftables, clamav, mac_policy, samba | 29 | 4538/4538 |
| 5 (hardening) | hardening | 8 | 4538/4538 |
| 6 (ssh) | ssh | 24 | 4538/4538 |
| **Total** | **27 files** | **120 sites** | **4538/4538** |

13 sites were intentionally not migrated (capped deductions, level branching, conditional points, divergent template_vars). See `CHANGELOG.md` for the breakdown.

#### Field-testing follows the same pattern as v0.5.0

The Phase-1 v0.5.0 release was field-tested on 5 distros (Linux Mint 22.3 production + so6minttest, Debian 13 trixie, Kali Rolling, Ubuntu 26.04 LTS) with `sudo bob -v -d --french`. v0.5.1's refactor preserves the wire output exactly, so the same cross-distro coverage applies. The recommended field test for v0.5.1: install via `pipx upgrade bodyguard-of-bits` and run `sudo bob -v -d` — the audit output, score breakdown, and per-domain bars must be bit-identical to v0.5.0 (modulo system state changes between runs).

---

### v0.5.0 — 4538/4538 (2026-05-21)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4538 passed in 7.77s
```

**Net: +39 (zero removals, no contract change).** v0.5.0 opens the v0.5.x refactor branch with 6 audit findings + 1 latent bug surfaced by the new tests. **The audit pipeline behaviour is unchanged** — JSON `schema_version="1"`, the 7 score domains, the 116 EXPLAIN_KEYS, the 34 filterable sections all preserved.

#### `tests/test_domain_scores_mapping_complete.py` (+4 — new file)

AST-based scan of `bob/checks/*.py` for every literal `key="X.Y"` argument to emitting methods (`add_deduction`, `warn`, `alert`, `info`, `ok`). Extracts unique prefixes and asserts each is either explicit in `_PREFIX_TO_DOMAIN` (`bob/domain_scores.py`) or whitelisted in `_CATCH_ALL_BY_DESIGN` with a justification:

| Test | Coverage |
|---|---|
| `test_every_emitted_prefix_is_mapped_or_whitelisted` | Hard-fail on any new unmapped prefix (the future-drift guard) |
| `test_no_stale_catchall_entries` | Warn (not fail) on whitelist entries with no current emitter |
| `test_no_stale_prefix_to_domain_entries` | Warn on `_PREFIX_TO_DOMAIN` entries unused by static call sites |
| `test_all_entries_have_justifications` | Every whitelist entry must have a non-empty reason |

#### `tests/test_cron.py` — 5 new classes (+35)

Phase 5 preliminary coverage — cron.py was the codebase's worst-tested module (0.60× per SNAPSHOT).

| Class | Tests | What it pins |
|---|---|---|
| `TestValidateCronField` | 13 | All branches: `*`, `N`, `N-M`, `*/K`, `N-M/K`, `,`-lists, out-of-bounds (v0.4.3 regression class), reversed range, empty entry, garbage |
| `TestValidateCustomCron` | 7 | Full 5-field discipline, per-field bounds (minute 0-59, hour 0-23, etc.), 4-field rejection, 6-field rejection |
| `TestBuildScriptContent` | 7 | Shebang, `shlex.quote()` behaviour (simple email + space-containing edge case), `LOG_DIR` quoting, `--quiet --detailed` invocation, `AUDIT_EMAIL`/`AUDIT_LOG` exports |
| `TestApplyCronSchedule` | 3 | Schedule replacement preserves email comment, missing-file OSError surfacing |
| `TestApplyCronEmail` | 5 | Email comment + `NOTIFY_EMAILS=` script line update + **legacy `NOTIFY_EMAIL=` (no S) regex parity** + missing-script tolerance + `shlex.quote()` quoting |

#### Latent bug fixed (discovered by `TestApplyCronSchedule`)

The new `TestApplyCronSchedule::test_replaces_schedule` failed on first run with `NameError: name '_os' is not defined` at `bob/cron.py:855`. Root cause: v0.4.8 cron-deduplication extracted `apply_cron_schedule()` from `bob/tui/cron.py` to public `bob.cron` API but missed renaming `_os.open(...)` to `os.open(...)`. The `_os` alias is local to three *other* functions in `cron.py` (`import os as _os` scoped per-function). At module level only `os` is imported. The helper had been silently dead since v0.4.8 ship — the curses TUI wired it but isn't exercised by automated tests, so the bug only manifested at interactive runtime. Fix: 3 references on 2 lines.

#### Test adaptations (refactor #7 ripple)

| File | Change | Why |
|---|---|---|
| `tests/test_fail2ban.py` | `_make_run_stub` no longer handles `systemctl is-active` (lost the `service_active` parameter); each test adds `patch("bob.checks.fail2ban.is_unit_active", return_value=...)` | The migration to `is_unit_active()` means the systemctl call no longer goes through the patched `_run`; it goes through `is_unit_active` from `_run.py`'s namespace |
| `tests/test_ntp.py` | `_make_run_side_effect` reduced to timedatectl-only; new `_make_is_active_stub` helper; each test patches both `_run` (for timedatectl) and `is_unit_active` (for service detection) | Same reason |

No assertion changed semantically — the contract these tests pin (NTP/Fail2ban snapshot fields, service-active inference) is preserved.

All 4538 tests pass in 7.77s on Python 3.12 / Linux Mint 22.3 / `so6desktop`.

---

### v0.4.8 — 4499/4499 (2026-05-21)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4499 passed in 6.29s
```

**Net: −1 (no new tests, 1 removal).** v0.4.8 is a code-hardening release: a sub-agent code-review pass surfaced 4 important + 5 minor + 3 suggestion findings, all addressed. The pyproject.toml was deeply audited and 6 packaging hardening fixes were applied. No new behaviour, no contract change — the audit pipeline, the JSON `schema_version="1"`, the 7 score domains, the 116 EXPLAIN_KEYS, and the 34 filterable sections are all unchanged.

**Why −1 test:** `test_default_method_is_none` in `tests/test_secure_boot.py` asserted that a `SecureBootSnapshot` constructed without `method=` defaults to `None`. That field was discovered to be dead — nothing reads it, the value is never propagated to the report — so the field itself was removed from the dataclass. The test that pinned its default value became meaningless and was deleted with the field.

#### Dead-field cleanup — kwargs removed from existing tests

| File | Field removed | Tests updated |
|---|---|---|
| `tests/test_firewall.py`, `test_degraded.py`, `test_ufw_logging.py` | `ipv4_rules_count`, `ipv6_rules_count` | Constructor kwargs dropped (~6 sites) |
| `tests/test_samba.py` | `min_protocol=""` | Constructor kwarg dropped (1 site) |
| `tests/test_clamav.py` | `db_path`, `last_scan_log_path` | Constructor kwargs dropped + 1 assertion at line 471 removed |
| `tests/test_secure_boot.py` | `method=` | `make_snap()` helper updated + 1 test removed (`test_default_method_is_none`) |

No semantic change to the assertions that remained — these fields were never read by production code, so the tests pinning them were structural noise.

#### What's covered (no new tests, but the existing suite catches the work)

| Audit finding | Existing test coverage that validates the fix |
|---|---|
| I4 — `chown_to_sudo_user()` on report/log creation | Manual smoke test (sudo + non-root user); the existing `test_logs.py` and `test_report.py` exercise the surrounding paths |
| M1 — `_C_LOCALE_ENV` consistency | Already covered by `test_locale_coverage.py` AST scanner (no new sites required) |
| M3 — `log_rotation._service_active` refactor | Covered by existing `test_log_rotation.py` |
| M2/S2 — cron helper extraction | Covered by existing `test_cron.py` (~150 tests) + `test_tui_cron.py` |
| S1 — `auth_log` 90-day window docstring | Docs change only, no behaviour delta |
| S3 — `SCORE_BAR_WIDTH` exported | Import sites updated, covered by existing `test_breakdown.py` + `test_domain_scores.py` |
| pyproject.toml hardening | Validated via `python -m build --wheel` + `twine check dist/*` in CI |

All 4499 tests pass in 6.29s on the local development workstation.

---

### v0.4.7 — 4500/4500 (2026-05-21)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4500 passed in 5.55s
```

**Net: 0 (no new tests, no removals).** v0.4.7 is a maintenance release: documentation audit, cosmetic UI harmonization (gauge bars), bash completion overhaul, and CI automation for GitHub Release creation. None of these changes the audit pipeline behaviour or the scoring contract, so no test coverage was added.

3 tests in `tests/test_breakdown.py::TestBar` were adapted (not new tests, just adjusted assertions) to handle the new ANSI-coloured bar output from `bob.output.score_bar()`:

| Test | Before | After |
|---|---|---|
| `test_full_score_all_filled` | `assert _bar(10) == "██████████"` (10-char plain string) | Strips `re.compile(r"\x1b\[[0-9;]*m")` from `_bar(10)` before comparing to `"██████████"` |
| `test_zero_score_all_empty` | `assert _bar(0) == "░░░░░░░░░░"` | Same: strip ANSI then compare |
| `test_five_half_filled` | `assert len(bar) == 10` | Strip ANSI then assert visible content (5 `█`, 5 `░`) and length |

The bar string went from 10 characters to ~19 characters with ANSI escape sequences wrapping the visible content. The visible content (the actual `█` / `░` characters) is unchanged — only the colour codes around them were added.

All other tests pass unchanged, including the entire `bob/checks/` test suite (~3000 tests), domain scoring, JSON contract, locale coverage, profile inheritance, golden scoring scenarios, and the CLI parser tests.

---

### v0.4.6 — 4500/4500 (2026-05-17)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4500 passed in 5.94s
```

**Net: +11 (no removals).** Terrain test pass v0.4.5 surfaced two reproducible bugs across 13 audits on 6 systems (5 VMs + production Linux Mint workstation). Both fixed and covered.

#### `tests/test_kernel_modules.py` — `TestParseInstalledKernels` (+5)

Direct coverage of **Bug 1** (`dpkg-query` did not filter on `ii` state, listed kernels in `rc` state after `apt remove` / `autoremove`):

| Test | Coverage |
|---|---|
| `test_status_prefixed_ii_kept` | `ii ` rows produce the version list (basic happy path) |
| `test_status_prefixed_rc_excluded` | `rc ` row dropped while sibling `ii ` row kept (direct Bug 1 reproduction) |
| `test_status_prefixed_excludes_all_non_installed_states` | `ii`/`rc`/`pn`/`un`/`iU` cohabit; only `ii` survives |
| `test_status_prefixed_hi_kept` | `hi` (apt-mark hold) packages stay in the list |
| `test_mixed_legacy_and_status_prefixed_format` | Backward compat — legacy (no `|` prefix) and new (`ii |...`) lines mix correctly |

#### `tests/test_domain_scores.py` — `TestActiveDomainsIncludesOK` (+6)

Direct coverage of **Bug 2** (`active_domains_from_engine` excluded `OK`-only domains → score dropped after remediation):

| Test | Coverage |
|---|---|
| `test_ok_finding_makes_domain_active` | `OK` finding promotes a domain (the fix) |
| `test_warn_finding_makes_domain_active` | Backward compat: `WARN` still promotes |
| `test_alert_finding_makes_domain_active` | Backward compat: `ALERT` still promotes |
| `test_info_only_finding_does_not_promote_domain` | `INFO`-only domains stay hidden (preserved by design) |
| `test_no_findings_no_active_domains` | Empty engine → empty active set (baseline regression guard) |
| `test_remediation_keeps_domain_at_max_score` | Direct Debian 13 reproduction: ssh has WARN (8/10) + updates remediated to OK only → global = `(8+10)/2 = 9` instead of `8` |

#### Multi-distro integration CI (additive — not unit tests)

A new GitHub Actions workflow `.github/workflows/integration.yml` runs BOB inside containers of Debian 12/13, Ubuntu 22.04/24.04/25.04, Kali Rolling, Fedora 41 on every push/PR to `main`. Each job asserts: exit code ≤ 3, no locale sentinel keys `[xxx.yyy]` in output, no Python tracebacks. Catches the regression class that unit tests can't reach (distro-specific subprocess assumptions, locale fallback, non-Debian families). 7/7 distros green at v0.4.6 release.

Terrain validation post-release: 14 audits on 5 systems confirm 7 `rc` kernels correctly filtered (3 + 2 + 1 + 0 + 1) and score deltas positive on the 3 systems with remediated state (Debian 13 +3, Mint test +1, Ubuntu 26.04 LTS +2).

---

### v0.4.5 — 4489/4489 (2026-05-17)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4489 passed in 5.81s
```

**Net: 0 (pure refactor of `tests/test_locale_coverage.py` — no source file in `bob/` modified).**

The locale-coverage scanner switched from regex-over-source-text to AST parsing (`ast.parse` + `ast.walk` + `ast.Call` + `ast.Name` checks). Same 9 tests in `TestLocaleCoverage` + `TestExplainNamespaceCoverage` + `TestPlaceholderParity`, same external contract.

#### What changed inside the test file

| Aspect | Before (regex) | After (AST) |
|---|---|---|
| Source reading | `re.finditer` on file text | `ast.parse(...)`, walk the tree |
| Translation call detection | Pattern `t\([\'"]([\w.]+)[\'"]` with negative lookbehind | `ast.Call(func=ast.Name(id in {"t","_t"}))` |
| First arg extraction | Regex group | `_literal_key_arg(call)` — checks `ast.Constant(str)` |
| `_KEY_EXCLUSIONS` allowlist | 2 entries (`samba.open_world`, `log.blocked_attempts` from docstring matches) | **Deleted** — docstrings are inert string constants, AST cannot mistake them for call sites |

#### What this fixes (vs the regex form)

- **Docstring matches.** With AST, examples like `t("samba.open_world")` inside a docstring of `bob/i18n.py` are leaf string constants without a calling site — they cannot produce a false positive.
- **Multi-line call sites.** AST is whitespace-independent — calls split across lines (`t(\n    "foo.bar",\n    x=1,\n)`) match identically.
- **Attribute calls.** `obj._t("foo")` resolves to `ast.Attribute`, not `ast.Name` — the type check rejects it cleanly without ad-hoc lookbehind tightening.

#### Performance note

AST parsing is ~5× slower than regex on this codebase (300 ms vs 60 ms for `tests/test_locale_coverage.py`). Negligible in absolute terms — the whole test suite still runs in ~6 s.

---

### v0.4.4 — 4489/4489 (2026-05-16)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4489 passed in 5.66s
```

**Net: +21 (no removals).** Cross-distro terrain hardening. One critical bug + three minor presentation fixes surfaced by terrain testing on Debian 13, Kali Rolling, Mint test, Ubuntu 26.04 LTS. v0.4.3 audit-deferred items also landed (S4 home-bounded symlink, M4 `_parse_ufw_covered_ports` refactor, I2 wave-2 `key=` on services/virtualization).

#### `tests/test_updates.py` (+9) — critical `updates.py` bug coverage

`updates.py` reported "system up to date" on 100% of vierge Debian-family VMs (Debian 13 with 59 packages pending, Kali Rolling with 868, Mint with 33, Ubuntu LTS with 23 of which 21 were security updates). Two root causes: `apt-get -s upgrade` is conservative and back-holds anything pulling a new package (typical kernel), and a stale apt cache silently returned 0 packages.

| Test theme | Coverage |
|---|---|
| `-s dist-upgrade` parsing | Replaces `-s upgrade`, parses the new line format (`Inst foo (...)`/`Conf foo (...)`) |
| Stale apt cache detection | `Path("/var/cache/apt/pkgcache.bin")` mtime > 7 days → `result.warn("updates.apt_cache_stale", days=N)` |
| Cross-check vs `apt list --upgradable` | If `dist-upgrade -s` returns 0 but `apt list` returns > 0 → incoherence note |
| "Surface d'attaque" cascade | When updates state is `unknown`, the surface section no longer says "à jour"; propagates `updates_unknown` instead |

#### `tests/test_mac_policy.py` (+2) — AppArmor 0-profile dedicated key

Kali had AppArmor active with 0 enforce + 0 complain profiles. v0.4.3 emitted a contradictory message ("aucun profil en mode enforce (0 en plainte)"). New 3-case logic:

| Case | Message |
|---|---|
| `enforce > 0` + `complain > 0` | "X enforce, Y complain — passer enforce" (Mint default) |
| `enforce > 0` + `complain == 0` | "tous les profils en enforce — bon état" |
| `enforce == 0` + `complain == 0` | New: "AppArmor activé mais aucun profil chargé — installer apparmor-profiles-extra" |

#### `tests/test_disk.py` (+3) — SMART skip when all-virtual

On Kali VM `/dev/vda` (libvirt), v0.4.3 emitted `ℹ /dev/vda — SMART non applicable` then `✔ Tous les disques ont passé le contrôle SMART`. Second line is misleading — no SMART actually ran. Fix: if all disks are SMART-non-applicable, skip the OK summary; emit a single INFO "SMART non-applicable — environnement virtualisé/conteneur".

#### `tests/test_ddns.py` (+2) — DDNS ports inline in WARN

On Mint test VM, DDNS WARN was emitted with port list as separate `→ 22/tcp` / `→ 80/tcp` action lines, looking like remediation commands. Ports now inlined in the WARN message itself: `DDNS actif avec port(s) ouverts sans restriction (22/tcp, 80/tcp) — vérifiez…`.

#### `tests/test_locale_coverage.py` (new, +9) — locale fallback regression guard

After the v0.4.3 `[logs.attempts]` sentinel incident (locale key removed without updating its call sites in `display.py`), this file scans all `bob/**/*.py` for `t("xxx.yyy")` / `_t("xxx.yyy")` calls (initial regex form, later refactored to AST in v0.4.5) and asserts that every key exists in both `en.json` and `fr.json`. Catches the entire class of sentinel regressions in CI.

Three test classes: `TestLocaleCoverage` (key existence), `TestExplainNamespaceCoverage` (every `EXPLAIN_KEYS` entry has full `title`/`why`/`how`/`cis_ref` quartet in both locales), `TestPlaceholderParity` (every `{var}` placeholder in EN matches FR).

#### `tests/test_ssh.py` (+1) — home-bounded symlink (S4 redesign)

New helper `_is_safe_user_path(path, owner_home)` in `bob/checks/_run.py`: accepts symlinks pointing inside the owner's home, rejects ones pointing elsewhere. Applied in `ssh.py` (authorized_keys / ssh/config parsing) — preserves dotfiles-via-git use cases without losing the symlink-attack guard. `_is_safe_config_path` retained for `/etc/cron.d/`.

---

### v0.4.3 — 4468/4468 (2026-05-15)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4468 passed in 5.41s
```

**Net: +16 (incl. +4 regression coverage, no removals).** Doc catch-up + post-audit hardening pass. One critical (`--json-full` crash) + five important fixes + eight minor + five suggestions surfaced by agent code review.

#### `tests/test_hardening.py` (+5) — `--json-full` HardeningSnapshot dead-attr regression

`bob --json --json-full` crashed because `bob/json_output.py` referenced 5 attributes that had been removed from `HardeningSnapshot` (`kernel.unprivileged_bpf_disabled`, `kernel.unprivileged_userns_clone`, `fs.protected_fifos`, `fs.protected_regular`, `kernel.modules_disabled`). Tests now exercise `build_json_data` with realistic `HardeningSnapshot` fixtures across both `--json` (short) and `--json --json-full` (extended) modes.

#### `tests/test_explain.py` (+4) — 4 firewall keys promoted to `EXPLAIN_KEYS`

`prerequisites.ufw_missing`, `firewall.inactive`, `firewall.policy_open`, `firewall.policy_routed_open` were promoted from "documented but unfrozen" to canonical `EXPLAIN_KEYS` entries. Each needed: full `title`/`why`/`how`/`cis_ref` in `en.json` + `fr.json`, group label change from "Firewall Logging" → "Firewall", and a regression test that `bob --explain firewall.inactive` returns content (not "not found").

#### `tests/test_ssl_certs.py` + `tests/test_logs.py` (+2) — `strptime("%b ...")` locale-independent

`strptime("%b ...")` broke when `LANG=fr_FR.UTF-8` set the C library to French month names ("janv", "févr"). `bob/checks/ssl_certs.py` and `bob/checks/logs.py` now wrap the call with a `_C_LOCALE_ENV` context manager to force English month parsing regardless of host locale.

#### `tests/test_ports.py` (+1) — `_is_covered_by_ufw` IP false-positive

A UFW rule `from 192.168.1.22 to any` was being matched as "covers port 22" because the regex captured `22` from the source IP. Anchored the port-extraction regex to the `port/proto` field only.

#### `tests/test_cron_audit.py` (+1) — range validator out-of-bounds

Cron expressions like `60 * * * *` (minute = 60 is invalid) were accepted. Validator now rejects out-of-bounds values per field (`0-59` for minute, `0-23` for hour, etc.).

#### `tests/test_email.py` + `tests/test_html_output.py` (+3) — markdown links not HTML-escaped

Email body HTML rendering was escaping `[label](url)` markdown to literal `&lt;a&gt;` tags. Order of operations in `_inline_format()` reversed so markdown-to-HTML conversion happens before generic escaping.

#### Other items in pass

`key=` attribute added to ~30 findings in `docker`/`firewall_stack`/`network_context`/`ports`. 7 dead locale keys removed (e.g. `samba.dangerous_macro`). i18n concat anti-pattern resolved in `ddns` and `logs` (single composed string instead of `t(key1) + " " + t(key2)`). CIS references added to 8 findings. Short CHANGELOG corrected for v0.4.2.

---

### v0.4.2 — 4452/4452 (2026-05-14)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4452 passed in 5.25s
```

**Net: +3.** Phase 3 distro-ready (packaging discipline) ships packaging artefacts — no Python code changes there. A separate pre-release hardening pass (agent audit) added small code fixes (firewall keys, `_C_LOCALE_ENV` on 3 sites, `watch.py` user_config threading, AppArmor binary list, `BOB_SHARE` rename with fallback) and one new test file `test_template_vars_migration.py` (3 tests) that tracks Phase 2 migration debt visibly.

Separate validation:

| Artefact | Validation command | Result |
|---|---|---|
| `man/bob.1` | `groff -man -Tutf8 man/bob.1 >/dev/null && man -l man/bob.1` | ✓ |
| `man/bob.conf.5` | same | ✓ |
| `man/bob-profile.5` | same | ✓ |
| `bob/data/schemas/*.json` | `python3 -c "import json; json.load(open(f))"` × 3 | ✓ |
| `debian/control` | manual review, syntax matches dh-make output | ✓ |
| `debian/copyright` | DEP-5 format, manual review | ✓ |
| `debian/rules` | executable (`chmod +x`), valid Makefile syntax | ✓ |
| `debian/apparmor.d/bob` | manual review, paths cross-checked against `bob/checks/*` exec sites | ✓ |
| `packaging/rpm/bob.spec` | manual review, `pyproject-rpm-macros` patterns | ✓ |

Full `dpkg-buildpackage` + `lintian` + `rpmbuild` + `rpmlint` validation is deferred to the first community packaging attempt (AUR/COPR or first Debian unstable upload). Upstream commits to fixing any lintian/rpmlint issues reported in subsequent patch releases.

---

### v0.4.1 — 4449/4449 (2026-05-14)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4449 passed in 5.07s
```

**Net: +19 (no removals).** Phase 2 distro-ready (architectural decoupling): `bob/tui/` extraction, `--offline` integration tests, locale-independent finding/deduction representation via `template_vars`, plus a post-review hardening pass on `bob/formatter.py` (4 edge-case tests).

#### `tests/test_formatter.py` (new, +14)

`bob.formatter` — locale-independent message reconstruction:

| Class | Tests | Coverage |
|---|---:|---|
| `TestFormatFinding` | 5 | Resolution order: key + template_vars renders via i18n, key alone returns template, no key falls back to message, unknown key falls back, empty input edge case |
| `TestFormatDeduction` | 2 | Same resolution order applied to `Deduction.key` + `template_vars` → `reason` |
| `TestLocaleRoundtrip` | 1 | Same `(key, template_vars)` yields different text in `fr` vs `en` — the whole point of the decoupling |
| `TestBackwardCompatibility` | 2 | Legacy findings (no key, no template_vars) pass through unchanged |
| `TestFormatterEdgeCases` (post-review) | 4 | Empty template_vars on placeholder template returns raw, partial template_vars raises KeyError, key wins over mismatched message, empty message + no key returns "" |

#### `tests/test_webhook.py` (+3)

`--offline` strict mode contract:

| Test | Coverage |
|---|---|
| `test_webhook_with_offline_flag_parses` | CLI parser accepts `--offline --webhook=URL` together (not mutually exclusive at parse time) |
| `test_offline_skips_webhook_send` | Mirrors `__main__.py:277` decision branch — fails if the offline gate is ever dropped |
| `test_get_public_ip_offline_skips_urllib` | Monkeypatches `sysinfo.urllib` with an exploding stub; raises AssertionError if any urlopen reached in offline mode |

#### `tests/test_json_schema.py` (+2)

`template_vars` field exposed in JSON output:

| Test | Coverage |
|---|---|
| `test_each_deduction_has_template_vars_field` | Every deduction exposes `template_vars` dict (empty for legacy checks) |
| `test_each_finding_has_template_vars_field` | Every finding (full mode) exposes `template_vars` dict |

#### `bob/tui/cron.py` (extraction — no new tests)

`bob/cron_ui.py` (952 lines) moved to `bob/tui/cron.py` via `git mv`. The 4430 existing tests already exercise the import path; the full suite remained 4430/4430 after the move, proving the rename is transparent.

---

### v0.4.0 — 4430/4430 (2026-05-14)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4430 passed in 5.52s
```

**Net: +82 (no removals).** Phase 1 distro-ready contracts frozen, plus two post-review hardening passes:
- **Pass #1** (+22 tests in `test_services_schema.py`): strict 1–65535 port regex, `$defs` factorization, `if/then`/`anyOf` business constraints, plugin-file `schema_version` wrapper.
- **Pass #2** (+3 tests, defense-in-depth): `services-list.minItems: 1` (rejects empty arrays), real-class fixtures replacing `MagicMock` in `test_json_schema.py` (so renamed attributes raise `AttributeError` instead of being auto-mocked), `EXPECTED_REQUIRED_KEYS_V1` duplicated as a drift-detection contract, `RefResolver`→`referencing` compat shim for jsonschema 4.18+, asserts via `e.absolute_path` instead of brittle message matching.

#### `tests/test_i18n.py` — `TestDetectSystemLang` (+12)

POSIX locale auto-detection (`$LC_ALL` / `$LC_MESSAGES` / `$LANG`):

| Test | Coverage |
|---|---|
| `test_no_env_returns_default` | All env vars unset → `"en"` |
| `test_lang_c_returns_default` | `LANG=C` → `"en"` |
| `test_lang_posix_returns_default` | `LANG=POSIX` → `"en"` |
| `test_lang_c_utf8_returns_default` | `LANG=C.UTF-8` → `"en"` |
| `test_fr_fr_returns_fr` | `LANG=fr_FR.UTF-8` → `"fr"` |
| `test_fr_be_returns_fr` | `LANG=fr_BE` → `"fr"` |
| `test_fr_with_modifier_returns_fr` | `LANG=fr_FR.UTF-8@euro` → `"fr"` |
| `test_en_us_returns_en` | `LANG=en_US.UTF-8` → `"en"` |
| `test_unsupported_lang_falls_back_to_default` | `ja_JP`/`de_DE`/`es_ES`/`zh_CN` → `"en"` |
| `test_lc_all_overrides_lang` | `LC_ALL=fr` overrides `LANG=en` |
| `test_lc_messages_overrides_lang` | `LC_MESSAGES=fr` overrides `LANG=en` |
| `test_empty_lc_all_falls_through_to_lang` | `LC_ALL=""` → consults `LANG` |

#### `tests/test_cli.py` — locale integration (+4)

| Test | Coverage |
|---|---|
| `test_french_overrides_system_locale` | `--french` wins on `LANG=ja_JP` |
| `test_lang_explicit_overrides_system_locale` | `--lang=en` wins on `LANG=fr_FR` |
| `test_default_uses_system_locale_when_fr` | Default → `fr` when `LANG=fr_FR.UTF-8` |
| `test_default_uses_en_when_lang_c` | Default → `en` when `LANG=C` |

#### `tests/test_json_schema.py` (new, +17)

JSON output schema invariants — public API contract:

| Class | Tests |
|---|---:|
| `TestSchemaVersion` | 2 |
| `TestRequiredKeysAlwaysPresent` | 6 |
| `TestFieldTypes` | 5 |
| `TestStableKeysExposed` | 3 |
| `TestDomainScoresStructure` | 1 |

Verifies `schema_version="1"`, required top-level keys, field types, locale-independent `key` field on each finding/deduction.

**Pass #2 hardening:** all `MagicMock` injections in fixtures replaced by real BOB dataclasses (`SystemInfo`, `PortsSnapshot`, `FirewallStackSnapshot`, `NetworkContextSnapshot`, `CheckResult`) so a renamed attribute in `bob.json_output.build_json_data` raises `AttributeError` instead of being silently auto-mocked. Timestamp test now uses `datetime.fromisoformat()` (strict ISO 8601). Two new defense-in-depth tests: `test_short_mode_strict_set` (rejects unexpected keys leaking into short mode) and `test_constants_match_expected_set` (catches drift between production constants and the test-side hard-coded contract).

#### `tests/test_explain.py` — alias map + freeze (+6)

| Test | Coverage |
|---|---|
| `test_alias_map_is_dict` | `EXPLAIN_KEY_ALIASES` is a dict |
| `test_alias_targets_resolve_to_valid_keys` | Every alias target exists in canonical set |
| `test_alias_keys_are_not_in_canonical_set` | Aliases don't shadow real keys |
| `test_normalize_key_resolves_aliases` | Registered alias gets resolved |
| `test_normalize_key_passthrough_when_no_alias` | Unknown keys pass through unchanged |
| `test_core_keys_present_in_canonical_set` | 16 frozen "load-bearing" keys must remain in `EXPLAIN_KEYS` |

#### `tests/test_services_schema.py` (new, +43)

Plugin services formal JSON Schema (Draft 2020-12), extended after two post-review hardening passes:

| Class | Tests | Coverage |
|---|---:|---|
| `TestSchemasAreWellFormed` | 4 | Schemas pass Draft 2020-12 self-validation; `services-list` rejects empty array (pass #2: `minItems: 1`) |
| `TestBundledServicesMatchSchema` | 3 | Bundled `services.json` validates entry-by-entry; unique IDs (`Counter` O(n)) |
| `TestValidPluginSamples` | 3 | Sample valid plugins (minimal fixed, with detection, user config_key) |
| `TestInvalidPluginSamples` | 10 | Rejection cases: missing field, bad risk, bad port, port 0/65536, unknown field, fixed without ports, ID with spaces, empty binary string. Pass #2: 5 of these now assert via `e.absolute_path` (stable across jsonschema versions) instead of message-substring matching. |
| `TestSchemaPythonParity` | 2 | Schema-valid ↔ Python-valid alignment |
| `TestBusinessConstraints` (new pass #1) | 7 | `auto` requires `config_files`, undetectable service rejected, empty `detection: {}` rejected |
| `TestPluginFileWrapper` (new pass #1) | 6 | Legacy array + wrapped `{schema_version, services}` accepted; v2 / extras rejected. Pass #2: cross-file `$ref` resolution via the `_make_resolved_validator` compat shim (modern `referencing` first, legacy `RefResolver` fallback). |
| `TestRegistryAcceptsBothShapes` (new pass #1) | 7 | Python `_extract_plugin_entries` parity with the meta-schema |
| Boundary tests | 2 | Port 65535 accepted, 65536 rejected (strict regex) |

A module-scope `service_validator` fixture is shared across all classes (pass #2 — replaces 4 duplicated per-class one-liners).

`jsonschema` is a test-only dependency (uses `pytest.importorskip`).

#### `tests/test_min_level.py` — score display

`TestScoreTrend::test_stable_shows_equal` renamed to `test_stable_shows_no_annotation` and inverted: stable score now displays `"7/10"` exactly (no `= 7` suffix).

#### `tests/conftest.py` (new)

Autouse fixture forces `LC_ALL=C`/`LANG=C` for every test, making locale-dependent CLI defaults deterministic regardless of the developer's host locale.

---

### v0.3.6 — 4348/4348 (2026-05-09)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4348 passed in 5.04s
```

**No new tests — code-review pass.** Eight related fixes: `Path.home()` → `get_user_home()` in 7 modules · IPv6 ULA/link-local in `_is_private_or_loopback` · SSH `AllowTcpForwarding local` accepted · UFW logging header skipped when UFW inactive · `NOTIFY_EMAIL` legacy regex · `_check_weak_algo` moved to sub-check section · 22 unused imports removed (pyflakes clean except for one intentional `noqa`) · 47 dead locale keys removed.

**Field validation:** Full audit on so6desktop (Linux Mint 22.3) completed with score 8/10. UFW logging section header now hidden when UFW inactive; IPv6 link-local correctly classified as private; profiles/plugins/baselines correctly loaded from `/home/so6/.config/bob/` (not `/root/.config/bob/`).

---

### v0.3.5 — 4348/4348 (2026-05-08)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4348 passed in 5.22s
```

**No new tests — pure refactoring (`runner.py` `_sec` closure −295 lines, `ssh.py` `_check_weak_algo` −26 lines)**

---

### v0.3.4 — 4348/4348 (2026-05-08)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4348 passed in 5.17s
```

**No new tests — hotfix only (pass `user_config` to `run_checks()` — `NameError` on SUID whitelist)**

---

### v0.3.3 — 4348/4348 (2026-05-07)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4348 passed in 5.21s
```

**Net: +1 from v0.3.2 (+7 new capped_indices tests, −6 was_capped tests removed)**

#### `tests/test_domain_scores.py` — `TestCappedIndices` replaces `TestWasCapped` (+7, −6)

`TestWasCapped` tested the `deduction.was_capped` bool flag (removed in v0.3.3). Replaced by `TestCappedIndices` which tests the `frozenset[int]` return value of `compute_domain_scores()`.

| Test | Coverage |
|------|----------|
| `test_no_cap_returns_empty_frozenset` | No tool cap triggered → second return value is `frozenset()` |
| `test_single_capped_deduction_returns_index` | One deduction exceeds cap → index `0` in returned frozenset |
| `test_uncapped_deduction_not_in_frozenset` | Deduction within cap → index absent from frozenset |
| `test_multiple_deductions_only_capped_indices` | Two deductions, one capped → only the capped index returned |
| `test_frozenset_is_immutable` | Returned object is a `frozenset`, not a `set` |
| `test_engine_capped_indices_matches_return_value` | `engine.capped_indices` equals the frozenset returned by `compute_domain_scores()` |
| `test_non_tool_cap_key_never_capped` | Key with no tool-cap prefix → never in capped frozenset |

---

### v0.3.2 — 4347/4347 (2026-05-07)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4347 passed in 5.23s
```

**Net: +19 from v0.3.1 (+21 new whitelist tests, −2 dead-code tests removed)**

**New tests (+21):**

#### `tests/test_suid_audit.py` — `TestFromSystemUserWhitelist` (+8)

| Test | Coverage |
|------|----------|
| `test_whitelisted_suid_emits_info` | Snapshot with whitelisted paths → `suid_audit.whitelisted` INFO finding |
| `test_whitelisted_suid_no_deduction` | Whitelisted paths → no deduction applied |
| `test_whitelisted_suid_ok_result_when_no_unexpected` | All suppressed → `suid_audit.ok` still present |
| `test_whitelisted_suid_warn_result_when_unexpected_remain` | Mix of whitelisted + unexpected → both findings present |
| `test_whitelisted_count_in_info_message` | 2 whitelisted paths → "2" appears in INFO message |
| `test_no_whitelisted_finding_when_list_empty` | Empty `whitelisted_suid` → no INFO finding |
| `test_whitelisted_truncation_at_10` | 11 whitelisted paths → "+1 more" suffix |

#### `tests/test_suid_audit.py` — `TestGetSuidWhitelist` (+7)

| Test | Coverage |
|------|----------|
| `test_returns_empty_list_when_key_absent` | Missing key → `[]` |
| `test_single_pattern` | `kismet_cap_*` → `["kismet_cap_*"]` |
| `test_multiple_patterns_comma_separated` | `a, b, c` → `["a", "b", "c"]` |
| `test_strips_whitespace_around_patterns` | `  foo_*  ,  bar  ` → `["foo_*", "bar"]` |
| `test_empty_value_returns_empty_list` | Empty string value → `[]` |
| `test_commas_only_returns_empty_list` | ` , , ` → `[]` |
| `test_persists_and_reloads` | Written and reloaded → same list |

#### `tests/test_suid_audit.py` — `TestGlobMatching` (+7)

| Test | Coverage |
|------|----------|
| `test_glob_matches_kismet_cap_prefix` | `kismet_cap_*` matches 3 Kismet paths |
| `test_exact_name_match` | Exact basename pattern whitelists matching path |
| `test_non_matching_pattern_leaves_unexpected` | Non-matching pattern → path stays unexpected |
| `test_empty_patterns_leaves_all_unexpected` | Empty patterns → all paths unexpected |
| `test_wildcard_star_matches_all` | `*` pattern → everything whitelisted |
| `test_partial_glob_mix` | Mixed: one matched, one not |
| `test_multiple_patterns_any_match_whitelists` | Two exact patterns → each matches its target |

**Removed tests (−2, DC-1):**

`tests/test_suid_audit.py` — `TestIsRootOwned` deleted along with `_is_root_owned()` dead code:
- `test_nonexistent_path_returns_false`
- `test_current_user_file_not_root_owned_when_not_root`

---

### v0.3.1 — 4328/4328 (2026-05-06)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4328 passed in 4.33s
```

**New tests (+6):**

#### `tests/test_domain_scores.py` — `TestWasCapped` (+6)

| Test | Coverage |
|------|----------|
| `test_uncapped_deduction_not_marked` | Deduction within tool cap → `was_capped` stays `False` |
| `test_fully_absorbed_deduction_marked` | Second deduction after cap exhausted → `was_capped = True` |
| `test_partially_absorbed_deduction_marked` | Deduction partially exceeds remaining cap → `was_capped = True` |
| `test_non_tool_cap_key_never_marked` | Key with no tool-cap prefix → `was_capped` always `False` |
| `test_cached_domain_scores_on_engine` | After `apply_domain_score_override()`, `engine.domain_scores` matches direct call |
| `test_engine_domain_scores_empty_before_override` | Before override, `engine.domain_scores` returns `{}` |

---

### v0.3.0 — 4322/4322 (2026-05-06)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4322 passed in 4.45s
```

**New tests (+48):**

#### `tests/test_breakdown.py` (new file, +16)

| Class | Test | Coverage |
|-------|------|----------|
| `TestBar` | `test_full_score_all_filled` | Score 10 → all filled blocks |
| `TestBar` | `test_zero_score_all_empty` | Score 0 → all empty blocks |
| `TestBar` | `test_five_half_filled` | Score 5 → half filled |
| `TestDisplayBreakdownClean` | `test_no_deductions_message` | No deductions → `no_deductions` key printed |
| `TestDisplayBreakdownClean` | `test_section_title_printed` | Section header printed |
| `TestDisplayBreakdownClean` | `test_final_score_ten_shown` | Score 10 → `breakdown.final_score` key printed |
| `TestDisplayBreakdownWithDeductions` | `test_deductions_header_shown` | Deductions present → header shown |
| `TestDisplayBreakdownWithDeductions` | `test_deduction_keys_shown` | Each deduction key appears in output |
| `TestDisplayBreakdownWithDeductions` | `test_raw_score_shown` | `breakdown.raw_score` key printed |
| `TestDisplayBreakdownWithDeductions` | `test_domain_scores_header_shown` | Active domains → header shown |
| `TestDisplayBreakdownWithDeductions` | `test_domain_average_shown` | Global override set → `breakdown.domain_average` printed |
| `TestDisplayBreakdownWithDeductions` | `test_final_score_shown` | `breakdown.final_score` key printed |
| `TestDisplayBreakdownToolCap` | `test_tool_cap_message_shown_when_exceeded` | Total deductions > cap → tool cap info line shown |
| `TestDisplayBreakdownToolCap` | `test_no_tool_cap_message_when_within_limit` | Total deductions ≤ cap → no tool cap message |
| `TestDisplayBreakdownEngineCap` | `test_engine_cap_message_shown` | `engine.cap_info` set → `breakdown.engine_cap_applied` shown |
| `TestDisplayBreakdownEngineCap` | `test_engine_cap_message_not_shown_when_absent` | No cap → no cap message |

#### `tests/test_golden_scenarios.py` (new file, +32)

| Class | Tests | Coverage |
|-------|-------|----------|
| `TestCleanMachine` | 4 | Score 10/10; no breakdown; no active domains; INFO findings excluded from domain activation |
| `TestHardenedServer` | 3 | 2 hardening deductions → score 8; domain deductions count; raw breakdown assertions |
| `TestDefaultDesktop` | 3 | 4 deductions across 3 domains → score 9; per-domain deduction exact counts |
| `TestPoorlyConfiguredServer` | 3 | Raw score 3; domain average 8; domain average improves over raw |
| `TestFirewallInactive` | 3 | Engine cap enforced at 3; domain average can exceed capped raw; `cap_info` stored |
| `TestDebian13Minimal` | 4 | Raw score 2; domain average 6; rootkit tool cap; 6 total hardening deductions after cap |
| `TestToolCapInvariants` | 4 | rootkit/clamav/file_integrity each capped at 1pt; uncapped tool (ssh) accumulates normally |
| `TestScoreStability` | 5 | Order independence; same-domain monotonicity; domain independence; score ∈ [0, MAX_SCORE]; raw floor 0 |
| `TestMultiDomainMachine` | 3 | 5 active domains exact frozenset; each domain deducted once; score 9 |

#### `tests/test_min_level.py` (renamed, +0 net)

`test_stable_shows_right_arrow` → `test_stable_shows_equal` — assertion updated from `"→" in val` to `"= 7" in val`.

---

### v0.2.4 — 4274/4274 (2026-05-05)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4274 passed in 4.65s
```

**New tests (+12):**

#### `tests/test_kernel_modules.py` (+2)

| Test | Coverage |
|------|----------|
| `test_up_to_date_names_running_kernel_not_unsigned_sibling` | Running `amd64` with `-unsigned` sibling sorted as `most_recent` → OK message names the running kernel, not the unsigned sibling |
| `test_debian_signed_unsigned_pair_uses_obsolete_same_message` | Signed/unsigned pair at the top of the kernel list → `kernels_obsolete_same` key selected (no "running / latest" pair in text), not `kernels_obsolete` |

#### `tests/test_compare.py` — `TestDisplayDelta` (+4)

| Test | Coverage |
|------|----------|
| `test_variable_deductions_increased_shown_without_structural_change` | `deduction_delta > 0`, no structural change (no alert/warn delta, no new/resolved keys) → variable-deductions message shown |
| `test_variable_deductions_decreased_shown_without_structural_change` | `deduction_delta < 0`, no structural change → variable-deductions decrease message shown |
| `test_variable_deductions_suppressed_when_warn_delta` | `deduction_delta != 0` but `warn_delta != 0` → message suppressed (structural change explains score move) |
| `test_variable_deductions_suppressed_when_new_finding_key` | `deduction_delta != 0` but `new_finding_keys` non-empty → message suppressed |

#### `tests/test_compare.py` — `TestDeductionTracking` (new class, +6)

| Test | Coverage |
|------|----------|
| `test_deduction_total_none_in_new_baseline_defaults` | `AuditBaseline()` default `deduction_total` is `None` (not `0`) |
| `test_load_baseline_returns_none_when_field_absent` | Old JSON without `"deduction_total"` key → `None` after `load_baseline()` |
| `test_load_baseline_returns_int_when_field_present` | New JSON with `"deduction_total": 5` → `5` (int) after `load_baseline()` |
| `test_deduction_delta_zero_when_prev_is_old_baseline` | `prev.deduction_total is None` → `compute_delta()` returns `deduction_delta == 0` |
| `test_deduction_delta_computed_when_both_tracked` | Both sides have int `deduction_total` → correct signed delta computed |
| `test_deduction_delta_zero_when_unchanged` | Same value on both sides → `deduction_delta == 0` |

---

### v0.2.3 — 4262/4262 (2026-05-03)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4262 passed in 4.53s
```

**New tests (+1):**

#### `tests/test_exposure.py` (+1)

| Test | Coverage |
|------|----------|
| `test_not_active_shows_stopped_text` | SSH installed but service stopped → attack-surface table uses `exposure.ssh_stopped` key ("installé — non démarré"), not the merged `ssh_not_running` key |

**Updated/renamed tests (4):**

| File | Test | Change |
|------|------|--------|
| `tests/test_services.py` | `test_not_listening_critical_adds_warn` → `test_not_listening_critical_adds_info` | `NOT_LISTENING` demoted to INFO regardless of service severity |
| `tests/test_services.py` | `test_not_listening_high_adds_warn` → `test_not_listening_high_adds_info` | Same — also asserts no WARN finding present |
| `tests/test_logs.py` | `test_finding_is_warn_level` → `test_finding_is_info_level` | IoT local dominance demoted to INFO — asserts `FindingLevel.INFO` |
| `tests/test_logs.py` | `test_score_deduction_one_point` → `test_no_score_deduction` | IoT local dominance: no deduction — asserts `len(local_deductions) == 0` |

---

### v0.2.2 — 4255/4255 (2026-05-02)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4255 passed in 4.42s
```

**New tests (+17):**

#### `tests/test_firewall.py` — `TestOrphanRules` (+3)

| Test | Coverage |
|------|----------|
| `test_bare_port_rule_flagged_when_nothing_listening` | `57621 ALLOW IN` with no TCP or UDP listener → flagged as orphan |
| `test_bare_port_rule_not_flagged_when_tcp_listening` | `57621/tcp` in listening set → not flagged |
| `test_bare_port_rule_not_flagged_when_udp_listening` | `57621/udp` in listening set → not flagged |

#### `tests/test_scoring.py` — `TestScoringInvariants` (+5)

Structural invariants for the scoring engine — properties that must hold regardless of input:

| Test | Invariant |
|------|-----------|
| `test_score_floor_is_zero_on_huge_deduction` | Score never goes below 0 even with 999-point deduction |
| `test_score_ceiling_is_max_on_no_deductions` | Score equals MAX_SCORE when no deductions |
| `test_deductions_are_monotone_decreasing` | Each deduction never increases the score |
| `test_cap_above_current_score_is_noop` | A cap above the current score does not alter it |
| `test_score_after_domain_override_in_valid_range` | After `apply_domain_score_override()`, score ∈ [0, 10] |

#### `tests/test_domain_scores.py` — `TestScoringInvariants` (+7)

Structural invariants for the domain scoring pipeline:

| Test | Invariant |
|------|-----------|
| `test_info_only_findings_do_not_activate_domain` | INFO findings with no deductions do not mark a domain active |
| `test_warn_finding_activates_domain` | A WARN finding marks the corresponding domain active |
| `test_alert_finding_activates_domain` | An ALERT finding marks the corresponding domain active |
| `test_deduction_alone_activates_domain` | A deduction (no finding) still activates the domain |
| `test_global_average_bounded_by_active_domain_scores` | Global average ∈ [min, max] of active domain scores |
| `test_all_domain_scores_in_valid_range` | Every domain score always in [0, MAX_SCORE] |
| `test_compute_global_always_in_valid_range` | `compute_global_from_domains` always returns a value in [0, 10] |

#### `tests/test_manage_logs.py` — `TestStatFallback` (+2)

Regression tests for the v0.2.1 `.stat()` race condition fix. A log file can disappear between the directory scan and the display loop (e.g. logrotate running concurrently). The mock targets only `.log` files to avoid breaking `Path.exists()` on directories (Python 3.12: `exists()` calls `self.stat()` internally).

| Test | Coverage |
|------|----------|
| `TestStatFallback.test_cur_logs_stat_oserror_uses_fallback` | `.stat()` raises `OSError` in `cur_logs` loop → output shows `(0 KB)` and `"?"` without crash |
| `TestStatFallback.test_extra_logs_stat_oserror_uses_fallback` | `.stat()` raises `OSError` in `extra_sections` loop → same fallback output |

**Updated tests (2):**

| File | Test | Change |
|------|------|--------|
| `tests/test_clamav.py` | `test_db_very_outdated_deducts_1` (was `_deducts_2`) | `clamav.db_very_outdated` deduction lowered from 2pt to 1pt (Fix 3) |
| `tests/test_clamav.py` | `test_worst_case` | Total deductions 4→3 (freshclam:1 + db_very_outdated:1 + scan_very_old:1) |

---

### v0.2.0 — 4238/4238 (2026-05-01)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4238 passed in 4.88s
```

**New tests (+32):**

#### `tests/test_kernel_modules.py` (+6)

| Test | Coverage |
|------|----------|
| `TestKernelRebootPending.test_no_reboot_pending_debian_signed_plus_unsigned_same_version` | Running `amd64` with `amd64-unsigned` installed → no reboot warning |
| `TestKernelRebootPending.test_reboot_still_pending_when_genuinely_newer_debian_kernel` | Genuine newer version still triggers reboot pending |
| `TestStripUnsigned.test_strips_unsigned_suffix` | `-unsigned` suffix removed |
| `TestStripUnsigned.test_no_change_without_suffix` | String without suffix unchanged |
| `TestStripUnsigned.test_no_change_ubuntu_style` | Ubuntu-style kernel unchanged |
| `TestStripUnsigned.test_no_change_empty` | Empty string safe |

#### `tests/test_cron.py` (+6)

| Test | Coverage |
|------|----------|
| `TestDetectMta.test_no_sendmail_returns_false` | No sendmail → `(False, "")` |
| `TestDetectMta.test_postfix_detected_via_config_file` | `/etc/postfix/main.cf` present → `(True, "Postfix")` |
| `TestDetectMta.test_exim_detected` | `exim4` in PATH → `(True, "Exim")` |
| `TestDetectMta.test_msmtp_detected` | `msmtp` in PATH → `(True, "msmtp")` |
| `TestDetectMta.test_ssmtp_detected` | `ssmtp` in PATH → `(True, "ssmtp")` |
| `TestDetectMta.test_unknown_mta_returns_empty_name` | sendmail found, unknown provider → `(True, "")` |

#### `tests/test_scoring.py` (+6)

| Test | Coverage |
|------|----------|
| `TestSetGlobalScore.test_override_replaces_raw_score` | Override value returned by `engine.score` |
| `TestSetGlobalScore.test_no_override_by_default` | Raw score used when no override set |
| `TestSetGlobalScore.test_override_clamps_above_max` | Values > 10 clamped to 10 |
| `TestSetGlobalScore.test_override_clamps_below_zero` | Values < 0 clamped to 0 |
| `TestSetGlobalScore.test_level_reflects_overridden_score` | `engine.level` derived from override |
| `TestSetGlobalScore.test_raw_score_unchanged_after_override` | `engine._raw_score` untouched |

#### `tests/test_domain_scores.py` (+14)

**TestToolCaps (7 tests)**

| Test | Coverage |
|------|----------|
| `test_rootkit_two_findings_capped_at_one` | 2×`rootkit.*` deductions → domain gets 1 |
| `test_clamav_two_findings_capped_at_one` | 2×`clamav.*` deductions → domain gets 1 |
| `test_file_integrity_two_findings_capped_at_one` | 2×`file_integrity.*` → domain gets 1 |
| `test_uncapped_prefix_accumulates_fully` | `hardening.*` accumulates without cap |
| `test_caps_do_not_bleed_across_tools` | rootkit cap does not reduce clamav allowance |
| `test_cap_respects_first_deduction_points` | Single 2-pt deduction against cap of 1 → contributes 1 |
| `test_tool_caps_dict_contains_expected_keys` | `_TOOL_CAPS` has rootkit, clamav, file_integrity |

**TestComputeGlobalFromDomains (4 tests)**

| Test | Coverage |
|------|----------|
| `test_average_of_two_active_domains` | Mean of two domain scores, rounded |
| `test_no_active_domains_returns_max` | Empty active set → MAX_SCORE |
| `test_result_clamped_to_max` | Result ≤ 10 |
| `test_result_non_negative` | Result ≥ 0 |

**TestApplyDomainScoreOverride (3 tests)**

| Test | Coverage |
|------|----------|
| `test_engine_score_changes_after_override` | `engine.score` differs from raw after override |
| `test_score_in_valid_range` | Override within [0, 10] |
| `test_debian13_scenario` | 8 deductions raw=2, domain average ≥ 5 |

#### `tests/test_logs.py` (0 new, 3 corrected)

Three tests were corrected to assert the actual intended behaviour (WARN −1 pt for IoT dominance). The previous assertions were verifying the wrong behaviour (INFO, no deduction).

| Test | Before | After |
|------|--------|-------|
| `test_check_logs_emits_warn_finding` | asserted INFO key present | asserts WARN key present |
| `test_finding_is_warn_level` | asserted `FindingLevel.INFO` | asserts `FindingLevel.WARN` |
| `test_score_deduction_one_point` | asserted no deductions | asserts 1 deduction of 1 pt |

---

### v0.1.1 — 4206/4206 (2026-04-29)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4206 passed in 4.19s
```

**New tests — `tests/test_firmware.py` (+4):**

Regression tests for the fwupd 1.9+ tree-format output bug found on Ubuntu 26.04 LTS. fwupdmgr changed its output format from a flat list to a tree structure using `├─`, `└─`, `│` drawing characters. The previous parser captured these as device names, producing garbled output (`│, ├─UEFI CA: (+7)`).

| Test | Coverage |
|------|----------|
| `test_tree_format_extracts_device_names` | `├─` and `└─` lines yield correct device names |
| `test_tree_format_excludes_container_line` | Top-level container name is not captured |
| `test_tree_format_excludes_tree_connectors` | Raw `│`, `├`, `└` characters do not appear as device names |
| `test_tree_format_strips_trailing_colon` | Device names from `├─Name:` lines have no trailing colon |

---

### post-v0.1.0 — 4202/4202 (2026-04-27)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4202 passed in 4.38s
```

**Bugs found during Ubuntu 26.04 LTS first run (`so6ubuntutest`):**

**Root cause fixed — exposure surface: `ssh.not_installed` and `fail2ban.not_installed` not detected:**
Both keys are emitted at `INFO` level by their respective checks. `compute_exposure()` in `exposure.py` only looked in `bad_keys` (ALERT+WARN), so neither key was ever matched — SSH was shown as "key only, root disabled" and fail2ban as "active" even when neither was installed.
Fix: added `all_keys = bad_keys | info_keys`; `ssh.not_installed` and `fail2ban.not_installed` now checked against `all_keys`. (commit `3fa43b5`)

**Root cause fixed — SUID false positive: `sudo.ws` flagged on Ubuntu 26.04:**
`/usr/bin/sudo.ws` is a legitimate binary shipped by the `sudo` package on Ubuntu 26.04 (`dpkg -S` confirmed). Added to `_KNOWN_SUID` whitelist in `suid_audit.py`. (commit `3fa43b5`)

---

### v0.1.0 — 4200/4200 (2026-04-26)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4200 passed in 4.93s
```

#### Test files (65 total)

| File | Tests | Domain |
|------|-------|--------|
| `test_cis_refs.py` | 39 | CIS benchmark mapping |
| `test_iptables_nftables.py` | 51 | Firewall stack (iptables/nftables) |
| `test_firewall.py` | — | UFW rules audit |
| `test_ssh.py` | — | SSH configuration |
| `test_hardening.py` | — | Kernel hardening sysctl |
| `test_kernel_hardening.py` | — | Kernel hardening extended |
| `test_kernel_modules.py` | — | Kernel module audit |
| `test_services.py` | — | Service registry + risk |
| `test_services_state.py` | — | Service state audit |
| `test_docker.py` | — | Docker UFW bypass |
| `test_docker_audit.py` | — | Docker daemon hardening |
| `test_ports.py` | — | Port classification |
| `test_exposure.py` | — | Port exposure analysis |
| `test_scoring.py` | — | Scoring engine |
| `test_domain_scores.py` | — | Domain scores |
| `test_explain.py` | — | --explain TUI |
| `test_display_explain_hint.py` | — | CIS hint display |
| `test_cli.py` | — | CLI argument parsing |
| `test_exit_codes.py` | — | Exit code logic |
| `test_correlation.py` | — | Signal correlation |
| `test_recurrence.py` | — | Recurring findings |
| `test_compare.py` | — | Diff/baseline |
| `test_history.py` | — | Score history |
| `test_ignore.py` | — | Ignore list |
| `test_fixes.py` | — | --fix / --apply |
| `test_auth_log.py` | — | Auth log analysis |
| `test_ufw_logging.py` | — | UFW logging level |
| `test_log_rotation.py` | — | Log rotation |
| `test_cron.py` | — | Cron scheduling |
| `test_cron_audit.py` | — | Cron job security |
| `test_manage_logs.py` | — | Log management TUI |
| `test_webhook.py` | — | Webhook notifications |
| `test_profiles.py` | — | Audit profiles |
| `test_registry.py` | — | Service registry |
| `test_config.py` | — | Configuration store |
| `test_sysinfo.py` | — | System information |
| `test_network_context.py` | — | Network context |
| `test_degraded.py` | — | Degraded mode (ss/rules/log absent) |
| `test_output.py` | — | Terminal output |
| `test_markdown_output.py` | — | Markdown output |
| `test_html_output.py` | — | HTML output |
| `test_csv_output.py` | — | CSV output |
| `test_report.py` | — | Report generation |
| `test_min_level.py` | — | --min-level filter |
| `test_watch.py` | — | --watch mode |
| `test_check_rules.py` | — | Rule validation |
| `test_file_perms.py` | — | File permissions |
| `test_suid_audit.py` | — | SUID/SGID audit |
| `test_user_accounts.py` | — | User accounts |
| `test_password_policy.py` | — | Password policy |
| `test_umask.py` | — | System umask |
| `test_updates.py` | — | System updates |
| `test_ntp.py` | — | NTP sync |
| `test_fail2ban.py` | — | Fail2ban |
| `test_rootkit.py` | — | Rootkit scan |
| `test_auditd.py` | — | Audit daemon |
| `test_secure_boot.py` | — | Secure Boot |
| `test_file_integrity.py` | — | File integrity |
| `test_clamav.py` | — | ClamAV |
| `test_mac_policy.py` | — | AppArmor/SELinux |
| `test_backup.py` | — | Backup detection |
| `test_disk.py` | — | Disk health |
| `test_memory.py` | — | Memory/swap |
| `test_ssl_certs.py` | — | TLS cert expiry |
| `test_systemd_timers.py` | — | Systemd timers |
| `test_desktop_apps.py` | — | Desktop apps |
| `test_samba.py` | — | Samba hardening |
| `test_ddns.py` | — | DDNS detection |
| `test_firmware.py` | — | Firmware/microcode |
| `test_smtp.py` | — | SMTP exposure |
| `test_ipv6.py` | — | IPv6 consistency |
| `test_virtualization.py` | — | Virtualization detection |
| `test_email_store_mgmt.py` | — | Email store management |
| `test_recurrence.py` | — | Recurrence tracking |
| `tests/helpers.py` | — | Shared test utilities |

---


**Test VM:** Linux Mint 22.3 — `so6minttest`
**Reference state** (clean baseline after each test):

```bash
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80
sudo ufw enable
```

---

## Category A — Open-any wildcards

Rules that open all ports to all sources — highest severity.

### A1 — Full wildcard `Anywhere ALLOW IN Anywhere`

```bash
sudo ufw allow from any
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Rule allowing all incoming connections without port restriction | ✔ v0.1.0.0 |
| `-2` score deduction | ✔ |
| Fix proposed: `sudo ufw --force delete N` | ✔ |
| Fix applied correctly | ✔ v0.1.0 |
| **IPv6 rule also detected and fixed** (`Anywhere (v6) ALLOW IN Anywhere (v6)`) | ✔ v0.1.0 |

**Root cause fixed :** `ufw status numbered` pads lines with trailing spaces — the `$` anchor in the regex never matched. Fixed: `Anywhere$` → `Anywhere\s*$`. (commit `8ccd9b6`)

**Root cause fixed :** IPv6 wildcard rules (`Anywhere (v6) ALLOW IN Anywhere (v6)`) escaped detection — `open_any_pattern` did not account for the `(v6)` suffix. Fixed: pattern extended with `(?:\s+\(v6\))?` on both sides. Both IPv4 and IPv6 rules are now flagged and fixed independently.

---

### A2 — TCP wildcard `Anywhere/tcp ALLOW IN Anywhere/tcp`

```bash
sudo ufw allow proto tcp from any to any
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Rule allowing all incoming connections without port restriction | ✔ v0.1.0 |
| `-2` score deduction | ✔ v0.1.0 |
| Fix applied correctly | ✔ v0.1.0 |
| **IPv6 variant also detected** (`Anywhere/tcp (v6) ALLOW IN Anywhere/tcp (v6)`) | ✔ v0.1.0 |

**Root cause fixed :** Pattern extended to `Anywhere(?:/\w+)?` on both sides to cover `/tcp`, `/udp` variants. (commit `1dd9ede`)

**v0.1.0:** Same IPv6 fix as A1 applies here.

---

### A3 — UDP wildcard `Anywhere/udp ALLOW IN Anywhere/udp`

```bash
sudo ufw allow proto udp from any to any
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Rule allowing all incoming connections without port restriction | ✔ v0.1.0 |
| `-2` score deduction | ✔ v0.1.0 |
| Fix applied correctly | ✔ v0.1.0 |
| **IPv6 variant also detected** | ✔ v0.1.0 |

---

### A4 — All three wildcards simultaneously

```bash
sudo ufw allow from any
sudo ufw allow proto tcp from any to any
sudo ufw allow proto udp from any to any
```

| Expected | Result |
|----------|--------|
| 3 distinct `✖ [ALERT]` findings (IPv4 only, IPV6=no) | ✔ v0.1.0 |
| 6 distinct `✖ [ALERT]` findings (IPv4 + IPv6, IPV6=yes) | ✔ v0.1.0 |
| Score: 1/10 (IPV6=no), Risk level: CRITICAL | ✔ v0.1.0 |
| 6 fixes proposed and applied in reverse index order (avoids renumbering) | ✔ v0.1.0 |

---

### A5 — False positive: source-restricted rule

```bash
sudo ufw allow from 192.168.1.0/24
```

| Expected | Result |
|----------|--------|
| `✔ [OK]` No 'allow from any' rule without port restriction detected | ✔ v0.1.0 |
| Source-restricted rule is NOT flagged as open-any | ✔ |

> `ufw status numbered` shows `Anywhere ALLOW IN 192.168.1.0/24` — destination is `Anywhere` but source is restricted. Pattern correctly requires BOTH sides to be `Anywhere` to flag.

---

## Category B — Duplicate rules

### B1 — Exact duplicate

```bash
sudo ufw allow 80/tcp
sudo ufw allow 80/tcp   # UFW says: "Skipping adding existing rule"
```

| Expected | Result |
|----------|--------|
| UFW natively prevents true exact duplicates | ✔ confirmed |
| Not testable via CLI — would require direct file manipulation | noted |

> **Note:** Exact duplicates can only arise from direct `/etc/ufw/` file editing or external tools (Ansible, scripts). UFW's CLI prevents them.

---

### B2 — Same rule, different comments

```bash
sudo ufw allow 80/tcp comment "test2"
# 80 (no proto) already present in baseline
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Duplicate UFW rule detected: `80/tcp ALLOW IN Anywhere` | ✔ v0.1.0 |
| Comment stripped before comparison — `# test2` ignored | ✔ v0.1.0 |
| Redundant `80/tcp` deleted, `80` kept | ✔ v0.1.0 |

**Root cause fixed:** Comparison now uses comment-stripped, whitespace-normalized text. (commit `b7a285a`)

---

### B3 — Semantic duplicate: `PORT/proto` redundant when `PORT` exists

```bash
sudo ufw allow 80/tcp comment "test2"
# 80 (no proto) already present → 80/tcp is redundant
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Duplicate UFW rule detected: `80/tcp ALLOW IN Anywhere` | ✔ v0.1.0 |
| `-1` score deduction | ✔ v0.1.0 |
| Fix deletes the protocol-specific rule, keeps the broader one | ✔ v0.1.0 |

**Root cause fixed:** Two-pass detection — first pass collects all protocol-less rules, second pass checks if `PORT/proto` is a subset of an existing `PORT` rule. (commit `b7a285a`)

---

### B4 — Semantic duplicate: UDP variant

```bash
sudo ufw allow 53/udp
sudo ufw allow 53
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` `53/udp` detected as redundant | ✔ unit test |

> Validated via unit test only (DNS port — not in services registry, no practical risk on the VM).

---

### B5 — No false positive: `PORT/tcp` + `PORT/udp` without `PORT`

```bash
sudo ufw allow 80/tcp
sudo ufw allow 80/udp
# No bare "80" rule
```

| Expected | Result |
|----------|--------|
| `✔ [OK]` No duplicate UFW rules detected | ✔ v0.1.0 |
| `80/tcp` and `80/udp` are complementary — not flagged | ✔ v0.1.0 |

> Also note: when baseline has `80` (bare), adding `80/tcp` + `80/udp` correctly flags BOTH as semantic duplicates of `80`. Verified live.

---

## Category C — Critical services exposed

### C1 — SSH exposed (baseline state)

SSH is always present in the reference state (`ufw allow 22/tcp`). This scenario documents the expected behaviour for a critical service with an unrestricted UFW ALLOW rule.

```bash
# Baseline state — SSH already exposed
sudo bob
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Port 22/tcp — open to internet — no source restriction in UFW | ✔ v0.1.0.0 |
| Risk context CRITICAL displayed | ✔ v0.1.0.0 |
| `-2` score deduction (NAT/local context) | ✔ v0.1.0.0 |
| Panorama: SSH `⚠` (OPEN_WORLD) | ✔ v0.1.0.0 |
| DDNS `→ 22/tcp` | ✔ v0.1.0.0 |
| **Remediation:** source-restrict → switches to OPEN_LOCAL (WARN not ALERT, no deduction) | ✔ v0.1.0.0 |

> **Note:** `openssh-server` must be installed and active (`sudo apt install openssh-server && sudo systemctl enable --now ssh`). If inactive/disabled, the service is INFO-only with no port exposure check.

---

### C3 — Redis exposed on all interfaces (service installed and active)

```bash
sudo ufw allow 6379
# Redis configured to bind 0.0.0.0 (not the default)
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Port 6379/tcp — open to internet (Action required) | ✔ v0.1.0 |
| Risk context CRITICAL displayed | ✔ v0.1.0 |
| `-2` score deduction (NAT context) | ✔ v0.1.0 |
| Panorama: Redis `⚠` | ✔ v0.1.0 |
| DDNS cross-check: `→ 6379/tcp` | ✔ v0.1.0 (`6379/udp` filtered — no UDP listener) |

**Root cause fixed (obs 1):** CRITICAL/HIGH services with `OPEN_WORLD` exposure now raise `alert()` instead of `warn()`, moving them to "Action required". (commit `e01b24b`)

---

### C3b — Redis loopback only — false positive fix 

Default Redis configuration: binds to `127.0.0.1` only, but a permissive UFW rule exists.

```bash
sudo ufw allow 6379
# Redis default: bind 127.0.0.1 (loopback only)
```

| Expected | Result |
|----------|--------|
| `ℹ [INFO]` Port 6379/tcp — bound to localhost only — UFW rule has no effect on external access | ✔ v0.1.0 |
| No ALERT, no score deduction | ✔ v0.1.0 |
| Panorama: Redis `✔` (rule exists, exposure = LOOPBACK) | ✔ v0.1.0 |
| DDNS: `6379/tcp` NOT in exposed ports (loopback only) | ✔ v0.1.0 |
| DDNS: `6379/udp` NOT in exposed ports (no UDP listener) | ✔ v0.1.0 |

**Root cause fixed :** `_classify_exposure()` was UFW-only and did not cross-check actual socket bindings. Fix: `PortsSnapshot` is now collected before CHECK 3; ports where all `ss` bindings are loopback get `Exposure.LOOPBACK` (INFO, no deduction). `_find_open_ports()` in `ddns.py` now also receives the `loopback_ports` and `active_ports` sets. (commits `2bfc85b`, `64311be`)

---

### C2 — MySQL exposed (service not installed)

```bash
sudo ufw allow 3306
```

| Expected | Result |
|----------|--------|
| No service alert (MySQL not installed) | ✔ v0.1.0 |
| Port 3306 open in UFW but unmatched to any installed service | ✔ v0.1.0 |
| DDNS: `3306/tcp` and `3306/udp` NOT in exposed ports (no active listener) | ✔ v0.1.0 |

> **Behaviour updated :** `_find_open_ports()` now cross-checks against actual non-loopback listeners (`active_ports` set from `ss`). Orphan UFW rules (port open, no service running) are excluded from the DDNS exposed ports list. `3306/tcp` and `3306/udp` no longer appear in DDNS findings when MySQL is not installed.

---

### C4 — Nginx exposed (medium-risk service, installed and active)

```bash
sudo apt install nginx
sudo ufw allow 80
sudo bob
```

| Expected | Result |
|----------|--------|
| `⚠ [WARNING]` Port 80/tcp — open to internet — no source restriction in UFW | ✔ v0.1.0.0 |
| Risk context MEDIUM displayed | ✔ v0.1.0.0 |
| `-1` score deduction | ✔ v0.1.0.0 |
| Panorama: Nginx `⚠` | ✔ v0.1.0.0 |
| Finding appears in *Possible improvements* (not *Action required*) | ✔ v0.1.0.0 |

> Medium-risk services (`warn()` not `alert()`) — distinction from critical services like SSH or Redis.

---

### C5 — Samba exposed (critical service, installed and active)

```bash
sudo apt install samba
sudo ufw allow 445
sudo ufw allow 139
sudo bob
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Port 445/tcp — open to internet — no source restriction in UFW | ✔ v0.1.0.0 |
| `✖ [ALERT]` Port 139/tcp — open to internet | ✔ v0.1.0.0 |
| Risk context CRITICAL displayed (ransomware vector, EternalBlue) | ✔ v0.1.0.0 |
| `-2` deduction × 2 ports (−4 total) | ✔ v0.1.0.0 |
| Panorama: Samba `⚠` (OPEN_WORLD) | ✔ v0.1.0.0 |
| Both ports in *Action required* block | ✔ v0.1.0.0 |
| DDNS `→ 445/tcp`, `→ 139/tcp` | ✔ v0.1.0.0 |

> **Cleanup:** `sudo apt remove --purge samba && sudo ufw delete allow 445 && sudo ufw delete allow 139`

---

### C6 — Ports open in UFW, services not installed (multiple services)

For each entry below: open the port in UFW with no matching service installed. Expected behaviour: **no service-level alert**, port may appear as an unmatched open rule.

```bash
sudo ufw allow <PORT>
sudo bob
```

| Service | Port | Expected behaviour | Result |
|---------|------|--------------------|--------|
| VNC Server | 5900/tcp | No service alert — VNC not detected | ✔ v0.1.0.0 |
| FTP Server | 21/tcp | No service alert — FTP not detected | ✔ v0.1.0.0 |
| PostgreSQL | 5432/tcp | No service alert — PostgreSQL not detected | ✔ v0.1.0.0 |
| Mosquitto (MQTT) | 1883/tcp | `ℹ [INFO]` 1883/tcp loopback — UFW rule has no effect; 8883/tcp not listening — no message; Panorama ✔ | ✔ v0.1.0.0 ² |
| WireGuard | 51820/udp | `ℹ [INFO]` WireGuard installed but stopped/disabled — no port exposure check (INACTIVE early return) | ✔ v0.1.0.0 ¹ |
| Gitea | 3000/tcp | No service alert — Gitea not detected | ✔ v0.1.0.0 |
| Jellyfin | 8096/tcp | No service alert — Jellyfin not detected | ✔ v0.1.0.0 |
| Home Assistant | 8123/tcp | No service alert — HASS not detected | ✔ v0.1.0.0 |
| Cockpit | 9090/tcp | No service alert — Cockpit not detected | ✔ v0.1.0.0 |

> For all above: the port should appear in **UFW RULES ANALYSIS** if an active listener exists, but since the service is not installed there is no listener — no ALERT in NETWORK SERVICES ANALYSIS.
> DDNS cross-check: none of these ports should appear in DDNS exposed list (no active listener — v0.1.0).

> ¹ WireGuard was already installed (but inactive) on the test VM. The "not installed" path for WireGuard remains untested — behaviour confirmed: INACTIVE service with an open UFW rule → INFO only, no ALERT, no score deduction.

> ² Mosquitto was installed and ACTIVE on the test VM (not matching the "not installed" C6 scenario). Test revealed a bug: registry ports not actively listening (8883/tcp) incorrectly triggered `Exposure.NO_RULE` → panorama ✖. Fixed in beta (commit `67743ca`): `Exposure.NOT_LISTENING` for non-listening registry ports → panorama ✔.

> **Already validated:** MySQL / MariaDB (3306) → C2

---

### C7 — CUPS exposed (low-risk service, usually pre-installed on desktop Linux)

CUPS (print server) listens on `127.0.0.1:631` by default. This test verifies behaviour when CUPS is active and a UFW rule exists.

```bash
# CUPS is often pre-installed on Linux Mint
sudo ufw allow 631
sudo bob
```

| Expected | Result |
|----------|--------|
| `ℹ [INFO]` Port 631/tcp — bound to localhost only — UFW rule has no effect | ✔ v0.1.0.0 |
| No ALERT, no score deduction (loopback binding) | ✔ v0.1.0.0 |
| Panorama: CUPS `✔` (rule exists, loopback → INFO) | ✔ v0.1.0.0 |

> If CUPS binds to `0.0.0.0`: `⚠ [WARNING]` Port 631/tcp — open to internet (low risk, nature=improvement).

---

## Category D — IPv6 consistency

### D1 — IPv4 rules present, no IPv6 equivalent (warning expected)

```bash
# From baseline: 22/tcp and 80 are present, no (v6) rules
sudo ufw status numbered
```

> **Note:** Some distributions (or VMs with `IPV6=no` in `/etc/default/ufw`) do not add IPv6 rules. If all rules are already paired (IPv4 + IPv6), use `sudo ufw --force reset` and re-add only IPv4 rules:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp   # Do NOT let UFW create (v6) rules — requires IPV6=no
sudo ufw enable
```

| Expected | Result |
|----------|--------|
| `⚠ [WARNING]` IPv6 rules missing — only IPv4 rules present | ✔ v0.1.0 live (IPV6=no VM) |
| `-1` score deduction | ✔ v0.1.0 live |
| Live test | ✔ v0.1.0 |

---

### D2 — IPv4 and IPv6 rules both present (no warning)

```bash
# Baseline with IPV6=yes (default): 22/tcp and 22/tcp (v6) both present
sudo bob
```

| Expected | Result |
|----------|--------|
| `✔ [OK]` IPv4 and IPv6 rules both present | ✔ v0.1.0 live (IPV6=yes, A1 test) |
| No deduction | ✔ v0.1.0 live |
| Live test | ✔ v0.1.0 |

---

## Category E — Loopback-only ports 

### C8 — SSH restricted to LAN (OPEN_LOCAL path)

```bash
sudo ufw delete allow 22/tcp
sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp
sudo bob
```

| Expected | Result |
|----------|--------|
| `⚠ [WARNING]` Port 22/tcp — restricted to local network by UFW rule | ✔ v0.1.0 |
| No score deduction (OPEN_LOCAL ≠ OPEN_WORLD) | ✔ v0.1.0 |
| Panorama: SSH `✔` (LAN restriction = correct config) | ✔ v0.1.0 |
| DDNS: `ℹ` Port 22/tcp restricted to local network (not ALERT) | ✔ v0.1.0 |
| Risk context CRITICAL still displayed | ✔ v0.1.0 |

> **Cleanup:** `sudo ufw delete allow from 192.168.1.0/24 to any port 22 proto tcp && sudo ufw allow 22/tcp`

---



### E1 — Port listening on localhost only, no UFW rule — INFO not ALERT

```bash
# Any process bound exclusively to 127.0.0.1 without a UFW rule
# Example: netcat listening on loopback (or rely on Redis default config)
# Redis default: bind 127.0.0.1 — no UFW rule needed
sudo bob
```

| Expected | Result |
|----------|--------|
| `ℹ [INFO]` Port 6379/tcp — bound to localhost only — no UFW rule needed (covered by default deny) | ✔ v0.1.0.0 |
| No ALERT, no score deduction | ✔ v0.1.0.0 |
| Redis panorama ✔ | ✔ v0.1.0.0 |
| Message uses `services.exposure.loopback_no_rule` locale key (added with `Exposure.LOOPBACK_NO_RULE` fix) | ✔ v0.1.0.0 |

> **Note:** The original expected message referenced `ports.uncovered_local`. In practice, Redis on loopback with no UFW rule is handled by the services check path (`Exposure.LOOPBACK_NO_RULE`), not the ports check. The `ports.uncovered_local` key (`"Port {port} — bound to localhost only — no external exposure"`) applies to the ports section for processes not covered by the service registry.

---

## Additional observations

### Obs — Avahi panorama shows ✖ despite INFO message (v0.1.0)

Avahi binds on `0.0.0.0:5353/udp` (mDNS multicast). No UFW rule exists for 5353 → `Exposure.NO_RULE` → panorama ✖. The service check correctly emits `ℹ [INFO]` "covered by default deny policy", but the panorama symbol is set by the `NO_RULE` enum value regardless of the INFO severity.

**Root cause:** `NO_RULE` on a non-loopback, non-listening-externally port (multicast/LAN-only in practice) is treated identically to `NO_RULE` on a genuinely exposed port. A future fix could introduce `Exposure.NO_RULE_MULTICAST` or a broader mechanism to distinguish locally-scoped `NO_RULE` from truly exposed `NO_RULE`.

**Impact:** cosmetic only — no false ALERT, no score deduction.

---



### Obs — DDNS does not detect protocol-less rules (fixed)

With `80 ALLOW IN Anywhere` (no `/tcp`), the DDNS cross-check previously showed nothing for port 80.

**Root cause fixed:** `_find_open_ports()` now handles bare port rules — adds both `PORT/tcp` and `PORT/udp` to the open ports list. (commit `e01b24b`)

**Validated (v0.1.0):** Bare rule `80 ALLOW` with Nginx listening on `0.0.0.0:80` → DDNS correctly lists `→ 80/tcp` only (`80/udp` filtered — no UDP listener on port 80).

---

### Obs — DDNS false positives: system ports and orphan rules 

```bash
sudo ufw allow 53
sudo ufw allow 3306
sudo ufw allow 6379
# Redis on 127.0.0.1 only, MySQL not installed
```

| Expected | Result |
|----------|--------|
| DDNS: `53/tcp`, `53/udp` NOT listed (system port filter) | ✔ v0.1.0.0 |
| DDNS: `3306/tcp`, `3306/udp` NOT listed (no active listener) | ✔ v0.1.0.0 |
| DDNS: `6379/tcp`, `6379/udp` NOT listed (loopback only / no UDP listener) | ✔ v0.1.0.0 |

**Root cause fixed :** Added `_DDNS_SYSTEM_PORTS` constant (53, 67, 68, 546, 547, 5353) and `active_ports` cross-check in `_find_open_ports()`. Only ports with an actual non-loopback listener in `ss` output are included in the DDNS exposed list. (commit `64311be`)

---

### Obs — UFW allows wildcard rules after specific rules without error

```
Anywhere/tcp    ALLOW IN    Anywhere/tcp
22/tcp          ALLOW IN    Anywhere
```

UFW does not warn that `Anywhere/tcp` makes `22/tcp` redundant. bob correctly flags the wildcard.

---

## B1 note — exact duplicates via file manipulation

To test exact duplicates that UFW's CLI prevents, rules can be injected directly:

```bash
sudo cp /etc/ufw/user.rules /etc/ufw/user.rules.bak
# Manually duplicate a rule line in user.rules
sudo ufw reload
sudo bob
# Cleanup:
sudo cp /etc/ufw/user.rules.bak /etc/ufw/user.rules
sudo ufw reload
```

Not yet tested — low practical priority since UFW CLI prevents this.

---

© 2026 Cédric Clauzel
