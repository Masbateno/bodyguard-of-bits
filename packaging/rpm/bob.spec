%global pypi_name bodyguard-of-bits

Name:           bob
Version:        0.6.1
Release:        1%{?dist}
Summary:        Linux hardening auditor with CIS benchmark mapping
License:        MIT
URL:            https://github.com/Masbateno/bodyguard-of-bits
Source0:        https://github.com/Masbateno/bodyguard-of-bits/archive/v%{version}/%{pypi_name}-%{version}.tar.gz

BuildArch:      noarch

BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
BuildRequires:  python3-pip
BuildRequires:  pyproject-rpm-macros
BuildRequires:  python3-pytest

# Runtime suggestions / soft dependencies
# Note: BOB reads `ufw status`. firewalld is NOT a substitute and is not
# auto-detected. Users on Fedora typically need to install ufw explicitly
# (available in standard repos).
Recommends:     ufw
Recommends:     iproute2
Recommends:     systemd
Suggests:       fail2ban-server
Suggests:       rkhunter
Suggests:       clamav
Suggests:       audit
Suggests:       aide
Suggests:       smartmontools
Suggests:       fwupd
Suggests:       apparmor
Suggests:       apparmor-utils

%description
BOB (Bodyguard Of Bits) audits a Linux system against a curated set of
hardening checks (firewall, SSH, kernel sysctl, services, file permissions,
MAC policy, auditd, …) and reports findings with severity levels.

BOB is audit-only: it does not modify system state without explicit user
confirmation. A --fix mode prompts before each remediation; --offline
disables all outbound network calls for air-gapped environments.

This package ships the core audit pipeline, the CLI, and the optional
curses TUI in one binary. For Debian-style split packaging (bob-core /
bob-tui), see the debian/ folder in the source tree.

# ---------------------------------------------------------------------------
# Build & install
# ---------------------------------------------------------------------------

%prep
%autosetup -n %{pypi_name}-%{version}

%generate_buildrequires
%pyproject_buildrequires

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files bob

# Man pages
install -D -m 0644 man/bob.1         %{buildroot}%{_mandir}/man1/bob.1
install -D -m 0644 man/bob.conf.5    %{buildroot}%{_mandir}/man5/bob.conf.5
install -D -m 0644 man/bob-profile.5 %{buildroot}%{_mandir}/man5/bob-profile.5

# SECURITY.md to the docdir
install -D -m 0644 SECURITY.md       %{buildroot}%{_docdir}/%{name}/SECURITY.md

%check
# Smoke test: BOB imports cleanly and version is correct.
%{python3} -c "import bob; assert bob.__version__ == '%{version}', bob.__version__; print('bob v' + bob.__version__ + ' OK')"
# Full test suite (pyflakes-clean except 1 intentional noqa)
%{python3} -m pytest tests/ -q

# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------

%files -n %{name} -f %{pyproject_files}
%license LICENSE
%doc README.md README_FR.md SECURITY.md SECURITY_FR.md
%doc DOCUMENTS/README_TECH.md DOCUMENTS/README_TECH_FR.md
%{_bindir}/bob
%{_mandir}/man1/bob.1*
%{_mandir}/man5/bob.conf.5*
%{_mandir}/man5/bob-profile.5*

# ---------------------------------------------------------------------------
# Changelog
# ---------------------------------------------------------------------------

%changelog
* Tue May 26 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.6.1-1
- First hardening release on v0.6.x. Deep audit sub-agent
  surfaced 14 findings (0 critical + 6 important + 8 minor);
  6 important + 4 minor shipped.
- Atomic-write contract consolidation: extracted bob/_atomic.py
  as single source of truth; migrated 5 hand-rolled
  implementations + fixed 4 non-atomic sites.
- I-2 EOF contract: safe_input() wrapper + prompt_wizard()
  catches EOFError; 11 bare input() sites migrated.
- I-3: _validate_cron_field step bounds (rejects */200 for
  minute 0-59).
- I-4: shlex.quote() on 8 cmd= sites with user-controlled paths.
- I-5: history.jsonl mode 0o600 on first write.
- I-6: ignore.py atomic write via _atomic helper.
- M-2/M-3/M-6/M-8 minor fixes shipped; M-1/M-4/M-5/M-7 deferred.
- +17 regression tests in tests/test_atomic_v061.py and
  tests/test_cron.py.
- 4583 → 4600 tests.
- JSON contract, EXPLAIN_KEYS, keybindings, exit codes — all
  preserved. Wire output unchanged.
- bob/cron/_io.py::_atomic_write kept as alias for
  backwards-compat with existing test patches.

* Mon May 25 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.6.0-1
- Major bump opening v0.6.x branch. Two architectural splits
  (#13 + #14) deferred from v0.5.x, plus UFW_AUDIT_SHARE
  sunset honored. All contract-preserving via __init__.py
  re-exports.
- #13: bob/checks/ssh.py (1296L) → bob/checks/ssh/ package
  with 4 submodules (_directives 165L, _snapshot 198L,
  _parsers 446L, _subchecks 529L). All v0.5.x public API
  re-exported.
- #14: bob/cron.py (1204L) → bob/cron/ package with 4
  submodules (_parse 330L, _io 164L, _install 319L,
  _manage 445L). All v0.5.x public API re-exported.
- Removed legacy env var UFW_AUDIT_SHARE. Announced "REMOVED
  in v0.6.0" since v0.5.4 — honored. Only BOB_SHARE is now
  accepted by resolve_share_dir().
- Three trivial test-infrastructure updates: test_template_-
  vars_migration / test_domain_scores_mapping_complete use
  rglob instead of glob; TestApplyCronScheduleAtomic patches
  bob.cron._io._atomic_write instead of the package
  re-export.
- 4583 tests inchangés (0 added, 0 removed).
- Largest module post-split is ssh/_subchecks.py at 529L,
  well below the project's soft 1000-LoC ceiling.
- JSON contract, EXPLAIN_KEYS, keybindings, no-curses
  fallback, exit codes — all preserved.
- Closes the deferred architectural roadmap from v0.5.x.

* Mon May 25 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.5.8-1
- Cleanup release — clears the 5 cosmetic minors explicitly
  deferred by v0.5.7 (M-2, M-5, M-6, M-7, M-8). Closes the
  v0.5.x deep-audit campaign: 25 modules deep-audited +
  ~25 spot-checked, 0 critical findings outstanding.
- M-2: manage_logs.py cursor shift after delete now only counts
  deletions <= cursor (pre-fix shifted by total even when most
  deleted items sat after the cursor).
- M-5: schedule wizard constants promoted from local tuple
  unpack to module-level _Schedule(IntEnum) with explicit
  DAILY/WEEKDAYS/MONTHDAYS/CUSTOM names. IntEnum preserves
  `choice == _Schedule.X` semantics so wire-equivalent.
- M-6: _extract_summary_view sentinel None replaces falsy 0
  check (handles unreachable-in-practice SEP62-at-index-0).
- M-7: new _is_finding_continuation(line) helper stops 4-space
  grouping at finding markers and section delimiters
  (defends against over-greedy grouping).
- M-8: `from datetime import datetime` lifted to module-level
  in bob/cron.py and bob/tui/cron.py (3 local imports removed,
  plus 2 redundant local `import os` / `from pathlib import Path`
  dropped from _run_install_cron_plain).
- +12 regression tests (TestScheduleIntEnum,
  TestDatetimeImportLifted, TestCursorShiftAfterDelete,
  TestSummaryStartSentinel, TestIsFindingContinuation).
- 4571 → 4583 tests.
- Single-commit release. JSON contract, EXPLAIN_KEYS,
  keybindings, no-curses fallback, exit codes — all preserved.
- Wire output unchanged.
- 2 new module-level symbols: bob.tui.cron._Schedule and
  bob.manage_logs._is_finding_continuation. No removals.
- v0.6.0 reserved for #13 (ssh.py split) + #14 (cron.py split).

* Sun May 24 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.5.7-1
- Targeted hardening pass on curses TUI: bob/manage_logs.py
  (999 LoC) and bob/tui/cron.py (920 LoC) — the bucket
  deferred by v0.5.5 / v0.5.6 audits. 11 findings: 0 critical,
  3 important (I-1, I-2, I-3), 8 minor (3 shipped + 5 deferred
  to v0.5.8).
- I-1: _curses_readline accepted curses KEY_* keypad codes via
  chr(ch_i), inserting Greek/Unicode glyphs into TUI inputs.
  No security impact (downstream validation) but UX corrupted.
  Fix: new _is_printable_input_char(ch_i) helper bounds inputs
  to printable Latin-1 (32 <= ch_i < 256 and isprintable).
- I-2: three bare input() sites in manage_logs.py did not catch
  EOFError. Ctrl-D dumped a Python traceback. Fix: try/except
  EOFError aligning on the _rl() convention (EOF = empty).
- I-3: apply_cron_schedule() used raw os.open(O_TRUNC) + write
  instead of _atomic_write. Power-loss between truncate and
  write would silently empty the cron file. Fix: switch to
  _atomic_write(path, content, mode=0o640). Mirrors v0.5.5
  #C-1 / #I-1 — atomic-write contract now uniform across the
  codebase.
- M-1: deleted_one status flashed wrong filename under selective
  unlink failures. Now tracks first successfully-deleted name.
- M-3: dead-code elif body in _curses_edit_sub simplified.
- M-4: duplicate `from bob.cron import` consolidated.
- Deferred to v0.5.8: M-2 cursor-shift, M-5 wizard IntEnum,
  M-6 summary_start sentinel, M-7 continuation grouping,
  M-8 local datetime import.
- +11 regression tests across tests/test_cron.py and
  tests/test_manage_logs.py (TestApplyCronScheduleAtomic,
  TestIsPrintableInputChar, TestEOFErrorOnPromptPath,
  TestEOFErrorOnMoveConfirm, TestEOFErrorOnDeleteAllConfirm,
  TestDeletedOneCorrectName).
- 4560 → 4571 tests.
- Single-commit release. JSON contract, EXPLAIN_KEYS,
  keybindings, no-curses fallback, exit codes — all preserved.
- UX-visible deltas only: clean Ctrl-D exit (no traceback),
  function keys no longer leak Greek glyphs into TUI prompts.

* Sun May 24 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.5.6-1
- Targeted hardening pass on bob/checks/logs.py (662 LoC UFW
  log parser) — module deferred by v0.5.5 audit. 10 findings:
  0 critical, 2 important (I-1, I-2), 8 minor (M-1 to M-8).
- I-1: _PRIVATE_IP regex inconsistent with sysinfo.py (missed
  CGNAT 100.64/10 + IPv6 link-local fe80::/10 + false positives
  on fc/fd strings). Now delegates to canonical sysinfo helpers.
- I-2: year-rollover silently dropped near-realtime syslog
  events 1s ahead of wall-clock. Fix: 5-min tolerance +
  snapshot `now` once per parse.
- M-1: anchored [UFW BLOCK6?] matcher catches IPv6 variant.
- M-2: _count_available_days regex restricted to English month
  names.
- M-3: GeoIP DB path order City-before-Country across all dirs.
- M-4: geoip2_status() accepts symlinks like _geo_via_geoip2.
- M-5: _GEO_CACHE bounded at 2048 with FIFO eviction.
- M-6: binary tell()/seek() arithmetic (TextIOBase compliance).
- M-7: dropped redundant subprocess.TimeoutExpired.
- M-8: proto.upper() at parse time prevents bruteforce split.
- +15 regression tests in tests/test_logs.py (4 new classes).
- 4545 → 4560 tests.
- Single-module pass, single commit. JSON contract preserved.

* Sun May 24 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.5.5-1
- Hardening pass — post-v0.5.4 audit by deep sub-agent. 19
  findings: 4 real bugs (C-1 to C-4), 4 security smells
  (I-1 to I-4), 11 minor cleanups (M-1 to M-11).
- C-1: apply_cron_email() silently broke scheduled audits —
  scripts lost 0o755 executable bit via _atomic_write() forcing
  0o600. Fix: _atomic_write() takes explicit mode= now.
- C-2/C-3: password_policy cmds with '&&' or Unicode arrow
  rejected by --fix --apply. Demoted to nature='improvement'.
- C-4: EXPLAIN_KEYS drift for services_state. Fixed via
  EXPLAIN_KEY_ALIASES (preserves JSON output contract).
- I-1: recurrence/ignore state files written with default
  umask (world-readable). Now use os.open(..., 0o600).
- I-2: _apply_deduction bypassed score cap after finalize().
  Added defensive guard with WARNING log.
- I-3: _safe_url XSS in HTML email href attribute context.
  Now uses html.escape(url, quote=True).
- I-4: sysinfo._PRIVATE_IPV4_RE brittle + Python 3.12+ break.
  Replaced by explicit ipaddress.ip_network membership.
- M-1: email regex dedup via bob.config._EMAIL_RE.
- M-2: _NullReport → bob.report.NullReport (canonical).
- M-3: 3 dead locale keys removed.
- M-4: corr.fully_blind widened to fire on fail2ban or
  auditd blindness (was asymmetric).
- M-7: extract _has_actionable_findings() helper in updates.py.
- M-8/M-9: clarifying comments in ssh.py + ports.py.
- M-10: cron regex anchor tighter (skip comment lines).
- M-11: services_state cmd dropped '&&' journalctl chain.
- M-6 (separate commit): Optional[X] → X | None on 18 modules.
- Net diff: 23 code files, +312/-112 = +200 LoC.
- 4538 → 4545 tests (+7 regression coverage).
- JSON contract preserved.

* Thu May 22 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.5.4-1
- Refactor v0.5.x Phase 5 of 5 (final, closes the v0.5.x audit).
  Three audit findings (#6, #9, #15b) + one user-requested metier
  feature (cache APT option C). Two findings deferred to v0.6.0.
- #6: new prompt_wizard() helper in bob/_tty.py + 10 input()
  sites migrated in bob/cron.py (install + edit wizards).
- #9: UFW_AUDIT_SHARE env var DEPRECATED since v0.5.4, REMOVED
  in v0.6.0. logger.info -> logger.warning; docstring updated.
- #15b: _PREFIX_TO_DOMAIN explicit mapping. fail2ban -> ssh,
  virt -> hardening, docker_audit -> hardening. Per-domain score
  reshuffle on affected hosts; global score unchanged.
- Cache APT option C: new INFO updates.apt_cache_age line when
  no security/regular pending and cache below 7-day stale
  threshold. Closes observability gap surfaced by v0.5.3 Ubuntu
  VM terrain test.
- #13/#14 (ssh.py/cron.py splits) deferred to v0.6.0 per
  conservative-refactor principle.
- Net diff: 12 code files, +118 / -69 = +49 lines.
- 4538/4538 tests unchanged. Wire output: 1 new INFO line on
  idle hosts (cache APT C) + per-domain reshuffle on hosts with
  fail2ban/virt/docker_audit findings. Global score unchanged.
- 2 new locale keys (updates.apt_cache_age + detail) in EN+FR.
- JSON contract preserved.

* Thu May 22 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.5.3-1
- Refactor v0.5.x Phase 4 (audit findings #5 + #12 + #8). Three
  pure structural refactors; zero behaviour change.
- #5: new _LevelTraits frozen dataclass + 4-row dispatch dict in
  bob/display.py collapse the 4-branch OK/WARN/ALERT/INFO cascade
  in display_result() to a single declarative loop. The ALERT-only
  path that prints detail without --verbose is now
  detail_unconditional=True. New _emit_finding_body() helper
  consumes the traits.
- #12: print_audit_summary() split into 3 module-level helpers
  (_summary_header_lines, _summary_findings_lines,
  _summary_breakdown_lines) plus _add_finding_lines promoted from
  inner closure to module level. The orchestrator becomes a
  3-line assembler.
- #8: CheckResult.log_data escape hatch removed. The dict|None
  field is replaced by a tuple return from check_logs(...) ->
  (CheckResult, LogReportData | None). New frozen LogReportData
  dataclass in bob/checks/logs.py (log_days, days_available,
  total, brute_hits, top_ips, top_ports, svc_hits).
- Net diff: 5 files, +109 / -69 = +40 lines. display.py +23,
  logs.py +19, runner.py 0, scoring.py -1, tests +3.
- 4538/4538 tests unchanged. Wire output bit-identical to v0.5.2.
- SECURITY.md / SECURITY_FR.md: 0.5.x "current", 0.4.x EOL.
- #13 / #14 / #15b still deferred to Phase 5 (v0.5.4).
- JSON contract preserved.

* Thu May 22 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.5.2-1
- Refactor v0.5.x Phase 3 (audit findings #4 + #3).
- #4: new _BadDirective dataclass + _BAD_DIRECTIVES table + helper
  in bob/checks/ssh.py. Migrates 8 uniform sshd_config directives
  (PermitEmptyPasswords, X11Forwarding, IgnoreRhosts,
  HostbasedAuthentication, PermitUserEnvironment, StrictModes,
  AllowTcpForwarding, PubkeyAuthentication) from a cascade of
  if-blocks to a declarative table + loop. _check_sshd_config
  body: ~180 → ~50 LoC.
- Two predicate styles: bad_values tuple (most) and safe_values
  tuple (AllowTcpForwarding). __post_init__ catches malformed
  entries at module load.
- Sites kept imperative (don't fit): PermitRootLogin (4-way),
  PasswordAuthentication (ssh_exposed), MaxAuthTries (integer),
  LoginGraceTime, AllowUsers/AllowGroups, Match block, weak
  ciphers/macs/kex.
- #3: runner._sec() extended with keyword-only callbacks
  skip_if= and post_display=. 4 inline blocks migrated (samba,
  docker_audit, desktop_apps, disk). Net runner.py: -29 LoC.
- #13 (ssh.py split) deferred to Phase 5 — ssh.py stays at 1324
  LoC (target <1000 not met).
- Zero behaviour change. 4538/4538 tests unchanged. Wire output
  bit-identical to v0.5.1. JSON contract preserved.

* Thu May 21 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.5.1-1
- Refactor v0.5.x Phase 2 — big LoC win (audit finding #1).
- New CheckResult.warn_with_deduction() + .alert_with_deduction()
  helpers in bob/scoring.py collapse the paired
  result.warn() + result.add_deduction() idiom.
- 120 sites migrated across 27 files. Largest: ssh.py (24 sites,
  -146 lines), hardening.py (8), samba.py (6), mac_policy.py (6),
  clamav.py (5), disk.py (5), iptables_nftables.py (5),
  firewall.py (4), firewall_stack.py (4).
- 13 sites intentionally not migrated (capped deductions, level
  branching, conditional points, divergent template_vars).
- reason= override handles _reason-suffix translation key cases
  (e.g. ssh.host_key_dsa_reason vs ssh.host_key_dsa).
- Net diff: 37 files changed, +483 / -1002 = -519 lines.
- Zero behaviour change. Tests stay at 4538/4538. Wire output
  bit-identical to v0.5.0.
- 6 migration waves with full pytest between each.
- JSON schema_version="1", 7 score domains, 116 EXPLAIN_KEYS,
  34 filterable sections, CLI surface — all preserved.

* Thu May 21 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.5.0-1
- Refactor v0.5.x Phase 1 (opens v0.5.x branch) — 6 audit findings
  + cron coverage pass + 1 latent bug surfaced by the new tests.
  Audit pipeline behaviour unchanged: schema_version="1", 7 score
  domains, 116 EXPLAIN_KEYS, 34 filterable sections preserved.
- #7: new is_unit_active() / is_unit_enabled() helpers in
  bob.checks._run; migrates the repeated
  `_run("systemctl", "is-active", X)` idiom at 9 sites. Defensive
  .lower() promoted centrally.
- #2: new bob.output.print_titled_box() — 4 sites migrated
  (cron.py x3, manage_logs.py x1). Closes --no-color leak.
- #10: new bob.report.Report typing.Protocol (PEP 544) capturing
  AuditReport/NullReport/MarkdownReport shared contract.
- #11: new emit_section() + emit_group() closures in runner.py;
  20 sites migrated (5 group + 15 section headers). Net -28 lines.
- #15a: new tests/test_domain_scores_mapping_complete.py (+4 tests).
  AST scan asserts every emitted key prefix is mapped or whitelisted
  with justification — guards _PREFIX_TO_DOMAIN catch-all from
  silent drift.
- Cron coverage pass (Phase 5 preliminary): +35 tests across 5 new
  classes (TestValidateCronField, TestValidateCustomCron,
  TestBuildScriptContent, TestApplyCronSchedule, TestApplyCronEmail
  — incl. legacy NOTIFY_EMAIL= regex parity).
- Latent bug fixed (surfaced by new cron tests):
  apply_cron_schedule() referenced _os.open / _os.fdopen / _os.O_*
  — _os is only locally aliased in three OTHER functions in cron.py,
  never at module level. The v0.4.8 cron-dedup extraction missed
  the rename. The helper had been silently dead since v0.4.8 ship.
  Fix: _os -> os.
- 4499 -> 4538 tests (+39: +4 mapping, +35 cron).

* Thu May 21 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.4.8-1
- Code-hardening release — sub-agent code-review pass 4 (4 important
  + 5 minor + 3 suggestion findings) plus deep pyproject.toml audit
  (6 packaging hardening fixes). No audit pipeline behaviour change.
- I4 (important): bob.report.Reporter + bob.manage_logs call
  chown_to_sudo_user() on file/directory creation. When bob is run
  via sudo, report file and log directory tree are now owned by the
  invoking user instead of root.
- I1-I3 + M4-M5 (important + minor): dead dataclass fields removed
  (ssh.config_source_files, firewall.ipv4_rules_count and
  ipv6_rules_count, samba.min_protocol, clamav.db_path and
  last_scan_log_path, secure_boot.method). Constructor args + parser
  intermediates dropped accordingly.
- M1 (minor): _C_LOCALE_ENV added to 3 remaining subprocess.check_output
  sites in checks/desktop_apps.py and checks/smtp.py for codebase
  consistency.
- M3 (minor): log_rotation._service_active replaced with shared
  _run() helper. 12 lines -> 1 line, same behaviour.
- M2 + S2 (minor + suggestion): cron-entry mutation logic extracted
  to public bob.cron.apply_cron_schedule() and apply_cron_email();
  TUI cron uses them instead of duplicating logic. Legacy
  NOTIFY_EMAILS regex preserved.
- S1 (suggestion): docstring on checks/auth_log.py explaining the
  90-day window vs --log-days flag.
- S3 (suggestion): bob.output.SCORE_BAR_WIDTH promoted to public
  constant; bob.breakdown + bob.domain_scores import it instead of
  duplicating the literal 10.
- pyproject.toml hardening: setuptools>=77 minimum (PEP 639), wheel
  dropped from build-system.requires, authors/maintainers
  canonicalised, Production/Stable classifier, explicit empty
  dependencies = [], geoip2 moved to optional-dependencies,
  packages.find restricted to bob/bob.checks/bob.tui.
- 4499 tests (was 4500): one test removed
  (test_secure_boot::test_default_method_is_none) after the dead
  method field was deleted.

* Thu May 21 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.4.7-1
- Maintenance release — documentation audit + UI cosmetic + bash
  completion overhaul + CI release automation. No audit pipeline
  behavior change.
- Cross-doc audit: 24 corrections across 8 files (README, README_FR,
  README_TECH + FR, README_DEV + FR, SECURITY_FR, man/bob.1,
  man/bob-profile.5, AUTOMATION + FR). Rectifies stale "9 domains"
  (now 7 score domains), fictional "docker" profile (real is
  "container"), --list-checks / --list-profiles / --min-level=info /
  --format=text flags documented but rejected at CLI, webhook
  payload structure / timeout / send condition wrong.
- DOCUMENTS/SNAPSHOT.md added (~640 lines, internal cartography
  for refactor prep and sub-agent briefing; 20 correction passes
  against the actual code state; not shipped in %doc).
- UI: gauge bars in --watch, --breakdown, per-domain scores, and
  --manage-logs history now share a coloured rendering via
  bob.output.score_bar() — green (>=8), yellow (5-7), red (0-4),
  matching the existing display._disk_bar style. --no-color
  continues to neutralise the colours.
- bob/data/bob.bash-completion comprehensive overhaul. Critical fix
  for --check=/--skip=/--format=/etc. value completion silently
  failing due to COMP_WORDBREAKS '=' split (now uses bash-completion
  positional-arg convention $2/$3). Function renamed _ufw_audit ->
  _bob, dead code removed (install.sh completion), section list
  matches `bob --check=list` exactly, long-options list achieves
  parity with cli.py (added --check=, --skip=, --output-dir=,
  --breakdown, --no-colour; short -B added).
- CI: publish.yml gains 4th job that auto-creates the GitHub
  Release after PyPI publish succeeds (extracts title from
  CHANGELOG.md, body from DOCUMENTS/CHANGELOG_FULL.md, attaches
  wheel + sdist as assets). Removes manual `gh release create`
  step.
- 4500 tests (unchanged). 3 tests in test_breakdown adapted to
  strip ANSI codes before comparing visible bar content.

* Sun May 17 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.4.6-1
- Terrain test pass v0.4.5 fixes:
  * Bug 1: dpkg-query in kernel_modules.py now filters on 'ii' state
    so kernels left in 'rc' state by `apt remove` are no longer
    reported as installed.
  * Bug 2: active_domains_from_engine now includes OK findings so
    a domain that goes clean after remediation stays at 10/10 in
    the global average instead of disappearing.
- 4500 tests (+11).
- Adds multi-distro integration CI workflow (validates BOB on
  Debian 12/13, Ubuntu 22/24/25, Kali Rolling, Fedora 41).

* Sun May 17 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.4.5-1
- Test infrastructure hardening: tests/test_locale_coverage.py
  switched from regex scanning to AST parsing (ast.walk + ast.Call
  + ast.Name). Eliminates docstring false positives, multi-line
  call site fragility, and obj._t(...) attribute call edge cases.
- 4489 tests (unchanged).

* Sat May 16 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.4.4-1
- Cross-distro terrain hardening: critical updates.py bug fixed
  (reported "up to date" on 100% of vierge Debian-family VMs with
  pending updates including 21 Ubuntu LTS security patches).
  Now uses `apt-get -s dist-upgrade`, detects stale apt cache,
  cross-checks via `apt list --upgradable`.
- AppArmor 0-profile dedicated key; SMART skip on all-virtual disks;
  DDNS ports inlined in WARN message.
- 4489 tests (+21).

* Fri May 15 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.4.3-1
- Doc catch-up + post-audit hardening pass.
- 4 firewall explanation keys promoted to EXPLAIN_KEYS.
- Critical: --json-full crash on HardeningSnapshot fixed (5 dead
  attribute references removed).
- Important fixes: strptime locale independence (ssl_certs, logs),
  _is_covered_by_ufw IP false-positive killed, cron range validator
  rejects out-of-bounds values, email markdown not escaped to HTML.
- 4468 tests (+16).

* Thu May 14 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.4.2-1
- Initial Fedora packaging (Phase 3 of the distro-ready roadmap).
- Ships man pages bob(1), bob.conf(5), bob-profile(5).
- Ships SECURITY.md threat model.
