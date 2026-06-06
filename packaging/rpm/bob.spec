%global pypi_name bodyguard-of-bits

Name:           bob
Version:        0.8.3
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
* Sat Jun 06 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.8.3-1
- HOTFIX: v0.8.2 audit path crashed with UnboundLocalError on every
  non --test-webhook invocation. Root cause: the v0.8.2 --test-webhook
  handler did `from bob.config import UserConfig` inside main(), which
  shadowed the module-level binding for the entire function. Line 298
  (audit path) raised `UnboundLocalError: cannot access local variable
  'UserConfig'` on every regular `bob` invocation. Same shadowing
  pattern existed for `os` and `traceback` inside the top-level except
  handler.
- Fix: removed the redundant local imports of UserConfig + os; promoted
  `traceback` to a module-scope import.
- Regression guard: tests/test_v083_main_scope_guard.py (2 tests)
  statically asserts main() does not shadow any name imported at module
  scope.
- v0.8.2 broken on PyPI; users should upgrade to v0.8.3 immediately.
- Tests 6244 → 6246 (+2 guard). 0 regression.

* Sat Jun 06 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.8.2-1
- Conservative-bundle patch — 6 user-facing + DX items, no BREAKING.
- Bash completion v0.8.2 (sync _SECTIONS + _EXPLAIN_KEYS + add
  --unignore=KEY / --ignore=KEY / --explain KEY completions + 21
  sync-guard + functional tests).
- i18n consolidation: bob/_i18n_safe.py module exposes
  make_fallback_t(labels) + t_or_hardcoded(key, fallback). Replaces 4
  hand-rolled _fallback_t bodies + 1 _t_or_hardcoded across
  config/webhook/markdown_output/html_output/__main__. Single source of
  truth, consistent format-or-keep-template semantics.
- --test-webhook smoke command: POST a tagged minimal payload to the
  configured webhook URL and exit. Reuses every URL-validation guard
  from send_webhook. 4 new locale keys EN+FR.
- --check=list section descriptions: 44 sections × 2 langues = 88
  one-line technical descriptions sourced from
  sections.descriptions.<name>.
- D-3 EXPLAIN_KEY_ALIASES deprecation warning: one-shot logger.warning
  on alias resolution pointing at the canonical name + v0.9.0 retrait
  timeline. Logger-only so machine-readable outputs aren't polluted.
- scripts/lint_locales.py: dev tool catching strict EN/FR key parity,
  placeholder-set parity, trailing-whitespace contract (I-2 pass 7),
  empty/long value sanity.
- Tests: 6198 → 6244 (+46 net). 0 regression. v0.6.x and v0.7.x
  remain EOL.

* Fri Jun 05 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.8.1-1
- Minor maintenance + deep-hardening audit cycle. Closes 26 gap
  tiers across 3 sub-agent audit passes (passes 6-8) + an initial
  drift / framing / silent-feature-gap sweep (T6/T10/T11/T26/T27/
  T31/T32/T39/T57/T60/T74 + workstation alias retrait).
- T6 — profile severity coverage audit (desktop +24 overrides,
  workstation +28 overrides, 30% coverage of actionable warn/alert
  keys). T10 — i18n exceptions in webhook/config/__main__ (14 new
  locale keys EN+FR + fallback dict pattern from v0.7.2 M-4).
- **workstation alias retrait — BREAKING.** The v0.1.0 alias that
  silently redirected `bob -p workstation` to the desktop profile
  has been retired so workstation.conf is now a first-class
  business-context profile (backup / auditd / mac_policy at WARN
  while relaxing personal-use ergonomics). Users on the alias see
  different severity output for those 3 finding families. Migration:
  drop a copy of desktop.conf at ~/.config/bob/profiles/
  workstation.conf to restore v0.8.0 semantics.
- T11 — Finding.detail field parity across CSV + JSON v1/v2
  (additive, no schema break). T26 — explain dispatch for
  services.exposed.<id> via existing service_risk.* locale content
  (38 services auto-explainable, zero per-service maintenance).
  T27 — webhook payload detail + note parity (generic + Slack).
  T31/T37 — nature backfill on 90 warn/alert sites so
  `bob --fix --apply` actually picks up the actionable findings
  (filtered by f.nature == "action"). T32 — profile typo validation
  with logger.warning on unknown override keys. T39 — orphan
  service_risk.ollama_llm_server cleanup. T57 — --unignore CLI
  path + remove_ignore_key helper + 2 locale keys. T60 —
  _t_or_hardcoded helper wires cli.error.* prefixes through main()
  catch-all. T74 — webhook URL credential redaction
  (redact_url_credentials strips user:pass@ before display).
- Audit pass 6 (5 findings shipped). I-1 ignore.yml comment
  preservation in remove_ignore_key. M-1 T32 regex accepts digit-
  containing keys + file_perms.* permissive prefix. M-2 services.
  exposure canonical Exposure-enum set + bogus svc_id rejection.
  M-3 service_label_to_subkey transform consolidated in registry.py
  (single source of truth across explain.py + 2 display.py sites).
  M-4 --unignore documented in man/bob.1 + mutual-exclusion guard
  with --ignore.
- Audit pass 7 (3 findings shipped). I-1 remove_ignore_key regex
  match loader grammar (multi-space, tab now removable). I-2 FR
  colon typography drift on T10/T60 error prefixes — colon-space
  now embedded in locale values (FR "Erreur : ", EN "Error: ") so
  no more double-colon mixed style. M-1 man/bob.1 --show-ignored
  description rewrite to match actual behaviour.
- Audit pass 8 (5 findings shipped). I-1 _KEY_LINE_RE unified — drop
  \s*$ anchor so loader sees inline-commented entries; pass 7 sibling
  regex was dead code masked by defensive load_ignore_keys guard.
  I-2 runner.py 3 hardcoded Warning: prefix sites i18n'd via
  cli.error.warning_prefix + cli.runner.* (6 new locale keys EN+FR).
  M-1 --webhook-secret phantom removed from _VALUE_TAKING_OPTS.
  M-2 _ufw_inactive variants narrowed to (no_rule, loopback_no_rule).
  M-3 t() trailing-whitespace contract test pin (defends I-2 pass 7
  against future locale-normaliser scripts).
- Plus: tests/conftest.py autouse `_ensure_i18n_initialised_for_tests`
  mirrors production invariant (i18n.init before runner.py) in test
  environment, with opt-out for test_i18n.py.
- Tests: 5521 → **6198** (+677 net). 0 regression. ~190 dedicated
  v0.8.1 tests across test_t10_exception_i18n / test_t11_t26_v081 /
  test_t27_t31_t32_v081 / test_t39_t57_t60_v081 / test_t74_v081 /
  test_v081_audit_fixes / test_v081_audit_pass7 / test_v081_audit_pass8.
  v0.6.x remains EOL. Upgrade: `pipx upgrade bodyguard-of-bits`.

* Thu Jun 04 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.8.0-1
- Minor major — drift batch + framing actions + silent-feature-gap
  audit pass. Closes the v0.7.x cycle (4 hardening patches
  v0.7.1-v0.7.4) and opens v0.8.x.
- Drift batch (11 items, anti-drift). CHANGELOG_FR + CHANGELOG_FULL_FR
  backfill of v0.7.0-v0.7.4 (5 entries previously missing). Man pages
  ".TH" lines bumped (bob.1 / bob.conf.5 / bob-profile.5) to current
  version + date. README_TECH{,_FR}.md shields.io version badge
  bumped (was stuck at v0.7.4). debian/changelog backfilled with all
  v0.7.x entries + v0.6.x history. RPM %changelog mirrors. TESTING.md
  per-version table backfilled. README.md + README_FR.md Install
  section synced with the 4-substep README_TECH.md flow (Prereq /
  Install / Enable sudo + bash completion / Uninstall) — was diverging
  since v0.4.x.
- Framing actions (anti-sur-claim). A1: summary box "Hypotheses:
  profile=X | context=Y | posture=Z" header line (display.py) — pure
  UI, conditioned score visible alongside the verdict. A2: new "What
  BOB is / is NOT" section in README{,_FR} + SECURITY{,_FR} — BOB
  audits configuration hardening, is NOT a threat-modeling engine
  / active reachability scanner. Both shipped per
  project-audit-framing-actions Tier 1 recommendation.
- Silent feature-gap audit (8 tiers, post-drift sweep). Tier 1
  (+51 explain entries for previously-uncovered WARN/ALERT findings —
  ouvre 15 new EXPLAIN prefixes; baseline 117 keys / 30 prefixes →
  168 keys / 45 prefixes). Tier 1bis (+8 SSH directives gain
  cmd_template field; PermitEmptyPasswords / X11Forwarding /
  IgnoreRhosts / HostbasedAuthentication / PermitUserEnvironment /
  StrictModes / AllowTcpForwarding / PubkeyAuthentication now suggest
  cmd= via bob --fix --apply instead of "manual fix required").
  Tier 2 (services.json 32 → 38: Tailscale / Caddy / AdGuard Home /
  Vaultwarden / Ollama / Authelia). Tier 3
  (warn_with_deduction backfill: services.state.installed_inactive_critical
  +1pt, services.state.active_disabled +1pt, firewall.policy_unknown
  +2pts, virt.snap_network capped 2pts cumulative). Tier 4
  (5 service_risk locales backfill: SMTP / NFS / Jenkins / OpenVPN /
  Squid — IDs in services.json but zero service_risk.{level,exposure,
  threat} entries). Tier 7 (profiles/{desktop,workstation}.conf
  rename hardening.auto_updates_missing → updates.unattended_not_configured
  — pre-fix the override didn't match the actually-emitted key).
  Tier 9 (Markdown + HTML format parity for Finding.detail and
  Finding.note — were terminal+JSON+text only, missing from
  Markdown/HTML).
- New test guards (4 files). test_runner.py (smoke on _sec()
  orchestrator). test_explain_coverage.py (each actionable key has
  an explain entry). test_fix_coverage.py (each actionable finding
  has cmd= OR is in _MANUAL_BY_DESIGN whitelist with inline rationale
  OR _HELPER_DISPATCH_SITES for non-literal keys). 5th CI guard
  test_doc_version_consistency.py (man + shields + debian top + rpm
  Version + 4 CHANGELOG top entries vs pyproject.toml).
- Orphan __version__ "1.14.0" removed from bob/checks/__init__.py
  (copy-paste from v0.1.0, unused). BOB_DEBUG env var documented in
  SECURITY.md trap-door inventory.
- Deferred to v0.8.1: Tier 6 (profile severity coverage audit —
  94% findings use default severity, ~20-30 keys candidates for
  profile overrides), Tier 10 (i18n 27 hardcoded English exception
  messages in webhook.py + config.py). D-1..D-4 contract
  (sections renumbering / fusion _ALL_SECTIONS+_ALWAYS_ON_SECTIONS /
  EXPLAIN_KEY_ALIASES retraits / sub-checks granulaires) remains
  open for v0.8.x continuation.
- Tests: 5521 → ~6008 (+487 net). 0 regression. Upgrade:
  `pipx upgrade bodyguard-of-bits`.
- v0.6.x remains EOL (declared in v0.7.2).

* Tue Jun 02 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.7.4-1
- Fourth v0.7.x hardening patch — second deep-audit pass after
  v0.7.3. Bundle-aggressive (6 important + 8 minor shipped,
  zero defer this cycle).
- I-1 --quiet output leaks: Docker exposed_ports,
  display_geoip_notice, display_ports_overview,
  display_log_results all printed regardless of -q. Contract
  break. All four sites now honour config.quiet.
- I-2 --explain UI labels i18n (WHY/HOW/SCORING/curses
  picker/detail headers/picker footer/list header/unknown-key
  error). 18 new explain.ui.* locale keys EN+FR.
- I-3 __main__ CLI flows i18n: --check=list / --ignore=KEY /
  --reset-baseline / --diff no-baseline. New cli.list.* /
  cli.ignore.* / cli.baseline.* + compare.no_baseline_yet.
- I-4 webhook scheme symmetry: config.py::set_webhook_url
  now case-insensitive — mirrors v0.7.3 I-5 on
  webhook.py::send_webhook. Silent persist-fail on
  `bob --webhook HTTPS://...` closed.
- I-5 services.py _PRIVATE_ADDR retired — delegates to
  sysinfo._is_private_or_loopback_ipv4/_ipv6 (restores
  v0.5.6 single-source-of-truth invariant).
- I-6 CSV `risk` aligned to JSON v1 (BREAKING wire format):
  engine.effective_level → engine.level (score-only). Migrate
  to JSON v2 posture_escalation.score_level for the
  posture-escalated value.
- M-1 recurrence.py dead .tmp cleanup removed (random tmp
  names since v0.7.2 M-7).
- M-2 CLI value-missing UX: `bob -l` → "-l requires a value"
  instead of "Unknown option". New _VALUE_TAKING_OPTS
  frozenset. -e/--explain and --watch intentionally absent
  (no-arg forms documented).
- M-3 cron wrapper PYTHONPATH trailing-colon footgun:
  `path${PYTHONPATH:+:$PYTHONPATH}` instead of
  `path:"$PYTHONPATH"`.
- M-4 _sandbox.py + plugin_checks.py: 9 WARN paths gain
  stable key="plugin.sandbox.<reason>" + optional i18n via
  threaded t. 9 new plugin.sandbox.* locale keys.
- M-5 report.py::write_header accepts labels= dict (v0.7.3
  M-5 pattern). 4 new banner.* keys.
- M-6 fixes.py "(unsafe shell syntax in command)" → new
  fixes.skipped_unsafe_shell key.
- M-7 json_output uses engine.domain_scores cache instead
  of re-running compute_domain_scores().
- M-8 set_posture_from_engine rejects bool subclass-of-int
  (isinstance(True, int) is True).
- Tests: 5502 → 5521 (+19 net), 0 regression.
- v0.6.x remains EOL (declared in v0.7.2).

* Tue Jun 02 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.7.3-1
- Third v0.7.x hardening patch — full deep-audit pass
  (sub-agent + 14 fixes + 5 justified skips).
- I-1 FR locale "finding" → "découverte".
- I-2 completion.py SUDO_USER not validated (KeyError on
  malformed value). Guarded via regex + try/except.
- I-3 CSV column `section` → `nature` (BREAKING wire format).
- I-4 manage_logs.py 3 bare input() → safe_input() (lines
  365/388 migrated; 104 kept for readline integration).
- I-5 webhook URL scheme case-insensitive (RFC 3986).
- I-6 markdown/html level guard idiom convergence.
- M-2 --lang VALUE space-separated form accepted.
- M-3 `bob -e ""` empty key rejected at parse.
- M-4 argv hardening on -w / --ignore / --output-dir.
- M-5 report.py field labels i18n (OK/Warning/Alert/Score/
  Risk/Context). New report.field_* keys.
- M-6 _inline_format double-escape URL chars fix.
- M-10 set_posture_from_engine helper extract.
- M-11 send_html_email CRLF stripping defensive.
- M-12 html_output risk label translated (FR badges).
- Tests: 5490 → 5502 (+12 net), 0 regression.

* Mon Jun 01 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.7.2-1
- Second v0.7.x hardening patch — closes the 6 minors
  deferred by v0.7.1 + formalises v0.6.x EOL.
- M-4 i18n extraction on Markdown / HTML exports (24+22 new
  locale keys with t=None English fallback).
- M-6 sysinfo accepts IPv6 public IP (ipaddress.ip_address()
  replaces IPv4-only regex).
- M-7 _atomic.py tmp-file collision under concurrent writers
  (tempfile.mkstemp).
- M-8 SCHEMA_*_KEYS wired as enforced invariants.
- M-9 --json-full --json-v1 help text.
- M-10 display.py posture-detection paths deduped
  (_compute_posture_annotation helper).
- v0.6.x officially declared EOL in SECURITY.md +
  SECURITY_FR.md.
- Tests: 5479 → 5490 (+11 net), 0 regression.

* Mon Jun 01 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.7.1-1
- First v0.7.x hardening patch — same-day follow-up to
  v0.7.0 final. 4 important + 3 minor shipped.
- I-1 watch-mode contract drift: bob --watch created a fresh
  ScoreEngine() per iteration but never called set_posture()
  and never set ignore_keys.
- I-2 MarkdownReport.write_summary signature drift
  (posture_annotation kwarg added to Protocol + impl).
- I-3 JSON v1 `risk` field wire-format break — v0.7.0
  silently shifted from engine.level to
  engine.effective_level. Reverted to preserve v0.6.x
  layout contract.
- I-5 webhook plaintext URL accepted — http:// now rejected
  by default; opt-out via BOB_WEBHOOK_ALLOW_INSECURE=1.
- M-1 unused `from typing import Any` removed.
- M-2 _atomic.py: explicit fsync(fd) before close +
  fsync(dir_fd) after rename.
- M-5 --ignore=KEY validates against canonical EXPLAIN_KEYS
  pattern before write.
- Tests: 5466 → 5479 (+13 net), 0 regression.

* Mon Jun 01 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.7.0-1
- Major bump — opens the v0.7.x stable branch. Rolls up
  b1+b2+b3+b4 beta cycle with three thematic phases.
- Phase 1 (T1 Foundation): Python 3.14 added to CI matrix;
  new ScoreEngine.set_posture() + effective_level property +
  posture_escalation block computing
  max(score_level, posture_floor); new EXPLAIN key
  risk.escalated_posture.
- Phase 2 (T2 Schema v2): build_json_data(...,
  schema_version="2") is the new default; --json-v1 flag
  preserves v0.6.x layout exactly. EXPLAIN_KEYS baseline =
  117 keys / 30 prefixes / 100% conformance.
- Phase 3 (T3 Plugin Sandbox Runner): new bob/_sandbox.py
  (~900 LoC) — process isolation via mp spawn, 5s wall
  timeout + RLIMIT_AS=256MiB + RLIMIT_CPU=10s, import
  allowlist, restricted __builtins__, open() wrapper
  rejecting writes + denying reads on sensitive paths,
  extensive os module attribute strip (84 attrs), JSON-safe
  dict round-trip through mp.Queue. Threat model recadré
  honest in SECURITY.md — in-process Python sandboxing is
  NOT a security boundary (PEP 416 consensus); the shipped
  AppArmor profile is the real boundary.
- Four release-engineering guards added in flight:
  integration-first, smoke-after-commit, version-consistency,
  smoke-plugin-on-CI.
- 5391 → 5466 tests across the v0.7.0 cycle, 0 regression.
- Deferred to v0.8.0: D-1 sections renumbering, D-2 fusion
  _ALL_SECTIONS+_ALWAYS_ON_SECTIONS, D-3 retrait aliases
  EXPLAIN_KEYS obsolètes, D-4 sub-checks granulaires,
  removal of BOB_SANDBOX_LEGACY=1 trap door.
- v0.6.x branch officially EOL.

* Fri May 29 2026 Cédric Clauzel <cedricclauzel@mailo.com> - 0.6.2-1
- CRITICAL packaging hotfix. Every wheel since v0.6.0 was
  missing bob/checks/ssh/ and bob/cron/ subpackages. Users who
  pipx-upgraded hit ModuleNotFoundError on every invocation.
- Root cause: pyproject.toml [tool.setuptools.packages.find]
  had a literal include list inherited from v0.4.x. The v0.6.0
  splits added bob.checks.ssh and bob.cron but the list was
  not updated. setuptools' find_packages() excluded both
  subpackages from the wheel.
- Fix: include = ["bob*"] glob auto-discovers every current
  and future bob.* subpackage.
- CI hardened: pip install . (non-editable) + explicit smoke
  step importing every v0.6.x-added module.
- Why undetected: unit tests + pre-ship smoke ran from the
  source tree (sys.path resolution); CI used pip install -e .
  (editable mode bypasses find_packages discovery).
- No code changes. Only pyproject.toml (1 line) and
  workflows/integration.yml (~15 lines) modified.
- 4600 tests unchanged.
- JSON contract, EXPLAIN_KEYS, wire output — all preserved.
- Upgrade: pipx upgrade bodyguard-of-bits.

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
