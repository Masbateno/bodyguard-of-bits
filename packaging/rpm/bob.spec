%global pypi_name bodyguard-of-bits

Name:           bob
Version:        0.5.0
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
