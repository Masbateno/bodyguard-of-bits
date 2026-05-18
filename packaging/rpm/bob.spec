%global pypi_name bodyguard-of-bits

Name:           bob
Version:        0.4.6
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
%doc README.md README_FR.md SECURITY.md
%doc DOCUMENTS/README_TECH.md DOCUMENTS/README_TECH_FR.md
%{_bindir}/bob
%{_mandir}/man1/bob.1*
%{_mandir}/man5/bob.conf.5*
%{_mandir}/man5/bob-profile.5*

# ---------------------------------------------------------------------------
# Changelog
# ---------------------------------------------------------------------------

%changelog
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
