%global pypi_name bodyguard-of-bits

Name:           bob
Version:        0.4.2
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
* Thu May 14 2026 Cédric Clauzel <cedricclauzel30@gmail.com> - 0.4.2-1
- Initial Fedora packaging (Phase 3 of the distro-ready roadmap).
- Ships man pages bob(1), bob.conf(5), bob-profile(5).
- Ships SECURITY.md threat model.
