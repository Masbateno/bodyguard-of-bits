"""v0.15.2 — a service is not absent merely because dpkg is.

`_detect_installation` asked `dpkg-query` and nothing else, so on any
distribution that does not ship dpkg — the whole RHEL family, Arch, openSUSE,
Alpine — every service in the registry read as NOT INSTALLED. No error, no
crash: the audit ran, printed a services section, and reported every entry
absent. Measured in a Fedora container with httpd, vsftpd, memcached and
mariadb-server installed and confirmed by `rpm -q`, BOB saw none of them.

Three checks asked this question with a private dpkg call each — services,
firmware and ddns. One answer now, for the same reason the UFW rule grammar
and the `ss` address column were unified in this release: a rule kept in
several copies is a rule that will disagree with itself.

The behaviour was verified end to end against real installs on Debian, Fedora,
Arch and Alpine; container runs cannot happen in a unit test, so what each
manager is asked and how its answer is read is pinned here.
"""

from unittest.mock import patch

import pytest

from bob.checks._run import _PACKAGE_QUERIES, package_installed


class TestEveryManagerIsAsked:
    @pytest.mark.parametrize("tool", ["dpkg-query", "rpm", "pacman", "apk"])
    def test_the_manager_is_in_the_table(self, tool):
        assert tool in [entry[0] for entry in _PACKAGE_QUERIES]

    def test_dpkg_leads(self):
        """Debian is the project's reference; its query stays first."""
        assert _PACKAGE_QUERIES[0][0] == "dpkg-query"

    def test_a_missing_manager_is_skipped_not_run(self):
        """One `_command_exists` per family is the whole cost on any host."""
        with (
            patch("bob.checks._run._command_exists", return_value=False),
            patch("bob.checks._run._run") as runner,
        ):
            assert package_installed("anything") is None
        runner.assert_not_called()


class TestHowEachAnswerIsRead:
    def _ask(self, present_tool, output):
        def exists(tool):
            return tool == present_tool
        with (
            patch("bob.checks._run._command_exists", side_effect=exists),
            patch("bob.checks._run._run", return_value=output),
        ):
            return package_installed("whatever")

    def test_dpkg_needs_its_status_string(self):
        assert self._ask("dpkg-query", "install ok installed") == "dpkg-query"

    def test_dpkg_rejects_a_removed_package(self):
        """`deinstall ok config-files` is a package that is gone but configured."""
        assert self._ask("dpkg-query", "deinstall ok config-files") is None

    @pytest.mark.parametrize("tool,output", [
        ("rpm",    "httpd-2.4.62-1.fc41.x86_64\n"),
        ("pacman", "apache 2.4.62-1\n"),
        ("apk",    "vsftpd-3.0.5-r2\n"),
    ])
    def test_the_others_answer_by_printing_the_package(self, tool, output):
        assert self._ask(tool, output) == tool

    @pytest.mark.parametrize("tool", ["rpm", "pacman", "apk"])
    def test_silence_means_absent(self, tool):
        assert self._ask(tool, "") is None

    @pytest.mark.parametrize("tool", ["rpm", "pacman", "apk"])
    def test_whitespace_is_not_an_answer(self, tool):
        assert self._ask(tool, "  \n\t\n") is None


class TestTheDpkgArgumentSurvivesSubstitution:
    """`-f=${Status}` is not a format string.

    Substituting the package name with `str.format` read `{Status}` as a field
    and raised KeyError on every call — caught by the suite, but only because
    the end-to-end runner tests exercise the real path.
    """

    def test_the_status_format_reaches_dpkg_intact(self):
        seen = {}

        def record(*args, **kwargs):
            seen["args"] = args
            return ""

        with (
            patch("bob.checks._run._command_exists",
                  side_effect=lambda tool: tool == "dpkg-query"),
            patch("bob.checks._run._run", side_effect=record),
        ):
            package_installed("nginx")
        assert seen["args"] == ("dpkg-query", "-W", "-f=${Status}", "nginx")


class TestTheThreeCallersShareIt:
    """No module keeps its own dpkg call any more."""

    def test_no_check_queries_dpkg_privately(self):
        import re
        from pathlib import Path

        offenders = []
        for path in sorted(Path("bob/checks").rglob("*.py")):
            if path.name == "_run.py":
                continue  # defines the query
            for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if re.search(r'_run\(\s*["\']dpkg', line):
                    offenders.append(f"{path}:{number}")
        assert not offenders, (
            "these ask dpkg directly instead of calling package_installed(), "
            "so they answer False on every non-Debian host: "
            + ", ".join(offenders)
        )

    def test_services_reports_which_manager_answered(self):
        from bob.checks.services import _detect_installation
        from bob.registry import Detection, Service

        service = Service(id="x", label="X", packages=("httpd",), services=(),
                          ports=("80/tcp",), risk="low", config_key="fixed",
                          detection=Detection(binary=(), snap=(), config_files=()))
        with patch("bob.checks.services.package_installed", return_value="rpm"):
            assert _detect_installation(service) == (True, "rpm")


class TestTheRegistryNamesEachDistributionsPackage:
    """Package names differ, and a name BOB does not know is a service it
    cannot see.

    Measured by installing each candidate in Debian, Fedora, Arch and Alpine
    containers and asking the package manager itself what it shipped. Only the
    conclusions can live in a unit test; the container runs cannot.
    """

    @pytest.fixture(scope="class")
    def registry(self):
        from bob.registry import ServiceRegistry
        return ServiceRegistry.load()

    @pytest.mark.parametrize("service_id,names", [
        ("apache", {"apache2", "httpd", "apache"}),      # Debian / RHEL / Arch
        ("mysql",  {"mysql-server", "mariadb-server", "mariadb"}),
        ("ssh",    {"openssh-server", "openssh"}),       # Arch and Alpine drop -server
        ("redis",  {"redis-server", "redis", "valkey"}),
        ("ftp",    {"vsftpd", "proftpd"}),
    ])
    def test_every_measured_name_is_declared(self, service_id, names, registry):
        declared = set(next(s for s in registry._services
                            if s.id == service_id).packages)
        missing = names - declared
        assert not missing, f"{service_id}: {sorted(missing)} not in the registry"

    def test_redis_is_valkey_on_two_distributions(self, registry):
        """Fedora and Arch ship no redis config at all — only valkey's.

        `dnf install redis` and `pacman -S redis` both succeed and both leave
        /etc empty; the config that exists is /etc/valkey/valkey.conf. Without
        the name and the path, redis reads as absent on Fedora and Arch and as
        listening on its default port on Alpine.
        """
        service = next(s for s in registry._services if s.id == "redis")
        assert "valkey" in service.packages
        assert "/etc/valkey/valkey.conf" in service.detection.config_files


class TestConfigPathsMeasuredPerDistribution:
    @pytest.fixture(scope="class")
    def registry(self):
        from bob.registry import ServiceRegistry
        return ServiceRegistry.load()

    @pytest.mark.parametrize("service_id,path,where", [
        ("apache",     "/etc/apache2/ports.conf",              "Debian"),
        ("apache",     "/etc/apache2/httpd.conf",              "Alpine"),
        ("apache",     "/etc/httpd/conf/httpd.conf",           "Fedora and Arch"),
        ("ftp",        "/etc/vsftpd.conf",                     "Debian and Arch"),
        ("ftp",        "/etc/vsftpd/vsftpd.conf",              "Fedora and Alpine"),
        ("ftp",        "/etc/proftpd/proftpd.conf",            "Debian and Alpine"),
        ("ftp",        "/etc/proftpd.conf",                    "Fedora"),
        ("redis",      "/etc/redis/redis.conf",                "Debian"),
        ("redis",      "/etc/redis.conf",                      "Alpine"),
        ("redis",      "/etc/valkey/valkey.conf",              "Fedora and Arch"),
        ("postgresql", "/etc/postgresql/*/main/postgresql.conf", "Debian"),
        ("postgresql", "/var/lib/pgsql/data/postgresql.conf",  "RHEL"),
        ("postgresql", "/var/lib/postgres/data/postgresql.conf", "Arch"),
    ])
    def test_the_path_is_declared(self, service_id, path, where, registry):
        declared = next(s for s in registry._services
                        if s.id == service_id).detection.config_files
        assert path in declared, f"{service_id}: {where} path missing"

    def test_postgresql_keeps_its_config_outside_etc_on_rpm_hosts(self, registry):
        """initdb writes postgresql.conf into the data directory, not /etc.

        Nothing under /etc/postgresql exists on Fedora or Arch, so the Debian
        path alone meant the port was never read there.
        """
        declared = next(s for s in registry._services
                        if s.id == "postgresql").detection.config_files
        assert any(p.startswith("/var/lib/") for p in declared)
