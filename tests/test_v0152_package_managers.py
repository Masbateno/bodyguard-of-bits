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
