""""Not installed" and "nothing could ask" are different answers.

Found with a new instrument: run the whole audit in a namespace with every
external tool removed from PATH, and see what BOB still claims. A blind audit
should say "I could not look" almost everywhere. It reported **12 deductions
and zero degraded sections** — it announced a successful audit.

Most of those survive honestly: `backup.no_backup`, `log_rotation`,
`mac_policy` and `ntp` detect by the absence of the tool *itself*, so "no
backup tool found" is a true statement about the host. `ssh.*` reads a file.

One did not. `package_installed()` answers None in two situations a caller
cannot tell apart — the package is absent, or **no package manager exists to
ask** — and `firmware` turned that into "AMD CPU detected but no microcode
package installed", a WARN with a point deducted. On Gentoo, NixOS, Void,
Slackware or a minimal image, BOB stated a negative it never established.

The rule this pins: absence of evidence is not evidence of absence, and the
report has to keep the difference.
"""

from __future__ import annotations

import pytest

import bob.checks._run as run_mod
from bob import i18n
from bob.checks.firmware import FirmwareSnapshot, check_firmware

MANAGERS = ("dpkg-query", "rpm", "pacman", "apk")


@pytest.fixture()
def no_package_manager(monkeypatch):
    real = run_mod._command_exists
    monkeypatch.setattr(
        run_mod, "_command_exists",
        lambda tool: False if tool in MANAGERS else real(tool),
    )


class TestTheHelperCanSayItCouldNotAsk:
    def test_it_is_true_when_a_manager_exists(self):
        assert run_mod.package_query_possible() is True

    def test_it_is_false_when_none_does(self, no_package_manager):
        assert run_mod.package_query_possible() is False

    def test_package_installed_alone_cannot_tell_them_apart(self, no_package_manager):
        """The ambiguity this exists to resolve, stated as a test: a package
        that IS installed and one that is not both answer None once nothing can
        be asked."""
        assert run_mod.package_installed("intel-microcode") is None
        assert run_mod.package_installed("a-package-nobody-ships") is None


class TestMicrocodeDoesNotInventAVerdict:
    @staticmethod
    def _findings(snapshot):
        i18n.init(lang="en")
        return check_firmware(snapshot, i18n.t)

    def test_it_says_it_could_not_check(self):
        snap = FirmwareSnapshot(cpu_vendor="amd", microcode_installed=False,
                                package_query_possible=False)
        result = self._findings(snap)
        keys = [f.key for f in result.findings if "microcode" in f.key]
        assert keys == ["firmware.microcode_unknown"]
        assert not result.deductions, "an unverified negative must not cost points"

    def test_the_message_names_the_reason(self):
        snap = FirmwareSnapshot(cpu_vendor="intel", microcode_installed=False,
                                package_query_possible=False)
        message = next(f.message for f in self._findings(snap).findings
                       if "microcode" in f.key)
        assert "package manager" in message.lower()
        assert "not installed" not in message.lower()

    def test_a_genuinely_missing_package_still_warns(self):
        """Polarity twin. Without it, a check that answered "unknown" to
        everything would pass the test above and audit nothing."""
        snap = FirmwareSnapshot(cpu_vendor="amd", microcode_installed=False,
                                package_query_possible=True)
        result = self._findings(snap)
        keys = [f.key for f in result.findings if "microcode" in f.key]
        assert keys == ["firmware.microcode_missing"]
        assert sum(d.points for d in result.deductions) == 1

    def test_an_installed_package_is_still_reported_ok(self):
        snap = FirmwareSnapshot(cpu_vendor="amd", microcode_installed=True,
                                microcode_package="amd64-microcode",
                                package_query_possible=True)
        keys = [f.key for f in self._findings(snap).findings if "microcode" in f.key]
        assert keys == ["firmware.microcode_ok"]

    def test_an_unknown_vendor_is_unaffected(self):
        """The pre-existing degrade path must keep its own answer."""
        snap = FirmwareSnapshot(cpu_vendor="", microcode_installed=False,
                                package_query_possible=False)
        keys = [f.key for f in self._findings(snap).findings if "microcode" in f.key]
        assert keys == ["firmware.microcode_na"]


class TestEveryPackageAssertionIsGuarded:
    """Anti-drift guard.

    A module that turns a None from ``package_installed`` into a statement must
    consult ``package_query_possible`` first. The exempt ones do not assert on
    that answer alone — they fall back to a config file, a snap package or a
    binary on PATH, so a False there rests on several independent sources.
    """

    # module -> why it needs no guard
    EXEMPT = {
        "services.py": "falls back to snap and to a binary on PATH",
        "ddns.py": "falls back to the client's own config file",
        "updates.py": "unattended-upgrades is a Debian concept; the finding is "
                      "INFO with no deduction and reads the same on any host "
                      "without dpkg, which is where it is already expected",
    }

    def test_every_caller_either_guards_or_is_exempt(self):
        import ast
        from pathlib import Path

        root = Path(__file__).resolve().parent.parent / "bob"
        unguarded = []
        for path in sorted(root.rglob("*.py")):
            if path.name == "_run.py":
                continue
            src = path.read_text(encoding="utf-8")
            if "package_installed(" not in src:
                continue
            if "package_query_possible" in src or path.name in self.EXEMPT:
                continue
            unguarded.append(path.name)
        assert not unguarded, (
            "turns a package query into a statement without checking whether "
            f"anything could be asked: {unguarded}"
        )

    def test_the_exemptions_are_still_callers(self):
        """A stale exemption hides a module that no longer exists."""
        from pathlib import Path
        root = Path(__file__).resolve().parent.parent / "bob"
        callers = {p.name for p in root.rglob("*.py")
                   if "package_installed(" in p.read_text(encoding="utf-8")
                   and p.name != "_run.py"}
        stale = set(self.EXEMPT) - callers
        assert not stale, f"exempted but no longer calls package_installed: {stale}"
