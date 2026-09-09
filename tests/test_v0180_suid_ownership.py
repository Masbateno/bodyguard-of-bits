"""A SUID binary no package ships is a different claim from an unexpected one.

Kali 2026.2 carries fifteen unexpected SUID binaries, every one of them a
`kismet_cap_*` helper shipped by the distribution. BOB reported them as a
single warning, which is honest and undiscriminating: a distribution putting
SUID helpers on disk is surface an operator can reason about, while a
root-owned SUID binary belonging to *no* package is the shape a left-behind
privilege escalation takes.

Measured on that machine, with a SUID root binary planted at
`/usr/local/bin/backdoor-test`::

    before   ⚠ 15 unexpected root-owned SUID binary/binaries: kismet_cap_…
    after    ⚠ 16 unexpected root-owned SUID binary/binaries: kismet_cap_…
             ✖ 1 root-owned SUID binary/binaries belong to no package:
                 /usr/local/bin/backdoor-test
    removed  ⚠ 15 unexpected …, and the alert is gone

The ownership queries are measured too, on four package managers rather than
read from documentation — Debian 13, Arch, Alpine 3.22 and openSUSE Leap 15.6:

    dpkg -S /usr/bin/sh                 0  "dash: /usr/bin/sh"
    dpkg -S /usr/local/bin/notapackage  1  "no path found matching pattern"
    rpm -qf /bin/sh                     0  "bash-sh-4.4-150400.27.6.1.x86_64"
    rpm -qf /tmp/notapackage            1  "file … is not owned by any package"
    pacman -Qo /usr/bin/sh              0  "… is owned by bash 5.3.15-1"
    pacman -Qo /usr/local/bin/nota…     1  "error: No package owns …"
    apk info --who-owns /bin/sh         0  "… is owned by busybox-binsh-…"
    apk info --who-owns /usr/local/…    1  "Could not find owner package"

All four agree: 0 owned, 1 orphan. Anything else is an answer about the query,
not about the file — and must never become an accusation.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from bob.checks import _run
from bob.checks._run import CommandResult, FileOwner, _owner_name, package_owning
from bob.checks.suid_audit import _is_unowned


def _answer(code, stdout=""):
    return CommandResult(stdout, code == 0, "", code)


def _manager(name, code, stdout=""):
    return (patch.object(_run, "_command_exists", side_effect=lambda c: c == name),
            patch.object(_run, "run_result", return_value=_answer(code, stdout)))


class TestEachGrammarIsParsed:
    @pytest.mark.parametrize("line,expected", [
        ("dash: /usr/bin/sh", "dash"),
        ("/usr/bin/sh is owned by bash 5.3.15-1", "bash 5.3.15-1"),
        ("/bin/sh is owned by busybox-binsh-1.37.0-r18", "busybox-binsh-1.37.0-r18"),
        ("bash-sh-4.4-150400.27.6.1.x86_64", "bash-sh-4.4-150400.27.6.1.x86_64"),
    ])
    def test_the_owner_comes_out(self, line, expected):
        assert _owner_name(line) == expected

    def test_nothing_printed_yields_nothing(self):
        assert _owner_name("") == ""


class TestThreeStatesNotTwo:
    @pytest.mark.parametrize("tool,stdout", [
        ("dpkg", "dash: /usr/bin/sh"),
        ("rpm", "bash-sh-4.4.x86_64"),
        ("pacman", "/usr/bin/sh is owned by bash 5.3.15-1"),
        ("apk", "/bin/sh is owned by busybox-binsh-1.37.0-r18"),
    ])
    def test_exit_zero_names_the_package(self, tool, stdout):
        a, b = _manager(tool, 0, stdout)
        with a, b:
            owner = package_owning("/usr/bin/sh")
        assert owner.known is True
        assert owner.package

    @pytest.mark.parametrize("tool", ["dpkg", "rpm", "pacman", "apk"])
    def test_exit_one_is_a_real_answer_of_no_owner(self, tool):
        a, b = _manager(tool, 1, "not owned by any package")
        with a, b:
            assert package_owning("/usr/local/bin/x") == FileOwner(None, True)

    @pytest.mark.parametrize("code", [2, 3, 127, None])
    def test_any_other_status_settles_nothing(self, code):
        """A timeout, a locked database, a manager that does not index this."""
        a, b = _manager("dpkg", code, "")
        with a, b:
            owner = package_owning("/usr/local/bin/x")
        assert owner.known is False, (
            f"exit {code} was read as an answer about the file; it is an answer "
            "about the query"
        )

    def test_no_manager_at_all_settles_nothing(self):
        with patch.object(_run, "_command_exists", return_value=False):
            assert package_owning("/usr/local/bin/x") == FileOwner(None, False)


class TestOnlyAProvenOrphanIsAccused:
    """`_is_unowned` is what turns a query into a finding."""

    def test_a_package_owning_it_is_not_an_orphan(self):
        with patch("bob.checks.suid_audit.package_owning",
                   return_value=FileOwner("kismet-capture-common", True)):
            assert _is_unowned("/usr/bin/kismet_cap_linux_wifi") is False

    def test_a_proven_orphan_is(self):
        with patch("bob.checks.suid_audit.package_owning",
                   return_value=FileOwner(None, True)):
            assert _is_unowned("/usr/local/bin/backdoor-test") is True

    def test_an_unanswerable_query_is_not(self):
        """The whole point: silence is not evidence."""
        with patch("bob.checks.suid_audit.package_owning",
                   return_value=FileOwner(None, False)):
            assert _is_unowned("/usr/local/bin/anything") is False, (
                "a host whose package manager could not be asked would have "
                "every unexpected SUID binary reported as unowned"
            )


class TestTheCollectorPopulatesIt:
    """Drives `from_system`, not a hand-built snapshot.

    An earlier draft of this guard constructed the snapshot with `unowned_suid`
    already filled and so never exercised the line that fills it — the mutation
    that empties that list survived. Same mistake as the one made an hour
    earlier on `sshd_active_known`: guarding the shape rather than the path
    that runs.
    """

    def _collect(self, found, owned):
        """Run the real collector over *found*, with *owned* shipped by a package."""
        import os
        import stat as _stat
        import subprocess as _sp
        from types import SimpleNamespace
        from bob.checks import suid_audit as mod

        class _Stat:
            st_mode = _stat.S_ISUID | 0o755
            st_uid = 0

        with patch.object(mod.os.path, "isdir", return_value=True), \
             patch.object(mod.subprocess, "run",
                          return_value=SimpleNamespace(
                              stdout="\n".join(found), stderr="", returncode=0)), \
             patch.object(mod.os, "stat", return_value=_Stat()), \
             patch.object(mod, "package_owning",
                          side_effect=lambda p: (FileOwner("some-package", True)
                                                 if p in owned
                                                 else FileOwner(None, True))):
            return mod.SuidSnapshot.from_system()

    def test_an_orphan_reaches_the_snapshot(self):
        snap = self._collect(["/usr/bin/kismet_cap_linux_wifi",
                              "/usr/local/bin/backdoor-test"],
                             owned={"/usr/bin/kismet_cap_linux_wifi"})
        assert snap.unowned_suid == ["/usr/local/bin/backdoor-test"], (
            "the collector never asked who ships these, so a planted SUID root "
            "binary is just one more line among the distribution's own"
        )

    def test_a_fully_owned_host_yields_none(self):
        snap = self._collect(["/usr/bin/kismet_cap_linux_wifi"],
                             owned={"/usr/bin/kismet_cap_linux_wifi"})
        assert snap.unowned_suid == []


class TestTheTwoFindingsStaySeparate:
    def _check(self, *, unexpected, unowned):
        from bob.checks.suid_audit import SuidSnapshot, check_suid_audit
        snap = SuidSnapshot(suid_paths=list(unexpected), sgid_paths=[],
                            unexpected_suid=list(unexpected),
                            unowned_suid=list(unowned))
        return {f.key: f for f in check_suid_audit(snap).findings}

    def test_distribution_helpers_alone_raise_no_alert(self):
        found = self._check(unexpected=["/usr/bin/kismet_cap_linux_wifi"], unowned=[])
        assert "suid_audit.unexpected_suid" in found
        assert "suid_audit.unowned_suid" not in found

    def test_an_orphan_raises_its_own_finding(self):
        found = self._check(unexpected=["/usr/bin/kismet_cap_linux_wifi",
                                        "/usr/local/bin/backdoor-test"],
                            unowned=["/usr/local/bin/backdoor-test"])
        assert "suid_audit.unowned_suid" in found
        assert "suid_audit.unexpected_suid" in found, (
            "the orphan must not vanish from the broader count — the two "
            "findings describe the same binary from different angles"
        )

    def test_the_orphan_finding_outranks_the_other(self):
        from bob.scoring import FindingLevel
        found = self._check(unexpected=["/usr/local/bin/backdoor-test"],
                            unowned=["/usr/local/bin/backdoor-test"])
        assert found["suid_audit.unowned_suid"].level is FindingLevel.ALERT
        assert found["suid_audit.unexpected_suid"].level is FindingLevel.WARN

    def test_the_orphan_finding_shows_the_paths(self):
        found = self._check(unexpected=["/usr/local/bin/backdoor-test"],
                            unowned=["/usr/local/bin/backdoor-test"])
        assert "/usr/local/bin/backdoor-test" in found["suid_audit.unowned_suid"].message


class TestBothLocalesCarryIt:
    @pytest.mark.parametrize("locale", ["en", "fr"])
    def test_the_keys_exist(self, locale):
        import json
        from pathlib import Path
        data = json.loads((Path(__file__).resolve().parent.parent / "bob" / "locales"
                           / f"{locale}.json").read_text(encoding="utf-8"))
        block = data["suid_audit"]
        for key in ("unowned_suid", "unowned_suid_reason", "unowned_suid_detail"):
            assert key in block, f"{locale}.json is missing suid_audit.{key}"
        assert "{count}" in block["unowned_suid"]
        assert "{paths}" in block["unowned_suid"]

    @pytest.mark.parametrize("locale", ["en", "fr"])
    def test_the_detail_admits_a_legitimate_cause(self, locale):
        """It must not accuse: locally built software has no package either."""
        import json
        from pathlib import Path
        data = json.loads((Path(__file__).resolve().parent.parent / "bob" / "locales"
                           / f"{locale}.json").read_text(encoding="utf-8"))
        detail = data["suid_audit"]["unowned_suid_detail"].lower()
        assert any(w in detail for w in ("legitimate", "légitime", "compiled", "compilé"))
