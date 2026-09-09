"""The SSH unit is spelled differently by different packagers.

Every SSH fix command BOB emits used to end in ``sudo systemctl restart ssh``,
which is Debian's spelling. On Arch Linux::

    Failed to restart ssh.service: Unit ssh.service not found.

Measured on five machines, asking systemd directly:

    fedora43     ssh.service 0   sshd.service 0   (no server installed)
    debian13     ssh.service 1   sshd.service 1
    kali         ssh.service 1   sshd.service 0
    opensuse15   ssh.service 0   sshd.service 1
    archbob      ssh.service 0   sshd.service 1

No static name works everywhere. Debian ships ``ssh.service`` carrying an
``sshd.service`` alias, and the alias only materialises once the unit is
enabled — which is why Kali, a Debian derivative with SSH disabled, has just
the one. So the remediation for the most consequential findings BOB reports
was inert on Arch, openSUSE, Fedora and RHEL, and could not be fixed by
picking the other name either.

This is the class v0.17.1 closed for the service registry — Fedora calling
Apache ``httpd`` — met again in the fix commands, which the registry work did
not touch.
"""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import patch

import pytest

from bob.checks import _run
from bob.checks._run import ssh_unit

_SRC = Path(__file__).resolve().parent.parent / "bob"


class _Answer:
    def __init__(self, stdout): self.stdout = stdout


@pytest.fixture(autouse=True)
def _fresh_cache():
    ssh_unit.cache_clear()
    yield
    ssh_unit.cache_clear()


def _systemd_knows(*names):
    """Stub systemctl so only *names* exist as units."""
    def fake(*argv, **kw):
        # The unit is not the last argument — `--no-legend` is. An earlier
        # draft of this stub read argv[-1] and answered for every name.
        asked = [a for a in argv if a.endswith(".service")]
        wanted = asked[0] if asked else ""
        return _Answer("x\n" if any(f"{n}.service" == wanted for n in names) else "")
    return patch.object(_run, "run_result", side_effect=fake)


class TestItAsksSystemdRatherThanGuessing:
    def test_arch_and_opensuse_get_sshd(self):
        with _systemd_knows("sshd"):
            assert ssh_unit() == "sshd"

    def test_kali_gets_ssh(self):
        with _systemd_knows("ssh"):
            assert ssh_unit() == "ssh"

    def test_debian_carrying_both_keeps_its_own_name(self):
        with _systemd_knows("ssh", "sshd"):
            assert ssh_unit() == "ssh"

    def test_a_host_systemd_cannot_answer_for_falls_back(self):
        with _systemd_knows():
            assert ssh_unit() == "ssh"

    def test_no_systemctl_at_all_does_not_raise(self):
        with patch.object(_run, "run_result", side_effect=OSError("no systemctl")):
            assert ssh_unit() in ("ssh", "sshd")

    def test_the_answer_is_cached(self):
        calls = []

        def fake(*argv, **kw):
            calls.append(argv)
            return _Answer("x\n")

        with patch.object(_run, "run_result", side_effect=fake):
            ssh_unit(); ssh_unit(); ssh_unit()
        assert len(calls) == 1, (
            "an audit builds a dozen of these commands; the answer cannot "
            "change during a run"
        )


class TestNoCommandHardcodesTheDebianSpelling:
    @pytest.mark.parametrize("rel", [
        "checks/ssh/_subchecks.py", "checks/ssh/_directives.py",
    ])
    def test_the_source_names_no_unit_literally(self, rel):
        src = "\n".join(ln for ln in (_SRC / rel).read_text(encoding="utf-8").splitlines()
                        if not ln.strip().startswith("#"))
        # `enable --now` too: the first sweep looked only for restart/reload
        # and missed the command attached to "SSH installed but not running".
        offenders = re.findall(
            r"systemctl (?:restart|reload|start|enable(?: --now)?) ssh\b(?!d)", src)
        assert not offenders, (
            f"{rel} hardcodes Debian's unit name; on Arch this is "
            "'Unit ssh.service not found'"
        )

    def test_the_directive_templates_go_through_the_resolver(self):
        src = (_SRC / "checks" / "ssh" / "_directives.py").read_text(encoding="utf-8")
        assert "@SSH_RESTART@" in src, "the templates lost their placeholder"
        assert '"@SSH_RESTART@", service_restart_cmd(ssh_unit())' in src, (
            "the placeholder is never substituted, so the literal token would "
            "reach the operator's terminal"
        )


class TestTheRenderedCommands:
    """Guarding what a check actually emits, not the helper."""

    def _cmds_for(self, unit):
        from bob.checks.ssh import _directives
        with _systemd_knows(unit):
            ssh_unit.cache_clear()
            out = [r.cmd_template.replace("@SSH_RESTART@",
                                          f"sudo systemctl restart {ssh_unit()}")
                   for r in _directives._BAD_DIRECTIVES if r.cmd_template]
        return out

    @pytest.mark.parametrize("unit", ["ssh", "sshd"])
    def test_every_command_names_the_resolved_unit(self, unit):
        cmds = self._cmds_for(unit)
        assert cmds, "no directive carries a command — the guard is inert"
        for cmd in cmds:
            if "systemctl" in cmd:
                assert f"systemctl restart {unit}" in cmd, cmd
            assert "@SSH_RESTART@" not in cmd


class TestTheProseAgreesWithTheCommand:
    """The fix command resolves the unit; the explanation must not contradict it.

    v0.17.0 closed this class for package managers — an explain block saying
    `apt` beside a `cmd` built for `dnf`. Resolving the SSH unit reopened it in
    the other direction: on Arch the command says `sshd` while 27 locale
    strings still said `ssh`.
    """

    @pytest.mark.parametrize("locale", ["en", "fr"])
    def test_no_unit_is_named_without_its_alternative(self, locale):
        import json
        data = json.loads((_SRC / "locales" / f"{locale}.json")
                          .read_text(encoding="utf-8"))

        def walk(node, path=""):
            if isinstance(node, dict):
                for k, v in node.items():
                    yield from walk(v, f"{path}.{k}")
            elif isinstance(node, str):
                yield path.strip("."), node

        bare = []
        for key, text in walk(data):
            for m in re.finditer(
                    r"systemctl (?:restart|reload|status|is-active|start|"
                    r"enable --now) ssh(?!d)(?![-\w])(.{0,40})", text):
                if "sshd" not in m.group(1):
                    bare.append(key)
        assert not bare, (
            f"{locale}: prose names Debian's unit with no mention of the other "
            f"spelling, while the command beside it resolves to sshd on Arch, "
            f"Fedora, RHEL and openSUSE: {sorted(set(bare))}"
        )

    @pytest.mark.parametrize("locale", ["en", "fr"])
    def test_the_alternative_names_the_distributions(self, locale):
        import json
        text = (_SRC / "locales" / f"{locale}.json").read_text(encoding="utf-8")
        assert "sshd" in text and "Arch" in text, (
            "the note must say which distributions use the other spelling, not "
            "merely that another exists"
        )
