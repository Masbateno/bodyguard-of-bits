"""v0.24.1 — the eight table-driven sshd fixes make the directive effective.

Measured on the Mint desktop audit: X11Forwarding and AllowTcpForwarding were
offered ``sudo sed -i 's/^#*X11Forwarding yes/X11Forwarding no/'
/etc/ssh/sshd_config`` while MaxAuthTries, three lines below, went through the
drop-in. The sed form is a no-op when a drop-in sets the value (sshd keeps the
first value it reads) or when the line is spelled ``X11Forwarding  yes`` /
``X11Forwarding=yes``. All eight now use ``_sshd_directive_fix``.

These tests run the generated edit for real on a temporary file — guarding what
the command does, not how it reads.
"""

from __future__ import annotations

import subprocess

import pytest

from bob.checks.ssh._directives import _BAD_DIRECTIVES, _apply_bad_directive, _sshd_directive_fix
from bob.scoring import CheckResult


def _t(key: str, **_kw) -> str:
    return key


def _edit_part(cmd: str, real: str, tmp: str) -> str:
    """The file-editing half of a fix command, aimed at *tmp*, without sudo."""
    edit = cmd.split(" && sudo sshd -t")[0]
    return edit.replace("sudo ", "").replace(real, tmp)


def _emitted_cmd(rule, cfg) -> str:
    result = CheckResult()
    bad = rule.bad_values[0] if rule.bad_values else "yes"
    assert _apply_bad_directive(rule, {**cfg, rule.name: bad}, result, _t)
    return next(f.cmd for f in result.findings if f.cmd)


@pytest.mark.parametrize("rule", _BAD_DIRECTIVES, ids=lambda r: r.name)
def test_every_table_directive_targets_the_dropin(rule):
    cmd = _emitted_cmd(rule, {"_dropin_dir": "/etc/ssh/sshd_config.d"})
    assert "/etc/ssh/sshd_config.d/00-bob-hardening.conf" in cmd
    assert "s/^#*" not in cmd


@pytest.mark.parametrize("rule", _BAD_DIRECTIVES, ids=lambda r: r.name)
def test_every_table_directive_tests_the_config_before_restarting(rule):
    cmd = _emitted_cmd(rule, {})
    assert "sudo sshd -t && " in cmd
    assert cmd.index("sshd -t") < cmd.index("restart")


def test_main_file_fix_survives_odd_spelling_and_a_trailing_match_block(tmp_path):
    conf = tmp_path / "sshd_config"
    conf.write_text("Port 22\nX11Forwarding  yes\n#X11Forwarding=no\n"
                    "Match User backup\n    ForceCommand internal-sftp\n",
                    encoding="utf-8")
    cmd = _sshd_directive_fix("X11Forwarding no", "X11Forwarding", {})
    subprocess.run(["bash", "-c", _edit_part(cmd, "/etc/ssh/sshd_config", str(conf))],
                   check=True)
    lines = conf.read_text(encoding="utf-8").splitlines()
    # first line, so it is global and read first; every other spelling gone;
    # the Match block untouched and still last
    assert lines[0] == "X11Forwarding no"
    assert sum("x11forwarding" in ln.lower() for ln in lines) == 1
    assert lines[-2:] == ["Match User backup", "    ForceCommand internal-sftp"]


def test_dropin_fix_is_idempotent(tmp_path):
    d = tmp_path / "sshd_config.d"
    d.mkdir()
    cmd = _sshd_directive_fix("AllowTcpForwarding no", "AllowTcpForwarding",
                              {"_dropin_dir": str(d)})
    edit = cmd.split(" && sudo sshd -t")[0].replace("sudo ", "")
    for _ in range(2):
        subprocess.run(["bash", "-c", edit], check=True)
    assert (d / "00-bob-hardening.conf").read_text(encoding="utf-8") == "AllowTcpForwarding no\n"
