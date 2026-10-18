"""``--explain`` names the host's privilege word, as the printed fixes do (v0.25.1).

The explain entries write ``sudo`` in their commands. On a host where only
``doas`` is installed (Alpine), the entry must name ``doas``; on a host with
``sudo`` the text is unchanged. ``sudoers`` and other words are not touched.
"""
from __future__ import annotations

import re

import pytest

from bob import _privilege, i18n
from bob.explain import run_explain

_COMMAND_SUDO = re.compile(r"(?<![\w./-])sudo(?=\s)")


def _render(capsys, key="ssh.password_auth") -> str:
    i18n.init("en")
    try:
        assert run_explain(key, i18n.t) is True
    finally:
        i18n.init("en")
    return capsys.readouterr().out


@pytest.fixture
def host(monkeypatch):
    def set_prefix(prefix: str) -> None:
        monkeypatch.setattr(_privilege, "privilege_prefix", lambda: prefix)
    return set_prefix


def test_doas_only_host_explain_names_doas(capsys, host):
    host("doas")
    out = _render(capsys)
    assert "doas " in out
    assert not _COMMAND_SUDO.search(out), out


def test_sudo_host_explain_is_unchanged(capsys, host):
    host("sudo")
    out = _render(capsys)
    assert "sudo " in out
    assert "doas" not in out


def test_sudoers_is_not_rewritten(capsys, host):
    host("doas")
    out = _render(capsys, key="file_perms.sudoers_nopasswd_all")
    assert "sudoers" in out


def test_finding_prose_names_doas_on_a_doas_only_host(monkeypatch):
    """v0.25.1 — a finding's message, detail and note follow the host too."""
    from bob import _privilege
    from bob.scoring import CheckResult
    monkeypatch.setattr(_privilege, "privilege_prefix", lambda: "doas")
    r = CheckResult()
    r.warn(message="shadow unreadable (run with sudo)", key="x.y",
           detail="Fix: sudo chmod 600 /etc/ssh/key", note="see sudo crontab -e")
    f = r.findings[0]
    assert "doas" in f.message and "doas chmod" in f.detail and "doas crontab" in f.note
    assert "sudo " not in f.message + f.detail + f.note


def test_a_text_without_sudo_never_asks_the_host(monkeypatch):
    """v0.25.1 — plugin findings are built in the sandbox, where `os` is restricted."""
    from bob import _privilege
    def boom():
        raise AssertionError("privilege_prefix must not be called")
    monkeypatch.setattr(_privilege, "privilege_prefix", boom)
    assert _privilege.with_privilege("Firewall inactive") == "Firewall inactive"
