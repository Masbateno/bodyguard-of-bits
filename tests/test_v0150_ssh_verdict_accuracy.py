"""
v0.15.0 — verdict-accuracy guards for the SSH check.

The v0.14.1 campaigns tested robustness and reporting; none of them asked
whether BOB's security *judgements* are right. This file pins the first
answers, found by differential testing against OpenSSH's own parser
(`sshd -T`, OpenSSH 9.6) — the tests themselves are self-contained and do not
need sshd installed.

The defect these guard against is the most discrediting kind a hardening
auditor can have: the same dangerous configuration, written slightly
differently, stops being reported.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from bob.checks.ssh._parsers import _parse_config_file, _strip_inline_comment
from bob.checks.ssh._snapshot import SSHSnapshot
from bob.checks.ssh._subchecks import _check_sshd_config
from bob.scoring import CheckResult


def _verdicts(body: str) -> dict[str, str]:
    """Parse an sshd_config body and return {finding key: level}."""
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as fh:
        fh.write(body)
        path = Path(fh.name)
    try:
        cfg: dict = {}
        _parse_config_file(path, cfg, set())
        result = CheckResult()
        _check_sshd_config(
            SSHSnapshot(sshd_installed=True, sshd_active=True, sshd_config=cfg),
            result, lambda k, **kw: k,
        )
        return {f.key: f.level.value for f in result.findings if f.key}
    finally:
        path.unlink(missing_ok=True)


class TestInlineCommentsDoNotChangeVerdicts:
    """An unquoted `#` starts a comment in sshd_config — OpenSSH ignores the
    rest of the line. BOB kept it as part of the value, and every sub-check
    compares values exactly, so a trailing note silently rewrote the audit."""

    INSECURE = (
        "PermitRootLogin yes\n"
        "PasswordAuthentication yes\n"
        "PermitEmptyPasswords yes\n"
        "X11Forwarding yes\n"
    )

    def test_same_config_commented_yields_same_verdicts(self):
        commented = "".join(l + "   # operator note\n"
                            for l in self.INSECURE.strip().splitlines())
        assert _verdicts(self.INSECURE) == _verdicts(commented)

    @pytest.mark.parametrize("key,level", [
        ("ssh.permit_root_login", "alert"),
        ("ssh.permit_empty_passwords", "alert"),
        ("ssh.password_auth", "warn"),
        ("ssh.x11.forwarding.server", "warn"),
    ])
    def test_each_finding_survives_a_trailing_comment(self, key, level):
        """Before the fix: root-login went ALERT → INFO and the other three
        vanished, so a genuinely dangerous host scored *higher*."""
        commented = "".join(l + " # TODO\n"
                            for l in self.INSECURE.strip().splitlines())
        assert _verdicts(commented).get(key) == level

    def test_a_hardened_value_is_not_falsely_flagged(self):
        """The same bug fired the other way: `MaxAuthTries 2 # strict` failed
        int(), fell back to the default 6, and 6 > 3 warned a correct host."""
        assert "ssh.max_auth_tries" not in _verdicts("MaxAuthTries 2 # strict\n")
        assert "ssh.max_auth_tries" in _verdicts("MaxAuthTries 10\n")


class TestStripInlineComment:
    """Semantics verified against `sshd -T` (OpenSSH 9.6)."""

    @pytest.mark.parametrize("raw,expected", [
        ("yes # TODO remove",      "yes"),
        ("yes",                    "yes"),
        ("/etc/issue # note",      "/etc/issue"),
        ("2 # strict",             "2"),
        ('"/etc/my#file"',         '"/etc/my#file"'),   # quoted # is literal
        ("#only-a-comment",        ""),
        ("a b c",                  "a b c"),
    ])
    def test_cuts_at_unquoted_hash_only(self, raw, expected):
        assert _strip_inline_comment(raw).strip() == expected


class TestPermitRootLoginValueSpace:
    """Every value OpenSSH accepts must land in the right branch."""

    @pytest.mark.parametrize("value,expected_key", [
        ("yes",                  "ssh.permit_root_login"),             # alert
        ("no",                   "ssh.permit_root_login_disabled"),    # ok
        ("prohibit-password",    "ssh.permit_root_login_restricted"),  # ok
        ("without-password",     "ssh.permit_root_login_restricted"),  # ok, pre-6.7 spelling
        ("forced-commands-only", "ssh.permit_root_login_restricted"),  # ok
    ])
    def test_value_maps_to_the_right_finding(self, value, expected_key):
        assert expected_key in _verdicts(f"PermitRootLogin {value}\n")

    def test_without_password_is_credited_not_merely_noted(self):
        """It is the pre-6.7 spelling of prohibit-password and OpenSSH still
        accepts it; before v0.15.0 a correctly hardened legacy host fell into
        the "unrecognised value" INFO branch and got no credit."""
        v = _verdicts("PermitRootLogin without-password\n")
        assert v.get("ssh.permit_root_login_restricted") == "ok"
        assert "ssh.permit_root_login" not in v
