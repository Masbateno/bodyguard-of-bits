"""SSH authentication written by `sshd-session` was invisible to BOB.

OpenSSH 9.8 moved per-connection work out of `sshd` into `sshd-session`, and
from then on "Accepted", "Failed password" and "Invalid user" are written under
that identifier. BOB queried `journalctl -t sshd` and matched `sshd[pid]:` —
so on Debian 13, Ubuntu 25.04, Fedora 41+, Arch and Raspberry Pi OS trixie it
counted none of them.

Measured on a Raspberry Pi Zero W (Raspbian 13, OpenSSH 10.0p2), same journal,
same minute:

    journal:        71 failed attempts, 29 accepted logins
    BOB 0.18.0:     ✔ OK  No successful SSH logins recorded
    fixed:          ⚠ 71 failed SSH login attempt(s) — consider installing fail2ban
                    ℹ 29 successful SSH login(s) — top sources: 192.168.1.10 (29)

The brute-force detection was the part that mattered: in the middle of an
attack it answered with nothing.

The lines below are the real format from that board.
"""

from __future__ import annotations

import subprocess

import pytest

from bob.checks import auth_log as A
from bob.checks.auth_log import AuthLogSnapshot, check_auth_log

_ACCEPTED_PW = ("Sep 11 13:20:04 pizero sshd-session[1605]: Accepted password for so6 "
                "from 192.168.1.10 port 58814 ssh2")
_ACCEPTED_KEY = ("Sep 11 13:25:31 pizero sshd-session[1659]: Accepted publickey for so6 "
                 "from 192.168.1.10 port 54466 ssh2: ED25519 SHA256:abc")
_INVALID = "Sep 11 13:42:06 pizero sshd-session[2911]: Invalid user intrus1 from 127.0.0.1 port 57392"
_FAILED = "Sep 11 13:55:00 pizero sshd-session[2950]: Failed password for so6 from ::1 port 38704 ssh2"
_PENALTY = ("Sep 11 13:42:35 pizero sshd[1049]: drop connection #0 from [127.0.0.1]:52466 on "
            "[127.0.0.1]:22 penalty: connections without attempting authentication")
_LEGACY_FAILED = "Apr 18 10:23:45 host sshd[123]: Failed password for root from 203.0.113.9 port 1 ssh2"
_LEGACY_ACCEPTED = ("Apr 18 10:23:46 host sshd[124]: Accepted publickey for admin "
                    "from 203.0.113.9 port 2 ssh2")


def _keys(result):
    return {f.key for f in result.findings}


# ---------------------------------------------------------------------------
# The parse
# ---------------------------------------------------------------------------

def test_accepted_logins_from_sshd_session_are_counted():
    snap = AuthLogSnapshot.from_text("\n".join([_ACCEPTED_PW, _ACCEPTED_KEY]))
    assert [(e.method, e.user, e.source) for e in snap.entries] == [
        ("password", "so6", "192.168.1.10"),
        ("publickey", "so6", "192.168.1.10"),
    ]


def test_failures_from_sshd_session_are_counted():
    snap = AuthLogSnapshot.from_text("\n".join([_INVALID, _FAILED]))
    assert snap.failed_count == 2


def test_the_old_sshd_lines_still_count():
    """The mirror: OpenSSH < 9.8 (Debian 12, Ubuntu 24.04) must not regress."""
    snap = AuthLogSnapshot.from_text("\n".join([_LEGACY_FAILED, _LEGACY_ACCEPTED]))
    assert snap.failed_count == 1
    assert [e.user for e in snap.entries] == ["admin"]


def test_a_penalty_drop_is_not_an_attempt():
    """`sshd` itself logs these; they are refusals, not authentication."""
    assert AuthLogSnapshot.from_text(_PENALTY).failed_count == 0


# ---------------------------------------------------------------------------
# The query
# ---------------------------------------------------------------------------

def test_the_journal_is_asked_for_sshd_session(monkeypatch):
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(A.subprocess, "run", fake_run)
    A._read_auth_from_journald()
    argv = seen["argv"]
    idents = [argv[i + 1] for i, a in enumerate(argv) if a == "-t"]
    assert "sshd-session" in idents, f"journalctl was asked for {idents} only"
    assert "sshd" in idents, "and the pre-9.8 identifier must stay"


# ---------------------------------------------------------------------------
# The verdicts, as rendered
# ---------------------------------------------------------------------------

def test_an_attack_logged_by_sshd_session_raises_the_brute_force_warning():
    lines = [_INVALID.replace("[2911]", f"[{3000 + i}]") for i in range(A._BRUTE_FORCE_THRESHOLD)]
    result = check_auth_log(AuthLogSnapshot.from_text("\n".join(lines)))
    assert "auth_log.brute_force" in _keys(result)


def test_real_logins_are_not_reported_as_none():
    result = check_auth_log(AuthLogSnapshot.from_text(_ACCEPTED_KEY))
    assert "auth_log.no_logins" not in _keys(result)
    assert "auth_log.summary" in _keys(result)


# ---------------------------------------------------------------------------
# The command follows the source it read
# ---------------------------------------------------------------------------

_PUBLIC = ("Sep 11 13:25:31 pizero sshd-session[1659]: Accepted publickey for so6 "
           "from 203.0.113.7 port 54466 ssh2")


@pytest.mark.parametrize("source,expected,forbidden", [
    ("journald", "journalctl", "/var/log/auth.log"),
    ("auth.log", "/var/log/auth.log", "journalctl"),
])
def test_the_offered_command_reads_where_bob_read(source, expected, forbidden):
    snap = AuthLogSnapshot.from_text(_PUBLIC)
    snap.source = source
    cmd = next(f.cmd for f in check_auth_log(snap).findings
               if f.key == "auth_log.public_login")
    assert expected in cmd and forbidden not in cmd, cmd
    if source == "journald":
        assert "-t sshd-session" in cmd


def test_the_journal_fallback_records_its_source(monkeypatch):
    monkeypatch.setattr(A, "_LOG_PATHS", ())
    monkeypatch.setattr(A, "_read_auth_from_journald", lambda: _PUBLIC + "\n")
    assert AuthLogSnapshot.from_system().source == "journald"
