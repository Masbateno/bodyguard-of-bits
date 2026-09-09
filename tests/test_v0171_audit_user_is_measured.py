"""BOB knows who is running it, even when the environment does not say.

Measured on three VMs through the same execution path, all running as root:

    Debian 13        USER='root'   SUDO_USER=None   euid 0 -> root
    Kali 2026.2      USER='root'   SUDO_USER=None   euid 0 -> root
    openSUSE 15.6    USER=None     SUDO_USER=None   euid 0 -> root

Only openSUSE printed ``User : unknown`` in the report header. The process
identity was identical on all three, and the kernel would have answered on all
three — BOB was reading `SUDO_USER or USER` and giving up when neither was set.

An environment variable is a claim; ``geteuid()`` is a measurement. Any
non-interactive context can arrive without ``USER`` — a systemd timer, a guest
agent, a minimal image — and this header is written into the report file, so
"unknown" outlives the run that produced it.

``SUDO_USER`` stays first, because it carries something the euid cannot: the
human behind the sudo. It is validated against the password database, so a
value that names nobody falls through to the measurement rather than being
printed as fact.
"""

from __future__ import annotations

import os
import pwd
from unittest.mock import patch

import pytest

from bob.sysinfo import audit_user


class TestTheEnvironmentIsNotTheSource:
    def test_no_environment_at_all_still_answers(self, monkeypatch):
        """The openSUSE case, exactly."""
        monkeypatch.delenv("USER", raising=False)
        monkeypatch.delenv("SUDO_USER", raising=False)
        answer = audit_user()
        assert answer == pwd.getpwuid(os.geteuid()).pw_name
        assert answer != "unknown"

    def test_a_lying_user_variable_does_not_win(self, monkeypatch):
        monkeypatch.delenv("SUDO_USER", raising=False)
        monkeypatch.setenv("USER", "definitely-not-this-account")
        assert audit_user() == pwd.getpwuid(os.geteuid()).pw_name

    def test_the_word_unknown_is_gone(self, monkeypatch):
        monkeypatch.delenv("USER", raising=False)
        monkeypatch.delenv("SUDO_USER", raising=False)
        assert "unknown" not in audit_user()


class TestSudoUserKeepsItsPlace:
    """It names the human, which the euid cannot."""

    def test_a_real_sudo_user_is_reported(self, monkeypatch):
        real = pwd.getpwuid(os.getuid()).pw_name
        monkeypatch.setenv("SUDO_USER", real)
        assert audit_user() == real

    def test_a_sudo_user_naming_nobody_falls_through(self, monkeypatch):
        monkeypatch.setenv("SUDO_USER", "no-such-account-anywhere")
        assert audit_user() == pwd.getpwuid(os.geteuid()).pw_name

    @pytest.mark.parametrize("bogus", ["../root", "a b", "x" * 300, "root;id"])
    def test_a_malformed_sudo_user_is_refused(self, monkeypatch, bogus):
        monkeypatch.setenv("SUDO_USER", bogus)
        assert audit_user() == pwd.getpwuid(os.geteuid()).pw_name


class TestAUidWithNoNameIsStillAFact:
    def test_it_reports_the_number_rather_than_unknown(self, monkeypatch):
        """Containers with a mapped user have a uid and no passwd entry."""
        monkeypatch.delenv("USER", raising=False)
        monkeypatch.delenv("SUDO_USER", raising=False)
        with patch("pwd.getpwuid", side_effect=KeyError("no entry")), \
             patch("os.geteuid", return_value=61234):
            assert audit_user() == "uid 61234"


class TestTheHeaderUsesIt:
    def test_collect_system_info_goes_through_the_helper(self, monkeypatch):
        from bob import sysinfo
        monkeypatch.delenv("USER", raising=False)
        monkeypatch.delenv("SUDO_USER", raising=False)
        with patch.object(sysinfo, "audit_user", return_value="measured-name"):
            info = sysinfo.collect_system_info("0.0.0", "en")
        assert info.user == "measured-name", (
            "the header no longer asks the helper, so the environment is back "
            "in charge of an answer the kernel already has"
        )
