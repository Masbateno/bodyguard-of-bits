"""v0.25.1 — BOB finds the operator behind doas as it does behind sudo.

OpenBSD doas and OpenDoas set DOAS_USER; only SUDO_USER was read, so on an
Alpine host BOB run through doas kept its settings, ignore list, baseline and
history in /root and --install-completion skipped the /usr/local/bin link.
"""

import pwd

from bob import sysinfo


def _someone():
    return next(e for e in pwd.getpwall() if e.pw_dir and e.pw_name != "root")


def test_doas_user_resolves_the_home(monkeypatch):
    user = _someone()
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.setenv("DOAS_USER", user.pw_name)
    assert sysinfo.invoking_user_name() == user.pw_name
    assert str(sysinfo.get_user_home()) == user.pw_dir


def test_sudo_user_still_comes_first(monkeypatch):
    user = _someone()
    monkeypatch.setenv("SUDO_USER", user.pw_name)
    monkeypatch.setenv("DOAS_USER", "root")
    assert sysinfo.invoking_user_name() == user.pw_name


def test_a_malformed_value_is_ignored(monkeypatch):
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.setenv("DOAS_USER", "../../etc")
    assert sysinfo.invoking_user_name() == ""
