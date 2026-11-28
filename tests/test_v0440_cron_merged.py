"""v0.44.0 — B-051: --install-cron merged into --manage-cron.

Decided with the user (27 November 2026): one wizard for scheduled audits. The
list of jobs is the landing screen; ``n`` there makes a new job; ``--install-cron``
opens that list on a new one. A job written, or abandoned with Esc on its first
step, returns to the list.

The screen RAISES when its keys run out: --manage-cron's list is a landing
screen, where Esc does nothing — a fake screen answering Esc by default would
loop there forever (the workstation went down that way on 20 November).
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from bob import i18n
from bob.tui import _keys
from tests.test_v0390_confirm_and_selection import _EditCurses


def _t(key, **kw):
    return i18n.t(key, **kw)


class _KeysRanOut(BaseException):
    """BaseException, not Exception: the code under test catches Exception
    (bob/tui/cron.py's _read_key returns -1 on it), and a swallowed "keys ran
    out" let a field loop forever — measured on 27 November 2026, when a
    mutation's loop took the test run to its 8 GB memory cap."""


class _Screen:
    def __init__(self, keys):
        self._keys = list(keys)
        self.calls: list = []

    def getmaxyx(self):
        return 30, 100

    def erase(self):
        pass

    def refresh(self):
        pass

    def move(self, *_a):
        pass

    def clrtoeol(self):
        pass

    def addstr(self, row, col, text, attr=0):
        self.calls.append((row, col, text, attr))

    def getch(self):
        if not self._keys:
            raise _KeysRanOut("the screen asked for one key more than the test gave")
        return self._keys.pop(0)

    def get_wch(self):
        return self.getch()

    def drawn(self) -> str:
        return " ".join(c[2] for c in self.calls)


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    before = i18n.current_lang()
    i18n.init("en")
    monkeypatch.setitem(sys.modules, "curses", _EditCurses)
    monkeypatch.setattr(_EditCurses, "KEY_F4", 268, raising=False)   # F4, as a terminal sends it
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("SUDO_USER", raising=False)
    yield
    i18n.init(before)


@pytest.fixture
def cron_host(monkeypatch, tmp_path):
    """A host whose /etc/cron.d exists (a stand-in), with no job; creations recorded."""
    import bob.cron
    from bob.tui import cron
    cron_d = tmp_path / "cron.d"
    cron_d.mkdir()
    monkeypatch.setattr(bob.cron, "CRON_DIR", cron_d)
    monkeypatch.setattr(bob.cron, "use_crontab", lambda: False)
    monkeypatch.setattr(cron, "list_installed_crons", lambda: [])
    made = []
    monkeypatch.setattr(cron, "_run_install_cron_curses", lambda *a, **k: made.append(True) or 0)
    return SimpleNamespace(cron=cron, made=made, cron_d=cron_d)


def test_n_makes_a_new_job_from_the_list(cron_host):
    scr = _Screen([ord("n"), ord("q")])
    assert cron_host.cron._run_manage_cron_curses(scr, SimpleNamespace(lang="en"), _t) == 0
    assert cron_host.made == [True]


def test_install_cron_opens_the_list_on_a_new_job(cron_host):
    scr = _Screen([ord("q")])
    cron_host.cron._run_manage_cron_curses(scr, SimpleNamespace(lang="en"), _t, start_create=True)
    assert cron_host.made == [True]


def test_without_cron_d_nor_crontab_a_new_job_is_refused_and_said(cron_host, monkeypatch, tmp_path):
    import bob.cron
    monkeypatch.setattr(bob.cron, "CRON_DIR", tmp_path / "absent")
    scr = _Screen([ord("n"), ord("q")])
    cron_host.cron._run_manage_cron_curses(scr, SimpleNamespace(lang="en"), _t)
    assert cron_host.made == []
    assert str(tmp_path / "absent") in scr.drawn()
    assert "✖" in scr.drawn()                  # said as refused (its tone)


def test_the_list_announces_n():
    from bob.tui import cron
    assert _keys.NEW in cron._MANAGE_KEYS
    assert "n new" in " ".join(_keys.footer_lines(_t, cron._MANAGE_KEYS, width=200))


def test_an_empty_list_says_how_to_make_a_job(cron_host):
    scr = _Screen([ord("q")])
    cron_host.cron._run_manage_cron_curses(scr, SimpleNamespace(lang="en"), _t)
    assert "n creates one" in scr.drawn()


def test_esc_on_the_first_step_returns_to_the_list(monkeypatch, tmp_path):
    from bob.cli import AuditConfig
    from bob.tui import cron
    monkeypatch.setattr(cron, "list_installed_crons", lambda: [])
    user_config = SimpleNamespace(get=lambda key, default=None: str(tmp_path) if key == "log_dir" else default)
    scr = _Screen([27])
    assert cron._run_install_cron_curses(scr, user_config, AuditConfig(), _t) == 0
    assert "New scheduled audit" in scr.drawn()


def test_the_switcher_opens_install_cron_as_a_new_job(monkeypatch):
    from bob.tui import cron, switch
    seen = {}
    monkeypatch.setattr(cron, "_run_manage_cron_curses",
                        lambda scr, config, t, start_create=False: seen.setdefault("create", start_create) and 0)
    switch._launch("install", object(), None, None, _t)
    assert seen == {"create": True}


def test_esc_on_the_list_opens_the_menu_of_every_wizard(cron_host):
    """The user, 27 November 2026: Esc on a wizard's first page opens --bob-tui."""
    with pytest.raises(_keys.SwitchScreen) as asked:
        cron_host.cron._run_manage_cron_curses(_Screen([27]), SimpleNamespace(lang="en"), _t)
    assert asked.value.target == "hub"


def test_a_function_key_on_the_list_opens_its_wizard(cron_host):
    """The list is --manage-cron's landing screen: F2-F5 act there."""
    with pytest.raises(_keys.SwitchScreen) as asked:
        cron_host.cron._run_manage_cron_curses(_Screen([268]), SimpleNamespace(lang="en"), _t)
    assert asked.value.target == "team"


def test_a_function_key_below_the_list_does_nothing():
    """The user, 27 November 2026: the switch keys on landing screens only."""
    from bob.tui import cron
    scr = _Screen([268, 7, 27])
    assert cron._curses_choice_screen(scr, _t, "title", "prompt", ["a", "b"], 0) is None
    assert "F2-F5" not in scr.drawn()


def test_enter_on_the_list_says_edit():
    """The user, 27 November 2026: Enter opens a job to change it — "edit"
    ("modifier"), not "select" ("choisir")."""
    from bob.tui import cron
    assert _keys.EDIT in cron._MANAGE_KEYS and _keys.SELECT not in cron._MANAGE_KEYS
    for lang, word in (("en", "⏎ edit"), ("fr", "⏎ modifier")):
        i18n.init(lang)
        assert word in " ".join(_keys.footer_lines(i18n.t, cron._MANAGE_KEYS, width=200))
    i18n.init("en")
