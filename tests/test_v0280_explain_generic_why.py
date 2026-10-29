"""v0.28.0 — an explain with profile sections shows its generic WHY too.

Since v0.1.0 a key with server/desktop/container prose printed those sections
and never its generic WHY — a test pinned it. The generic WHY had since come to
carry measurements: DOCKER-USER (0.27.0), Docker over IPv6 (0.28.0, Docker
29.9.2: the port also listens on [::]; on a network without IPv6 no
DOCKER-USER rule stopped it, the host's IPv6 input filter did; on a --ipv6
network ip6tables' DOCKER-USER did), firewalld (Fedora 44) — and the HOW sent
the reader to "WHY". Both renderers (the terminal one and the curses detail
screen) now print it once, above the profile sections.
"""

from __future__ import annotations

import contextlib
import io

import pytest

from bob import i18n
from bob import explain as ex

KEYS = ["docker.exposed_port", "docker.exposed_bypass_ufw", "docker.iptables_bypass",
        "firewall_drivers.iptables_bypass", "logs.blocked_repeat_public"]


def _terminal(key, lang="en"):
    i18n.init(lang)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ex.run_explain(key, i18n.t)
    return buf.getvalue()


class _Screen:
    def __init__(self):
        self.text = []

    def getmaxyx(self):
        return (2000, 400)

    def erase(self):
        pass

    def refresh(self):
        pass

    def addstr(self, _row, _col, text, *_a):
        self.text.append(text)

    def getch(self):
        return 27


def _curses(monkeypatch, key):
    from bob.tui import _chrome
    i18n.init("en")
    monkeypatch.setattr(ex, "_init_colors", lambda: False)
    monkeypatch.setattr(_chrome, "draw", lambda *a, **k: None)
    monkeypatch.setattr(_chrome, "draw_header", lambda *a, **k: None)
    monkeypatch.setattr(_chrome, "chrome_height", lambda *a, **k: 0)
    screen = _Screen()
    ex._detail_screen(screen, key, i18n.t)
    return "\n".join(screen.text)


@pytest.mark.parametrize("key", KEYS)
def test_the_terminal_shows_the_measured_why(key):
    out = _terminal(key)
    why = i18n.t(f"explain.{key}.why")
    assert why.split(". ")[0] in out
    assert out.index(i18n.t("explain.ui.why_title")) < out.index("[ server ]")


@pytest.mark.parametrize("lang, words", [
    ("en", "no DOCKER-USER rule stopped it"), ("fr", "aucune règle DOCKER-USER ne l'a arrêté")])
def test_the_docker_ipv6_measurement_is_on_screen(lang, words):
    assert words in _terminal("docker.exposed_bypass_ufw", lang)


def test_the_curses_screen_shows_it_too(monkeypatch):
    out = _curses(monkeypatch, "docker.exposed_bypass_ufw")
    assert "WHY IT IS A RISK" in out and "[ server ]" in out
    assert out.index("WHY IT IS A RISK") < out.index("[ server ]")
    assert "userland proxy on" in out


@pytest.mark.parametrize("lang, words", [
    ("en", "These filter IPv4 only: for IPv6, see bob --explain docker.exposed_bypass_ufw"),
    ("fr", "Elles ne filtrent que l'IPv4 : pour l'IPv6, voir bob --explain docker.exposed_bypass_ufw"),
])
def test_the_docker_user_example_says_ipv4_only(lang, words):
    assert words in _terminal("docker.exposed_port", lang)


@pytest.mark.parametrize("lang, words", [("en", "every IPv4 and IPv6 address"),
                                         ("fr", "toutes les adresses IPv4 et IPv6")])
def test_the_default_publish_is_both_families(lang, words):
    assert words in _terminal("docker.exposed_port", lang)
    assert "0.0.0.0 = " not in _terminal("docker.exposed_port", lang)


@pytest.mark.parametrize("lang, words", [("en", "over IPv4 a host firewall rule does not filter it"),
                                         ("fr", "en IPv4 une règle du pare-feu de l'hôte ne le filtre pas")])
def test_the_runtime_hint_says_ipv4(lang, words):
    i18n.init(lang)
    try:
        assert words in i18n.t("docker.iptables_bypass_detail3")
    finally:
        i18n.init("en")
