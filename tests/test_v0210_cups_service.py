"""v0.21.0 — CUPS print-service configuration check (cupsd.conf).

The shipped cupsd.conf listens on localhost only. A Listen on a routable
address / `*` / `0.0.0.0`, or a bare `Port`, turns cupsd into a network daemon
(CUPS has a long remote-CVE history). `Browsing On` advertises printers over the
network (the 2024 cups-browsed RCE vector). The listen exposure carries a
deduction; Browsing is INFO. "Unreadable" is never read as "localhost-only".
"""

from __future__ import annotations

import bob.checks.cups as cups_mod
from bob.checks.cups import CupsSnapshot, check_cups, _is_loopback_listen
from bob.scoring import FindingLevel
from tests.helpers import _keys, _get_finding


def _levels_of(result, key):
    return [f.level for f in result.findings if f.key == key]


# ---------------------------------------------------------------------------
# Not present / unreadable
# ---------------------------------------------------------------------------

def test_not_present_is_info():
    result = check_cups(CupsSnapshot(cfg_present=False))
    assert _keys(result) == ["cups.not_present"]


def test_unreadable_is_info_not_localhost():
    result = check_cups(CupsSnapshot(cfg_present=True, readable=False))
    assert _keys(result) == ["cups.cfg_unreadable"]
    assert "cups.listen_localhost" not in _keys(result)


# ---------------------------------------------------------------------------
# Listen address
# ---------------------------------------------------------------------------

class TestListen:
    def test_localhost_only_is_ok(self):
        snap = CupsSnapshot(cfg_present=True, readable=True,
                            listen_values=["localhost:631", "/run/cups/cups.sock"],
                            listens_non_loopback=False)
        assert "cups.listen_localhost" in _keys(check_cups(snap))
        assert "cups.listen_exposed" not in _keys(check_cups(snap))

    def test_non_loopback_warns_and_deducts(self):
        """The mutation guard: a network Listen must WARN + deduct."""
        snap = CupsSnapshot(cfg_present=True, readable=True,
                            listen_values=["0.0.0.0:631"],
                            listens_non_loopback=True)
        result = check_cups(snap)
        assert FindingLevel.WARN in _levels_of(result, "cups.listen_exposed")
        assert sum(d.points for d in result.deductions) >= 1

    def test_exposed_message_names_the_listen(self):
        snap = CupsSnapshot(cfg_present=True, readable=True,
                            listen_values=["Port 631"], listens_non_loopback=True)
        f = _get_finding(check_cups(snap), "cups.listen_exposed")
        assert f is not None and "Port 631" in f.message


# ---------------------------------------------------------------------------
# Browsing
# ---------------------------------------------------------------------------

class TestBrowsing:
    def test_browsing_on_is_info(self):
        snap = CupsSnapshot(cfg_present=True, readable=True,
                            listens_non_loopback=False, browsing_on=True)
        f = _get_finding(check_cups(snap), "cups.browsing_on")
        assert f is not None and f.level == FindingLevel.INFO

    def test_browsing_off_is_ok(self):
        snap = CupsSnapshot(cfg_present=True, readable=True,
                            listens_non_loopback=False, browsing_on=False)
        assert "cups.browsing_off" in _keys(check_cups(snap))


# ---------------------------------------------------------------------------
# Loopback detection polarity
# ---------------------------------------------------------------------------

class TestLoopbackDetection:
    def test_loopback_forms(self):
        for v in ("localhost:631", "127.0.0.1:631", "[::1]:631", "::1",
                  "/run/cups/cups.sock"):
            assert _is_loopback_listen(v), v

    def test_network_forms(self):
        for v in ("0.0.0.0:631", "*:631", "192.168.1.5:631", "10.0.0.1"):
            assert not _is_loopback_listen(v), v


# ---------------------------------------------------------------------------
# from_system parsing (exercises _is_loopback_listen through the real path)
# ---------------------------------------------------------------------------

class TestFromSystemParsing:
    def _snap(self, monkeypatch, conf: str) -> CupsSnapshot:
        monkeypatch.setattr(cups_mod, "path_exists", lambda p: True)
        monkeypatch.setattr(cups_mod, "read_text_capped", lambda p, **kw: conf)
        return CupsSnapshot.from_system()

    def test_non_loopback_listen_is_detected(self, monkeypatch):
        """The mutation guard: parsing a 0.0.0.0 Listen must flag exposure."""
        snap = self._snap(monkeypatch, "Listen 0.0.0.0:631\nBrowsing Off\n")
        assert snap.listens_non_loopback is True

    def test_localhost_listen_not_flagged(self, monkeypatch):
        snap = self._snap(monkeypatch,
                          "Listen localhost:631\nListen /run/cups/cups.sock\n")
        assert snap.listens_non_loopback is False

    def test_bare_port_is_exposure(self, monkeypatch):
        snap = self._snap(monkeypatch, "Port 631\n")
        assert snap.listens_non_loopback is True

    def test_commented_listen_ignored(self, monkeypatch):
        snap = self._snap(monkeypatch,
                          "Listen localhost:631\n# Listen 0.0.0.0:631\n")
        assert snap.listens_non_loopback is False

    def test_browsing_on_parsed(self, monkeypatch):
        snap = self._snap(monkeypatch, "Listen localhost:631\nBrowsing On\n")
        assert snap.browsing_on is True
