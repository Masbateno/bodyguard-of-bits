"""The fallback audit profile is auto-detected: desktop hosts are not over-strict.

Before v0.20.3 the fallback profile was a hardcoded "server". On a real Linux
Mint 22.3 with lightdm active BOB defaulted to server and scored 6/10 where the
desktop profile scores 8/10 — the server profile keeps backup / auditd /
mac_policy at WARN that a desktop legitimately relaxes. `detect_default_profile`
now reads the system's role from systemd (graphical.target or an active
display-manager) and returns "desktop" there, "server" everywhere else.

Detection only *relaxes*: it can pick desktop over the stricter server, never
the reverse, and it is used only as the fallback — an explicit --profile or a
saved one always wins (asserted in the resolver, exercised here at the unit).
"""

from __future__ import annotations

import subprocess

import bob.sysinfo as S


def _fake_systemctl(answers: "dict[tuple, str]", present: bool = True):
    def run(argv, **kwargs):
        if not present:
            raise FileNotFoundError("systemctl")
        key = tuple(argv[1:])  # drop "systemctl"
        return subprocess.CompletedProcess(argv, 0, stdout=answers.get(key, ""), stderr="")
    return run


class TestDesktopAutodetect:
    def test_graphical_target_without_active_dm_is_server(self, monkeypatch):
        # A real headless Ubuntu Server (.14) had get-default == graphical.target
        # with display-manager INACTIVE. graphical.target alone must NOT read as
        # desktop — only an active display-manager does.
        monkeypatch.setattr(S.subprocess, "run", _fake_systemctl({
            ("get-default",): "graphical.target",
            ("is-active", "display-manager.service"): "inactive",
        }))
        assert S.detect_default_profile() == "server"

    def test_active_display_manager_is_desktop(self, monkeypatch):
        monkeypatch.setattr(S.subprocess, "run", _fake_systemctl({
            ("get-default",): "multi-user.target",
            ("is-active", "display-manager.service"): "active",
        }))
        assert S.detect_default_profile() == "desktop"

    def test_multi_user_no_dm_is_server(self, monkeypatch):
        monkeypatch.setattr(S.subprocess, "run", _fake_systemctl({
            ("get-default",): "multi-user.target",
            ("is-active", "display-manager.service"): "inactive",
        }))
        assert S.detect_default_profile() == "server"

    def test_no_systemd_is_server(self, monkeypatch):
        """A host without systemctl cannot be read as desktop — stays server."""
        monkeypatch.setattr(S.subprocess, "run", _fake_systemctl({}, present=False))
        assert S.detect_default_profile() == "server"
