"""firewalld installed-but-stopped must not read as "not installed" in the banner.

On firewalld 2.1.2 (openSUSE Leap 16), `firewall-cmd --version` needs the daemon
and exits non-zero with "FirewallD is not running" when stopped, so BOB's version
probe returned "" and the banner said "firewalld: not installed" — false; the
binary was present (measured in the v0.21.2 field campaign). Presence is now
detected by the client binary, independent of the daemon.
"""

from __future__ import annotations

from bob import sysinfo


class _Empty:
    """A CompletedProcess stand-in: every command yields empty stdout, so no
    version is parsed regardless of what the test host actually has."""
    stdout = ""


def test_firewalld_present_via_binary_when_version_unavailable(monkeypatch):
    monkeypatch.setattr(sysinfo.subprocess, "run", lambda *a, **k: _Empty())
    monkeypatch.setattr(sysinfo.shutil, "which",
                        lambda c: "/usr/bin/firewall-cmd" if c == "firewall-cmd" else None)

    info = sysinfo.collect_system_info(version="t", lang="en")

    assert info.firewalld_version == ""      # version unobtainable (daemon down)
    assert info.firewalld_present is True     # but the binary is there


def test_firewalld_absent_is_not_present(monkeypatch):
    monkeypatch.setattr(sysinfo.subprocess, "run", lambda *a, **k: _Empty())
    monkeypatch.setattr(sysinfo.shutil, "which", lambda c: None)

    info = sysinfo.collect_system_info(version="t", lang="en")

    assert info.firewalld_present is False
