"""v0.42.0 — package integrity on apt without debsums: dpkg --verify (B-042).

Found on the developer's workstation audit under 0.40.0 (21 November 2026):
debsums was not installed, so the section stayed unread and the score a
ceiling (≤ 9/10), while BOB's own AIDE text recommends ``dpkg --verify`` —
the verifier dpkg ships. It now steps in when debsums is missing.

Measured on the test Mint (dpkg 1.22.6, 2025 packages): 499 s, exit 0, the
25 lines below. Kept: the 21 digest mismatches outside /etc — Mint's own
changes to files under /usr, the same 21 that 0.32.0 measured with debsums.
Left out, as debsums -c leaves them out: configuration files (``c``), /etc,
and ``missing`` rows. The section stays INFO: nothing is counted.
"""

from __future__ import annotations

import pytest

from bob.checks import package_integrity as P
from bob.visibility import VISIBILITY_KEYS

#: ``dpkg --verify`` on the test Mint, 21 November 2026, as printed.
MEASURED = (
    '??5??????   /usr/lib/firefox/distribution/distribution.ini\n'
    '??5??????   /usr/share/applications/libreoffice-draw.desktop\n'
    '??5?????? c /etc/iproute2/rt_tables\n'
    '??5??????   /usr/share/applications/yelp.desktop\n'
    'missing     /etc/apparmor.d/disable\n'
    'missing   c /etc/apparmor.d/nautilus\n'
    '??5??????   /usr/share/icons/HighContrast/16x16/places/start-here.png\n'
    '??5??????   /usr/share/icons/HighContrast/22x22/places/start-here.png\n'
    '??5??????   /usr/share/icons/HighContrast/24x24/places/start-here.png\n'
    '??5??????   /usr/share/icons/HighContrast/32x32/places/start-here.png\n'
    '??5??????   /usr/share/icons/HighContrast/48x48/places/start-here.png\n'
    '??5??????   /usr/share/icons/HighContrast/scalable/places/start-here.svg\n'
    '??5??????   /usr/share/icons/Yaru/16x16/places/start-here.png\n'
    '??5??????   /usr/share/icons/Yaru/22x22/places/start-here.png\n'
    '??5??????   /usr/share/icons/Yaru/24x24/places/start-here.png\n'
    '??5??????   /usr/share/icons/Yaru/32x32/places/start-here.png\n'
    '??5??????   /usr/share/icons/Yaru/48x48/places/start-here.png\n'
    '??5??????   /usr/share/applications/im-config.desktop\n'
    '??5??????   /usr/share/cups/data/default-testpage.pdf\n'
    '??5??????   /usr/share/sounds/freedesktop/stereo/device-added.oga\n'
    '??5??????   /usr/share/sounds/freedesktop/stereo/device-removed.oga\n'
    '??5??????   /usr/share/applications/org.freedesktop.IBus.Setup.desktop\n'
    '??5??????   /usr/share/applications/info.desktop\n'
    '??5?????? c /etc/cryptsetup-initramfs/conf-hook\n'
    '??5??????   /usr/share/applications/mate-color-select.desktop\n'
)


def test_the_measured_output_gives_the_21_files():
    changed = P._parse_dpkg_verify(MEASURED)
    assert len(changed) == 21
    assert all(p.startswith("/usr/") for p in changed)
    assert "/usr/lib/firefox/distribution/distribution.ini" in changed


@pytest.mark.parametrize("line", [
    "??5?????? c /etc/iproute2/rt_tables\n",         # a configuration file
    "??5?????? c /usr/share/foo/defaults.conf\n",   # a configuration file outside /etc
    "missing     /usr/bin/gone\n",                     # missing, outside /etc
    "missing     /etc/apparmor.d/disable\n",           # missing
    "missing   c /etc/apparmor.d/nautilus\n",
    "??5??????   /etc/ssh/moduli\n",                   # /etc, an admin edit
    "?????????   /usr/bin/ls\n",                       # no digest mismatch
])
def test_what_is_left_out(line):
    assert P._parse_dpkg_verify(line) == []


def _snapshot(monkeypatch, tools, run):
    monkeypatch.setattr(P, "detect_install_manager", lambda: "apt")
    monkeypatch.setattr(P, "_command_exists", lambda name: name in tools)
    calls = []
    def fake_run(args):
        calls.append(args)
        return run
    monkeypatch.setattr(P, "_run_capped", fake_run)
    # v0.43.0 — the no-digest count reads the host's dpkg database; held out,
    # so this test does not depend on the packages of the machine it runs on.
    monkeypatch.setattr(P, "_dpkg_undigested", lambda *a: {})
    return P.PackageIntegritySnapshot.from_system(), calls


def test_without_debsums_dpkg_verifies(monkeypatch):
    snap, calls = _snapshot(monkeypatch, {"dpkg"}, (MEASURED, True, False, True))
    assert calls == [("dpkg", "--verify")]
    assert snap.tool == "dpkg" and snap.ran and len(snap.changed_files) == 21
    keys = {f.key for f in P.check_package_integrity(snap).findings}
    assert keys == {"package_integrity.changed"}


def test_debsums_is_still_preferred(monkeypatch):
    snap, calls = _snapshot(monkeypatch, {"dpkg", "debsums"}, ("", True, False, True))
    assert calls == [("debsums", "-c")] and snap.tool == "debsums"


def test_a_failed_dpkg_is_not_verified_never_clean(monkeypatch):
    snap, _ = _snapshot(monkeypatch, {"dpkg"}, ("", False, False, True))
    keys = {f.key for f in P.check_package_integrity(snap).findings}
    assert keys == {"package_integrity.verifier_failed"}
    assert "package_integrity.verifier_failed" in VISIBILITY_KEYS


def test_dpkg_with_differences_exits_0_and_is_read(monkeypatch):
    """Measured: exit 0 with 25 lines — a zero exit is not "nothing found"."""
    snap, _ = _snapshot(monkeypatch, {"dpkg"}, (MEASURED, True, False, True))
    assert not snap.failed and snap.changed_files
