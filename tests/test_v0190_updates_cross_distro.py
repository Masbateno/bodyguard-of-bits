"""v0.19.0 — the updates check works on dnf/zypper/pacman/apk, not just apt.

Field-tested on real Fedora 43, openSUSE Leap 15.6, Alpine 3.22 and Arch VMs:
the check was apt-only (`if not apt-get: return`), so on 4 of the 5 distro
families it reported "no apt" and was blind — a Fedora host with 242 pending
updates got a clean-ish verdict. The fixtures below are the *actual* command
output captured on those VMs, so the parsers are pinned against reality.

Managers with a security channel (apt, dnf, zypper) can raise the −2 security
deduction; those without one (pacman, apk) report every pending package as
regular (INFO), because BOB does not invent a severity the tool cannot supply.
"""

from __future__ import annotations

import bob.checks.updates as U
from bob.checks.updates import (
    UpdatesSnapshot,
    check_updates,
    _collect_dnf,
    _collect_zypper,
    _collect_pacman,
    _collect_apk,
    _upgrade_cmd,
)

# --- real command output captured on the VMs (2026-09-13) -------------------

_DNF_CHECKUPDATE = """\
NetworkManager.x86_64                1:1.54.3-3.fc43            updates
audit.x86_64                         4.2.1-1.fc43              updates
btrfs-progs.x86_64                   7.1-1.fc43                updates

Obsoleting Packages
somepkg.noarch                       2.0-1.fc43               updates
"""

_DNF_SECURITY = """\
Name                   Type     Severity            Package                        Issued
FEDORA-2026-00b3d3d018 security Moderate  openssl-1:3.5.8-1.fc43.x86_64 2026-09-10 01:12:46
FEDORA-2025-d93200cf16 security Important libbrotli-1.2.0-1.fc43.x86_64 2025-12-12 01:32:22
FEDORA-2025-d93200cf16 security Important python3-urllib3-2.6.1-1.fc43.noarch 2025-12-12 01:32:22
"""

_ZYPPER_UPDATES = """\
S  | Repository | Name                   | Current Version | Available Version | Arch
---+------------+------------------------+-----------------+-------------------+-------
v  | SLE 15     | cloud-init             | 23.3-lp156.3.9  | 25.1.3-150400     | x86_64
v  | SLE 15     | kernel-default-base    | 6.4.0-1         | 6.4.0-2           | x86_64
"""

_ZYPPER_SECURITY = """\
Repository | Name                        | Category | Severity  | Interactive | Status | Since | Summary
-----------+-----------------------------+----------+-----------+-------------+--------+-------+--------
SLE 15     | openSUSE-SLE-15.6-2026-1840 | security | important | reboot      | needed | -      | kernel
3 patches needed (3 security patches)
"""

_APK = """\
Installed:                                Available:
alpine-base-3.22.1-r0                   < 3.22.5-r0
apk-tools-2.14.9-r2                     < 2.14.10-r0
python3-urllib3+socks-1.0-r0            < 1.1-r0
"""

_PACMAN = """\
archlinux-keyring 20260727-1 -> 20260909-1
curl 8.21.0-1 -> 8.22.0-1
"""


def _fake_run(mapping):
    """Return a _run stand-in that dispatches on the command + subcommand."""
    def run(*args, **kwargs):
        key = " ".join(args)
        for needle, out in mapping.items():
            if needle in key:
                return out
        return ""
    return run


class TestDnfParser:
    def test_security_and_regular_split(self, monkeypatch):
        monkeypatch.setattr(U, "_run", _fake_run({
            "updateinfo": _DNF_SECURITY, "check-update": _DNF_CHECKUPDATE,
        }))
        sec, reg = _collect_dnf()
        assert set(sec) == {"openssl", "libbrotli", "python3-urllib3"}
        # NetworkManager/audit/btrfs-progs are regular; Obsoleting section skipped
        assert "NetworkManager" in reg and "audit" in reg and "btrfs-progs" in reg
        assert "somepkg" not in reg   # under "Obsoleting Packages"


class TestZypperParser:
    def test_security_patches_and_updates(self, monkeypatch):
        monkeypatch.setattr(U, "_run", _fake_run({
            "list-patches": _ZYPPER_SECURITY, "list-updates": _ZYPPER_UPDATES,
        }))
        sec, reg = _collect_zypper()
        assert sec == ["openSUSE-SLE-15.6-2026-1840"]
        assert set(reg) == {"cloud-init", "kernel-default-base"}


class TestNoSecurityChannel:
    def test_apk_all_regular(self, monkeypatch):
        monkeypatch.setattr(U, "_run", _fake_run({"version": _APK}))
        sec, reg = _collect_apk()
        assert sec == []
        assert set(reg) == {"alpine-base", "apk-tools", "python3-urllib3+socks"}

    def test_pacman_all_regular(self, monkeypatch):
        monkeypatch.setattr(U, "_run", _fake_run({"-Qu": _PACMAN}))
        sec, reg = _collect_pacman()
        assert sec == []
        assert set(reg) == {"archlinux-keyring", "curl"}


class TestDispatch:
    def _only(self, *names):
        s = set(names)
        return lambda c: c in s

    def test_from_system_picks_dnf(self, monkeypatch):
        monkeypatch.setattr(U, "_command_exists", self._only("dnf"))
        monkeypatch.setattr(U, "_collect_dnf", lambda: (["openssl"], ["curl"]))
        snap = UpdatesSnapshot.from_system()
        assert snap.manager == "dnf" and snap.apt_available is False
        assert snap.pending_security == ["openssl"]

    def test_apt_still_wins_when_present(self, monkeypatch):
        monkeypatch.setattr(U, "_command_exists", self._only("apt-get", "dnf"))
        monkeypatch.setattr(U, "_collect_pending_updates", lambda: ([], []))
        monkeypatch.setattr(U, "_check_unattended", lambda: (True, True))
        monkeypatch.setattr(U, "_apt_cache_age_days", lambda: 0)
        monkeypatch.setattr(U, "_count_upgradable", lambda: 0)
        snap = UpdatesSnapshot.from_system()
        assert snap.manager == "apt" and snap.apt_available is True


class TestCheckAcrossManagers:
    def test_dnf_security_deducts_with_dnf_fix(self):
        snap = UpdatesSnapshot(manager="dnf", pending_security=["openssl"])
        r = check_updates(snap)
        keys = [f.key for f in r.findings]
        assert "updates.security_pending" in keys
        assert sum(d.points for d in r.deductions) == 2
        cmd = next(f.cmd for f in r.findings if f.key == "updates.security_pending")
        assert cmd == "sudo dnf upgrade --security -y"

    def test_pacman_regular_is_info_no_deduction(self):
        snap = UpdatesSnapshot(manager="pacman", pending_regular=["curl", "expat"])
        r = check_updates(snap)
        keys = [f.key for f in r.findings]
        assert "updates.regular_pending" in keys
        assert "updates.security_pending" not in keys
        assert r.deductions == []

    def test_no_manager_says_no_apt(self):
        snap = UpdatesSnapshot()   # manager="", apt_available=False
        r = check_updates(snap)
        assert r.findings[0].key == "updates.no_apt"

    def test_non_apt_skips_unattended_and_cache(self):
        """The apt-only extras must not fire on a dnf host."""
        snap = UpdatesSnapshot(manager="dnf", pending_regular=["curl"])
        keys = [f.key for f in check_updates(snap).findings]
        assert "updates.unattended_not_configured" not in keys
        assert "updates.apt_cache_age" not in keys
        assert "updates.apt_cache_stale" not in keys


def test_upgrade_cmd_per_manager():
    assert _upgrade_cmd("apt").startswith("sudo apt-get upgrade")
    assert _upgrade_cmd("dnf") == "sudo dnf upgrade --security -y"
    assert _upgrade_cmd("zypper") == "sudo zypper patch --category security -y"
    assert _upgrade_cmd("pacman") == "sudo pacman -Syu"
    assert _upgrade_cmd("apk") == "sudo apk upgrade"
