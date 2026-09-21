"""Two accuracy fixes found on a real Kali Linux desktop (192.168.1.19).

#1 — the at-a-glance SSH line lied. ``compute_exposure`` built its SSH summary
from *bad-severity* keys only, so on a LAN/desktop host where password auth is
merely downgraded to INFO the summary fell through to "key-only, root login
disabled" — while ``PasswordAuthentication yes`` was in force. The detailed
finding said the opposite. The glance now distinguishes password-auth-on
(green, but truthful) from a genuinely key-only host, and no longer calls
prohibit-password "disabled".

#2 — a %group NOPASSWD:ALL grant to an empty group read like a live alarm.
Kali ships ``%kali-trusted ALL=(ALL:ALL) NOPASSWD: ALL`` with the group empty:
the grant is real but latent. The finding now says so instead of implying
someone currently holds passwordless root.
"""

from __future__ import annotations

from dataclasses import dataclass

from bob.exposure import ExposureItem, compute_exposure
from bob.scoring import Finding, FindingLevel
from bob.checks.file_perms import (
    FilePermsSnapshot,
    check_file_perms,
    _nopasswd_group,
    _group_has_no_members,
)
from bob.checks.updates import UpdatesSnapshot, check_updates
from bob import i18n


# --- exposure test scaffolding (mirrors tests/test_exposure.py) -------------

def _t(key: str, **kwargs) -> str:
    return key.format(**kwargs) if kwargs else key


class _FakeEngine:
    def __init__(self, *key_level_pairs):
        self.findings = [Finding(level=lvl, message="m", key=k)
                         for k, lvl in key_level_pairs]


@dataclass
class _FakePorts:
    ports: list
    ports_readable: bool = True


def _exposure_item(label: str, *key_level_pairs) -> ExposureItem:
    engine = _FakeEngine(*key_level_pairs)
    items = compute_exposure(engine, _FakePorts(ports=[]),
                             "local", True, "deny", _t)
    for it in items:
        if it.label == label:
            return it
    raise AssertionError(f"no {label} exposure item")


def _ssh_item(*key_level_pairs) -> ExposureItem:
    return _exposure_item("exposure.ssh", *key_level_pairs)


def _updates_item(*key_level_pairs) -> ExposureItem:
    return _exposure_item("exposure.updates", *key_level_pairs)


# ---------------------------------------------------------------------------
# #1 — glance SSH summary is truthful about password auth
# ---------------------------------------------------------------------------

class TestSshGlanceSummary:
    def test_password_on_summary_not_key_only(self):
        """The mutation guard: password auth enabled (INFO) must NOT read as
        'key-only'."""
        item = _ssh_item(("ssh.password_auth", FindingLevel.INFO))
        assert item.color == "ok"
        assert item.detail == "exposure.ssh_ok_password_on"
        assert item.detail != "exposure.ssh_ok"

    def test_no_password_key_is_genuine_key_only(self):
        # nothing about ssh in the findings → truly key-only
        item = _ssh_item()
        assert item.color == "ok"
        assert item.detail == "exposure.ssh_ok"

    def test_password_auth_warn_still_flagged_as_issue(self):
        # public host: password auth is WARN → it is an issue, not a green tick
        item = _ssh_item(("ssh.password_auth", FindingLevel.WARN))
        assert item.color in ("warn", "alert")
        assert "exposure.ssh_password" in item.detail

    def test_root_login_wording_is_restricted_not_disabled(self):
        assert "disabled" not in i18n.t("exposure.ssh_ok")
        assert "restricted" in i18n.t("exposure.ssh_ok")


# ---------------------------------------------------------------------------
# #2 — empty-group NOPASSWD:ALL is reported as latent
# ---------------------------------------------------------------------------

class TestEmptyGroupNopasswd:
    _LINE = "%kali-trusted ALL=(ALL:ALL) NOPASSWD: ALL"

    def test_empty_group_message_says_latent(self):
        """The mutation guard: an empty-group grant must be flagged empty."""
        snap = FilePermsSnapshot(
            sudoers_nopasswd_all=[self._LINE],
            sudoers_nopasswd_empty_groups=["kali-trusted"],
        )
        result = check_file_perms(snap, t=i18n.t)
        msg = next(f.message for f in result.findings
                   if f.key == "file_perms.sudoers_nopasswd_all")
        assert "empty" in msg.lower()
        assert "kali-trusted" in msg

    def test_non_empty_group_uses_plain_message(self):
        snap = FilePermsSnapshot(
            sudoers_nopasswd_all=[self._LINE],
            sudoers_nopasswd_empty_groups=[],   # group has members
        )
        result = check_file_perms(snap, t=i18n.t)
        msg = next(f.message for f in result.findings
                   if f.key == "file_perms.sudoers_nopasswd_all")
        assert "empty" not in msg.lower()

    def test_empty_group_still_warns_and_deducts(self):
        # latent is not harmless — the WARN and its deduction stay
        snap = FilePermsSnapshot(
            sudoers_nopasswd_all=[self._LINE],
            sudoers_nopasswd_empty_groups=["kali-trusted"],
        )
        result = check_file_perms(snap, t=i18n.t)
        assert any(f.key == "file_perms.sudoers_nopasswd_all"
                   and f.level == FindingLevel.WARN for f in result.findings)


class TestNoSecurityChannelUpdates:
    """#3 — a distro with no security channel must not read as 'security à jour'
    while updates are pending (Kali rolling, Arch, Alpine)."""

    def test_no_channel_emits_no_security_channel_finding(self):
        """The mutation guard: no channel + regular pending → the honest key."""
        snap = UpdatesSnapshot(
            manager="apt", apt_available=True,
            pending_security=[], pending_regular=["a", "b", "c"],
            security_channel_present=False,
            unattended_installed=True, unattended_enabled=True,
        )
        keys = {f.key for f in check_updates(snap, t=i18n.t).findings}
        assert "updates.no_security_channel" in keys
        assert "updates.regular_pending" not in keys

    def test_channel_present_keeps_regular_pending(self):
        # Debian/Ubuntu with a clean security channel + regular updates: the
        # security channel IS clean, so "regular pending" (and a green glance)
        # stays correct — this is the regression guard.
        snap = UpdatesSnapshot(
            manager="apt", apt_available=True,
            pending_security=[], pending_regular=["a", "b"],
            security_channel_present=True,
            unattended_installed=True, unattended_enabled=True,
        )
        keys = {f.key for f in check_updates(snap, t=i18n.t).findings}
        assert "updates.regular_pending" in keys
        assert "updates.no_security_channel" not in keys

    def test_glance_no_channel_is_not_a_green_tick(self):
        item = _updates_item(("updates.no_security_channel", FindingLevel.INFO))
        assert item.color == "warn"
        assert item.detail == "exposure.updates_no_channel"
        assert item.detail != "exposure.updates_ok"

    def test_glance_regular_only_stays_up_to_date(self):
        # channel present, only regular pending → security genuinely up to date
        item = _updates_item(("updates.regular_pending", FindingLevel.INFO))
        assert item.color == "ok"
        assert item.detail == "exposure.updates_ok"


class TestNopasswdGroupParsing:
    def test_group_grant_extracts_name(self):
        assert _nopasswd_group("%kali-trusted ALL=(ALL:ALL) NOPASSWD: ALL") == "kali-trusted"

    def test_user_grant_has_no_group(self):
        assert _nopasswd_group("john ALL=(ALL) NOPASSWD:ALL") is None

    def test_leading_whitespace_tolerated(self):
        assert _nopasswd_group("  %wheel ALL=(ALL) NOPASSWD: ALL") == "wheel"

    def test_unresolvable_group_is_not_claimed_empty(self):
        # never claim "empty" on uncertainty — an unknown group resolves False
        assert _group_has_no_members("no-such-group-xyz-42") is False
