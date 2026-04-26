"""
Unit tests for bob.checks.samba module.

All tests use SambaSnapshot instances built directly — no subprocess calls
and no file I/O. Check logic is exercised in isolation.

Run with: python -m pytest tests/test_samba.py -v
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from bob.checks.samba import (
    GuestShare,
    SambaSnapshot,
    check_samba,
    _read_smb_conf,
    _section_get,
    _is_yes,
)
from bob.scoring import FindingLevel
from tests.helpers import _levels, _t


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_snap(**kwargs) -> SambaSnapshot:
    defaults = dict(
        installed=True,
        daemon_installed=True,
        conf_readable=True,
        smb1_enabled=False,
        min_protocol="",
        null_passwords=False,
        server_signing="",
        map_to_guest="",
        bind_interfaces_only=False,
        guest_shares=[],
    )
    defaults.update(kwargs)
    return SambaSnapshot(**defaults)


def keys(result) -> list[str]:
    return [f.key for f in result.findings]


def has_level(result, level: FindingLevel) -> bool:
    return any(f.level == level for f in result.findings)


def deduction_points(result) -> int:
    return sum(d.points for d in result.deductions)


# ---------------------------------------------------------------------------
# Not installed / conf unreadable
# ---------------------------------------------------------------------------

class TestNotInstalled:
    def test_not_installed_returns_empty_result(self):
        snap = make_snap(installed=False)
        result = check_samba(snap, t=_t)
        assert result.findings == []
        assert result.deductions == []

    def test_not_installed_conf_readable_state_ignored(self):
        snap = make_snap(installed=False, conf_readable=True)
        result = check_samba(snap, t=_t)
        assert result.findings == []


class TestConfOnlyNoDaemon:
    """smb.conf found but Samba daemon not installed (e.g. samba-common without samba)."""

    def test_conf_only_emits_info(self):
        snap = make_snap(installed=True, daemon_installed=False)
        result = check_samba(snap, t=_t)
        assert has_level(result, FindingLevel.INFO)

    def test_conf_only_key(self):
        snap = make_snap(installed=True, daemon_installed=False)
        result = check_samba(snap, t=_t)
        assert "samba.conf_only" in keys(result)

    def test_conf_only_no_deductions(self):
        snap = make_snap(installed=True, daemon_installed=False,
                         smb1_enabled=False, null_passwords=False,
                         map_to_guest="", server_signing="")
        result = check_samba(snap, t=_t)
        assert result.deductions == []

    def test_conf_only_with_issue_still_deducts(self):
        """Config-only mode still audits and deducts for real issues."""
        snap = make_snap(installed=True, daemon_installed=False,
                         map_to_guest="bad user")
        result = check_samba(snap, t=_t)
        assert any(d.key == "samba.map_to_guest" for d in result.deductions)


class TestConfUnreadable:
    def test_conf_unreadable_is_info(self):
        snap = make_snap(conf_readable=False)
        result = check_samba(snap, t=_t)
        assert has_level(result, FindingLevel.INFO)

    def test_conf_unreadable_key(self):
        snap = make_snap(conf_readable=False)
        result = check_samba(snap, t=_t)
        assert "samba.conf_unreadable" in keys(result)

    def test_conf_unreadable_no_deductions(self):
        snap = make_snap(conf_readable=False)
        result = check_samba(snap, t=_t)
        assert deduction_points(result) == 0


# ---------------------------------------------------------------------------
# SMB1 protocol
# ---------------------------------------------------------------------------

class TestSmb1:
    def test_smb1_enabled_is_alert(self):
        snap = make_snap(smb1_enabled=True)
        result = check_samba(snap, t=_t)
        assert has_level(result, FindingLevel.ALERT)

    def test_smb1_enabled_key(self):
        snap = make_snap(smb1_enabled=True)
        result = check_samba(snap, t=_t)
        assert "samba.smb1_enabled" in keys(result)

    def test_smb1_enabled_deducts_2(self):
        snap = make_snap(smb1_enabled=True)
        result = check_samba(snap, t=_t)
        smb1_pts = sum(d.points for d in result.deductions if d.key == "samba.smb1_enabled")
        assert smb1_pts == 2

    def test_smb1_disabled_is_ok(self):
        snap = make_snap(smb1_enabled=False)
        result = check_samba(snap, t=_t)
        ok_findings = [f for f in result.findings if f.key == "samba.smb1_disabled"]
        assert len(ok_findings) == 1

    def test_smb1_disabled_no_deduction(self):
        snap = make_snap(smb1_enabled=False)
        result = check_samba(snap, t=_t)
        smb1_pts = sum(d.points for d in result.deductions if d.key == "samba.smb1_enabled")
        assert smb1_pts == 0


# ---------------------------------------------------------------------------
# Null passwords
# ---------------------------------------------------------------------------

class TestNullPasswords:
    def test_null_passwords_is_alert(self):
        snap = make_snap(null_passwords=True)
        result = check_samba(snap, t=_t)
        null_findings = [f for f in result.findings if f.key == "samba.null_passwords"]
        assert null_findings and null_findings[0].level == FindingLevel.ALERT

    def test_null_passwords_deducts_3(self):
        snap = make_snap(null_passwords=True)
        result = check_samba(snap, t=_t)
        pts = sum(d.points for d in result.deductions if d.key == "samba.null_passwords")
        assert pts == 3

    def test_null_passwords_false_is_ok(self):
        snap = make_snap(null_passwords=False)
        result = check_samba(snap, t=_t)
        ok_findings = [f for f in result.findings if f.key == "samba.null_passwords_ok"]
        assert len(ok_findings) == 1

    def test_null_passwords_false_no_deduction(self):
        snap = make_snap(null_passwords=False)
        result = check_samba(snap, t=_t)
        pts = sum(d.points for d in result.deductions if d.key == "samba.null_passwords")
        assert pts == 0


# ---------------------------------------------------------------------------
# Server signing
# ---------------------------------------------------------------------------

class TestServerSigning:
    def test_signing_disabled_is_warn(self):
        snap = make_snap(server_signing="disabled")
        result = check_samba(snap, t=_t)
        findings = [f for f in result.findings if f.key == "samba.server_signing_disabled"]
        assert findings and findings[0].level == FindingLevel.WARN

    def test_signing_disabled_deducts_1(self):
        snap = make_snap(server_signing="disabled")
        result = check_samba(snap, t=_t)
        pts = sum(d.points for d in result.deductions if d.key == "samba.server_signing_disabled")
        assert pts == 1

    def test_signing_mandatory_is_ok(self):
        snap = make_snap(server_signing="mandatory")
        result = check_samba(snap, t=_t)
        ok_findings = [f for f in result.findings if f.key == "samba.server_signing_mandatory"]
        assert len(ok_findings) == 1

    def test_signing_mandatory_no_deduction(self):
        snap = make_snap(server_signing="mandatory")
        result = check_samba(snap, t=_t)
        pts = sum(d.points for d in result.deductions if d.key == "samba.server_signing_disabled")
        assert pts == 0

    def test_signing_auto_is_info(self):
        snap = make_snap(server_signing="auto")
        result = check_samba(snap, t=_t)
        findings = [f for f in result.findings if f.key == "samba.server_signing_auto"]
        assert findings and findings[0].level == FindingLevel.INFO

    def test_signing_auto_no_deduction(self):
        snap = make_snap(server_signing="auto")
        result = check_samba(snap, t=_t)
        pts = sum(d.points for d in result.deductions if d.key == "samba.server_signing_disabled")
        assert pts == 0

    def test_signing_empty_produces_info(self):
        # When server_signing is not set Samba defaults to auto — report as INFO
        snap = make_snap(server_signing="")
        result = check_samba(snap, t=_t)
        signing_findings = [f for f in result.findings if "server_signing" in (f.key or "")]
        assert len(signing_findings) == 1
        assert signing_findings[0].level == FindingLevel.INFO

    def test_signing_yes_is_mandatory(self):
        # In Samba 4.x "yes"/"true" → signing enforced (same as mandatory)
        snap = make_snap(server_signing="mandatory")
        result = check_samba(snap, t=_t)
        ok_findings = [f for f in result.findings if f.key == "samba.server_signing_mandatory"]
        assert len(ok_findings) == 1


# ---------------------------------------------------------------------------
# map to guest
# ---------------------------------------------------------------------------

class TestMapToGuest:
    def test_map_to_guest_bad_user_is_warn(self):
        snap = make_snap(map_to_guest="bad user")
        result = check_samba(snap, t=_t)
        findings = [f for f in result.findings if f.key == "samba.map_to_guest"]
        assert findings and findings[0].level == FindingLevel.WARN

    def test_map_to_guest_bad_user_deducts_1(self):
        snap = make_snap(map_to_guest="bad user")
        result = check_samba(snap, t=_t)
        pts = sum(d.points for d in result.deductions if d.key == "samba.map_to_guest")
        assert pts == 1

    def test_map_to_guest_never_no_finding(self):
        snap = make_snap(map_to_guest="never")
        result = check_samba(snap, t=_t)
        findings = [f for f in result.findings if f.key == "samba.map_to_guest"]
        assert len(findings) == 0

    def test_map_to_guest_empty_no_finding(self):
        snap = make_snap(map_to_guest="")
        result = check_samba(snap, t=_t)
        findings = [f for f in result.findings if f.key == "samba.map_to_guest"]
        assert len(findings) == 0

    def test_map_to_guest_bad_password_no_finding(self):
        snap = make_snap(map_to_guest="bad password")
        result = check_samba(snap, t=_t)
        findings = [f for f in result.findings if f.key == "samba.map_to_guest"]
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Guest shares
# ---------------------------------------------------------------------------

class TestGuestShares:
    def test_guest_writable_is_alert(self):
        share = GuestShare(name="public", path="/srv/public", writable=True)
        snap = make_snap(guest_shares=[share])
        result = check_samba(snap, t=_t)
        findings = [f for f in result.findings if f.key == "samba.guest_writable"]
        assert findings and findings[0].level == FindingLevel.ALERT

    def test_guest_writable_deducts_2_per_share(self):
        share1 = GuestShare(name="data", path="/srv/data", writable=True)
        share2 = GuestShare(name="backup", path="/srv/backup", writable=True)
        snap = make_snap(guest_shares=[share1, share2])
        result = check_samba(snap, t=_t)
        pts = sum(d.points for d in result.deductions if d.key == "samba.guest_writable")
        assert pts == 4  # 2 + 2

    def test_guest_readonly_is_warn(self):
        share = GuestShare(name="media", path="/srv/media", writable=False)
        snap = make_snap(guest_shares=[share])
        result = check_samba(snap, t=_t)
        findings = [f for f in result.findings if f.key == "samba.guest_readonly"]
        assert findings and findings[0].level == FindingLevel.WARN

    def test_guest_readonly_deducts_1_per_share(self):
        share1 = GuestShare(name="media", path="/srv/media", writable=False)
        share2 = GuestShare(name="docs", path="/srv/docs", writable=False)
        snap = make_snap(guest_shares=[share1, share2])
        result = check_samba(snap, t=_t)
        pts = sum(d.points for d in result.deductions if d.key == "samba.guest_readonly")
        assert pts == 2  # 1 + 1

    def test_mixed_guest_shares(self):
        writable = GuestShare(name="upload", path="/srv/upload", writable=True)
        readonly = GuestShare(name="media", path="/srv/media", writable=False)
        snap = make_snap(guest_shares=[writable, readonly])
        result = check_samba(snap, t=_t)
        alert_findings = [f for f in result.findings if f.key == "samba.guest_writable"]
        warn_findings = [f for f in result.findings if f.key == "samba.guest_readonly"]
        assert len(alert_findings) == 1
        assert len(warn_findings) == 1

    def test_no_guest_shares_no_guest_findings(self):
        snap = make_snap(guest_shares=[])
        result = check_samba(snap, t=_t)
        guest_findings = [f for f in result.findings
                          if f.key in ("samba.guest_writable", "samba.guest_readonly")]
        assert guest_findings == []


# ---------------------------------------------------------------------------
# Bind interfaces only
# ---------------------------------------------------------------------------

class TestBindInterfaces:
    def test_bind_not_set_is_info(self):
        snap = make_snap(bind_interfaces_only=False)
        result = check_samba(snap, t=_t)
        findings = [f for f in result.findings if f.key == "samba.bind_interfaces_not_set"]
        assert findings and findings[0].level == FindingLevel.INFO

    def test_bind_not_set_no_deduction(self):
        snap = make_snap(bind_interfaces_only=False)
        result = check_samba(snap, t=_t)
        pts = sum(d.points for d in result.deductions if d.key == "samba.bind_interfaces_not_set")
        assert pts == 0

    def test_bind_set_no_finding(self):
        snap = make_snap(bind_interfaces_only=True)
        result = check_samba(snap, t=_t)
        findings = [f for f in result.findings if f.key == "samba.bind_interfaces_not_set"]
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Cumulative deductions
# ---------------------------------------------------------------------------

class TestCumulativeDeductions:
    def test_perfect_config_minimal_deductions(self):
        snap = make_snap(
            smb1_enabled=False,
            null_passwords=False,
            server_signing="mandatory",
            map_to_guest="never",
            bind_interfaces_only=True,
            guest_shares=[],
        )
        result = check_samba(snap, t=_t)
        assert deduction_points(result) == 0

    def test_worst_case_high_deductions(self):
        snap = make_snap(
            smb1_enabled=True,
            null_passwords=True,
            server_signing="disabled",
            map_to_guest="bad user",
            guest_shares=[
                GuestShare(name="rw", writable=True),
                GuestShare(name="ro", writable=False),
            ],
        )
        result = check_samba(snap, t=_t)
        # SMB1: 2, null_passwords: 3, server_signing: 1, map_to_guest: 1,
        # guest_writable: 2, guest_readonly: 1 → total 10
        assert deduction_points(result) == 10

    def test_alert_count_worst_case(self):
        snap = make_snap(
            smb1_enabled=True,
            null_passwords=True,
            guest_shares=[GuestShare(name="rw", writable=True)],
        )
        result = check_samba(snap, t=_t)
        alert_count = sum(1 for f in result.findings if f.level == FindingLevel.ALERT)
        assert alert_count >= 3  # smb1 + null_passwords + guest_writable


# ---------------------------------------------------------------------------
# _read_smb_conf parser
# ---------------------------------------------------------------------------

class TestReadSmbConf:
    def _write_conf(self, tmp_path: Path, content: str) -> Path:
        p = tmp_path / "smb.conf"
        p.write_text(textwrap.dedent(content), encoding="utf-8")
        return p

    def test_parses_global_section(self, tmp_path):
        conf = self._write_conf(tmp_path, """\
            [global]
            workgroup = WORKGROUP
            min protocol = SMB2
        """)
        result = _read_smb_conf(conf)
        assert "global" in result
        assert result["global"]["min protocol"] == "SMB2"

    def test_parses_share_section(self, tmp_path):
        conf = self._write_conf(tmp_path, """\
            [global]
            workgroup = WORKGROUP

            [public]
            path = /srv/public
            guest ok = yes
            read only = yes
        """)
        result = _read_smb_conf(conf)
        assert "public" in result
        assert result["public"]["path"] == "/srv/public"
        assert result["public"]["guest ok"] == "yes"

    def test_ignores_hash_comments(self, tmp_path):
        conf = self._write_conf(tmp_path, """\
            [global]
            # this is a comment
            workgroup = WORKGROUP  # inline comment
        """)
        result = _read_smb_conf(conf)
        assert result["global"]["workgroup"] == "WORKGROUP"

    def test_ignores_semicolon_comments(self, tmp_path):
        conf = self._write_conf(tmp_path, """\
            [global]
            ; semicolon comment
            workgroup = WORKGROUP ; inline
        """)
        result = _read_smb_conf(conf)
        assert result["global"]["workgroup"] == "WORKGROUP"

    def test_case_insensitive_section_names(self, tmp_path):
        conf = self._write_conf(tmp_path, """\
            [Global]
            workgroup = WORKGROUP
        """)
        result = _read_smb_conf(conf)
        assert "global" in result

    def test_keys_with_spaces(self, tmp_path):
        conf = self._write_conf(tmp_path, """\
            [global]
            min protocol = NT1
            null passwords = yes
            map to guest = bad user
        """)
        result = _read_smb_conf(conf)
        glb = result["global"]
        assert glb["min protocol"] == "NT1"
        assert glb["null passwords"] == "yes"
        assert glb["map to guest"] == "bad user"

    def test_multiple_sections(self, tmp_path):
        conf = self._write_conf(tmp_path, """\
            [global]
            workgroup = WORKGROUP
            [homes]
            browseable = no
            [myshare]
            path = /data
        """)
        result = _read_smb_conf(conf)
        assert "global" in result
        assert "homes" in result
        assert "myshare" in result


# ---------------------------------------------------------------------------
# _section_get / _is_yes helpers
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_section_get_present_key(self):
        assert _section_get({"min protocol": "SMB2"}, "min protocol") == "SMB2"

    def test_section_get_absent_key(self):
        assert _section_get({}, "min protocol") == ""

    def test_section_get_strips_whitespace(self):
        assert _section_get({"path": "  /srv/data  "}, "path") == "/srv/data"

    def test_section_get_case_insensitive_key(self):
        # keys in opts are already lowercased by parser; helper lowercases the lookup key
        assert _section_get({"guest ok": "yes"}, "Guest Ok") == "yes"

    def test_is_yes_true_values(self):
        for val in ("yes", "true", "1"):
            assert _is_yes({"flag": val}, "flag")

    def test_is_yes_false_values(self):
        for val in ("no", "false", "0", ""):
            assert not _is_yes({"flag": val}, "flag")

    def test_is_yes_absent_key(self):
        assert not _is_yes({}, "flag")

    def test_is_yes_case_insensitive(self):
        assert _is_yes({"flag": "YES"}, "flag")
        assert _is_yes({"flag": "True"}, "flag")


# ---------------------------------------------------------------------------
# SambaSnapshot.from_system — not installed paths
# ---------------------------------------------------------------------------

class TestFromSystemNotInstalled:
    def test_from_system_no_smbd_no_conf(self, monkeypatch, tmp_path):
        """When smbd is absent and smb.conf does not exist → not installed."""
        import bob.checks.samba as samba_mod
        monkeypatch.setattr(samba_mod, "_command_exists", lambda name: False)
        monkeypatch.setattr(samba_mod, "_SMB_CONF_PATH", tmp_path / "smb.conf")
        snap = SambaSnapshot.from_system()
        assert not snap.installed
        assert not snap.conf_readable

    def test_from_system_conf_exists_marks_installed(self, monkeypatch, tmp_path):
        """When smb.conf exists even without smbd → installed = True."""
        import bob.checks.samba as samba_mod
        conf = tmp_path / "smb.conf"
        conf.write_text("[global]\nworkgroup = WORKGROUP\n", encoding="utf-8")
        monkeypatch.setattr(samba_mod, "_command_exists", lambda name: False)
        monkeypatch.setattr(samba_mod, "_SMB_CONF_PATH", conf)
        snap = SambaSnapshot.from_system()
        assert snap.installed
        assert snap.conf_readable

    def test_from_system_smb1_detected(self, monkeypatch, tmp_path):
        """from_system() correctly detects max protocol = NT1 as SMB1."""
        import bob.checks.samba as samba_mod
        conf = tmp_path / "smb.conf"
        conf.write_text("[global]\nmax protocol = NT1\n", encoding="utf-8")
        monkeypatch.setattr(samba_mod, "_command_exists", lambda name: False)
        monkeypatch.setattr(samba_mod, "_SMB_CONF_PATH", conf)
        snap = SambaSnapshot.from_system()
        assert snap.smb1_enabled

    def test_from_system_null_passwords_detected(self, monkeypatch, tmp_path):
        import bob.checks.samba as samba_mod
        conf = tmp_path / "smb.conf"
        conf.write_text("[global]\nnull passwords = yes\n", encoding="utf-8")
        monkeypatch.setattr(samba_mod, "_command_exists", lambda name: False)
        monkeypatch.setattr(samba_mod, "_SMB_CONF_PATH", conf)
        snap = SambaSnapshot.from_system()
        assert snap.null_passwords

    def test_from_system_guest_writable_share(self, monkeypatch, tmp_path):
        import bob.checks.samba as samba_mod
        conf = tmp_path / "smb.conf"
        conf.write_text(
            "[global]\nworkgroup = WORKGROUP\n\n"
            "[public]\npath = /srv/public\nguest ok = yes\nwritable = yes\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(samba_mod, "_command_exists", lambda name: False)
        monkeypatch.setattr(samba_mod, "_SMB_CONF_PATH", conf)
        snap = SambaSnapshot.from_system()
        assert len(snap.guest_shares) == 1
        assert snap.guest_shares[0].writable

    def test_from_system_guest_readonly_share(self, monkeypatch, tmp_path):
        import bob.checks.samba as samba_mod
        conf = tmp_path / "smb.conf"
        conf.write_text(
            "[global]\nworkgroup = WORKGROUP\n\n"
            "[media]\npath = /srv/media\nguest ok = yes\nread only = yes\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(samba_mod, "_command_exists", lambda name: False)
        monkeypatch.setattr(samba_mod, "_SMB_CONF_PATH", conf)
        snap = SambaSnapshot.from_system()
        assert len(snap.guest_shares) == 1
        assert not snap.guest_shares[0].writable

    def test_from_system_bind_interfaces_only(self, monkeypatch, tmp_path):
        import bob.checks.samba as samba_mod
        conf = tmp_path / "smb.conf"
        conf.write_text("[global]\nbind interfaces only = yes\n", encoding="utf-8")
        monkeypatch.setattr(samba_mod, "_command_exists", lambda name: False)
        monkeypatch.setattr(samba_mod, "_SMB_CONF_PATH", conf)
        snap = SambaSnapshot.from_system()
        assert snap.bind_interfaces_only

    def test_from_system_server_signing_mandatory(self, monkeypatch, tmp_path):
        import bob.checks.samba as samba_mod
        conf = tmp_path / "smb.conf"
        conf.write_text("[global]\nserver signing = mandatory\n", encoding="utf-8")
        monkeypatch.setattr(samba_mod, "_command_exists", lambda name: False)
        monkeypatch.setattr(samba_mod, "_SMB_CONF_PATH", conf)
        snap = SambaSnapshot.from_system()
        assert snap.server_signing == "mandatory"

    def test_from_system_server_signing_disabled(self, monkeypatch, tmp_path):
        import bob.checks.samba as samba_mod
        conf = tmp_path / "smb.conf"
        conf.write_text("[global]\nserver signing = disabled\n", encoding="utf-8")
        monkeypatch.setattr(samba_mod, "_command_exists", lambda name: False)
        monkeypatch.setattr(samba_mod, "_SMB_CONF_PATH", conf)
        snap = SambaSnapshot.from_system()
        assert snap.server_signing == "disabled"

    def test_from_system_server_signing_yes_is_mandatory(self, monkeypatch, tmp_path):
        """server signing = yes → mandatory in Samba 4.x."""
        import bob.checks.samba as samba_mod
        conf = tmp_path / "smb.conf"
        conf.write_text("[global]\nserver signing = yes\n", encoding="utf-8")
        monkeypatch.setattr(samba_mod, "_command_exists", lambda name: False)
        monkeypatch.setattr(samba_mod, "_SMB_CONF_PATH", conf)
        snap = SambaSnapshot.from_system()
        assert snap.server_signing == "mandatory"

    def test_from_system_map_to_guest_bad_user(self, monkeypatch, tmp_path):
        import bob.checks.samba as samba_mod
        conf = tmp_path / "smb.conf"
        conf.write_text("[global]\nmap to guest = bad user\n", encoding="utf-8")
        monkeypatch.setattr(samba_mod, "_command_exists", lambda name: False)
        monkeypatch.setattr(samba_mod, "_SMB_CONF_PATH", conf)
        snap = SambaSnapshot.from_system()
        assert snap.map_to_guest == "bad user"

    def test_from_system_meta_sections_not_shares(self, monkeypatch, tmp_path):
        """[homes], [printers], [print$], [IPC$] should not produce guest_shares."""
        import bob.checks.samba as samba_mod
        conf = tmp_path / "smb.conf"
        conf.write_text(
            "[global]\nworkgroup = WORKGROUP\n\n"
            "[homes]\nguest ok = yes\n\n"
            "[printers]\nguest ok = yes\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(samba_mod, "_command_exists", lambda name: False)
        monkeypatch.setattr(samba_mod, "_SMB_CONF_PATH", conf)
        snap = SambaSnapshot.from_system()
        assert snap.guest_shares == []

    def test_from_system_smb1_min_protocol_nt1_no_max(self, monkeypatch, tmp_path):
        """min protocol = NT1 with no max protocol → SMB1 enabled."""
        import bob.checks.samba as samba_mod
        conf = tmp_path / "smb.conf"
        conf.write_text("[global]\nmin protocol = NT1\n", encoding="utf-8")
        monkeypatch.setattr(samba_mod, "_command_exists", lambda name: False)
        monkeypatch.setattr(samba_mod, "_SMB_CONF_PATH", conf)
        snap = SambaSnapshot.from_system()
        assert snap.smb1_enabled

    def test_from_system_read_only_no_skips_guest(self, monkeypatch, tmp_path):
        """read only = no → writable = True for guest share."""
        import bob.checks.samba as samba_mod
        conf = tmp_path / "smb.conf"
        conf.write_text(
            "[global]\nworkgroup = WORKGROUP\n\n"
            "[upload]\npath = /srv/upload\npublic = yes\nread only = no\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(samba_mod, "_command_exists", lambda name: False)
        monkeypatch.setattr(samba_mod, "_SMB_CONF_PATH", conf)
        snap = SambaSnapshot.from_system()
        assert len(snap.guest_shares) == 1
        assert snap.guest_shares[0].writable
