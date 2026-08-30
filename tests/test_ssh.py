"""Unit tests for bob.checks.ssh."""

from __future__ import annotations

import base64
import os
import struct
import types
from pathlib import Path

import pytest

from bob.checks.ssh import (
    AuthorizedKeyEntry,
    ClientConfigEntry,
    HostKeyInfo,
    KnownHostEntry,
    PrivateKeyInfo,
    SSHSnapshot,
    _has_passphrase,
    _parse_authorized_keys,
    _parse_client_config,
    _parse_known_hosts,
    _parse_time_seconds,
    _rsa_bits_from_blob,
    check_ssh,
)
from bob.scoring import FindingLevel
from tests.helpers import _deduction_keys, _deduction_points, _has_finding

# Default LoginGraceTime used by _parse_time_seconds on invalid input
_DEFAULT_GRACE_SECS = 120


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _levels(result):
    return [f.level for f in result.findings]


def _keys(result):
    return [f.key for f in result.findings]


def _make_rsa_blob(bits: int) -> str:
    """Construct a minimal but structurally valid SSH RSA public key base64 blob.

    The modulus is prefixed with a 0x00 SSH MPInt sign byte (convention for positive
    integers whose high bit would otherwise indicate a negative number).
    _rsa_bits_from_blob skips leading zero bytes when computing the bit count, so
    _make_rsa_blob(2048) correctly yields 2048 bits.
    """
    ktype    = b"ssh-rsa"
    exponent = b"\x01\x00\x01"                  # 65537
    modulus  = b"\x00" + b"\xff" * (bits // 8)  # MPInt sign byte + actual modulus bytes
    blob = (
        struct.pack(">I", len(ktype))    + ktype    +
        struct.pack(">I", len(exponent)) + exponent +
        struct.pack(">I", len(modulus))  + modulus
    )
    return base64.b64encode(blob).decode()


def base_snapshot(**kwargs) -> SSHSnapshot:
    """Return a minimal snapshot with sshd installed and active.

    All list-type fields are explicitly initialised to [] so that tests are
    unaffected by future changes to SSHSnapshot field defaults.
    """
    defaults = dict(
        sshd_installed=True,
        sshd_active=True,
        sshd_config={},
        sudo_user="testuser",
        user_home=Path("/home/testuser"),
        ssh_dir_exists=False,
        private_keys=[],
        authorized_keys_exists=False,
        authorized_keys_perms=None,
        authorized_keys_entries=[],
        client_config_exists=False,
        client_config_entries=[],
        known_hosts_exists=False,
        known_hosts_entries=[],
        host_keys=[],
        install_cmd="",
    )
    defaults.update(kwargs)
    return SSHSnapshot(**defaults)


def _make_host_key(key_type: str, rsa_bits: int = None, name: str = None) -> HostKeyInfo:
    if name is None:
        name = f"ssh_host_{key_type}_key"
    return HostKeyInfo(
        path=Path(f"/etc/ssh/{name}"),
        key_type=key_type,
        rsa_bits=rsa_bits,
    )


# ---------------------------------------------------------------------------
# 1. SSH not installed / not active
# ---------------------------------------------------------------------------

class TestSSHPresence:
    def test_not_installed_returns_info(self):
        snap = base_snapshot(sshd_installed=False)
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.not_installed", FindingLevel.INFO)

    def test_not_installed_returns_early(self):
        snap = base_snapshot(sshd_installed=False)
        result = check_ssh(snap)
        # Only one finding (the not_installed info) — check returns early
        assert len(result.findings) == 1

    def test_not_active_returns_warn(self):
        snap = base_snapshot(sshd_active=False, ssh_dir_exists=False)
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.not_active", FindingLevel.WARN)

    def test_active_returns_ok(self):
        snap = base_snapshot()
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.active", FindingLevel.OK)


# ---------------------------------------------------------------------------
# 2. sshd_config — critical directives
# ---------------------------------------------------------------------------

class TestSshdConfig:
    def test_permit_root_login_yes_is_alert(self):
        snap = base_snapshot(sshd_config={"permitrootlogin": "yes"})
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.permit_root_login", FindingLevel.ALERT)

    def test_permit_root_login_yes_deduction(self):
        snap = base_snapshot(sshd_config={"permitrootlogin": "yes"})
        result = check_ssh(snap)
        assert "ssh.permit_root_login" in _deduction_keys(result)

    def test_permit_root_login_no_no_alert(self):
        snap = base_snapshot(sshd_config={"permitrootlogin": "no"})
        result = check_ssh(snap)
        assert not _has_finding(result, "ssh.permit_root_login", FindingLevel.ALERT)

    def test_permit_root_login_no_is_ok(self):
        snap = base_snapshot(sshd_config={"permitrootlogin": "no"})
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.permit_root_login_disabled", FindingLevel.OK)

    def test_permit_root_login_prohibit_password_is_ok(self):
        snap = base_snapshot(sshd_config={"permitrootlogin": "prohibit-password"})
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.permit_root_login_restricted", FindingLevel.OK)

    def test_permit_root_login_forced_commands_is_ok(self):
        snap = base_snapshot(sshd_config={"permitrootlogin": "forced-commands-only"})
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.permit_root_login_restricted", FindingLevel.OK)

    def test_permit_root_login_default_is_ok(self):
        """Default (key absent) → prohibit-password → OK."""
        snap = base_snapshot(sshd_config={})
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.permit_root_login_restricted", FindingLevel.OK)

    def test_permit_root_login_no_deduction_when_ok(self):
        snap = base_snapshot(sshd_config={"permitrootlogin": "no"})
        result = check_ssh(snap)
        assert "ssh.permit_root_login" not in _deduction_keys(result)

    def test_permit_root_login_unknown_value_is_info(self):
        # NB: this used to use "without-password" as its example of an unknown
        # value, which encoded a v0.15.0 bug as expected behaviour — that is the
        # pre-6.7 spelling of "prohibit-password" and OpenSSH accepts it. Use a
        # value sshd would genuinely reject.
        snap = base_snapshot(sshd_config={"permitrootlogin": "banana"})
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.permit_root_login", FindingLevel.INFO)

    def test_permit_root_login_without_password_is_restricted(self):
        """`without-password` == `prohibit-password` (OpenSSH < 6.7 spelling)."""
        snap = base_snapshot(sshd_config={"permitrootlogin": "without-password"})
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.permit_root_login_restricted", FindingLevel.OK)
        assert "ssh.permit_root_login" not in _deduction_keys(result)

    def test_password_auth_yes_is_warn(self):
        snap = base_snapshot(sshd_config={"passwordauthentication": "yes"})
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.password_auth", FindingLevel.WARN)

    def test_password_auth_no_no_warn(self):
        snap = base_snapshot(sshd_config={"passwordauthentication": "no"})
        result = check_ssh(snap)
        assert not _has_finding(result, "ssh.password_auth", FindingLevel.WARN)

    def test_permit_empty_passwords_is_alert(self):
        snap = base_snapshot(sshd_config={"permitemptypasswords": "yes"})
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.permit_empty_passwords", FindingLevel.ALERT)
        assert "ssh.permit_empty_passwords" in _deduction_keys(result)

    def test_max_auth_tries_high_is_warn(self):
        snap = base_snapshot(sshd_config={"maxauthtries": "6"})
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.max_auth_tries", FindingLevel.WARN)

    def test_max_auth_tries_low_no_warn(self):
        snap = base_snapshot(sshd_config={"maxauthtries": "3"})
        result = check_ssh(snap)
        assert not _has_finding(result, "ssh.max_auth_tries", FindingLevel.WARN)

    def test_x11_forwarding_warn(self):
        snap = base_snapshot(sshd_config={"x11forwarding": "yes"})
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.x11.forwarding.server", FindingLevel.WARN)
        assert "ssh.x11.forwarding.server" in _deduction_keys(result)

    def test_ignore_rhosts_disabled_warn(self):
        snap = base_snapshot(sshd_config={"ignorerhosts": "no"})
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.ignore_rhosts_disabled", FindingLevel.WARN)
        assert "ssh.ignore_rhosts_disabled" in _deduction_keys(result)

    def test_host_based_auth_alert(self):
        snap = base_snapshot(sshd_config={"hostbasedauthentication": "yes"})
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.host_based_auth", FindingLevel.ALERT)
        assert "ssh.host_based_auth" in _deduction_keys(result)

    def test_strict_modes_disabled_warn(self):
        snap = base_snapshot(sshd_config={"strictmodes": "no"})
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.strict_modes_disabled", FindingLevel.WARN)
        assert "ssh.strict_modes_disabled" in _deduction_keys(result)

    def test_permit_user_env_warn(self):
        snap = base_snapshot(sshd_config={"permituserenvironment": "yes"})
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.permit_user_env", FindingLevel.WARN)
        assert "ssh.permit_user_env" in _deduction_keys(result)

    def test_no_issues_emits_config_ok(self):
        snap = base_snapshot(sshd_config={
            "permitrootlogin": "no",
            "passwordauthentication": "no",
            "maxauthtries": "3",
            "allowusers": "admin",
            "allowtcpforwarding": "no",
        })
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.config_ok", FindingLevel.OK)
        assert not any(f.level == FindingLevel.ALERT for f in result.findings)

    def test_no_allow_users_info(self):
        snap = base_snapshot(sshd_config={})
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.no_allow_users", FindingLevel.INFO)

    def test_allow_users_present_no_info(self):
        snap = base_snapshot(sshd_config={"allowusers": "admin"})
        result = check_ssh(snap)
        assert not _has_finding(result, "ssh.no_allow_users", FindingLevel.INFO)

    def test_allow_tcp_forwarding_enabled_warn(self):
        """AllowTcpForwarding not set (default yes) → WARN + deduction."""
        snap = base_snapshot(sshd_config={})
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.allow_tcp_forwarding", FindingLevel.WARN)
        assert "ssh.allow_tcp_forwarding" in _deduction_keys(result)

    def test_allow_tcp_forwarding_disabled_no_warn(self):
        snap = base_snapshot(sshd_config={"allowtcpforwarding": "no"})
        result = check_ssh(snap)
        assert not _has_finding(result, "ssh.allow_tcp_forwarding", FindingLevel.WARN)

    def test_pubkey_auth_disabled_alert(self):
        snap = base_snapshot(sshd_config={"pubkeyauthentication": "no"})
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.pubkey_auth_disabled", FindingLevel.ALERT)
        assert "ssh.pubkey_auth_disabled" in _deduction_keys(result)

    def test_pubkey_auth_enabled_no_alert(self):
        snap = base_snapshot(sshd_config={"pubkeyauthentication": "yes"})
        result = check_ssh(snap)
        assert not _has_finding(result, "ssh.pubkey_auth_disabled", FindingLevel.ALERT)

    def test_multiple_issues_accumulate_deductions(self):
        """Multiple config issues must each produce a deduction — no short-circuit."""
        snap = base_snapshot(sshd_config={
            "permitrootlogin": "yes",
            "permitemptypasswords": "yes",
            "passwordauthentication": "yes",
            "x11forwarding": "yes",
        })
        result = check_ssh(snap)
        dk = _deduction_keys(result)
        # Verify each issue produced its own deduction — the key assertions are
        # sufficient; coupling to exact point totals would break if weights change.
        assert "ssh.permit_root_login" in dk
        assert "ssh.permit_empty_passwords" in dk
        assert "ssh.password_auth" in dk
        assert "ssh.x11.forwarding.server" in dk
        assert len(result.deductions) >= 4


# ---------------------------------------------------------------------------
# 3. Weak crypto
# ---------------------------------------------------------------------------

class TestWeakCrypto:
    def test_weak_cipher_warn(self):
        snap = base_snapshot(sshd_config={"ciphers": "aes128-cbc,aes256-gcm@openssh.com"})
        result = check_ssh(snap)
        assert "ssh.weak_ciphers" in _deduction_keys(result)

    def test_strong_ciphers_only_no_warn(self):
        snap = base_snapshot(sshd_config={"ciphers": "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com"})
        result = check_ssh(snap)
        assert "ssh.weak_ciphers" not in _deduction_keys(result)

    def test_weak_mac_warn(self):
        snap = base_snapshot(sshd_config={"macs": "hmac-sha1,hmac-sha2-256"})
        result = check_ssh(snap)
        assert "ssh.weak_macs" in _deduction_keys(result)

    def test_weak_kex_warn(self):
        snap = base_snapshot(sshd_config={"kexalgorithms": "diffie-hellman-group1-sha1,curve25519-sha256"})
        result = check_ssh(snap)
        assert "ssh.weak_kex" in _deduction_keys(result)

    def test_no_crypto_override_no_deductions(self):
        # When Ciphers/MACs/KexAlgorithms not set, no crypto deductions
        snap = base_snapshot(sshd_config={})
        result = check_ssh(snap)
        assert "ssh.weak_ciphers" not in _deduction_keys(result)
        assert "ssh.weak_macs" not in _deduction_keys(result)
        assert "ssh.weak_kex" not in _deduction_keys(result)


# ---------------------------------------------------------------------------
# 4. ~/.ssh directory permissions
# ---------------------------------------------------------------------------

class TestSshDir:
    def test_dir_not_found_info(self):
        snap = base_snapshot(ssh_dir_exists=False)
        result = check_ssh(snap)
        assert "ssh.dir_not_found" in [
            f.key for f in result.findings if f.level == FindingLevel.INFO
        ]

    def test_correct_perms_ok(self):
        snap = base_snapshot(ssh_dir_exists=True, ssh_dir_perms=0o700)
        result = check_ssh(snap)
        assert "ssh.dir_perms_ok" in _keys(result)

    def test_wrong_perms_alert(self):
        snap = base_snapshot(ssh_dir_exists=True, ssh_dir_perms=0o755)
        result = check_ssh(snap)
        assert "ssh.dir_perms" in [
            f.key for f in result.findings if f.level == FindingLevel.ALERT
        ]
        assert "ssh.dir_perms" in _deduction_keys(result)

    @pytest.mark.skipif(os.geteuid() == 0,
                        reason="root bypasses directory search permissions")
    def test_unreadable_ssh_dir_degrades(self, tmp_path, monkeypatch):
        # ~/.ssh under a directory the auditor cannot search (e.g. /root/.ssh
        # under a user namespace where root maps to an unprivileged uid) makes
        # is_dir() raise PermissionError. from_system() must degrade cleanly —
        # neither raise nor leak the OSError — not abort the whole audit.
        home = tmp_path / "home"
        (home / ".ssh").mkdir(parents=True)
        home.chmod(0o000)  # parent unsearchable -> is_dir(home/.ssh) -> EACCES
        monkeypatch.setenv("SUDO_USER", "fakeuser")
        monkeypatch.setattr("bob.checks.ssh._snapshot.pwd.getpwnam",
                            lambda u: types.SimpleNamespace(pw_dir=str(home)))
        try:
            snap = SSHSnapshot.from_system()   # must NOT raise
        finally:
            home.chmod(0o700)                  # restore for tmp cleanup
        assert snap.ssh_dir_exists is False    # degraded, audit continues


# ---------------------------------------------------------------------------
# 5. Private keys
# ---------------------------------------------------------------------------

class TestPrivateKeys:
    def _make_key(self, **kwargs) -> PrivateKeyInfo:
        defaults = dict(
            path=Path("/home/testuser/.ssh/id_ed25519"),
            permissions=0o600,
            key_type="ed25519",
            rsa_bits=None,
            has_passphrase=True,
        )
        defaults.update(kwargs)
        return PrivateKeyInfo(**defaults)

    def test_no_keys_info(self):
        snap = base_snapshot(ssh_dir_exists=True, ssh_dir_perms=0o700, private_keys=[])
        result = check_ssh(snap)
        assert "ssh.no_private_keys" in [
            f.key for f in result.findings if f.level == FindingLevel.INFO
        ]

    def test_good_key_ok(self):
        key = self._make_key()
        snap = base_snapshot(ssh_dir_exists=True, ssh_dir_perms=0o700, private_keys=[key])
        result = check_ssh(snap)
        assert "ssh.key_ok" in _keys(result)

    def test_wrong_perms_alert(self):
        key = self._make_key(permissions=0o644)
        snap = base_snapshot(ssh_dir_exists=True, ssh_dir_perms=0o700, private_keys=[key])
        result = check_ssh(snap)
        assert "ssh.private_key_perms" in _deduction_keys(result)

    def test_dsa_key_alert(self):
        key = self._make_key(key_type="dsa")
        snap = base_snapshot(ssh_dir_exists=True, ssh_dir_perms=0o700, private_keys=[key])
        result = check_ssh(snap)
        assert "ssh.dsa_key" in _deduction_keys(result)

    def test_rsa_weak_warn(self):
        key = self._make_key(key_type="rsa", rsa_bits=1024)
        snap = base_snapshot(ssh_dir_exists=True, ssh_dir_perms=0o700, private_keys=[key])
        result = check_ssh(snap)
        assert "ssh.rsa_weak" in _deduction_keys(result)

    def test_rsa_strong_ok(self):
        key = self._make_key(key_type="rsa", rsa_bits=4096)
        snap = base_snapshot(ssh_dir_exists=True, ssh_dir_perms=0o700, private_keys=[key])
        result = check_ssh(snap)
        assert "ssh.rsa_ok" in _keys(result)

    def test_no_passphrase_warn(self):
        key = self._make_key(has_passphrase=False)
        snap = base_snapshot(ssh_dir_exists=True, ssh_dir_perms=0o700, private_keys=[key])
        result = check_ssh(snap)
        assert "ssh.no_passphrase" in _deduction_keys(result)

    def test_passphrase_unknown_no_warn(self):
        key = self._make_key(has_passphrase=None)
        snap = base_snapshot(ssh_dir_exists=True, ssh_dir_perms=0o700, private_keys=[key])
        result = check_ssh(snap)
        assert "ssh.no_passphrase" not in _deduction_keys(result)


# ---------------------------------------------------------------------------
# 6. authorized_keys
# ---------------------------------------------------------------------------

class TestAuthorizedKeys:
    def _make_entry(self, **kwargs) -> AuthorizedKeyEntry:
        defaults = dict(
            line_no=1,
            key_type="ssh-ed25519",
            rsa_bits=None,
            has_restrictions=False,
            blob_prefix="AAAA" * 8,
        )
        defaults.update(kwargs)
        return AuthorizedKeyEntry(**defaults)

    def test_not_found_info(self):
        snap = base_snapshot(ssh_dir_exists=True, ssh_dir_perms=0o700,
                             authorized_keys_exists=False)
        result = check_ssh(snap)
        assert "ssh.authorized_keys_not_found" in [
            f.key for f in result.findings if f.level == FindingLevel.INFO
        ]

    def test_wrong_perms_alert(self):
        entry = self._make_entry()
        snap = base_snapshot(
            ssh_dir_exists=True, ssh_dir_perms=0o700,
            authorized_keys_exists=True,
            authorized_keys_perms=0o644,
            authorized_keys_entries=[entry],
        )
        result = check_ssh(snap)
        assert "ssh.authorized_keys_perms" in _deduction_keys(result)

    def test_dsa_entry_alert(self):
        entry = self._make_entry(key_type="ssh-dss", line_no=3)
        snap = base_snapshot(
            ssh_dir_exists=True, ssh_dir_perms=0o700,
            authorized_keys_exists=True, authorized_keys_perms=0o600,
            authorized_keys_entries=[entry],
        )
        result = check_ssh(snap)
        assert "ssh.authorized_keys_dsa" in _deduction_keys(result)

    def test_rsa_weak_entry_warn(self):
        entry = self._make_entry(key_type="ssh-rsa", rsa_bits=1024, line_no=2)
        snap = base_snapshot(
            ssh_dir_exists=True, ssh_dir_perms=0o700,
            authorized_keys_exists=True, authorized_keys_perms=0o600,
            authorized_keys_entries=[entry],
        )
        result = check_ssh(snap)
        assert "ssh.authorized_keys_weak_key" in _deduction_keys(result)

    def test_duplicate_keys_warn(self):
        blob = "BBBB" * 8
        e1 = self._make_entry(line_no=1, blob_prefix=blob)
        e2 = self._make_entry(line_no=5, blob_prefix=blob)
        snap = base_snapshot(
            ssh_dir_exists=True, ssh_dir_perms=0o700,
            authorized_keys_exists=True, authorized_keys_perms=0o600,
            authorized_keys_entries=[e1, e2],
        )
        result = check_ssh(snap)
        assert "ssh.authorized_keys_duplicate" in _deduction_keys(result)

    def test_no_restrictions_info(self):
        entry = self._make_entry(has_restrictions=False)
        snap = base_snapshot(
            ssh_dir_exists=True, ssh_dir_perms=0o700,
            authorized_keys_exists=True, authorized_keys_perms=0o600,
            authorized_keys_entries=[entry],
        )
        result = check_ssh(snap)
        assert "ssh.authorized_keys_no_restrictions" in [
            f.key for f in result.findings if f.level == FindingLevel.INFO
        ]

    def test_good_entry_ok(self):
        entry = self._make_entry(key_type="ssh-ed25519", has_restrictions=True)
        snap = base_snapshot(
            ssh_dir_exists=True, ssh_dir_perms=0o700,
            authorized_keys_exists=True, authorized_keys_perms=0o600,
            authorized_keys_entries=[entry],
        )
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.authorized_keys_ok", FindingLevel.OK)

    def test_dsa_entry_suppresses_ok(self):
        """authorized_keys_ok must NOT appear when a DSA key is present."""
        entry = self._make_entry(key_type="ssh-dss", line_no=1)
        snap = base_snapshot(
            ssh_dir_exists=True, ssh_dir_perms=0o700,
            authorized_keys_exists=True, authorized_keys_perms=0o600,
            authorized_keys_entries=[entry],
        )
        result = check_ssh(snap)
        assert not _has_finding(result, "ssh.authorized_keys_ok", FindingLevel.OK)

    def test_duplicate_suppresses_ok(self):
        """authorized_keys_ok must NOT appear when there are duplicate keys."""
        blob = "CCCC" * 8
        e1 = self._make_entry(line_no=1, blob_prefix=blob)
        e2 = self._make_entry(line_no=2, blob_prefix=blob)
        snap = base_snapshot(
            ssh_dir_exists=True, ssh_dir_perms=0o700,
            authorized_keys_exists=True, authorized_keys_perms=0o600,
            authorized_keys_entries=[e1, e2],
        )
        result = check_ssh(snap)
        assert not _has_finding(result, "ssh.authorized_keys_ok", FindingLevel.OK)

    def test_weak_rsa_entry_suppresses_ok(self):
        """Weak RSA key sets ak_found_issue → authorized_keys_ok must NOT appear."""
        entry = self._make_entry(key_type="ssh-rsa", rsa_bits=1024, line_no=1)
        snap = base_snapshot(
            ssh_dir_exists=True, ssh_dir_perms=0o700,
            authorized_keys_exists=True, authorized_keys_perms=0o600,
            authorized_keys_entries=[entry],
        )
        result = check_ssh(snap)
        assert not _has_finding(result, "ssh.authorized_keys_ok", FindingLevel.OK)

    def test_wrong_perms_does_not_suppress_ok(self):
        """Wrong file permissions produce an ALERT but do NOT set ak_found_issue.
        authorized_keys_ok refers to key content only, so it coexists with the
        permissions ALERT when the entries themselves are clean."""
        entry = self._make_entry(key_type="ssh-ed25519", has_restrictions=True)
        snap = base_snapshot(
            ssh_dir_exists=True, ssh_dir_perms=0o700,
            authorized_keys_exists=True, authorized_keys_perms=0o644,
            authorized_keys_entries=[entry],
        )
        result = check_ssh(snap)
        # ALERT on perms
        assert "ssh.authorized_keys_perms" in _deduction_keys(result)
        # OK on entries (content check is independent from permissions check)
        assert _has_finding(result, "ssh.authorized_keys_ok", FindingLevel.OK)

    def test_no_restrictions_does_not_suppress_ok(self):
        """no_restrictions is INFO and does NOT set ak_found_issue — OK still appears."""
        entry = self._make_entry(key_type="ssh-ed25519", has_restrictions=False)
        snap = base_snapshot(
            ssh_dir_exists=True, ssh_dir_perms=0o700,
            authorized_keys_exists=True, authorized_keys_perms=0o600,
            authorized_keys_entries=[entry],
        )
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.authorized_keys_no_restrictions", FindingLevel.INFO)
        assert _has_finding(result, "ssh.authorized_keys_ok", FindingLevel.OK)


# ---------------------------------------------------------------------------
# 7. Client config (~/.ssh/config)
# ---------------------------------------------------------------------------

class TestClientConfig:
    def _snap(self, entries):
        return base_snapshot(
            ssh_dir_exists=True, ssh_dir_perms=0o700,
            client_config_exists=True,
            client_config_entries=entries,
        )

    def test_not_found_info(self):
        snap = base_snapshot(ssh_dir_exists=True, ssh_dir_perms=0o700,
                             client_config_exists=False)
        result = check_ssh(snap)
        assert "ssh.client_config_not_found" in [
            f.key for f in result.findings if f.level == FindingLevel.INFO
        ]

    def test_strict_host_checking_no_alert(self):
        entries = [ClientConfigEntry(host="*", key="stricthostkeychecking", value="no")]
        result = check_ssh(self._snap(entries))
        assert "ssh.client_strict_host_no" in _deduction_keys(result)

    def test_known_hosts_devnull_alert(self):
        entries = [ClientConfigEntry(host="*", key="userknownhostsfile", value="/dev/null")]
        result = check_ssh(self._snap(entries))
        assert "ssh.client_known_hosts_devnull" in _deduction_keys(result)

    def test_forward_agent_warn(self):
        entries = [ClientConfigEntry(host="*", key="forwardagent", value="yes")]
        result = check_ssh(self._snap(entries))
        assert "ssh.client_forward_agent" in _deduction_keys(result)

    def test_clean_config_ok(self):
        entries = [ClientConfigEntry(host="*", key="serveralivecountmax", value="3")]
        result = check_ssh(self._snap(entries))
        assert "ssh.client_config_ok" in _keys(result)

    def test_empty_config_ok(self):
        result = check_ssh(self._snap([]))
        assert "ssh.client_config_ok" in _keys(result)


# ---------------------------------------------------------------------------
# 8. known_hosts
# ---------------------------------------------------------------------------

class TestKnownHosts:
    def _snap(self, entries):
        return base_snapshot(
            ssh_dir_exists=True, ssh_dir_perms=0o700,
            known_hosts_exists=True,
            known_hosts_entries=entries,
        )

    def test_not_found_info(self):
        snap = base_snapshot(ssh_dir_exists=True, ssh_dir_perms=0o700,
                             known_hosts_exists=False)
        result = check_ssh(snap)
        assert "ssh.known_hosts_not_found" in [
            f.key for f in result.findings if f.level == FindingLevel.INFO
        ]

    def test_deprecated_key_type_warn(self):
        entries = [KnownHostEntry(line_no=1, host="github.com",
                                  key_type="ssh-dss", is_hashed=False)]
        result = check_ssh(self._snap(entries))
        assert "ssh.known_hosts_deprecated" in _deduction_keys(result)

    def test_duplicate_host_info(self):
        entries = [
            KnownHostEntry(line_no=1, host="example.com", key_type="ssh-ed25519", is_hashed=False),
            KnownHostEntry(line_no=8, host="example.com", key_type="ssh-rsa", is_hashed=False),
        ]
        result = check_ssh(self._snap(entries))
        assert "ssh.known_hosts_duplicate" in [
            f.key for f in result.findings if f.level == FindingLevel.INFO
        ]

    def test_hashed_entries_no_duplicate_warning(self):
        # Hashed entries can't be compared — should not report duplicates
        entries = [
            KnownHostEntry(line_no=1, host="|1|abc|def", key_type="ssh-ed25519", is_hashed=True),
            KnownHostEntry(line_no=2, host="|1|abc|def", key_type="ssh-ed25519", is_hashed=True),
        ]
        result = check_ssh(self._snap(entries))
        info_keys = [f.key for f in result.findings if f.level == FindingLevel.INFO]
        assert "ssh.known_hosts_duplicate" not in info_keys

    def test_clean_known_hosts_ok(self):
        entries = [
            KnownHostEntry(line_no=1, host="github.com", key_type="ssh-ed25519", is_hashed=False),
        ]
        result = check_ssh(self._snap(entries))
        assert "ssh.known_hosts_ok" in _keys(result)

    def test_comma_separated_host_duplicate_detected(self):
        """A host that appears in two entries (once alone, once in a comma list) is a duplicate."""
        entries = [
            KnownHostEntry(line_no=1, host="host1,host2", key_type="ssh-ed25519", is_hashed=False),
            KnownHostEntry(line_no=5, host="host1",       key_type="ssh-rsa",    is_hashed=False),
        ]
        result = check_ssh(self._snap(entries))
        info_keys = [f.key for f in result.findings if f.level == FindingLevel.INFO]
        assert "ssh.known_hosts_duplicate" in info_keys


# ---------------------------------------------------------------------------
# 9. Parsing helpers
# ---------------------------------------------------------------------------

class TestParseTimeSeconds:
    def test_plain_int(self):
        assert _parse_time_seconds("120") == 120

    def test_seconds_suffix(self):
        assert _parse_time_seconds("30s") == 30

    def test_minutes_suffix(self):
        assert _parse_time_seconds("2m") == 120

    def test_hours_suffix(self):
        assert _parse_time_seconds("1h") == 3600

    def test_invalid_returns_default(self):
        assert _parse_time_seconds("invalid") == _DEFAULT_GRACE_SECS


class TestParseAuthorizedKeys:
    def test_parses_ed25519(self, tmp_path):
        ak = tmp_path / "authorized_keys"
        ak.write_text("ssh-ed25519 AAAA...blob user@host\n")
        entries = _parse_authorized_keys(ak)
        assert len(entries) == 1
        assert entries[0].key_type == "ssh-ed25519"
        assert not entries[0].has_restrictions

    def test_parses_options(self, tmp_path):
        ak = tmp_path / "authorized_keys"
        ak.write_text('command="/bin/backup" ssh-ed25519 AAAA...blob user@host\n')
        entries = _parse_authorized_keys(ak)
        assert len(entries) == 1
        assert entries[0].has_restrictions

    def test_skips_comments(self, tmp_path):
        ak = tmp_path / "authorized_keys"
        ak.write_text("# this is a comment\nssh-ed25519 AAAA...blob user@host\n")
        entries = _parse_authorized_keys(ak)
        assert len(entries) == 1

    def test_skips_blank_lines(self, tmp_path):
        ak = tmp_path / "authorized_keys"
        ak.write_text("\nssh-ed25519 AAAA...blob user@host\n\n")
        entries = _parse_authorized_keys(ak)
        assert len(entries) == 1

    def test_multiple_entries(self, tmp_path):
        ak = tmp_path / "authorized_keys"
        ak.write_text(
            "ssh-ed25519 AAAA...blobA userA@host\n"
            "ssh-rsa BBBB...blobB userB@host\n"
        )
        entries = _parse_authorized_keys(ak)
        assert len(entries) == 2


class TestParseClientConfig:
    def test_parses_global_directive(self, tmp_path):
        cfg = tmp_path / "config"
        cfg.write_text("StrictHostKeyChecking no\n")
        entries = _parse_client_config(cfg)
        assert any(e.key == "stricthostkeychecking" and e.value == "no" for e in entries)

    def test_parses_host_block(self, tmp_path):
        cfg = tmp_path / "config"
        cfg.write_text("Host example.com\n  ForwardAgent yes\n")
        entries = _parse_client_config(cfg)
        fwd = [e for e in entries if e.key == "forwardagent"]
        assert fwd and fwd[0].host == "example.com"

    def test_skips_comments(self, tmp_path):
        cfg = tmp_path / "config"
        cfg.write_text("# Comment\nServerAliveInterval 60\n")
        entries = _parse_client_config(cfg)
        assert len(entries) == 1


class TestParseKnownHosts:
    def test_plain_entry(self, tmp_path):
        kh = tmp_path / "known_hosts"
        kh.write_text("github.com ssh-ed25519 AAAA...blob\n")
        entries = _parse_known_hosts(kh)
        assert len(entries) == 1
        assert entries[0].host == "github.com"
        assert not entries[0].is_hashed

    def test_hashed_entry(self, tmp_path):
        kh = tmp_path / "known_hosts"
        kh.write_text("|1|abc123|def456 ssh-ed25519 AAAA...blob\n")
        entries = _parse_known_hosts(kh)
        assert entries[0].is_hashed

    def test_skips_comments_and_blanks(self, tmp_path):
        kh = tmp_path / "known_hosts"
        kh.write_text("# comment\n\ngithub.com ssh-ed25519 AAAA...blob\n")
        entries = _parse_known_hosts(kh)
        assert len(entries) == 1


class TestRsaBitsFromBlob:
    def test_invalid_blob_returns_none(self):
        assert _rsa_bits_from_blob("not_valid_base64!!!") is None

    def test_too_short_blob_returns_none(self):
        assert _rsa_bits_from_blob(base64.b64encode(b"\x00" * 4).decode()) is None

    def test_valid_2048_blob(self):
        blob = _make_rsa_blob(2048)
        bits = _rsa_bits_from_blob(blob)
        assert bits == 2048

    def test_valid_4096_blob(self):
        blob = _make_rsa_blob(4096)
        bits = _rsa_bits_from_blob(blob)
        assert bits == 4096

    def test_valid_1024_blob(self):
        blob = _make_rsa_blob(1024)
        bits = _rsa_bits_from_blob(blob)
        assert bits == 1024


class TestHasPassphrase:
    def test_new_format_encrypted(self, tmp_path):
        """Simulate an OpenSSH new-format encrypted key header."""
        import base64
        # Build minimal openssh-key-v1 blob with cipher != "none"
        magic = b"openssh-key-v1\x00"
        cipher = b"aes256-ctr"
        blob = magic + len(cipher).to_bytes(4, "big") + cipher
        b64 = base64.b64encode(blob).decode()
        key_text = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            + b64 + "\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        )
        kf = tmp_path / "id_ed25519"
        kf.write_text(key_text)
        assert _has_passphrase(kf)

    def test_new_format_unencrypted(self, tmp_path):
        import base64
        magic = b"openssh-key-v1\x00"
        cipher = b"none"
        blob = magic + len(cipher).to_bytes(4, "big") + cipher
        b64 = base64.b64encode(blob).decode()
        key_text = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            + b64 + "\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        )
        kf = tmp_path / "id_ed25519"
        kf.write_text(key_text)
        assert not _has_passphrase(kf)

    def test_old_pem_encrypted(self, tmp_path):
        kf = tmp_path / "id_rsa"
        kf.write_text(
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "Proc-Type: 4,ENCRYPTED\n"
            "DEK-Info: AES-128-CBC,...\n"
            "...\n"
            "-----END RSA PRIVATE KEY-----\n"
        )
        assert _has_passphrase(kf)

    def test_old_pem_unencrypted(self, tmp_path):
        kf = tmp_path / "id_rsa"
        kf.write_text(
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA...\n"
            "-----END RSA PRIVATE KEY-----\n"
        )
        assert not _has_passphrase(kf)

    def test_missing_file_returns_none(self, tmp_path):
        assert _has_passphrase(tmp_path / "nonexistent") is None

    def test_empty_file_returns_none(self, tmp_path):
        kf = tmp_path / "id_empty"
        kf.write_bytes(b"")
        assert _has_passphrase(kf) is None

    def test_truncated_openssh_header_returns_none(self, tmp_path):
        """Binary header present but truncated before cipher length field."""
        import base64
        magic = b"openssh-key-v1\x00"
        # Only 2 bytes after magic — not enough for the 4-byte cipher length
        blob = magic + b"\x00\x0a"
        b64 = base64.b64encode(blob).decode()
        key_text = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            + b64 + "\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        )
        kf = tmp_path / "id_truncated"
        kf.write_text(key_text)
        assert _has_passphrase(kf) is None


# ---------------------------------------------------------------------------
# Host key checks
# ---------------------------------------------------------------------------

class TestHostKeyDsa:
    def test_dsa_host_key_is_warn(self):
        snap = base_snapshot(host_keys=[_make_host_key("dsa")])
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.host_key_dsa", FindingLevel.WARN)

    def test_dsa_host_key_deducts_1(self):
        snap = base_snapshot(host_keys=[_make_host_key("dsa")])
        result = check_ssh(snap)
        assert _deduction_points(result) >= 1
        assert "ssh.host_key_dsa" in _deduction_keys(result)

    def test_dsa_host_key_has_fix_cmd(self):
        snap = base_snapshot(host_keys=[_make_host_key("dsa")])
        result = check_ssh(snap)
        f = next(f for f in result.findings if f.key == "ssh.host_key_dsa")
        assert f.cmd is not None
        assert f.cmd_type == "fix"

    def test_dsa_host_key_has_detail(self):
        snap = base_snapshot(host_keys=[_make_host_key("dsa")])
        result = check_ssh(snap)
        f = next(f for f in result.findings if f.key == "ssh.host_key_dsa")
        assert f.detail is not None


class TestHostKeyRsaShort:
    @pytest.mark.parametrize("bits", [1024, 2048, 3072, 3999])
    def test_rsa_short_is_info(self, bits):
        snap = base_snapshot(host_keys=[_make_host_key("rsa", rsa_bits=bits)])
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.host_key_rsa_short", FindingLevel.INFO)

    def test_rsa_short_no_deduction(self):
        snap = base_snapshot(host_keys=[_make_host_key("rsa", rsa_bits=3072)])
        result = check_ssh(snap)
        assert "ssh.host_key_rsa_short" not in _deduction_keys(result)

    def test_rsa_short_has_detail(self):
        snap = base_snapshot(host_keys=[_make_host_key("rsa", rsa_bits=3072)])
        result = check_ssh(snap)
        f = next(f for f in result.findings if f.key == "ssh.host_key_rsa_short")
        assert f.detail is not None

    def test_rsa_short_has_fix_cmd(self):
        snap = base_snapshot(host_keys=[_make_host_key("rsa", rsa_bits=3072)])
        result = check_ssh(snap)
        f = next(f for f in result.findings if f.key == "ssh.host_key_rsa_short")
        assert f.cmd is not None
        assert f.cmd_type == "fix"

    def test_rsa_4096_is_ok(self):
        snap = base_snapshot(host_keys=[_make_host_key("rsa", rsa_bits=4096)])
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.host_key_ok", FindingLevel.OK)
        assert "ssh.host_key_rsa_short" not in _keys(result)

    def test_rsa_8192_is_ok(self):
        snap = base_snapshot(host_keys=[_make_host_key("rsa", rsa_bits=8192)])
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.host_key_ok", FindingLevel.OK)

    def test_rsa_bits_none_is_ok(self):
        """RSA key with undeterminable size → OK (no false positive)."""
        snap = base_snapshot(host_keys=[_make_host_key("rsa", rsa_bits=None)])
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.host_key_ok", FindingLevel.OK)


class TestHostKeyStrong:
    @pytest.mark.parametrize("key_type", ["ed25519", "ecdsa", "unknown"])
    def test_strong_key_is_ok(self, key_type):
        snap = base_snapshot(host_keys=[_make_host_key(key_type)])
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.host_key_ok", FindingLevel.OK)

    @pytest.mark.parametrize("key_type", ["ed25519", "ecdsa"])
    def test_strong_key_no_deduction(self, key_type):
        snap = base_snapshot(host_keys=[_make_host_key(key_type)])
        result = check_ssh(snap)
        assert "ssh.host_key_ok" not in _deduction_keys(result)

    def test_no_host_keys_no_finding(self):
        """Empty host_keys list → _check_host_keys is a no-op."""
        snap = base_snapshot(host_keys=[])
        result = check_ssh(snap)
        assert "ssh.host_key_ok" not in _keys(result)
        assert "ssh.host_key_dsa" not in _keys(result)
        assert "ssh.host_key_rsa_short" not in _keys(result)


class TestHostKeyCombined:
    def test_realistic_setup_rsa3072_ecdsa_ed25519(self):
        """Matches the real system: RSA 3072 (INFO), ECDSA 256 (OK), ed25519 (OK)."""
        snap = base_snapshot(host_keys=[
            _make_host_key("rsa", rsa_bits=3072, name="ssh_host_rsa_key"),
            _make_host_key("ecdsa", name="ssh_host_ecdsa_key"),
            _make_host_key("ed25519", name="ssh_host_ed25519_key"),
        ])
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.host_key_rsa_short", FindingLevel.INFO)
        assert _has_finding(result, "ssh.host_key_ok", FindingLevel.OK)
        # RSA short and strong keys must not generate deductions
        assert "ssh.host_key_rsa_short" not in _deduction_keys(result)
        assert "ssh.host_key_ok" not in _deduction_keys(result)

    def test_dsa_plus_ed25519(self):
        """DSA host key (WARN) + ed25519 (OK) → deduction from DSA only."""
        snap = base_snapshot(host_keys=[
            _make_host_key("dsa"),
            _make_host_key("ed25519"),
        ])
        result = check_ssh(snap)
        assert _has_finding(result, "ssh.host_key_dsa", FindingLevel.WARN)
        assert _has_finding(result, "ssh.host_key_ok", FindingLevel.OK)
        # Only 1 deduction (from DSA)
        dsa_deductions = [d for d in result.deductions if d.key == "ssh.host_key_dsa"]
        assert len(dsa_deductions) == 1

    def test_multiple_dsa_keys_each_deduct(self):
        """Two DSA keys → two separate deductions."""
        snap = base_snapshot(host_keys=[
            _make_host_key("dsa", name="ssh_host_dsa_key"),
            _make_host_key("dsa", name="ssh_host_dsa2_key"),
        ])
        result = check_ssh(snap)
        dsa_deductions = [d for d in result.deductions if d.key == "ssh.host_key_dsa"]
        assert len(dsa_deductions) == 2
