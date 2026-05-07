"""
SSH security audit check for BOB.

Analyses:
  - /etc/ssh/sshd_config (server configuration) + drop-ins
  - ~/.ssh/ directory permissions
  - Private SSH keys (type, size, passphrase, permissions)
  - authorized_keys (key types, duplicates, restrictions)
  - ~/.ssh/config (client configuration)
  - known_hosts (deprecated key types, duplicates)

The user-side checks (~/.ssh/) target the user who invoked sudo
(SUDO_USER environment variable), falling back to root's home.

Usage:
    from bob.checks.ssh import SSHSnapshot, check_ssh

    snapshot = SSHSnapshot.from_system()
    result   = check_ssh(snapshot)
"""

from __future__ import annotations

import base64
import binascii
import glob as _glob
import os
import pwd
import re
import stat
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from bob.checks._run import TranslationFunc, _command_exists, _identity_t, _run
from bob.scoring import CheckResult, FindingLevel

# ---------------------------------------------------------------------------
# Weak crypto reference sets (OpenSSH deprecated algorithms)
# ---------------------------------------------------------------------------

_WEAK_CIPHERS: frozenset[str] = frozenset({
    "3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
    "arcfour", "arcfour128", "arcfour256",
    "blowfish-cbc", "cast128-cbc",
    "rijndael-cbc@lysator.liu.se",
})

_WEAK_MACS: frozenset[str] = frozenset({
    "hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96",
    "umac-64@openssh.com",
    "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com",
    "hmac-sha1-etm@openssh.com", "hmac-sha1-96-etm@openssh.com",
    "umac-64-etm@openssh.com",
})

_WEAK_KEX: frozenset[str] = frozenset({
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
})

_SSHD_CONFIG_PATH = Path("/etc/ssh/sshd_config")

# Files in ~/.ssh/ that are never private keys
_NON_KEY_FILES: frozenset[str] = frozenset({
    "authorized_keys", "authorized_keys2",
    "known_hosts", "known_hosts2",
    "config", "environment", "rc",
})

# Public key file extensions (their private counterpart is the bare name)
_PUB_SUFFIX = ".pub"


# ---------------------------------------------------------------------------
# Sub-dataclasses
# ---------------------------------------------------------------------------

@dataclass
class HostKeyInfo:
    """Information about a server host key in /etc/ssh/."""
    path:     Path
    key_type: str           # "rsa", "dsa", "ecdsa", "ed25519", "unknown"
    rsa_bits: Optional[int] # None for non-RSA keys or when undeterminable


@dataclass
class PrivateKeyInfo:
    """Information about a private SSH key file in ~/.ssh/."""
    path:           Path
    permissions:    int           # raw stat mode bits (S_IMODE)
    key_type:       str           # "rsa", "dsa", "ecdsa", "ed25519", "unknown"
    rsa_bits:       Optional[int] # None for non-RSA keys or when undeterminable
    has_passphrase: Optional[bool]# None if undeterminable


@dataclass
class AuthorizedKeyEntry:
    """A single valid key entry from authorized_keys."""
    line_no:          int
    key_type:         str           # e.g. "ssh-rsa", "ssh-ed25519"
    rsa_bits:         Optional[int]
    has_restrictions: bool          # True if options like command=, from=, no-pty present
    blob_prefix:      str           # first 32 chars of base64 blob (used for dedup)


@dataclass
class KnownHostEntry:
    """A single entry from known_hosts."""
    line_no:   int
    host:      str   # raw host field (may be hashed "|1|…")
    key_type:  str
    is_hashed: bool


@dataclass
class ClientConfigEntry:
    """A directive from ~/.ssh/config."""
    host:  str  # "Host" pattern this applies to ("*" = global)
    key:   str  # directive name (lowercased)
    value: str  # directive value (stripped)


# ---------------------------------------------------------------------------
# System snapshot
# ---------------------------------------------------------------------------

@dataclass
class SSHSnapshot:
    """
    Raw snapshot of SSH configuration state.

    All file I/O and subprocess calls happen in from_system().
    check_ssh() operates on this snapshot only (pure logic).
    """
    sshd_installed:          bool = False
    sshd_active:             bool = False
    sshd_config:             dict = field(default_factory=dict)
    config_source_files:     List[str] = field(default_factory=list)

    host_keys:               List[HostKeyInfo] = field(default_factory=list)

    sudo_user:               str = ""
    user_home:               Optional[Path] = None
    ssh_dir_exists:          bool = False
    ssh_dir_perms:           Optional[int] = None  # None if dir absent

    private_keys:            List[PrivateKeyInfo] = field(default_factory=list)

    authorized_keys_exists:  bool = False
    authorized_keys_perms:   Optional[int] = None
    authorized_keys_entries: List[AuthorizedKeyEntry] = field(default_factory=list)

    client_config_exists:    bool = False
    client_config_entries:   List[ClientConfigEntry] = field(default_factory=list)

    known_hosts_exists:      bool = False
    known_hosts_entries:     List[KnownHostEntry] = field(default_factory=list)
    install_cmd:             str = ""  # distro-appropriate install command

    @classmethod
    def from_system(cls) -> "SSHSnapshot":
        snap = cls()

        # --- distro-appropriate install command ---
        snap.install_cmd = _detect_ssh_install_cmd()

        # --- sshd installation and status ---
        snap.sshd_installed = (
            _command_exists("sshd")
            or Path("/usr/sbin/sshd").exists()
            or Path("/sbin/sshd").exists()
        )
        if snap.sshd_installed and _command_exists("systemctl"):
            for unit in ("ssh", "sshd"):
                out = (_run("systemctl", "is-active", unit) or "").strip()
                if out == "active":
                    snap.sshd_active = True
                    break

        # --- server host keys ---
        snap.host_keys = _collect_host_keys()

        # --- sshd_config (server) ---
        if _SSHD_CONFIG_PATH.exists():
            seen: set[str] = set()
            config: dict[str, str] = {}
            sources: list[str] = []
            _parse_config_file(_SSHD_CONFIG_PATH, config, seen, sources)
            snap.sshd_config = config
            snap.config_source_files = sources

        # --- resolve the real user behind sudo ---
        sudo_user = os.environ.get("SUDO_USER", "")
        snap.sudo_user = sudo_user
        if sudo_user:
            try:
                snap.user_home = Path(pwd.getpwnam(sudo_user).pw_dir)
            except KeyError:
                pass
        if snap.user_home is None:
            snap.user_home = Path("/root")

        ssh_dir = snap.user_home / ".ssh"

        # --- ~/.ssh directory ---
        if ssh_dir.is_dir():
            snap.ssh_dir_exists = True
            try:
                snap.ssh_dir_perms = stat.S_IMODE(ssh_dir.stat().st_mode)
            except OSError:
                pass

            # private keys
            snap.private_keys = _collect_private_keys(ssh_dir)

            # authorized_keys
            ak_path = ssh_dir / "authorized_keys"
            if ak_path.is_file():
                snap.authorized_keys_exists = True
                try:
                    snap.authorized_keys_perms = stat.S_IMODE(ak_path.stat().st_mode)
                except OSError:
                    pass
                snap.authorized_keys_entries = _parse_authorized_keys(ak_path)

            # client config
            cfg_path = ssh_dir / "config"
            if cfg_path.is_file():
                snap.client_config_exists = True
                snap.client_config_entries = _parse_client_config(cfg_path)

            # known_hosts
            kh_path = ssh_dir / "known_hosts"
            if kh_path.is_file():
                snap.known_hosts_exists = True
                snap.known_hosts_entries = _parse_known_hosts(kh_path)

        return snap


# ---------------------------------------------------------------------------
# Main check function (pure logic — no I/O)
# ---------------------------------------------------------------------------

def check_ssh(snapshot: SSHSnapshot, t: TranslationFunc | None = None, ssh_exposed: bool = True) -> CheckResult:
    """
    Check SSH server and client configuration.

    Args:
        snapshot:     SSHSnapshot collected from the system (or built in tests).
        t:            Translation function. Defaults to key pass-through.
        ssh_exposed:  False when SSH is not reachable from outside (local network +
                      UFW default deny). Downgrades PasswordAuthentication from WARN
                      to INFO and appends a context note.

    Returns:
        CheckResult with findings and score deductions.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    # --- SSH not installed ---
    if not snapshot.sshd_installed:
        result.info(
            message=_t("ssh.not_installed"),
            detail=_t("ssh.not_installed_detail", cmd=snapshot.install_cmd),
            key="ssh.not_installed",
        )
        return result

    # --- SSH not active ---
    if not snapshot.sshd_active:
        result.warn(
            message=_t("ssh.not_active"),
            detail=_t("ssh.not_active_detail"),
            nature="action",
            cmd="sudo systemctl enable --now ssh",
            key="ssh.not_active",
        )
    else:
        result.ok(message=_t("ssh.active"), key="ssh.active")

    # --- server host keys ---
    _check_host_keys(snapshot, result, _t)

    # --- sshd_config ---
    _check_sshd_config(snapshot, result, _t, ssh_exposed=ssh_exposed)

    # --- ~/.ssh directory permissions ---
    _check_ssh_dir(snapshot, result, _t)

    # --- private keys ---
    _check_private_keys(snapshot, result, _t)

    # --- authorized_keys ---
    _check_authorized_keys(snapshot, result, _t)

    # --- client config (~/.ssh/config) ---
    _check_client_config(snapshot, result, _t)

    # --- known_hosts ---
    _check_known_hosts(snapshot, result, _t)

    # Correlation note: when SSH is behind a deny firewall on a local network,
    # the above informational findings have reduced real-world impact.
    if not ssh_exposed:
        has_non_ok = any(
            f.level != FindingLevel.OK
            for f in result.findings
        )
        if has_non_ok:
            result.info(
                message=_t("ssh.local_context_note"),
                key="ssh.local_context_note",
            )

    return result


# ---------------------------------------------------------------------------
# Sub-check functions
# ---------------------------------------------------------------------------

def _check_host_keys(snapshot: SSHSnapshot, result: CheckResult, _t) -> None:
    """Audit server host keys in /etc/ssh/ssh_host_*."""
    keys = snapshot.host_keys
    if not keys:
        return  # No host keys found — daemon probably not configured, skip silently

    for hk in keys:
        name = hk.path.name

        if hk.key_type == "dsa":
            result.warn(
                message=_t("ssh.host_key_dsa", name=name),
                nature="improvement",
                detail=_t("ssh.host_key_dsa_detail"),
                cmd=f"sudo rm {hk.path} {hk.path}.pub && sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N '' && sudo systemctl restart ssh",
                cmd_type="fix",
                key="ssh.host_key_dsa",
            )
            result.add_deduction(
                reason=_t("ssh.host_key_dsa_reason", name=name),
                points=1,
                context="local",
                key="ssh.host_key_dsa",
            )

        elif hk.key_type == "rsa" and hk.rsa_bits is not None and hk.rsa_bits < 4096:
            result.info(
                message=_t("ssh.host_key_rsa_short", name=name, bits=hk.rsa_bits),
                detail=_t("ssh.host_key_rsa_short_detail"),
                cmd="sudo ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N '' && sudo systemctl restart ssh",
                cmd_type="fix",
                key="ssh.host_key_rsa_short",
            )

        else:
            # ed25519, ecdsa, RSA ≥ 4096, or unknown → OK
            result.ok(
                message=_t("ssh.host_key_ok", name=name, type=hk.key_type.upper()),
                key="ssh.host_key_ok",
            )


def _check_sshd_config(snapshot: SSHSnapshot, result: CheckResult, _t,
                       ssh_exposed: bool = True) -> None:
    """Analyse /etc/ssh/sshd_config directives."""
    cfg = snapshot.sshd_config
    found_issue = False

    # PermitRootLogin
    prl = cfg.get("permitrootlogin", "prohibit-password").lower()
    if prl == "yes":
        result.alert(
            message=_t("ssh.permit_root_login", value=prl),
            detail=_t("ssh.permit_root_login_detail"),
            nature="improvement",
            cmd="",
            key="ssh.permit_root_login",
        )
        result.add_deduction(
            reason=_t("ssh.permit_root_login", value=prl),
            points=3, context="local", key="ssh.permit_root_login",
        )
        found_issue = True
    elif prl == "no":
        result.ok(
            message=_t("ssh.permit_root_login_disabled"),
            key="ssh.permit_root_login_disabled",
        )
    elif prl in ("prohibit-password", "forced-commands-only"):
        result.ok(
            message=_t("ssh.permit_root_login_restricted", value=prl),
            key="ssh.permit_root_login_restricted",
        )
    else:
        result.info(
            message=_t("ssh.permit_root_login", value=prl),
            key="ssh.permit_root_login",
        )

    # PasswordAuthentication
    pw_auth = cfg.get("passwordauthentication", "yes").lower()
    if pw_auth == "yes":
        if ssh_exposed:
            result.warn(
                message=_t("ssh.password_auth"),
                detail=_t("ssh.password_auth_detail"),
                nature="improvement",
                cmd="",
                key="ssh.password_auth",
            )
            result.add_deduction(
                reason=_t("ssh.password_auth"),
                points=2, context="local", key="ssh.password_auth",
            )
            found_issue = True
        else:
            result.info(
                message=_t("ssh.password_auth_local"),
                detail=_t("ssh.password_auth_local_detail"),
                key="ssh.password_auth",
            )

    # PermitEmptyPasswords
    pep = cfg.get("permitemptypasswords", "no").lower()
    if pep == "yes":
        result.alert(
            message=_t("ssh.permit_empty_passwords"),
            nature="improvement",
            cmd="",
            key="ssh.permit_empty_passwords",
        )
        result.add_deduction(
            reason=_t("ssh.permit_empty_passwords"),
            points=5, context="local", key="ssh.permit_empty_passwords",
        )
        found_issue = True

    # MaxAuthTries
    try:
        max_tries = int(cfg.get("maxauthtries", "6"))
    except ValueError:
        max_tries = 6
    if max_tries > 3:
        result.warn(
            message=_t("ssh.max_auth_tries", value=max_tries),
            nature="improvement",
            cmd="",
            key="ssh.max_auth_tries",
        )
        result.add_deduction(
            reason=_t("ssh.max_auth_tries", value=max_tries),
            points=1, context="local", key="ssh.max_auth_tries",
        )
        found_issue = True

    # LoginGraceTime
    raw_grace = cfg.get("logingracetime", "120")
    grace_secs = _parse_time_seconds(raw_grace)
    if grace_secs > 60:
        result.info(
            message=_t("ssh.login_grace_time", value=grace_secs),
            key="ssh.login_grace_time",
        )

    # X11Forwarding
    x11 = cfg.get("x11forwarding", "no").lower()
    if x11 == "yes":
        result.warn(
            message=_t("ssh.x11_forwarding"),
            nature="improvement",
            cmd="",
            key="ssh.x11_forwarding",
        )
        result.add_deduction(
            reason=_t("ssh.x11_forwarding"),
            points=1, context="local", key="ssh.x11_forwarding",
        )
        found_issue = True

    # IgnoreRhosts
    ignore_rhosts = cfg.get("ignorerhosts", "yes").lower()
    if ignore_rhosts == "no":
        result.warn(
            message=_t("ssh.ignore_rhosts_disabled"),
            nature="improvement",
            cmd="",
            key="ssh.ignore_rhosts_disabled",
        )
        result.add_deduction(
            reason=_t("ssh.ignore_rhosts_disabled"),
            points=2, context="local", key="ssh.ignore_rhosts_disabled",
        )
        found_issue = True

    # HostbasedAuthentication
    hba = cfg.get("hostbasedauthentication", "no").lower()
    if hba == "yes":
        result.alert(
            message=_t("ssh.host_based_auth"),
            nature="improvement",
            cmd="",
            key="ssh.host_based_auth",
        )
        result.add_deduction(
            reason=_t("ssh.host_based_auth"),
            points=3, context="local", key="ssh.host_based_auth",
        )
        found_issue = True

    # PermitUserEnvironment
    pue = cfg.get("permituserenvironment", "no").lower()
    if pue == "yes":
        result.warn(
            message=_t("ssh.permit_user_env"),
            nature="improvement",
            cmd="",
            key="ssh.permit_user_env",
        )
        result.add_deduction(
            reason=_t("ssh.permit_user_env"),
            points=1, context="local", key="ssh.permit_user_env",
        )
        found_issue = True

    # StrictModes
    strict = cfg.get("strictmodes", "yes").lower()
    if strict == "no":
        result.warn(
            message=_t("ssh.strict_modes_disabled"),
            nature="improvement",
            cmd="",
            key="ssh.strict_modes_disabled",
        )
        result.add_deduction(
            reason=_t("ssh.strict_modes_disabled"),
            points=2, context="local", key="ssh.strict_modes_disabled",
        )
        found_issue = True

    # Weak Ciphers
    ciphers_str = cfg.get("ciphers", "")
    if ciphers_str:
        configured = {c.strip().lower() for c in ciphers_str.split(",")}
        weak = sorted(configured & _WEAK_CIPHERS)
        if weak:
            result.warn(
                message=_t("ssh.weak_ciphers", ciphers=", ".join(weak)),
                nature="improvement",
                cmd="",
                key="ssh.weak_ciphers",
            )
            result.add_deduction(
                reason=_t("ssh.weak_ciphers", ciphers=", ".join(weak)),
                points=2, context="local", key="ssh.weak_ciphers",
            )
            found_issue = True

    # Weak MACs
    macs_str = cfg.get("macs", "")
    if macs_str:
        configured = {m.strip().lower() for m in macs_str.split(",")}
        weak = sorted(configured & _WEAK_MACS)
        if weak:
            result.warn(
                message=_t("ssh.weak_macs", macs=", ".join(weak)),
                nature="improvement",
                cmd="",
                key="ssh.weak_macs",
            )
            result.add_deduction(
                reason=_t("ssh.weak_macs", macs=", ".join(weak)),
                points=1, context="local", key="ssh.weak_macs",
            )
            found_issue = True

    # Weak KexAlgorithms
    kex_str = cfg.get("kexalgorithms", "")
    if kex_str:
        configured = {k.strip().lower() for k in kex_str.split(",")}
        weak = sorted(configured & _WEAK_KEX)
        if weak:
            result.warn(
                message=_t("ssh.weak_kex", kex=", ".join(weak)),
                nature="improvement",
                cmd="",
                key="ssh.weak_kex",
            )
            result.add_deduction(
                reason=_t("ssh.weak_kex", kex=", ".join(weak)),
                points=1, context="local", key="ssh.weak_kex",
            )
            found_issue = True

    # AllowTcpForwarding
    atf = cfg.get("allowtcpforwarding", "yes").lower()
    if atf not in ("no",):
        result.warn(
            message=_t("ssh.allow_tcp_forwarding"),
            detail=_t("ssh.allow_tcp_forwarding_detail"),
            nature="improvement",
            cmd="",
            key="ssh.allow_tcp_forwarding",
        )
        result.add_deduction(
            reason=_t("ssh.allow_tcp_forwarding"),
            points=1, context="local", key="ssh.allow_tcp_forwarding",
        )
        found_issue = True

    # PubkeyAuthentication
    pka = cfg.get("pubkeyauthentication", "yes").lower()
    if pka == "no":
        result.alert(
            message=_t("ssh.pubkey_auth_disabled"),
            detail=_t("ssh.pubkey_auth_disabled_detail"),
            nature="improvement",
            cmd="",
            key="ssh.pubkey_auth_disabled",
        )
        result.add_deduction(
            reason=_t("ssh.pubkey_auth_disabled"),
            points=3, context="local", key="ssh.pubkey_auth_disabled",
        )
        found_issue = True

    # AllowUsers / AllowGroups (informational only)
    has_restriction = any(k in cfg for k in ("allowusers", "allowgroups",
                                              "denyusers", "denygroups"))
    if not has_restriction:
        result.info(
            message=_t("ssh.no_allow_users"),
            key="ssh.no_allow_users",
        )

    if cfg.get("_match_block"):
        result.info(
            message=_t("ssh.match_block_skipped"),
            key="ssh.match_block_skipped",
        )

    if not found_issue:
        result.ok(message=_t("ssh.config_ok"), key="ssh.config_ok")


def _check_ssh_dir(snapshot: SSHSnapshot, result: CheckResult, _t) -> None:
    """Check ~/.ssh directory permissions."""
    user = snapshot.sudo_user or "root"
    if not snapshot.ssh_dir_exists:
        result.info(
            message=_t("ssh.dir_not_found", user=user),
            key="ssh.dir_not_found",
        )
        return

    perms = snapshot.ssh_dir_perms
    if perms is not None and perms != 0o700:
        perms_str = oct(perms)
        result.alert(
            message=_t("ssh.dir_perms", perms=perms_str),
            nature="action",
            cmd=f"chmod 700 {snapshot.user_home / '.ssh'}",
            key="ssh.dir_perms",
        )
        result.add_deduction(
            reason=_t("ssh.dir_perms", perms=perms_str),
            points=2, context="local", key="ssh.dir_perms",
        )
    else:
        result.ok(message=_t("ssh.dir_perms_ok"), key="ssh.dir_perms_ok")


def _check_private_keys(snapshot: SSHSnapshot, result: CheckResult, _t) -> None:
    """Analyse private SSH keys in ~/.ssh/."""
    if not snapshot.ssh_dir_exists:
        return

    keys = snapshot.private_keys
    if not keys:
        result.info(message=_t("ssh.no_private_keys"), key="ssh.no_private_keys")
        return

    for ki in keys:
        name = ki.path.name

        # permissions
        if ki.permissions != 0o600:
            perms_str = oct(ki.permissions)
            result.alert(
                message=_t("ssh.private_key_perms", name=name, perms=perms_str),
                nature="action",
                cmd=f"chmod 600 {ki.path}",
                key="ssh.private_key_perms",
            )
            result.add_deduction(
                reason=_t("ssh.private_key_perms", name=name, perms=perms_str),
                points=2, context="local", key="ssh.private_key_perms",
            )

        # key type
        if ki.key_type == "dsa":
            result.alert(
                message=_t("ssh.dsa_key", name=name),
                detail=_t("ssh.dsa_key_detail"),
                nature="improvement",
                cmd="",
                key="ssh.dsa_key",
            )
            result.add_deduction(
                reason=_t("ssh.dsa_key", name=name),
                points=2, context="local", key="ssh.dsa_key",
            )
        elif ki.key_type == "rsa" and ki.rsa_bits is not None and ki.rsa_bits < 2048:
            result.warn(
                message=_t("ssh.rsa_weak", name=name, bits=ki.rsa_bits),
                nature="improvement",
                cmd="",
                key="ssh.rsa_weak",
            )
            result.add_deduction(
                reason=_t("ssh.rsa_weak", name=name, bits=ki.rsa_bits),
                points=1, context="local", key="ssh.rsa_weak",
            )
        elif ki.key_type == "rsa" and ki.rsa_bits is not None:
            result.ok(
                message=_t("ssh.rsa_ok", name=name, bits=ki.rsa_bits),
                key="ssh.rsa_ok",
            )

        # passphrase
        if ki.has_passphrase is False:
            result.warn(
                message=_t("ssh.no_passphrase", name=name),
                nature="improvement",
                cmd="",
                key="ssh.no_passphrase",
            )
            result.add_deduction(
                reason=_t("ssh.no_passphrase", name=name),
                points=1, context="local", key="ssh.no_passphrase",
            )

        if (ki.permissions == 0o600
                and ki.key_type not in ("dsa",)
                and not (ki.key_type == "rsa"
                         and ki.rsa_bits is not None
                         and ki.rsa_bits < 2048)
                and ki.has_passphrase is not False):
            result.ok(
                message=_t("ssh.key_ok", name=name),
                key="ssh.key_ok",
            )


def _check_authorized_keys(snapshot: SSHSnapshot, result: CheckResult, _t) -> None:
    """Analyse authorized_keys entries."""
    if not snapshot.ssh_dir_exists:
        return

    if not snapshot.authorized_keys_exists:
        result.info(
            message=_t("ssh.authorized_keys_not_found"),
            key="ssh.authorized_keys_not_found",
        )
        return

    # permissions
    perms = snapshot.authorized_keys_perms
    if perms is not None and perms != 0o600:
        ak_path = (snapshot.user_home or Path("/root")) / ".ssh" / "authorized_keys"
        result.alert(
            message=_t("ssh.authorized_keys_perms", perms=oct(perms)),
            nature="action",
            cmd=f"chmod 600 {ak_path}",
            key="ssh.authorized_keys_perms",
        )
        result.add_deduction(
            reason=_t("ssh.authorized_keys_perms", perms=oct(perms)),
            points=2, context="local", key="ssh.authorized_keys_perms",
        )

    entries = snapshot.authorized_keys_entries
    if not entries:
        return

    ak_found_issue = False

    # weak key types and sizes
    for entry in entries:
        if entry.key_type == "ssh-dss":
            result.alert(
                message=_t("ssh.authorized_keys_dsa", line=entry.line_no),
                nature="improvement",
                cmd="",
                key="ssh.authorized_keys_dsa",
            )
            result.add_deduction(
                reason=_t("ssh.authorized_keys_dsa", line=entry.line_no),
                points=2, context="local", key="ssh.authorized_keys_dsa",
            )
            ak_found_issue = True
        elif (entry.key_type == "ssh-rsa"
              and entry.rsa_bits is not None
              and entry.rsa_bits < 2048):
            result.warn(
                message=_t("ssh.authorized_keys_weak_key",
                           line=entry.line_no,
                           type=entry.key_type,
                           bits=entry.rsa_bits),
                key="ssh.authorized_keys_weak_key",
            )
            result.add_deduction(
                reason=_t("ssh.authorized_keys_weak_key",
                          line=entry.line_no,
                          type=entry.key_type,
                          bits=entry.rsa_bits),
                points=1, context="local", key="ssh.authorized_keys_weak_key",
            )
            ak_found_issue = True

    # duplicate keys
    seen_blobs: dict[str, int] = {}
    for entry in entries:
        if entry.blob_prefix in seen_blobs:
            result.warn(
                message=_t("ssh.authorized_keys_duplicate",
                           a=seen_blobs[entry.blob_prefix],
                           b=entry.line_no),
                key="ssh.authorized_keys_duplicate",
            )
            result.add_deduction(
                reason=_t("ssh.authorized_keys_duplicate",
                          a=seen_blobs[entry.blob_prefix],
                          b=entry.line_no),
                points=1, context="local", key="ssh.authorized_keys_duplicate",
            )
            ak_found_issue = True
        else:
            seen_blobs[entry.blob_prefix] = entry.line_no

    # keys without restrictions (informational — does not prevent ok)
    unrestricted = [e for e in entries if not e.has_restrictions]
    if unrestricted:
        result.info(
            message=_t("ssh.authorized_keys_no_restrictions",
                       count=len(unrestricted)),
            key="ssh.authorized_keys_no_restrictions",
        )

    if not ak_found_issue:
        result.ok(
            message=_t("ssh.authorized_keys_ok", count=len(entries)),
            key="ssh.authorized_keys_ok",
        )


def _check_client_config(snapshot: SSHSnapshot, result: CheckResult, _t) -> None:
    """Analyse ~/.ssh/config for dangerous settings."""
    if not snapshot.ssh_dir_exists:
        return

    if not snapshot.client_config_exists:
        result.info(
            message=_t("ssh.client_config_not_found"),
            key="ssh.client_config_not_found",
        )
        return

    found_issue = False
    entries = snapshot.client_config_entries

    for entry in entries:
        k, v = entry.key, entry.value.lower()

        if k == "stricthostkeychecking" and v == "no":
            result.alert(
                message=_t("ssh.client_strict_host_no"),
                detail=_t("ssh.client_strict_host_no_detail"),
                nature="improvement",
                cmd="",
                key="ssh.client_strict_host_no",
            )
            result.add_deduction(
                reason=_t("ssh.client_strict_host_no"),
                points=3, context="local", key="ssh.client_strict_host_no",
            )
            found_issue = True

        elif k == "userknownhostsfile" and "/dev/null" in v:
            result.alert(
                message=_t("ssh.client_known_hosts_devnull"),
                detail=_t("ssh.client_known_hosts_devnull_detail"),
                nature="improvement",
                cmd="",
                key="ssh.client_known_hosts_devnull",
            )
            result.add_deduction(
                reason=_t("ssh.client_known_hosts_devnull"),
                points=3, context="local", key="ssh.client_known_hosts_devnull",
            )
            found_issue = True

        elif k == "forwardagent" and v == "yes":
            result.warn(
                message=_t("ssh.client_forward_agent"),
                detail=_t("ssh.client_forward_agent_detail"),
                nature="improvement",
                cmd="",
                key="ssh.client_forward_agent",
            )
            result.add_deduction(
                reason=_t("ssh.client_forward_agent"),
                points=1, context="local", key="ssh.client_forward_agent",
            )
            found_issue = True

    if not found_issue:
        result.ok(
            message=_t("ssh.client_config_ok"),
            key="ssh.client_config_ok",
        )


def _check_known_hosts(snapshot: SSHSnapshot, result: CheckResult, _t) -> None:
    """Analyse known_hosts entries."""
    if not snapshot.ssh_dir_exists:
        return

    if not snapshot.known_hosts_exists:
        result.info(
            message=_t("ssh.known_hosts_not_found"),
            key="ssh.known_hosts_not_found",
        )
        return

    entries = snapshot.known_hosts_entries
    found_issue = False

    # deprecated key types
    deprecated = [e for e in entries if e.key_type in ("ssh-dss", "ssh-rsa1")]
    for e in deprecated:
        result.warn(
            message=_t("ssh.known_hosts_deprecated",
                       line=e.line_no, type=e.key_type),
            key="ssh.known_hosts_deprecated",
        )
        result.add_deduction(
            reason=_t("ssh.known_hosts_deprecated",
                      line=e.line_no, type=e.key_type),
            points=1, context="local", key="ssh.known_hosts_deprecated",
        )
        found_issue = True

    # duplicate host entries (plain text only — hashed entries can't be compared)
    # A host field may contain multiple names: "host1,host2,host3"
    plain_hosts: dict[str, list[int]] = {}
    for e in entries:
        if not e.is_hashed:
            for h in e.host.split(","):
                plain_hosts.setdefault(h.strip(), []).append(e.line_no)
    for host, lines in plain_hosts.items():
        if len(lines) > 1:
            result.info(
                message=_t("ssh.known_hosts_duplicate", host=host),
                key="ssh.known_hosts_duplicate",
            )
            found_issue = True

    if not found_issue:
        result.ok(
            message=_t("ssh.known_hosts_ok", count=len(entries)),
            key="ssh.known_hosts_ok",
        )


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _parse_config_file(
    path: Path,
    config: dict[str, str],
    seen: set[str],
    sources: list[str],
) -> None:
    """
    Parse an sshd_config file (or drop-in) into config dict.
    First-value-wins semantics (OpenSSH behaviour).
    Handles Include directives recursively.
    Stops at first Match block (conditional config — not parsed).
    """
    canonical = str(path.resolve())
    if canonical in seen:
        return
    seen.add(canonical)
    sources.append(str(path))

    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Stop at Match blocks — conditional overrides not handled
        if re.match(r"^match\b", stripped, re.IGNORECASE):
            config["_match_block"] = True
            break

        # Include directive
        inc_match = re.match(r"^include\s+(.+)$", stripped, re.IGNORECASE)
        if inc_match:
            pattern = inc_match.group(1).strip()
            if not os.path.isabs(pattern):
                pattern = str(path.parent / pattern)
            for inc in sorted(_glob.glob(pattern)):
                _parse_config_file(Path(inc), config, seen, sources)
            continue

        # Key Value  (space or = separator; value may be quoted)
        m = re.match(r"^(\w+)[\s=]+(.+)$", stripped)
        if m:
            key   = m.group(1).lower()
            value = m.group(2).strip().strip('"')
            config.setdefault(key, value)  # first-value-wins


def _collect_private_keys(ssh_dir: Path) -> list[PrivateKeyInfo]:
    """Return PrivateKeyInfo for each private key file found in ssh_dir."""
    results = []
    try:
        entries = list(ssh_dir.iterdir())
    except OSError:
        return results

    pub_names = {f.stem for f in entries if f.suffix == _PUB_SUFFIX}

    for f in entries:
        if f.suffix == _PUB_SUFFIX:
            continue
        if f.name in _NON_KEY_FILES:
            continue
        if not f.is_file():
            continue

        # Confirm it looks like a private key
        try:
            header = f.read_bytes()[:64].decode("ascii", errors="ignore")
        except OSError:
            continue
        if "PRIVATE KEY" not in header and f.stem not in pub_names:
            continue

        try:
            perms = stat.S_IMODE(f.stat().st_mode)
        except OSError:
            perms = 0

        key_type = _detect_private_key_type(f, header)
        rsa_bits: Optional[int] = None
        if key_type == "rsa":
            pub = ssh_dir / (f.name + _PUB_SUFFIX)
            if pub.is_file():
                rsa_bits = _rsa_bits_from_pub_file(pub)

        has_pass = _has_passphrase(f)

        results.append(PrivateKeyInfo(
            path=f,
            permissions=perms,
            key_type=key_type,
            rsa_bits=rsa_bits,
            has_passphrase=has_pass,
        ))
    return results


def _detect_private_key_type(path: Path, header: str) -> str:
    """Infer key type from file header or name."""
    header_lower = header.lower()
    if "rsa private key" in header_lower:
        return "rsa"
    if "dsa private key" in header_lower:
        return "dsa"
    if "ec private key" in header_lower:
        return "ecdsa"
    # New OpenSSH format — check filename
    # Check ecdsa before dsa — "ecdsa" contains "dsa" as a substring
    name = path.stem.lower()
    if "ecdsa" in name:
        return "ecdsa"
    if "rsa" in name:
        return "rsa"
    if "dsa" in name:
        return "dsa"
    if "ed25519" in name:
        return "ed25519"
    # New format without name hints — try reading the full public key blob
    pub = path.parent / (path.name + _PUB_SUFFIX)
    if pub.is_file():
        try:
            first = pub.read_text(encoding="utf-8", errors="ignore").split()
            if first:
                return _key_type_from_algo(first[0])
        except OSError:
            pass
    return "unknown"


def _key_type_from_algo(algo: str) -> str:
    """Map SSH algorithm string to short key type."""
    algo = algo.lower()
    # Check ecdsa before dsa — "ecdsa" contains "dsa" as a substring
    if "ecdsa" in algo:
        return "ecdsa"
    if "rsa" in algo:
        return "rsa"
    if "dss" in algo or "dsa" in algo:
        return "dsa"
    if "ed25519" in algo:
        return "ed25519"
    return "unknown"


def _rsa_bits_from_pub_file(pub_path: Path) -> Optional[int]:
    """Extract RSA key size in bits from a .pub file."""
    try:
        parts = pub_path.read_text(encoding="utf-8", errors="ignore").split()
    except OSError:
        return None
    if len(parts) < 2:
        return None
    return _rsa_bits_from_blob(parts[1])


def _rsa_bits_from_blob(b64_blob: str) -> Optional[int]:
    """
    Decode the base64 public key blob and extract the RSA modulus length.
    SSH RSA public key wire format: [ktype_len][ktype][e_len][e][n_len][n]
    """
    try:
        data = base64.b64decode(b64_blob + "==")
        pos = 0
        # skip key type string
        ktype_len = struct.unpack_from(">I", data, pos)[0]
        pos += 4 + ktype_len
        # skip public exponent
        e_len = struct.unpack_from(">I", data, pos)[0]
        pos += 4 + e_len
        # read modulus
        n_len = struct.unpack_from(">I", data, pos)[0]
        pos += 4
        n_bytes = data[pos: pos + n_len]
        # strip potential leading 0x00 sign byte
        if n_bytes and n_bytes[0] == 0:
            n_bytes = n_bytes[1:]
        return len(n_bytes) * 8
    except (struct.error, ValueError):
        return None


def _has_passphrase(path: Path) -> Optional[bool]:
    """
    Return True if the private key is encrypted, False if not, None if unknown.

    Supports:
    - New OpenSSH format (openssh-key-v1): checks cipher field in binary header
    - Old PEM format (RSA/DSA/EC): checks for "Proc-Type: 4,ENCRYPTED" line
    """
    try:
        raw = path.read_bytes()
    except OSError:
        return None

    text = raw.decode("ascii", errors="ignore")

    # New OpenSSH format
    if "BEGIN OPENSSH PRIVATE KEY" in text:
        b64_lines = [ln for ln in text.splitlines()
                     if not ln.startswith("-----")]
        try:
            data = base64.b64decode("".join(b64_lines))
            magic = b"openssh-key-v1\x00"
            if data.startswith(magic):
                pos = len(magic)
                if len(data) < pos + 4:
                    return None
                cipher_len = int.from_bytes(data[pos: pos + 4], "big")
                if len(data) < pos + 4 + cipher_len:
                    return None
                cipher = data[pos + 4: pos + 4 + cipher_len].decode(
                    "ascii", errors="ignore"
                )
                return cipher != "none"
        except (binascii.Error, ValueError):
            return None

    # Old PEM format
    if "Proc-Type: 4,ENCRYPTED" in text or "DEK-Info:" in text:
        return True
    if any(m in text for m in (
        "BEGIN RSA PRIVATE KEY",
        "BEGIN DSA PRIVATE KEY",
        "BEGIN EC PRIVATE KEY",
        "BEGIN PRIVATE KEY",
    )):
        return False

    return None


# Regex matching SSH public key algo names in authorized_keys
_AK_KEY_TYPES = re.compile(
    r"^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp256|"
    r"ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh\.com|"
    r"sk-ecdsa-sha2-nistp256@openssh\.com)$",
    re.IGNORECASE,
)

# Options that restrict key usage
_AK_RESTRICTIONS = re.compile(
    r'\b(command=|from=|no-pty|no-x11-forwarding|no-agent-forwarding|'
    r'no-port-forwarding|restrict\b)',
    re.IGNORECASE,
)


def _parse_authorized_keys(path: Path) -> list[AuthorizedKeyEntry]:
    """Parse authorized_keys, return one AuthorizedKeyEntry per valid key line."""
    entries: list[AuthorizedKeyEntry] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return entries

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        tokens = stripped.split()
        # Find the key type token
        key_type = ""
        blob = ""
        has_restrictions = False

        for i, tok in enumerate(tokens):
            if _AK_KEY_TYPES.match(tok):
                key_type = tok.lower()
                blob = tokens[i + 1] if i + 1 < len(tokens) else ""
                # Anything before the key type are options
                if i > 0:
                    options_str = " ".join(tokens[:i])
                    has_restrictions = bool(_AK_RESTRICTIONS.search(options_str))
                break

        if not key_type:
            continue

        rsa_bits: Optional[int] = None
        if key_type == "ssh-rsa" and blob:
            rsa_bits = _rsa_bits_from_blob(blob)

        entries.append(AuthorizedKeyEntry(
            line_no=lineno,
            key_type=key_type,
            rsa_bits=rsa_bits,
            has_restrictions=has_restrictions,
            blob_prefix=blob[:32],
        ))
    return entries


def _parse_client_config(path: Path) -> list[ClientConfigEntry]:
    """Parse ~/.ssh/config into ClientConfigEntry list."""
    entries: list[ClientConfigEntry] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return entries

    current_host = "*"
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = re.match(r"^(\w+)\s+(.+)$", stripped)
        if not m:
            continue
        key   = m.group(1).lower()
        value = m.group(2).strip()
        if key == "host":
            current_host = value
            continue
        entries.append(ClientConfigEntry(
            host=current_host,
            key=key,
            value=value,
        ))
    return entries


def _parse_known_hosts(path: Path) -> list[KnownHostEntry]:
    """Parse known_hosts into KnownHostEntry list."""
    entries: list[KnownHostEntry] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return entries

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        host     = parts[0]
        key_type = parts[1].lower() if len(parts) >= 2 else "unknown"
        is_hashed = host.startswith("|1|")
        entries.append(KnownHostEntry(
            line_no=lineno,
            host=host,
            key_type=key_type,
            is_hashed=is_hashed,
        ))
    return entries


def _collect_host_keys() -> list[HostKeyInfo]:
    """
    Collect server host key info from /etc/ssh/ssh_host_*_key.pub.

    Reads the .pub file (world-readable) to determine type and RSA size
    without needing root access to the private key.
    """
    results: list[HostKeyInfo] = []
    try:
        pub_files = sorted(Path("/etc/ssh").glob("ssh_host_*_key.pub"))
    except OSError:
        return results

    for pub in pub_files:
        # Private key path (same name without .pub)
        priv = pub.with_suffix("")
        try:
            parts = pub.read_text(encoding="utf-8", errors="ignore").split()
        except OSError:
            continue
        if len(parts) < 2:
            continue

        algo = parts[0].lower()
        blob = parts[1]
        key_type = _key_type_from_algo(algo)
        rsa_bits: Optional[int] = None
        if key_type == "rsa":
            rsa_bits = _rsa_bits_from_blob(blob)

        results.append(HostKeyInfo(path=priv, key_type=key_type, rsa_bits=rsa_bits))

    return results


def _detect_ssh_install_cmd() -> str:
    """Return the distro-appropriate command to install openssh-server."""
    candidates = [
        ("apt",    "sudo apt install openssh-server"),
        ("apt-get","sudo apt-get install openssh-server"),
        ("dnf",    "sudo dnf install openssh-server"),
        ("yum",    "sudo yum install openssh-server"),
        ("pacman", "sudo pacman -S openssh"),
        ("zypper", "sudo zypper install openssh"),
        ("apk",    "sudo apk add openssh"),
    ]
    for cmd, install in candidates:
        if _command_exists(cmd):
            return install
    return "sudo <package-manager> install openssh-server"


def _parse_time_seconds(value: str) -> int:
    """
    Parse sshd LoginGraceTime value to seconds.
    Accepts plain integer (seconds) or suffixes: s, m, h, d, w.
    Returns 120 on parse error (OpenSSH default).
    """
    value = value.strip().lower()
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    if value and value[-1] in multipliers:
        try:
            return int(value[:-1]) * multipliers[value[-1]]
        except ValueError:
            return 120
    try:
        return int(value)
    except ValueError:
        return 120
