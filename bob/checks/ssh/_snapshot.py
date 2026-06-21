"""SSH dataclasses and SSHSnapshot.

Extracted from bob/checks/ssh.py in v0.6.0 (#13 split). The dataclasses
have no SSH-internal dependencies — they're plain data. SSHSnapshot.from_system()
uses local imports of ``_parsers`` to break the natural cycle between the
data layer and the parser layer.
"""

from __future__ import annotations

import os
import pwd
import stat
from dataclasses import dataclass, field
from pathlib import Path

from bob.checks._run import _command_exists, _is_safe_user_path, is_unit_active

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

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
    rsa_bits: int | None # None for non-RSA keys or when undeterminable

@dataclass
class PrivateKeyInfo:
    """Information about a private SSH key file in ~/.ssh/."""
    path:           Path
    permissions:    int           # raw stat mode bits (S_IMODE)
    key_type:       str           # "rsa", "dsa", "ecdsa", "ed25519", "unknown"
    rsa_bits:       int | None # None for non-RSA keys or when undeterminable
    has_passphrase: bool | None# None if undeterminable

@dataclass
class AuthorizedKeyEntry:
    """A single valid key entry from authorized_keys."""
    line_no:          int
    key_type:         str           # e.g. "ssh-rsa", "ssh-ed25519"
    rsa_bits:         int | None
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

    host_keys:               list[HostKeyInfo] = field(default_factory=list)

    sudo_user:               str = ""
    user_home:               Path | None = None
    ssh_dir_exists:          bool = False
    ssh_dir_perms:           int | None = None  # None if dir absent

    private_keys:            list[PrivateKeyInfo] = field(default_factory=list)

    authorized_keys_exists:  bool = False
    authorized_keys_perms:   int | None = None
    authorized_keys_entries: list[AuthorizedKeyEntry] = field(default_factory=list)

    client_config_exists:    bool = False
    client_config_entries:   list[ClientConfigEntry] = field(default_factory=list)

    known_hosts_exists:      bool = False
    known_hosts_entries:     list[KnownHostEntry] = field(default_factory=list)
    install_cmd:             str = ""  # distro-appropriate install command

    @classmethod
    def from_system(cls) -> "SSHSnapshot":
        # Local import to break the snapshot/parsers cycle: _parsers needs the
        # dataclasses defined above, so it imports from _snapshot at module
        # level; _snapshot can therefore only import from _parsers inside
        # function bodies.
        from . import _parsers

        snap = cls()

        # --- distro-appropriate install command ---
        snap.install_cmd = _parsers._detect_ssh_install_cmd()

        # --- sshd installation and status ---
        snap.sshd_installed = (
            _command_exists("sshd")
            or Path("/usr/sbin/sshd").exists()
            or Path("/sbin/sshd").exists()
        )
        if snap.sshd_installed and _command_exists("systemctl"):
            for unit in ("ssh", "sshd"):
                if is_unit_active(unit):
                    snap.sshd_active = True
                    break

        # --- server host keys ---
        snap.host_keys = _parsers._collect_host_keys()

        # --- sshd_config (server) ---
        if _SSHD_CONFIG_PATH.exists():
            seen: set[str] = set()
            config: dict[str, str] = {}
            _parsers._parse_config_file(_SSHD_CONFIG_PATH, config, seen)
            snap.sshd_config = config

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
        # The whole user-side probe is guarded: ~/.ssh can sit under a directory
        # the auditor cannot search (e.g. /root/.ssh under a user namespace where
        # root maps to an unprivileged uid), making is_dir()/iterdir() raise
        # PermissionError. A read-only auditor degrades to "couldn't read ~/.ssh"
        # rather than aborting the audit or leaking the OSError into its output.
        # Mirrors ddns._config_present.
        try:
            if ssh_dir.is_dir():
                snap.ssh_dir_exists = True
                try:
                    snap.ssh_dir_perms = stat.S_IMODE(ssh_dir.stat().st_mode)
                except OSError:
                    pass

                # private keys
                snap.private_keys = _parsers._collect_private_keys(ssh_dir)

                # authorized_keys — accept dotfiles symlinks inside home, reject
                # symlinks pointing outside (e.g. attacker linking authorized_keys
                # to /etc/shadow would leak its content into the audit report).
                ak_path = ssh_dir / "authorized_keys"
                if ak_path.is_file() and _is_safe_user_path(ak_path, snap.user_home):
                    snap.authorized_keys_exists = True
                    try:
                        snap.authorized_keys_perms = stat.S_IMODE(ak_path.stat().st_mode)
                    except OSError:
                        pass
                    snap.authorized_keys_entries = _parsers._parse_authorized_keys(ak_path)

                # client config — same symlink-out-of-home protection.
                cfg_path = ssh_dir / "config"
                if cfg_path.is_file() and _is_safe_user_path(cfg_path, snap.user_home):
                    snap.client_config_exists = True
                    snap.client_config_entries = _parsers._parse_client_config(cfg_path)

                # known_hosts — public data but apply the same protection by symmetry.
                kh_path = ssh_dir / "known_hosts"
                if kh_path.is_file() and _is_safe_user_path(kh_path, snap.user_home):
                    snap.known_hosts_exists = True
                    snap.known_hosts_entries = _parsers._parse_known_hosts(kh_path)
        except OSError:
            pass

        return snap
