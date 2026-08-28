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

Module layout (v0.6.0 #13 split):
  - ``_directives``: _BadDirective table + _WEAK_* sets + _apply_bad_directive
  - ``_snapshot``:   HostKeyInfo / PrivateKeyInfo / Authorized/Known/Client dataclasses
                     + SSHSnapshot + SSHSnapshot.from_system
  - ``_parsers``:    pure parsers for sshd_config, authorized_keys, known_hosts,
                     client config + key-type / RSA-size helpers + install-cmd probe
  - ``_subchecks``:  check_ssh + per-area _check_* helpers
"""

from __future__ import annotations

# --- Public API ------------------------------------------------------------
from ._snapshot import (
    AuthorizedKeyEntry,
    ClientConfigEntry,
    HostKeyInfo,
    KnownHostEntry,
    PrivateKeyInfo,
    SSHSnapshot,
)
from ._subchecks import check_ssh

# --- Re-exports for tests / backwards-compat ------------------------------
# These leading-underscore helpers are imported by tests/test_ssh.py — keep
# them re-exported so that `from bob.checks.ssh import _has_passphrase` etc.
# continues to work after the v0.6.0 split.
from ._parsers import (  # noqa: F401 — pure parsers re-exported for tests + back-compat
    _has_passphrase,
    _parse_authorized_keys,
    _parse_client_config,
    _parse_known_hosts,
    _parse_time_seconds,
    _rsa_bits_from_blob,
)

__all__ = [
    "AuthorizedKeyEntry",
    "ClientConfigEntry",
    "HostKeyInfo",
    "KnownHostEntry",
    "PrivateKeyInfo",
    "SSHSnapshot",
    "check_ssh",
]
