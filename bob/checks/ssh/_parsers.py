"""SSH config / key / known-hosts parsers and stateless helpers.

Extracted from bob/checks/ssh.py in v0.6.0 (#13 split). Imports dataclasses
from ``_snapshot`` at module level; _snapshot can only call into _parsers via
function-local imports to avoid the natural cycle.

All functions here are pure (file I/O only — no subprocess except the system
install-command probe in ``_detect_ssh_install_cmd``).
"""

from __future__ import annotations

import base64
import binascii
import glob as _glob
import os
import re
import stat
import struct
from pathlib import Path

from bob.checks._run import _command_exists

from ._snapshot import (
    AuthorizedKeyEntry,
    ClientConfigEntry,
    HostKeyInfo,
    KnownHostEntry,
    PrivateKeyInfo,
    _NON_KEY_FILES,
    _PUB_SUFFIX,
)


def _parse_config_file(
    path: Path,
    config: dict[str, str],
    seen: set[str],
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

    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Stop at Match blocks — conditional overrides not handled.
        # M-8 (v0.5.5): this also stops Include parsing for any include
        # directives appearing AFTER a Match block, which OpenSSH itself
        # would parse. Intentional: handling conditional includes safely
        # requires modeling the full Match context. The audit surfaces
        # the gap via `_match_block=True` → `ssh.match_block` INFO,
        # warning the user to review their config manually.
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
                _parse_config_file(Path(inc), config, seen)
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
        rsa_bits: int | None = None
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

def _rsa_bits_from_pub_file(pub_path: Path) -> int | None:
    """Extract RSA key size in bits from a .pub file."""
    try:
        parts = pub_path.read_text(encoding="utf-8", errors="ignore").split()
    except OSError:
        return None
    if len(parts) < 2:
        return None
    return _rsa_bits_from_blob(parts[1])

def _rsa_bits_from_blob(b64_blob: str) -> int | None:
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

def _has_passphrase(path: Path) -> bool | None:
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

        rsa_bits: int | None = None
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
        rsa_bits: int | None = None
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
