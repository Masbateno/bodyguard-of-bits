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

from bob._atomic import read_text_capped
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
    outer: "dict | None" = None,
) -> None:
    """
    Parse an sshd_config file (or drop-in) into config dict.
    First-value-wins semantics (OpenSSH behaviour).
    Handles Include directives recursively.

    v0.37.0 — Match blocks are read, as sshd reads them (measured with
    ``sshd -T -C`` on Linux Mint 22.3, OpenSSH 9.6p1, a10370): a block runs
    to the next Match or the end of its file — a Match in an included file
    ends with that file, and the including file goes on globally; inside a
    block the first value of a directive wins. Each block is kept in
    ``config["_match_blocks"]`` as ``{"criteria", "settings", "file"}``; an
    Include inside a block is not followed and is recorded in
    ``config["_match_include_unread"]``.

    ``Match all`` is a block like the others, one that every connection
    matches — not a return to the global settings (measured, same host,
    review of 14 November 2026): a value it sets beats the global one, before
    it, or after the Include once an included file's block ends (measured both
    ways; inside one file, what follows a Match belongs to it) (``PasswordAuthentication no`` then ``Match all``
    / ``PasswordAuthentication yes`` → yes for everyone); and since the first
    matching block wins, a later block's value for that key is never applied
    (``Match all`` / ``… no`` then ``Match Address …`` / ``… yes`` → no from that
    address too), while an earlier block's still is. So a ``Match all`` value
    becomes the effective setting in ``config`` itself, recorded in
    ``config["_match_all_keys"]`` (key → file), and a later block's setting for
    such a key is dropped.

    v0.38.0 — an Include inside a block is followed (measured with ``sshd -T
    -C``, a10380, 15 November 2026): what it brings belongs to that block, the
    first value winning across the file boundary; a Match inside the included
    file opens a block that takes a session only when the including block
    does too (both criteria); the including block goes on after the Include.
    *outer* is that including block. A file it names that cannot be read keeps
    the section a ceiling (``_match_include_unread``).

    v0.38.0 — a block whose sessions an earlier block already takes, for a
    key that earlier block set first, never applies that key (measured: a
    ``/25`` after a ``/24``, the same user list in any order or case, ``User
    *``…). Such a setting is dropped and recorded in the block's ``shadowed``
    (key → the earlier block's criteria) — only where the cover is certain
    (`_criteria_cover`); otherwise it is still counted, as before.
    """
    canonical = str(path.resolve())
    seen_key = canonical if outer is None else f"{canonical}@{id(outer)}"
    if seen_key in seen:
        return
    seen.add(seen_key)

    try:
        lines = read_text_capped(path, encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        if outer is not None:
            config.setdefault("_match_include_unread", []).append(
                f"{outer['criteria']}: Include {path}")
        return

    block: "dict | None" = outer         # the Match block being read, None = global
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m_match = re.match(r"^match\s+(.+)$", stripped, re.IGNORECASE)
        if m_match or re.match(r"^match\s*$", stripped, re.IGNORECASE):
            criteria = _strip_inline_comment(m_match.group(1)).strip() if m_match else ""
            if outer is not None:
                criteria = _both_criteria(outer["criteria"], criteria)
            config["_match_block"] = True
            block = {"criteria": criteria, "settings": {}, "file": str(path)}
            config.setdefault("_match_blocks", []).append(block)
            continue

        # Include directive
        inc_match = re.match(r"^include\s+(.+)$", stripped, re.IGNORECASE)
        if inc_match:
            pattern = inc_match.group(1).strip()
            if not os.path.isabs(pattern):
                pattern = str(path.parent / pattern)
            if block is not None:
                # Read in place, its lines the block's (measured, a10380).
                for inc in sorted(_glob.glob(pattern)):
                    _parse_config_file(Path(inc), config, seen, outer=block)
                continue
            # v0.19.0: record the first glob drop-in directory. Modern OpenSSH
            # ships ``Include /etc/ssh/sshd_config.d/*.conf`` at the very top of
            # sshd_config, so a directive set in a drop-in (e.g. cloud-init's
            # ``50-cloud-init.conf``) is read first and, first-value-wins, beats
            # the main file. A fix that edits only the main file is then a no-op;
            # the remediation must write a drop-in that sorts *before* the
            # offending one (``00-bob-hardening.conf``). Recorded here so the
            # sub-check can target the right file. Field-test finding on a real
            # Raspberry Pi (Raspbian trixie).
            if "*" in pattern:
                config.setdefault("_dropin_dir", os.path.dirname(pattern))
            for inc in sorted(_glob.glob(pattern)):
                _parse_config_file(Path(inc), config, seen)
            continue

        # Key Value  (space or = separator; value may be quoted)
        m = re.match(r"^(\w+)[\s=]+(.+)$", stripped)
        if m:
            key   = m.group(1).lower()
            value = _strip_inline_comment(m.group(2)).strip().strip('"')
            if block is not None:
                match_all = config.setdefault("_match_all_keys", {})
                if key in match_all:
                    continue                                # an earlier Match all set it: never applied
                if key in block["settings"]:
                    continue                                # first value wins in the block
                # Only values already read sit in the other blocks: an earlier
                # block that set this key did so before this line (reading order).
                cover = _earlier_cover(config.get("_match_blocks", []), block, key)
                if cover is not None:
                    block.setdefault("shadowed", {})[key] = cover
                    continue                                # an earlier block takes every session first
                block["settings"][key] = value
                if block["criteria"].lower() == "all":
                    match_all[key] = str(path)
                    config[key] = value                     # beats the global value, before or after
                continue
            # v0.32.0 — HostKey is the one directive here that accumulates:
            # sshd loads every key named, in order (sshd_config(5)). Kept
            # whole beside the first-value-wins entry, so the host-key check
            # knows which files sshd serves.
            if key == "hostkey":
                config.setdefault("_hostkeys", []).append(value)
            config.setdefault(key, value)  # first-value-wins


def _both_criteria(outer: str, inner: str) -> str:
    """The criteria of a Match read inside a block's Include: a session must
    match both (measured, a10380 C1d). ``all`` adds nothing."""
    if outer.strip().lower() == "all":
        return inner
    if inner.strip().lower() == "all":
        return outer
    return f"{outer} {inner}"


#: v0.38.0 — the Match criteria whose cover can be decided from the text.
_COVERABLE = frozenset({"user", "group", "host", "address", "localaddress", "localport"})


def _parse_criteria(criteria: str) -> "dict[str, list[str]] | None":
    """``User a,b Address x`` → {"user": ["a", "b"], "address": ["x"]};
    None when it cannot be read as keyword / pattern-list pairs."""
    words = criteria.split()
    if len(words) % 2:
        return None
    out: "dict[str, list[str]]" = {}
    for kw, value in zip(words[0::2], words[1::2], strict=True):
        kw = kw.lower()
        if kw in out:
            return None
        out[kw] = [p for p in value.split(",") if p]
    return out


def _entry_covered(kw: str, entry: str, patterns: "list[str]") -> bool:
    """One positive entry of the later block lies inside the earlier list."""
    from fnmatch import fnmatchcase
    if kw in ("address", "localaddress"):
        import ipaddress
        try:
            inner = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return entry in patterns
        for p in patterns:
            try:
                outer = ipaddress.ip_network(p, strict=False)
            except ValueError:
                continue
            if inner.version == outer.version and inner.subnet_of(outer):
                return True
        return False
    if any(c in entry for c in "*?"):
        return entry in patterns or "*" in patterns
    # v0.38.0 (review 1, m12) — sshd's patterns know `*` and `?` only: a `[` is
    # a literal there (measured: `User a[lb]ice` does not take alice), a class
    # for fnmatch, which then called alice covered and dropped a deduction sshd
    # applies. `[[]` is fnmatch's literal `[`.
    return any(fnmatchcase(entry, p.replace("[", "[[]")) for p in patterns)


def _criteria_cover(earlier: str, later: str) -> bool:
    """Whether every session *later* takes is certainly taken by *earlier*
    (measured cases, a10380): each keyword of *earlier* is in *later*, every
    positive entry of *later* lies inside *earlier*'s list, and *earlier* has
    no negation. Anything this cannot decide is False — the setting is then
    counted, as before 0.38.0."""
    a, b = _parse_criteria(earlier), _parse_criteria(later)
    if a is None or b is None or not a or not set(a) <= _COVERABLE:
        return False
    for kw, patterns in a.items():
        if any(p.startswith("!") for p in patterns) or kw not in b:
            return False
        positives = [e for e in b[kw] if not e.startswith("!")]
        if not positives or not all(_entry_covered(kw, e, patterns) for e in positives):
            return False
    return True


def _earlier_cover(blocks: "list[dict]", block: dict, key: str) -> "str | None":
    """The criteria of another block that already set *key* and takes every
    session *block* takes; None when there is none. Called as *key* is read,
    so whatever the other blocks hold was read before it."""
    for other in blocks:
        if other is not block and key in other["settings"] and _criteria_cover(other["criteria"], block["criteria"]):
            return other["criteria"]
    return None


def _strip_inline_comment(value: str) -> str:
    """Cut an sshd_config value at an unquoted ``#``, as OpenSSH does.

    v0.15.0 — the parser previously kept the whole remainder of the line, so
    ``PermitRootLogin yes # TODO remove`` yielded the value
    ``"yes # TODO remove"``. Every sub-check compares values exactly
    (``prl == "yes"``, ``v in bad_values``, ``v not in safe_values``), so one
    trailing comment silently changed the verdict — and in both directions:

      * ``bad_values`` directives stopped matching → the finding vanished.
        Measured on one file: ``PermitRootLogin yes`` went ALERT → INFO, and
        ``PermitEmptyPasswords``, ``PasswordAuthentication`` and
        ``X11Forwarding`` disappeared entirely. The host scored *higher* for
        being commented.
      * ``safe_values`` directives stopped matching too, so a *correct*
        setting was reported as bad. ``MaxAuthTries 2 # strict`` failed
        ``int()``, fell back to the default 6, and 6 > 3 raised a warning on a
        properly hardened host.

    Verified against ``sshd -T`` (OpenSSH 9.6): an unquoted ``#`` starts a
    comment, a ``#`` inside double quotes is literal.
    """
    out, in_quotes = [], False
    for ch in value:
        if ch == '"':
            in_quotes = not in_quotes
        elif ch == "#" and not in_quotes:
            break
        out.append(ch)
    return "".join(out)


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
            first = read_text_capped(pub, encoding="utf-8", errors="ignore").split()
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
        parts = read_text_capped(pub_path, encoding="utf-8", errors="ignore").split()
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
        lines = read_text_capped(path, encoding="utf-8", errors="ignore").splitlines()
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
        lines = read_text_capped(path, encoding="utf-8", errors="ignore").splitlines()
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
        value = _strip_inline_comment(m.group(2)).strip()
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
        lines = read_text_capped(path, encoding="utf-8", errors="ignore").splitlines()
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
            parts = read_text_capped(pub, encoding="utf-8", errors="ignore").split()
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
        ("apt",    "sudo apt install -y openssh-server"),
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
