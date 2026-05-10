"""
System information helpers for BOB.

Collects OS/kernel/UFW metadata, detects network context (NAT vs public IP),
and resolves the real user home directory when running under sudo.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from pathlib import Path

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# User home
# ---------------------------------------------------------------------------

def get_user_home() -> Path:
    """Return the real user home directory, respecting SUDO_USER."""
    sudo_user = os.environ.get("SUDO_USER", "")
    if sudo_user and re.match(r"^[a-zA-Z0-9_.-]{1,256}$", sudo_user):
        import pwd
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            _log.debug("SUDO_USER %r not found in password database, falling back to Path.home()", sudo_user)
    return Path.home()


def chown_to_sudo_user(path: Path) -> None:
    """
    When running under sudo, chown a file or directory back to the invoking user.

    No-op when SUDO_USER is unset, when the path doesn't exist, or when chown fails
    (the call needs root privileges). Used after creating user-config files/directories
    so the real user can still read/edit them in non-sudo sessions.
    """
    sudo_user = os.environ.get("SUDO_USER", "")
    if not sudo_user or not re.match(r"^[a-zA-Z0-9_.-]{1,256}$", sudo_user):
        return
    try:
        import pwd
        pw = pwd.getpwnam(sudo_user)
        os.chown(path, pw.pw_uid, pw.pw_gid)
    except (KeyError, OSError) as exc:
        _log.debug("chown_to_sudo_user(%s) failed: %s", path, exc)


# ---------------------------------------------------------------------------
# System info
# ---------------------------------------------------------------------------

def collect_system_info(version: str, lang: str):
    """Collect system information for the report header."""
    from bob.report import SystemInfo
    from bob.output import sanitize as _sanitize

    def run(*args):
        try:
            r = subprocess.run(list(args), capture_output=True, text=True, timeout=5)
            return r.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return "N/A"

    # OS name
    os_name = "N/A"
    try:
        with open("/etc/os-release", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line[:512]
                if line.startswith("PRETTY_NAME="):
                    os_name = _sanitize(
                        line.split("=", 1)[1].strip().strip('"'), max_len=64
                    )
                    break
    except OSError as exc:
        _log.debug("Cannot read /etc/os-release: %s", exc)

    # UFW version
    ufw_ver_raw = run("ufw", "version")
    ufw_match = re.search(r"[\d.]+", ufw_ver_raw)
    ufw_version = ufw_match.group(0) if ufw_match else "N/A"

    # iptables version — empty string if not installed
    ipt_raw = run("iptables", "--version")
    ipt_match = re.search(r"v([\d.]+(?:\s+\([^)]+\))?)", ipt_raw)
    iptables_version = ipt_match.group(1) if ipt_match else ""

    # nftables version — empty string if not installed
    nft_raw = run("nft", "--version")
    nft_match = re.search(r"v([\d.]+)", nft_raw)
    nftables_version = nft_match.group(1) if nft_match else ""

    return SystemInfo(
        os_name=os_name,
        hostname=_sanitize(run("hostname"), max_len=64),
        kernel=_sanitize(run("uname", "-r"), max_len=64),
        ufw_version=ufw_version,
        iptables_version=iptables_version,
        nftables_version=nftables_version,
        user=_sanitize(
            os.environ.get("SUDO_USER") or os.environ.get("USER", "unknown"),
            max_len=32,
        ),
        config_path=str(get_user_home() / ".config" / "bob" / "config.conf"),
        language=lang,
        version=version,
    )


# ---------------------------------------------------------------------------
# Network context
# ---------------------------------------------------------------------------

# Private IPv4 ranges (RFC 1918 + loopback + CGNAT)
_PRIVATE_IPV4_RE = re.compile(
    r"^(10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)"
)


_PUBLIC_IP_PROVIDERS = [
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
]

# Private/loopback IPv6 prefixes
_PRIVATE_IPV6_RE = re.compile(
    r"^(::1$|fe80:|fc[0-9a-f]{2}:|fd[0-9a-f]{2}:)",
    re.IGNORECASE,
)


def get_public_ip(offline: bool = False) -> str:
    """
    Attempt to determine public IP via lightweight HTTP requests.

    Tries multiple providers in order; returns the first valid IPv4 response.
    Returns "" immediately when offline=True or all providers fail.

    Args:
        offline: If True, skip all HTTP calls and return "" immediately.
    """
    if offline:
        return ""

    import urllib.error
    import urllib.request

    ipv4_re = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    for url in _PUBLIC_IP_PROVIDERS:
        try:
            with urllib.request.urlopen(url, timeout=3) as resp:
                ip = resp.read(64).decode().strip()
            if ipv4_re.match(ip):
                return ip
        except (OSError, urllib.error.URLError, ValueError):
            continue
    return ""


def detect_network_context(offline: bool = False) -> tuple[str, str]:
    """
    Detect whether the machine has a direct public IP.

    Checks IPv4 routes and addresses first, then IPv6 addresses.
    Falls back to querying a public IP service when no local public
    address is found.

    Args:
        offline: If True, skip the external IP lookup (get_public_ip).

    Returns:
        Tuple of (context: "local"|"public", public_ip: str).
    """
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        if re.search(r"via\s+" + _PRIVATE_IPV4_RE.pattern.removeprefix("^"), result.stdout):
            public_ip = get_public_ip(offline=offline)
            return "local", public_ip
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        _log.debug("ip route failed during network type detection: %s", exc)

    try:
        result = subprocess.run(
            ["ip", "addr", "show"],
            capture_output=True, text=True, timeout=5,
        )
        # IPv4 public address
        for match in re.finditer(r"inet\s+([\d.]+)/", result.stdout):
            ip = match.group(1)
            if not _PRIVATE_IPV4_RE.match(ip):
                return "public", ip
        # IPv6 public address (non-loopback, non-link-local, non-ULA)
        for match in re.finditer(r"inet6\s+([0-9a-fA-F:]+)/", result.stdout):
            ip = match.group(1)
            if not _PRIVATE_IPV6_RE.match(ip):
                return "public", ip
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        _log.debug("ip addr failed during network type detection: %s", exc)

    public_ip = get_public_ip(offline=offline)
    return "local", public_ip
