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

from bob.checks._run import _C_LOCALE_ENV

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
            r = subprocess.run(
                list(args), capture_output=True, text=True, timeout=5,
                env=_C_LOCALE_ENV,
            )
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

_PUBLIC_IP_PROVIDERS = [
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
]


# I-4 (v0.5.5): explicit network list rather than stdlib `is_private` —
# Python 3.12.4+ widened is_private to include documentation/reserved
# ranges (e.g. 203.0.113.0/24, 198.51.100.0/24) that BOB treats as
# "public" for network-context detection. RFC 1918 + loopback + link-
# local + CGNAT covers what we actually want; documentation ranges are
# globally routable in practice and should NOT trigger "local" context.
import ipaddress as _ipaddress

_PRIVATE_IPV4_NETS = (
    _ipaddress.ip_network("10.0.0.0/8"),
    _ipaddress.ip_network("172.16.0.0/12"),
    _ipaddress.ip_network("192.168.0.0/16"),
    _ipaddress.ip_network("127.0.0.0/8"),       # loopback
    _ipaddress.ip_network("169.254.0.0/16"),    # link-local
    _ipaddress.ip_network("100.64.0.0/10"),     # CGNAT
)

_PRIVATE_IPV6_NETS = (
    _ipaddress.ip_network("::1/128"),           # loopback
    _ipaddress.ip_network("fe80::/10"),         # link-local
    _ipaddress.ip_network("fc00::/7"),          # ULA (Unique Local)
)


def _is_private_or_loopback_ipv4(ip: str) -> bool:
    """Return True if ``ip`` is RFC 1918, loopback, link-local, or CGNAT.

    Replaces the previous brittle hand-rolled regex `_PRIVATE_IPV4_RE`
    and its `removeprefix("^")` hack at the call site.
    """
    try:
        addr = _ipaddress.IPv4Address(ip)
    except (ValueError, _ipaddress.AddressValueError):
        return False
    return any(addr in net for net in _PRIVATE_IPV4_NETS)


def _is_private_or_loopback_ipv6(ip: str) -> bool:
    """Return True if ``ip`` is loopback (::1), link-local (fe80::/10), or ULA (fc00::/7).

    Uses explicit network list (not stdlib `is_private`) — Python 3.12+
    widens `is_private` to include 2001:db8::/32 (documentation), which
    BOB treats as "public" for network-context detection.
    """
    try:
        addr = _ipaddress.IPv6Address(ip)
    except (ValueError, _ipaddress.AddressValueError):
        return False
    return any(addr in net for net in _PRIVATE_IPV6_NETS)


def get_public_ip(offline: bool = False) -> str:
    """
    Attempt to determine public IP via lightweight HTTP requests.

    Tries multiple providers in order; returns the first valid IPv4 OR IPv6
    response. Returns "" immediately when offline=True or all providers fail.

    M-6 (v0.7.2): accepts IPv6 responses too. Providers return v6 when the
    request was sent over v6 (typical on v6-only hosts); pre-v0.7.2 the
    IPv4-only regex rejected those, so v6-only hosts always reported
    public_ip="" even though they had a working public address.

    Args:
        offline: If True, skip all HTTP calls and return "" immediately.
    """
    if offline:
        return ""

    import ipaddress
    import urllib.error
    import urllib.request

    for url in _PUBLIC_IP_PROVIDERS:
        try:
            with urllib.request.urlopen(url, timeout=3) as resp:
                ip = resp.read(64).decode().strip()
            # Accept any valid IP address (v4 or v6). ipaddress.ip_address
            # rejects malformed strings, hostname-style responses, and other
            # junk via ValueError, which we catch in the except clause below.
            ipaddress.ip_address(ip)
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
            env=_C_LOCALE_ENV,
        )
        # Match the gateway IP after "via" and validate via stdlib.
        gw_match = re.search(r"via\s+(\S+)", result.stdout)
        if gw_match and _is_private_or_loopback_ipv4(gw_match.group(1)):
            public_ip = get_public_ip(offline=offline)
            return "local", public_ip
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        _log.debug("ip route failed during network type detection: %s", exc)

    try:
        result = subprocess.run(
            ["ip", "addr", "show"],
            capture_output=True, text=True, timeout=5,
            env=_C_LOCALE_ENV,
        )
        # IPv4 public address
        for match in re.finditer(r"inet\s+([\d.]+)/", result.stdout):
            ip = match.group(1)
            if not _is_private_or_loopback_ipv4(ip):
                return "public", ip
        # IPv6 public address (non-loopback, non-link-local, non-ULA)
        for match in re.finditer(r"inet6\s+([0-9a-fA-F:]+)/", result.stdout):
            ip = match.group(1)
            if not _is_private_or_loopback_ipv6(ip):
                return "public", ip
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        _log.debug("ip addr failed during network type detection: %s", exc)

    public_ip = get_public_ip(offline=offline)
    return "local", public_ip
