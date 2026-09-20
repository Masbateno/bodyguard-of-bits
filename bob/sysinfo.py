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


def chown_fd_to_sudo_user(fd: int) -> None:
    """chown an *already-open* file descriptor back to the invoking user.

    v0.14.1: the path-based :func:`chown_to_sudo_user` follows symlinks and
    re-resolves the name, leaving a TOCTOU window between ``os.open`` and the
    chown. Operating on the descriptor the caller already holds removes both
    problems — it is the same object that was opened under ``O_NOFOLLOW``.
    """
    sudo_user = os.environ.get("SUDO_USER", "")
    if not sudo_user or not re.match(r"^[a-zA-Z0-9_.-]{1,256}$", sudo_user):
        return
    try:
        import pwd
        pw = pwd.getpwnam(sudo_user)
        os.fchown(fd, pw.pw_uid, pw.pw_gid)
    except (KeyError, OSError) as exc:
        _log.debug("chown_fd_to_sudo_user(%s) failed: %s", fd, exc)


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

def audit_user() -> str:
    """Who is running this audit — measured, not believed.

    Until v0.17.1 this read `SUDO_USER or USER` and printed "unknown" when
    neither was set. Measured on three VMs through the same execution path, all
    running as root: Debian 13 and Kali carry `USER=root` in the environment,
    openSUSE Leap 15.6 carries nothing, and only there did the report header
    say `User : unknown`. The process identity was the same on all three, and
    the kernel would have answered on all three.

    An environment variable is a claim; `geteuid()` is a measurement. Any
    non-interactive context can arrive without `USER` — a systemd timer, a
    guest agent, a minimal image — and the header goes into the written report,
    so "unknown" outlives the run.

    `SUDO_USER` stays first because it carries information the euid does not:
    the human behind the sudo. It is validated against the password database
    the same way :func:`get_user_home` validates it, so a spoofed value falls
    through to the measurement instead of being printed.

    Falls back to ``uid N`` — still a fact — when the uid has no passwd entry,
    which happens in containers with a mapped user.
    """
    import pwd  # local, as in get_user_home above — the module is POSIX-only

    sudo_user = os.environ.get("SUDO_USER", "")
    if sudo_user and re.match(r"^[a-zA-Z0-9_.-]{1,256}$", sudo_user):
        try:
            pwd.getpwnam(sudo_user)
            return sudo_user
        except KeyError:
            _log.debug("SUDO_USER %r not in the password database", sudo_user)
    euid = os.geteuid()
    try:
        return pwd.getpwuid(euid).pw_name
    except KeyError:
        return f"uid {euid}"


def detect_default_profile() -> str:
    """Best-effort role detection for the *fallback* audit profile.

    Returns ``"desktop"`` when the system's role is a graphical session, else
    ``"server"``. Used only when the operator has set no profile at all — an
    explicit ``--profile`` or a saved one always wins.

    A server audit on a desktop is over-strict: it keeps backup / auditd /
    mac_policy at WARN that the ``desktop`` profile relaxes to INFO. Measured on
    a real Linux Mint 22.3 where lightdm was active but BOB defaulted to server
    and scored 6/10 where desktop scores 8/10.

    The signal, root-safe and needing no ``$DISPLAY``, is an **active**
    ``display-manager.service`` (the generic gdm/lightdm/sddm/gdm3 alias that
    presents the login session). ``systemctl get-default == graphical.target``
    was tried too, but it is NOT a reliable desktop signal on its own: a real
    headless Ubuntu Server (.14) carried ``graphical.target`` as its default
    with ``display-manager`` **inactive**, and reading that as desktop would
    have relaxed a server's profile. A genuine desktop always runs a DM.

    Anything else — no active DM, or a host without systemd — reads as
    ``server``, the safe, stricter default. Detection can only *relax*; it
    never tightens.
    """
    def _run(*args) -> str:
        try:
            r = subprocess.run(
                list(args), capture_output=True, text=True, timeout=5,
                env=_C_LOCALE_ENV,
            )
            return r.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return ""

    if _run("systemctl", "is-active", "display-manager.service") == "active":
        return "desktop"
    return "server"


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
    # v0.17.1: empty, like iptables and nftables below. It used to be the
    # sentinel "N/A", which three render sites then prefixed with a version
    # marker — the header read `UFW : vN/A` on openSUSE Leap 15.6, where ufw
    # is genuinely absent. A sentinel that reaches the screen is not a
    # statement about the machine.
    ufw_version = ufw_match.group(0) if ufw_match else ""

    # iptables version — empty string if not installed
    ipt_raw = run("iptables", "--version")
    ipt_match = re.search(r"v([\d.]+(?:\s+\([^)]+\))?)", ipt_raw)
    iptables_version = ipt_match.group(1) if ipt_match else ""

    # nftables version — empty string if not installed
    nft_raw = run("nft", "--version")
    nft_match = re.search(r"v([\d.]+)", nft_raw)
    nftables_version = nft_match.group(1) if nft_match else ""

    # firewalld version — empty string if the client is not installed. Same
    # rule as UFW above: the banner names the firewall front-ends that are
    # present, so a firewalld host is not read as "UFW not installed" and
    # nothing else. `firewall-cmd --version` prints just the number.
    fwd_raw = run("firewall-cmd", "--version")
    fwd_match = re.search(r"[\d.]+", fwd_raw)
    firewalld_version = fwd_match.group(0) if fwd_match else ""

    # Init / service manager — systemd on most distributions, OpenRC on Alpine,
    # something else (busybox init, sysvinit) elsewhere. BOB's service and
    # firewall reasoning assumes systemd in places, so naming the actual manager
    # up front is honest about what the audit could and could not inspect.
    init_system = ""
    sysd_raw = run("systemctl", "--version")
    sysd_match = re.search(r"systemd\s+(\d+)", sysd_raw)
    if sysd_match:
        init_system = f"systemd {sysd_match.group(1)}"
    else:
        orc_raw = run("openrc", "--version")
        orc_match = re.search(r"[\d.]+", orc_raw)
        if "openrc" in orc_raw.lower():
            init_system = f"OpenRC {orc_match.group(0)}" if orc_match else "OpenRC"
        else:
            try:
                init_system = _sanitize(
                    Path("/proc/1/comm").read_text(encoding="ascii",
                                                   errors="ignore").strip(),
                    max_len=32)
            except OSError:
                init_system = ""

    # v0.17.1: both from `os.uname()`, which is a syscall and cannot be
    # missing, rather than from binaries that can be. Arch Linux ships no
    # `hostname` command in its cloud image — systemd's `hostnamectl` replaces
    # it — so `run("hostname")` returned the "N/A" sentinel and the report
    # header read `Host : N/A`, on the one field that says which machine the
    # report is about. Debian, Kali and openSUSE all carry the binary, which is
    # why it took a fourth distribution to show. `uname -r` has the same shape
    # and the same exposure, two lines from the defect, so it moves too.
    _uname = os.uname()
    return SystemInfo(
        os_name=os_name,
        hostname=_sanitize(_uname.nodename, max_len=64),
        kernel=_sanitize(_uname.release, max_len=64),
        ufw_version=ufw_version,
        iptables_version=iptables_version,
        nftables_version=nftables_version,
        firewalld_version=firewalld_version,
        init_system=init_system,
        user=_sanitize(audit_user(), max_len=32),
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
