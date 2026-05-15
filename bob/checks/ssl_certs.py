"""
TLS/SSL certificate expiry audit for BOB (CHECK 43).

Scans local certificate stores and web/mail server configs for server TLS/SSL
certificates that are expired or close to expiry.

Sources scanned (read-only, no network calls):
  - /etc/letsencrypt/live/*/fullchain.pem  — Let's Encrypt certificates
  - /etc/ssl/private/*.{pem,crt,cert}       — manually installed server certs
  - nginx:   ssl_certificate directives
  - apache2: SSLCertificateFile directives
  - postfix: smtpd_tls_cert_file in /etc/postfix/main.cf

Score impact (per certificate, total capped at −4):
  - Expired cert:       ALERT  −2 pts
  - Expires < 7 days:   ALERT  −2 pts
  - Expires < 30 days:  WARN   −1 pt
  - Valid cert:          OK

Split into:
  1. SslCertsSnapshot.from_system() — discovers cert files and reads expiry.
  2. check_ssl_certs(snapshot, t)   — pure analysis, returns CheckResult.
"""

from __future__ import annotations

import re
import shlex
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from bob.checks._run import (
    TranslationFunc,
    _C_LOCALE_ENV,
    _command_exists,
    _identity_t,
    _parse_english_month_day,
)
from bob.scoring import CheckResult

_WARN_DAYS      = 30
_ALERT_DAYS     = 7
_MAX_CERT_SIZE  = 50_000     # bytes — skip files larger than this (CA bundles)
_MAX_CERTS      = 30         # hard cap to avoid stalling on large deployments
_MAX_CONF_FILES = 100        # max .conf files to scan per directory tree
_MAX_CONF_SIZE  = 1_000_000  # bytes — skip conf files larger than this

_ENDDATE_RE = re.compile(r"notAfter=(\w+\s+\d+\s+\d+:\d+:\d+\s+\d{4})")

_NGINX_SSL_RE  = re.compile(r"^\s*ssl_certificate\s+([^;]+);", re.MULTILINE)
_APACHE_SSL_RE = re.compile(r"^\s*SSLCertificateFile\s+(\S+)", re.MULTILINE | re.IGNORECASE)
_POSTFIX_RE    = re.compile(r"^\s*smtpd_tls_cert_file\s*=\s*(\S+)", re.MULTILINE)


@dataclass
class CertEntry:
    """A single discovered server certificate."""
    path:       str
    days_left:  Optional[int]   # None = could not read
    expiry_str: str
    error:      Optional[str] = None


@dataclass
class SslCertsSnapshot:
    """
    Discovered server TLS/SSL certificates and their expiry status.

    Attributes:
        certs:              List of discovered cert entries.
        openssl_available:  True if the openssl binary is present.
    """
    certs:             List[CertEntry] = field(default_factory=list)
    openssl_available: bool = True

    @classmethod
    def from_system(cls) -> "SslCertsSnapshot":
        """Discover server cert files and read their expiry dates."""
        snap = cls()
        snap.openssl_available = _command_exists("openssl")
        if not snap.openssl_available:
            return snap

        paths: set[str] = set()  # realpath-deduped set

        # --- Let's Encrypt ---
        le_dir = Path("/etc/letsencrypt/live")
        if le_dir.is_dir():
            for cert in le_dir.glob("*/fullchain.pem"):
                _add_path(cert, paths)

        # --- /etc/ssl/private ---
        priv = Path("/etc/ssl/private")
        if priv.is_dir():
            for ext in ("*.pem", "*.crt", "*.cert"):
                for cert in priv.glob(ext):
                    _add_path(cert, paths)

        # --- nginx ---
        for conf_dir in (Path("/etc/nginx/sites-enabled"), Path("/etc/nginx")):
            _collect_from_configs(conf_dir, _NGINX_SSL_RE, paths)

        # --- apache2 ---
        for conf_dir in (Path("/etc/apache2/sites-enabled"), Path("/etc/apache2")):
            _collect_from_configs(conf_dir, _APACHE_SSL_RE, paths)

        # --- postfix ---
        postfix_cf = Path("/etc/postfix/main.cf")
        if postfix_cf.exists():
            try:
                content = postfix_cf.read_text(encoding="utf-8", errors="ignore")
                for m in _POSTFIX_RE.finditer(content):
                    _add_path(Path(m.group(1).strip()), paths)
            except OSError:
                pass

        paths = {p for p in paths if "snakeoil" not in Path(p).name.lower()}

        for path_str in list(paths)[:_MAX_CERTS]:
            days_left, expiry_str, error = _read_cert_expiry(Path(path_str))
            snap.certs.append(CertEntry(
                path=path_str,
                days_left=days_left,
                expiry_str=expiry_str,
                error=error,
            ))

        snap.certs.sort(key=lambda c: (c.days_left is None, c.days_left or 0))
        return snap


# ---------------------------------------------------------------------------
# Check logic
# ---------------------------------------------------------------------------

def check_ssl_certs(snapshot: SslCertsSnapshot, t: TranslationFunc | None = None) -> CheckResult:
    """
    Evaluate certificate expiry and emit findings.

    ALERT for expired or near-expiry certs, WARN for certs < 30 days,
    INFO when no certs are found or openssl is unavailable.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if not snapshot.openssl_available:
        result.info(
            message=_t("ssl_certs.openssl_unavailable"),
            key="ssl_certs.openssl_unavailable",
        )
        return result

    if not snapshot.certs:
        result.info(
            message=_t("ssl_certs.no_certs"),
            key="ssl_certs.no_certs",
        )
        return result

    total_deduction = 0

    for cert in snapshot.certs:
        if cert.error and cert.days_left is None:
            result.info(
                message=_t("ssl_certs.read_error", path=cert.path, error=cert.error),
                key="ssl_certs.read_error",
            )
            continue

        days = cert.days_left
        short_path = Path(cert.path).name

        if days is not None and days <= 0:
            _cert_name = shlex.quote(Path(cert.path).parent.name)
            result.alert(
                message=_t("ssl_certs.expired", path=short_path, days=abs(days)),
                cmd=f"sudo certbot renew --cert-name {_cert_name}",
                cmd_type="fix",
                key="ssl_certs.expired",
            )
            if total_deduction < 4:
                pts = min(2, 4 - total_deduction)
                result.add_deduction(
                    reason=_t("ssl_certs.expired", path=short_path, days=abs(days)),
                    points=pts,
                    context="local",
                    key="ssl_certs.expired",
                )
                total_deduction += pts

        elif days is not None and days <= _ALERT_DAYS:
            result.alert(
                message=_t("ssl_certs.expiring_critical", path=short_path, days=days),
                cmd="sudo certbot renew",
                cmd_type="fix",
                key="ssl_certs.expiring_critical",
            )
            if total_deduction < 4:
                pts = min(2, 4 - total_deduction)
                result.add_deduction(
                    reason=_t("ssl_certs.expiring_critical", path=short_path, days=days),
                    points=pts,
                    context="local",
                    key="ssl_certs.expiring_critical",
                )
                total_deduction += pts

        elif days is not None and days <= _WARN_DAYS:
            result.warn(
                message=_t("ssl_certs.expiring_soon", path=short_path, days=days),
                nature="improvement",
                cmd="sudo certbot renew",
                cmd_type="fix",
                key="ssl_certs.expiring_soon",
            )
            if total_deduction < 4:
                pts = min(1, 4 - total_deduction)
                result.add_deduction(
                    reason=_t("ssl_certs.expiring_soon", path=short_path, days=days),
                    points=pts,
                    context="local",
                    key="ssl_certs.expiring_soon",
                )
                total_deduction += pts

        elif days is not None:
            result.ok(
                message=_t("ssl_certs.ok", path=short_path, days=days),
                key="ssl_certs.ok",
            )
        else:
            result.info(
                message=_t("ssl_certs.read_error", path=cert.path, error="days_left unknown"),
                key="ssl_certs.read_error",
            )

    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _add_path(path: Path, seen: set[str]) -> None:
    """Resolve symlinks and add to the set if file exists and is readable."""
    try:
        real = str(path.resolve())
        if path.exists() and real not in seen:
            seen.add(real)
    except OSError:
        pass


def _collect_from_configs(conf_dir: Path, pattern: re.Pattern, paths: set[str]) -> None:
    """Scan .conf files in conf_dir for cert path matches (capped at _MAX_CONF_FILES)."""
    if not conf_dir.is_dir():
        return
    scanned = 0
    for conf in conf_dir.glob("**/*.conf"):
        if scanned >= _MAX_CONF_FILES:
            break
        scanned += 1
        try:
            if conf.stat().st_size > _MAX_CONF_SIZE:
                continue
            content = conf.read_text(encoding="utf-8", errors="ignore")
            for m in pattern.finditer(content):
                _add_path(Path(m.group(1).strip().strip("'\"")), paths)
        except OSError:
            pass


def _read_cert_expiry(path: Path) -> tuple[Optional[int], str, Optional[str]]:
    """
    Run openssl x509 on *path* and return (days_left, expiry_str, error).

    days_left is None when the cert cannot be read or parsed.
    """
    try:
        if path.stat().st_size > _MAX_CERT_SIZE:
            return None, "", "file too large — likely a CA bundle, not a server cert"
    except OSError as exc:
        return None, "", str(exc)

    try:
        proc = subprocess.run(
            ["openssl", "x509", "-enddate", "-noout", "-in", str(path)],
            capture_output=True, text=True, timeout=5,
            env=_C_LOCALE_ENV,
        )
        if proc.returncode != 0:
            return None, "", (proc.stderr.strip() or "openssl error")

        m = _ENDDATE_RE.search(proc.stdout)
        if not m:
            return None, "", "could not parse notAfter field"

        expiry_str = m.group(1).strip()
        # Don't use datetime.strptime("%b ...") here: it depends on the Python
        # process LC_TIME, not the subprocess env. _parse_english_month_day
        # is locale-independent.
        parts = expiry_str.split()
        if len(parts) < 4:
            return None, "", "could not parse notAfter field"
        parsed = _parse_english_month_day(expiry_str)
        if parsed is None:
            return None, "", "could not parse notAfter field"
        month, day, hh, mm, ss = parsed
        try:
            year = int(parts[3])
        except (ValueError, IndexError):
            return None, "", "could not parse notAfter year"
        expiry_dt = datetime(year, month, day, hh, mm, ss, tzinfo=timezone.utc)
        days_left = (expiry_dt - datetime.now(timezone.utc)).days
        return days_left, expiry_str, None

    except subprocess.TimeoutExpired:
        return None, "", "openssl timed out"
    except (OSError, ValueError) as exc:
        return None, "", str(exc)
