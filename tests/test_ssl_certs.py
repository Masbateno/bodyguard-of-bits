"""Tests for TLS/SSL certificate expiry check (CHECK 43)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from bob.checks.ssl_certs import (
    CertEntry,
    SslCertsSnapshot,
    _add_path,
    _collect_from_configs,
    _read_cert_expiry,
    check_ssl_certs,
)
from bob.scoring import FindingLevel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _snap(*certs: CertEntry, openssl: bool = True) -> SslCertsSnapshot:
    return SslCertsSnapshot(certs=list(certs), openssl_available=openssl)


def _cert(path: str = "server.crt", days: int | None = 90, error: str | None = None) -> CertEntry:
    expiry = "Apr 19 00:00:00 2027" if days and days > 0 else "Apr 19 00:00:00 2020"
    return CertEntry(path=path, days_left=days, expiry_str=expiry, error=error)


# ---------------------------------------------------------------------------
# TestCheckSslCerts — pure logic
# ---------------------------------------------------------------------------

class TestCheckSslCerts:
    def test_no_openssl_returns_info(self):
        result = check_ssl_certs(_snap(openssl=False))
        assert result.findings[0].level == FindingLevel.INFO
        assert result.findings[0].key == "ssl_certs.openssl_unavailable"

    def test_no_certs_returns_info(self):
        result = check_ssl_certs(_snap())
        assert result.findings[0].level == FindingLevel.INFO
        assert result.findings[0].key == "ssl_certs.no_certs"

    def test_valid_cert_ok(self):
        result = check_ssl_certs(_snap(_cert(days=180)))
        assert result.findings[0].level == FindingLevel.OK
        assert result.findings[0].key == "ssl_certs.ok"

    def test_expiring_soon_warn(self):
        result = check_ssl_certs(_snap(_cert(days=20)))
        assert result.findings[0].level == FindingLevel.WARN
        assert result.findings[0].key == "ssl_certs.expiring_soon"

    def test_expiring_soon_deducts_1pt(self):
        result = check_ssl_certs(_snap(_cert(days=20)))
        assert sum(d.points for d in result.deductions) == 1

    def test_expiring_critical_alert(self):
        result = check_ssl_certs(_snap(_cert(days=3)))
        assert result.findings[0].level == FindingLevel.ALERT
        assert result.findings[0].key == "ssl_certs.expiring_critical"

    def test_expiring_critical_deducts_2pts(self):
        result = check_ssl_certs(_snap(_cert(days=3)))
        assert sum(d.points for d in result.deductions) == 2

    def test_expired_alert(self):
        # v0.15.0: days_left is a floored timedelta, so -1 is the first value a
        # genuinely expired certificate can take — even one minute past
        # notAfter. 0 means "still valid, under 24h left"; see the threshold
        # test below and test_v0150_ssl_expiry_boundary.py.
        result = check_ssl_certs(_snap(_cert(days=-1)))
        assert result.findings[0].level == FindingLevel.ALERT
        assert result.findings[0].key == "ssl_certs.expired"

    def test_expired_negative_days_alert(self):
        result = check_ssl_certs(_snap(_cert(days=-5)))
        assert result.findings[0].level == FindingLevel.ALERT
        assert result.findings[0].key == "ssl_certs.expired"

    def test_expired_deducts_2pts(self):
        result = check_ssl_certs(_snap(_cert(days=-5)))
        assert sum(d.points for d in result.deductions) == 2

    def test_expired_cmd_uses_parent_name(self):
        """certbot renew --cert-name should use the directory name, not the filename."""
        c = CertEntry(
            path="/etc/letsencrypt/live/example.com/fullchain.pem",
            days_left=-1, expiry_str="", error=None,
        )
        result = check_ssl_certs(_snap(c))
        finding = next(f for f in result.findings if f.key == "ssl_certs.expired")
        assert "example.com" in (finding.cmd or "")
        assert "fullchain.pem" not in (finding.cmd or "")

    def test_expired_cmd_quotes_special_chars(self):
        """Cert names with special characters must be shell-quoted in the command."""
        c = CertEntry(
            path="/etc/letsencrypt/live/my domain/fullchain.pem",
            days_left=-1, expiry_str="", error=None,
        )
        result = check_ssl_certs(_snap(c))
        finding = next(f for f in result.findings if f.key == "ssl_certs.expired")
        cmd = finding.cmd or ""
        # shlex.quote wraps in single quotes: 'my domain'
        assert "'my domain'" in cmd or '"my domain"' in cmd

    def test_read_error_emits_info(self):
        c = _cert(days=None, error="permission denied")
        result = check_ssl_certs(_snap(c))
        assert result.findings[0].level == FindingLevel.INFO
        assert result.findings[0].key == "ssl_certs.read_error"

    def test_read_error_no_deduction(self):
        c = _cert(days=None, error="permission denied")
        result = check_ssl_certs(_snap(c))
        assert not result.deductions

    def test_days_none_without_error_produces_finding(self):
        """days_left=None with no error string falls through to ok branch — documents behavior."""
        c = CertEntry(path="unknown.crt", days_left=None, expiry_str="", error=None)
        result = check_ssl_certs(_snap(c))
        assert result.findings  # must produce at least one finding, not crash

    def test_path_injection_quoted_in_certbot_cmd(self):
        """Semicolons in cert directory names must be shell-quoted, not interpreted."""
        c = CertEntry(
            path="/etc/letsencrypt/live/evil;rm -rf /;/fullchain.pem",
            days_left=-1, expiry_str="", error=None,
        )
        result = check_ssl_certs(_snap(c))
        finding = next(f for f in result.findings if f.key == "ssl_certs.expired")
        cmd = finding.cmd or ""
        # shlex.quote wraps dangerous strings in single quotes
        assert "rm -rf" not in cmd.replace("'", "").replace('"', "")


class TestSslCertsMixedFindings:
    """Behaviour when multiple certs of different states coexist."""

    def test_all_finding_types_present(self):
        result = check_ssl_certs(_snap(
            _cert("a.crt", days=-1),   # expired
            _cert("b.crt", days=20),   # warn
            _cert("c.crt", days=180),  # ok
        ))
        keys = [f.key for f in result.findings]
        assert "ssl_certs.expired" in keys
        assert "ssl_certs.expiring_soon" in keys
        assert "ssl_certs.ok" in keys

    def test_three_findings_for_three_certs(self):
        result = check_ssl_certs(_snap(
            _cert("a.crt", days=-1),
            _cert("b.crt", days=5),
            _cert("c.crt", days=180),
        ))
        assert len(result.findings) == 3

    def test_ok_finding_not_suppressed_when_other_issues_exist(self):
        result = check_ssl_certs(_snap(
            _cert("bad.crt", days=-1),
            _cert("good.crt", days=180),
        ))
        assert any(f.key == "ssl_certs.ok" for f in result.findings)

    def test_error_cert_does_not_block_other_findings(self):
        result = check_ssl_certs(_snap(
            _cert("bad.crt", days=None, error="permission denied"),
            _cert("good.crt", days=180),
        ))
        keys = [f.key for f in result.findings]
        assert "ssl_certs.read_error" in keys
        assert "ssl_certs.ok" in keys


class TestSslCertsCap:
    """Total deductions are capped at 4 regardless of cert count."""

    def test_two_expired_capped_at_4(self):
        certs = [_cert(f"cert{i}.crt", days=-1) for i in range(3)]
        result = check_ssl_certs(_snap(*certs))
        assert sum(d.points for d in result.deductions) == 4

    def test_two_critical_capped_at_4(self):
        certs = [_cert(f"cert{i}.crt", days=3) for i in range(3)]
        result = check_ssl_certs(_snap(*certs))
        assert sum(d.points for d in result.deductions) == 4

    def test_four_warn_capped_at_4(self):
        certs = [_cert(f"cert{i}.crt", days=20) for i in range(6)]
        result = check_ssl_certs(_snap(*certs))
        assert sum(d.points for d in result.deductions) == 4

    def test_expired_plus_warn_capped_at_3(self):
        # 1 expired (−2) + 1 warn (−1) = −3, no cap needed
        result = check_ssl_certs(_snap(_cert("a.crt", days=-1), _cert("b.crt", days=20)))
        assert sum(d.points for d in result.deductions) == 3

    def test_mixed_expired_and_ok_no_cap(self):
        result = check_ssl_certs(_snap(_cert("a.crt", days=-1), _cert("b.crt", days=180)))
        assert sum(d.points for d in result.deductions) == 2

    def test_expired_plus_critical_plus_two_warn_capped_at_4(self):
        """expired(−2) + critical(−2) + warn(−1) + warn(−1) = −6 but cap is 4."""
        result = check_ssl_certs(_snap(
            _cert("a.crt", days=-1),   # expired  −2
            _cert("b.crt", days=3),    # critical −2
            _cert("c.crt", days=20),   # warn     −1
            _cert("d.crt", days=25),   # warn     −1
        ))
        assert sum(d.points for d in result.deductions) == 4


class TestSslCertsThresholds:
    """Boundary conditions around 0, 7, 30."""

    def test_exactly_0_days_is_critical_not_expired(self):
        """0 is the whole final day of a *valid* certificate — `openssl x509
        -checkend 0` accepts one with 23 hours left. It stays an ALERT with a
        deduction, but it is not expired."""
        result = check_ssl_certs(_snap(_cert(days=0)))
        assert result.findings[0].key == "ssl_certs.expiring_critical"
        assert result.findings[0].level == FindingLevel.ALERT

    def test_minus_one_day_is_expired(self):
        result = check_ssl_certs(_snap(_cert(days=-1)))
        assert result.findings[0].key == "ssl_certs.expired"

    def test_exactly_7_days_critical(self):
        result = check_ssl_certs(_snap(_cert(days=7)))
        assert result.findings[0].key == "ssl_certs.expiring_critical"

    def test_exactly_8_days_warn(self):
        result = check_ssl_certs(_snap(_cert(days=8)))
        assert result.findings[0].key == "ssl_certs.expiring_soon"

    def test_exactly_30_days_warn(self):
        result = check_ssl_certs(_snap(_cert(days=30)))
        assert result.findings[0].key == "ssl_certs.expiring_soon"

    def test_exactly_31_days_ok(self):
        result = check_ssl_certs(_snap(_cert(days=31)))
        assert result.findings[0].key == "ssl_certs.ok"


# ---------------------------------------------------------------------------
# TestSslCertsTranslation
# ---------------------------------------------------------------------------

class TestSslCertsTranslation:
    def test_t_called_with_correct_keys(self):
        calls = []

        def _t(key, **kwargs):
            calls.append(key)
            return key

        check_ssl_certs(_snap(_cert(days=5)), t=_t)
        assert "ssl_certs.expiring_critical" in calls

    def test_no_openssl_t(self):
        calls = []

        def _t(key, **kwargs):
            calls.append(key)
            return key

        check_ssl_certs(_snap(openssl=False), t=_t)
        assert "ssl_certs.openssl_unavailable" in calls


# ---------------------------------------------------------------------------
# TestAddPath
# ---------------------------------------------------------------------------

class TestAddPath:
    def test_existing_file_added(self, tmp_path):
        f = tmp_path / "server.crt"
        f.write_text("cert")
        seen: set[str] = set()
        _add_path(f, seen)
        assert len(seen) == 1

    def test_nonexistent_file_not_added(self, tmp_path):
        seen: set[str] = set()
        _add_path(tmp_path / "ghost.crt", seen)
        assert not seen

    def test_duplicate_not_added_twice(self, tmp_path):
        f = tmp_path / "server.crt"
        f.write_text("cert")
        seen: set[str] = set()
        _add_path(f, seen)
        _add_path(f, seen)
        assert len(seen) == 1

    def test_symlink_resolved(self, tmp_path):
        real = tmp_path / "real.crt"
        real.write_text("cert")
        link = tmp_path / "link.crt"
        link.symlink_to(real)
        seen: set[str] = set()
        _add_path(real, seen)
        _add_path(link, seen)  # should resolve to same realpath
        assert len(seen) == 1

    def test_broken_symlink_not_added(self, tmp_path):
        """Broken symlinks (target missing) must be silently skipped."""
        link = tmp_path / "broken.crt"
        link.symlink_to(tmp_path / "nonexistent.crt")
        seen: set[str] = set()
        _add_path(link, seen)
        assert not seen


# ---------------------------------------------------------------------------
# TestCollectFromConfigs
# ---------------------------------------------------------------------------

class TestCollectFromConfigs:
    def test_extracts_nginx_cert(self, tmp_path):
        import re
        from bob.checks.ssl_certs import _NGINX_SSL_RE

        conf = tmp_path / "default.conf"
        cert = tmp_path / "server.crt"
        cert.write_text("cert")
        conf.write_text(f"ssl_certificate {cert};")
        seen: set[str] = set()
        _collect_from_configs(tmp_path, _NGINX_SSL_RE, seen)
        assert str(cert.resolve()) in seen

    def test_extracts_apache_cert(self, tmp_path):
        from bob.checks.ssl_certs import _APACHE_SSL_RE

        conf = tmp_path / "site.conf"
        cert = tmp_path / "server.crt"
        cert.write_text("cert")
        conf.write_text(f"SSLCertificateFile {cert}")
        seen: set[str] = set()
        _collect_from_configs(tmp_path, _APACHE_SSL_RE, seen)
        assert str(cert.resolve()) in seen

    def test_nonexistent_dir_is_silent(self, tmp_path):
        from bob.checks.ssl_certs import _NGINX_SSL_RE

        seen: set[str] = set()
        _collect_from_configs(tmp_path / "noexist", _NGINX_SSL_RE, seen)
        assert not seen

    def test_only_conf_files_scanned(self, tmp_path):
        from bob.checks.ssl_certs import _NGINX_SSL_RE

        cert = tmp_path / "server.crt"
        cert.write_text("cert")
        txt = tmp_path / "default.txt"
        txt.write_text(f"ssl_certificate {cert};")
        seen: set[str] = set()
        _collect_from_configs(tmp_path, _NGINX_SSL_RE, seen)
        assert not seen

    def test_quoted_path_extracted(self, tmp_path):
        """ssl_certificate with quoted path must still be found."""
        from bob.checks.ssl_certs import _NGINX_SSL_RE

        cert = tmp_path / "server.crt"
        cert.write_text("cert")
        conf = tmp_path / "default.conf"
        conf.write_text(f'ssl_certificate "{cert}";')
        seen: set[str] = set()
        _collect_from_configs(tmp_path, _NGINX_SSL_RE, seen)
        assert str(cert.resolve()) in seen

    def test_inline_comment_ignored(self, tmp_path):
        """Trailing # comment must not corrupt the extracted path."""
        from bob.checks.ssl_certs import _NGINX_SSL_RE

        cert = tmp_path / "server.crt"
        cert.write_text("cert")
        conf = tmp_path / "default.conf"
        conf.write_text(f"ssl_certificate {cert}; # my cert\n")
        seen: set[str] = set()
        _collect_from_configs(tmp_path, _NGINX_SSL_RE, seen)
        assert str(cert.resolve()) in seen

    def test_extra_whitespace_before_path(self, tmp_path):
        """Extra spaces between directive and path must not prevent matching."""
        from bob.checks.ssl_certs import _NGINX_SSL_RE

        cert = tmp_path / "server.crt"
        cert.write_text("cert")
        conf = tmp_path / "default.conf"
        conf.write_text(f"ssl_certificate   {cert};")
        seen: set[str] = set()
        _collect_from_configs(tmp_path, _NGINX_SSL_RE, seen)
        assert str(cert.resolve()) in seen


# ---------------------------------------------------------------------------
# TestReadCertExpiry
# ---------------------------------------------------------------------------

class TestReadCertExpiry:
    def test_parses_valid_cert(self, tmp_path):
        cert = tmp_path / "server.crt"
        cert.write_text("fake")
        stdout = "notAfter=Apr 19 00:00:00 2099\n"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=stdout, stderr="")
            days, expiry_str, err = _read_cert_expiry(cert)
        assert days is not None and days > 0
        assert err is None
        assert expiry_str != ""

    def test_openssl_binary_invoked(self, tmp_path):
        """openssl must be called with the cert path as argument."""
        cert = tmp_path / "server.crt"
        cert.write_text("fake")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="notAfter=Apr 19 00:00:00 2099\n", stderr="")
            _read_cert_expiry(cert)
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args[0] == "openssl"
        assert str(cert) in args

    def test_parses_with_gmt_suffix(self, tmp_path):
        """openssl may append 'GMT' after the year — parser must handle this."""
        cert = tmp_path / "server.crt"
        cert.write_text("fake")
        stdout = "notAfter=Apr 19 00:00:00 2099 GMT\n"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=stdout, stderr="")
            days, expiry_str, err = _read_cert_expiry(cert)
        assert days is not None and days > 0
        assert err is None

    def test_parses_single_digit_day(self, tmp_path):
        """openssl pads single-digit days with a space: 'Apr  9' — parser must handle."""
        cert = tmp_path / "server.crt"
        cert.write_text("fake")
        stdout = "notAfter=Apr  9 00:00:00 2099\n"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=stdout, stderr="")
            days, expiry_str, err = _read_cert_expiry(cert)
        assert days is not None and days > 0

    def test_expired_cert_negative_days(self, tmp_path):
        cert = tmp_path / "server.crt"
        cert.write_text("fake")
        stdout = "notAfter=Apr 19 00:00:00 2000\n"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=stdout, stderr="")
            days, expiry_str, err = _read_cert_expiry(cert)
        assert days is not None and days < 0
        assert err is None

    def test_openssl_error_returns_none(self, tmp_path):
        cert = tmp_path / "server.crt"
        cert.write_text("fake")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="unable to load certificate")
            days, expiry_str, err = _read_cert_expiry(cert)
        assert days is None
        assert err == "unable to load certificate"

    def test_timeout_returns_error(self, tmp_path):
        cert = tmp_path / "server.crt"
        cert.write_text("fake")
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("openssl", 5)):
            days, expiry_str, err = _read_cert_expiry(cert)
        assert days is None
        assert "timed out" in err

    def test_large_file_skipped(self, tmp_path):
        """Files above _MAX_CERT_SIZE must be skipped without calling openssl."""
        from bob.checks.ssl_certs import _MAX_CERT_SIZE
        cert = tmp_path / "bundle.crt"
        cert.write_bytes(b"x" * (_MAX_CERT_SIZE + 1))
        days, expiry_str, err = _read_cert_expiry(cert)
        assert days is None
        assert err is not None  # some error message explaining the skip

    def test_unparseable_output_returns_error(self, tmp_path):
        cert = tmp_path / "server.crt"
        cert.write_text("fake")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="no date here\n", stderr="")
            days, expiry_str, err = _read_cert_expiry(cert)
        assert days is None
        assert err is not None


# ---------------------------------------------------------------------------
# TestSslCertsFromSystem
# ---------------------------------------------------------------------------

class TestSslCertsFromSystem:
    def test_no_openssl_returns_empty_snap(self):
        with patch("bob.checks.ssl_certs._command_exists", return_value=False):
            snap = SslCertsSnapshot.from_system()
        assert not snap.openssl_available
        assert snap.certs == []

    def test_discovers_letsencrypt_certs(self, tmp_path):
        le_live = tmp_path / "letsencrypt" / "live" / "example.com"
        le_live.mkdir(parents=True)
        cert = le_live / "fullchain.pem"
        cert.write_text("cert")

        stdout = "notAfter=Apr 19 00:00:00 2099\n"
        with (
            patch("bob.checks.ssl_certs._command_exists", return_value=True),
            patch("bob.checks.ssl_certs.Path") as mock_path_cls,
            patch("subprocess.run") as mock_run,
        ):
            # Bypass by testing _add_path directly instead
            pass

        # Simpler: patch Path("/etc/letsencrypt/live") to our tmp dir
        import bob.checks.ssl_certs as mod
        orig = mod.Path

        def _patched_path(s):
            if s == "/etc/letsencrypt/live":
                return le_live.parent
            if s == "/etc/ssl/private":
                return tmp_path / "nonexist"
            if s == "/etc/postfix/main.cf":
                return tmp_path / "nonexist_main.cf"
            return orig(s)

        with (
            patch.object(mod, "Path", side_effect=_patched_path),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="notAfter=Apr 19 00:00:00 2099\n", stderr="")
            snap = SslCertsSnapshot.from_system()

        assert any("fullchain.pem" in c.path for c in snap.certs)

    def test_certs_sorted_by_days_left(self):
        certs = [
            _cert("c.crt", days=180),
            _cert("a.crt", days=5),
            _cert("b.crt", days=25),
        ]
        snap = _snap(*certs)
        snap.certs.sort(key=lambda c: (c.days_left is None, c.days_left or 0))
        assert snap.certs[0].days_left == 5
        assert snap.certs[1].days_left == 25
        assert snap.certs[2].days_left == 180

    def test_none_days_sorted_last(self):
        certs = [
            _cert("a.crt", days=None, error="oops"),
            _cert("b.crt", days=10),
        ]
        snap = _snap(*certs)
        snap.certs.sort(key=lambda c: (c.days_left is None, c.days_left or 0))
        assert snap.certs[0].days_left == 10
        assert snap.certs[1].days_left is None

    def test_max_certs_limit_respected(self, tmp_path):
        """SslCertsSnapshot must not exceed _MAX_CERTS regardless of paths discovered."""
        from bob.checks.ssl_certs import _MAX_CERTS
        import bob.checks.ssl_certs as mod

        le_live = tmp_path / "letsencrypt" / "live"
        le_live.mkdir(parents=True)
        certs = []
        for i in range(_MAX_CERTS + 10):
            d = le_live / f"domain{i}.example.com"
            d.mkdir()
            c = d / "fullchain.pem"
            c.write_text("cert")
            certs.append(c)

        orig_path = mod.Path
        def _patched_path(s):
            if s == "/etc/letsencrypt/live":
                return le_live
            if s in ("/etc/ssl/private", "/etc/postfix/main.cf",
                     "/etc/nginx/sites-enabled", "/etc/nginx",
                     "/etc/apache2/sites-enabled", "/etc/apache2"):
                return tmp_path / "nonexist"
            return orig_path(s)

        with (
            patch("bob.checks.ssl_certs._command_exists", return_value=True),
            patch.object(mod, "Path", side_effect=_patched_path),
            patch("subprocess.run") as mock_run,
        ):
            from unittest.mock import MagicMock
            mock_run.return_value = MagicMock(returncode=0, stdout="notAfter=Apr 19 00:00:00 2099\n", stderr="")
            snap = SslCertsSnapshot.from_system()

        assert len(snap.certs) <= _MAX_CERTS
