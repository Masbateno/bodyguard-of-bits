"""
v0.15.0 — a certificate valid for another 23 hours was reported as EXPIRED.

The expectations here are not written by hand. Nine certificates are minted at
the boundaries and each verdict is compared against `openssl x509 -checkend 0`,
which is the authority on whether a certificate is currently valid.

`days_left` is a floored timedelta. Python floors negative timedeltas too, so:

    expires in 23h        ->  0
    expires in 1h         ->  0
    expired 1 minute ago  -> -1
    expired 12h ago       -> -1

`days <= 0` therefore covered the entire final day of a *still-valid*
certificate. BOB raised `ssl_certs.expired` — an ALERT, with a 2-point
deduction and a message stating it expired "0 days ago" — for a certificate
openssl accepts. Two of the nine minted cases were wrong, both in the alarming
direction, which is the recoverable one but still a false statement an operator
disproves in one command.

`days == 0` now falls into the critical branch: still an ALERT, still a
deduction, but the claim is true.
"""

from __future__ import annotations

import datetime
import subprocess
from pathlib import Path

import pytest

from bob.checks.ssl_certs import (
    CertEntry,
    SslCertsSnapshot,
    _read_cert_expiry,
    check_ssl_certs,
)

cryptography = pytest.importorskip("cryptography")

from cryptography import x509                                    # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa         # noqa: E402
from cryptography.x509.oid import NameOID                         # noqa: E402


def _mint(tmp_path: Path, name: str, not_after: datetime.datetime) -> Path:
    now = datetime.datetime.now(datetime.timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=365))
            .not_valid_after(not_after)
            .sign(key, hashes.SHA256()))
    path = tmp_path / f"{name}.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


def _openssl_says_valid(path: Path) -> bool:
    return subprocess.run(
        ["openssl", "x509", "-checkend", "0", "-noout", "-in", str(path)],
        capture_output=True).returncode == 0


def _keys(path: Path) -> list[str]:
    days, expiry, err = _read_cert_expiry(path)
    snap = SslCertsSnapshot(
        certs=[CertEntry(path=str(path), days_left=days, expiry_str=expiry, error=err)],
        openssl_available=True)
    return [f.key for f in check_ssl_certs(snap).findings]


_NOW = datetime.datetime.now(datetime.timezone.utc)
_CASES = {
    "expired_10d": _NOW - datetime.timedelta(days=10),
    "expired_1h":  _NOW - datetime.timedelta(hours=1),
    "in_1h":       _NOW + datetime.timedelta(hours=1),
    "in_23h":      _NOW + datetime.timedelta(hours=23),
    "in_2d":       _NOW + datetime.timedelta(days=2),
    "in_400d":     _NOW + datetime.timedelta(days=400),
    # single-digit day: openssl renders notAfter with a double space
    "single_digit": datetime.datetime(2031, 1, 5, tzinfo=datetime.timezone.utc),
    # >= 2050 switches the ASN.1 encoding from UTCTime to GeneralizedTime
    "year_2060":    datetime.datetime(2060, 6, 15, 12, tzinfo=datetime.timezone.utc),
}


@pytest.mark.skipif(not subprocess.run(["which", "openssl"], capture_output=True).returncode == 0,
                    reason="openssl not installed")
class TestAgainstOpenssl:
    @pytest.mark.parametrize("name", sorted(_CASES))
    def test_expired_matches_openssl(self, tmp_path, name):
        path = _mint(tmp_path, name, _CASES[name])
        claims_expired = "ssl_certs.expired" in _keys(path)
        assert claims_expired is not _openssl_says_valid(path), (
            f"{name}: BOB says expired={claims_expired}, "
            f"openssl says valid={_openssl_says_valid(path)}")

    @pytest.mark.parametrize("name", ["in_1h", "in_23h"])
    def test_a_certificate_in_its_last_day_is_critical_not_expired(self, tmp_path, name):
        keys = _keys(_mint(tmp_path, name, _CASES[name]))
        assert "ssl_certs.expiring_critical" in keys
        assert "ssl_certs.expired" not in keys

    @pytest.mark.parametrize("name", ["expired_1h", "expired_10d"])
    def test_a_genuinely_expired_certificate_is_still_alerted(self, tmp_path, name):
        assert "ssl_certs.expired" in _keys(_mint(tmp_path, name, _CASES[name]))

    def test_the_last_day_still_costs_points(self, tmp_path):
        """Downgrading the wording must not downgrade the urgency."""
        path = _mint(tmp_path, "in_23h", _CASES["in_23h"])
        days, expiry, err = _read_cert_expiry(path)
        snap = SslCertsSnapshot(
            certs=[CertEntry(path=str(path), days_left=days, expiry_str=expiry, error=err)],
            openssl_available=True)
        result = check_ssl_certs(snap)
        assert sum(d.points for d in result.deductions) > 0

    @pytest.mark.parametrize("name", ["single_digit", "year_2060", "in_400d"])
    def test_unusual_date_renderings_still_parse(self, tmp_path, name):
        """A double-space day and a GeneralizedTime year must not read as an
        error — an unparseable notAfter is its own, different finding."""
        days, _, err = _read_cert_expiry(_mint(tmp_path, name, _CASES[name]))
        assert err is None and days is not None and days > 0
