"""v0.15.2 — a certificate BOB never finds is a certificate that never expires.

`ssl_certs` walks the web server configs to learn which certificates are
actually served, then reports how long each has left. Two of those walks looked
in the wrong place, and both failed silently: no error, no finding, just an
empty list where an expiring certificate should have been.

Measured in containers with a real certificate five days from expiry, declared
the ordinary way for each server:

  Debian nginx   the stock site is `sites-enabled/default`, with no extension,
                 and the scan globbed `**/*.conf` — the one file that declares
                 the certificate was never opened.
  Fedora httpd   only `/etc/apache2` was scanned. Fedora and Arch keep their
                 vhosts under `/etc/httpd`, so the whole RHEL family went
                 unexamined.

Both now report the certificate with four days left.
"""

from bob.checks.ssl_certs import (
    _APACHE_SSL_RE as _APACHE,
    _NGINX_SSL_RE as _NGINX,
    _collect_from_configs,
)


def _cert(tmp_path, name="cert.pem"):
    """A real file: `_add_path` only records certificates that exist."""
    target = tmp_path / name
    target.write_text("-----BEGIN CERTIFICATE-----\n")
    return target


class TestExtensionlessSiteFiles:
    """Debian names an nginx site after the site, not after `.conf`."""

    def test_a_file_without_an_extension_is_scanned(self, tmp_path):
        cert = _cert(tmp_path)
        (tmp_path / "default").write_text(
            f"server {{\n ssl_certificate {cert};\n}}\n"
        )
        found: set = set()
        _collect_from_configs(tmp_path, _NGINX, found, any_filename=True)
        assert found == {str(cert)}

    def test_the_conf_only_scan_still_misses_it(self, tmp_path):
        """Pins why the flag is needed rather than assuming it."""
        cert = _cert(tmp_path)
        (tmp_path / "default").write_text(
            f"server {{\n ssl_certificate {cert};\n}}\n"
        )
        found: set = set()
        _collect_from_configs(tmp_path, _NGINX, found)
        assert found == set()

    def test_conf_files_are_still_scanned_with_the_flag(self, tmp_path):
        cert = _cert(tmp_path)
        (tmp_path / "site.conf").write_text(
            f"server {{\n ssl_certificate {cert};\n}}\n"
        )
        found: set = set()
        _collect_from_configs(tmp_path, _NGINX, found, any_filename=True)
        assert found == {str(cert)}

    def test_a_directory_entry_is_not_read_as_a_file(self, tmp_path):
        """`**/*` matches directories too; they must not reach `read_text`."""
        cert = _cert(tmp_path)
        (tmp_path / "subdir").mkdir()
        (tmp_path / "subdir" / "site").write_text(
            f"server {{\n ssl_certificate {cert};\n}}\n"
        )
        found: set = set()
        _collect_from_configs(tmp_path, _NGINX, found, any_filename=True)
        assert found == {str(cert)}


class TestBothApacheTrees:
    """Debian and openSUSE under /etc/apache2, Fedora and Arch under /etc/httpd."""

    def test_the_httpd_tree_is_declared(self):
        import inspect

        from bob.checks import ssl_certs
        source = inspect.getsource(ssl_certs.SslCertsSnapshot.from_system)
        assert '"/etc/httpd"' in source, "the RHEL apache tree is not scanned"
        assert '"/etc/apache2"' in source, "the Debian apache tree was dropped"

    def test_an_httpd_vhost_is_read(self, tmp_path):
        cert = _cert(tmp_path, "httpd.pem")
        vhost = tmp_path / "conf.d"
        vhost.mkdir()
        (vhost / "ssl.conf").write_text(
            f"<VirtualHost *:443>\nSSLCertificateFile {cert}\n</VirtualHost>\n"
        )
        found: set = set()
        _collect_from_configs(tmp_path, _APACHE, found)
        assert found == {str(cert)}


class TestTheScanStaysBounded:
    """The caps that keep this from walking a large tree must still hold."""

    def test_oversized_files_are_skipped(self, tmp_path, monkeypatch):
        from bob.checks import ssl_certs
        monkeypatch.setattr(ssl_certs, "_MAX_CONF_SIZE", 10)
        cert = _cert(tmp_path, "big.pem")
        (tmp_path / "big.conf").write_text(f"ssl_certificate {cert};\n" * 20)
        found: set = set()
        _collect_from_configs(tmp_path, _NGINX, found)
        assert found == set()

    def test_the_file_count_is_capped(self, tmp_path, monkeypatch):
        from bob.checks import ssl_certs
        monkeypatch.setattr(ssl_certs, "_MAX_CONF_FILES", 2)
        for index in range(6):
            cert = _cert(tmp_path, f"c{index}.pem")
            (tmp_path / f"s{index}.conf").write_text(f"ssl_certificate {cert};\n")
        found: set = set()
        _collect_from_configs(tmp_path, _NGINX, found)
        assert len(found) <= 2

    def test_a_missing_directory_is_not_an_error(self, tmp_path):
        found: set = set()
        _collect_from_configs(tmp_path / "absent", _NGINX, found, any_filename=True)
        assert found == set()
