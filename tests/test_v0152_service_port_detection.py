"""v0.15.2 — the port BOB audits must be the port the service listens on.

`_auto_detect_port` reads a service's own config to find its real port, and
the whole exposure verdict hangs off the answer: the wrong port is looked up
in the listening set, classified against the wrong UFW rule, and reported at
the wrong risk.

Its reader took the first digits following a directive keyword. A directive's
argument is very often an *address*, so `listen 127.0.0.1:8080;` — the ordinary
way to bind nginx to one interface — was read as **port 127**. That is the
v0.15.0 UFW defect (`80/tcp ALLOW IN 192.168.1.22` covering ports 1, 22, 168
and 192) in another module, and the third instance of the family in this
release after the `ss` address column.

Only 8 of the registry's 38 services are installed on any one machine, so these
formats were never exercised. The configs below are the upstream shapes, one
per format family.
"""

import pytest

from bob.checks.services import _auto_detect_port, _port_from_directive
from bob.registry import ServiceRegistry


class TestPortFromDirective:
    """The value after a directive is not always a bare number."""

    @pytest.mark.parametrize("value,expected", [
        ("8080",                "8080"),
        ("8080;",               "8080"),   # nginx statement terminator
        ('"3307"',              "3307"),   # quoted
        ("127.0.0.1:8080;",     "8080"),   # bind address — read as 127 before
        ("192.168.1.10:8443",   "8443"),   # read as 192 before
        ("[::]:443",            "443"),    # IPv6 — no match at all before
        ("[::1]:631",           "631"),
        ("*:80",                "80"),
    ])
    def test_the_port_is_what_follows_the_last_colon(self, value, expected):
        assert _port_from_directive(value) == expected

    @pytest.mark.parametrize("value", ["0", "65536", "99999", "-1", "abc", "", "YES"])
    def test_a_non_port_is_refused(self, value):
        assert _port_from_directive(value) is None

    def test_port_zero_is_not_a_port(self):
        """Redis uses `port 0` to disable TCP entirely — a hardened setting.

        Reporting `0/tcp` invented a socket that cannot exist. Returning None
        lets the caller fall back to the registry default, which the listening
        set then correctly reports as not listening.
        """
        assert _port_from_directive("0") is None


# One config per upstream format family, keyed by the service that ships it.
_CONFIGS: "dict[str, tuple[str, str, str]]" = {
    # service        path under /etc                          content                                        expected
    "nginx":        ("nginx/nginx.conf",                      "http {\n server {\n  listen 127.0.0.1:8080;\n }\n}\n", "8080"),
    "apache":       ("apache2/ports.conf",                    "Listen 8081\n",                                "8081"),
    "mysql":        ("mysql/mysql.conf.d/mysqld.cnf",         "[mysqld]\nbind-address = 0.0.0.0\nport = 3307\n", "3307"),
    "redis":        ("redis/redis.conf",                      "bind 127.0.0.1 -::1\nport 6381\n",             "6381"),
    "mongodb":      ("mongod.conf",                           "net:\n  port: 27018\n  bindIp: 127.0.0.1\n",   "27018"),
    "elasticsearch":("elasticsearch/elasticsearch.yml",       "network.host: 0.0.0.0\nhttp.port: 9201\n",     "9201"),
    "ftp":          ("vsftpd.conf",                           "listen=YES\nlisten_port=2121\n",               "2121"),
    "memcached":    ("memcached.conf",                        "\n-m 64\n-p 11212\n-l 127.0.0.1\n",            "11212"),
    "rdp":          ("xrdp/xrdp.ini",                         "[Globals]\nini_version=1\nport=3390\n",        "3390"),
    "squid":        ("squid/squid.conf",                      "http_port 3129\n",                             "3129"),
    "mosquitto":    ("mosquitto/mosquitto.conf",              "listener 1884\nallow_anonymous false\n",       "1884"),
    "cockpit":      ("cockpit/cockpit.conf",                  "[WebService]\nPort = 9092\n",                  "9092"),
    "gitea":        ("gitea/app.ini",                         "[server]\nHTTP_PORT = 3001\n",                 "3001"),
    "homeassistant":("homeassistant/configuration.yaml",      "http:\n  server_port: 8124\n",                 "8124"),
    "jellyfin":     ("jellyfin/network.xml",                  '<?xml version="1.0"?>\n<N>\n<PublicPort>8097</PublicPort>\n</N>\n', "8097"),
    "caddy":        ("caddy/Caddyfile",                       ":8443 {\n  root * /srv\n}\n",                  "8443"),
    "jenkins":      ("default/jenkins",                       "JENKINS_PORT=8081\n",                          "8081"),
    "vaultwarden":  ("vaultwarden.env",                       "ROCKET_PORT=8001\n",                           "8001"),
    "transmission": ("transmission-daemon/settings.json",     '{\n "rpc-port": 9092\n}\n',                    "9092"),
    "authelia":     ("authelia/configuration.yml",            "server:\n  host: 0.0.0.0\n  port: 9092\n",     "9092"),
}


@pytest.fixture(scope="module")
def registry():
    return ServiceRegistry.load()


class TestEveryConfigFormatIsRead:
    """Twenty services, seven format families, none of them installed here."""

    @pytest.mark.parametrize("service_id", sorted(_CONFIGS))
    def test_the_real_port_is_found(self, service_id, registry, tmp_path, monkeypatch):
        rel, content, expected = _CONFIGS[service_id]
        service = next(s for s in registry._services if s.id == service_id)

        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

        # Rewrite the service's declared config paths onto the temporary tree.
        # `Service` is frozen, so build a copy rather than patching in place.
        import dataclasses

        from bob.registry import Detection
        redirected = tuple(
            str(tmp_path / c.lstrip("/").removeprefix("etc/"))
            for c in service.detection.config_files
        )
        probe = dataclasses.replace(
            service,
            detection=Detection(binary=service.detection.binary,
                                snap=service.detection.snap,
                                config_files=redirected),
        )
        monkeypatch.setattr("bob.checks.services._is_safe_config_path", lambda p: True)

        detected = _auto_detect_port(probe)
        assert detected is not None, f"{service_id}: no port found in its own config"
        assert detected.split("/")[0] == expected


class TestNoFalsePositives:
    """The vocabulary was widened; it must not swallow neighbouring words."""

    @pytest.mark.parametrize("line", [
        "passport = 1234",
        "my_passport: 99",
        "report 8080",
        "# port = 9999",
        "support: 4242",
    ])
    def test_a_lookalike_directive_is_not_a_port(self, line, tmp_path, registry, monkeypatch):
        import dataclasses

        service = next(s for s in registry._services if s.id == "redis")
        target = tmp_path / "redis.conf"
        target.write_text(line + "\n", encoding="utf-8")
        from bob.registry import Detection
        probe = dataclasses.replace(
            service, detection=Detection(binary=(), snap=(), config_files=(str(target),))
        )
        monkeypatch.setattr("bob.checks.services._is_safe_config_path", lambda p: True)
        assert _auto_detect_port(probe) is None
