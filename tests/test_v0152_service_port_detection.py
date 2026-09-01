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


def _probe(registry, service_id, filename, content, tmp_path, monkeypatch,
           pattern=None):
    """Run the real reader against one config file placed in a temp tree."""
    import dataclasses

    from bob.registry import Detection
    service = next(s for s in registry._services if s.id == service_id)
    target = tmp_path / filename
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    declared = str(tmp_path / pattern) if pattern else str(target)
    probe = dataclasses.replace(
        service, detection=Detection(binary=(), snap=(), config_files=(declared,))
    )
    monkeypatch.setattr("bob.checks.services._is_safe_config_path", lambda p: True)
    detected = _auto_detect_port(probe)
    return detected.split("/")[0] if detected else None


class TestServicesThatDeclaredNoConfigAtAll:
    """Three of the seven presence-only services do ship a port in a config.

    They were declared ``config_key: "fixed"``, so BOB asserted the registry
    default without ever looking — PostgreSQL on 5432 and WireGuard on 51820
    whatever the operator had set. Both are critical or high risk, and both
    keep their port in a standard system file.
    """

    def test_postgresql_versioned_path(self, registry, tmp_path, monkeypatch):
        assert _probe(registry, "postgresql", "postgresql/16/main/postgresql.conf",
                      "port = 5433\t# (change requires restart)\n",
                      tmp_path, monkeypatch,
                      pattern="postgresql/*/main/postgresql.conf") == "5433"

    def test_wireguard_camelcase_directive(self, registry, tmp_path, monkeypatch):
        """`ListenPort` has no separator, so the dotted rule cannot reach it."""
        assert _probe(registry, "wireguard", "wireguard/wg0.conf",
                      "[Interface]\nAddress = 10.0.0.1/24\nListenPort = 51821\n",
                      tmp_path, monkeypatch, pattern="wireguard/*.conf") == "51821"

    def test_syncthing_address_element(self, registry, tmp_path, monkeypatch):
        """Syncthing's XML keeps the port behind an <address>, not a *Port* tag."""
        assert _probe(registry, "syncthing", "syncthing/config.xml",
                      '<configuration>\n <gui>\n'
                      '  <address>0.0.0.0:8385</address>\n </gui>\n</configuration>\n',
                      tmp_path, monkeypatch) == "8385"

    def test_a_glob_that_matches_nothing_is_not_an_error(self, registry, tmp_path,
                                                        monkeypatch):
        import dataclasses

        from bob.registry import Detection
        service = next(s for s in registry._services if s.id == "postgresql")
        probe = dataclasses.replace(
            service,
            detection=Detection(binary=(), snap=(),
                                config_files=(str(tmp_path / "nothing/*/here.conf"),)),
        )
        assert _auto_detect_port(probe) is None


class TestAdditiveVersusOverridingDirectives:
    """Which repeat wins depends on what the directive means.

    `listen`/`listener` are additive — a server may declare several and they all
    apply, so the first is as representative as any. A `port` key overrides:
    redis, mysql and the YAML readers apply the last one, and changing a port by
    appending a line is the same operator habit that drove the v0.15.0 umask and
    login.defs findings.
    """

    def test_a_repeated_port_key_takes_the_last(self, registry, tmp_path, monkeypatch):
        assert _probe(registry, "redis", "redis.conf", "port 6379\nport 6380\n",
                      tmp_path, monkeypatch) == "6380"

    def test_repeated_listen_directives_take_the_first(self, registry, tmp_path,
                                                       monkeypatch):
        assert _probe(registry, "nginx", "nginx.conf",
                      "http {\n server {\n  listen 80;\n }\n"
                      " server {\n  listen 443 ssl;\n }\n}\n",
                      tmp_path, monkeypatch) == "80"

    def test_a_yaml_key_repeated_takes_the_last(self, registry, tmp_path, monkeypatch):
        assert _probe(registry, "elasticsearch", "elasticsearch.yml",
                      "http.port: 9201\ntransport.port: 9301\n",
                      tmp_path, monkeypatch) == "9301"

    def test_a_single_occurrence_is_unaffected(self, registry, tmp_path, monkeypatch):
        assert _probe(registry, "redis", "redis.conf", "port 6381\n",
                      tmp_path, monkeypatch) == "6381"


class TestTheClientSectionIsNotTheListeningPort:
    """`[client]` carries the port clients connect *to*, never the listener.

    It is written above `[mysqld]` in the shipped MySQL/MariaDB files, so a
    first-match reader answered with it.
    """

    def test_the_server_section_wins(self, registry, tmp_path, monkeypatch):
        assert _probe(registry, "mysql", "my.cnf",
                      "[client]\nport = 3306\n[mysqld]\nport = 3307\n",
                      tmp_path, monkeypatch) == "3307"

    def test_a_file_without_a_client_section_is_unaffected(self, registry, tmp_path,
                                                           monkeypatch):
        assert _probe(registry, "mysql", "my.cnf", "[mysqld]\nport = 3307\n",
                      tmp_path, monkeypatch) == "3307"


class TestOtherRealConfigShapes:
    @pytest.mark.parametrize("content,expected", [
        ("http {\n server {\n  listen 8080 default_server;\n }\n}\n", "8080"),
        ("http {\n server {\n  listen *:8081;\n }\n}\n",              "8081"),
        ("http {\n server {\n  listen [::]:8443 ssl http2;\n }\n}\n", "8443"),
    ])
    def test_nginx_listen_forms(self, content, expected, registry, tmp_path, monkeypatch):
        assert _probe(registry, "nginx", "nginx.conf", content,
                      tmp_path, monkeypatch) == expected

    def test_a_unix_socket_is_not_a_port(self, registry, tmp_path, monkeypatch):
        assert _probe(registry, "nginx", "nginx.conf",
                      "http {\n server {\n  listen unix:/run/nginx.sock;\n }\n}\n",
                      tmp_path, monkeypatch) is None

    def test_an_inline_comment_after_the_value(self, registry, tmp_path, monkeypatch):
        assert _probe(registry, "mysql", "my.cnf", "port = 3308 # application port\n",
                      tmp_path, monkeypatch) == "3308"

    def test_a_commented_directive_above_the_real_one(self, registry, tmp_path,
                                                      monkeypatch):
        assert _probe(registry, "mysql", "my.cnf", "# port = 9999\nport\t=\t3308\n",
                      tmp_path, monkeypatch) == "3308"
