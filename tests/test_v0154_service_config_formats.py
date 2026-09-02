"""Every declared config format must actually be parseable.

Backlog item 3, second half. The fifteen services with their own installer —
gitea, authelia, vaultwarden, ollama, jellyfin, caddy, elasticsearch, mongodb,
jenkins, adguard, homeassistant, transmission and the rest — were never
installed to check what BOB reads from them. They cannot be: they are not in
the distribution repositories, and installing them would change the posture of
the very host the audit uses as its reference.

What *is* checkable without installing them is the question that decides
whether declaring a config file buys anything: **does BOB's parser understand
the format that service actually writes?** Declaring
`/etc/authelia/configuration.yml` is worth nothing if the reader cannot find a
port in YAML.

Eleven formats, one snippet each, taken from the syntax each project
documents. Ten worked. The eleventh, ollama, did not: its documented way to
move its port is an ``Environment=`` line in a systemd unit carrying a
host:port pair, with no ``port`` keyword for the generic regex to find.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bob.checks.services import _auto_detect_ports
from bob.registry import Detection, Service


def probe(tmp_path: Path, filename: str, content: str, default="1/tcp") -> list[str]:
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8")
    service = Service(
        id="probe", label="Probe", packages=(), services=(), ports=(default,),
        risk="low",
        detection=Detection(binary=(), snap=(), config_files=(str(path),)),
    )
    return _auto_detect_ports(service)


# (label, filename, content, expected port) — one per format the 15 declare.
FORMATS = [
    ("gitea INI",        "app.ini",           "[server]\nPROTOCOL = http\nHTTP_PORT = 3000\n", "3000/tcp"),
    ("jenkins env",      "jenkins",           "NAME=jenkins\nHTTP_PORT=8080\n",                "8080/tcp"),
    ("vaultwarden env",  "vaultwarden.env",   "DOMAIN=https://x\nROCKET_PORT=8000\n",          "8000/tcp"),
    ("elasticsearch YAML","elasticsearch.yml","cluster.name: x\nhttp.port: 9200\n",            "9200/tcp"),
    ("mongodb YAML",     "mongod.conf",       "net:\n  bindIp: 127.0.0.1\n  port: 27017\n",    "27017/tcp"),
    ("authelia YAML",    "configuration.yml", "server:\n  port: 9091\n",                       "9091/tcp"),
    ("adguard YAML",     "AdGuardHome.yaml",  "bind_host: 0.0.0.0\nbind_port: 3000\n",         "3000/tcp"),
    ("homeassistant YAML","configuration.yaml","http:\n  server_port: 8123\n",                 "8123/tcp"),
    ("transmission JSON","settings.json",     '{"rpc-enabled": true, "rpc-port": 9091}\n',     "9091/tcp"),
    ("jellyfin XML",     "network.xml",       "<Net><PublicPort>8096</PublicPort></Net>\n",    "8096/tcp"),
    ("caddy Caddyfile",  "Caddyfile",         ':8443 {\n  respond "ok"\n}\n',                  "8443/tcp"),
    ("ollama unit",      "ollama.service",    '[Service]\nEnvironment="OLLAMA_HOST=0.0.0.0:11434"\n', "11434/tcp"),
]


class TestEveryDeclaredFormatIsUnderstood:
    @pytest.mark.parametrize(
        "label, filename, content, expected",
        FORMATS, ids=[f[0] for f in FORMATS],
    )
    def test_the_port_is_found(self, tmp_path, label, filename, content, expected):
        assert probe(tmp_path, filename, content) == [expected], (
            f"{label}: declaring this config file buys nothing if the port "
            f"cannot be read out of it"
        )

    def test_an_unparseable_file_falls_back_rather_than_guessing(self, tmp_path):
        """Polarity twin: a format with no port must yield nothing, not a
        number scraped from elsewhere."""
        assert probe(tmp_path, "app.ini", "[server]\nPROTOCOL = http\n") == []


class TestTheSystemdUnitRuleStaysNarrow:
    """The ollama fix reads `Environment=<UNIT>_HOST=addr:port`.

    A generic `*_HOST=host:port` rule would read `DATABASE_HOST=db:5432` as a
    port this service listens on, when it is the address of something it
    connects *to*. A false listening port is worse than a missed one: the
    operator has no way to tell it is wrong.
    """

    def test_the_units_own_variable_is_read(self, tmp_path):
        content = '[Service]\nEnvironment="OLLAMA_HOST=127.0.0.1:11500"\n'
        assert probe(tmp_path, "ollama.service", content) == ["11500/tcp"]

    def test_quotes_are_optional(self, tmp_path):
        content = "[Service]\nEnvironment=OLLAMA_HOST=0.0.0.0:11434\n"
        assert probe(tmp_path, "ollama.service", content) == ["11434/tcp"]

    def test_another_services_host_variable_is_ignored(self, tmp_path):
        content = '[Service]\nEnvironment="DATABASE_HOST=db:5432"\n'
        assert probe(tmp_path, "ollama.service", content) == []

    def test_a_host_without_a_port_falls_back(self, tmp_path):
        content = '[Service]\nEnvironment="OLLAMA_HOST=0.0.0.0"\n'
        assert probe(tmp_path, "ollama.service", content) == []
