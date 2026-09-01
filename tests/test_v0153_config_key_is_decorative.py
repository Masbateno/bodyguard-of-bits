"""v0.15.3 — what `config_key` claims, and what decides the behaviour.

The field was documented four ways, validated a fifth, and read once. Its
description promised that `"ask"` prompts the operator and saves the answer,
and that a free-form identifier is read from the user config. Neither has an
implementation, and eight services carried a config path under `"ask"` whose
file was therefore never opened — nginx on 8443 was audited as 80 and 443
until v0.15.2.

Since that release the reader opens a config whenever `detection.config_files`
names one, whatever the strategy is called. So the field decides nothing, and
these tests pin that so the description cannot drift back into a promise.

Retiring it is a registry contract change and is queued rather than done: it
costs nothing to keep, and consumers read services.json.
"""

import dataclasses

import pytest

from bob.checks.services import _resolve_ports
from bob.registry import VALID_CONFIG_KEYS, Detection, Service, ServiceRegistry


def _probe(config_key: str, config_file, tmp_path):
    files = ()
    if config_file is not None:
        target = tmp_path / "svc.conf"
        target.write_text(config_file, encoding="utf-8")
        files = (str(target),)
    return Service(id="probe", label="Probe", packages=(), services=(),
                   ports=("1194/udp",), risk="low", config_key=config_key,
                   detection=Detection(binary=(), snap=(), config_files=files))


class TestTheStrategyNameChangesNothing:
    """Every declared form behaves identically; only the path matters."""

    @pytest.mark.parametrize("config_key", ["auto", "ask", "fixed", "ssh_port"])
    def test_a_declared_config_is_read_whatever_it_is_called(
        self, config_key, tmp_path, monkeypatch
    ):
        monkeypatch.setattr("bob.checks.services._is_safe_service_config",
                            lambda path, declared: True)
        service = _probe(config_key, "port 1195\n", tmp_path)
        assert _resolve_ports(service) == ["1195/udp"]

    @pytest.mark.parametrize("config_key", ["auto", "ask", "fixed", "ssh_port"])
    def test_no_declared_config_falls_back_whatever_it_is_called(
        self, config_key, tmp_path
    ):
        assert _resolve_ports(_probe(config_key, None, tmp_path)) == ["1194/udp"]

    def test_the_two_answers_differ_only_by_the_path(self, tmp_path, monkeypatch):
        """The discriminator, stated once."""
        monkeypatch.setattr("bob.checks.services._is_safe_service_config",
                            lambda path, declared: True)
        with_path = _resolve_ports(_probe("fixed", "port 1195\n", tmp_path))
        without = _resolve_ports(_probe("auto", None, tmp_path))
        assert with_path != without
        assert (with_path, without) == (["1195/udp"], ["1194/udp"])


class TestTheFieldIsReadInOnePlace:
    def test_only_the_resolver_consults_it(self):
        """A second reader would make this field load-bearing again."""
        import re
        from pathlib import Path

        readers = []
        for path in sorted(Path("bob").rglob("*.py")):
            for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                stripped = line.strip()
                if stripped.startswith("#") or '"""' in stripped:
                    continue
                if re.search(r"\.config_key\b", line):
                    readers.append(f"{path}:{number}")
        assert readers == ["bob/checks/services.py:555"], (
            "config_key is read somewhere new; it is documented as decorative, "
            "so either the documentation or the new reader is wrong: "
            + ", ".join(readers)
        )


class TestTheValidatorStillAcceptsAllFourForms:
    """Keeping the field means keeping what the registry may contain."""

    @pytest.mark.parametrize("config_key", sorted(VALID_CONFIG_KEYS) + ["ssh_port"])
    def test_the_form_loads(self, config_key):
        Service.from_dict({
            "id": "probe", "label": "Probe", "packages": ["p"], "services": ["p"],
            "ports": ["1/tcp"], "risk": "low", "config_key": config_key,
        })

    @pytest.mark.parametrize("config_key", ["class", "not an identifier", ""])
    def test_a_form_that_is_neither_is_refused(self, config_key):
        with pytest.raises(ValueError):
            Service.from_dict({
                "id": "probe", "label": "Probe", "packages": ["p"],
                "services": ["p"], "ports": ["1/tcp"], "risk": "low",
                "config_key": config_key,
            })


class TestTheRegistryUsesNoNamedKey:
    def test_the_free_form_identifier_has_no_user(self):
        """Documented, validated, and exercised by nothing."""
        named = [
            s.id for s in ServiceRegistry.load()._services
            if s.config_key not in VALID_CONFIG_KEYS
        ]
        assert not named, (
            "a service now uses the named-key form, which nothing implements: "
            + ", ".join(named)
        )
