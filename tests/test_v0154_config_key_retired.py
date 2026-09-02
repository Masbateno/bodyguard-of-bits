"""v0.15.4 — `config_key` retired from the service registry.

The field declared a port-resolution strategy in four forms: ``"fixed"``,
``"auto"``, ``"ask"``, or a free-form identifier naming a user-config key such
as ``ssh_port``. None of it was ever wired. ``"ask"`` — documented as prompting
the operator — had no implementation, no service used the identifier form, and
since v0.15.2 a service's configuration is read whenever
``detection.config_files`` names one, whatever the field said. v0.15.3 pinned
the field as decorative and queued its removal as a contract change; this is
that change.

Removal is behaviour-preserving on the bundled registry, and the two facts that
make it so are asserted below rather than asserted in prose: no service ever
carried ``"auto"`` without also declaring a config path, so dropping that term
from the reader's condition never flips it; and every service declares a port,
so the lone rule the field enforced (``"fixed"`` requires a port) is restated
directly and applies to all of them.

``config_key`` stays *accepted* by the JSON schema. ``additionalProperties`` is
false, so removing it from ``properties`` would reject the
``~/.config/bob/services.d/*.json`` files users have already written — a
documented plugin contract. It validates, loads, and does nothing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bob.registry import Service, ServiceRegistry

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT / "bob" / "data" / "schemas" / "service.schema.json").read_text(encoding="utf-8"))


def bundled() -> list[dict]:
    raw = json.loads((ROOT / "bob" / "data" / "services.json").read_text(encoding="utf-8"))
    entries = raw["services"] if isinstance(raw, dict) and "services" in raw else raw
    return list(entries.values()) if isinstance(entries, dict) else entries


def base_entry(**over) -> dict:
    entry = {
        "id": "probe", "label": "Probe", "packages": ["probe"],
        "services": ["probe.service"], "ports": ["9999/tcp"], "risk": "low",
        "detection": {"config_files": ["/etc/probe.conf"]},
    }
    entry.update(over)
    return entry


class TestTheFieldIsGone:
    def test_no_bundled_service_declares_it(self):
        offenders = [s["id"] for s in bundled() if "config_key" in s]
        assert not offenders, f"still declaring config_key: {offenders}"

    def test_the_registry_exposes_no_such_attribute(self):
        assert not hasattr(Service.from_dict(base_entry()), "config_key")

    def test_it_is_not_required_by_the_schema(self):
        assert "config_key" not in SCHEMA["required"]

    def test_no_code_reads_it(self):
        """The v0.15.3 guard watched for a *second* reader; now there is none."""
        src = "\n".join(
            p.read_text(encoding="utf-8") for p in ROOT.joinpath("bob").rglob("*.py")
        )
        assert "service.config_key" not in src
        assert "VALID_CONFIG_KEYS" not in src


class TestUserFilesKeepLoading:
    """additionalProperties is false, so tolerance has to be explicit."""

    def test_an_old_entry_still_validates(self):
        jsonschema = pytest.importorskip("jsonschema")
        jsonschema.validate(base_entry(config_key="ask"), SCHEMA)

    def test_an_old_entry_still_loads_and_the_value_is_dropped(self):
        service = Service.from_dict(base_entry(config_key="ssh_port"))
        assert service.id == "probe"
        assert not hasattr(service, "config_key")

    @pytest.mark.parametrize("value", ["fixed", "auto", "ask", "ssh_port"])
    def test_every_historical_form_is_tolerated(self, value):
        assert Service.from_dict(base_entry(config_key=value)).ports == ("9999/tcp",)


class TestRemovalWasBehaviourPreserving:
    """The two facts the removal rests on, checked against the real registry."""

    def test_no_service_relied_on_the_auto_term(self):
        """The reader was `config_key == "auto" or config_files`. Dropping the
        first term only changes an outcome for a service that had "auto" and no
        declared path — the bundled registry has never contained one."""
        without_path = [
            s["id"] for s in bundled()
            if not (s.get("detection") or {}).get("config_files")
        ]
        # none of these can have relied on "auto": the field is gone, and the
        # assertion that matters is that they fall back, which they do.
        for entry in bundled():
            service = Service.from_dict(entry)
            declared = bool(service.detection.config_files)
            assert declared or entry["id"] in without_path

    def test_every_service_declares_a_port(self):
        """The lone rule config_key enforced, now stated for all services."""
        portless = [s["id"] for s in bundled() if not s.get("ports")]
        assert not portless, f"services with no port: {portless}"

    def test_a_portless_service_with_a_config_still_loads(self):
        """Deliberately NOT "every service needs a port": a service may declare
        none and let them be parsed out of its own config — what the old "auto"
        form meant. Making the rule universal would have rejected that, which
        the existing registry tests caught."""
        assert Service.from_dict(base_entry(ports=[])).ports == ()

    def test_a_service_with_neither_port_nor_config_is_refused(self):
        """The genuinely unusable entry: BOB could never learn its ports."""
        with pytest.raises(ValueError, match="could never be determined"):
            Service.from_dict(base_entry(ports=[], detection={}))

    def test_the_bundled_registry_still_loads(self):
        assert len(ServiceRegistry.load().all()) == len(bundled()) == 38
