"""
JSON Schema validation for service definitions — Phase 1 distro-ready contract.

Validates that:
  - The bundled `bob/data/services.json` conforms to `service.schema.json`.
  - The schemas themselves are valid Draft 2020-12 JSON Schema documents.
  - Sample valid/invalid plugin entries behave as expected when parsed.

The schema is shipped in `bob/data/schemas/` and described in README_TECH.md
"Service plugins" section. It mirrors the Python-side validation in
`bob.registry.Service.from_dict()` — keep both in sync.

`jsonschema` is a test-only dependency; it is NOT required at runtime.

Run with: python -m pytest tests/test_services_schema.py -v
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

# Collected-and-skipped rather than not collected at all: see the note in
# test_v0150_ssl_expiry_boundary.py. `importorskip` here removed 43 tests from
# the count on any machine without jsonschema, which is what the project's CI
# is, so the documented figure could never match what CI measured.
try:
    import jsonschema
    _HAVE_JSONSCHEMA = True
except ImportError:                                              # pragma: no cover
    jsonschema = None
    _HAVE_JSONSCHEMA = False

pytestmark = pytest.mark.skipif(
    not _HAVE_JSONSCHEMA, reason="jsonschema is not installed"
)


_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SCHEMAS_DIR = _PROJECT_ROOT / "bob" / "data" / "schemas"
_SERVICES_JSON = _PROJECT_ROOT / "bob" / "data" / "services.json"


def _load_json(path: Path) -> dict | list:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _make_resolved_validator(root_schema: dict, extra_schemas: dict[str, dict] | None = None):
    """
    Build a Draft 2020-12 validator that resolves cross-file ``$ref`` entries.

    Compatibility shim: jsonschema 4.18+ deprecates ``RefResolver`` in favour of
    the ``referencing`` library. We try the modern path first and fall back to
    the legacy ``RefResolver`` for older versions (jsonschema 4.10–4.17). When
    we eventually drop support for jsonschema < 4.18, the legacy branch can go.
    """
    extra = extra_schemas or {}

    # Modern path (jsonschema 4.18+)
    try:
        from referencing import Registry, Resource  # type: ignore
        resources = [(uri, Resource.from_contents(s)) for uri, s in extra.items()]
        if "$id" in root_schema:
            resources.append((root_schema["$id"], Resource.from_contents(root_schema)))
        registry = Registry().with_resources(resources)
        return jsonschema.Draft202012Validator(root_schema, registry=registry)
    except ImportError:
        pass  # fall through to legacy path

    # Legacy path (jsonschema 4.10–4.17)
    store = dict(extra)
    if "$id" in root_schema:
        store[root_schema["$id"]] = root_schema
    resolver = jsonschema.RefResolver(base_uri="", referrer=root_schema, store=store)
    return jsonschema.Draft202012Validator(root_schema, resolver=resolver)


# ---------------------------------------------------------------------------
# Module-scope fixtures (DRY — every test class that needs a validator pulls
# from these instead of redefining its own).
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def service_schema() -> dict:
    return _load_json(_SCHEMAS_DIR / "service.schema.json")


@pytest.fixture(scope="module")
def services_list_schema() -> dict:
    return _load_json(_SCHEMAS_DIR / "services-list.schema.json")


@pytest.fixture(scope="module")
def plugin_file_schema() -> dict:
    return _load_json(_SCHEMAS_DIR / "plugin-file.schema.json")


@pytest.fixture(scope="module")
def service_validator(service_schema):
    """Validator for a single service entry (used by 4 of 5 schema test classes)."""
    return jsonschema.Draft202012Validator(service_schema)


# ---------------------------------------------------------------------------
# Schemas themselves are valid
# ---------------------------------------------------------------------------

class TestSchemasAreWellFormed:
    def test_service_schema_is_valid_jsonschema(self, service_schema):
        # Validator is available — confirms Draft 2020-12 compliance
        jsonschema.Draft202012Validator.check_schema(service_schema)

    def test_services_list_schema_is_valid_jsonschema(self, services_list_schema):
        jsonschema.Draft202012Validator.check_schema(services_list_schema)

    def test_service_schema_has_id_and_title(self, service_schema):
        assert service_schema["$id"]
        assert service_schema["title"] == "BOB service definition"

    def test_services_list_rejects_empty_array(self, services_list_schema, service_schema):
        """Empty array is structurally meaningless — schema enforces minItems: 1."""
        validator = _make_resolved_validator(
            services_list_schema,
            extra_schemas={
                "service.schema.json": service_schema,
                "services-list.schema.json": services_list_schema,
                service_schema["$id"]: service_schema,
            },
        )
        errors = list(validator.iter_errors([]))
        assert errors, "empty array must be rejected by minItems: 1"


# ---------------------------------------------------------------------------
# Bundled services.json matches the schema
# ---------------------------------------------------------------------------

class TestBundledServicesMatchSchema:
    def test_services_json_loads(self):
        data = _load_json(_SERVICES_JSON)
        assert isinstance(data, list)
        assert len(data) > 0

    def test_each_service_validates(self, service_schema):
        data = _load_json(_SERVICES_JSON)
        validator = jsonschema.Draft202012Validator(service_schema)
        errors = []
        for entry in data:
            for err in validator.iter_errors(entry):
                errors.append(f"{entry.get('id', '?')}: {err.message}")
        assert not errors, "Schema mismatches in bundled services.json:\n" + "\n".join(errors)

    def test_bundled_services_have_unique_ids(self):
        data = _load_json(_SERVICES_JSON)
        ids = [entry["id"] for entry in data]
        # Counter is O(n); the previous `ids.count(x)` per-id was O(n²).
        duplicates = [name for name, n in Counter(ids).items() if n > 1]
        assert not duplicates, f"Duplicate service IDs in bundled list: {duplicates}"


# ---------------------------------------------------------------------------
# Sample plugin entries — happy path
# ---------------------------------------------------------------------------

class TestValidPluginSamples:
    """Custom plugin samples that must pass schema validation."""

    @pytest.fixture
    def validator(self, service_validator):
        # Delegate to the module-scope fixture — a single validator instance
        # is shared across all per-class needs (DRY).
        return service_validator

    def test_minimal_fixed_service(self, validator):
        entry = {
            "id": "myservice",
            "label": "My Service",
            "packages": ["mypackage"],
            "services": ["myservice"],
            "ports": ["8080/tcp"],
            "risk": "medium",
            "config_key": "fixed",
        }
        errors = list(validator.iter_errors(entry))
        assert not errors, [e.message for e in errors]

    def test_with_detection_block(self, validator):
        entry = {
            "id": "snap-app",
            "label": "Snap App",
            "packages": [],
            "services": [],
            "ports": ["1234/tcp"],
            "risk": "low",
            "config_key": "fixed",
            "detection": {
                "binary": ["/usr/local/bin/myapp"],
                "snap": ["myapp-snap"],
                "config_files": ["/etc/myapp/config.yml"],
            },
        }
        errors = list(validator.iter_errors(entry))
        assert not errors, [e.message for e in errors]

    def test_user_config_key(self, validator):
        entry = {
            "id": "mydb",
            "label": "My DB",
            "packages": ["mydb-server"],
            "services": ["mydb"],
            "ports": ["3306/tcp"],
            "risk": "high",
            "config_key": "mydb_port",
        }
        errors = list(validator.iter_errors(entry))
        assert not errors, [e.message for e in errors]


# ---------------------------------------------------------------------------
# Invalid plugin entries — must be rejected
# ---------------------------------------------------------------------------

class TestInvalidPluginSamples:
    """Schema must reject malformed plugin entries."""

    @pytest.fixture
    def validator(self, service_validator):
        # Delegate to the module-scope fixture — a single validator instance
        # is shared across all per-class needs (DRY).
        return service_validator

    def test_missing_required_field(self, validator):
        entry = {"id": "x", "label": "X"}  # missing packages, services, ports, risk, config_key
        errors = list(validator.iter_errors(entry))
        assert errors

    def test_invalid_risk_value(self, validator):
        entry = {
            "id": "x", "label": "X",
            "packages": [], "services": [], "ports": ["80/tcp"],
            "risk": "extreme",   # not in enum
            "config_key": "fixed",
        }
        errors = list(validator.iter_errors(entry))
        assert any("extreme" in e.message or "enum" in e.message.lower() for e in errors)

    def test_invalid_port_format(self, validator):
        entry = {
            "id": "x", "label": "X",
            "packages": [], "services": [],
            "ports": ["80"],  # missing /tcp
            "risk": "low", "config_key": "fixed",
        }
        errors = list(validator.iter_errors(entry))
        # Targeted check: at least one error concerns the ports[0] item.
        # `e.absolute_path` is more stable across jsonschema versions than `e.message`.
        port_errors = [e for e in errors if list(e.absolute_path)[:2] == ["ports", 0]]
        assert port_errors, f"expected error on /ports/0, got: {[list(e.absolute_path) for e in errors]}"

    def test_port_zero_rejected(self, validator):
        entry = {
            "id": "x", "label": "X",
            "packages": [], "services": [],
            "ports": ["0/tcp"],  # port 0 invalid
            "risk": "low", "config_key": "fixed",
        }
        errors = list(validator.iter_errors(entry))
        port_errors = [e for e in errors if list(e.absolute_path)[:2] == ["ports", 0]]
        assert port_errors, f"expected error on /ports/0, got: {[list(e.absolute_path) for e in errors]}"

    def test_port_above_65535_rejected_by_schema(self, validator):
        """
        Port range 1–65535 is enforced by the schema regex AND by Python.
        Schema-valid must equal application-valid.
        """
        entry = {
            "id": "x", "label": "X",
            "packages": ["x"], "services": [],
            "ports": ["99999/tcp"],
            "risk": "low", "config_key": "fixed",
        }
        errors = list(validator.iter_errors(entry))
        port_errors = [e for e in errors if list(e.absolute_path)[:2] == ["ports", 0]]
        assert port_errors, "schema must reject port 99999 at /ports/0"

    def test_port_65535_accepted(self, validator):
        """Boundary: port 65535 is the highest valid port and must pass."""
        entry = {
            "id": "x", "label": "X",
            "packages": ["x"], "services": [],
            "ports": ["65535/tcp"],
            "risk": "low", "config_key": "fixed",
        }
        errors = list(validator.iter_errors(entry))
        assert not errors, [e.message for e in errors]

    def test_port_65536_rejected(self, validator):
        """Boundary: port 65536 is one past the max and must fail."""
        entry = {
            "id": "x", "label": "X",
            "packages": ["x"], "services": [],
            "ports": ["65536/tcp"],
            "risk": "low", "config_key": "fixed",
        }
        errors = list(validator.iter_errors(entry))
        assert errors, "schema must reject port 65536"

    def test_unknown_field_rejected(self, validator):
        entry = {
            "id": "x", "label": "X",
            "packages": [], "services": [], "ports": ["80/tcp"],
            "risk": "low", "config_key": "fixed",
            "extra_field": "should be rejected",
        }
        errors = list(validator.iter_errors(entry))
        assert errors

    def test_fixed_without_ports_rejected(self, validator):
        entry = {
            "id": "x", "label": "X",
            "packages": [], "services": [],
            "ports": [],  # empty + config_key=fixed → rejected
            "risk": "low", "config_key": "fixed",
        }
        errors = list(validator.iter_errors(entry))
        assert errors

    def test_id_with_spaces_rejected(self, validator):
        entry = {
            "id": "my service",  # invalid identifier (space)
            "label": "X",
            "packages": [], "services": [], "ports": ["80/tcp"],
            "risk": "low", "config_key": "fixed",
        }
        errors = list(validator.iter_errors(entry))
        id_errors = [e for e in errors if list(e.absolute_path) == ["id"]]
        assert id_errors, f"expected error on /id, got: {[list(e.absolute_path) for e in errors]}"

    def test_empty_binary_string_rejected(self, validator):
        entry = {
            "id": "x", "label": "X",
            "packages": [], "services": [], "ports": ["80/tcp"],
            "risk": "low", "config_key": "fixed",
            "detection": {"binary": [""]},  # empty string not allowed
        }
        errors = list(validator.iter_errors(entry))
        binary_errors = [
            e for e in errors
            if list(e.absolute_path)[:3] == ["detection", "binary", 0]
        ]
        assert binary_errors, (
            f"expected error on /detection/binary/0, "
            f"got: {[list(e.absolute_path) for e in errors]}"
        )


# ---------------------------------------------------------------------------
# Schema/Python validator parity
# ---------------------------------------------------------------------------

class TestSchemaPythonParity:
    """
    Ensure the JSON Schema and `Service.from_dict()` agree on what is valid.
    Both are sources of truth — they must stay aligned.
    """

    @pytest.fixture
    def validator(self, service_validator):
        # Delegate to the module-scope fixture — a single validator instance
        # is shared across all per-class needs (DRY).
        return service_validator

    def test_valid_for_schema_is_valid_for_python(self, validator):
        from bob.registry import Service

        entry = {
            "id": "valid_x",
            "label": "Valid",
            "packages": ["pkg"],
            "services": ["svc"],
            "ports": ["443/tcp"],
            "risk": "high",
            "config_key": "fixed",
        }
        # Schema says valid
        assert not list(validator.iter_errors(entry))
        # Python parser also accepts
        Service.from_dict(entry)  # raises if invalid

    def test_invalid_for_schema_rejected_by_python(self):
        from bob.registry import Service

        # Missing required field
        entry = {"id": "x", "label": "X"}
        with pytest.raises(ValueError):
            Service.from_dict(entry)


# ---------------------------------------------------------------------------
# Business constraints introduced in v0.4.0 (Phase 1 Vague 1)
# ---------------------------------------------------------------------------

class TestBusinessConstraints:
    """Schema-level checks that prevent semantically broken plugin entries."""

    @pytest.fixture
    def validator(self, service_validator):
        # Delegate to the module-scope fixture — a single validator instance
        # is shared across all per-class needs (DRY).
        return service_validator

    def test_auto_without_config_files_rejected(self, validator):
        """config_key='auto' with no config_files = nothing to parse."""
        entry = {
            "id": "x", "label": "X",
            "packages": ["x"], "services": [],
            "ports": ["80/tcp"],
            "risk": "low", "config_key": "auto",
        }
        errors = list(validator.iter_errors(entry))
        assert errors, "auto without config_files must be rejected"

    def test_auto_with_empty_config_files_rejected(self, validator):
        entry = {
            "id": "x", "label": "X",
            "packages": ["x"], "services": [],
            "ports": ["80/tcp"],
            "risk": "low", "config_key": "auto",
            "detection": {"config_files": []},
        }
        errors = list(validator.iter_errors(entry))
        assert errors, "auto with empty config_files must be rejected"

    def test_auto_with_config_files_accepted(self, validator):
        entry = {
            "id": "x", "label": "X",
            "packages": ["x"], "services": [],
            "ports": ["80/tcp"],
            "risk": "low", "config_key": "auto",
            "detection": {"config_files": ["/etc/x.conf"]},
        }
        errors = list(validator.iter_errors(entry))
        assert not errors, [e.message for e in errors]

    def test_undetectable_service_rejected(self, validator):
        """No packages, no services, no detection.binary/snap — service is invisible."""
        entry = {
            "id": "ghost", "label": "Ghost",
            "packages": [],
            "services": [],
            "ports": ["80/tcp"],
            "risk": "low", "config_key": "fixed",
        }
        errors = list(validator.iter_errors(entry))
        assert errors, "service with no detection mechanism must be rejected"

    def test_detection_via_binary_only_accepted(self, validator):
        entry = {
            "id": "snap-only", "label": "Snap Only",
            "packages": [],
            "services": [],
            "ports": ["80/tcp"],
            "risk": "low", "config_key": "fixed",
            "detection": {"binary": ["myapp"]},
        }
        errors = list(validator.iter_errors(entry))
        assert not errors, [e.message for e in errors]

    def test_detection_via_snap_only_accepted(self, validator):
        entry = {
            "id": "snap-only", "label": "Snap Only",
            "packages": [],
            "services": [],
            "ports": ["80/tcp"],
            "risk": "low", "config_key": "fixed",
            "detection": {"snap": ["myapp"]},
        }
        errors = list(validator.iter_errors(entry))
        assert not errors, [e.message for e in errors]

    def test_empty_detection_object_rejected(self, validator):
        """detection: {} adds nothing — schema rejects it via minProperties: 1."""
        entry = {
            "id": "x", "label": "X",
            "packages": ["x"], "services": [],
            "ports": ["80/tcp"],
            "risk": "low", "config_key": "fixed",
            "detection": {},
        }
        errors = list(validator.iter_errors(entry))
        assert errors, "empty detection object must be rejected"


# ---------------------------------------------------------------------------
# Plugin file wrapper schema (v0.4.0 Phase 1 Vague 1)
# ---------------------------------------------------------------------------

class TestPluginFileWrapper:
    """Plugin files accept both legacy array form and wrapped object form."""

    @pytest.fixture(scope="class")
    def plugin_file_validator(self, plugin_file_schema, services_list_schema, service_schema):
        # Cross-file $ref resolution via the shared compat helper:
        # tries the modern `referencing` Registry first (jsonschema 4.18+),
        # falls back to the legacy RefResolver path (jsonschema 4.10–4.17).
        return _make_resolved_validator(
            plugin_file_schema,
            extra_schemas={
                "plugin-file.schema.json": plugin_file_schema,
                "services-list.schema.json": services_list_schema,
                "service.schema.json": service_schema,
                services_list_schema["$id"]: services_list_schema,
                service_schema["$id"]: service_schema,
            },
        )

    @pytest.fixture
    def valid_service(self):
        return {
            "id": "myapp",
            "label": "My App",
            "packages": ["myapp"],
            "services": ["myapp"],
            "ports": ["8080/tcp"],
            "risk": "medium",
            "config_key": "fixed",
        }

    def test_legacy_array_accepted(self, plugin_file_validator, valid_service):
        errors = list(plugin_file_validator.iter_errors([valid_service]))
        assert not errors, [e.message for e in errors]

    def test_wrapped_v1_accepted(self, plugin_file_validator, valid_service):
        wrapped = {"schema_version": 1, "services": [valid_service]}
        errors = list(plugin_file_validator.iter_errors(wrapped))
        assert not errors, [e.message for e in errors]

    def test_wrapped_without_schema_version_rejected(self, plugin_file_validator, valid_service):
        wrapped = {"services": [valid_service]}
        errors = list(plugin_file_validator.iter_errors(wrapped))
        assert errors

    def test_wrapped_without_services_rejected(self, plugin_file_validator):
        wrapped = {"schema_version": 1}
        errors = list(plugin_file_validator.iter_errors(wrapped))
        assert errors

    def test_wrapped_v2_currently_rejected(self, plugin_file_validator, valid_service):
        """v2 doesn't exist yet → schema rejects it. Future v2 will lift this constraint."""
        wrapped = {"schema_version": 2, "services": [valid_service]}
        errors = list(plugin_file_validator.iter_errors(wrapped))
        assert errors

    def test_wrapped_extra_fields_rejected(self, plugin_file_validator, valid_service):
        """Reserved fields like `metadata`, `disabled` are rejected today."""
        wrapped = {"schema_version": 1, "services": [valid_service], "metadata": {"author": "x"}}
        errors = list(plugin_file_validator.iter_errors(wrapped))
        assert errors


# ---------------------------------------------------------------------------
# Python loader accepts both shapes (registry._extract_plugin_entries)
# ---------------------------------------------------------------------------

class TestRegistryAcceptsBothShapes:
    """The runtime loader must accept legacy arrays AND wrapped objects."""

    def test_extract_legacy_array(self):
        from bob.registry import _extract_plugin_entries
        raw = [{"id": "x"}]
        assert _extract_plugin_entries(raw, "plug.json") == [{"id": "x"}]

    def test_extract_wrapped_v1(self):
        from bob.registry import _extract_plugin_entries
        raw = {"schema_version": 1, "services": [{"id": "x"}]}
        assert _extract_plugin_entries(raw, "plug.json") == [{"id": "x"}]

    def test_extract_wrapped_unknown_version_rejected(self, caplog):
        from bob.registry import _extract_plugin_entries
        raw = {"schema_version": 99, "services": [{"id": "x"}]}
        result = _extract_plugin_entries(raw, "plug.json")
        assert result is None

    def test_extract_wrapped_zero_version_rejected(self):
        from bob.registry import _extract_plugin_entries
        raw = {"schema_version": 0, "services": [{"id": "x"}]}
        assert _extract_plugin_entries(raw, "plug.json") is None

    def test_extract_wrapped_missing_services_rejected(self):
        from bob.registry import _extract_plugin_entries
        raw = {"schema_version": 1}
        assert _extract_plugin_entries(raw, "plug.json") is None

    def test_extract_wrapped_non_int_version_rejected(self):
        from bob.registry import _extract_plugin_entries
        raw = {"schema_version": "1", "services": []}
        assert _extract_plugin_entries(raw, "plug.json") is None

    def test_extract_other_type_rejected(self):
        from bob.registry import _extract_plugin_entries
        assert _extract_plugin_entries("not a list", "plug.json") is None
        assert _extract_plugin_entries(42, "plug.json") is None
