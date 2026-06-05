"""
T11 + T26 (v0.8.1) regression pins.

T11 — `Finding.detail` format parity across CSV + JSON v1 + JSON v2.
v0.8.0 T9 added detail to Markdown + HTML; v0.8.1 closes the gap for the
machine-readable sinks (CSV column + JSON field on every finding entry).

T26 — `bob --explain services.exposed.<svc_id>` dynamic dispatch.
v0.8.0 T2 added 6 modern services (32 → 38) but none of the 38 service IDs
had ``--explain`` coverage. v0.8.1 routes the lookup to the existing
``service_risk.<label_transform>.{level,exposure,threat}`` content (added
by v0.8.0 T4) via a fallback dispatch inside ``run_explain``, so any
service registered in ``bob/data/services.json`` becomes
``--explain``-able with zero per-service maintenance.
"""

from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Fixtures: a minimal ScoreEngine + SysInfo for format-output tests
# ---------------------------------------------------------------------------

@pytest.fixture
def engine_with_detail():
    """Engine carrying a finding with non-empty .detail (the v0.8.1 invariant)."""
    from bob.scoring import ScoreEngine, Finding, FindingLevel
    e = ScoreEngine()
    e.findings.append(Finding(
        level=FindingLevel.WARN,
        message="SUID dumps not restricted",
        detail="Restricting SUID dumps to root limits exposure; disabling them entirely is safer.",
        nature="improvement",
        cmd="sudo sysctl -w fs.suid_dumpable=0",
        note="",
        key="kernel_hardening.suid_dump_all",
        template_vars={},
    ))
    e.finalize()
    return e


@pytest.fixture
def sys_info_stub():
    info = MagicMock()
    info.hostname = "testhost"
    return info


@pytest.fixture
def json_kwargs(sys_info_stub):
    """Common keyword args for ``build_json_data`` — empty snapshots are
    sufficient since these tests only assert on the ``findings`` block."""
    from bob.checks.ports import PortsSnapshot
    from bob.checks.firewall_stack import FirewallStackSnapshot
    from bob.checks.network_context import NetworkContextSnapshot
    return {
        "network_context": "local",
        "public_ip": "",
        "snapshots": [],
        "ports_snapshot": PortsSnapshot.from_system(),
        "stack_snapshot": FirewallStackSnapshot.from_system(),
        "net_snapshot": NetworkContextSnapshot.from_system(),
        "full": True,
        "version": "0.8.1",
    }


# ===========================================================================
# T11 — CSV: ``detail`` column present + populated
# ===========================================================================

class TestT11CsvDetail:

    def test_csv_header_contains_detail_column(self, engine_with_detail, sys_info_stub):
        from bob.csv_output import build_csv_output
        out = build_csv_output(engine_with_detail, sys_info_stub)
        reader = csv.reader(io.StringIO(out))
        header = next(reader)
        assert "detail" in header, f"CSV header missing 'detail': {header}"

    def test_csv_detail_column_carries_finding_detail(self, engine_with_detail, sys_info_stub):
        from bob.csv_output import build_csv_output
        out = build_csv_output(engine_with_detail, sys_info_stub)
        reader = csv.DictReader(io.StringIO(out))
        rows = list(reader)
        assert len(rows) == 1
        assert "Restricting SUID dumps" in rows[0]["detail"]

    def test_csv_detail_column_position_between_message_and_fix_cmd(self):
        """The column ordering is documented in the inline comment — pin it
        so future header reorders don't break column-by-index consumers without
        the test surfacing it."""
        from bob.csv_output import _HEADERS
        msg_idx = _HEADERS.index("message")
        det_idx = _HEADERS.index("detail")
        fix_idx = _HEADERS.index("fix_cmd")
        assert msg_idx < det_idx < fix_idx, \
            f"detail must sit between message and fix_cmd: {_HEADERS}"


# ===========================================================================
# T11 — JSON v1: ``detail`` field present on every finding entry
# ===========================================================================

class TestT11JsonV1Detail:

    def test_json_v1_findings_carry_detail(self, engine_with_detail, sys_info_stub, json_kwargs):
        from bob.json_output import build_json_data
        data = build_json_data(
            engine_with_detail, sys_info_stub,
            schema_version="1", **json_kwargs,
        )
        assert "findings" in data
        assert len(data["findings"]) == 1
        f = data["findings"][0]
        assert "detail" in f, f"JSON v1 finding missing 'detail' field: {list(f.keys())}"
        assert "Restricting SUID dumps" in f["detail"]


# ===========================================================================
# T11 — JSON v2: ``detail`` field present on every finding entry
# ===========================================================================

class TestT11JsonV2Detail:

    def test_json_v2_findings_carry_detail(self, engine_with_detail, sys_info_stub, json_kwargs):
        from bob.json_output import build_json_data
        data = build_json_data(
            engine_with_detail, sys_info_stub,
            schema_version="2", **json_kwargs,
        )
        assert "findings" in data
        f = data["findings"][0]
        assert "detail" in f
        assert "Restricting SUID dumps" in f["detail"]


# ===========================================================================
# T11 — Cross-format parity: every textual sink agrees on the detail content
# ===========================================================================

class TestT11CrossFormatDetailParity:
    """All 4 machine-readable sinks (CSV + JSON v1 + JSON v2 + the existing
    Markdown / HTML closed in v0.8.0 T9) must surface the exact same
    ``Finding.detail`` string. A drift between any two means a sink dropped
    the field again."""

    def test_csv_and_json_v1_agree_on_detail(self, engine_with_detail, sys_info_stub, json_kwargs):
        from bob.csv_output import build_csv_output
        from bob.json_output import build_json_data
        csv_out = build_csv_output(engine_with_detail, sys_info_stub)
        csv_row = next(csv.DictReader(io.StringIO(csv_out)))
        v1 = build_json_data(engine_with_detail, sys_info_stub,
                             schema_version="1", **json_kwargs)
        assert csv_row["detail"] == v1["findings"][0]["detail"]

    def test_json_v1_and_v2_agree_on_detail(self, engine_with_detail, sys_info_stub, json_kwargs):
        from bob.json_output import build_json_data
        v1 = build_json_data(engine_with_detail, sys_info_stub,
                             schema_version="1", **json_kwargs)
        v2 = build_json_data(engine_with_detail, sys_info_stub,
                             schema_version="2", **json_kwargs)
        assert v1["findings"][0]["detail"] == v2["findings"][0]["detail"]


# ===========================================================================
# T26 — services.exposed.<svc_id> dispatch
# ===========================================================================

class TestT26ServicesExposedDispatch:
    """The dispatch routes ``bob --explain services.exposed.<id>`` to the
    ``service_risk.<label_transform>.{level,exposure,threat}`` content for
    every service registered in ``bob/data/services.json``."""

    @pytest.fixture(autouse=True)
    def _init_i18n(self):
        from bob import i18n
        i18n.init(lang="en")
        yield
        i18n.init(lang="en")

    def _capture(self, key: str) -> str:
        from bob import i18n
        from bob.explain import run_explain
        buf = io.StringIO()
        old, sys.stdout = sys.stdout, buf
        try:
            run_explain(key, i18n.t)
        finally:
            sys.stdout = old
        return buf.getvalue()

    def test_dispatch_renders_ssh(self):
        out = self._capture("services.exposed.ssh")
        assert "No explanation available" not in out
        assert "SSH Server" in out
        assert "CRITICAL" in out
        assert "EXPOSURE" in out
        assert "POTENTIAL THREAT" in out

    def test_dispatch_renders_samba(self):
        out = self._capture("services.exposed.samba")
        assert "Samba" in out
        # samba label transform → samba_windows_file_sharing
        assert "ransomware" in out.lower() or "EternalBlue" in out

    def test_dispatch_renders_t2_added_services(self):
        """The 6 services added by v0.8.0 T2 (Tailscale, Caddy, AdGuard Home,
        Vaultwarden, Ollama, Authelia) must each resolve via the dispatch."""
        for svc_id in ("tailscale", "caddy", "adguard_home", "vaultwarden", "ollama", "authelia"):
            out = self._capture(f"services.exposed.{svc_id}")
            assert "No explanation available" not in out, \
                f"services.exposed.{svc_id} fell through to unknown-key path"

    def test_dispatch_returns_unknown_for_nonexistent_service(self):
        """A typo / non-registered service ID must still fall through to the
        regular unknown-key path (no silent 'rendered nothing' bug)."""
        out = self._capture("services.exposed.totally_not_a_service_xyz")
        assert "No explanation available" in out

    def test_dispatch_renders_french(self):
        from bob import i18n
        i18n.init(lang="fr")
        out = self._capture("services.exposed.ssh")
        assert "CRITIQUE" in out
        assert "EXPOSITION" in out
        assert "MENACE POTENTIELLE" in out


class TestT26LabelTransformIsCanonical:
    """The label → subkey transform used by the dispatch MUST match the
    transform used by ``display.py::display_risk_context`` or
    ``--explain services.exposed.<id>`` will resolve to a different locale
    entry than the audit's "Service network analysis" section."""

    def test_helper_matches_display_transform(self):
        from bob.explain import _service_label_to_subkey
        # Pinned examples (must match display.py:152-154)
        cases = [
            ("SSH Server", "ssh_server"),
            ("VNC Server", "vnc_server"),
            ("Samba (Windows file sharing)", "samba_windows_file_sharing"),
            ("MySQL / MariaDB", "mysql___mariadb"),
            ("AdGuard Home (DNS sinkhole)", "adguard_home_dns_sinkhole"),
            ("Vaultwarden Password Manager", "vaultwarden_password_manager"),
        ]
        for label, expected in cases:
            assert _service_label_to_subkey(label) == expected


class TestT26EveryRegisteredServiceResolves:
    """Cross-cutting invariant: every service in services.json must have a
    matching ``service_risk.<label_transform>.level`` locale entry in EN + FR.
    This is the precondition for T26 dispatch to work — a regression here
    means a service was added without the locale block."""

    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_every_service_has_risk_block(self, lang):
        from bob.registry import ServiceRegistry
        from bob.explain import _service_label_to_subkey
        repo_root = Path(__file__).resolve().parent.parent
        locale = json.loads((repo_root / "bob" / "locales" / f"{lang}.json").read_text(encoding="utf-8"))
        risk_block = locale.get("service_risk", {})

        registry = ServiceRegistry.load()
        for svc in registry.all():
            subkey = _service_label_to_subkey(svc.label)
            entry = risk_block.get(subkey)
            assert isinstance(entry, dict), \
                f"{lang}: service {svc.id!r} (label {svc.label!r}) → subkey {subkey!r} missing service_risk block"
            for field in ("level", "exposure", "threat"):
                assert field in entry, \
                    f"{lang}: service_risk.{subkey} missing '{field}' field"
