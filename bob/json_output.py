"""
JSON serialization of audit results — stable public output contract.

The structure below is part of BOB's public API. Backwards-compatibility rules:

  - Top-level keys never disappear, never get renamed, never change semantics
    within a given major ``schema_version``.
  - New top-level keys MAY be added in any release; clients should ignore
    unknown keys.
  - Nested dicts follow the same rule. Nested keys may be added but never
    removed/renamed within the same major schema version.
  - Breaking changes bump ``schema_version`` to a new major (``"2"``, ``"3"``…).

One schema version is emitted by this module:

  - **v3** (current, default) — v0.12.0 release. F9 renames the integer
    count keys ``alerts`` → ``alert_count`` and ``warnings`` →
    ``warning_count`` for symmetry with the existing ``info_count``. Per the
    versioning rule above, a key rename is a breaking change, so it bumps the
    major from ``"2"`` to ``"3"`` rather than mutating ``"2"`` in place.
  - **v2** (v0.7.0) and **v1** (v0.6.x) are retired — exactly as v1 was
    retired in v0.9.0 F-3, BOB emits only the current major and keeps no
    legacy builders. A consumer pinned to ``schema_version == "2"`` must
    re-pin to ``"3"`` and rename the two count keys.

For full schema reference, see DOCUMENTS/README_TECH.md → "JSON output schema".
"""

from __future__ import annotations

from datetime import datetime, timezone

from bob.checks.firewall_stack import FirewallStackSnapshot
from bob.checks.hardening import HardeningSnapshot
from bob.checks.ipv6 import IPv6Snapshot
from bob.checks.network_context import NetworkContextSnapshot, top_remote_ips
from bob.checks.ports import PortsSnapshot
from bob.checks.services import ServiceSnapshot
from bob.report import SystemInfo
from bob.scoring import ScoreEngine

# Default schema version emitted when no explicit version is requested.
DEFAULT_SCHEMA_VERSION = "3"

# Supported schema versions — any value outside this set raises ValueError.
# v0.9.0 F-3 retired ``"1"`` (legacy v0.6.x). v0.12.0 F9 retired ``"2"``
# (v0.7.0) when the breaking count-key rename bumped the major to ``"3"``.
# Following the established clean-cut pattern, only the current major is
# emitted — the SCHEMA_V1_*/_build_v1 and now the v2 names give way to v3.
SUPPORTED_SCHEMA_VERSIONS = frozenset({"3"})

# Top-level keys ALWAYS present in v3 output, regardless of ``full``.
SCHEMA_V3_REQUIRED_KEYS = frozenset({
    "schema_version",
    "version",
    "host",
    "timestamp_utc",          # B-3 (renamed from "timestamp")
    "score",
    "score_max",
    "risk",
    "network_context",        # A-2 (always dict, never overwritten)
    "public_ip",
    "alert_count",            # F9 (v0.12.0, v2→v3): renamed from "alerts"
    "warning_count",          # F9 (v0.12.0, v2→v3): renamed from "warnings"
    "info_count",             # B-7 — symmetry with alert_count/warning_count
    "deductions",
    "domain_scores",
    "posture_escalation",     # A-4 (new — exposes Phase 1 escalation context)
    # v0.14.1: sections whose check raised and were degraded in place by the
    # ``runner._sec`` fault barrier instead of aborting the audit. Empty list
    # on a healthy run. Additive within schema v3 — a consumer that ignores
    # the key keeps working, one that reads it can tell "score 9 with every
    # section evaluated" from "score 9 with two sections never run".
    "degraded_sections",
})

# Additional top-level keys present in v3 only when ``full=True``.
SCHEMA_V3_FULL_KEYS = frozenset({
    "findings",
    "services",
    "open_ports",
    "open_ports_all",         # B-5 (new — unfiltered counterpart)
    "firewall_drivers",
    "deductions_raw",         # B-4 (new — unfiltered counterpart)
    "hardening",
    "ipv6",
})


def build_json_data(
    engine: ScoreEngine,
    sys_info: SystemInfo,
    network_context: str,
    public_ip: str,
    snapshots: list[ServiceSnapshot],
    ports_snapshot: PortsSnapshot,
    stack_snapshot: FirewallStackSnapshot,
    net_snapshot: NetworkContextSnapshot,
    full: bool,
    version: str,
    hardening_snapshot: HardeningSnapshot | None = None,
    ipv6_snapshot: IPv6Snapshot | None = None,
    schema_version: str = DEFAULT_SCHEMA_VERSION,
    profile=None,
    config=None,
    degraded_sections: "tuple[str, ...] | list[str]" = (),
) -> dict:
    """Serialize audit results to a JSON-ready dict.

    Args:
        schema_version: ``"3"`` (default, the only supported major). Any other
            value raises ``ValueError``. Non-string raises ``TypeError``.
            See module docstring for the contract.

    Raises:
        TypeError: when ``schema_version`` is not a ``str``.
        ValueError: when ``schema_version`` is a string outside
            ``SUPPORTED_SCHEMA_VERSIONS``.
    """
    if not isinstance(schema_version, str):
        raise TypeError(
            f"schema_version must be str, got {type(schema_version).__name__}. "
            f"Pass \"3\" as a string."
        )
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise ValueError(
            f"schema_version={schema_version!r} not supported. "
            f"Supported values: {sorted(SUPPORTED_SCHEMA_VERSIONS)} "
            f"(v0.9.0 retired \"1\"; v0.12.0 F9 retired \"2\")."
        )

    # Only the current major (v3) lands here; v1 (v0.9.0 F-3) and v2
    # (v0.12.0 F9) dispatches were retired with their builders.
    return _build_v3(
        engine, sys_info, network_context, public_ip, snapshots,
        ports_snapshot, stack_snapshot, net_snapshot, full, version,
        hardening_snapshot, ipv6_snapshot, profile=profile, config=config,
        degraded_sections=degraded_sections,
    )


# v0.9.0 F-3: ``_build_v1`` deleted with the ``--json-v1`` retrait. v0.12.0 F9:
# the v2 builder became v3 in place (count-key rename). Only one builder remains.


# ---------------------------------------------------------------------------
# v3 — current schema (v0.12.0; count keys renamed from v2)
# ---------------------------------------------------------------------------

def _build_v3(
    engine: ScoreEngine,
    sys_info: SystemInfo,
    network_context: str,
    public_ip: str,
    snapshots: list[ServiceSnapshot],
    ports_snapshot: PortsSnapshot,
    stack_snapshot: FirewallStackSnapshot,
    net_snapshot: NetworkContextSnapshot,
    full: bool,
    version: str,
    hardening_snapshot: HardeningSnapshot | None,
    ipv6_snapshot: IPv6Snapshot | None,
    profile=None,
    config=None,
    degraded_sections: "tuple[str, ...] | list[str]" = (),
) -> dict:
    """v2 producer — v0.7.0 schema.

    Differences from v1 (driven by tests/test_json_schema_v2.py):

      - ``schema_version`` = "2"
      - ``timestamp`` → ``timestamp_utc`` (B-3 — name signals UTC encoding)
      - ``info_count`` added at top level (B-7)
      - ``network_context`` is ALWAYS a dict with a canonical ``context``
        field; in full mode, also carries ``interfaces`` / ``connections_count``
        / ``top_remote_ips`` (A-2 — fixes v1's type inconsistency P1)
      - ``posture_escalation`` block exposes:
          * ``applied``      bool
          * ``reason_key``   str|null (i18n key when applied)
          * ``score_level``  str — the un-escalated baseline
        Together with top-level ``risk`` (= effective_level), consumers can
        tell if and why a host's displayed risk was raised by posture (A-4).
      - In full mode, additional unfiltered counterparts:
          * ``deductions_raw``  — all breakdown entries, including 0-point caps (B-4)
          * ``open_ports_all``  — all listening ports including localhost-bound (B-5)
      - ``domain_scores[d]`` now includes ``deductions`` (int count) in
        addition to score+label (B-6).
    """
    # I-2 (v0.7.0 Phase 2.1): defensive unpack via
    # bob.scoring.unpack_posture_escalation. Real ScoreEngine always returns
    # a (RiskLevel|None, str) tuple but the helper guards against test mocks
    # returning a non-iterable (same hazard as the Phase 1 hotfix 4ed2e3b).
    from bob.scoring import unpack_posture_escalation
    _posture_floor, _posture_key = unpack_posture_escalation(engine)
    posture_block = {
        "applied":     _posture_floor is not None,
        "reason_key":  _posture_key if _posture_floor is not None else None,
        "score_level": engine.level.value,
    }

    nc_block: dict = {"context": network_context}

    data: dict = {
        "schema_version":  "3",
        "version":         version,
        "host":            sys_info.hostname,
        "timestamp_utc":   datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "score":           engine.score,
        "score_max":       10,
        "risk":            engine.effective_level.value,
        "network_context": nc_block,
        "public_ip":       public_ip,
        "alert_count":     engine.alert_count,
        "warning_count":   engine.warn_count,
        "info_count":      engine.info_count,
        "degraded_sections": list(degraded_sections),
        "deductions": [
            {
                "reason":        d.reason,
                "points":        d.points,
                "key":           d.key,
                "template_vars": d.template_vars,
            }
            for d in engine.breakdown if d.points > 0
        ],
        "posture_escalation": posture_block,
    }

    if full:
        _populate_v2_full_blocks(
            data, engine, snapshots, ports_snapshot, stack_snapshot,
            net_snapshot, hardening_snapshot, ipv6_snapshot,
        )
        # A-2 fix: enrich the network_context dict (don't overwrite it).
        nc_block["interfaces"] = [
            {
                "name":    iface.name,
                "type":    iface.if_type,
                "up":      iface.is_up,
                "address": iface.address,
            }
            for iface in net_snapshot.interfaces
        ]
        nc_block["connections_count"] = len(net_snapshot.connections)
        nc_block["top_remote_ips"] = [
            {"ip": ip, "count": n}
            for ip, n in top_remote_ips(net_snapshot.connections, n=5)
        ]

    # Domain sub-scores (always included, includes deductions count in v2)
    # M-7 (v0.7.4): use cache when available — see _build_v1 for rationale.
    from bob.domain_scores import (
        compute_domain_scores, DOMAINS, active_domains_from_engine,
        domain_inactive_reason,
    )
    _ds = engine.domain_scores or compute_domain_scores(engine)[0]
    # v0.12.1 (ADV-1): expose per-domain ``active`` + ``reason`` so a machine
    # consumer can (a) reproduce the headline score — which averages only the
    # active domains then applies the F1 cap — and (b) tell an absent component
    # (score 10, active=false) from a genuine 10/10. Mirrors the text display.
    # Additive within schema v3 — existing keys are unchanged.
    _active = engine.active_domains or active_domains_from_engine(engine)
    data["domain_scores"] = {
        domain: {
            "score":      _ds[domain]["score"],
            "label":      _ds[domain]["label"],
            "deductions": _ds[domain]["deductions"],   # B-6
            "active":     domain in _active,
            "reason":     (None if domain in _active
                           else domain_inactive_reason(domain, engine, profile, config)),
        }
        for domain in DOMAINS
    }

    return data


def _populate_v2_full_blocks(
    data: dict,
    engine: ScoreEngine,
    snapshots: list[ServiceSnapshot],
    ports_snapshot: PortsSnapshot,
    stack_snapshot: FirewallStackSnapshot,
    net_snapshot: NetworkContextSnapshot,
    hardening_snapshot: HardeningSnapshot | None,
    ipv6_snapshot: IPv6Snapshot | None,
) -> None:
    data["findings"] = [
        {
            "key":           f.key,
            "level":         f.level.value,
            "message":       f.message,
            "nature":        f.nature,
            # T11 (v0.8.1): ``detail`` was already in CSV/MD/HTML/text but the
            # JSON sinks dropped it silently. Additive field — consumers
            # parsing JSON by field-name (the canonical access pattern) are
            # unaffected; new field appears for every finding emitting a
            # ``Finding.detail`` (most action/improvement findings do).
            "detail":        f.detail,
            "cmd":           f.cmd,
            "note":          f.note,
            "template_vars": f.template_vars,
        }
        for f in engine.findings
    ]
    data["services"] = [
        {
            "name":      snap.service.label,
            "installed": snap.installed,
            "active":    snap.state.is_active,
            "risk":      snap.risk,
            "ports": {
                port: {"exposure": exp.value}
                for port, exp in snap.exposures.items()
            },
        }
        for snap in snapshots if snap.installed
    ]
    data["open_ports"] = [
        {
            "port":    lp.port_proto,
            "address": lp.address,
            "process": lp.process,
        }
        for lp in ports_snapshot.ports if lp.is_all_interfaces
    ]
    # B-5 — unfiltered counterpart of open_ports
    data["open_ports_all"] = [
        {
            "port":    lp.port_proto,
            "address": lp.address,
            "process": lp.process,
        }
        for lp in ports_snapshot.ports
    ]
    # B-4 — unfiltered counterpart of deductions
    data["deductions_raw"] = [
        {
            "reason":        d.reason,
            "points":        d.points,
            "key":           d.key,
            "template_vars": d.template_vars,
        }
        for d in engine.breakdown
    ]
    data["firewall_drivers"] = {
        "input_bypasses":    stack_snapshot.input_raw_accepts,
        "forward_bypasses":  stack_snapshot.forward_raw_accepts,
        "nftables_active":   stack_snapshot.nftables_active,
        "ip_forward":        stack_snapshot.ip_forward,
        "docker_present":    stack_snapshot.docker_present,
        "wireguard_present": stack_snapshot.wireguard_present,
        "libvirt_present":   stack_snapshot.libvirt_present,
    }
    if hardening_snapshot is not None:
        data["hardening"] = {
            "rp_filter":                   hardening_snapshot.rp_filter,
            "accept_redirects":            hardening_snapshot.accept_redirects,
            "log_martians":                hardening_snapshot.log_martians,
            "icmp_echo_ignore_broadcasts": hardening_snapshot.icmp_echo_ignore_broadcasts,
            "tcp_syncookies":              hardening_snapshot.tcp_syncookies,
            "accept_source_route":         hardening_snapshot.accept_source_route,
            "accept_redirects_v6":         hardening_snapshot.accept_redirects_v6,
            "send_redirects":              hardening_snapshot.send_redirects,
            "protected_hardlinks":         hardening_snapshot.protected_hardlinks,
            "protected_symlinks":          hardening_snapshot.protected_symlinks,
        }
    if ipv6_snapshot is not None:
        data["ipv6"] = {
            "kernel_ipv6_enabled": ipv6_snapshot.kernel_ipv6_enabled,
            "ufw_ipv6_enabled":    ipv6_snapshot.ufw_ipv6_enabled,
            "ipv6_listeners":      ipv6_snapshot.ipv6_listeners,
            "ufw_v6_covered":      ipv6_snapshot.ufw_v6_covered,
        }

# M-4 (v0.7.0 Phase 2.1): the legacy ``_SCHEMA_VERSION = DEFAULT_SCHEMA_VERSION``
# alias was removed. Grep across bob/ and tests/ confirmed zero consumers.
# External clients that need the constant should import
# ``DEFAULT_SCHEMA_VERSION`` (the explicit name) directly.
