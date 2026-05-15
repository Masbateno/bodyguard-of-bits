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

_SCHEMA_VERSION = "1"

# Top-level keys ALWAYS present in the output, regardless of `full=`.
# Tests assert this set as a hard invariant (no removal, no rename within v1).
SCHEMA_V1_REQUIRED_KEYS = frozenset({
    "schema_version",
    "version",
    "host",
    "timestamp",
    "score",
    "score_max",
    "risk",
    "network_context",
    "public_ip",
    "alerts",
    "warnings",
    "deductions",
    "domain_scores",
})

# Additional top-level keys present only when `full=True` (--json-full).
SCHEMA_V1_FULL_KEYS = frozenset({
    "findings",
    "services",
    "open_ports",
    "firewall_stack",
    "hardening",        # only when hardening_snapshot provided
    "ipv6",             # only when ipv6_snapshot provided
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
) -> dict:
    """Serialize audit results to a JSON-ready dict."""
    data: dict = {
        "schema_version":  _SCHEMA_VERSION,
        "version":         version,
        "host":            sys_info.hostname,
        "timestamp":       datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "score":           engine.score,
        "score_max":       10,
        "risk":            engine.level.value,
        "network_context": network_context,
        "public_ip":       public_ip,
        "alerts":          engine.alert_count,
        "warnings":        engine.warn_count,
        "deductions": [
            {
                "reason":        d.reason,
                "points":        d.points,
                "key":           d.key,
                "template_vars": d.template_vars,
            }
            for d in engine.breakdown if d.points > 0
        ],
    }
    if full:
        data["findings"] = [
            {
                "key":           f.key,
                "level":         f.level.value,
                "message":       f.message,
                "nature":        f.nature,
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
        data["firewall_stack"] = {
            "input_bypasses":    stack_snapshot.input_raw_accepts,
            "forward_bypasses":  stack_snapshot.forward_raw_accepts,
            "nftables_active":   stack_snapshot.nftables_active,
            "ip_forward":        stack_snapshot.ip_forward,
            "docker_present":    stack_snapshot.docker_present,
            "wireguard_present": stack_snapshot.wireguard_present,
            "libvirt_present":   stack_snapshot.libvirt_present,
        }
        data["network_context"] = {
            "interfaces": [
                {
                    "name":    iface.name,
                    "type":    iface.if_type,
                    "up":      iface.is_up,
                    "address": iface.address,
                }
                for iface in net_snapshot.interfaces
            ],
            "connections_count": len(net_snapshot.connections),
            "top_remote_ips": [
                {"ip": ip, "count": n}
                for ip, n in top_remote_ips(net_snapshot.connections, n=5)
            ],
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

    # Domain sub-scores (always included)
    from bob.domain_scores import compute_domain_scores, DOMAINS
    _ds, _ = compute_domain_scores(engine)
    data["domain_scores"] = {
        domain: {"score": _ds[domain]["score"], "label": _ds[domain]["label"]}
        for domain in DOMAINS
    }

    return data
