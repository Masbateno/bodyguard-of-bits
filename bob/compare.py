"""
Comparative audit report for BOB.

Saves a compact JSON baseline after each audit and, on the next run,
computes and displays what changed since the last audit.

Baseline file: ~/.config/bob/last_baseline.json

Usage:
    from bob.compare import (
        build_baseline, save_baseline, load_baseline,
        compute_delta, display_delta,
    )

    prev  = load_baseline()
    # ... run audit ...
    curr  = build_baseline(engine, ports_snapshot, snapshots)
    if prev:
        display_delta(compute_delta(prev, curr), t, output_mod)
    save_baseline(curr)
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from bob._atomic import atomic_write, read_text_capped
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # avoid circular imports at runtime
    from bob.checks.ports import PortsSnapshot
    from bob.checks.services import ServiceSnapshot
    from bob.scoring import ScoreEngine

from bob.sysinfo import chown_to_sudo_user, get_user_home

logger = logging.getLogger(__name__)

_CONFIG_DIR    = get_user_home() / ".config" / "bob"
_BASELINE_FILENAME = "last_baseline.json"
_BASELINE_PATH = _CONFIG_DIR / _BASELINE_FILENAME

# Public alias — external code should reference this instead of the underscore
# version. Kept side-by-side so existing callers (bob.__main__) keep working
# during the migration. The underscore form may be removed in a future major.
BASELINE_PATH = _BASELINE_PATH


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class AuditBaseline:
    """
    Compact snapshot of one audit run, persisted between invocations.

    Args:
        timestamp:       ISO-8601 UTC string of when the audit ran.
        score:           Final score (0–10).
        alert_count:     Number of ALERT findings.
        warn_count:      Number of WARN findings.
        info_count:      Number of INFO findings.
        open_ports:      Sorted list of 'port/proto' strings listening on all
                         interfaces (0.0.0.0 or ::) at audit time.
        active_services: Sorted list of service labels that were active.
    """
    timestamp:       str
    score:           int
    alert_count:     int
    warn_count:      int
    info_count:      int = 0
    open_ports:      list[str]       = field(default_factory=list)
    active_services: list[str]       = field(default_factory=list)
    finding_keys:    list[str] | None = None  # None = pre-v1.22 baseline (key absent)
    deduction_total: int | None = None        # None = pre-v0.2.3 baseline (field absent)
    hostname:        str | None = None        # v0.9.0 F-2 — None = pre-v0.9.0 baseline


@dataclass
class AuditDelta:
    """
    Differences between two consecutive audit baselines.

    Positive score_delta means improvement (score went up).
    Positive alert_delta / warn_delta / info_delta means more findings (regression).
    """
    prev_timestamp:   str
    score_delta:      int         # current - previous
    alert_delta:      int         # current - previous
    warn_delta:       int         # current - previous
    info_delta:       int         # current - previous
    new_ports:        list[str]   # appeared since last audit
    closed_ports:     list[str]   # gone since last audit
    new_services:     list[str]   # became active
    stopped_services: list[str]   # became inactive
    new_finding_keys:      list[str] = field(default_factory=list)  # ALERT/WARN keys new since last audit
    resolved_finding_keys: list[str] = field(default_factory=list)  # ALERT/WARN keys resolved
    deduction_delta:       int = 0                                   # change in total raw deduction points

    def is_empty(self) -> bool:
        """Return True when no changes were detected since the previous audit."""
        return (
            self.score_delta == 0
            and self.alert_delta == 0
            and self.warn_delta == 0
            and self.info_delta == 0
            and not self.new_ports
            and not self.closed_ports
            and not self.new_services
            and not self.stopped_services
            and not self.new_finding_keys
            and not self.resolved_finding_keys
        )


# ---------------------------------------------------------------------------
# Build / save / load
# ---------------------------------------------------------------------------

def build_baseline(
    engine: "ScoreEngine",
    ports_snapshot: "PortsSnapshot",
    snapshots: "list[ServiceSnapshot]",
) -> AuditBaseline:
    """
    Build an AuditBaseline from the current audit results.

    Args:
        engine:         Finalized ScoreEngine.
        ports_snapshot: PortsSnapshot with all listening ports.
        snapshots:      List of ServiceSnapshot objects (all registered services).

    Returns:
        AuditBaseline ready for serialization.
    """
    # Exclude ephemeral ports (>= 32768) — they change between audits and
    # produce noise in the comparative report (AVAHI, libvirt, VPN, etc.)
    open_ports = sorted({
        lp.port_proto
        for lp in ports_snapshot.ports
        if lp.is_all_interfaces and _is_stable_port(lp.port_proto)
    })

    active_services = sorted({
        snap.service.label
        for snap in snapshots
        if snap.installed and snap.state and snap.state.is_active
    })

    from bob.scoring import FindingLevel
    finding_keys = sorted({
        f.key
        for f in engine.findings
        if f.key and f.level in (FindingLevel.ALERT, FindingLevel.WARN)
    })
    deduction_total = sum(d.points for d in engine.breakdown)

    # v0.9.0 F-2: capture hostname so cross-machine ``--diff PATH`` can
    # surface a friendly ``baseline from <host>`` line. ``socket.gethostname``
    # never raises and is consistent with what the report headers use.
    import socket
    try:
        _host = socket.gethostname()
    except OSError:
        _host = ""

    return AuditBaseline(
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        score=engine.score,
        alert_count=engine.alert_count,
        warn_count=engine.warn_count,
        info_count=engine.info_count,
        open_ports=open_ports,
        active_services=active_services,
        finding_keys=finding_keys,
        deduction_total=deduction_total,
        hostname=_host or None,
    )


def save_baseline(baseline: AuditBaseline, path: Path | None = None) -> None:
    """
    Persist the baseline to disk using an atomic write.

    Silently swallows OS errors — baseline persistence is best-effort.
    """
    dest = path or (_CONFIG_DIR / _BASELINE_FILENAME)
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        chown_to_sudo_user(dest.parent)
        atomic_write(
            dest,
            json.dumps(asdict(baseline), ensure_ascii=False, indent=2),
            mode=0o600,
        )
        chown_to_sudo_user(dest)
    except OSError as exc:
        logger.debug("save_baseline: could not write %s: %s", dest, exc)


class BaselineLoadError(ValueError):
    """v0.9.0 F-2 — raised when an explicit baseline path cannot be loaded.

    Distinguishes "explicit ``--diff PATH`` failed" (loud, user typed a path
    so they expect a result) from "default baseline missing" (silent — the
    auto-managed file may simply not exist yet on a first run).
    """


def load_baseline(path: Path | None = None, *, strict: bool = False) -> AuditBaseline | None:
    """
    Load a baseline from disk.

    Args:
        path: explicit baseline file path. ``None`` (default) loads the
            auto-managed ``~/.config/bob/last_baseline.json`` — the
            behaviour established in v0.3.0 and used by the bare ``--diff``
            flag in v0.8.x.
        strict: when True, errors (missing file, invalid JSON, schema
            mismatch) raise ``BaselineLoadError`` instead of returning None.
            v0.9.0 F-2 wires this to True when the caller passed an
            explicit ``--diff PATH`` so the user gets actionable feedback
            instead of silent ``"No previous baseline yet"`` messaging.

    Returns:
        AuditBaseline if the file exists and is valid, None otherwise
        (when ``strict=False``).

    Raises:
        BaselineLoadError: when ``strict=True`` and the file cannot be
            loaded or carries the v0.6.x ``schema_version="1"`` (retired
            in v0.9.0 F-3).
    """
    # v0.9.2: i18n the BaselineLoadError messages. The raise sites run
    # AFTER ``i18n.init()`` (load_baseline lives in the audit path, not
    # parse_args), so ``t_or_hardcoded`` resolves to the locale-rendered
    # message when i18n is initialised and falls back to the English
    # baseline otherwise. Same pattern as ``bob._i18n_safe`` (v0.8.2).
    from bob._i18n_safe import t_or_hardcoded

    src = path or (_CONFIG_DIR / _BASELINE_FILENAME)
    try:
        raw = json.loads(read_text_capped(src))
    except FileNotFoundError as exc:
        if strict:
            msg = t_or_hardcoded(
                "compare.baseline_load.not_found",
                f"Baseline file not found: {src} — check the path and "
                f"that the file exists on this machine.",
            ).format(path=src)
            raise BaselineLoadError(msg) from exc
        logger.debug("load_baseline: %s does not exist", src)
        return None
    except (OSError, ValueError) as exc:
        if strict:
            msg = t_or_hardcoded(
                "compare.baseline_load.invalid_json",
                f"Baseline file {src} could not be read or parsed as "
                f"JSON: {exc}",
            ).format(path=src, error=exc)
            raise BaselineLoadError(msg) from exc
        logger.debug("load_baseline: could not read %s: %s", src, exc)
        return None

    # v0.9.0 F-2: reject the legacy v0.6.x schema explicitly. Pre-v0.9.0
    # baselines emitted by `--json-v1` (retired in v0.9.0 F-3) carried
    # ``schema_version="1"``; the v2 layout has no such field. We check
    # for the marker only when present to avoid false positives.
    schema_version = raw.get("schema_version") if isinstance(raw, dict) else None
    if schema_version == "1":
        msg = t_or_hardcoded(
            "compare.baseline_load.v1_schema",
            f"Baseline file {src} carries the legacy v0.6.x schema "
            f"(schema_version=\"1\") which was retired in v0.9.0 F-3. "
            f"Re-generate the baseline on a v0.9.0+ host.",
        ).format(path=src)
        if strict:
            raise BaselineLoadError(msg)
        logger.warning("load_baseline: %s", msg)
        return None

    try:
        # v0.9.2: cross-version baseline migration shim. When a baseline
        # written by v0.7.x / v0.8.x carries finding keys with prefixes
        # renamed in v0.9.0 D-1 (e.g. ``iptables_nft.input_accept``), the
        # diff against a v0.9.0+ audit (emitting the canonical
        # ``firewall_iptables.input_accept``) would surface the SAME
        # physical issue as both resolved (old key) AND new (new key)
        # — see the v0.9.1 CHANGELOG entry for the field-test repro on
        # Ubuntu 26.04. The shim remaps each legacy prefix to its
        # canonical form at load time so the comparison is clean. Keys
        # already using canonical names (or keys with no rename
        # mapping) pass through unchanged.
        from bob._v090_renames import remap_finding_key
        raw_keys = raw.get("finding_keys")
        if isinstance(raw_keys, list):
            finding_keys = [remap_finding_key(str(k)) for k in raw_keys]
        else:
            finding_keys = None

        return AuditBaseline(
            timestamp=str(raw.get("timestamp", "")),
            score=int(raw.get("score", 0)),
            alert_count=int(raw.get("alert_count", 0)),
            warn_count=int(raw.get("warn_count", 0)),
            info_count=int(raw.get("info_count", 0)),
            open_ports=list(raw.get("open_ports", [])),
            active_services=list(raw.get("active_services", [])),
            finding_keys=finding_keys,
            deduction_total=int(raw["deduction_total"]) if isinstance(raw.get("deduction_total"), int) else None,
            hostname=(str(raw["hostname"]) if isinstance(raw.get("hostname"), str) and raw["hostname"] else None),
        )
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        if strict:
            msg = t_or_hardcoded(
                "compare.baseline_load.bad_shape",
                f"Baseline file {src} has unexpected shape: {exc}",
            ).format(path=src, error=exc)
            raise BaselineLoadError(msg) from exc
        logger.debug("load_baseline: could not unpack %s: %s", src, exc)
        return None


# ---------------------------------------------------------------------------
# Delta computation
# ---------------------------------------------------------------------------

def compute_delta(prev: AuditBaseline, curr: AuditBaseline) -> AuditDelta:
    """
    Compute the differences between two baselines.

    Args:
        prev: Baseline from the previous audit run.
        curr: Baseline from the current audit run.

    Returns:
        AuditDelta describing what changed.
    """
    prev_ports = set(prev.open_ports)
    curr_ports = set(curr.open_ports)

    prev_svcs = set(prev.active_services)
    curr_svcs = set(curr.active_services)

    # Only diff finding keys when the previous baseline is v1.22+ (finding_keys is not None).
    # None means an older baseline that never stored the key — skip to avoid false "new" noise.
    # An empty list [] is a legitimately clean audit and must be diffed normally.
    if prev.finding_keys is not None:
        prev_keys = set(prev.finding_keys)
        curr_keys = set(curr.finding_keys or [])
        new_finding_keys      = sorted(curr_keys - prev_keys)
        resolved_finding_keys = sorted(prev_keys - curr_keys)
    else:
        new_finding_keys      = []
        resolved_finding_keys = []

    return AuditDelta(
        prev_timestamp=prev.timestamp,
        score_delta=curr.score - prev.score,
        alert_delta=curr.alert_count - prev.alert_count,
        warn_delta=curr.warn_count - prev.warn_count,
        info_delta=curr.info_count - prev.info_count,
        new_ports=sorted(curr_ports - prev_ports),
        closed_ports=sorted(prev_ports - curr_ports),
        new_services=sorted(curr_svcs - prev_svcs),
        stopped_services=sorted(prev_svcs - curr_svcs),
        new_finding_keys=new_finding_keys,
        resolved_finding_keys=resolved_finding_keys,
        deduction_delta=(
            curr.deduction_total - prev.deduction_total
            if prev.deduction_total is not None and curr.deduction_total is not None
            else 0
        ),
    )


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def display_delta(delta: AuditDelta, t, output_mod) -> None:
    """
    Print a human-readable summary of changes since the last audit.

    Args:
        delta:      AuditDelta from compute_delta().
        t:          Translation function.
        output_mod: The bob.output module (passed to avoid circular import).
    """
    output_mod.print_section(t("compare.section_title"))

    # --- Previous audit timestamp ---
    output_mod.print_dim(t("compare.previous_run", timestamp=delta.prev_timestamp))

    # --- Score ---
    if delta.score_delta > 0:
        output_mod.print_ok(t("compare.score_improved",
                               delta=delta.score_delta))
    elif delta.score_delta < 0:
        output_mod.print_warn(t("compare.score_degraded",
                                 delta=abs(delta.score_delta)))
    else:
        output_mod.print_info(t("compare.score_unchanged"))

    # --- Alerts ---
    if delta.alert_delta > 0:
        output_mod.print_warn(t("compare.alerts_increased", delta=delta.alert_delta))
    elif delta.alert_delta < 0:
        output_mod.print_ok(t("compare.alerts_decreased", delta=abs(delta.alert_delta)))

    # --- Warnings ---
    if delta.warn_delta > 0:
        output_mod.print_warn(t("compare.warns_increased", delta=delta.warn_delta))
    elif delta.warn_delta < 0:
        output_mod.print_ok(t("compare.warns_decreased", delta=abs(delta.warn_delta)))

    # --- Info findings ---
    if delta.info_delta < 0:
        output_mod.print_ok(t("compare.info_decreased", delta=abs(delta.info_delta)))
    elif delta.info_delta > 0:
        output_mod.print_info(t("compare.info_increased", delta=delta.info_delta))

    # --- Variable deductions (score moved without structural key/count changes) ---
    has_structural_explanation = (
        delta.alert_delta != 0
        or delta.warn_delta != 0
        or delta.new_finding_keys
        or delta.resolved_finding_keys
    )
    if delta.deduction_delta != 0 and not has_structural_explanation:
        if delta.deduction_delta > 0:
            output_mod.print_info(t("compare.variable_deductions_increased",
                                     delta=delta.deduction_delta))
        else:
            output_mod.print_info(t("compare.variable_deductions_decreased",
                                     delta=abs(delta.deduction_delta)))

    # --- New / resolved ALERT+WARN finding keys ---
    for key in delta.new_finding_keys:
        output_mod.print_warn(t("compare.key_appeared", finding=key))
    for key in delta.resolved_finding_keys:
        output_mod.print_ok(t("compare.key_resolved", finding=key))

    # --- Ports ---
    for port in delta.new_ports:
        output_mod.print_warn(t("compare.port_appeared", port=port))

    for port in delta.closed_ports:
        output_mod.print_ok(t("compare.port_closed", port=port))

    # --- Services ---
    for svc in delta.new_services:
        output_mod.print_info(t("compare.service_appeared", service=svc))

    for svc in delta.stopped_services:
        output_mod.print_info(t("compare.service_stopped", service=svc))

    # --- No changes ---
    if delta.is_empty():
        output_mod.print_ok(t("compare.no_changes"))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_stable_port(port_proto: str) -> bool:
    """Return True if the port number is below the Linux ephemeral range.

    Ephemeral ports (>= 32768 by default on Linux) change between audits
    and would flood the comparative report with false-positive "new port"
    findings from AVAHI, libvirt, VPN, and other transient UDP sockets.
    """
    try:
        return int(port_proto.split("/")[0]) < 32768
    except (ValueError, IndexError):
        return False
