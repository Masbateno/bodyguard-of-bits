"""
Service hardening audit (systemd-analyze security) for BOB.

Surfaces the systemd-analyze security exposure of the host's RUNNING service
units — a documented, deterministic, offline-safe view of how hardened each
service is (NoNewPrivileges, ProtectSystem, capability bounding, namespacing…).

INFO-only by design (v0.13.0): systemd ships most units unhardened, so a high
exposure score is the *normal* default state of a Linux host, not a chosen
misconfiguration — and systemd's own documentation describes the score as a
relative hardening guide, not a vulnerability verdict. BOB therefore surfaces
the picture (counts by predicate + the least-hardened running services + a
pointer to ``systemd-analyze security <unit>``) **without any score deduction**.
Calibrating a defensible deduction (e.g. an admin-authored UNSAFE unit) is left
for real-world signal — see CHANGELOG v0.13.0.

No network calls. Two local commands: ``systemctl list-units`` (to scope to
running services) + ``systemd-analyze security --json=short``.

Split into:
  1. ServiceHardeningSnapshot.from_system() — runs the two commands and parses.
  2. check_service_hardening(snapshot, t)   — pure analysis, returns CheckResult.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from bob.checks._run import TranslationFunc, _command_exists, _identity_t, _run, strip_unit_glyph
from bob.scoring import CheckResult

# Hard cap on units parsed, to never stall on a large deployment.
_MAX_UNITS = 500
# How many least-hardened running services to list.
_TOP_N = 5
# systemd-analyze predicate buckets considered "noteworthy" (worst first).
_NOTEWORTHY = ("UNSAFE", "EXPOSED")


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------

@dataclass
class ServiceHardeningSnapshot:
    """Raw snapshot of running-service systemd exposure.

    Attributes:
        available: True when the ``systemd-analyze`` binary is present.
        units:     ``(unit, exposure, predicate)`` for each RUNNING service unit
                   that systemd-analyze scored, sorted worst-exposure first.
        total:     number of running service units analysed.
    """
    available: bool = False
    units: list[tuple[str, float, str]] = field(default_factory=list)
    total: int = 0

    @classmethod
    def from_system(cls) -> "ServiceHardeningSnapshot":
        snap = cls()
        if not _command_exists("systemd-analyze"):
            return snap
        snap.available = True

        running = _running_services()
        out = _run("systemd-analyze", "security", "--json=short")
        if not out:
            return snap
        try:
            data = json.loads(out)
        except (ValueError, TypeError):
            return snap
        if not isinstance(data, list):
            return snap

        rows: list[tuple[str, float, str]] = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            unit = str(entry.get("unit", ""))
            # Scope to running services when we could determine the set; if the
            # list-units call failed (empty set) fall back to all analysed units.
            if running and unit not in running:
                continue
            # The cap bounds how many results are kept, applied *after* the
            # scope filter. Slicing `data` first made it bound which running
            # services were considered at all, alphabetically, on any host
            # whose analysed-unit count exceeds it.
            if len(rows) >= _MAX_UNITS:
                break
            try:
                exposure = float(entry.get("exposure", 0) or 0)
            except (ValueError, TypeError):
                exposure = 0.0
            predicate = str(entry.get("predicate", "")).upper()
            rows.append((unit, exposure, predicate))

        rows.sort(key=lambda r: r[1], reverse=True)
        snap.units = rows
        snap.total = len(rows)
        return snap


def _running_services() -> set[str]:
    """Return the set of running ``*.service`` unit names (empty on failure)."""
    out = _run("systemctl", "list-units", "--type=service",
               "--state=running", "--no-legend")
    names: set[str] = set()
    for line in out.splitlines():
        parts = strip_unit_glyph(line).split()
        if parts and parts[0].endswith(".service"):
            names.add(parts[0])
    return names


# ---------------------------------------------------------------------------
# Check logic
# ---------------------------------------------------------------------------

def check_service_hardening(
    snapshot: ServiceHardeningSnapshot, t: TranslationFunc | None = None
) -> CheckResult:
    """Surface systemd service-hardening exposure (INFO-only, no deduction)."""
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if not snapshot.available:
        result.info(message=_t("systemd_hardening.no_tool"),
                    key="systemd_hardening.no_tool")
        return result

    if snapshot.total == 0:
        result.info(message=_t("systemd_hardening.none"),
                    key="systemd_hardening.none")
        return result

    unsafe  = sum(1 for _, _, p in snapshot.units if p == "UNSAFE")
    exposed = sum(1 for _, _, p in snapshot.units if p == "EXPOSED")
    lower   = snapshot.total - unsafe - exposed

    result.info(
        message=_t("systemd_hardening.summary", total=snapshot.total,
                   unsafe=unsafe, exposed=exposed, lower=lower),
        detail=_t("systemd_hardening.summary_detail"),
        key="systemd_hardening.summary",
    )

    worst = [u for u in snapshot.units if u[2] in _NOTEWORTHY][:_TOP_N]
    if worst:
        listing = ", ".join(f"{unit} ({exp:.1f} {pred})" for unit, exp, pred in worst)
        result.info(
            message=_t("systemd_hardening.worst", count=len(worst), units=listing),
            key="systemd_hardening.worst",
        )

    return result
