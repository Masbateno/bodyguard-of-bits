"""
Services panorama builder for BOB.

Converts ServiceSnapshot lists into display-ready row dicts consumed
by output.print_services_panorama().
"""

from __future__ import annotations

from typing import TypedDict

from bob.checks.services import Exposure


class PanoramaRow(TypedDict):
    """Typed view-model produced by build_panorama_rows()."""
    label:  str
    risk:   str
    status: str
    ports:  str
    ufw:    str


def build_panorama_rows(all_snapshots) -> list[PanoramaRow]:
    """Convert ServiceSnapshot list to display dicts for print_services_panorama()."""
    rows: list[PanoramaRow] = []

    for snap in all_snapshots:
        state = getattr(snap, "state", None)

        # Status
        if not snap.installed:
            status = "not_installed"
        elif not state:
            status = "unknown"
        elif state.is_active:
            status = "active"
        elif state.is_inactive:
            status = "inactive"
        else:
            status = "unknown"

        # Ports — str(p) guards against non-string port values
        if snap.installed and snap.ports:
            ports_str = ", ".join(str(p) for p in snap.ports)
        else:
            ports_str = "—"

        # UFW indicator — exposures guard prevents AttributeError on unexpected None
        exposures = snap.exposures or {}
        if not snap.installed or not exposures:
            ufw = "na"
        elif any(e == Exposure.OPEN_WORLD for e in exposures.values()):
            ufw = "warn"
        else:
            ufw = "ok"

        rows.append(PanoramaRow(
            label=snap.label,
            risk=(snap.risk or "").lower(),
            status=status,
            ports=ports_str,
            ufw=ufw,
        ))

    return sorted(rows, key=lambda r: r["label"].lower())
