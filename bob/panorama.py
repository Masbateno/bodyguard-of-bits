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
    #: v0.35.0 — one of bob.checks.services.PORT_SCOPES, or "na".
    scope:  str


#: v0.35.0 — the reaches the panorama colours as a warning, and as calm.
WARN_SCOPES = frozenset({"anyone", "unfiltered", "accepted"})
CALM_SCOPES = frozenset({"this_host", "denied", "no_listener"})


def _scope(snap, port_scopes) -> str:
    """The widest reach the services section concluded for *snap*'s ports.
    A service it did not examine (installed, stopped, not high-risk) gets
    "no_listener" when none of its ports listens (measured by the port scan),
    "not_examined" otherwise — no port included (none of the registry's
    services lacks one). Decided after review: "—" means not installed, and
    nothing else; a listening port of an unexamined service is the ports
    section's."""
    from bob.checks.services import PORT_SCOPES
    if not snap.installed:
        return "na"
    seen = (port_scopes or {}).get(snap.service.id) or {}
    if seen:
        return min(seen.values(), key=lambda s: PORT_SCOPES.index(s) if s in PORT_SCOPES else 3)
    exposures = snap.exposures or {}
    if exposures and all(e == Exposure.NOT_LISTENING for e in exposures.values()):
        return "no_listener"
    return "not_examined"


def build_panorama_rows(all_snapshots, port_scopes=None) -> list[PanoramaRow]:
    """Convert ServiceSnapshot list to display dicts for print_services_panorama().
    *port_scopes*: service id → {port: reach} as the services section
    concluded it (ServiceSnapshot.port_scope)."""
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

        scope = _scope(snap, port_scopes)
        ufw = "warn" if scope in WARN_SCOPES else ("na" if scope in ("na", "not_examined") else "ok")

        rows.append(PanoramaRow(
            label=snap.label,
            risk=(snap.risk or "").lower(),
            status=status,
            ports=ports_str,
            ufw=ufw,
            scope=scope,
        ))

    return sorted(rows, key=lambda r: r["label"].lower())
