"""
Orphan systemd socket-unit audit for BOB.

Sits at the systemd × listening-sockets intersection opened by v0.13.0. A
socket-activated service is normal and healthy; what is *not* healthy is a
``.socket`` unit that is still active (a kernel socket is open / a path is being
listened on) while the ``.service`` it is supposed to hand connections to is
**broken** — gone (not-found / masked), or present but in a ``failed`` state
(e.g. a bad ``ExecStart`` that crashes on activation). Either way something
accepts connections but the consumer behind it cannot serve them — a latent
exposure, typically the leftover of a removed/renamed package or a misconfigured
unit. A ``.socket`` stuck in ``failed`` itself is the same class of problem.

A service being merely *disabled* / *inactive* is **not** flagged: that is the
expected resting state of a socket-activated service (systemd starts it on the
first connection), so treating it as broken would false-positive on virtually
every healthy socket. Only ``LoadState`` gone/masked or ``ActiveState=failed``
counts as broken. A socket with an *empty* ``Triggers=`` (systemd internals such
as ``systemd-coredump.socket`` activated by other means) is likewise never
flagged. When a socket declares several trigger services, it is orphaned if
*any* of them is broken.

INFO-only by design (v0.13.1): a deduction belongs in the v0.14.0 scoring bundle
(an orphan socket bound to a non-loopback address is an operator-visible
exposure, but calibration waits for real-world signal).

No network calls. Local ``systemctl`` only.

Split into:
  1. SocketUnitsSnapshot.from_system() — enumerate sockets + resolve triggers.
  2. check_socket_units(snapshot, t)   — pure analysis, returns CheckResult.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

from bob.checks._run import TranslationFunc, _command_exists, _identity_t, _run
from bob.scoring import CheckResult

# Hard cap on sockets parsed, to never stall on a large deployment.
_MAX_SOCKETS = 400
# How many orphaned/failed sockets to list in the finding.
_TOP_N = 10
# Trigger LoadState values that mean the backing service is gone or unusable.
_BROKEN_LOAD = frozenset({"not-found", "masked", "error", "bad-setting"})

# A Listen= value looks like "0.0.0.0:22 (Stream)" or "/run/foo (Stream)".
_LISTEN_ADDR = re.compile(r"^(.*?)\s+\([^)]*\)\s*$")
# Loopback / unix-path addresses are not network-exposed.
_LOOPBACK = re.compile(r"^(127\.|\[::1\]|::1\b)")
# A non-loopback IP:port — "0.0.0.0:22", "10.0.0.1:22", "[::]:22", or "*:22".
_ALL_OR_PUBLIC_IP = re.compile(r"^(\*|\d{1,3}(\.\d{1,3}){3}|\[?[0-9a-fA-F:]+\]?):\d+$")


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------

@dataclass
class SocketUnit:
    """A single ``.socket`` unit and the health of its backing service.

    Attributes:
        name:            the ``*.socket`` unit name.
        active_state:    systemd ActiveState (active / inactive / failed / …).
        listens:         raw Listen addresses (e.g. "0.0.0.0:22", "/run/foo").
        triggers:        the backing ``*.service`` unit(s) (empty when none).
        broken_trigger:  first trigger found gone/masked or in a failed state
                         ("" when every declared trigger is healthy).
    """
    name: str = ""
    active_state: str = ""
    listens: list[str] = field(default_factory=list)
    triggers: list[str] = field(default_factory=list)
    broken_trigger: str = ""

    @property
    def is_failed(self) -> bool:
        """The socket unit itself failed."""
        return self.active_state == "failed"

    @property
    def is_orphan(self) -> bool:
        """At least one declared trigger service is gone/masked or failed."""
        return bool(self.broken_trigger)

    @property
    def is_network_listener(self) -> bool:
        """True when at least one Listen address is a non-loopback IP socket."""
        for addr in self.listens:
            if _LOOPBACK.match(addr):
                continue
            if _ALL_OR_PUBLIC_IP.match(addr):
                return True
        return False


@dataclass
class SocketUnitsSnapshot:
    """Raw snapshot of the host's ``.socket`` units.

    Attributes:
        available: True when ``systemctl`` is present.
        sockets:   parsed SocketUnit entries (bounded by _MAX_SOCKETS).
    """
    available: bool = False
    sockets: list[SocketUnit] = field(default_factory=list)

    @classmethod
    def from_system(cls) -> "SocketUnitsSnapshot":
        snap = cls()
        if not _command_exists("systemctl"):
            return snap
        snap.available = True

        names = _socket_unit_names()[:_MAX_SOCKETS]
        health_cache: dict[str, tuple[str, str]] = {}
        for name in names:
            su = _socket_unit(name)
            for trig in su.triggers:
                if trig not in health_cache:
                    health_cache[trig] = _trigger_health(trig)
                load, active = health_cache[trig]
                if _is_broken(load, active):
                    su.broken_trigger = trig
                    break
            snap.sockets.append(su)
        return snap


def _socket_unit_names() -> list[str]:
    """All loaded ``*.socket`` unit names (empty list on failure)."""
    out = _run("systemctl", "list-units", "--type=socket", "--all", "--no-legend")
    names: list[str] = []
    for line in out.splitlines():
        parts = line.split()
        # A leading "●" status glyph can prefix failed units; skip to the name.
        for tok in parts:
            if tok.endswith(".socket"):
                names.append(tok)
                break
    return names


def _socket_unit(name: str) -> SocketUnit:
    """Resolve ActiveState / Triggers / Listen for one socket unit."""
    su = SocketUnit(name=name)
    out = _run("systemctl", "show", name, "-p", "ActiveState", "-p", "Triggers",
               "-p", "Listen")
    for line in out.splitlines():
        key, _, value = line.partition("=")
        if key == "ActiveState":
            su.active_state = value.strip()
        elif key == "Triggers":
            # space-separated; keep every backing .service (a socket may declare
            # more than one — orphaned if any of them is broken).
            su.triggers = [t for t in value.split() if t.endswith(".service")]
        elif key == "Listen":
            m = _LISTEN_ADDR.match(value.strip())
            addr = m.group(1).strip() if m else value.strip()
            if addr:
                su.listens.append(addr)
    return su


def _trigger_health(unit: str) -> tuple[str, str]:
    """(LoadState, ActiveState) of a unit; ("", "") on failure."""
    out = _run("systemctl", "show", unit, "-p", "LoadState", "-p", "ActiveState")
    load = active = ""
    for line in out.splitlines():
        key, _, value = line.partition("=")
        if key == "LoadState":
            load = value.strip()
        elif key == "ActiveState":
            active = value.strip()
    return load, active


def _is_broken(load: str, active: str) -> bool:
    """A trigger service is broken when it is gone/masked, or present but failed.

    ``inactive`` is deliberately *not* broken: that is the normal resting state
    of a socket-activated service (systemd starts it on demand). Only a hard
    ``failed`` ActiveState — a service that tried to run and crashed — counts.
    """
    return load in _BROKEN_LOAD or active == "failed"


# ---------------------------------------------------------------------------
# Check logic
# ---------------------------------------------------------------------------

def check_socket_units(
    snapshot: SocketUnitsSnapshot, t: TranslationFunc | None = None
) -> CheckResult:
    """Surface orphaned / failed systemd socket units (INFO-only, no deduction)."""
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if not snapshot.available:
        result.info(message=_t("socket_units.no_tool"), key="socket_units.no_tool")
        return result

    orphans = [s for s in snapshot.sockets if s.is_orphan]
    failed = [s for s in snapshot.sockets if s.is_failed and not s.is_orphan]

    if not orphans and not failed:
        result.info(
            message=_t("socket_units.clean", total=len(snapshot.sockets)),
            key="socket_units.clean",
        )
        return result

    flagged = orphans + failed
    exposed = sum(1 for s in flagged if s.is_network_listener)
    result.info(
        message=_t("socket_units.summary", orphans=len(orphans),
                   failed=len(failed), exposed=exposed),
        detail=_t("socket_units.summary_detail"),
        key="socket_units.summary",
    )

    # v0.15.4 "teeth": a socket unit holding a non-loopback port open while the
    # service behind it is broken is an operator-visible state, not an editor
    # default — systemd accepts the connection and then fails it. The count
    # stays in the INFO summary above; the exposed subset gets its own finding
    # so it can be explained, ignored and deducted for on its own terms.
    if exposed:
        first = next(s for s in flagged if s.is_network_listener)
        result.warn_with_deduction(
            message=_t("socket_units.orphan_exposed", count=exposed),
            detail=_t("socket_units.orphan_exposed_detail"),
            key="socket_units.orphan_exposed",
            points=1,
            nature="improvement",
            cmd=f"sudo systemctl disable --now {shlex.quote(first.name)}",
        )

    for su in flagged[:_TOP_N]:
        reason = "orphan" if su.is_orphan else "failed"
        addr = su.listens[0] if su.listens else "?"
        net = " [net]" if su.is_network_listener else ""
        trigger = su.broken_trigger or (su.triggers[0] if su.triggers else "-")
        result.info(
            message=_t(f"socket_units.{reason}", name=su.name, addr=addr,
                       trigger=trigger, net=net),
            key=f"socket_units.{reason}",
        )

    return result
