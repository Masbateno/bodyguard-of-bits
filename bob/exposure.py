"""Real exposure view for BOB.

Synthesises firewall state, open ports, network context, and finding keys
into a compact attack-surface table shown at the end of the audit summary.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bob.checks.ports import PortsSnapshot
    from bob.scoring import ScoreEngine


@dataclass
class ExposureItem:
    label: str
    icon: str       # "✔" / "✖" / "⚠"
    color: str      # "ok" / "warn" / "alert"
    detail: str


def compute_exposure(
    engine: "ScoreEngine",
    ports_snapshot: "PortsSnapshot",
    network_context: str,
    fw_active: bool,
    fw_policy: str,
    t,
) -> list[ExposureItem]:
    """
    Return a list of ExposureItems describing the machine's real attack surface.

    Args:
        engine:          Finalized ScoreEngine.
        ports_snapshot:  PortsSnapshot from the current audit run.
        network_context: "public" | "local" from detect_network_context().
        fw_active:       Whether UFW is currently active.
        fw_policy:       UFW incoming policy ("deny", "allow", "reject", "unknown").
        t:               Translation function.
    """
    from bob.scoring import FindingLevel

    alert_keys = {f.key for f in engine.findings if f.key and f.level == FindingLevel.ALERT}
    warn_keys  = {f.key for f in engine.findings if f.key and f.level == FindingLevel.WARN}
    info_keys  = {f.key for f in engine.findings if f.key and f.level == FindingLevel.INFO}
    bad_keys   = alert_keys | warn_keys
    all_keys   = bad_keys | info_keys

    items: list[ExposureItem] = []

    # --- Internet exposure ---
    if network_context == "public":
        items.append(ExposureItem(
            label=t("exposure.internet_facing"),
            icon="✖", color="alert",
            detail=t("exposure.internet_facing_detail"),
        ))
    elif "ddns.warn" in bad_keys:
        items.append(ExposureItem(
            label=t("exposure.internet_facing"),
            icon="⚠", color="warn",
            detail=t("exposure.internet_facing_ddns"),
        ))
    else:
        items.append(ExposureItem(
            label=t("exposure.internet_facing"),
            icon="✔", color="ok",
            detail=t("exposure.internet_facing_local"),
        ))

    # --- Firewall ---
    if not fw_active:
        items.append(ExposureItem(
            label=t("exposure.firewall"),
            icon="✖", color="alert",
            detail=t("exposure.firewall_inactive"),
        ))
    elif fw_policy not in ("deny", "reject"):
        items.append(ExposureItem(
            label=t("exposure.firewall"),
            icon="✖", color="alert",
            detail=t("exposure.firewall_allow_all"),
        ))
    else:
        policy_str = t("exposure.firewall_policy", policy=fw_policy)
        items.append(ExposureItem(
            label=t("exposure.firewall"),
            icon="✔", color="ok",
            detail=policy_str,
        ))

    # --- Exposed ports (all-interfaces, stable) ---
    # UDP ports above 32767 are kernel-assigned ephemeral sockets (client-side),
    # not server ports — mirror the same filter used in check_ports().
    exposed = sorted(
        {
            lp.port_proto
            for lp in ports_snapshot.ports
            if lp.is_all_interfaces
            and not (lp.proto == "udp" and lp.port > 32767)
        },
        key=lambda s: int(s.split("/")[0]),
    )
    if exposed:
        color = "alert" if not fw_active or fw_policy not in ("deny", "reject") else "warn"
        items.append(ExposureItem(
            label=t("exposure.open_ports"),
            icon="⚠" if color == "warn" else "✖",
            color=color,
            detail=", ".join(exposed),
        ))
    elif not ports_snapshot.ports_readable:
        # A green tick here would be the whole audit's summary line asserting
        # "nothing exposed" off a socket list that was never read.
        items.append(ExposureItem(
            label=t("exposure.open_ports"),
            icon="⚠", color="warn",
            detail=t("exposure.open_ports_unknown"),
        ))
    else:
        items.append(ExposureItem(
            label=t("exposure.open_ports"),
            icon="✔", color="ok",
            detail=t("exposure.no_open_ports"),
        ))

    # --- SSH ---
    ssh_issues = []
    if "ssh.permit_root_login" in bad_keys:
        ssh_issues.append(t("exposure.ssh_root"))
    if "ssh.password_auth" in bad_keys:
        ssh_issues.append(t("exposure.ssh_password"))
    if "ssh.weak_ciphers" in bad_keys or "ssh.weak_kex" in bad_keys:
        ssh_issues.append(t("exposure.ssh_weak_crypto"))

    if "ssh.not_installed" in all_keys:
        items.append(ExposureItem(
            label=t("exposure.ssh"),
            icon="✔", color="ok",
            detail=t("exposure.ssh_not_installed"),
        ))
    elif "ssh.not_active" in bad_keys:
        items.append(ExposureItem(
            label=t("exposure.ssh"),
            icon="✔", color="ok",
            detail=t("exposure.ssh_stopped"),
        ))
    elif ssh_issues:
        color = "alert" if any(k in alert_keys for k in
                               ("ssh.permit_root_login", "ssh.password_auth")) else "warn"
        items.append(ExposureItem(
            label=t("exposure.ssh"),
            icon="✖" if color == "alert" else "⚠",
            color=color,
            detail=" · ".join(ssh_issues),
        ))
    else:
        items.append(ExposureItem(
            label=t("exposure.ssh"),
            icon="✔", color="ok",
            detail=t("exposure.ssh_ok"),
        ))

    # --- Brute-force protection ---
    if "fail2ban.not_installed" in all_keys:
        items.append(ExposureItem(
            label=t("exposure.brute_force"),
            icon="✖", color="warn",
            detail=t("exposure.brute_force_missing"),
        ))
    elif "fail2ban.service_inactive" in bad_keys:
        items.append(ExposureItem(
            label=t("exposure.brute_force"),
            icon="✖", color="warn",
            detail=t("exposure.brute_force_inactive"),
        ))
    else:
        items.append(ExposureItem(
            label=t("exposure.brute_force"),
            icon="✔", color="ok",
            detail=t("exposure.brute_force_ok"),
        ))

    # --- Security updates ---
    # Order matters: prefer "unknown" over "ok" when the snapshot is unreliable
    # (stale cache or inconsistent state) — false reassurance on a security
    # check is worse than admitting we don't know.
    if "updates.security_pending" in bad_keys:
        items.append(ExposureItem(
            label=t("exposure.updates"),
            icon="✖", color="warn",
            detail=t("exposure.updates_pending"),
        ))
    elif "updates.apt_cache_stale" in bad_keys or "updates.dist_upgrade_inconsistent" in bad_keys:
        items.append(ExposureItem(
            label=t("exposure.updates"),
            icon="⚠", color="warn",
            detail=t("exposure.updates_unknown"),
        ))
    else:
        items.append(ExposureItem(
            label=t("exposure.updates"),
            icon="✔", color="ok",
            detail=t("exposure.updates_ok"),
        ))

    return items
