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
    fw_backend: str = "ufw",
) -> list[ExposureItem]:
    """
    Return a list of ExposureItems describing the machine's real attack surface.

    Args:
        engine:          Finalized ScoreEngine.
        ports_snapshot:  PortsSnapshot from the current audit run.
        network_context: "public" | "local" from detect_network_context().
        fw_active:       Whether a firewall filters inbound traffic — UFW,
                         firewalld or a raw nftables/iptables ruleset.
        fw_policy:       That firewall's inbound default ("deny", "allow",
                         "reject", "unknown").
        t:               Translation function.
        fw_backend:      "ufw", "firewalld" or "netfilter" (see
                         ``bob.checks.firewall.FirewallPosture``).
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
    _backend_label = {"netfilter": "nftables/iptables"}.get(fw_backend, fw_backend)
    if not fw_active:
        items.append(ExposureItem(
            label=t("exposure.firewall"),
            icon="✖", color="alert",
            detail=t("exposure.firewall_inactive"),
        ))
    elif fw_policy == "unknown":
        # v0.24.1: an unread default was printed as "default policy is ALLOW —
        # no filtering" — on every firewalld host, whose policy BOB never read.
        items.append(ExposureItem(
            label=t("exposure.firewall"),
            icon="⚠", color="warn",
            detail=t("exposure.firewall_policy_unread", backend=_backend_label),
        ))
    elif fw_policy not in ("deny", "reject"):
        items.append(ExposureItem(
            label=t("exposure.firewall"),
            icon="✖", color="alert",
            detail=t("exposure.firewall_allow_all"),
        ))
    else:
        policy_str = (t("exposure.firewall_policy", policy=fw_policy)
                      if fw_backend == "ufw" else
                      t("exposure.firewall_policy_backend", policy=fw_policy,
                        backend=_backend_label))
        items.append(ExposureItem(
            label=t("exposure.firewall"),
            icon="✔", color="ok",
            detail=policy_str,
        ))

    # --- Exposed ports ---
    # UDP ports above 32767 are kernel-assigned ephemeral sockets (client-side),
    # not server ports — mirror the same filter used in check_ports().
    # v0.24.0: a bind to one concrete host address (Samba on 192.168.1.10) is as
    # reachable from that network as 0.0.0.0, so it counts too — except the
    # DNS/DHCP-class ports check_ports itself calls system-internal (libvirt's
    # dnsmasq on its own bridge address).
    from bob.checks.ports import is_specific_unicast, is_system_internal
    exposed = sorted(
        {
            lp.port_proto
            for lp in ports_snapshot.ports
            if (lp.is_all_interfaces
                or (is_specific_unicast(lp) and not is_system_internal(lp)))
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

    if "ssh.config_unreadable" in all_keys:
        # No directive was read, so "key-only, root login disabled" would be a
        # statement about OpenSSH's defaults rather than about this host.
        items.append(ExposureItem(
            label=t("exposure.ssh"),
            icon="⚠", color="warn",
            detail=t("exposure.ssh_config_unknown"),
        ))
    elif "ssh.not_installed" in all_keys:
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
    elif "ssh.password_auth" in all_keys:
        # No ssh issue at this context's severity, but password auth *is*
        # enabled — it was only downgraded to INFO (e.g. a LAN/desktop host).
        # "key-only" would be a false statement here (measured on a real Kali
        # desktop: PasswordAuthentication yes, reported INFO, summary claimed
        # key-only). Green stays — it is acceptable for the context — but the
        # detail must not deny that password auth is on.
        items.append(ExposureItem(
            label=t("exposure.ssh"),
            icon="✔", color="ok",
            detail=t("exposure.ssh_ok_password_on"),
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
        # v0.24.0: name the cause that was measured. One "stale or inconsistent"
        # line for both read "stale" beside a cache reported 0 days old.
        stale = "updates.apt_cache_stale" in bad_keys
        inconsistent = "updates.dist_upgrade_inconsistent" in bad_keys
        key = ("exposure.updates_unknown" if stale and inconsistent
               else "exposure.updates_stale" if stale
               else "exposure.updates_inconsistent")
        items.append(ExposureItem(
            label=t("exposure.updates"),
            icon="⚠", color="warn",
            detail=t(key),
        ))
    elif "updates.no_security_channel" in all_keys:
        # A rolling distro with no security channel and updates pending: BOB
        # cannot say "security up to date" — it cannot classify security here at
        # all, and updates are waiting. A green tick would be false reassurance.
        items.append(ExposureItem(
            label=t("exposure.updates"),
            icon="⚠", color="warn",
            detail=t("exposure.updates_no_channel"),
        ))
    else:
        items.append(ExposureItem(
            label=t("exposure.updates"),
            icon="✔", color="ok",
            detail=t("exposure.updates_ok"),
        ))

    return items
