"""Audit runner — sequentially executes all audit checks."""

from __future__ import annotations

import difflib
import sys
from typing import NamedTuple

from bob import output
from bob.cli import AuditConfig
from bob.config import UserConfig
from bob.profiles import AuditProfile, apply_profile
from bob.display import (
    check_single_service_display,
    display_disk_partitions,
    display_geoip_notice,
    display_log_results,
    display_network_context,
    display_ports_overview,
    display_result,
    display_risk_context,
    display_services_panorama,
)
from bob.output import print_group, print_info, print_section, print_service_header
from bob.registry import ServiceRegistry
from bob.report import AuditReport, Report
from bob.scoring import ScoreEngine
from bob.checks.ddns import DdnsSnapshot, check_ddns, ddns_effective_context
from bob.checks.auth_log import AuthLogSnapshot, check_auth_log
from bob.checks.docker import DockerSnapshot, check_docker
from bob.checks.firewall import FirewallStatus, check_firewall, check_rules, check_ufw_logging
from bob.checks.iptables_nftables import IptablesNftSnapshot, check_iptables_nftables
from bob.checks.umask import UmaskSnapshot, check_umask
from bob.checks.firewall_stack import FirewallStackSnapshot, check_firewall_stack
from bob.checks.network_context import NetworkContextSnapshot, check_network_context
from bob.checks.logs import LogsSnapshot, check_logs, geoip2_status
from bob.checks.ports import PortsSnapshot, check_ports
from bob.checks.services import ServiceSnapshot
from bob.checks.virtualization import VirtSnapshot, check_virtualization
from bob.checks.hardening import HardeningSnapshot, check_hardening
from bob.checks.kernel_hardening import KernelHardeningSnapshot, check_kernel_hardening
from bob.checks.suid_audit import SuidSnapshot, check_suid_audit
from bob.checks.docker_audit import DockerAuditSnapshot, check_docker_audit
from bob.checks.log_rotation import LogRotationSnapshot, check_log_rotation
from bob.checks.ipv6 import IPv6Snapshot, check_ipv6
from bob.checks.ssh import SSHSnapshot, check_ssh
from bob.checks.file_perms import FilePermsSnapshot, check_file_perms
from bob.checks.updates import UpdatesSnapshot, check_updates
from bob.checks.kernel_modules import KernelModulesSnapshot, check_kernel_modules
from bob.checks.mac_policy import MacPolicySnapshot, check_mac_policy
from bob.checks.cron_audit import CronAuditSnapshot, check_cron_audit
from bob.checks.services_state import ServicesStateSnapshot, check_services_state
from bob.checks.user_accounts import UserAccountsSnapshot, check_user_accounts
from bob.checks.password_policy import PasswordPolicySnapshot, check_password_policy
from bob.checks.memory import MemorySnapshot, check_memory
from bob.checks.disk import DiskSnapshot, check_disk
from bob.checks.samba import SambaSnapshot, check_samba
from bob.checks.clamav import ClamAVSnapshot, check_clamav
from bob.checks.smtp import SmtpSnapshot, check_smtp
from bob.checks.desktop_apps import DesktopAppsSnapshot, check_desktop_apps
from bob.checks.backup import BackupSnapshot, check_backup
from bob.checks.auditd import AuditdSnapshot, check_auditd
from bob.checks.secure_boot import SecureBootSnapshot, check_secure_boot
from bob.checks.file_integrity import FileIntegritySnapshot, check_file_integrity
from bob.checks.ntp import NtpSnapshot, check_ntp
from bob.checks.fail2ban import Fail2banSnapshot, check_fail2ban
from bob.checks.rootkit import RootkitSnapshot, check_rootkit
from bob.checks.ssl_certs import SslCertsSnapshot, check_ssl_certs
from bob.checks.systemd_timers import SystemdTimersSnapshot, check_systemd_timers
from bob.checks.firmware import FirmwareSnapshot, check_firmware
from bob.plugin_checks import load_plugin_checks


_ALL_SECTIONS: tuple[str, ...] = (
    "ipv6", "smtp", "ssh", "auth_log", "user_accounts", "password_policy",
    "file_perms", "hardening", "kernel_hardening", "suid_audit", "docker_audit",
    "log_rotation", "kernel_modules", "mac_policy", "cron_audit", "services_state",
    "updates", "umask", "memory", "disk", "backup", "auditd", "secure_boot",
    "fail2ban", "clamav", "file_integrity", "rootkit", "ntp", "systemd_timers",
    "ssl_certs", "firmware", "iptables_nft", "samba", "desktop_apps",
)


def _section_enabled(section: str, config: "AuditConfig", profile: "AuditProfile | None") -> bool:
    """Return True if the section should be run given config filters and the active profile.

    Token matching is prefix-aware: a token matches a section when the section
    name equals the token OR starts with it (e.g. "kernel" matches both
    "kernel_hardening" and "kernel_modules").
    """
    if config.check_only:
        if not any(section == tok or section.startswith(tok) for tok in config.check_only):
            return False
    if config.skip_checks:
        if any(section == tok or section.startswith(tok) for tok in config.skip_checks):
            return False
    return profile is None or not profile.should_skip_section(section)


def validate_check_filters(config: "AuditConfig") -> str | None:
    """Validate --check / --skip tokens against known sections.

    Prints warnings to stderr for unrecognised tokens and returns a fatal error
    string when every --check token is unrecognised (nothing would run).
    Returns None when all is well.
    """
    def _matches(tok: str) -> bool:
        return any(s == tok or s.startswith(tok) for s in _ALL_SECTIONS)

    def _suggest(tok: str) -> str:
        matches = difflib.get_close_matches(tok, _ALL_SECTIONS, n=3, cutoff=0.5)
        if matches:
            return f"Did you mean: {', '.join(matches)}"
        return f"Available sections: {', '.join(_ALL_SECTIONS)}"

    if config.check_only:
        bad = sorted(tok for tok in config.check_only if not _matches(tok))
        if bad:
            for tok in bad:
                print(f"Warning: --check '{tok}' matches no known section — {_suggest(tok)}", file=sys.stderr)
            if len(bad) == len(config.check_only):
                return "--check matched no known sections. Run 'bob --help' to list available checks."

    if config.skip_checks:
        for tok in sorted(config.skip_checks):
            if not _matches(tok):
                print(f"Warning: --skip '{tok}' matches no known section — {_suggest(tok)}", file=sys.stderr)

    return None


class ChecksResult(NamedTuple):
    snapshots:          list
    ports_snapshot:     PortsSnapshot
    stack_snapshot:     FirewallStackSnapshot
    net_snapshot:       NetworkContextSnapshot
    hardening_snapshot: HardeningSnapshot
    ipv6_snapshot:      IPv6Snapshot
    fw_active:          bool = False
    fw_policy:          str  = "unknown"
    network_context:    str  = "local"


def init_report(config: AuditConfig, user_config: UserConfig, t, version: str) -> AuditReport:
    """Open a timestamped report file, or return a null (no-op) report."""
    if config.detailed:
        from bob.manage_logs import get_or_prompt_log_dir
        log_dir = get_or_prompt_log_dir(user_config, config, t)
        report  = AuditReport.open(directory=log_dir, version=version)
        output.print_ok(t("audit.report_saved", path=report.path))
        if not config.quiet:
            print()
        return report
    return AuditReport.null()


def run_checks(
    config: AuditConfig,
    t,
    engine: ScoreEngine,
    report: Report,
    registry: ServiceRegistry,
    network_context: str,
    profile: AuditProfile | None = None,
    prev_recurrence: "dict[str, int] | None" = None,
    user_config: UserConfig | None = None,
) -> ChecksResult:
    """Run all audit checks in sequence."""
    _pr: dict[str, int] = prev_recurrence or {}
    _pname = profile.name if profile is not None else "server"

    def emit_section(section_key: str) -> None:
        """Print and write a section header (respects ``--quiet``)."""
        title = t(f"sections.{section_key}")
        if not config.quiet:
            print_section(title)
        report.write_section(title)

    def emit_group(group_key: str) -> None:
        """Print and write a group header (respects ``--quiet``)."""
        title = t(f"groups.{group_key}")
        if not config.quiet:
            print_group(title)
        report.write_group(title)

    def _sec(
        section: str,
        snapshot,
        check_fn,
        *,
        skip_if=None,
        post_display=None,
        **check_kwargs,
    ) -> None:
        """Run one audit section.

        Args:
            section: section key (drives header text + `_section_enabled` gate
                via profile / `--check`).
            snapshot: pre-collected snapshot object (passed positionally to
                ``check_fn``).
            check_fn: pure check function returning a ``CheckResult``.
            skip_if: optional ``Callable[[snapshot], bool]`` — when truthy,
                the section is skipped without emitting the header (used for
                "if installed" / "if detected" gates that depend on the
                snapshot rather than the profile).
            post_display: optional ``Callable[[snapshot, result], None]``
                invoked after ``display_result`` (still inside the ``if not
                config.quiet`` block conceptually). Used by checks that need
                an extra display call — e.g. partition bars for ``disk``, port
                tables for ``ports_analysis``.
            **check_kwargs: forwarded to ``check_fn`` after ``snapshot`` and ``t``.
        """
        if not _section_enabled(section, config, profile):
            return
        if skip_if is not None and skip_if(snapshot):
            return
        emit_section(section)
        result = check_fn(snapshot, t=t, **check_kwargs)
        if profile is not None:
            apply_profile(result, profile)
        engine.apply(result)
        display_result(result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if post_display is not None and not config.quiet:
            post_display(snapshot, result)
        if not config.quiet:
            print()

    # =========================================================================
    # GROUP 1 — FIREWALL & RÉSEAU
    # =========================================================================
    emit_group("firewall_network")

    # ---- CHECK 1 — Firewall status ----
    emit_section("firewall")

    fw_status  = FirewallStatus.from_system()
    fw_result  = check_firewall(fw_status, t=t)
    engine.apply(fw_result)
    display_result(fw_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)

    if fw_status.ufw_output:
        report.write_section("UFW STATUS")
        report.write_raw(fw_status.ufw_output)

    # ---- CHECK 2 — UFW rules ----
    ufw_numbered = fw_status.numbered_output
    ufw_verbose  = fw_status.ufw_output

    # Collect ports early so orphan-rule detection can cross-reference
    ports_snapshot        = PortsSnapshot.from_system()
    loopback_only_ports   = ports_snapshot.loopback_only_ports
    active_external_ports = ports_snapshot.active_external_ports
    all_listening_ports   = loopback_only_ports | active_external_ports

    emit_section("rules")

    rules_result = check_rules(
        ufw_verbose, ufw_numbered, t, fw_status.ipv6_ufw_enabled,
        listening_ports=all_listening_ports,
    )
    engine.apply(rules_result)
    display_result(rules_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)

    if config.verbose and ufw_verbose and not config.quiet:
        output.print_dim(t("rules.ufw_status_detail"))
        print()
        print(ufw_verbose)

    # ---- CHECK 40 — UFW logging level (skipped when UFW inactive — covered by check_firewall) ----
    if fw_status.active:
        emit_section("ufw_logging")

        ufw_logging_result = check_ufw_logging(fw_status, t=t)
        engine.apply(ufw_logging_result)
        display_result(ufw_logging_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)

    # ---- CHECK 46 — iptables / nftables (UFW inactive only) ----
    if not fw_status.active and _section_enabled("iptables_nft", config, profile):
        emit_section("iptables_nft")
        ipt_snapshot  = IptablesNftSnapshot.from_system()
        ipt_result    = check_iptables_nftables(ipt_snapshot, ufw_installed=fw_status.installed, t=t)
        engine.apply(ipt_result)
        display_result(ipt_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 2b — Firewall stack analysis ----
    emit_section("firewall_stack")

    stack_snapshot = FirewallStackSnapshot.from_system()
    stack_result   = check_firewall_stack(stack_snapshot, t=t)
    engine.apply(stack_result)
    display_result(stack_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
    if not config.quiet:
        print()

    # ---- CHECK 2c — Network context (interfaces + connections) ----
    emit_section("network_context")

    net_snapshot = NetworkContextSnapshot.from_system()
    net_result   = check_network_context(net_snapshot, t=t)
    engine.apply(net_result)
    display_result(net_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
    if not config.quiet:
        display_network_context(net_snapshot, t, output)

    # ---- CHECK 10 — IPv6 consistency ----
    ipv6_snapshot = IPv6Snapshot.from_system()
    _sec("ipv6", ipv6_snapshot, check_ipv6, ufw_active=fw_status.active)

    # =========================================================================
    # GROUP 2 — EXPOSITION & SERVICES
    # =========================================================================
    emit_group("exposure_services")

    # ---- CHECK 3 — Network services ----
    # Upgrade network_context to "ddns" when DDNS is active with open ports
    # so that service exposure deductions are scored at public-equivalent weight.
    ddns_snapshot = DdnsSnapshot.from_system()
    if network_context == "local":
        network_context = ddns_effective_context(
            ddns_snapshot, ufw_numbered, loopback_only_ports, active_external_ports,
        )

    # SSH exposure known here: used both in services loop (risk context note)
    # and later in CHECK 11 (ssh_exposed flag).
    _ssh_exposed = (
        network_context != "local"
        or fw_status.incoming_policy not in ("deny", "reject")
    )

    emit_section("services")

    snapshots     = ServiceSnapshot.collect(
        registry, ufw_rules=ufw_numbered, loopback_ports=loopback_only_ports,
        all_listening_ports=all_listening_ports,
    )
    audited_ports: set[str] = set()

    _SEVERITY_ORDER = {"critical": 0, "critique": 0, "high": 1, "élevé": 1,
                       "medium": 2, "moyen": 2, "low": 3, "faible": 3}

    def _snap_severity(snap) -> int:
        svc_id = (snap.service.label.lower()
                  .replace(" ", "_").replace("/", "_")
                  .replace("(", "").replace(")", ""))
        level = t(f"service_risk.{svc_id}.level").lower()
        for kw, rank in _SEVERITY_ORDER.items():
            if kw in level:
                return rank
        return 4  # inactive / unknown → last

    snapshots = sorted(snapshots, key=_snap_severity)

    for snap in snapshots:
        if not config.quiet:
            print_service_header(snap.label)
        report.write_raw(f"\n  > {snap.label}")
        if snap.is_active or (snap.installed and not snap.is_active and snap.service.is_high_or_critical):
            _risk_note = (
                t("service_risk.local_exposure_note")
                if snap.service.id == "ssh" and not _ssh_exposed
                else None
            )
            _port_note = None
            if snap.service.id == "ssh" and snap.ports and not any(
                p.startswith("22/") for p in snap.ports
            ):
                _port_note = t("service_risk.nonstandard_port_note")
            display_risk_context(snap.service.label, config.lang, t, report,
                                 context_note=_risk_note,
                                 is_local=(network_context == "local"))
            if _port_note and not config.quiet:
                print_info(_port_note)
        svc_result = check_single_service_display(
            snap, network_context, t, report, config.verbose,
            quiet=config.quiet, ufw_active=fw_status.active,
        )
        engine.apply(svc_result)
        audited_ports.update(snap.ports)

    if not config.quiet:
        display_services_panorama(registry, ufw_numbered, loopback_only_ports,
                                   all_listening_ports, config, t)

    # ---- CHECK 4 — Listening ports ----
    emit_section("ports_analysis")

    ports_result = check_ports(
        ports_snapshot,
        audited_ports=audited_ports,
        network_context=network_context,
        default_incoming_policy=fw_status.incoming_policy,
        ufw_active=fw_status.active,
        t=t,
    )
    engine.apply(ports_result)
    display_result(ports_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
    display_ports_overview(ports_snapshot, config, t, report, output)

    # ---- CHECK 5 — UFW log analysis ----
    if not config.quiet:
        print_section(t("sections.logs"))

    logs_snapshot = LogsSnapshot.from_system(log_days=config.log_days)
    display_geoip_notice(geoip2_status(), t, output)
    logs_result = check_logs(logs_snapshot, audited_ports=audited_ports, t=t)
    engine.apply(logs_result)
    display_log_results(logs_result, logs_snapshot, config, t, report)

    # ---- CHECK 6 — DDNS / external exposure ----
    emit_section("ddns")

    ddns_result   = check_ddns(
        ddns_snapshot, ufw_rules=ufw_numbered, t=t,
        loopback_ports=loopback_only_ports,
        active_ports=active_external_ports,
    )
    engine.apply(ddns_result)
    display_result(ddns_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
    # v0.4.4: the port list is now interpolated into the WARN message itself
    # (see ddns.py); we no longer print "→ 22/tcp" sub-items here.

    # ---- CHECK 7 — Docker ----
    emit_section("docker")

    docker_snapshot = DockerSnapshot.from_system()
    docker_result   = check_docker(docker_snapshot, network_context=network_context, t=t)
    engine.apply(docker_result)
    display_result(docker_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)

    if docker_snapshot.exposed_ports:
        output.print_dim(t("docker.exposed_ports") + " :")
        for port in docker_snapshot.exposed_ports:
            safe_name = output.sanitize(port.container_name, max_len=128)
            output.print_dim(
                f"  {safe_name}: {port.port_proto} → "
                f"{port.container_port}/{port.proto}"
            )
    if not config.quiet:
        print()

    # ---- CHECK 8 — Virtualisation ----
    emit_section("virtualization")

    virt_snapshot = VirtSnapshot.from_system()
    virt_result   = check_virtualization(virt_snapshot, t=t)
    engine.apply(virt_result)
    display_result(virt_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
    if not config.quiet:
        print()

    # ---- CHECK 24 — Samba security audit ----
    samba_snapshot = SambaSnapshot.from_system()
    _sec("samba", samba_snapshot, check_samba,
         skip_if=lambda s: not s.installed)

    # ---- CHECK 26 — SMTP local exposure ----
    smtp_snapshot = SmtpSnapshot.from_system()
    _sec("smtp", smtp_snapshot, check_smtp)

    # =========================================================================
    # GROUP 3 — CONTRÔLE D'ACCÈS
    # =========================================================================
    emit_group("access_control")

    # ---- CHECK 11 — SSH security ----
    ssh_snapshot = SSHSnapshot.from_system()
    _sec("ssh", ssh_snapshot, check_ssh, ssh_exposed=_ssh_exposed)

    # ---- CHECK 42 — SSH auth.log login analysis ----
    auth_log_snapshot = AuthLogSnapshot.from_system()
    _sec("auth_log", auth_log_snapshot, check_auth_log)

    # ---- CHECK 17 — User account audit ----
    user_accounts_snapshot = UserAccountsSnapshot.from_system()
    _sec("user_accounts", user_accounts_snapshot, check_user_accounts)

    # ---- CHECK 18 — Password policy audit ----
    password_policy_snapshot = PasswordPolicySnapshot.from_system()
    _sec("password_policy", password_policy_snapshot, check_password_policy)

    # ---- CHECK 12 — Sensitive file permissions + sudoers ----
    file_perms_snapshot = FilePermsSnapshot.from_system()
    _sec("file_perms", file_perms_snapshot, check_file_perms)

    # =========================================================================
    # GROUP 4 — DURCISSEMENT SYSTÈME
    # =========================================================================
    emit_group("system_hardening")

    # ---- CHECK 9 — System hardening ----
    hardening_snapshot = HardeningSnapshot.from_system()
    _sec("hardening", hardening_snapshot, check_hardening)

    # ---- CHECK 36 — Kernel hardening ----
    kernel_hardening_snapshot = KernelHardeningSnapshot.from_system()
    _sec("kernel_hardening", kernel_hardening_snapshot, check_kernel_hardening)

    # ---- CHECK 37 — SUID/SGID binary audit ----
    suid_snapshot = SuidSnapshot.from_system(
        user_whitelist=user_config.get_suid_whitelist() if user_config is not None else []
    )
    _sec("suid_audit", suid_snapshot, check_suid_audit)

    # ---- CHECK 38 — Docker container security audit ----
    docker_audit_snapshot = DockerAuditSnapshot.from_system()
    _sec("docker_audit", docker_audit_snapshot, check_docker_audit,
         skip_if=lambda s: not s.docker_installed)

    # ---- CHECK 39 — Log rotation & system journaling ----
    log_rotation_snapshot = LogRotationSnapshot.from_system()
    _sec("log_rotation", log_rotation_snapshot, check_log_rotation)

    # ---- CHECK 14 — Kernel module audit ----
    kernel_modules_snapshot = KernelModulesSnapshot.from_system()
    _sec("kernel_modules", kernel_modules_snapshot, check_kernel_modules, profile_name=_pname)

    # ---- CHECK 34 — MAC policy (AppArmor / SELinux) ----
    mac_policy_snapshot = MacPolicySnapshot.from_system()
    _sec("mac_policy", mac_policy_snapshot, check_mac_policy, profile_name=_pname)

    # ---- CHECK 15 — Cron job audit ----
    cron_audit_snapshot = CronAuditSnapshot.from_system()
    _sec("cron_audit", cron_audit_snapshot, check_cron_audit)

    # ---- CHECK 16 — Service state audit ----
    services_state_snapshot = ServicesStateSnapshot.from_system()
    _sec("services_state", services_state_snapshot, check_services_state)

    # ---- CHECK 13 — System updates ----
    updates_snapshot = UpdatesSnapshot.from_system()
    _sec("updates", updates_snapshot, check_updates, profile_name=_pname)

    # ---- CHECK 41 — System umask ----
    umask_snapshot = UmaskSnapshot.from_system()
    _sec("umask", umask_snapshot, check_umask)

    # ---- CHECK 23 — Memory & Swap ----
    memory_snapshot = MemorySnapshot.from_system()
    _sec("memory", memory_snapshot, check_memory, profile_name=_pname)

    # ---- CHECK 22 — Disk health (SMART + partition usage) ----
    disk_snapshot = DiskSnapshot.from_system()
    _sec("disk", disk_snapshot, check_disk,
         post_display=lambda snap, _r: display_disk_partitions(snap, t, output))

    # =========================================================================
    # GROUP 5 — DÉTECTION & SANTÉ
    # =========================================================================
    emit_group("detection_health")

    # ---- CHECK 35 — Backup solution ----
    backup_snapshot = BackupSnapshot.from_system()
    _sec("backup", backup_snapshot, check_backup, profile_name=_pname)

    # ---- CHECK 31 — Linux Audit Framework (auditd) ----
    auditd_snapshot = AuditdSnapshot.from_system()
    _sec("auditd", auditd_snapshot, check_auditd, profile_name=_pname)

    # ---- CHECK 32 — Secure Boot ----
    secure_boot_snapshot = SecureBootSnapshot.from_system()
    _sec("secure_boot", secure_boot_snapshot, check_secure_boot, profile_name=_pname)

    # ---- CHECK 29 — Fail2ban intrusion prevention ----
    fail2ban_snapshot = Fail2banSnapshot.from_system()
    _sec("fail2ban", fail2ban_snapshot, check_fail2ban)

    # ---- CHECK 25 — ClamAV antivirus audit ----
    clamav_snapshot = ClamAVSnapshot.from_system()
    _sec("clamav", clamav_snapshot, check_clamav)

    # ---- CHECK 33 — File integrity monitoring (AIDE / Tripwire) ----
    file_integrity_snapshot = FileIntegritySnapshot.from_system()
    _sec("file_integrity", file_integrity_snapshot, check_file_integrity)

    # ---- CHECK 30 — Rootkit & integrity scan ----
    rootkit_snapshot = RootkitSnapshot.from_system()
    _sec("rootkit", rootkit_snapshot, check_rootkit)

    # ---- CHECK 28 — NTP time synchronisation ----
    ntp_snapshot = NtpSnapshot.from_system()
    _sec("ntp", ntp_snapshot, check_ntp)

    # ---- CHECK 19 — Desktop application audit ----
    desktop_snapshot = DesktopAppsSnapshot.from_system()
    _sec("desktop_apps", desktop_snapshot, check_desktop_apps,
         skip_if=lambda s: not s.detected)

    # ---- CHECK 45 — Firmware & microcode audit ----
    firmware_snapshot = FirmwareSnapshot.from_system()
    _sec("firmware", firmware_snapshot, check_firmware)

    # ---- CHECK 44 — Systemd timers audit ----
    timers_snapshot = SystemdTimersSnapshot.from_system()
    _sec("systemd_timers", timers_snapshot, check_systemd_timers)

    # ---- CHECK 43 — TLS/SSL certificate expiry ----
    ssl_certs_snapshot = SslCertsSnapshot.from_system()
    _sec("ssl_certs", ssl_certs_snapshot, check_ssl_certs)

    # ---- Plugin checks (user-defined, checks.d/) ----
    for plugin in load_plugin_checks():
        if profile is not None and profile.should_skip_section(plugin.name.lower()):
            continue
        if not config.quiet:
            print_section(plugin.name)
        report.write_section(plugin.name)
        plugin_result = plugin.run(t)
        if profile is not None:
            apply_profile(plugin_result, profile)
        engine.apply(plugin_result)
        display_result(plugin_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    return ChecksResult(
        snapshots=snapshots,
        ports_snapshot=ports_snapshot,
        stack_snapshot=stack_snapshot,
        net_snapshot=net_snapshot,
        hardening_snapshot=hardening_snapshot,
        ipv6_snapshot=ipv6_snapshot,
        fw_active=fw_status.active,
        fw_policy=fw_status.incoming_policy or "unknown",
        network_context=network_context,
    )
