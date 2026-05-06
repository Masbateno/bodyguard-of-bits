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
from bob.report import AuditReport
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
    "ssl_certs", "firmware", "iptables_nft",
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
    report: AuditReport,
    registry: ServiceRegistry,
    network_context: str,
    profile: AuditProfile | None = None,
    prev_recurrence: "dict[str, int] | None" = None,
) -> ChecksResult:
    """Run all audit checks in sequence."""
    _pr: dict[str, int] = prev_recurrence or {}

    # =========================================================================
    # GROUP 1 — FIREWALL & RÉSEAU
    # =========================================================================
    if not config.quiet:
        print_group(t("groups.firewall_network"))
    report.write_group(t("groups.firewall_network"))

    # ---- CHECK 1 — Firewall status ----
    if not config.quiet:
        print_section(t("sections.firewall"))
    report.write_section(t("sections.firewall"))

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

    if not config.quiet:
        print_section(t("sections.rules"))
    report.write_section(t("sections.rules"))

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

    # ---- CHECK 40 — UFW logging level ----
    if not config.quiet:
        print_section(t("sections.ufw_logging"))
    report.write_section(t("sections.ufw_logging"))

    ufw_logging_result = check_ufw_logging(fw_status, t=t)
    engine.apply(ufw_logging_result)
    display_result(ufw_logging_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)

    # ---- CHECK 46 — iptables / nftables (UFW inactive only) ----
    if not fw_status.active and _section_enabled("iptables_nft", config, profile):
        if not config.quiet:
            print_section(t("sections.iptables_nft"))
        report.write_section(t("sections.iptables_nft"))
        ipt_snapshot  = IptablesNftSnapshot.from_system()
        ipt_result    = check_iptables_nftables(ipt_snapshot, ufw_installed=fw_status.installed, t=t)
        engine.apply(ipt_result)
        display_result(ipt_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 2b — Firewall stack analysis ----
    if not config.quiet:
        print_section(t("sections.firewall_stack"))
    report.write_section(t("sections.firewall_stack"))

    stack_snapshot = FirewallStackSnapshot.from_system()
    stack_result   = check_firewall_stack(stack_snapshot, t=t)
    engine.apply(stack_result)
    display_result(stack_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
    if not config.quiet:
        print()

    # ---- CHECK 2c — Network context (interfaces + connections) ----
    if not config.quiet:
        print_section(t("sections.network_context"))
    report.write_section(t("sections.network_context"))

    net_snapshot = NetworkContextSnapshot.from_system()
    net_result   = check_network_context(net_snapshot, t=t)
    engine.apply(net_result)
    display_result(net_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
    if not config.quiet:
        display_network_context(net_snapshot, t, output)

    # ---- CHECK 10 — IPv6 consistency ----
    ipv6_snapshot = IPv6Snapshot.from_system()
    if _section_enabled("ipv6", config, profile):
        if not config.quiet:
            print_section(t("sections.ipv6"))
        report.write_section(t("sections.ipv6"))
        ipv6_result = check_ipv6(ipv6_snapshot, ufw_active=fw_status.active, t=t)
        if profile is not None:
            apply_profile(ipv6_result, profile)
        engine.apply(ipv6_result)
        display_result(ipv6_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # =========================================================================
    # GROUP 2 — EXPOSITION & SERVICES
    # =========================================================================
    if not config.quiet:
        print_group(t("groups.exposure_services"))
    report.write_group(t("groups.exposure_services"))

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

    if not config.quiet:
        print_section(t("sections.services"))
    report.write_section(t("sections.services"))

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
    if not config.quiet:
        print_section(t("sections.ports_analysis"))
    report.write_section(t("sections.ports_analysis"))

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
    if not config.quiet:
        print_section(t("sections.ddns"))
    report.write_section(t("sections.ddns"))

    ddns_result   = check_ddns(
        ddns_snapshot, ufw_rules=ufw_numbered, t=t,
        loopback_ports=loopback_only_ports,
        active_ports=active_external_ports,
    )
    engine.apply(ddns_result)
    display_result(ddns_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
    for port in ddns_result.open_ports:
        output.print_dim(f"  → {port}")

    # ---- CHECK 7 — Docker ----
    if not config.quiet:
        print_section(t("sections.docker"))
    report.write_section(t("sections.docker"))

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
    if not config.quiet:
        print_section(t("sections.virtualization"))
    report.write_section(t("sections.virtualization"))

    virt_snapshot = VirtSnapshot.from_system()
    virt_result   = check_virtualization(virt_snapshot, t=t)
    engine.apply(virt_result)
    display_result(virt_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
    if not config.quiet:
        print()

    # ---- CHECK 24 — Samba security audit ----
    samba_snapshot = SambaSnapshot.from_system()
    if samba_snapshot.installed and _section_enabled("samba", config, profile):
        if not config.quiet:
            print_section(t("sections.samba"))
        report.write_section(t("sections.samba"))
        samba_result = check_samba(samba_snapshot, t=t)
        if profile is not None:
            apply_profile(samba_result, profile)
        engine.apply(samba_result)
        display_result(samba_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 26 — SMTP local exposure ----
    smtp_snapshot = SmtpSnapshot.from_system()
    if _section_enabled("smtp", config, profile):
        if not config.quiet:
            print_section(t("sections.smtp"))
        report.write_section(t("sections.smtp"))
        smtp_result = check_smtp(smtp_snapshot, t=t)
        if profile is not None:
            apply_profile(smtp_result, profile)
        engine.apply(smtp_result)
        display_result(smtp_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # =========================================================================
    # GROUP 3 — CONTRÔLE D'ACCÈS
    # =========================================================================
    if not config.quiet:
        print_group(t("groups.access_control"))
    report.write_group(t("groups.access_control"))

    # ---- CHECK 11 — SSH security ----
    ssh_snapshot = SSHSnapshot.from_system()
    if _section_enabled("ssh", config, profile):
        if not config.quiet:
            print_section(t("sections.ssh"))
        report.write_section(t("sections.ssh"))
        ssh_result = check_ssh(ssh_snapshot, t=t, ssh_exposed=_ssh_exposed)
        if profile is not None:
            apply_profile(ssh_result, profile)
        engine.apply(ssh_result)
        display_result(ssh_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 42 — SSH auth.log login analysis ----
    auth_log_snapshot = AuthLogSnapshot.from_system()
    if _section_enabled("auth_log", config, profile):
        if not config.quiet:
            print_section(t("sections.auth_log"))
        report.write_section(t("sections.auth_log"))
        auth_log_result = check_auth_log(auth_log_snapshot, t=t)
        engine.apply(auth_log_result)
        display_result(auth_log_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 17 — User account audit ----
    user_accounts_snapshot = UserAccountsSnapshot.from_system()
    if _section_enabled("user_accounts", config, profile):
        if not config.quiet:
            print_section(t("sections.user_accounts"))
        report.write_section(t("sections.user_accounts"))
        user_accounts_result = check_user_accounts(user_accounts_snapshot, t=t)
        if profile is not None:
            apply_profile(user_accounts_result, profile)
        engine.apply(user_accounts_result)
        display_result(user_accounts_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 18 — Password policy audit ----
    password_policy_snapshot = PasswordPolicySnapshot.from_system()
    if _section_enabled("password_policy", config, profile):
        if not config.quiet:
            print_section(t("sections.password_policy"))
        report.write_section(t("sections.password_policy"))
        password_policy_result = check_password_policy(password_policy_snapshot, t=t)
        if profile is not None:
            apply_profile(password_policy_result, profile)
        engine.apply(password_policy_result)
        display_result(password_policy_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 12 — Sensitive file permissions + sudoers ----
    file_perms_snapshot = FilePermsSnapshot.from_system()
    if _section_enabled("file_perms", config, profile):
        if not config.quiet:
            print_section(t("sections.file_perms"))
        report.write_section(t("sections.file_perms"))
        file_perms_result = check_file_perms(file_perms_snapshot, t=t)
        if profile is not None:
            apply_profile(file_perms_result, profile)
        engine.apply(file_perms_result)
        display_result(file_perms_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # =========================================================================
    # GROUP 4 — DURCISSEMENT SYSTÈME
    # =========================================================================
    if not config.quiet:
        print_group(t("groups.system_hardening"))
    report.write_group(t("groups.system_hardening"))

    # ---- CHECK 9 — System hardening ----
    hardening_snapshot = HardeningSnapshot.from_system()
    if _section_enabled("hardening", config, profile):
        if not config.quiet:
            print_section(t("sections.hardening"))
        report.write_section(t("sections.hardening"))
        hardening_result = check_hardening(hardening_snapshot, t=t)
        if profile is not None:
            apply_profile(hardening_result, profile)
        engine.apply(hardening_result)
        display_result(hardening_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 36 — Kernel hardening ----
    kernel_hardening_snapshot = KernelHardeningSnapshot.from_system()
    if _section_enabled("kernel_hardening", config, profile):
        if not config.quiet:
            print_section(t("sections.kernel_hardening"))
        report.write_section(t("sections.kernel_hardening"))
        kernel_hardening_result = check_kernel_hardening(kernel_hardening_snapshot, t=t)
        if profile is not None:
            apply_profile(kernel_hardening_result, profile)
        engine.apply(kernel_hardening_result)
        display_result(kernel_hardening_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 37 — SUID/SGID binary audit ----
    suid_snapshot = SuidSnapshot.from_system()
    if _section_enabled("suid_audit", config, profile):
        if not config.quiet:
            print_section(t("sections.suid_audit"))
        report.write_section(t("sections.suid_audit"))
        suid_result = check_suid_audit(suid_snapshot, t=t)
        if profile is not None:
            apply_profile(suid_result, profile)
        engine.apply(suid_result)
        display_result(suid_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 38 — Docker container security audit ----
    docker_audit_snapshot = DockerAuditSnapshot.from_system()
    if docker_audit_snapshot.docker_installed:
        if _section_enabled("docker_audit", config, profile):
            if not config.quiet:
                print_section(t("sections.docker_audit"))
            report.write_section(t("sections.docker_audit"))
            docker_audit_result = check_docker_audit(docker_audit_snapshot, t=t)
            if profile is not None:
                apply_profile(docker_audit_result, profile)
            engine.apply(docker_audit_result)
            display_result(docker_audit_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
            if not config.quiet:
                print()

    # ---- CHECK 39 — Log rotation & system journaling ----
    log_rotation_snapshot = LogRotationSnapshot.from_system()
    if _section_enabled("log_rotation", config, profile):
        if not config.quiet:
            print_section(t("sections.log_rotation"))
        report.write_section(t("sections.log_rotation"))
        log_rotation_result = check_log_rotation(log_rotation_snapshot, t=t)
        if profile is not None:
            apply_profile(log_rotation_result, profile)
        engine.apply(log_rotation_result)
        display_result(log_rotation_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 14 — Kernel module audit ----
    kernel_modules_snapshot = KernelModulesSnapshot.from_system()
    if _section_enabled("kernel_modules", config, profile):
        if not config.quiet:
            print_section(t("sections.kernel_modules"))
        report.write_section(t("sections.kernel_modules"))
        kernel_modules_result = check_kernel_modules(
            kernel_modules_snapshot, t=t,
            profile_name=profile.name if profile is not None else "server",
        )
        if profile is not None:
            apply_profile(kernel_modules_result, profile)
        engine.apply(kernel_modules_result)
        display_result(kernel_modules_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 34 — MAC policy (AppArmor / SELinux) ----
    mac_policy_snapshot = MacPolicySnapshot.from_system()
    if _section_enabled("mac_policy", config, profile):
        if not config.quiet:
            print_section(t("sections.mac_policy"))
        report.write_section(t("sections.mac_policy"))
        mac_policy_result = check_mac_policy(
            mac_policy_snapshot, t=t,
            profile_name=profile.name if profile is not None else "server",
        )
        if profile is not None:
            apply_profile(mac_policy_result, profile)
        engine.apply(mac_policy_result)
        display_result(mac_policy_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 15 — Cron job audit ----
    cron_audit_snapshot = CronAuditSnapshot.from_system()
    if _section_enabled("cron_audit", config, profile):
        if not config.quiet:
            print_section(t("sections.cron_audit"))
        report.write_section(t("sections.cron_audit"))
        cron_audit_result = check_cron_audit(cron_audit_snapshot, t=t)
        if profile is not None:
            apply_profile(cron_audit_result, profile)
        engine.apply(cron_audit_result)
        display_result(cron_audit_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 16 — Service state audit ----
    services_state_snapshot = ServicesStateSnapshot.from_system()
    if _section_enabled("services_state", config, profile):
        if not config.quiet:
            print_section(t("sections.services_state"))
        report.write_section(t("sections.services_state"))
        services_state_result = check_services_state(services_state_snapshot, t=t)
        if profile is not None:
            apply_profile(services_state_result, profile)
        engine.apply(services_state_result)
        display_result(services_state_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 13 — System updates ----
    updates_snapshot = UpdatesSnapshot.from_system()
    if _section_enabled("updates", config, profile):
        if not config.quiet:
            print_section(t("sections.updates"))
        report.write_section(t("sections.updates"))
        updates_result = check_updates(
            updates_snapshot, t=t,
            profile_name=profile.name if profile is not None else "server",
        )
        if profile is not None:
            apply_profile(updates_result, profile)
        engine.apply(updates_result)
        display_result(updates_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 41 — System umask ----
    umask_snapshot = UmaskSnapshot.from_system()
    if _section_enabled("umask", config, profile):
        if not config.quiet:
            print_section(t("sections.umask"))
        report.write_section(t("sections.umask"))
        umask_result = check_umask(umask_snapshot, t=t)
        if profile is not None:
            apply_profile(umask_result, profile)
        engine.apply(umask_result)
        display_result(umask_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 23 — Memory & Swap ----
    memory_snapshot = MemorySnapshot.from_system()
    if _section_enabled("memory", config, profile):
        if not config.quiet:
            print_section(t("sections.memory"))
        report.write_section(t("sections.memory"))
        memory_result = check_memory(
            memory_snapshot, t=t,
            profile_name=profile.name if profile is not None else "server",
        )
        if profile is not None:
            apply_profile(memory_result, profile)
        engine.apply(memory_result)
        display_result(memory_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 22 — Disk health (SMART + partition usage) ----
    disk_snapshot = DiskSnapshot.from_system()
    if _section_enabled("disk", config, profile):
        if not config.quiet:
            print_section(t("sections.disk"))
        report.write_section(t("sections.disk"))
        disk_result = check_disk(disk_snapshot, t=t)
        if profile is not None:
            apply_profile(disk_result, profile)
        engine.apply(disk_result)
        display_result(disk_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            display_disk_partitions(disk_snapshot, t, output)
            print()

    # =========================================================================
    # GROUP 5 — DÉTECTION & SANTÉ
    # =========================================================================
    if not config.quiet:
        print_group(t("groups.detection_health"))
    report.write_group(t("groups.detection_health"))

    # ---- CHECK 35 — Backup solution ----
    backup_snapshot = BackupSnapshot.from_system()
    if _section_enabled("backup", config, profile):
        if not config.quiet:
            print_section(t("sections.backup"))
        report.write_section(t("sections.backup"))
        backup_result = check_backup(
            backup_snapshot, t=t,
            profile_name=profile.name if profile is not None else "server",
        )
        if profile is not None:
            apply_profile(backup_result, profile)
        engine.apply(backup_result)
        display_result(backup_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 31 — Linux Audit Framework (auditd) ----
    auditd_snapshot = AuditdSnapshot.from_system()
    if _section_enabled("auditd", config, profile):
        if not config.quiet:
            print_section(t("sections.auditd"))
        report.write_section(t("sections.auditd"))
        auditd_result = check_auditd(
            auditd_snapshot, t=t,
            profile_name=profile.name if profile is not None else "server",
        )
        if profile is not None:
            apply_profile(auditd_result, profile)
        engine.apply(auditd_result)
        display_result(auditd_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 32 — Secure Boot ----
    secure_boot_snapshot = SecureBootSnapshot.from_system()
    if _section_enabled("secure_boot", config, profile):
        if not config.quiet:
            print_section(t("sections.secure_boot"))
        report.write_section(t("sections.secure_boot"))
        secure_boot_result = check_secure_boot(
            secure_boot_snapshot, t=t,
            profile_name=profile.name if profile is not None else "server",
        )
        if profile is not None:
            apply_profile(secure_boot_result, profile)
        engine.apply(secure_boot_result)
        display_result(secure_boot_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 29 — Fail2ban intrusion prevention ----
    fail2ban_snapshot = Fail2banSnapshot.from_system()
    if _section_enabled("fail2ban", config, profile):
        if not config.quiet:
            print_section(t("sections.fail2ban"))
        report.write_section(t("sections.fail2ban"))
        fail2ban_result = check_fail2ban(fail2ban_snapshot, t=t)
        if profile is not None:
            apply_profile(fail2ban_result, profile)
        engine.apply(fail2ban_result)
        display_result(fail2ban_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 25 — ClamAV antivirus audit ----
    clamav_snapshot = ClamAVSnapshot.from_system()
    if _section_enabled("clamav", config, profile):
        if not config.quiet:
            print_section(t("sections.clamav"))
        report.write_section(t("sections.clamav"))
        clamav_result = check_clamav(clamav_snapshot, t=t)
        if profile is not None:
            apply_profile(clamav_result, profile)
        engine.apply(clamav_result)
        display_result(clamav_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 33 — File integrity monitoring (AIDE / Tripwire) ----
    file_integrity_snapshot = FileIntegritySnapshot.from_system()
    if _section_enabled("file_integrity", config, profile):
        if not config.quiet:
            print_section(t("sections.file_integrity"))
        report.write_section(t("sections.file_integrity"))
        file_integrity_result = check_file_integrity(file_integrity_snapshot, t=t)
        if profile is not None:
            apply_profile(file_integrity_result, profile)
        engine.apply(file_integrity_result)
        display_result(file_integrity_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 30 — Rootkit & integrity scan ----
    rootkit_snapshot = RootkitSnapshot.from_system()
    if _section_enabled("rootkit", config, profile):
        if not config.quiet:
            print_section(t("sections.rootkit"))
        report.write_section(t("sections.rootkit"))
        rootkit_result = check_rootkit(rootkit_snapshot, t=t)
        if profile is not None:
            apply_profile(rootkit_result, profile)
        engine.apply(rootkit_result)
        display_result(rootkit_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 28 — NTP time synchronisation ----
    ntp_snapshot = NtpSnapshot.from_system()
    if _section_enabled("ntp", config, profile):
        if not config.quiet:
            print_section(t("sections.ntp"))
        report.write_section(t("sections.ntp"))
        ntp_result = check_ntp(ntp_snapshot, t=t)
        if profile is not None:
            apply_profile(ntp_result, profile)
        engine.apply(ntp_result)
        display_result(ntp_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 19 — Desktop application audit ----
    desktop_snapshot = DesktopAppsSnapshot.from_system()
    if desktop_snapshot.detected and _section_enabled("desktop_apps", config, profile):
        if not config.quiet:
            print_section(t("sections.desktop_apps"))
        report.write_section(t("sections.desktop_apps"))
        desktop_result = check_desktop_apps(desktop_snapshot, t=t)
        if profile is not None:
            apply_profile(desktop_result, profile)
        engine.apply(desktop_result)
        display_result(desktop_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 45 — Firmware & microcode audit ----
    firmware_snapshot = FirmwareSnapshot.from_system()
    if _section_enabled("firmware", config, profile):
        if not config.quiet:
            print_section(t("sections.firmware"))
        report.write_section(t("sections.firmware"))
        firmware_result = check_firmware(firmware_snapshot, t=t)
        if profile is not None:
            apply_profile(firmware_result, profile)
        engine.apply(firmware_result)
        display_result(firmware_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 44 — Systemd timers audit ----
    timers_snapshot = SystemdTimersSnapshot.from_system()
    if _section_enabled("systemd_timers", config, profile):
        if not config.quiet:
            print_section(t("sections.systemd_timers"))
        report.write_section(t("sections.systemd_timers"))
        timers_result = check_systemd_timers(timers_snapshot, t=t)
        if profile is not None:
            apply_profile(timers_result, profile)
        engine.apply(timers_result)
        display_result(timers_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 43 — TLS/SSL certificate expiry ----
    ssl_certs_snapshot = SslCertsSnapshot.from_system()
    if _section_enabled("ssl_certs", config, profile):
        if not config.quiet:
            print_section(t("sections.ssl_certs"))
        report.write_section(t("sections.ssl_certs"))
        ssl_certs_result = check_ssl_certs(ssl_certs_snapshot, t=t)
        if profile is not None:
            apply_profile(ssl_certs_result, profile)
        engine.apply(ssl_certs_result)
        display_result(ssl_certs_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

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
