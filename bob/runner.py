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
from bob.checks.systemd_hardening import ServiceHardeningSnapshot, check_service_hardening
from bob.checks.container_security import ContainerSecuritySnapshot, check_container_security
from bob.checks.socket_units import SocketUnitsSnapshot, check_socket_units
from bob.checks.cloud_context import CloudContextSnapshot, check_cloud_context
from bob.checks.firmware import FirmwareSnapshot, check_firmware
from bob.plugin_checks import load_plugin_checks


# v0.9.0 D-2: single source of truth for both filterable and always-on
# sections. Pre-v0.9.0, two parallel tuples (``_ALL_SECTIONS`` for filterable
# and ``_ALWAYS_ON_SECTIONS`` for unconditional sections) had to be kept in
# sync manually: adding a section meant remembering which tuple to update,
# and the validation logic plus the ``bob --check=list`` rendering had to
# union the two. The unified ``_SECTIONS`` tuple carries an ``always_on``
# flag per entry, and the back-compat derived views ``_ALL_SECTIONS`` /
# ``_ALWAYS_ON_SECTIONS`` are computed from it for existing consumers
# (``bob/__main__.py`` + tests + the bash-completion sync guard).
#
# M-7 (v0.7.0) context — always-on sections (``firewall``, ``ports``,
# ``services``, ``firewall_rules``, ``ufw_logging``, ``firewall_drivers``,
# ``network_context``, ``ddns``, ``docker``, ``virtualization``) are not
# gated by ``_section_enabled``; ``--check``/``--skip`` warn but have no
# effect on them. Pre-fix, ``--check=firewall`` raised a fatal
# "matches no known section" error even though ``bob --check=list``
# advertises these as "core checks always run".


class _Section(NamedTuple):
    """v0.9.0 D-2: single section descriptor unifying the v0.5.x-v0.8.x split."""
    name:      str
    always_on: bool


_SECTIONS: tuple[_Section, ...] = (
    # Filterable sections (gated by --check / --skip / profile)
    _Section("ipv6",              False),
    _Section("smtp",              False),
    _Section("ssh",               False),
    _Section("auth_log",          False),
    _Section("user_accounts",     False),
    _Section("password_policy",   False),
    _Section("file_perms",        False),
    _Section("hardening",         False),
    _Section("kernel_hardening",  False),
    _Section("suid_audit",        False),
    _Section("docker_hardening",  False),
    _Section("log_rotation",      False),
    _Section("kernel_modules",    False),
    _Section("mac_policy",        False),
    _Section("cron",              False),
    _Section("services_health",   False),
    _Section("systemd_hardening", False),
    _Section("container_security", False),
    _Section("socket_units",      False),
    _Section("cloud_context",     False),
    _Section("updates",           False),
    _Section("umask",             False),
    _Section("memory",            False),
    _Section("disk",              False),
    _Section("backup",            False),
    _Section("auditd",            False),
    _Section("secure_boot",       False),
    _Section("fail2ban",          False),
    _Section("clamav",            False),
    _Section("file_integrity",    False),
    _Section("rootkit",           False),
    _Section("ntp",               False),
    _Section("systemd_timers",    False),
    _Section("ssl_certs",         False),
    _Section("firmware",          False),
    _Section("firewall_iptables", False),
    _Section("samba",             False),
    _Section("desktop_apps",      False),
    # Always-on sections (run unconditionally; --check / --skip warn)
    _Section("firewall",          True),
    _Section("firewall_rules",    True),
    _Section("ufw_logging",       True),
    _Section("firewall_drivers",  True),
    _Section("network_context",   True),
    _Section("services",          True),
    _Section("ports",             True),
    _Section("ddns",              True),
    _Section("docker",            True),
    _Section("virtualization",    True),
)

# Back-compat derived views. Existing consumers (``bob/__main__.py``,
# ``tests/test_cli.py``, ``tests/test_v082_items.py``,
# ``tests/test_v082_bash_completion.py``) keep referring to these names —
# the views are immutable tuples built once at import time. New code
# should consume ``_SECTIONS`` directly to access the ``always_on`` flag.
_ALL_SECTIONS:        tuple[str, ...] = tuple(s.name for s in _SECTIONS if not s.always_on)
_ALWAYS_ON_SECTIONS:  tuple[str, ...] = tuple(s.name for s in _SECTIONS if s.always_on)

# v0.9.0 D-1: section renames. When a user passes one of these legacy names
# via ``--check`` or ``--skip``, the validator emits a hard migration error
# pointing at the new canonical name. The map is read-only and consulted
# only by ``validate_check_filters``; ``_section_enabled`` works exclusively
# against ``_ALL_SECTIONS`` + ``_ALWAYS_ON_SECTIONS`` so the legacy names
# cannot accidentally re-enable a section.
#
# v0.9.2: extracted to ``bob/_v090_renames.py`` so ``bob.compare`` can also
# consume it for the baseline migration shim without forming a circular
# import (runner already imports from compare). Imported here under the
# legacy name ``_RENAMED_SECTIONS_V090`` for back-compat with any out-of-tree
# script that happened to reference it.
from bob._v090_renames import SECTION_RENAMES_V090 as _RENAMED_SECTIONS_V090


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
    string when every --check token matches neither a filterable nor an
    always-on section (nothing would run beyond the always-on core).
    Returns None when all is well.

    M-7 (v0.7.0): always-on section names (firewall, rules, ports_analysis…)
    are now recognised — they previously triggered "matches no known section"
    warnings + a fatal error on ``--check=firewall``.
    """
    def _matches_filterable(tok: str) -> bool:
        return any(s == tok or s.startswith(tok) for s in _ALL_SECTIONS)

    def _matches_always_on(tok: str) -> bool:
        return any(s == tok or s.startswith(tok) for s in _ALWAYS_ON_SECTIONS)

    def _suggest(tok: str) -> str:
        from bob import i18n
        all_known = _ALL_SECTIONS + _ALWAYS_ON_SECTIONS
        matches = difflib.get_close_matches(tok, all_known, n=3, cutoff=0.5)
        if matches:
            return i18n.t("cli.runner.suggest_did_you_mean",
                          matches=", ".join(matches))
        return i18n.t("cli.runner.suggest_run_list")

    # I-2 pass 8 (v0.8.1 audit): the validate_check_filters warning sites
    # (3 hardcoded "Warning:" prefixes) were left un-i18n'd when T10
    # i18n'd the cli.error.* family in __main__.py. The runner runs after
    # ``i18n.init`` (called at __main__.py:184) so accessing ``i18n.t``
    # directly is safe here. We use the locale prefix value, which since
    # I-2 pass 7 includes its own trailing ``": "`` / ``" : "`` for
    # consistent FR typography.
    from bob import i18n

    # v0.9.0 D-1: detect legacy section names and fail loud with a clear
    # migration hint. We surface the rename BEFORE the generic
    # ``check_no_match`` warning so the user sees the precise instruction
    # instead of a fuzzy "did you mean" guess that may or may not nail it.
    if config.check_only:
        renamed = sorted(
            tok for tok in config.check_only if tok in _RENAMED_SECTIONS_V090
        )
        if renamed:
            for tok in renamed:
                new = _RENAMED_SECTIONS_V090[tok]
                print(
                    f"{i18n.t('cli.error.warning_prefix')}"
                    + i18n.t("cli.runner.section_renamed",
                             old=repr(tok), new=repr(new)),
                    file=sys.stderr,
                )
            return i18n.t("cli.runner.section_renamed_fatal")

    if config.check_only:
        bad = sorted(
            tok for tok in config.check_only
            if not (_matches_filterable(tok) or _matches_always_on(tok))
        )
        if bad:
            for tok in bad:
                print(
                    f"{i18n.t('cli.error.warning_prefix')}"
                    + i18n.t("cli.runner.check_no_match",
                             tok=repr(tok), suggestion=_suggest(tok)),
                    file=sys.stderr,
                )
            # Fatal only when NO token matches anything — always-on tokens
            # still count as "something will run".
            if len(bad) == len(config.check_only):
                return i18n.t("cli.runner.check_no_match_fatal")

    if config.skip_checks:
        # v0.9.0 D-1: mirror the renaming guard for --skip so the user gets
        # the same precise migration error.
        renamed = sorted(
            tok for tok in config.skip_checks if tok in _RENAMED_SECTIONS_V090
        )
        if renamed:
            for tok in renamed:
                new = _RENAMED_SECTIONS_V090[tok]
                print(
                    f"{i18n.t('cli.error.warning_prefix')}"
                    + i18n.t("cli.runner.section_renamed",
                             old=repr(tok), new=repr(new)),
                    file=sys.stderr,
                )
            return i18n.t("cli.runner.section_renamed_fatal")

        for tok in sorted(config.skip_checks):
            # v0.9.0 D-1: check always-on BEFORE filterable. After the section
            # renumber (`firewall_iptables` / `firewall_rules` / `firewall_drivers`
            # added to ``_ALL_SECTIONS``), the token ``firewall`` matches a
            # filterable via the startswith rule, which would silence the
            # "no effect" warning that operators legitimately expect for
            # ``--skip=firewall``. Exact always-on matches now take precedence
            # over prefix filterable matches.
            if tok in _ALWAYS_ON_SECTIONS:
                # --skip on an always-on section is a no-op: warn the user
                # rather than silently swallow their intent.
                print(
                    f"{i18n.t('cli.error.warning_prefix')}"
                    + i18n.t("cli.runner.skip_no_effect", tok=repr(tok)),
                    file=sys.stderr,
                )
                continue
            if _matches_filterable(tok):
                continue
            if _matches_always_on(tok):
                # Prefix-matched always-on (rare — only when the user types a
                # prefix that ONLY appears in ``_ALWAYS_ON_SECTIONS``). Same
                # warning, but reached via the fallback path.
                print(
                    f"{i18n.t('cli.error.warning_prefix')}"
                    + i18n.t("cli.runner.skip_no_effect", tok=repr(tok)),
                    file=sys.stderr,
                )
                continue
            print(
                f"{i18n.t('cli.error.warning_prefix')}"
                + i18n.t("cli.runner.skip_no_match",
                         tok=repr(tok), suggestion=_suggest(tok)),
                file=sys.stderr,
            )

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
            snapshot: either a pre-collected snapshot object, or a zero-arg
                callable returning one (``XxxSnapshot.from_system``). A
                callable is invoked *after* the ``_section_enabled`` gate, so
                a section excluded by ``--check`` / ``--skip`` / the active
                profile costs nothing — pre-v0.13.3 every snapshot was
                collected eagerly at the call site and `--check=ssh` still
                paid for all 47 checks. No snapshot class produces a callable
                instance, so ``callable()`` distinguishes the two without
                ambiguity.
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
        if callable(snapshot):
            snapshot = snapshot()
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

    emit_section("firewall_rules")

    rules_result = check_rules(
        ufw_verbose, ufw_numbered, t, fw_status.ipv6_ufw_enabled,
        listening_ports=all_listening_ports,
    )
    engine.apply(rules_result)
    display_result(rules_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)

    if config.verbose and ufw_verbose and not config.quiet:
        output.print_dim(t("firewall_rules.ufw_status_detail"))
        print()
        print(ufw_verbose)

    # ---- CHECK 40 — UFW logging level (skipped when UFW inactive — covered by check_firewall) ----
    if fw_status.active:
        emit_section("ufw_logging")

        ufw_logging_result = check_ufw_logging(fw_status, t=t)
        engine.apply(ufw_logging_result)
        display_result(ufw_logging_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)

    # ---- CHECK 46 — iptables / nftables (UFW inactive only) ----
    if not fw_status.active and _section_enabled("firewall_iptables", config, profile):
        emit_section("firewall_iptables")
        ipt_snapshot  = IptablesNftSnapshot.from_system()
        ipt_result    = check_iptables_nftables(ipt_snapshot, ufw_installed=fw_status.installed, t=t)
        engine.apply(ipt_result)
        display_result(ipt_result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
        if not config.quiet:
            print()

    # ---- CHECK 2b — Firewall stack analysis ----
    emit_section("firewall_drivers")

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
    emit_section("ports")

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
    display_geoip_notice(geoip2_status(), t, output, quiet=config.quiet)
    logs_result, logs_report = check_logs(logs_snapshot, audited_ports=audited_ports, t=t)
    engine.apply(logs_result)
    display_log_results(logs_result, logs_snapshot, logs_report, config, t, report)

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

    # I-1 (v0.7.4): gate the exposed-ports block on --quiet to honour the
    # `bob -q` empty-stdout contract. Pre-v0.7.4 this block printed even in
    # quiet mode whenever Docker containers exposed ports.
    if docker_snapshot.exposed_ports and not config.quiet:
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
    _sec("docker_hardening", docker_audit_snapshot, check_docker_audit,
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
    _sec("cron", cron_audit_snapshot, check_cron_audit)

    # ---- CHECK 16 — Service state audit ----
    _sec("services_health", ServicesStateSnapshot.from_system, check_services_state)

    # ---- CHECK 46 — Service hardening (systemd-analyze security) ----
    _sec("systemd_hardening", ServiceHardeningSnapshot.from_system, check_service_hardening)

    # ---- CHECK 47 — Container self-hardening posture (only inside a container) ----
    container_security_snapshot = ContainerSecuritySnapshot.from_system()
    _sec("container_security", container_security_snapshot, check_container_security,
         skip_if=lambda s: not s.in_container)

    # ---- CHECK 48 — Orphan / failed systemd socket units ----
    _sec("socket_units", SocketUnitsSnapshot.from_system, check_socket_units)

    # ---- CHECK 49 — Host-side cloud context (only on a cloud instance) ----
    cloud_context_snapshot = CloudContextSnapshot.from_system()
    _sec("cloud_context", cloud_context_snapshot, check_cloud_context,
         skip_if=lambda s: not s.is_cloud)

    # ---- CHECK 13 — System updates ----
    _sec("updates", UpdatesSnapshot.from_system, check_updates, profile_name=_pname)

    # ---- CHECK 41 — System umask ----
    umask_snapshot = UmaskSnapshot.from_system()
    _sec("umask", umask_snapshot, check_umask)

    # ---- CHECK 23 — Memory & Swap ----
    memory_snapshot = MemorySnapshot.from_system()
    _sec("memory", memory_snapshot, check_memory, profile_name=_pname)

    # ---- CHECK 22 — Disk health (SMART + partition usage) ----
    _sec("disk", DiskSnapshot.from_system, check_disk,
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
