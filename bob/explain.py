"""
--explain KEY implementation for BOB.

Prints a structured explanation for a given finding key:
  - what the finding means (title)
  - why it is a security risk (why)
  - how to fix it step by step (how)

Key normalisation strips file-specific middle segments so that e.g.
'file_perms.shadow.world_writable' resolves to 'file_perms.world_writable'.

Usage:
    from bob.explain import run_explain
    run_explain("ssh.password_auth", t)
    run_explain("list", t)          # prints all available keys

==============================================================================
STABLE PUBLIC API — `--explain` KEY FREEZE POLICY
==============================================================================

The keys exposed via `--explain` (and also surfaced as `Finding.key` /
`Deduction.key` in the JSON output) are part of BOB's public contract:

  - **No removal** — once a key is published in a release, it stays callable
    for the lifetime of the major schema version.
  - **No semantic shift** — a key always describes the same underlying check.
  - **Renames go through `EXPLAIN_KEY_ALIASES`** — the old name keeps working
    indefinitely (or at least one full major release cycle before the alias
    itself can be retired).
  - **Additions are free** — new keys can be added in any minor release.

Clients (scripts, dashboards, distro packagers) can rely on the key set and
match findings via `key`, locale-independent, across versions.
==============================================================================
"""

from __future__ import annotations

import logging
import re
import sys

from bob.cis_refs import get_cis_ref

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Available explain keys — organised by group
# ---------------------------------------------------------------------------

# Each entry: (group label, [keys])
_EXPLAIN_GROUPS: list[tuple[str, list[str]]] = [
    ("SSH — Authentication", [
        "ssh.password_auth",
        "ssh.permit_root_login",
        "ssh.permit_empty_passwords",
        "ssh.pubkey_auth_disabled",
        "ssh.no_passphrase",
        "ssh.dsa_key",
        "ssh.rsa_weak",
        "ssh.login_grace_time",
        "ssh.no_allow_users",
        "ssh.private_key_perms",
    ]),
    ("SSH — Access Control", [
        "ssh.max_auth_tries",
        "ssh.allow_tcp_forwarding",
        "ssh.x11_forwarding",
        "ssh.permit_user_env",
        "ssh.ignore_rhosts_disabled",
        "ssh.host_based_auth",
        "ssh.strict_modes_disabled",
        "ssh.client_strict_host_no",
    ]),
    ("SSH — Cryptography", [
        "ssh.weak_ciphers",
        "ssh.weak_macs",
        "ssh.weak_kex",
    ]),
    ("SSH — Authorized Keys", [
        "ssh.authorized_keys_perms",
        "ssh.authorized_keys_dsa",
        "ssh.authorized_keys_weak_key",
        "ssh.authorized_keys_no_restrictions",
        "ssh.authorized_keys_duplicate",
    ]),
    ("SSH — Client Config", [
        "ssh.dir_perms",
        "ssh.client_forward_agent",
        "ssh.client_known_hosts_devnull",
        "ssh.known_hosts_deprecated",
        "ssh.known_hosts_duplicate",
    ]),
    ("ClamAV", [
        "clamav.db_very_outdated",
        "clamav.db_outdated",
        "clamav.scan_very_old",
        "clamav.scan_old",
    ]),
    ("Samba", [
        "samba.smb1_enabled",
        "samba.null_passwords",
        "samba.guest_writable",
        "samba.guest_readonly",
        "samba.server_signing_disabled",
        "samba.map_to_guest",
    ]),
    ("Files & Access", [
        "file_perms.world_writable",
        "file_perms.too_permissive",
        "file_perms.sudoers_nopasswd_all",
        "file_perms.ssh_host_key_perms",
    ]),
    ("Updates", [
        "updates.security_pending",
        "updates.unattended_not_configured",
    ]),
    ("Hardening", [
        "hardening.rp_filter_disabled",
        "hardening.rp_filter_loose",
        "hardening.redirects_enabled",
        "hardening.log_martians_disabled",
        "hardening.tcp_syncookies_disabled",
        "hardening.accept_source_route_enabled",
        "hardening.accept_redirects_v6_enabled",
        "hardening.send_redirects_enabled",
        "hardening.protected_hardlinks_disabled",
        "hardening.protected_symlinks_disabled",
    ]),
    ("iptables / nftables", [
        "iptables_nft.no_backend",
        "iptables_nft.input_accept",
        "iptables_nft.forward_accept",
        "iptables_nft.no_loopback",
        "iptables_nft.no_conntrack",
    ]),
    ("MAC policy (AppArmor / SELinux)", [
        "mac_policy.apparmor_inactive",
        "mac_policy.apparmor_no_enforce",
        "mac_policy.apparmor_no_profiles",
        "mac_policy.no_enforce",
        "mac_policy.no_mac",
        "mac_policy.selinux_disabled",
    ]),
    ("Firewall stack integrity", [
        "firewall_stack.iptables_bypass",
        "firewall_stack.iptables_forward_bypass",
        "firewall_stack.nftables_parallel",
        "firewall_stack.ip_forward_enabled",
    ]),
    ("Docker", [
        "docker.iptables_bypass",
        "docker.exposed_port",
        "docker.exposed_bypass_ufw",
    ]),
    ("Network services", [
        "services.exposure.open_local",
        "services.state.active_disabled",
        "services.state.installed_inactive_critical",
    ]),
    ("Rootkit detection", [
        "rootkit.db_outdated",
        "rootkit.no_scan",
        "rootkit.scan_old",
    ]),
    ("Listening ports", [
        "ports.uncovered",
        "ports.uncovered_netbios",
    ]),
    ("NTP / time sync", [
        "ntp.not_enabled",
        "ntp.not_synchronized",
    ]),
    ("ClamAV (additional)", [
        "clamav.db_not_found",
        "clamav.freshclam_missing",
    ]),
    ("fail2ban", [
        "fail2ban.no_jails",
        "fail2ban.service_inactive",
    ]),
    ("DDNS / external exposure", [
        "ddns.found",
        "ddns.warn",
    ]),
    ("SSH (additional)", [
        "ssh.host_key_dsa",
        "ssh.not_active",
    ]),
    ("Updates (additional)", [
        "updates.apt_cache_stale",
        "updates.dist_upgrade_inconsistent",
    ]),
    ("Log rotation / journald", [
        "log_rotation.journald_volatile",
        "log_rotation.logrotate_missing",
    ]),
    ("UFW log analysis", [
        "logs.brute_found",
    ]),
    ("SMTP", [
        "smtp.exposed",
    ]),
    ("Backup", [
        "backup.no_backup",
    ]),
    ("Virtualisation (additional)", [
        "virt.snap_network",
    ]),
    ("Network context", [
        "network_context.sensitive_remote",
    ]),
    ("Kernel Modules", [
        "kernel_modules.risky_fs",
        "kernel_modules.risky_net",
    ]),
    ("Firewall Rules", [
        "rules.duplicate_found",
        "rules.open_any_found",
        "rules.ipv6_missing",
    ]),
    ("IPv6", [
        "ipv6.ufw_disabled_listeners_present",
        "ipv6.port_no_v6_rule",
        "ipv6.ufw_enabled_kernel_disabled",
    ]),
    ("Password Policy", [
        "password_policy.no_quality_module",
        "password_policy.weak_minlen",
        "password_policy.no_expiry",
    ]),
    ("User Accounts", [
        "user_accounts.uid_zero",
        "user_accounts.empty_password",
        "user_accounts.expired_account",
        "user_accounts.no_shadow",
    ]),
    ("Cron", [
        "cron_audit.pipe_to_shell",
        "cron_audit.world_writable",
    ]),
    ("Services", [
        "services_state.enabled_inactive",
    ]),
    ("Disk", [
        "disk.smart_failed",
        "disk.reallocated_sectors",
        "disk.pending_sectors",
        "disk.uncorrectable_errors",
        "disk.partition_critical",
    ]),
    ("Memory", [
        "memory.swappiness_ssd_wear",
        "memory.swappiness_unjustified",
    ]),
    ("Auditd", [
        "auditd.not_installed",
        "auditd.service_inactive",
        "auditd.no_rules",
        "auditd.missing_sensitive_rules",
    ]),
    ("Secure Boot", [
        "secure_boot.setup_mode",
        "secure_boot.disabled",
    ]),
    ("File Integrity", [
        "file_integrity.not_installed",
        "file_integrity.no_db",
        "file_integrity.no_check",
        "file_integrity.check_old",
    ]),
    ("Virtualisation", [
        "virt.bypass_risk",
    ]),
    ("Authentication Logs", [
        "auth_log.brute_force",
        "auth_log.public_login",
    ]),
    ("Umask", [
        "umask.world_writable",
        "umask.group_writable",
    ]),
    ("Firewall", [
        "prerequisites.ufw_missing",
        "firewall.inactive",
        "firewall.policy_open",
        "firewall.policy_unknown",
        "firewall.logging_off",
    ]),
    ("TLS / SSL Certificates", [
        "ssl_certs.expired",
        "ssl_certs.expiring_critical",
        "ssl_certs.expiring_soon",
    ]),
    ("Systemd Timers", [
        "systemd_timers.pipe_to_shell",
        "systemd_timers.world_writable",
        "systemd_timers.user_created_root",
    ]),
    ("Firmware", [
        "firmware.fwupd_updates",
        "firmware.microcode_missing",
    ]),
    ("Docker", [
        "docker_audit.privileged",
        "docker_audit.root_containers",
        "docker_audit.socket_mounted",
        "docker_audit.host_network",
    ]),
    ("Kernel Hardening", [
        "kernel_hardening.aslr_disabled",
        "kernel_hardening.aslr_conservative",
        "kernel_hardening.ptrace_unrestricted",
        "kernel_hardening.dmesg_exposed",
        "kernel_hardening.kptr_exposed",
        "kernel_hardening.suid_dump_all",
    ]),
    ("SUID / SGID", [
        "suid_audit.unexpected_suid",
        "suid_audit.unexpected_sgid",
    ]),
    ("Risk", [
        "risk.escalated_posture",
    ]),
]

# Flat list derived from groups — used externally and for key lookup
EXPLAIN_KEYS: list[str] = [k for _, keys in _EXPLAIN_GROUPS for k in keys]

# ---------------------------------------------------------------------------
# Key aliases — backward compatibility for renamed keys
# ---------------------------------------------------------------------------
#
# When a key is renamed, add an entry here:  old_name → new_name
# `normalize_key()` resolves aliases transparently so old scripts/clients
# referencing the legacy name keep working.
#
# Aliases never expire within the same major schema version. A future major
# bump (schema_version "2") MAY drop aliases, but each removal must be
# announced one full minor release in advance with a deprecation notice.
#
# Currently empty — no key has been renamed yet. This map exists so a future
# rename has a documented, tested migration path.
# ---------------------------------------------------------------------------

EXPLAIN_KEY_ALIASES: dict[str, str] = {
    # v0.5.5: services_state.py emits "services_state.service_inactive" but
    # the EXPLAIN_KEYS entry and locale block are named "enabled_inactive"
    # (different naming choices made independently — drift detected by the
    # hardening audit). JSON output keeps emitting "service_inactive" to
    # preserve the contract; `bob --explain` routes through the canonical
    # name via this alias.
    "services_state.service_inactive": "services_state.enabled_inactive",
}


# ---------------------------------------------------------------------------
# Key normalisation
# ---------------------------------------------------------------------------

# file_perms findings sometimes carry one or more intermediate path segments
# (e.g. 'file_perms.shadow.world_writable', 'file_perms.a.b.c.world_writable').
# Strip all intermediate segments so the explain lookup always resolves.
_NORMALIZE_RE = re.compile(
    r"^(file_perms)\.(?:[^.]+\.)+"
    r"(world_writable|too_permissive|ssh_host_key_perms"
    r"|sudoers_nopasswd_all|sudoers_nopasswd_specific)$"
)


def normalize_key(key: str) -> str:
    """
    Return the canonical explain-lookup key.

    Resolution order:
      1. Strip path-segment middles for ``file_perms.*`` keys
         (``file_perms.shadow.world_writable`` → ``file_perms.world_writable``).
      2. Resolve via ``EXPLAIN_KEY_ALIASES`` if the result is a legacy name
         (e.g. an alias added when a key was renamed).

    D-3 (v0.8.2): when an alias is hit, emit a one-time DEPRECATION warning
    pointing at the canonical name + the planned v0.9.0 retrait timeline so
    operators have explicit signal to migrate scripts / saved profiles /
    ignore.yml entries before the retrait lands. The warning is logger-only
    (not user-facing print) so machine-readable JSON / CSV consumers aren't
    polluted; operators see it in the BOB log stream + via ``--detailed``
    log files.

    Examples:
        'file_perms.shadow.world_writable'  →  'file_perms.world_writable'
        'ssh.password_auth'                 →  'ssh.password_auth'   (unchanged)
        '<legacy_name>'                     →  '<current_name>'      (via aliases)
    """
    m = _NORMALIZE_RE.match(key)
    if m:
        key = f"{m.group(1)}.{m.group(2)}"
    if key in EXPLAIN_KEY_ALIASES:
        canonical = EXPLAIN_KEY_ALIASES[key]
        _warn_alias_deprecation(key, canonical)
        return canonical
    return key


# D-3 (v0.8.2) — deprecation warning state. We emit at most one warning per
# alias per process so a watch-mode session or a CI job listing every alias
# doesn't spam the log stream. The set is process-local; subprocess /
# multi-process audits each get their own warning (acceptable trade-off
# for the simplicity of not threading state through the call chain).
_WARNED_ALIASES: set[str] = set()


def _warn_alias_deprecation(alias: str, canonical: str) -> None:
    """Emit a one-time deprecation warning for *alias* → *canonical*.

    Issued via ``logger.warning`` so it surfaces in the BOB log stream
    (``--detailed`` ``.log`` reports + journald when run via cron) but
    doesn't pollute the machine-readable JSON / CSV / Markdown outputs.

    Retrait timeline: scheduled for v0.9.0. Operators upgrading from
    v0.8.x have 1+ release cycles to migrate (mirrors the back-compat
    contract documented in SECURITY.md).
    """
    if alias in _WARNED_ALIASES:
        return
    _WARNED_ALIASES.add(alias)
    logger.warning(
        "DEPRECATION: explain key %r is a legacy alias for %r — the alias "
        "is scheduled for retrait in v0.9.0. Migrate scripts, saved "
        "profiles, and ignore.yml entries to the canonical name.",
        alias, canonical,
    )


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

_DIVIDER_WIDE  = "─" * 60
_DIVIDER_SHORT = "─" * 10

# Ordered profiles shown in the profile-variant display.
_EXPLAIN_PROFILES: tuple = ("server", "desktop", "container")


def _has_profile_variants(key: str, t) -> bool:
    """Return True if *key* has at least one profile-specific 'why' translation.

    Works with both the real i18n.t (returns "[key.path]" for missing keys)
    and mock translation functions used in tests (return the key path itself).
    """
    probe = t(f"explain.{key}.server.why")
    bare_key      = f"explain.{key}.server.why"
    bracketed_key = f"[{bare_key}]"
    return probe not in (bare_key, bracketed_key)


def _service_label_to_subkey(label: str) -> str:
    """M-3 (v0.8.1 audit) backward-compat alias for
    ``bob.registry.service_label_to_subkey``.

    Pre-M-3 this module-level helper held the canonical transform. The
    audit surfaced that ``display.py`` had two inline duplicates of the
    same logic so the "single source of truth" claim was false. The
    canonical implementation now lives in ``bob/registry.py`` next to the
    Service dataclass that owns the label semantics; this module-level
    alias remains so the T26 ``--explain`` dispatch + the dedicated
    ``tests/test_t11_t26_v081.py::TestT26LabelTransformIsCanonical``
    coverage continues to resolve.
    """
    from bob.registry import service_label_to_subkey
    return service_label_to_subkey(label)


def _render_dynamic_service_explain(norm: str, t) -> bool:
    """T26 (v0.8.1): render ``bob --explain services.exposed.<id>`` from the
    existing ``service_risk.<label_transform>.*`` locale block.

    Returns True if the dispatch succeeded (the caller must then return).
    Returns False when the service ID is unknown OR the matching
    ``service_risk.<subkey>.level`` locale entry is missing — caller falls
    back to the regular ``unknown_key`` error path.

    The lookup chain:

      1. Extract ``<svc_id>`` from ``services.exposed.<svc_id>`` (everything
         after the ``services.exposed.`` prefix).
      2. Resolve ``<svc_id>`` to ``Service.label`` via the service registry.
      3. Apply ``_service_label_to_subkey(label)`` to obtain the
         ``service_risk.*`` subkey (e.g. ``ssh`` → ``ssh_server``).
      4. Lookup ``service_risk.<subkey>.{level,exposure,threat}`` in locale.

    The rendered output mirrors the regular WHY/HOW shape so the operator
    sees a consistent ``--explain`` layout across static + dynamic keys.
    """
    svc_id = norm[len("services.exposed."):]
    if not svc_id:
        return False
    # Resolve the service label from the registry — failures fall back to
    # the unknown-key path. Lazy import avoids the registry → display →
    # explain circular reference that older versions of the codebase hit.
    try:
        from bob.registry import ServiceRegistry
        registry = ServiceRegistry.load()
        service  = registry.get(svc_id)
    except Exception:
        return False
    if service is None:
        return False

    subkey       = _service_label_to_subkey(service.label)
    level_key    = f"service_risk.{subkey}.level"
    exposure_key = f"service_risk.{subkey}.exposure"
    threat_key   = f"service_risk.{subkey}.threat"

    level_val    = t(level_key)
    # Detect missing locale entry — t() returns "[key]" (real i18n) or the
    # bare key (test stubs). Either way means the lookup failed.
    if level_val in (level_key, f"[{level_key}]"):
        return False

    exposure_val = t(exposure_key)
    threat_val   = t(threat_key)

    # Render synthetic explain output mirroring the uniform-profiles shape
    cis_val = get_cis_ref(norm)
    _key_label   = t("explain.ui.label_key")
    _title_label = t("explain.ui.label_title")
    _cis_label   = t("explain.ui.label_cis")

    # The title is constructed from the service label + risk level so the
    # operator sees both context elements at a glance.
    synthetic_title = f"{service.label} — {level_val}"

    # Use ``risk_context.*`` labels (already EN+FR translated, consumed by
    # ``display.py::display_risk_context``) instead of ``explain.ui.why/how``
    # since the synthetic dispatch surfaces service exposure + threat
    # (descriptive) rather than risk-cause + remediation-steps (the static
    # explain shape). Same labels the operator already sees in the audit
    # output's "Service network analysis" section, keeping the vocabulary
    # consistent across both surfaces.
    _exposure_label = t("risk_context.exposure")
    _threat_label   = t("risk_context.threat")

    print()
    print(_DIVIDER_WIDE)
    print(f"  {_key_label}:   {norm}")
    print(f"  {_title_label}: {synthetic_title}")
    if cis_val:
        print(f"  {_cis_label}:   {cis_val}")
    print(_DIVIDER_WIDE)
    print()
    print(_exposure_label.upper())
    print(_DIVIDER_SHORT)
    print(exposure_val)
    print()
    print(_threat_label.upper())
    print(_DIVIDER_SHORT)
    print(threat_val)
    print()
    _explain_scoring(norm, t)
    return True


def run_explain(key: str, t) -> None:
    """
    Print a structured explanation for *key*.

    Pass key="list" to print all available keys.

    Args:
        key: Finding key (e.g. "ssh.password_auth") or "list".
        t:   Translation function from bob.i18n.
    """
    key = key.strip()

    # ---- list mode ---------------------------------------------------------
    if key == "list":
        print(t("explain.ui.list_header"))
        for group_label, keys in _EXPLAIN_GROUPS:
            print()
            print(f"  ── {group_label} {'─' * max(0, 46 - len(group_label))}─")
            for k in keys:
                title = t(f"explain.{k}.title")
                print(f"    {k:<42}  {title}")
        print()
        return

    # ---- single key mode ---------------------------------------------------
    norm = normalize_key(key)

    title_val = t(f"explain.{norm}.title")
    why_val   = t(f"explain.{norm}.why")
    how_val   = t(f"explain.{norm}.how")

    # t() returns "[key]" in production or the bare key in test stubs
    _title_key = f"explain.{norm}.title"
    key_unknown = title_val in (_title_key, f"[{_title_key}]")

    # T26 (v0.8.1): dynamic dispatch for ``services.exposed.<svc_id>``.
    # The runtime emits ``services.exposed.<id>`` for each service in
    # bob/data/services.json. Pre-T26 the 38 service IDs had no
    # ``--explain`` coverage even though their risk content already
    # existed under ``service_risk.<label_transform>.{level,exposure,
    # threat}`` (added by v0.8.0 T4). T26 routes the lookup to that
    # content so any registered service becomes ``--explain``-able
    # without per-service maintenance.
    if key_unknown and norm.startswith("services.exposed."):
        rendered = _render_dynamic_service_explain(norm, t)
        if rendered:
            return

    if key_unknown:
        print(t("explain.ui.unknown_key", requested=repr(key)))
        print()
        print(t("explain.ui.unknown_hint"))
        return

    cis_val = get_cis_ref(norm)
    _key_label   = t("explain.ui.label_key")
    _title_label = t("explain.ui.label_title")
    _cis_label   = t("explain.ui.label_cis")

    print()
    print(_DIVIDER_WIDE)
    print(f"  {_key_label}:   {norm}")
    print(f"  {_title_label}: {title_val}")
    if cis_val:
        print(f"  {_cis_label}:   {cis_val}")
    print(_DIVIDER_WIDE)

    if _has_profile_variants(norm, t):
        # Profile-differentiated display — one section per profile
        for profile in _EXPLAIN_PROFILES:
            pwhy_key = f"explain.{norm}.{profile}.why"
            pwhy = t(pwhy_key)
            # Skip profiles with no translation (handles both mock and real i18n)
            if pwhy in (pwhy_key, f"[{pwhy_key}]"):
                continue

            # Use profile-specific how if present, otherwise fall back to generic
            phow_key = f"explain.{norm}.{profile}.how"
            phow_candidate = t(phow_key)
            phow = (
                phow_candidate
                if phow_candidate not in (phow_key, f"[{phow_key}]")
                else how_val
            )

            print()
            print(f"[ {profile} ]")
            print(_DIVIDER_SHORT)
            print(pwhy)
            print()
            print(t("explain.ui.how_title"))
            print(_DIVIDER_SHORT)
            print(phow)
            print()
    else:
        # Uniform risk across all profiles
        print()
        print(t("explain.ui.why_title"))
        print(_DIVIDER_SHORT)
        print(why_val)
        print()
        print(t("explain.ui.how_title"))
        print(_DIVIDER_SHORT)
        print(how_val)
        print()
        _note = "\u24d8  " + t("explain.ui.uniform_profiles_note")
        if sys.stdout.isatty():
            print(f"  \033[33m{_note}\033[0m")
        else:
            print(f"  {_note}")
        print()

    _explain_scoring(norm, t)


def _explain_scoring(key: str, t) -> None:
    """Print the scoring context for *key* (domain, tool cap, breakdown hint)."""
    from bob.domain_scores import key_to_domain, TOOL_CAPS, LABELS

    domain_id = key_to_domain(key)
    if not domain_id:
        return

    domain_label = LABELS.get(domain_id, domain_id.capitalize())
    prefix = key.split(".", 1)[0]
    tool_cap = TOOL_CAPS.get(prefix)

    print(t("explain.ui.scoring_title"))
    print("\u2500" * 40)
    print(f"  {t('explain.ui.scoring_domain')}   : {domain_label}")
    if tool_cap is not None:
        print(
            f"  {t('explain.ui.scoring_tool_cap')} : "
            + t("explain.ui.scoring_tool_cap_value", cap=tool_cap, prefix=prefix)
        )
    print(
        f"  {t('explain.ui.scoring_impact')}   : "
        + t("explain.ui.scoring_impact_value")
    )
    print()


# ---------------------------------------------------------------------------
# Interactive picker (curses TUI)
# ---------------------------------------------------------------------------

def _init_colors():
    """Initialise curses colour pairs (call once per wrapper session)."""
    import curses
    has_color = curses.has_colors()
    if has_color:
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_BLACK,  curses.COLOR_CYAN)    # selected row
        curses.init_pair(2, curses.COLOR_YELLOW, -1)                   # group header
        curses.init_pair(3, curses.COLOR_WHITE,  -1)                   # normal key row
        curses.init_pair(4, curses.COLOR_CYAN,   -1)                   # detail heading
        curses.init_pair(5, curses.COLOR_WHITE,  curses.COLOR_CYAN)   # top banner
    return has_color


def _detail_screen(stdscr, key: str, t) -> None:
    """
    Display the full explanation for *key* inside curses.
    ESC, q, or Enter returns to the picker.
    The text is word-wrapped to the terminal width and scrollable with ↑↓/PgUp/PgDn.
    """
    import curses
    import textwrap

    has_color = _init_colors()

    norm      = normalize_key(key)
    title_val = t(f"explain.{norm}.title")
    why_val   = t(f"explain.{norm}.why")
    how_val   = t(f"explain.{norm}.how")
    _cis = get_cis_ref(norm)
    _key_label   = t("explain.ui.label_key")
    _title_label = t("explain.ui.label_title")
    _cis_label   = t("explain.ui.label_cis")
    cis_line  = f"  {_cis_label}:   {_cis}" if _cis else ""

    def _build_lines(w: int) -> list[tuple[str, int]]:
        """Return (text, attr) pairs for each display line."""
        import curses as _c
        lines: list[tuple[str, int]] = []

        h_attr      = (_c.color_pair(4) | _c.A_BOLD) if has_color else _c.A_BOLD
        yellow_attr = _c.color_pair(2) if has_color else 0
        dim         = _c.A_DIM
        normal      = 0
        bold        = _c.A_BOLD

        lines.append((f"  {_key_label}:   {norm}", dim))
        lines.append((f"  {_title_label}: {title_val}", h_attr))
        if cis_line:
            lines.append((cis_line, dim))
        lines.append(("  " + "─" * min(56, w - 4), dim))

        if _has_profile_variants(norm, t):
            # One section per profile
            for profile in _EXPLAIN_PROFILES:
                pwhy_key = f"explain.{norm}.{profile}.why"
                pwhy = t(pwhy_key)
                if pwhy in (pwhy_key, f"[{pwhy_key}]"):
                    continue
                phow_key = f"explain.{norm}.{profile}.how"
                phow_candidate = t(phow_key)
                phow = (
                    phow_candidate
                    if phow_candidate not in (phow_key, f"[{phow_key}]")
                    else how_val
                )
                lines.append(("", normal))
                lines.append((f"  [ {profile} ]", bold))
                lines.append(("  " + "─" * 10, dim))
                for para in pwhy.split("\n"):
                    for wrapped in textwrap.wrap(para, w - 4) or [""]:
                        lines.append((f"  {wrapped}", normal))
                lines.append(("", normal))
                lines.append(("  " + t("explain.ui.how_title"), bold))
                lines.append(("  " + "─" * 10, dim))
                for para in phow.split("\n"):
                    for wrapped in textwrap.wrap(para, w - 4) or [""]:
                        lines.append((f"  {wrapped}", normal))
                lines.append(("", normal))
        else:
            lines.append(("", normal))
            lines.append(("  " + t("explain.ui.why_title"), bold))
            lines.append(("  " + "─" * 10, dim))
            for para in why_val.split("\n"):
                for wrapped in textwrap.wrap(para, w - 4) or [""]:
                    lines.append((f"  {wrapped}", normal))
            lines.append(("", normal))
            lines.append(("  HOW TO FIX", bold))
            lines.append(("  " + "─" * 10, dim))
            for para in how_val.split("\n"):
                for wrapped in textwrap.wrap(para, w - 4) or [""]:
                    lines.append((f"  {wrapped}", normal))
            lines.append(("", normal))
            lines.append(("  \u24d8  " + t("explain.ui.uniform_profiles_note"), yellow_attr))
            lines.append(("", normal))
        return lines

    scroll = 0

    while True:
        h, w    = stdscr.getmaxyx()
        content = _build_lines(w)
        body_h  = h - 2          # 1 header + 1 footer
        max_scroll = max(0, len(content) - body_h)

        stdscr.erase()

        # ── header ──────────────────────────────────────────────────────────
        header = f"  {norm}    " + t("explain.ui.detail_header") + "  "
        hdr_attr = (curses.color_pair(5) | curses.A_BOLD) if has_color else curses.A_REVERSE
        try:
            stdscr.addstr(0, 0, header.ljust(w - 1)[: w - 1], hdr_attr)
        except curses.error:
            pass

        # ── content ──────────────────────────────────────────────────────────
        for row in range(body_h):
            idx = scroll + row
            if idx >= len(content):
                break
            text, attr = content[idx]
            try:
                stdscr.addstr(row + 1, 0, text[: w - 1], attr)
            except curses.error:
                pass

        # ── footer ───────────────────────────────────────────────────────────
        pct    = int(100 * (scroll + body_h) / max(1, len(content)))
        pct    = min(pct, 100)
        footer = f"  {pct}%  ({'scroll up' if scroll > 0 else 'top'}) "
        try:
            stdscr.addstr(h - 1, 0, footer[: w - 1], curses.A_DIM)
        except curses.error:
            pass

        stdscr.refresh()

        ch = stdscr.getch()
        if ch == 27:                                   # ESC only — q stays in detail
            return
        elif ch == curses.KEY_UP:
            scroll = max(0, scroll - 1)
        elif ch == curses.KEY_DOWN:
            scroll = min(max_scroll, scroll + 1)
        elif ch == curses.KEY_PPAGE:
            scroll = max(0, scroll - body_h)
        elif ch == curses.KEY_NPAGE:
            scroll = min(max_scroll, scroll + body_h)


def _picker(stdscr, items: list, initial_selected: int, t) -> tuple:
    """
    Curses picker loop.  Returns (action, key_or_None, current_selected).
    action: "quit" | "view"

    Navigation is clamped — UP at the first key stays on the first key,
    DOWN at the last key stays on the last key (no circular wrap).
    """
    import curses  # local import — curses may not exist everywhere

    try:
        curses.curs_set(0)
    except curses.error:
        pass

    has_color = _init_colors()

    # Pre-compute indices of selectable (key) items for clamped navigation
    key_indices = [i for i, (tp, _) in enumerate(items) if tp == "key"]

    selected = initial_selected
    scroll   = 0

    while True:
        h, w = stdscr.getmaxyx()
        list_h = h - 2  # 1 header line + 1 footer line

        # Keep selected item in view
        if selected - scroll >= list_h:
            scroll = selected - list_h + 1
        if selected < scroll:
            # Also pull in the group header immediately above the selected key
            new_scroll = selected
            if new_scroll > 0 and items[new_scroll - 1][0] == "group":
                new_scroll -= 1
            scroll = new_scroll

        stdscr.erase()

        # ── header ──────────────────────────────────────────────────────────
        header = "  " + t("explain.ui.picker_header") + "  "
        hdr_attr = (curses.color_pair(5) | curses.A_BOLD) if has_color else curses.A_REVERSE
        try:
            stdscr.addstr(0, 0, header.ljust(w - 1)[: w - 1], hdr_attr)
        except curses.error:
            pass

        # ── items ────────────────────────────────────────────────────────────
        for row in range(list_h):
            idx = scroll + row
            if idx >= len(items):
                break
            item_type, item_val = items[idx]
            y = row + 1

            if item_type == "group":
                label = f"  ── {item_val} "
                attr  = (curses.color_pair(2) | curses.A_BOLD) if has_color else curses.A_BOLD
                try:
                    stdscr.addstr(y, 0, label[: w - 1], attr)
                except curses.error:
                    pass
            else:
                title = t(f"explain.{item_val}.title")
                if title == f"explain.{item_val}.title":
                    title = ""
                line  = f"    {item_val:<46} {title}"
                if idx == selected:
                    attr = (curses.color_pair(1) | curses.A_BOLD) if has_color else curses.A_REVERSE
                    padded = line[: w - 1].ljust(w - 1)
                    try:
                        stdscr.addstr(y, 0, padded[: w - 1], attr)
                    except curses.error:
                        pass
                else:
                    attr = curses.color_pair(3) if has_color else 0
                    try:
                        stdscr.addstr(y, 0, line[: w - 1], attr)
                    except curses.error:
                        pass

        # ── footer ───────────────────────────────────────────────────────────
        n_keys = len(key_indices)
        footer = "  " + t(
            "explain.ui.picker_footer",
            n_keys=n_keys,
            n_groups=len(_EXPLAIN_GROUPS),
        ) + " "
        try:
            stdscr.addstr(h - 1, 0, footer[: w - 1], curses.A_DIM)
        except curses.error:
            pass

        stdscr.refresh()

        ch = stdscr.getch()

        if ch in (ord("q"), ord("Q")):                 # q / Q → quit (ESC stays in picker)
            return ("quit", None, selected)

        elif ch == curses.KEY_UP:
            # Move to the previous selectable item — clamp at first
            pos = key_indices.index(selected) if selected in key_indices else 0
            if pos > 0:
                selected = key_indices[pos - 1]

        elif ch == curses.KEY_DOWN:
            # Move to the next selectable item — clamp at last
            pos = key_indices.index(selected) if selected in key_indices else 0
            if pos < len(key_indices) - 1:
                selected = key_indices[pos + 1]

        elif ch in (curses.KEY_ENTER, 10, 13):
            if items[selected][0] == "key":
                # Show detail screen inside curses, then return to picker
                _detail_screen(stdscr, items[selected][1], t)
                # Redraw picker on next iteration (no return — loop continues)


def run_explain_interactive(t) -> None:
    """
    Launch the interactive --explain picker (curses TUI).

    Falls back to plain `--explain list` output when stdout is not a TTY
    or when curses is unavailable (e.g. inside a pipe or SSH without TERM).
    """
    import curses

    if not sys.stdout.isatty():
        run_explain("list", t)
        return

    # Build flat item list: group headers + keys
    items: list[tuple[str, str]] = []
    for group_label, keys in _EXPLAIN_GROUPS:
        items.append(("group", group_label))
        for k in keys:
            items.append(("key", k))

    # Start on first selectable key
    selected = next(
        (i for i, (tp, _) in enumerate(items) if tp == "key"), 0
    )

    # Reduce ESC key delay from the default 1000ms to 25ms.
    # curses waits after ESC to distinguish escape sequences — 25ms is enough.
    import os
    os.environ.setdefault("ESCDELAY", "25")

    try:
        curses.wrapper(lambda scr: _picker(scr, items, selected, t))
    except (curses.error, OSError):
        # curses unavailable or terminal too small — fallback
        run_explain("list", t)
