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

# v0.16.3 — a top-level import despite bob/tui's "import lazily from non-TUI
# code" policy, and safe: bob/tui/__init__.py is a docstring and _keys.py
# deliberately never imports curses (it resolves the constants against a module
# passed in). A headless bob-core build stays importable.
from bob.tui import _keys
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
        "ssh.x11.forwarding.server",
        "ssh.x11.forwarding.client",
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
        "firewall_iptables.no_backend",
        "firewall_iptables.nft_no_input_filter",
        "firewall_iptables.input_accept",
        "firewall_iptables.forward_accept",
        "firewall_iptables.no_loopback",
        "firewall_iptables.no_conntrack",
    ]),
    ("MAC policy (AppArmor / SELinux)", [
        "mac_policy.apparmor_inactive",
        # v0.18.1: built in, disabled at boot — the stock Raspberry Pi kernel.
        "mac_policy.apparmor_off_in_kernel",
        "mac_policy.apparmor_no_enforce",
        "mac_policy.apparmor_no_profiles",
        "mac_policy.no_enforce",
        "mac_policy.no_mac",
        "mac_policy.selinux_disabled",
    ]),
    ("Firewall stack integrity", [
        "firewall_drivers.iptables_bypass",
        "firewall_drivers.iptables_forward_bypass",
        "firewall_drivers.nftables_parallel",
        "firewall_drivers.ip_forward_enabled",
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
        "services.state.inactive_enabled",
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
        "logs.blocked_repeat_public",
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
        "firewall_rules.duplicate_found",
        "firewall_rules.open_any_found",
        "firewall_rules.ipv6_missing",
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
        "cron.pipe_to_shell",
        "cron.world_writable",
    ]),
    ("Services", [
        "services_health.service_inactive",
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
        "docker_hardening.privileged",
        "docker_hardening.root_containers",
        "docker_hardening.socket_mounted",
        "docker_hardening.host_network",
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
        "suid_audit.unowned_suid",
        "suid_audit.unexpected_sgid",
    ]),
    ("Risk", [
        "risk.escalated_posture",
    ]),
    # v0.15.4: the sandbox family was the only group of WARN keys a user could
    # meet in a report and not look up. `bob --explain plugin.sandbox.timeout`
    # answered "no explanation available — run 'bob --explain list'", which
    # reads as "you mistyped the key" when BOB itself had just emitted it.
    # Their audience is plugin authors, and "why did this happen, how do I fix
    # it" is exactly what they need.
    # v0.15.4 "teeth": these three moved from INFO to WARN with a deduction,
    # so they became keys a user meets in a report — and therefore keys that
    # must be explainable. The rest of the container section stays INFO.
    ("Cloud and socket exposure", [
        "cloud_context.userdata_world_readable",
        "socket_units.orphan_exposed",
    ]),
    # v0.17.0: the two Raspberry Pi findings that carry a deduction. The rest
    # of the section is INFO — the board name, the ssh marker — and INFO keys
    # are not required to be explainable.
    ("Raspberry Pi", [
        "raspberry_pi.userconf_present",
        "raspberry_pi.legacy_account",
        # v0.18.1: trixie provisions through cloud-init instead of userconf.txt.
        "raspberry_pi.seed_password",
        "raspberry_pi.seed_wifi_key",
    ]),
    ("Container isolation", [
        "container_security.privileged",
        "container_security.cap_sys_admin",
        "container_security.no_seccomp",
    ]),
    ("Plugin checks — sandbox failures", [
        "plugin.sandbox.timeout",
        "plugin.sandbox.crashed",
        "plugin.sandbox.no_result",
        "plugin.sandbox.missing_run_check",
        "plugin.sandbox.bad_return",
        "plugin.sandbox.syntax_error",
        "plugin.sandbox.unreadable",
        "plugin.sandbox.rejected",
        "plugin.sandbox.serialize_failed",
        "plugin.sandbox.bad_payload",
        "plugin.sandbox.runner_error",
        "plugin.sandbox.error",
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
    # v0.10.1 D-4 Rank 1: ssh.x11_forwarding was split into
    # ssh.x11.forwarding.{server,client}. The legacy key keeps working via
    # this alias so pre-v0.10.1 scripts running ``bob --explain
    # ssh.x11_forwarding`` resolve to the server-side content (the original
    # finding was server-side only). For ignore.yml back-compat across BOTH
    # split halves, see bob/_v100_subcheck_renames.py::SUBCHECK_RENAMES_V100
    # (the fnmatch glob ``ssh.x11.forwarding.*`` covers both sub-keys).
    "ssh.x11_forwarding": "ssh.x11.forwarding.server",

    # v0.16.0: logs.brute_found named an authentication attack from packets the
    # firewall had already dropped. Renamed to join its two siblings
    # (blocked_repeat_local / _udp) from the same v0.15.5 fix. A script piping a
    # key out of an older report would otherwise get exit 3.
    "logs.brute_found": "logs.blocked_repeat_public",

    # v0.9.0 D-3: cleared on retrait. The only entry that lived here from
    # v0.5.5 through v0.8.x (``services_health.service_inactive`` →
    # ``enabled_inactive``, originally ``services_state.*`` pre-v0.9.0 D-1)
    # was a bridge over module-internal drift: the ``services_state.py``
    # check emitted ``...service_inactive`` while the EXPLAIN_KEYS entry +
    # locale block were named ``enabled_inactive``. v0.9.0 resolves the
    # drift at the source — the EXPLAIN_KEYS entry was renamed to
    # ``service_inactive`` to match the emitted key — so the alias is
    # no longer needed.
    #
    # The dict is intentionally kept (as an empty dict) so a future rename
    # has a one-line migration path: add the legacy → canonical mapping
    # here, and ``normalize_key()`` below resolves it transparently. A new
    # entry surfaces immediately in
    # ``test_explain_naming_convention::test_aliases_do_not_collide`` and
    # ``test_normalize_resolves_aliases``. See ``SECURITY.md`` for the
    # rename / alias contract.
    #
    # The v0.8.2 one-shot DEPRECATION warning machinery
    # (``_warn_alias_deprecation`` + ``_WARNED_ALIASES``) was removed in
    # v0.9.0 with this retrait — re-introduce a logger-level warning on
    # the next rename that needs operator migration signal.
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

    v0.9.0 D-3: the alias dict is empty; the lookup remains so a future
    rename has a one-line migration path. No deprecation warning fires
    on hit — re-introduce one when the next alias needs operator signal
    (the v0.8.2 ``_warn_alias_deprecation`` machinery was removed with
    the retrait of the sole v0.5.5–v0.8.x entry).

    Examples:
        'file_perms.shadow.world_writable'  →  'file_perms.world_writable'
        'ssh.password_auth'                 →  'ssh.password_auth'   (unchanged)
        '<legacy_name>'                     →  '<current_name>'      (via aliases)
    """
    m = _NORMALIZE_RE.match(key)
    if m:
        key = f"{m.group(1)}.{m.group(2)}"
    if key in EXPLAIN_KEY_ALIASES:
        return EXPLAIN_KEY_ALIASES[key]
    return key


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

_DIVIDER_WIDE  = "─" * 60
_DIVIDER_SHORT = "─" * 10

# Ordered profiles shown in the profile-variant display.
# v0.16.3 — ``workstation`` joins the list. It has had its own severity
# overrides since v0.8.1 and is offered by ``--profile``, yet ``--explain``
# rendered no section for it: an operator auditing a business workstation was
# shown how server, desktop and container treat a finding, and nothing about
# the profile they were actually running.
#
# It carries no hand-written prose, and inventing 71 explanations per locale
# would be 142 chances to say something false about a policy. Instead the
# section is derived from the profile file itself — see
# ``_profile_override_note`` — which cannot be wrong, and which does the same
# for any profile whose prose is missing.
_EXPLAIN_PROFILES: tuple = ("server", "desktop", "workstation", "container")


def _has_profile_variants(key: str, t) -> bool:
    """Return True if *key* has at least one profile-specific 'why' translation.

    Prose only. Whether a *profile* treats the key differently is a separate
    question with a separate answer — see ``profile_override_notes``.

    Works with both the real i18n.t (returns "[key.path]" for missing keys)
    and mock translation functions used in tests (return the key path itself).
    """
    probe = t(f"explain.{key}.server.why")
    bare_key      = f"explain.{key}.server.why"
    bracketed_key = f"[{bare_key}]"
    return probe not in (bare_key, bracketed_key)


def profile_override_notes(key: str, t) -> list[str]:
    """Derived lines about every shipped profile that treats *key* specially.

    Empty when no profile overrides the key or skips its section — and only
    then may the display claim the finding applies equally to all profiles.

    Asking the prose alone was a claim about the wrong thing: 32 keys had no
    per-profile ``why`` and were therefore announced as uniform across all
    profiles while ``desktop``, ``workstation`` or ``container`` downgraded
    them to INFO. ``ssh.password_auth`` is one — downgraded by three of the
    four profiles, and described as applying equally to them all.

    An operator reads that line to decide whether their profile changes the
    verdict. Answering "it does not" from the absence of an explanation is
    this project's oldest defect class, one layer up.
    """
    notes: list[str] = []
    for profile in _EXPLAIN_PROFILES:
        note = _profile_override_note(profile, key, t)
        if note:
            notes.append(note)
    return notes


def profile_notes_for_display(key: str, t) -> list[str]:
    """Every profile's line for *key*, or [] when none of them deviates.

    Where :func:`profile_override_notes` answers "does any profile treat this
    differently" — the question that decides which branch renders — this
    answers "what does each profile do", which is what an operator reads.

    The difference is the profiles that apply the default. Naming only the
    deviating ones left ``server`` never mentioned anywhere and ``workstation``
    absent from the five keys where it *refuses* the downgrade ``desktop``
    grants, so the finding counts in full there. A reader on one of those
    profiles saw an explanation that did not mention it and had to read the
    silence as "same as default" — an absence standing in for an answer, which
    is the defect this whole display was rewritten to stop making.

    Returns [] for a key no profile deviates on, so the caller still prints the
    single "applies equally to all profiles" line rather than four saying the
    same thing.
    """
    if not profile_override_notes(key, t):
        return []
    return [
        _profile_override_note(profile, key, t)
        or t("explain.ui.profile_default", profile=profile)
        for profile in _EXPLAIN_PROFILES
    ]


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


def _print_explain_list(t) -> None:
    """List every --explain key, grouped by CIS benchmark family.

    v0.18.1: grouped by family (CIS Ubuntu, CIS Docker, Best practice, …)
    rather than by audit section, each family a folder heading. The family a
    key belongs to comes from bob.cis_refs.cis_family, derived from the
    canonical English reference so the grouping does not shift with the
    interface language. v0.19.x will add more CIS distributions (Fedora,
    openSUSE, Alpine); a new family slots into the ordering by name.
    """
    from bob.cis_refs import (
        BEST_PRACTICE_FAMILY, cis_family, cis_family_sort_key,
    )

    families: "dict[str, list[str]]" = {}
    for k in EXPLAIN_KEYS:
        fam = cis_family(k) or BEST_PRACTICE_FAMILY
        families.setdefault(fam, []).append(k)

    print(t("explain.ui.list_header", count=len(EXPLAIN_KEYS)))
    for fam in sorted(families, key=cis_family_sort_key):
        keys = sorted(families[fam])
        # CIS benchmark names are proper nouns, verbatim in every locale; only
        # the best-practice family carries a translated label.
        label = (t("explain.ui.family_best_practice")
                 if fam == BEST_PRACTICE_FAMILY else fam)
        print()
        print(f"  \U0001F4C1 {label}  ({len(keys)})")
        for k in keys:
            title = t(f"explain.{k}.title")
            print(f"      {k:<42}  {title}")
    print()


def run_explain(key: str, t) -> bool:
    """
    Print a structured explanation for *key*.

    Pass key="list" to print all available keys.

    Args:
        key: Finding key (e.g. "ssh.password_auth") or "list".
        t:   Translation function from bob.i18n.

    Returns:
        True when an explanation (or the key list) was printed; False when
        *key* is unknown (F4, v0.12.0 — the caller maps this to a non-zero
        exit code so scripts can distinguish "explained" from "no such key").
    """
    key = key.strip()

    # ---- list mode ---------------------------------------------------------
    if key == "list":
        _print_explain_list(t)
        return True

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
            return True

    if key_unknown:
        print(t("explain.ui.unknown_key", requested=repr(key)))
        # F4 (v0.12.0): offer the closest known keys for a typo.
        import difflib
        suggestions = difflib.get_close_matches(key, EXPLAIN_KEYS, n=3, cutoff=0.6)
        if suggestions:
            print()
            print(t("explain.ui.did_you_mean", suggestions=", ".join(suggestions)))
        print()
        print(t("explain.ui.unknown_hint"))
        return False

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
            if pwhy in (pwhy_key, f"[{pwhy_key}]"):
                # No prose written for this profile. Say what its .conf says
                # rather than omitting the section: all 71 prose keys lack a
                # `workstation` variant, so skipping left an operator on that
                # profile reading server/desktop/container and concluding
                # their profile was not covered at all.
                print()
                print(_profile_header(profile))
                print(_DIVIDER_SHORT)
                print(_profile_override_note(profile, norm, t)
                      or t("explain.ui.profile_default", profile=profile))
                print()
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
            print(_profile_header(profile))
            print(_DIVIDER_SHORT)
            print(pwhy)
            print()
            print(_indent(t("explain.ui.how_title")))
            print(_indent(_DIVIDER_SHORT))
            print(_how_block(phow))
            print()
    else:
        # Uniform risk across all profiles
        print()
        print(t("explain.ui.why_title"))
        print(_DIVIDER_SHORT)
        print(why_val)
        print()
        print(_indent(t("explain.ui.how_title")))
        print(_indent(_DIVIDER_SHORT))
        print(_how_block(how_val))
        print()
        # Say "applies equally to all profiles" only when that is true. A
        # profile that downgrades this key to INFO, or skips its section, is
        # exactly what the operator came here to find out.
        _notes = profile_notes_for_display(norm, t)
        _lines = _notes or [t("explain.ui.uniform_profiles_note")]
        for _line in _lines:
            _note = "\u24d8  " + _line
            if sys.stdout.isatty():
                print(f"  \033[33m{_note}\033[0m")
            else:
                print(f"  {_note}")
        print()

    _explain_scoring(norm, t)
    return True


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

    # v0.16.1: shared chart — see bob/tui/_palette.py. Pair 4 is the one
    # screen-specific slot; here it is the detail-pane heading, not a warning.
    from bob.tui._palette import init_palette

    return init_palette(curses, notice=curses.COLOR_CYAN)


def _how_block(text: str) -> str:
    """A HOW TO FIX block with its verbatim lines in violet, prose left alone.

    Same rule as the curses screen: indentation marks the material. The charter
    says violet means "reproduce this exactly" on both surfaces, so a text page
    that left every line plain would make that sentence false.
    """
    if not sys.stdout.isatty():
        return _indent(text)
    from bob.output import command as _command
    out = []
    for line in text.split("\n"):
        out.append(_command(line) if _is_verbatim_line(line) else line)
    return _indent("\n".join(out))


def _is_verbatim_line(line: str) -> bool:
    """Whether a line of a HOW TO FIX block must be reproduced exactly.

    These blocks are numbered prose *and* material to transcribe:

        1. Edit /etc/samba/smb.conf
        2. In the [global] section set:
           server signing = mandatory
        4. Restart Samba:
           sudo systemctl restart smbd

    Indentation marks the material, and the locale is consistent about it
    across all 187 keys — 664 indented lines against 527 numbered steps and 74
    notes. Painting the whole block violet was the first attempt and it emptied
    the colour of meaning; two thirds of a block is prose.

    **Verbatim, not runnable.** `server signing = mandatory` is not a command,
    and separating the two is neither reliable nor useful. Not reliable: 37 of
    these lines are `sudo nano <file>  →  <directive>`, a command and a
    directive on one line, and classifying the rest needed a sixty-binary regex
    that still left 16% unsorted — a rule that needs such a list is a heuristic
    that drifts at the first check using a binary nobody listed. Not useful:
    from the operator's side both say the same thing, *reproduce this exactly,
    do not paraphrase*, and the prose above already says whether to run it or
    write it.
    """
    return bool(line) and line[:1].isspace() and bool(line.strip())


def _indent(text: str, spaces: int = 4) -> str:
    """Shift every line of *text* right, blank lines included as blank."""
    pad = " " * spaces
    return "\n".join(pad + line if line.strip() else line
                     for line in text.split("\n"))


def _profile_header(profile: str) -> str:
    """``[ profile ]`` in orange when the terminal takes colour.

    Brackets included: they are part of the label, and colouring the word
    alone leaves the delimiters reading as ordinary text.

    Honours the tool's colour policy through ``bob.output._c`` — resolved at
    call time, since ``output.init`` rebinds it — and the TTY check, so a
    piped or ``--no-color`` run stays plain.
    """
    label = f"[ {profile} ]"
    if not sys.stdout.isatty():
        return label
    from bob.output import _c
    return f"{_c.orange}{label}{_c.reset}" if _c.orange else label


def _profile_override_note(profile: str, key: str, t) -> str:
    """One derived line about how *profile* treats *key*, or "".

    Read from ``bob/data/profiles/<profile>.conf`` through the normal loader,
    so it inherits ``extends`` exactly as an audit does. Returns "" when the
    profile neither overrides the key nor skips its section — there is nothing
    to say then, and a section saying nothing is worse than none.
    """
    try:
        from bob.profiles import load_profile
        prof = load_profile(profile)
    except Exception:                      # pragma: no cover — defensive
        return ""

    section = key.split(".", 1)[0]
    if prof.should_skip_section(section):
        return t("explain.ui.profile_skips", profile=profile, section=section)

    level = prof.override_for(key)
    if level:
        return t("explain.ui.profile_override", profile=profile, level=level.upper())
    return ""


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
        from bob.tui._palette import VERBATIM as _VERBATIM_PAIR
        cmd_attr    = _c.color_pair(_VERBATIM_PAIR) if has_color else _c.A_NORMAL
        # Same pair the text path paints orange, from the shared chart.
        from bob.tui._palette import PROFILE as _PROFILE_PAIR
        prof_attr   = ((_c.color_pair(_PROFILE_PAIR) | _c.A_BOLD)
                       if has_color else _c.A_BOLD)
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
                    lines.append(("", normal))
                    lines.append((f"  [ {profile} ]", prof_attr))
                    lines.append(("  " + "─" * 10, dim))
                    _derived = (_profile_override_note(profile, norm, t)
                                or t("explain.ui.profile_default", profile=profile))
                    for wrapped in textwrap.wrap(_derived, w - 4) or [""]:
                        lines.append((f"  {wrapped}", normal))
                    lines.append(("", normal))
                    continue
                phow_key = f"explain.{norm}.{profile}.how"
                phow_candidate = t(phow_key)
                phow = (
                    phow_candidate
                    if phow_candidate not in (phow_key, f"[{phow_key}]")
                    else how_val
                )
                lines.append(("", normal))
                lines.append((f"  [ {profile} ]", prof_attr))
                lines.append(("  " + "─" * 10, dim))
                for para in pwhy.split("\n"):
                    for wrapped in textwrap.wrap(para, w - 4) or [""]:
                        lines.append((f"  {wrapped}", normal))
                lines.append(("", normal))
                lines.append(("      " + t("explain.ui.how_title"), bold))
                lines.append(("      " + "─" * 10, dim))
                for para in phow.split("\n"):
                    _a = cmd_attr if _is_verbatim_line(para) else normal
                    for wrapped in textwrap.wrap(para, w - 8) or [""]:
                        lines.append((f"      {wrapped}", _a))
                lines.append(("", normal))
        else:
            lines.append(("", normal))
            lines.append(("  " + t("explain.ui.why_title"), bold))
            lines.append(("  " + "─" * 10, dim))
            for para in why_val.split("\n"):
                for wrapped in textwrap.wrap(para, w - 4) or [""]:
                    lines.append((f"  {wrapped}", normal))
            lines.append(("", normal))
            lines.append(("      " + t("explain.ui.how_title"), bold))
            lines.append(("      " + "─" * 10, dim))
            for para in how_val.split("\n"):
                _a = cmd_attr if _is_verbatim_line(para) else normal
                for wrapped in textwrap.wrap(para, w - 8) or [""]:
                    lines.append((f"      {wrapped}", _a))
            lines.append(("", normal))
            for _line in profile_notes_for_display(norm, t) or [
                t("explain.ui.uniform_profiles_note")
            ]:
                for wrapped in textwrap.wrap("\u24d8  " + _line, w - 4) or [""]:
                    lines.append((f"  {wrapped}", yellow_attr))
            lines.append(("", normal))
        return lines

    scroll = 0

    while True:
        h, w    = stdscr.getmaxyx()
        content = _build_lines(w)
        from bob.tui import _chrome as _ch
        body_h  = max(1, h - 1 - _ch.chrome_height(t, _DETAIL_KEYS, w))
        max_scroll = max(0, len(content) - body_h)

        stdscr.erase()

        # ── header ──────────────────────────────────────────────────────────
        # v0.16.3 — title and progress in the banner, keys in the footer, as on
        # every other screen. The progress used to sit in the footer with the
        # words "scroll up" / "top" hardcoded in English, on a screen whose
        # body is fully translated.
        _pct = min(100, int(100 * (scroll + body_h) / max(1, len(content))))
        header = f"  {norm}    {_pct}%  "
        from bob.tui import _chrome
        _chrome.draw_header(stdscr, curses, header, has_color)

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

        # ── bottom chrome ────────────────────────────────────────────────────
        from bob.tui import _chrome
        _chrome.draw(stdscr, curses, t, _DETAIL_KEYS, has_color)

        stdscr.refresh()

        ch = stdscr.getch()
        action = _keys.resolve(curses, ch, _DETAIL_KEYS)
        if action == _keys.BACK:                       # nested screen: Esc goes back
            return
        elif action == _keys.MOVE:
            scroll = max(0, min(max_scroll, scroll + _keys.direction(curses, ch)))
        elif action == _keys.PAGE:
            scroll = max(0, min(max_scroll, scroll + body_h * _keys.direction(curses, ch)))
        elif action == _keys.EDGE:
            scroll = 0 if _keys.is_top(ch) else max_scroll


#: What the picker accepts. The navigation floor is universal; SELECT and
#: QUIT are this screen's own — it is a wizard's first page, so ``q`` exits
#: here and nowhere deeper.
_PICKER_KEYS = _keys.NAVIGATION + (_keys.SELECT,) + _keys.LANDING_EXIT

#: The detail screen is nested, so it goes back rather than quitting.
_DETAIL_KEYS = _keys.NAVIGATION + _keys.NESTED_EXIT


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
        from bob.tui import _chrome as _ch
        list_h = max(1, h - 1 - _ch.chrome_height(t, _PICKER_KEYS, w))

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
        # v0.16.3 — the banner carries the title and the context; the keys live
        # in the footer, as on every other screen. They used to be merged here,
        # which is why this wizard advertised a different set from the others.
        header = "  bob --explain    " + t(
            "explain.ui.picker_counts",
            n_keys=len(key_indices), n_groups=len(_EXPLAIN_GROUPS),
        ) + "  "
        from bob.tui import _chrome
        _chrome.draw_header(stdscr, curses, header, has_color)

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

        # ── bottom chrome ────────────────────────────────────────────────────
        from bob.tui import _chrome
        _chrome.draw(stdscr, curses, t, _PICKER_KEYS, has_color)

        stdscr.refresh()

        ch = stdscr.getch()

        action = _keys.resolve(curses, ch, _PICKER_KEYS)
        pos = key_indices.index(selected) if selected in key_indices else 0

        if action == _keys.QUIT:                       # landing screen: q exits
            return ("quit", None, selected)

        elif action == _keys.LANG:                     # landing screen: l switches
            _keys.toggle_language()
            continue

        elif action == _keys.MOVE:
            # Clamped, as before: UP on the first key stays, DOWN on the last stays.
            pos = max(0, min(len(key_indices) - 1, pos + _keys.direction(curses, ch)))
            selected = key_indices[pos]

        elif action == _keys.PAGE:
            step = max(1, list_h) * _keys.direction(curses, ch)
            pos = max(0, min(len(key_indices) - 1, pos + step))
            selected = key_indices[pos]

        elif action == _keys.EDGE:
            selected = key_indices[0 if _keys.is_top(ch) else -1]

        elif action == _keys.SELECT:
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
