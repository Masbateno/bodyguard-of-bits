"""
Audit profile system for BOB.

Profiles allow users to adjust the severity of individual check findings
based on their system's role (server, workstation, container, custom…).

Built-in profiles are shipped as .conf files under bob/data/profiles/.
User-defined profiles can be placed in ~/.config/bob/profiles/.

Profile file format (INI)
-------------------------
[profile]
name        = workstation
extends     = server
description = Desktop/workstation — relaxed hardening requirements

[overrides]
# key = target_level   (info | warn | alert | skip)
updates.unattended_not_configured = info
hardening.rp_filter_disabled   = info

[skip_sections]
# List section names to ignore entirely, one per line.
# Example:
# hardening

Usage
-----
    from bob.profiles import load_profile
    from bob.scoring import ScoreEngine

    profile = load_profile("workstation")
    engine  = ScoreEngine(profile=profile)
    engine.apply(result)          # overrides applied inside apply()

Since v0.14.0 the engine carries the profile and applies the overrides
itself. Calling ``apply_profile(result, profile)`` by hand still works and
is idempotent, but it is no longer the contract: doing it at the call site
is what left 8 shipped overrides dead, because only 2 of the 14
``engine.apply()`` sites in bob/runner.py remembered to do it.
"""

from __future__ import annotations

import configparser
import functools
import logging
from dataclasses import dataclass, field
from pathlib import Path

from bob.scoring import CheckResult, FindingLevel
from bob.sysinfo import get_user_home

logger = logging.getLogger(__name__)

# Directories searched for profile files (user overrides built-ins)
_BUILTIN_PROFILES_DIR = Path(__file__).parent / "data" / "profiles"
_USER_PROFILES_DIR    = get_user_home() / ".config" / "bob" / "profiles"

# Levels that can appear as override values in a profile file
_VALID_OVERRIDE_LEVELS: frozenset[str] = frozenset({"info", "warn", "alert", "skip"})

# Maximum inheritance depth — prevents circular extends chains
_MAX_EXTENDS_DEPTH = 8


# ---------------------------------------------------------------------------
# Data structure
# ---------------------------------------------------------------------------

@dataclass
class AuditProfile:
    """
    A named audit profile that adjusts finding severity.

    Args:
        name:          Profile identifier (e.g. "workstation").
        description:   Human-readable description.
        overrides:     Mapping of i18n key → target level ("info"|"warn"|"alert"|"skip").
        skip_sections: Set of section names to skip entirely.
    """
    name:          str
    description:   str                 = ""
    overrides:     dict[str, str]      = field(default_factory=dict)
    skip_sections: set[str]            = field(default_factory=set)

    def should_skip_section(self, section: str) -> bool:
        """Return True if this section should be skipped entirely."""
        return section in self.skip_sections

    def override_for(self, key: str) -> str | None:
        """
        Return the override action for a finding key, or None if no override.

        Returns:
            "info" | "warn" | "alert" | "skip" | None
        """
        return self.overrides.get(key)


# ---------------------------------------------------------------------------
# Built-in default profile
# ---------------------------------------------------------------------------

_DEFAULT_PROFILE = AuditProfile(
    name="server",
    description="Default server profile — no overrides",
)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_profile(name: str) -> AuditProfile:
    """
    Load a named profile by searching user then built-in profile directories.

    Resolves the `extends` chain up to _MAX_EXTENDS_DEPTH levels.
    Unknown profile names fall back to the default (server) profile with a
    logged warning — they never raise.

    Args:
        name: Profile name (e.g. "workstation") or "default"/"server".

    Returns:
        Resolved AuditProfile.
    """
    if name in ("default", "server", ""):
        return _DEFAULT_PROFILE
    # T6 (v0.8.1): the v0.1.0 alias ``workstation → desktop`` was retired —
    # ``workstation.conf`` is now a first-class profile with its own
    # severity overrides (business-context semantics: keeps backup / auditd /
    # mac_policy at WARN while relaxing personal-use ergonomics matching
    # ``desktop``). Users who depended on the alias (workstation = desktop)
    # see different severity outputs on backup.no_backup / auditd.* /
    # mac_policy.apparmor_no_enforce / file_integrity stays INFO.
    # See CHANGELOG v0.8.1 for migration.

    path = _find_profile_file(name)
    if path is None:
        logger.warning("Profile %r not found — using default (server)", name)
        return _DEFAULT_PROFILE

    try:
        return _load_from_path(path, depth=0)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Profile %r failed to load (%s) — using default", name, exc)
        return _DEFAULT_PROFILE


@functools.lru_cache(maxsize=1)
def _recognised_override_keys() -> set[str] | None:
    """T32 (v0.8.1): the catalogue of finding keys a profile is allowed to
    override. Used by ``_load_from_path`` to warn the operator about typos
    in ``[overrides]`` entries.

    The catalogue is the union of three sources:

      * ``bob.explain.EXPLAIN_KEYS`` — the 168 statically-emitted keys.
      * ``services.exposed.<id>`` and ``services.exposure.<id>`` for every
        service in ``bob/data/services.json`` (the dynamic per-service
        keys emitted by ``bob/checks/services.py``).
      * Helper-dispatched literal keys harvested from the check modules
        (e.g. ``ssh.weak_macs`` lives in a helper call site, not in
        EXPLAIN_KEYS but emitted at runtime).

    Cached with ``maxsize=1`` so repeated profile loads in the same process
    pay the disk + AST cost exactly once. Returns ``None`` if any source
    fails to import — the caller falls back to the pre-T32 "accept anything"
    behaviour rather than spamming false-positive warnings.
    """
    try:
        from bob.explain import EXPLAIN_KEYS
        recognised: set[str] = set(EXPLAIN_KEYS)
    except Exception:
        return None
    try:
        from bob.registry import ServiceRegistry
        registry = ServiceRegistry.load()
        # M-2 (v0.8.1 audit): the runtime emits ``services.exposed.<svc_id>``
        # for every registered service (legitimate dynamic key) but
        # ``services.exposure.*`` keys are **exposure-enum-typed**
        # (open_world / open_local / loopback / deny / no_rule /
        # loopback_no_rule / not_listening + ``_ufw_inactive`` variants),
        # not service-id-typed. Pre-fix the catalogue registered
        # ``services.exposure.{svc.id}`` (e.g. ``services.exposure.ollama``)
        # which silently accepted bogus overrides as "valid".
        for svc in registry.all():
            recognised.add(f"services.exposed.{svc.id}")
    except Exception:
        # Non-fatal — the EXPLAIN_KEYS subset is enough to flag obvious
        # typos like ``ssh.totally_not_a_key``.
        pass
    # M-2 (v0.8.1 audit): canonical ``services.exposure.*`` set, matching
    # the emit sites in ``bob/checks/services.py`` lines 353-355,390-403.
    # The base values come from the ``Exposure`` enum + the two static
    # explicit keys.
    for _exp_value in (
        "open_world", "open_local", "loopback",
        "deny", "no_rule", "loopback_no_rule", "not_listening",
    ):
        recognised.add(f"services.exposure.{_exp_value}")
    # M-2 pass 8 (v0.8.1 audit): the ``_ufw_inactive`` variants are
    # emitted ONLY when ``exposure in (NO_RULE, LOOPBACK_NO_RULE)`` —
    # see services.py:352-355. Pre-pass-8 the registration was permissive
    # across all 7 exposure values, so a profile override on e.g.
    # ``services.exposure.open_world_ufw_inactive = info`` was silently
    # accepted as valid (zero typo warning, zero runtime effect) — the
    # exact false-positive UX failure the original M-2 was meant to
    # close. Narrowed to the 2 exposures the runtime actually emits.
    for _exp_value in ("no_rule", "loopback_no_rule"):
        recognised.add(f"services.exposure.{_exp_value}_ufw_inactive")
    # Harvest literal key="..." emit sites that aren't in EXPLAIN_KEYS
    # (helper-dispatched keys, dynamic states, etc.) so the typo detector
    # doesn't false-positive on them.
    # M-1 (v0.8.1 audit): the regex now accepts digit-containing segments
    # (the pre-M-1 form ``[a-z_]+`` rejected real keys like
    # ``fail2ban.ssh_jail_active`` / ``ipv6.ufw_disabled_no_listeners`` /
    # ``ipv6.port_no_v6_rule``). Profile overrides on these keys triggered
    # spurious "not recognised" warnings even though the runtime emits
    # them as canonical literals. Aligns with the canonical pattern used
    # by ``bob/ignore.py::_CANONICAL_KEY_RE``.
    import re
    from pathlib import Path
    checks_dir = Path(__file__).parent / "checks"
    try:
        for f in checks_dir.rglob("*.py"):
            try:
                src = f.read_text(encoding="utf-8")
            except OSError:
                continue
            for m in re.finditer(
                r'key=["\']([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+)["\']', src
            ):
                recognised.add(m.group(1))
    except Exception:
        pass
    # M-1 (v0.8.1 audit) supplemental: ``bob/checks/file_perms.py`` emits
    # f-string keys of the form ``file_perms.<filename>.world_writable``
    # / ``.too_permissive`` / ``.no_owner`` etc. (lines 223,240,259). The
    # literal harvest can't see them; whitelist ``file_perms.*`` as a
    # permissive prefix mirror to how ``services.exposed.<id>`` is handled
    # above. The cost of a permissive prefix here is acceptable because
    # the namespace is narrow + every actionable check key already starts
    # with a real ``file_perms.<filename>`` segment by construction.
    recognised.add("file_perms.*")
    return recognised


@functools.lru_cache(maxsize=32)
def _find_profile_file(name: str) -> Path | None:
    """Return the .conf path for a named profile, user dir takes priority.

    Results are cached — deep extends chains pay disk cost only once per name.
    """
    for directory in (_USER_PROFILES_DIR, _BUILTIN_PROFILES_DIR):
        candidate = directory / f"{name}.conf"
        try:
            if candidate.is_file():
                return candidate
        except PermissionError:
            # Directory unreadable (e.g. created by root via sudo) — skip silently.
            continue
    return None


def _load_from_path(path: Path, depth: int) -> AuditProfile:
    """Parse a profile .conf file and resolve its extends chain."""
    if depth > _MAX_EXTENDS_DEPTH:
        raise RecursionError(f"Profile extends chain exceeds {_MAX_EXTENDS_DEPTH} levels")

    cp = configparser.ConfigParser(
        allow_no_value=True,
        inline_comment_prefixes=("#",),
    )
    cp.read(str(path), encoding="utf-8")

    # [profile] section
    name        = cp.get("profile", "name",        fallback=path.stem)
    description = cp.get("profile", "description", fallback="")
    extends     = cp.get("profile", "extends",     fallback="").strip()

    # Start with parent overrides if extends is set
    base_overrides:     dict[str, str] = {}
    base_skip_sections: set[str]       = set()

    if extends and extends not in ("", "none"):
        parent_path = _find_profile_file(extends)
        if parent_path is not None:
            parent = _load_from_path(parent_path, depth + 1)
            base_overrides     = dict(parent.overrides)
            base_skip_sections = set(parent.skip_sections)
        else:
            logger.warning(
                "Profile %r extends %r which was not found — parent ignored",
                name, extends,
            )

    # [overrides] section — child values win over parent
    overrides = dict(base_overrides)
    if cp.has_section("overrides"):
        # T32 (v0.8.1): build the set of recognised override keys once per
        # load so we can warn the operator about typos. Pre-T32 the loader
        # silently accepted any dotted-identifier key, so ``ssh.totally_not_a_key
        # = info`` and ``non_existant_section.foo = warn`` rode through
        # without any signal — users believed their policy applied but the
        # override never matched any emitted finding. The validation is
        # advisory (logger.warning, not raise) so existing profiles with
        # legacy entries from removed checks don't break loading.
        recognised = _recognised_override_keys()
        for key, value in cp.items("overrides"):
            if value is None:
                continue
            key   = key.strip().lower()    # normalise: "Hardening.Auto" → "hardening.auto"
            value = value.strip().lower()
            if value not in _VALID_OVERRIDE_LEVELS:
                logger.warning(
                    "Profile %r: unknown override level %r for key %r — ignored",
                    name, value, key,
                )
                continue
            # T32 typo detection — warn but still apply (compat-preserving)
            # M-1 (v0.8.1 audit): ``file_perms.*`` is registered as a
            # permissive prefix (see ``_recognised_override_keys``) because
            # the runtime emits f-string keys like
            # ``file_perms.passwd.world_writable`` that the literal harvest
            # can't see. Match the prefix here so legitimate file_perms
            # overrides don't trigger spurious warnings.
            if recognised is not None and key not in recognised:
                if not (
                    "file_perms.*" in recognised
                    and key.startswith("file_perms.")
                ):
                    logger.warning(
                        "Profile %r: override key %r is not recognised (typo or removed check?) — "
                        "the override will be loaded but will never match an emitted finding",
                        name, key,
                    )
            overrides[key] = value

    # [skip_sections] section
    skip_sections = set(base_skip_sections)
    if cp.has_section("skip_sections"):
        for section_name, _ in cp.items("skip_sections"):
            skip_sections.add(section_name.strip())

    return AuditProfile(
        name=name,
        description=description,
        overrides=overrides,
        skip_sections=skip_sections,
    )


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------

_LEVEL_MAP: dict[str, FindingLevel] = {
    "info":  FindingLevel.INFO,
    "warn":  FindingLevel.WARN,
    "alert": FindingLevel.ALERT,
}


def apply_profile(result: CheckResult, profile: AuditProfile) -> CheckResult:
    """
    Apply profile overrides to a CheckResult.  Mutates result in-place.

    For each finding whose ``key`` matches a profile override:
    - "skip"  → finding removed entirely; matching deductions removed.
    - "info"  → finding downgraded; deductions removed (no score impact).
    - "warn" | "alert" → finding level changed; deductions retained
      (scoring impact preserved — only the display level changes).

    Findings without a key are never modified.

    Note: section skipping (profile.should_skip_section) is applied upstream
    in runner.py before the check runs, so it is intentionally absent here.

    Args:
        result:  CheckResult produced by a check function.
        profile: AuditProfile to apply.

    Returns:
        The same CheckResult object, mutated in-place.
    """
    if not profile.overrides:
        return result

    for finding in list(result.findings):
        if not finding.key:
            continue
        action = profile.override_for(finding.key)
        if action is None:
            continue

        if action == "skip":
            _remove_deductions_for_key(result, finding.key)
            result.findings.remove(finding)

        else:
            new_level = _LEVEL_MAP[action]
            if new_level != finding.level:
                finding.level = new_level
                # Downgrade to INFO: remove deductions — finding no longer scores.
                # Remap to WARN/ALERT: keep deductions — scoring impact is retained.
                if new_level == FindingLevel.INFO:
                    _remove_deductions_for_key(result, finding.key)
                    finding.nature = ""  # remove from action/improvement buckets in summary

    return result


def _remove_deductions_for_key(result: CheckResult, key: str) -> None:
    """Remove all deductions whose key field matches the given finding key.

    Relies on Deduction.key being set to the same i18n key as the Finding it
    accompanies (set via add_deduction(key=…) in each check function).
    This is deterministic regardless of translated text or duplicate messages.
    """
    result.deductions = [d for d in result.deductions if d.key != key]
