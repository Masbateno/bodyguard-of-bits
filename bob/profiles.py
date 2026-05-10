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
hardening.auto_updates_missing = info
hardening.rp_filter_disabled   = info

[skip_sections]
# List section names to ignore entirely, one per line.
# Example:
# hardening

Usage
-----
    from bob.profiles import load_profile, apply_profile

    profile = load_profile("workstation")
    result  = apply_profile(result, profile)
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
    if name == "workstation":          # backward-compat alias
        name = "desktop"

    path = _find_profile_file(name)
    if path is None:
        logger.warning("Profile %r not found — using default (server)", name)
        return _DEFAULT_PROFILE

    try:
        return _load_from_path(path, depth=0)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Profile %r failed to load (%s) — using default", name, exc)
        return _DEFAULT_PROFILE


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
