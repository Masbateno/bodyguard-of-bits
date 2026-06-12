"""
Per-domain security sub-scores for BOB.

Groups deductions from a finalized ScoreEngine by security domain and
computes a score (0–10) for each domain independently.

Domains:
  ssh        — SSH server/client configuration (checks/ssh.py)
  samba      — Samba security audit (checks/samba.py)
  file_perms — Sensitive file permissions and sudoers (checks/file_perms.py)
  updates    — System package updates (checks/updates.py)
  hardening  — Kernel hardening and security tools (checks/hardening.py)
  disk       — Disk health: SMART + partition usage (checks/disk.py)
  firewall   — Firewall rules, ports, services, logs (everything else)

Usage:
    from bob.domain_scores import compute_domain_scores, DOMAINS

    scores, _ = compute_domain_scores(engine)
    for domain in DOMAINS:
        info = scores[domain]
        print(f"{info['label']}: {info['score']}/10")
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from bob.scoring import ScoreEngine

from bob.scoring import MAX_SCORE, FindingLevel

# ---------------------------------------------------------------------------
# Domain definitions
# ---------------------------------------------------------------------------

# Ordered list of canonical domain identifiers (display order).
DOMAINS: list[str] = ["ssh", "samba", "file_perms", "updates", "hardening", "disk", "firewall"]

# Human-readable English labels for each domain.
LABELS: dict[str, str] = {
    "ssh":        "SSH",
    "samba":      "Samba Security",
    "file_perms": "Files & Access",
    "updates":    "Updates",
    "hardening":  "Hardening",
    "disk":       "Disk Health",
    "firewall":   "Firewall & Services",
}

# Maximum total deduction (in points) that a single tool can contribute to its
# domain score.  Prevents one poorly-maintained tool from dominating the domain
# score when it emits several independent findings (e.g. rkhunter: db outdated
# + no scan run = 2 findings for the same configuration problem → capped at 1).
TOOL_CAPS: dict[str, int] = {
    "rootkit":        1,   # rkhunter/chkrootkit — db age + scan age
    "clamav":         1,   # ClamAV — db age + scan frequency
    "file_integrity": 1,   # AIDE/Tripwire — presence + freshness
}

# Known key prefixes that map to specific domains.
# Any prefix not listed here → "firewall" (catch-all).
#
# Re-attributions in v0.5.4 (audit finding #15b — Phase 5):
#   fail2ban     → ssh         (primary purpose is SSH anti-bruteforce)
#   virt         → hardening   (KVM/bridge bypass is kernel/system surface)
#   docker_audit → hardening   (container hardening / daemon.json security)
# `smtp` and `desktop_apps` stay in the firewall catch-all — no clean
# domain fit identified; revisit if a "detection" domain is introduced.
_PREFIX_TO_DOMAIN: dict[str, str] = {
    "ssh":              "ssh",
    "samba":            "samba",
    "file_perms":       "file_perms",
    "updates":          "updates",
    "hardening":        "hardening",
    "kernel_hardening": "hardening",
    "kernel_modules":   "hardening",
    "cron":       "hardening",
    "services_health":   "hardening",
    "user_accounts":    "file_perms",
    "password_policy":  "hardening",
    "memory":           "hardening",
    "clamav":           "hardening",
    "auditd":           "hardening",
    "secure_boot":      "hardening",
    "backup":           "disk",
    "file_integrity":   "hardening",
    "log_rotation":     "hardening",
    "mac_policy":       "hardening",
    "ntp":              "hardening",
    "rootkit":          "hardening",
    "suid_audit":       "hardening",
    "logs":             "hardening",
    "umask":            "hardening",
    "auth_log":         "ssh",
    "ssl_certs":        "hardening",
    "systemd_timers":   "hardening",
    "firmware":         "hardening",
    "disk":             "disk",
    "fail2ban":         "ssh",
    "virt":             "hardening",
    "docker_hardening":     "hardening",
}


def key_to_domain(key: str | None) -> str | None:
    """
    Map a deduction key (e.g. 'ssh.password_auth') to its domain.

    Returns None for synthetic/cap deductions (empty key), which are
    excluded from per-domain scoring.
    """
    if not key or not isinstance(key, str):
        return None
    prefix = key.split(".", 1)[0]
    domain = _PREFIX_TO_DOMAIN.get(prefix)
    if domain is None:
        # New check key without a domain mapping → falls back to firewall.
        # Log so packagers/devs notice unmapped prefixes when they add checks.
        logger.debug(
            "domain_scores: prefix %r has no entry in _PREFIX_TO_DOMAIN, "
            "defaulting to 'firewall'", prefix,
        )
        return "firewall"
    return domain


# ---------------------------------------------------------------------------
# Domain → contributing sections (inverse of _PREFIX_TO_DOMAIN)
# ---------------------------------------------------------------------------
# v0.12.1: used to explain WHY an inactive domain is inactive — a domain counts
# as "skipped by the active profile" when every section that could feed it is in
# the profile's skip_sections (checked via runner._section_enabled).
#
# Most finding-key prefixes ARE the runner section name, but a few differ; M-1
# (v0.12.2) maps those so _DOMAIN_SECTIONS holds real section names rather than
# key prefixes. (Both differing sections — virtualization, ufw_logging — are
# always-on, so the mismatch was behaviourally unreachable; this fixes the
# latent inaccuracy + the comment claim.)
_PREFIX_TO_SECTION: dict[str, str] = {
    "virt": "virtualization",
    "logs": "ufw_logging",
}
_DOMAIN_SECTIONS: dict[str, set[str]] = {}
for _prefix, _dom in _PREFIX_TO_DOMAIN.items():
    _DOMAIN_SECTIONS.setdefault(_dom, set()).add(_PREFIX_TO_SECTION.get(_prefix, _prefix))
del _prefix, _dom

# Inactive-domain reason codes (v0.12.1). A domain with no actionable
# (OK/WARN/ALERT) finding is still displayed, but shown without a score and
# annotated with the reason — never counted in the global average.
REASON_INFO_ONLY       = "info_only"        # assessed; only INFO notices
REASON_PROFILE_SKIPPED = "profile_skipped"  # the active profile skips it
REASON_FILTERED        = "filtered"         # excluded by --check / --skip
REASON_NOT_INSTALLED   = "not_installed"    # service/component absent


def domain_inactive_reason(
    domain: str, engine: "ScoreEngine", profile=None, config=None,
) -> str:
    """Classify why an inactive domain produced no actionable finding.

    Only meaningful for a domain that is NOT in
    ``active_domains_from_engine(engine)``. Returns one of
    ``REASON_INFO_ONLY`` / ``REASON_PROFILE_SKIPPED`` / ``REASON_FILTERED`` /
    ``REASON_NOT_INSTALLED``.

    Order matters:
      1. A domain that emitted INFO notices was genuinely assessed → INFO_ONLY.
      2. If at least one of the domain's sections actually ran (given
         ``--check`` / ``--skip`` and the profile) yet nothing was found, the
         component is simply absent → NOT_INSTALLED.
      3. Otherwise NONE of its sections ran; say why — a ``--check`` / ``--skip``
         filter (FILTERED) or the active profile (PROFILE_SKIPPED).

    This is why ``disk`` is never wrongly "not installed": a profile that skips
    it yields PROFILE_SKIPPED, and a ``--check=ssh`` that excludes it yields
    FILTERED — only a host where the disk section ran and found nothing would
    read NOT_INSTALLED (which does not happen for disk in practice).
    """
    for finding in engine.findings:
        if finding.level is FindingLevel.INFO and key_to_domain(finding.key) == domain:
            return REASON_INFO_ONLY

    sections = _DOMAIN_SECTIONS.get(domain, set())
    if not sections:
        return REASON_NOT_INSTALLED

    # Did any of the domain's sections actually run?
    if config is not None:
        from bob.runner import _section_enabled  # lazy: runner imports this module
        ran = any(_section_enabled(s, config, profile) for s in sections)
    elif profile is not None:
        ran = any(not profile.should_skip_section(s) for s in sections)
    else:
        ran = True
    if ran:
        return REASON_NOT_INSTALLED  # ran, found nothing → component absent

    # None ran — distinguish a user filter from a profile skip.
    if config is not None:
        def _match(section: str, tokens) -> bool:
            return any(section == tok or section.startswith(tok) for tok in tokens)
        check_excludes = bool(config.check_only) and not any(
            _match(s, config.check_only) for s in sections)
        skip_excludes = bool(config.skip_checks) and all(
            _match(s, config.skip_checks) for s in sections)
        if check_excludes or skip_excludes:
            return REASON_FILTERED
    return REASON_PROFILE_SKIPPED


# ---------------------------------------------------------------------------
# Main computation
# ---------------------------------------------------------------------------

def active_domains_from_engine(engine: "ScoreEngine") -> frozenset[str]:
    """
    Return the set of domain names that have at least one finding or deduction.

    A domain is "active" when any check from that domain emitted an
    actionable signal: OK (service installed and clean), WARN, or ALERT.
    Pure-INFO findings (advisory observations) do not promote a domain
    on their own — they're explicitly excluded so domains with only
    informational notices stay hidden from the global average.

    OK is included because terrain v0.4.5 surfaced a scoring inversion:
    after remediation of a WARN/ALERT (e.g. ``apt upgrade`` resolves
    ``updates.security_pending``), the check switches to emitting only
    ``updates.ok``. Without OK in the active set, the domain dropped
    out of ``active_domains_from_engine`` and the user-observed score
    *decreased* even though the system was strictly more secure than
    before. Including OK keeps the now-clean domain at 10/10 in the
    global average instead.

    Used to hide domains whose service is not installed (e.g. Samba
    absent → no samba.* findings at all → domain excluded from the
    score display).
    """
    _actionable = (FindingLevel.OK, FindingLevel.WARN, FindingLevel.ALERT)
    active: set[str] = set()
    for finding in engine.findings:
        if finding.level not in _actionable:
            continue
        domain = key_to_domain(finding.key)
        if domain:
            active.add(domain)
    for finding in engine.ignored_findings:
        if finding.level not in _actionable:
            continue
        domain = key_to_domain(finding.key)
        if domain:
            active.add(domain)
    for deduction in engine.breakdown:
        domain = key_to_domain(deduction.key)
        if domain:
            active.add(domain)
    return frozenset(active)


def compute_domain_scores(engine: "ScoreEngine") -> "tuple[dict[str, dict], frozenset[int]]":
    """
    Compute per-domain security sub-scores from a finalized ScoreEngine.

    Each domain score is computed independently as:
        max(0, MAX_SCORE - sum_of_deductions_for_domain)

    Deductions without a key (synthetic/cap) are excluded.

    Args:
        engine: A finalized ScoreEngine (engine.finalize() must have been called).

    Returns:
        Tuple of:
          - dict mapping domain identifier → {
                "score":      int  — 0 to 10,
                "deductions": int  — total points deducted in this domain,
                "label":      str  — human-readable English label,
            }
          - frozenset[int] of indices in engine.breakdown that were tool-capped
    """
    domain_deductions: dict[str, int] = {d: 0 for d in DOMAINS}
    tool_contributed:  dict[str, int] = {}   # key_prefix → points already counted
    capped_indices:    set[int]        = set()

    for i, deduction in enumerate(engine.breakdown):
        key    = deduction.key
        domain = key_to_domain(key)
        if domain is None:
            continue
        points = deduction.points
        prefix = key.split(".", 1)[0] if key else ""
        cap    = TOOL_CAPS.get(prefix)
        if cap is not None:
            already = tool_contributed.get(prefix, 0)
            allowed = min(points, cap - already)
            if allowed <= 0:
                capped_indices.add(i)
                continue
            if allowed < points:
                capped_indices.add(i)
            tool_contributed[prefix] = already + allowed
            points = allowed
        domain_deductions[domain] += points

    # Apply engine-level domain cap (e.g. firewall inactive → max 3/10 for the
    # firewall domain).  The cap delta is normally added to the breakdown when the
    # global raw_score exceeds the cap, but if many other deductions already push
    # the global raw_score below the cap threshold the delta is never appended.
    # We enforce it here at the domain level so the displayed score is always ≤ cap.
    engine_cap = engine.cap_info
    if engine_cap and engine_cap.key:
        cap_domain = key_to_domain(engine_cap.key)
        if cap_domain and cap_domain in domain_deductions:
            raw_domain = MAX_SCORE - domain_deductions[cap_domain]
            if raw_domain > engine_cap.maximum:
                domain_deductions[cap_domain] += raw_domain - engine_cap.maximum

    scores = {
        domain: {
            "score":      max(0, min(MAX_SCORE, MAX_SCORE - domain_deductions[domain])),
            "deductions": domain_deductions[domain],
            "label":      LABELS.get(domain, domain.capitalize()),
        }
        for domain in DOMAINS
    }
    return scores, frozenset(capped_indices)


# ---------------------------------------------------------------------------
# Global score from domain average
# ---------------------------------------------------------------------------

def compute_global_from_domains(
    domain_scores: dict,
    active_domains: "frozenset[str]",
) -> int:
    """
    Compute the global security score as the mean of active domain scores.

    Only domains with at least one finding or deduction are included (i.e.
    domains whose service is not installed are excluded).  The result is
    rounded and clamped to [0, MAX_SCORE].

    Args:
        domain_scores:  Output of compute_domain_scores().
        active_domains: Output of active_domains_from_engine().

    Returns:
        Integer global score 0–10.
    """
    active = [d for d in DOMAINS if d in active_domains and d in domain_scores]
    if not active:
        return MAX_SCORE
    total = sum(domain_scores[d]["score"] for d in active)
    return max(0, min(MAX_SCORE, round(total / len(active))))


def apply_domain_score_override(engine: "ScoreEngine") -> None:
    """
    Compute the domain-averaged global score and set it on the engine.

    Must be called after engine.finalize().  All subsequent reads of
    engine.score will return the domain-averaged value.

    Args:
        engine: A finalized ScoreEngine instance.
    """
    scores, capped_indices = compute_domain_scores(engine)
    active = active_domains_from_engine(engine)
    glob = compute_global_from_domains(scores, active)
    # F1 (v0.12.0): "10/10 means a flawless audit." The domain average smooths
    # multi-deduction domains, but rounding it up can erase a real deduction —
    # a host with one pending firmware update (raw 9/10) averaged to 10/10,
    # reading as "perfect" while the summary said "Action required". When ANY
    # deduction was applied (raw_score < MAX_SCORE) we cap the headline at
    # MAX_SCORE-1, reserving a perfect score for an audit with nothing to fix.
    # Lower averages are unaffected (they already round below MAX_SCORE-1).
    precap = glob
    if engine.raw_score < MAX_SCORE:
        glob = min(glob, MAX_SCORE - 1)
    engine.set_global_score(glob, precap=precap)
    engine.set_domain_scores(scores, active, capped_indices)


# ---------------------------------------------------------------------------
# Text rendering
# ---------------------------------------------------------------------------

from bob.output import SCORE_BAR_WIDTH as _BAR_WIDTH  # single source of truth, see bob.output


def _reason_text(reason: str, t, profile_name: str) -> str:
    """Translate an inactive-domain reason code to a human label (v0.12.1)."""
    if reason == REASON_PROFILE_SKIPPED:
        if t:
            txt = t("domain_scores.reason.not_assessed", profile=profile_name)
            if txt != "domain_scores.reason.not_assessed":
                return txt
        return f"not assessed ({profile_name} profile)"
    key, fallback = {
        REASON_INFO_ONLY:     ("domain_scores.reason.no_action",     "no action needed"),
        REASON_FILTERED:      ("domain_scores.reason.filtered",      "not assessed (--check/--skip)"),
        REASON_NOT_INSTALLED: ("domain_scores.reason.not_installed", "not installed"),
    }.get(reason, ("domain_scores.reason.not_installed", "not installed"))
    if t:
        txt = t(key)
        if txt != key:
            return txt
    return fallback


def render_domain_scores(
    scores: dict[str, dict],
    t=None,
    active_domains: "frozenset[str] | None" = None,
    *,
    engine: "ScoreEngine | None" = None,
    profile=None,
    config=None,
) -> list[str]:
    """
    Render domain scores as a list of indented text lines.

    Args:
        scores: Output of compute_domain_scores().
        t:      Optional translation function.  When provided the title line
                uses the locale key 'domain_scores.title'; otherwise the
                English default is used.
        active_domains: When ``engine`` is None, restricts the display to this
                set (legacy behaviour).
        engine: v0.12.1 — when provided, ALL domains are shown. Inactive ones
                (no actionable finding) are rendered without a score and
                annotated with the reason they were not scored; they remain
                excluded from the global average. ``active_domains`` is then
                derived from the engine and the argument is ignored.
        profile: active AuditProfile — used to label a domain skipped by the
                profile as "not assessed (<profile> profile)".

    Returns:
        List of strings (one per line), ready for print().
    """
    title = (t("domain_scores.title") if t else None) or "Domain Scores"

    lines: list[str] = [f"  {title}"]
    lines.append("  " + "─" * 40)

    if not scores:
        lines.append("  (no data)")
        return lines

    show_all = engine is not None
    if show_all:
        active_domains = active_domains_from_engine(engine)

    def _label(domain: str, fallback: str) -> str:
        if not t:
            return fallback
        translated = t(f"domain_scores.{domain}")
        return translated if translated != f"domain_scores.{domain}" else fallback

    labels = {d: _label(d, scores[d]["label"]) for d in DOMAINS if d in scores}
    label_width = max(len(lbl) for lbl in labels.values())

    from bob.output import score_bar
    profile_name = getattr(profile, "name", "") or ""

    for domain in DOMAINS:
        if domain not in scores:
            continue
        is_active = active_domains is None or domain in active_domains
        if not is_active and not show_all:
            continue  # legacy: hide inactive domains entirely
        label = labels[domain]
        if is_active:
            score = scores[domain]["score"]
            bar   = score_bar(int(score * _BAR_WIDTH / MAX_SCORE))
            lines.append(f"  {label:<{label_width}}  {score:>2}/10  {bar}")
        else:
            # v0.12.1: show the domain, but with its reason instead of a score,
            # dimmed and kept out of the average.
            from bob.output import _c
            reason = domain_inactive_reason(domain, engine, profile, config)
            reason_txt = _reason_text(reason, t, profile_name)
            lines.append(
                f"  {_c.dim}{label:<{label_width}}  {'—':>5}  {reason_txt}{_c.reset}"
            )

    return lines


def domain_rows(engine: "ScoreEngine", t=None, profile=None, config=None) -> list[dict]:
    """Format-agnostic per-domain display rows (v0.12.1, ADV-B1).

    Returns one dict per domain: ``{key, label, score, active, reason}`` where
    ``score`` is the int 0–10 for an active domain (and ``None`` for an
    inactive one) and ``reason`` is the human label explaining an inactive
    domain (empty string when active). The reason classification is the single
    source shared with the text display and JSON output
    (``domain_inactive_reason``); only the rendering differs per format
    (text bars / Markdown table / HTML). Used by Markdown + HTML exports.

    Returns ``[]`` for an engine double that does not expose the domain
    interface (legacy / test fakes) — callers guard on the empty list and
    simply omit the section, never crashing the report.
    """
    if not hasattr(engine, "domain_scores") or not hasattr(engine, "active_domains"):
        return []
    scores = engine.domain_scores or compute_domain_scores(engine)[0]
    active = engine.active_domains or active_domains_from_engine(engine)
    profile_name = getattr(profile, "name", "") or ""
    rows: list[dict] = []
    for domain in DOMAINS:
        if domain not in scores:
            continue
        label = scores[domain]["label"]
        if t:
            translated = t(f"domain_scores.{domain}")
            if translated != f"domain_scores.{domain}":
                label = translated
        if domain in active:
            rows.append({"key": domain, "label": label,
                         "score": scores[domain]["score"], "active": True, "reason": ""})
        else:
            reason = domain_inactive_reason(domain, engine, profile, config)
            rows.append({"key": domain, "label": label, "score": None,
                         "active": False, "reason": _reason_text(reason, t, profile_name)})
    return rows
