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
_PREFIX_TO_DOMAIN: dict[str, str] = {
    "ssh":              "ssh",
    "samba":            "samba",
    "file_perms":       "file_perms",
    "updates":          "updates",
    "hardening":        "hardening",
    "kernel_hardening": "hardening",
    "kernel_modules":   "hardening",
    "cron_audit":       "hardening",
    "services_state":   "hardening",
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
    engine.set_global_score(compute_global_from_domains(scores, active))
    engine.set_domain_scores(scores, active, capped_indices)


# ---------------------------------------------------------------------------
# Text rendering
# ---------------------------------------------------------------------------

from bob.output import SCORE_BAR_WIDTH as _BAR_WIDTH  # single source of truth, see bob.output


def render_domain_scores(
    scores: dict[str, dict],
    t=None,
    active_domains: "frozenset[str] | None" = None,
) -> list[str]:
    """
    Render domain scores as a list of indented text lines.

    Args:
        scores: Output of compute_domain_scores().
        t:      Optional translation function.  When provided the title line
                uses the locale key 'domain_scores.title'; otherwise the
                English default is used.

    Returns:
        List of strings (one per line), ready for print().
    """
    title = (t("domain_scores.title") if t else None) or "Domain Scores"

    lines: list[str] = [f"  {title}"]
    lines.append("  " + "─" * 40)

    if not scores:
        lines.append("  (no data)")
        return lines

    def _label(domain: str, fallback: str) -> str:
        if not t:
            return fallback
        translated = t(f"domain_scores.{domain}")
        return translated if translated != f"domain_scores.{domain}" else fallback

    labels = {d: _label(d, scores[d]["label"]) for d in DOMAINS if d in scores}
    label_width = max(len(lbl) for lbl in labels.values())

    for domain in DOMAINS:
        if domain not in scores:
            continue
        if active_domains is not None and domain not in active_domains:
            continue
        info  = scores[domain]
        score = info["score"]
        label = labels[domain]
        from bob.output import score_bar
        bar   = score_bar(int(score * _BAR_WIDTH / MAX_SCORE))
        lines.append(
            f"  {label:<{label_width}}  {score:>2}/10  {bar}"
        )

    return lines
