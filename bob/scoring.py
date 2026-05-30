"""
Scoring engine for BOB.

Maintains the security score (0-10), accumulates deductions from
individual checks, and derives the risk level from the final score.

No display logic lives here. All findings are plain data structures
consumed by output.py and report.py.

Usage:
    from bob.scoring import ScoreEngine, CheckResult, Deduction, Finding, FindingLevel

    engine = ScoreEngine()

    # Each check returns a CheckResult
    result = CheckResult(
        deductions=[Deduction(reason="Open port", points=2, context="public")],
        findings=[Finding(level=FindingLevel.ALERT, message="Port 22 open to internet")],
    )
    engine.apply(result)

    print(engine.score)    # 8
    print(engine.level)    # "low"
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class FindingLevel(Enum):
    """Severity level of a finding reported by a check."""
    OK      = "ok"
    INFO    = "info"
    WARN    = "warn"
    ALERT   = "alert"

class RiskLevel(Enum):
    """Overall risk level derived from the final score."""
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"

# Score thresholds — inclusive lower bound for each level
_RISK_THRESHOLDS: list[tuple[int, RiskLevel]] = [
    (8, RiskLevel.LOW),
    (5, RiskLevel.MEDIUM),
    (3, RiskLevel.HIGH),
    (0, RiskLevel.CRITICAL),
]

# Ordered for "max" comparison — LOW < MEDIUM < HIGH < CRITICAL (v0.7.0).
_RISK_ORDER: tuple[RiskLevel, ...] = (
    RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL,
)


def _risk_max(a: RiskLevel, b: "RiskLevel | None") -> RiskLevel:
    """Return the stricter of two risk levels. ``None`` is treated as no floor."""
    if b is None:
        return a
    return _RISK_ORDER[max(_RISK_ORDER.index(a), _RISK_ORDER.index(b))]

# Maximum achievable score
MAX_SCORE: int = 10

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

VALID_CONTEXTS: frozenset[str] = frozenset({"local", "public", "ddns", "structural"})

@dataclass
class Deduction:
    """
    A single score deduction with its justification.

    Args:
        reason:        Human-readable explanation (already translated by caller).
        points:        Number of points deducted (positive integer).
        context:       Network context at time of deduction — "local", "public",
                       or "structural" (for synthetic cap deductions).
                       Used for display in the score breakdown.
        key:           Stable i18n key linking this deduction to its Finding, so
                       that audit profiles can remove it deterministically when a
                       finding is skipped or downgraded to INFO.
                       Empty string means the deduction is not profile-controlled.
        template_vars: Optional mapping of variables used to interpolate `key`'s
                       i18n template (e.g. ``{"ciphers": "aes128-cbc, des-cbc"}``
                       for ``ssh.weak_ciphers``). When non-empty, external clients
                       can rebuild a localized `reason` from `key + template_vars`
                       without parsing the pre-formatted `reason` string.
                       Locale-independent contract — see DOCUMENTS/README_TECH.md
                       "JSON output schema". Additive since v0.4.1; legacy checks
                       leave this empty and still ship a fully-formatted `reason`.
    """
    reason:        str
    points:        int
    context:       str  = "local"
    key:           str  = ""
    template_vars: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.points < 0:
            raise ValueError(f"Deduction points must be non-negative, got {self.points}")
        if self.context not in VALID_CONTEXTS:
            raise ValueError(
                f"Deduction context {self.context!r} is invalid. "
                f"Must be one of: {sorted(VALID_CONTEXTS)}"
            )

@dataclass
class Finding:
    """
    A single audit finding for display in the terminal and report.

    Args:
        level:         Severity level (OK, INFO, WARN, ALERT).
        message:       Main finding message (already translated by caller).
        detail:        Optional secondary detail or recommendation text.
        nature:        Category used by --fix mode: "action" | "improvement" | "structural" | "".
        cmd:           Shell command shown in the "Que faire ?" block. Empty string if none.
        cmd_type:      How the command should be rendered: "fix" (→, default) or "check" (ℹ).
                       Use "check" for read-only diagnostic commands that do not change state.
        note:          Optional disclaimer or contextual warning shown after the cmd.
        key:           Stable i18n key linking this finding to a Deduction.reason so
                       audit profiles can override its severity.  Empty string means
                       the finding is not individually overridable by profiles.
        template_vars: Optional mapping of variables used to interpolate `key`'s
                       i18n template (e.g. ``{"count": 42}`` for a count placeholder).
                       When non-empty, external clients can rebuild a localized
                       message from `key + template_vars` via ``bob.formatter.format_finding()``
                       without depending on the pre-formatted `message` string.
                       Additive since v0.4.1; legacy checks leave this empty.
    """
    level:         FindingLevel
    message:       str
    detail:        str = ""
    nature:        str = ""
    cmd:           str = ""
    cmd_type:      str = "fix"
    note:          str = ""
    key:           str = ""
    template_vars: dict = field(default_factory=dict)

@dataclass
class ScoreCap:
    """
    A score ceiling request emitted by a check and processed by ScoreEngine.apply().

    Checks that need to impose a hard score ceiling (e.g. firewall inactive → max 3)
    attach a ScoreCap to their CheckResult rather than calling engine.cap() directly.
    This keeps orchestration logic inside the check where it belongs.
    """
    maximum: int
    reason:  str
    key:     str = ""

@dataclass
class CheckResult:
    """
    The complete output of a single check function.

    Returned by every check_* function and consumed by ScoreEngine.apply().

    Args:
        deductions:  List of score deductions to apply.
        findings:    List of findings to display.
        open_ports:  Ports identified as exposed (used by DDNS check for display).
        caps:        Score ceiling requests to be applied by the engine.
    """
    deductions:  list[Deduction] = field(default_factory=list)
    findings:    list[Finding]   = field(default_factory=list)
    open_ports:  list[str]       = field(default_factory=list)
    caps:        list[ScoreCap]  = field(default_factory=list)

    def add_deduction(
        self,
        reason: str,
        points: int,
        context: str = "local",
        key: str = "",
        template_vars: "dict | None" = None,
    ) -> None:
        """Convenience method to append a deduction. See Deduction docstring for template_vars contract."""
        self.deductions.append(
            Deduction(
                reason=reason, points=points, context=context, key=key,
                template_vars=dict(template_vars) if template_vars else {},
            )
        )

    def set_cap(self, maximum: int, reason: str, key: str = "") -> None:
        """
        Request a score ceiling to be enforced by the engine.

        Prefer this over calling engine.cap() directly in orchestrators —
        it keeps the cap logic co-located with the check that motivates it.
        """
        self.caps.append(ScoreCap(maximum=maximum, reason=reason, key=key))

    def add_finding(
        self,
        level: FindingLevel,
        message: str,
        detail: str = "",
        nature: str = "",
        cmd: str = "",
        cmd_type: str = "fix",
        note: str = "",
        key: str = "",
        template_vars: "dict | None" = None,
    ) -> None:
        """Convenience method to append a finding. See Finding docstring for template_vars contract."""
        self.findings.append(
            Finding(
                level=level, message=message, detail=detail,
                nature=nature, cmd=cmd, cmd_type=cmd_type, note=note, key=key,
                template_vars=dict(template_vars) if template_vars else {},
            )
        )

    def ok(self, message: str, detail: str = "", key: str = "",
           template_vars: "dict | None" = None) -> None:
        """Shorthand for adding an OK finding."""
        self.add_finding(FindingLevel.OK, message, detail, key=key, template_vars=template_vars)

    def info(self, message: str, detail: str = "", cmd: str = "", cmd_type: str = "fix",
             key: str = "", template_vars: "dict | None" = None) -> None:
        """Shorthand for adding an INFO finding."""
        self.add_finding(FindingLevel.INFO, message, detail, cmd=cmd, cmd_type=cmd_type,
                         key=key, template_vars=template_vars)

    def warn(self, message: str, detail: str = "", nature: str = "improvement", cmd: str = "",
             cmd_type: str = "fix", note: str = "", key: str = "",
             template_vars: "dict | None" = None) -> None:
        """Shorthand for adding a WARN finding."""
        self.add_finding(FindingLevel.WARN, message, detail, nature, cmd, cmd_type, note,
                         key=key, template_vars=template_vars)

    def alert(self, message: str, detail: str = "", nature: str = "action", cmd: str = "",
              cmd_type: str = "fix", note: str = "", key: str = "",
              template_vars: "dict | None" = None) -> None:
        """Shorthand for adding an ALERT finding."""
        self.add_finding(FindingLevel.ALERT, message, detail, nature, cmd, cmd_type, note,
                         key=key, template_vars=template_vars)

    def warn_with_deduction(
        self,
        key: str,
        *,
        message: str,
        points: int,
        reason: "str | None" = None,
        context: str = "local",
        detail: str = "",
        nature: str = "improvement",
        cmd: str = "",
        cmd_type: str = "fix",
        note: str = "",
        template_vars: "dict | None" = None,
    ) -> None:
        """Add a WARN finding and a matching deduction in one call.

        Collapses the paired ``result.warn(...) + result.add_deduction(...)``
        idiom that recurs ~130 times across ``bob/checks/*.py``. The same
        ``key`` and ``template_vars`` are used for both the finding and the
        deduction. The deduction ``reason`` defaults to ``message`` — pass
        ``reason=`` explicitly when the deduction string uses a different
        translation key (e.g. ``ssh.host_key_dsa_reason`` differs from
        ``ssh.host_key_dsa``).
        """
        self.warn(
            message=message, detail=detail, nature=nature,
            cmd=cmd, cmd_type=cmd_type, note=note,
            key=key, template_vars=template_vars,
        )
        self.add_deduction(
            reason=reason if reason is not None else message,
            points=points, context=context,
            key=key, template_vars=template_vars,
        )

    def alert_with_deduction(
        self,
        key: str,
        *,
        message: str,
        points: int,
        reason: "str | None" = None,
        context: str = "local",
        detail: str = "",
        nature: str = "action",
        cmd: str = "",
        cmd_type: str = "fix",
        note: str = "",
        template_vars: "dict | None" = None,
    ) -> None:
        """Add an ALERT finding and a matching deduction in one call.

        See :meth:`warn_with_deduction` for the contract.
        """
        self.alert(
            message=message, detail=detail, nature=nature,
            cmd=cmd, cmd_type=cmd_type, note=note,
            key=key, template_vars=template_vars,
        )
        self.add_deduction(
            reason=reason if reason is not None else message,
            points=points, context=context,
            key=key, template_vars=template_vars,
        )

# ---------------------------------------------------------------------------
# Score engine
# ---------------------------------------------------------------------------

class ScoreEngine:
    """
    Accumulates deductions from check results and computes the final score.

    The score starts at MAX_SCORE (10) and decreases with each deduction.
    A cap can be applied to enforce an absolute ceiling (e.g. firewall inactive → max 3).
    The cap is applied once, after all deductions, in finalize().

    Attributes:
        score:     Current score (0–10). Updated by apply() and finalize().
        breakdown: Ordered list of all applied deductions.
        findings:  Flat list of all findings from all applied CheckResults.
    """

    def __init__(self) -> None:
        self._raw_score: int = MAX_SCORE
        self._cap: ScoreCap | None = None
        self._global_override: int | None = None
        self.breakdown: list[Deduction] = []
        self.findings:  list[Finding]   = []
        self.ignored_findings: list[Finding] = []
        self.ignore_keys: frozenset[str] = frozenset()
        self._finalized: bool = False
        self._domain_scores: dict | None = None
        self._active_domains: frozenset | None = None
        self._capped_indices: frozenset[int] = frozenset()
        # Posture escalation state (v0.7.0) — set via set_posture(); consumed
        # by effective_level + posture_escalation.
        self._posture_firewall_inactive: bool = False
        self._posture_iptables_input_accept: bool = False
        self._posture_firewall_domain_score: int | None = None

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def apply(self, result: CheckResult) -> None:
        """
        Apply all deductions, findings, and caps from a CheckResult.

        Findings and deductions whose key is in self.ignore_keys are silently
        dropped and stored in self.ignored_findings for optional display.

        Caps embedded in result.caps are forwarded to engine.cap() so
        the orchestrator does not need to inspect check results directly.

        Args:
            result: Output of a check_* function.
        """
        ignored_keys = self.ignore_keys
        for deduction in result.deductions:
            if not (ignored_keys and deduction.key and deduction.key in ignored_keys):
                self._apply_deduction(deduction)
        for finding in result.findings:
            if ignored_keys and finding.key and finding.key in ignored_keys:
                self.ignored_findings.append(finding)
            else:
                self.findings.append(finding)
        for cap in result.caps:
            self.cap(maximum=cap.maximum, reason=cap.reason, key=cap.key)

    def deduct(self, reason: str, points: int, context: str = "local") -> None:
        """
        Apply a single deduction directly (without a CheckResult wrapper).

        Useful for deductions that arise from cross-check logic in the
        orchestrator rather than from a single check function.

        Args:
            reason:  Explanation string.
            points:  Points to deduct (positive integer).
            context: "local" or "public".
        """
        self._apply_deduction(Deduction(reason=reason, points=points, context=context))

    def cap(self, maximum: int, reason: str, key: str = "") -> None:
        """
        Register a score ceiling to be enforced during finalize().

        Only the lowest cap wins if cap() is called multiple times.

        Args:
            maximum: Score will not exceed this value after finalize().
            reason:  Explanation string displayed in the breakdown.
            key:     Stable i18n key linking this cap to its finding.
        """
        if self._cap is None or maximum < self._cap.maximum:
            self._cap = ScoreCap(maximum=maximum, reason=reason, key=key)

    def set_domain_scores(
        self,
        scores: dict,
        active: "frozenset[str]",
        capped_indices: "frozenset[int] | None" = None,
    ) -> None:
        """Cache domain scores computed by apply_domain_score_override()."""
        self._domain_scores  = scores
        self._active_domains = active
        self._capped_indices = capped_indices or frozenset()

    def set_global_score(self, score: int) -> None:
        """
        Override the global score with a domain-averaged value.

        Called by domain_scores.apply_domain_score_override() after finalize(),
        so that engine.score reflects the mean of active domain scores rather
        than the raw sum of all deductions.

        Do not call this directly — use apply_domain_score_override(engine)
        from bob.domain_scores, which computes the correct domain average.
        The raw pre-override score remains accessible as engine._raw_score.
        """
        self._global_override = max(0, min(MAX_SCORE, score))

    def finalize(self) -> None:
        """
        Apply the registered cap (if any) and clamp the score to [0, MAX_SCORE].

        If a cap reduces the score, a synthetic Deduction is added to the
        breakdown so the cap reason appears in the score breakdown.

        Should be called once, after all checks have run.
        Safe to call multiple times — subsequent calls are no-ops.

        Required call sequence (orchestrator contract):
            engine.finalize()
            apply_domain_score_override(engine)   # from bob.domain_scores

        After finalize() but before apply_domain_score_override(), engine.score
        returns the raw deduction-based score.  The domain-averaged global score
        is only available after apply_domain_score_override() sets the override.
        """
        if self._finalized:
            return
        if self._cap is not None and self._raw_score > self._cap.maximum:
            delta = self._raw_score - self._cap.maximum
            self.breakdown.append(
                Deduction(reason=self._cap.reason, points=delta, context="structural", key=self._cap.key)
            )
            self._raw_score = self._cap.maximum
        self._raw_score = max(0, min(MAX_SCORE, self._raw_score))
        self._finalized = True

    # ------------------------------------------------------------------
    # Read-only properties
    # ------------------------------------------------------------------

    @property
    def score(self) -> int:
        """
        Current score after all deductions and cap.

        Returns the domain-averaged global score if set_global_score() has been
        called; otherwise falls back to the raw deduction-based score.
        Calls finalize() implicitly if not yet called.
        """
        if not self._finalized:
            self.finalize()
        if self._global_override is not None:
            return self._global_override
        return self._raw_score

    @property
    def level(self) -> RiskLevel:
        """Risk level derived from the current score (score-only, pre-posture).

        Use ``effective_level`` for user-facing output — it includes posture
        escalation when the firewall is structurally broken even with a
        decent score.
        """
        s = self.score
        for threshold, risk in _RISK_THRESHOLDS:
            if s >= threshold:
                return risk
        return RiskLevel.CRITICAL  # fallback — should never be reached

    # -- posture escalation (v0.7.0) ----------------------------------------
    #
    # Background: pre-v0.7.0, the displayed risk level was derived purely
    # from the global score. A host with UFW OFF + INPUT ACCEPT but with
    # otherwise clean domains would still display "LOW risk" because the
    # global score (a weighted domain average) stays high (~8/10). The
    # firewall *domain* score is correctly capped to 3 but the global is not
    # — by design, see DOCUMENTS/README_TECH.md "Score architecture".
    #
    # The fix decouples posture from exposure: ``effective_level`` returns
    # ``max(score-derived level, posture floor)`` so a structurally broken
    # firewall always lifts the level out of LOW. Network exposure (LAN vs
    # public) is still the *base* driver — posture only adds a floor.

    def set_posture(
        self,
        *,
        firewall_inactive: bool = False,
        iptables_input_accept: bool = False,
        firewall_domain_score: int | None = None,
    ) -> None:
        """Record posture state for ``effective_level``/``posture_escalation``.

        Idempotent — calling twice with the same args is safe. Subsequent
        calls overwrite earlier state.

        Type guard: ``firewall_domain_score`` MUST be ``int`` or ``None``.
        Passing the full ``engine.domain_scores["firewall"]`` dict by mistake
        used to silently break ``posture_escalation`` at the ``<=`` comparison
        site; we now fail loudly with a clear TypeError instead.
        """
        if firewall_domain_score is not None and not isinstance(firewall_domain_score, int):
            raise TypeError(
                f"firewall_domain_score must be int or None, got "
                f"{type(firewall_domain_score).__name__}. "
                f"Did you pass engine.domain_scores['firewall'] (a dict) "
                f"instead of engine.domain_scores['firewall']['score'] (an int)?"
            )
        self._posture_firewall_inactive = firewall_inactive
        self._posture_iptables_input_accept = iptables_input_accept
        self._posture_firewall_domain_score = firewall_domain_score

    @property
    def posture_escalation(self) -> "tuple[RiskLevel | None, str]":
        """Return ``(floor, locale_key)`` — ``(None, "")`` when posture is fine.

        Triggers (in priority order — first match wins, see v0.7.0 design
        discussion Q1 option D):

        - ``firewall_inactive``       → ``HIGH``  (``scoring.posture.firewall_inactive``)
        - ``iptables_input_accept``   → ``HIGH``  (``scoring.posture.iptables_input_accept``)
        - ``firewall_domain_score ≤ 3`` → ``MEDIUM`` (``scoring.posture.firewall_domain_low``)
        """
        if self._posture_firewall_inactive:
            return RiskLevel.HIGH, "scoring.posture.firewall_inactive"
        if self._posture_iptables_input_accept:
            return RiskLevel.HIGH, "scoring.posture.iptables_input_accept"
        if (self._posture_firewall_domain_score is not None
                and self._posture_firewall_domain_score <= 3):
            return RiskLevel.MEDIUM, "scoring.posture.firewall_domain_low"
        return None, ""

    @property
    def effective_level(self) -> RiskLevel:
        """``level`` adjusted for posture escalation.

        Equals ``level`` when ``set_posture`` has not been called or when
        every trigger is False. Otherwise returns ``max(level, posture_floor)``.
        """
        floor, _ = self.posture_escalation
        return _risk_max(self.level, floor)

    @property
    def cap_info(self) -> ScoreCap | None:
        """The registered cap, or None if no cap was set."""
        return self._cap

    @property
    def raw_score(self) -> int:
        """Score after deductions and engine cap, before domain-average override."""
        return self._raw_score

    @property
    def global_override(self) -> int | None:
        """Domain-average override set by apply_domain_score_override(), or None."""
        return self._global_override

    @property
    def domain_scores(self) -> dict:
        """Per-domain scores cached by apply_domain_score_override(). Empty dict before that."""
        return self._domain_scores or {}

    @property
    def active_domains(self) -> "frozenset[str]":
        """Active domain set cached by apply_domain_score_override(). Empty frozenset before that."""
        return self._active_domains or frozenset()

    @property
    def capped_indices(self) -> "frozenset[int]":
        """Indices in engine.breakdown that were tool-capped during domain score computation."""
        return self._capped_indices

    @property
    def alert_count(self) -> int:
        """Number of ALERT-level findings."""
        return sum(1 for f in self.findings if f.level == FindingLevel.ALERT)

    @property
    def warn_count(self) -> int:
        """Number of WARN-level findings."""
        return sum(1 for f in self.findings if f.level == FindingLevel.WARN)

    @property
    def info_count(self) -> int:
        """Number of INFO-level findings."""
        return sum(1 for f in self.findings if f.level == FindingLevel.INFO)

    @property
    def ok_count(self) -> int:
        """Number of OK-level findings."""
        return sum(1 for f in self.findings if f.level == FindingLevel.OK)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _apply_deduction(self, deduction: Deduction) -> None:
        # I-2 (v0.5.5): defensive guard against post-finalize deductions.
        # The orchestrator contract is one-way: finalize() bakes in the cap
        # then sets _finalized=True. A late deduction would mutate
        # _raw_score *after* the cap was applied — bypassing it silently.
        # Log and drop instead.
        if self._finalized:
            logger.warning(
                "ScoreEngine: deduction %r applied after finalize() — discarded "
                "to preserve cap semantics. Re-order callers if intentional.",
                deduction.key or deduction.reason[:40],
            )
            return
        self._raw_score -= deduction.points
        self.breakdown.append(deduction)
