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
        # F1 (v0.12.0): the domain average BEFORE the "10 reserved for a
        # flawless audit" cap, so --breakdown can show the average and the cap
        # as two distinct steps rather than a single opaque number.
        self._global_precap: int | None = None
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

        # v0.10.0 D-4 — accept both exact matches (operator already
        # migrated their ignore.yml to canonical sub-keys) AND legacy
        # umbrella entries (operator wrote ``ssh.x11_forwarding`` pre-
        # v0.10.0 and expects it to keep silencing the now-split
        # ``ssh.x11.forwarding.{server,client}`` findings). The legacy
        # path uses fnmatch globs from SUBCHECK_RENAMES_V100 — see
        # ``bob/_v100_subcheck_renames.py`` for the migration table.
        from bob._v100_subcheck_renames import any_legacy_ignore_matches

        def _is_ignored(key: str | None) -> bool:
            if not (ignored_keys and key):
                return False
            if key in ignored_keys:
                return True
            return any_legacy_ignore_matches(key, ignored_keys)

        for deduction in result.deductions:
            if not _is_ignored(deduction.key):
                self._apply_deduction(deduction)
        for finding in result.findings:
            if _is_ignored(finding.key):
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

    def set_global_score(self, score: int, precap: "int | None" = None) -> None:
        """
        Override the global score with a domain-averaged value.

        Called by domain_scores.apply_domain_score_override() after finalize(),
        so that engine.score reflects the mean of active domain scores rather
        than the raw sum of all deductions.

        Do not call this directly — use apply_domain_score_override(engine)
        from bob.domain_scores, which computes the correct domain average.
        The raw pre-override score remains accessible as engine._raw_score.

        ``precap`` is the domain average before the F1 flawless-audit cap; it
        defaults to ``score`` when no cap was applied.
        """
        self._global_override = max(0, min(MAX_SCORE, score))
        self._global_precap = (
            max(0, min(MAX_SCORE, precap)) if precap is not None
            else self._global_override
        )

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
        # I-3 (v0.7.0 Phase 2.1): explicit bool rejection. ``isinstance(x, int)``
        # returns True for bool (subclass of int), so the original guard let
        # ``firewall_domain_score=fw_active`` slip through. A bool would then
        # coerce to 0/1 and silently trigger the ``<=3`` MEDIUM branch.
        if firewall_domain_score is not None and (
            isinstance(firewall_domain_score, bool)
            or not isinstance(firewall_domain_score, int)
        ):
            raise TypeError(
                f"firewall_domain_score must be int or None, got "
                f"{type(firewall_domain_score).__name__}. "
                f"Did you pass engine.domain_scores['firewall'] (a dict) "
                f"instead of engine.domain_scores['firewall']['score'] (an int)? "
                f"Note: bool is rejected explicitly even though it subclasses "
                f"int — pass an actual score integer."
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
    def domain_average_precap(self) -> int | None:
        """The domain average BEFORE the F1 flawless-audit cap (v0.12.0).

        Equals ``global_override`` when no cap was applied. Used by
        ``--breakdown`` to show the average and the cap as two steps.
        """
        return self._global_precap

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


# ---------------------------------------------------------------------------
# Posture escalation — engine consumer helper (I-2, v0.7.0 Phase 2.1)
# ---------------------------------------------------------------------------

def unpack_posture_escalation(engine: ScoreEngine) -> tuple[RiskLevel | None, str]:
    """Defensively unpack ``engine.posture_escalation`` for output sites.

    Real ``ScoreEngine`` instances always return a ``tuple[RiskLevel|None, str]``
    (``set_posture`` defaults yield ``(None, "")``). Test mocks (MagicMock-style)
    may return a non-iterable; without this guard, output sites would crash with
    TypeError/ValueError during unpacking — exactly the class of bug fixed by
    the Phase 1 hotfix 4ed2e3b for the summary box.

    Returns ``(None, "")`` on any unpacking failure so callers can render a
    minimal output instead of crashing.

    This helper is the single source of truth for the defensive pattern; the
    audit findings I-2 from project_v07x_phase1 strategy rule 1 (integration-
    first) recommended consolidating it before Phase 3 (T3 plugin sandbox
    runner) which will add new engine consumers that need the same guard.
    """
    _esc = getattr(engine, "posture_escalation", (None, ""))
    try:
        floor, key = _esc
        return floor, key
    except (TypeError, ValueError):
        return None, ""


def set_posture_from_engine(engine: "ScoreEngine", fw_active: bool) -> None:
    """M-10 (v0.7.3): consolidated call site for the posture-escalation
    setup duplicated in ``bob/__main__.py`` (the audit summary path) and
    ``bob/watch.py`` (the watch-mode iteration path).

    The two pre-v0.7.3 sites computed ``_fw = engine.domain_scores.get(
    "firewall")`` then called ``engine.set_posture(firewall_inactive=...,
    iptables_input_accept=..., firewall_domain_score=...)``. The helper
    centralises the dict-vs-int guard on the firewall domain score (Phase
    1 4ed2e3b lesson) so a future contributor adding a new entry point
    can't accidentally pass the wrong shape.

    Args:
        engine: A finalised ``ScoreEngine`` whose ``apply()`` calls are
                done and ``domain_score_override`` has been applied.
        fw_active: True if UFW was detected as active in the current audit.
                   Anything else (UFW disabled or detection failure)
                   triggers the ``firewall_inactive`` posture floor.
    """
    _fw_domain = engine.domain_scores.get("firewall")
    # Guard against the v0.7.0 Phase 1 4ed2e3b regression class: when
    # domain_scores contains a dict, extract the .score key; when it's
    # a legacy bare int, use it directly; when missing, pass None.
    # M-8 (v0.7.4): ``isinstance(bool, int)`` is True (bool is a subclass
    # of int) — without the explicit bool reject, a ``firewall: True`` in
    # domain_scores would slip through here and then raise TypeError in
    # ``set_posture``'s explicit-bool guard. Normalise to None so the
    # posture check still runs.
    if isinstance(_fw_domain, bool):
        _fw_score = None
    elif isinstance(_fw_domain, dict):
        _fw_score = _fw_domain.get("score")
    elif isinstance(_fw_domain, int):
        _fw_score = _fw_domain
    else:
        _fw_score = None
    engine.set_posture(
        firewall_inactive=not fw_active,
        # v0.10.2 I-1: the v0.9.0 D-1 rename ``iptables_nft.*`` →
        # ``firewall_iptables.*`` left this string-literal comparison
        # matching the retired prefix, so the iptables-passthrough
        # escalation has been silently dead since v0.9.0. Masked in
        # practice by the ``firewall_inactive`` branch (UFW down + iptables
        # ACCEPT both escalate to HIGH), but the iptables-only escalation
        # (UFW active + iptables ACCEPT rule) regressed to LOW.
        iptables_input_accept=any(
            f.key == "firewall_iptables.input_accept" for f in engine.findings
        ),
        firewall_domain_score=_fw_score,
    )
