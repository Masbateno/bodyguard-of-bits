"""
Display helpers for BOB.

Terminal output and report writing for check results, risk context,
log analysis, and the final audit summary.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from bob.cis_refs import get_cis_ref, get_cis_code
from bob.visibility import section_of


def _print_recurrence(prev_count: int) -> None:
    """Print a ↩ N× annotation when a finding has been seen in previous audits."""
    if prev_count <= 0:
        return
    from bob.output import _c
    total = prev_count + 1
    print(f"  {_c.cyan}↩ {total}×{_c.reset}")


def _wrap_for_box(prefix: str, text: str, inner: int) -> list[tuple[str, str]]:
    """Wrap text to fit inside a summary box of given inner width.

    The prefix is placed on the first line; continuation lines are indented
    to align with the text start. Returns a list of (content, "") tuples
    ready for print_summary_box.
    """
    avail = inner - len(prefix)
    if avail <= 0:
        return [(prefix, "")]
    if len(text) <= avail:
        return [(f"{prefix}{text}", "")]

    indent = " " * len(prefix)
    words = text.split()
    chunks: list[str] = []
    current = ""
    for word in words:
        # Truncate tokens that cannot fit on a line even alone
        if len(word) > avail:
            word = word[:avail - 1] + "…"
        if not current:
            current = word
        elif len(current) + 1 + len(word) <= avail:
            current += " " + word
        else:
            chunks.append(current)
            current = word
    if current:
        chunks.append(current)

    return [
        (f"{prefix}{line}" if i == 0 else f"{indent}{line}", "")
        for i, line in enumerate(chunks)
    ]


# ---------------------------------------------------------------------------
# Check result display
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _LevelTraits:
    """Per-finding-level display traits consumed by display_result.

    `detail_unconditional` is the ALERT-only exception: detail lines render
    even without --verbose. All other levels gate detail/cmd behind verbose.
    """
    report_label: str
    threshold_key: str
    print_fn: Callable[[str], None]
    has_recurrence: bool
    has_body: bool
    detail_unconditional: bool
    show_note: bool
    show_cis: bool


def _emit_finding_body(finding, traits: _LevelTraits, verbose: bool) -> None:
    """Emit detail / cmd / note / CIS lines for a finding, gated by traits and verbose."""
    if not traits.has_body:
        return
    from bob.output import (
        print_recommendation, print_check_cmd, print_dim, print_info,
    )
    detail = finding.detail.splitlines() if finding.detail else []
    if verbose and finding.cmd:
        if finding.cmd_type == "check":
            if detail:
                print_recommendation(detail)
            print_check_cmd(finding.cmd.splitlines())
        else:
            print_recommendation(detail, finding.cmd.splitlines())
    elif (verbose or traits.detail_unconditional) and detail:
        print_recommendation(detail)
    if traits.show_note and verbose and finding.note:
        print_info(finding.note)
    if traits.show_cis and verbose and finding.key:
        _cis = get_cis_ref(finding.key)
        if _cis:
            print_dim(_cis)


def display_result(
    result,
    report,
    verbose: bool,
    quiet: bool = False,
    recurrence: "dict[str, int] | None" = None,
) -> None:
    """Print all findings from a CheckResult to terminal and report."""
    from bob.scoring import FindingLevel
    from bob.output import (
        print_ok, print_warn, print_alert, print_info, _passes_threshold,
    )

    dispatch = {
        FindingLevel.OK:    _LevelTraits("OK",    "ok",    print_ok,    False, False, False, False, False),
        FindingLevel.WARN:  _LevelTraits("WARN",  "warn",  print_warn,  True,  True,  False, False, True),
        FindingLevel.ALERT: _LevelTraits("ALERT", "alert", print_alert, True,  True,  True,  True,  True),
        FindingLevel.INFO:  _LevelTraits("INFO",  "info",  print_info,  False, True,  False, False, False),
    }

    for finding in result.findings:
        if quiet:
            report.write_finding(finding.level.value.upper(), finding.message)
            continue
        traits = dispatch.get(finding.level)
        if traits is None:
            continue
        report.write_finding(traits.report_label, finding.message)
        if not _passes_threshold(traits.threshold_key):
            continue
        traits.print_fn(finding.message)
        if traits.has_recurrence and recurrence and finding.key:
            _print_recurrence(recurrence.get(finding.key, 0))
        _emit_finding_body(finding, traits, verbose)


# ---------------------------------------------------------------------------
# Risk context display
# ---------------------------------------------------------------------------

def display_risk_context(label: str, lang: str, t, report,
                         context_note: str | None = None,
                         is_local: bool = False) -> None:
    """Display two-axis risk context for a high/critical service."""
    # M-3 (v0.8.1 audit): centralised transform in ``bob.registry`` to
    # close the 3-way drift between this site, ``print_audit_summary``
    # below, and ``bob.explain._render_dynamic_service_explain``.
    from bob.registry import service_label_to_subkey
    svc_id = service_label_to_subkey(label)
    exposure = t(f"service_risk.{svc_id}.exposure")
    threat   = t(f"service_risk.{svc_id}.threat")
    level    = t(f"service_risk.{svc_id}.level")

    if exposure.startswith("["):
        return

    level_lower = level.lower()
    if "critical" in level_lower or "critique" in level_lower:
        risk_tier = "critical"
    elif "medium" in level_lower or "moyen" in level_lower:
        risk_tier = "medium"
    else:
        risk_tier = "low"

    level_display = f"{level} • LAN" if is_local else level

    from bob.output import print_risk_context, print_info
    print_risk_context(
        title=t("risk_context.title"),
        level=level_display,
        exposure_label=t("risk_context.exposure"),
        exposure=exposure,
        threat_label=t("risk_context.threat"),
        threat=threat,
        risk_tier=risk_tier,
    )
    if context_note:
        print_info(context_note)
    report.write_finding("INFO",
                         f"[{t('risk_context.title')} — {level_display}] {exposure}")


# ---------------------------------------------------------------------------
# Single service check + display
# ---------------------------------------------------------------------------

def check_single_service_display(snap, network_context, t, report, verbose,
                                  quiet: bool = False, ufw_active: bool = True):
    """Run check for a single service and return its CheckResult."""
    from bob.checks.services import check_services
    result = check_services([snap], network_context=network_context,
                            ufw_active=ufw_active, t=t)
    display_result(result, report, verbose, quiet=quiet)
    return result


# ---------------------------------------------------------------------------
# Log results display
# ---------------------------------------------------------------------------

def display_log_results(logs_result, snapshot, log_report, config, t, report) -> None:
    """Display structured log analysis results.

    ``log_report`` is a ``LogReportData`` or ``None`` (when no log file was
    found or the log was empty — fall back to generic finding display).

    I-1 (v0.7.4): all ``print_*`` calls are gated by ``config.quiet`` so
    ``bob -q`` produces empty stdout. ``report.write_*`` calls always run so
    the .log file (and machine-readable formats) remain complete.
    """
    from bob.checks.logs import get_ip_geo
    from bob.output import print_ok, print_warn, print_info, print_dim

    quiet = config.quiet

    if log_report is None:
        display_result(logs_result, report, config.verbose, quiet=quiet)
        return

    if not quiet:
        print_dim(
            f"{t('logs.period')} : {log_report.log_days} {t('logs.days_unit')} "
            f"— {log_report.days_available} {t('logs.days_available')}"
        )
        print()

    total = log_report.total
    if total == 0:
        if not quiet:
            print_ok(t("logs.empty"))
        return

    if not quiet:
        # Verdict line — one clear sentence before the details
        from bob.scoring import FindingLevel

        # "Suspicious activity" follows the chargeable hits, not every hit. It
        # used to fire on any repeated block at all, so a NAS remounting a
        # share put the word "suspicious" at the head of the section.
        _charged = any(
            f.key == "logs.blocked_repeat_public" and f.level == FindingLevel.WARN
            for f in logs_result.findings
        )
        if _charged:
            print_warn(t("logs.verdict_warn", total=total, days=log_report.log_days))
        else:
            print_ok(t("logs.verdict_ok", total=total, days=log_report.log_days))

        # Repeated-block findings.
        #
        # INFO is printed here too, and it has to be: v0.15.5 moved local and
        # UDP sources out of the deduction, and this loop rendered WARN only —
        # so reclassifying them would have made BOB stop mentioning traffic it
        # had measured. Withdrawing a deduction is not a licence to fall silent.
        # The other keys this section emits (top IPs, top ports, service hits,
        # local dominance) are rendered explicitly below and would double up,
        # so only the repeated-block family is taken from the findings list.
        _REPEAT_KEYS = {
            "logs.blocked_repeat_public",
            "logs.blocked_repeat_local",
            "logs.blocked_repeat_udp",
        }
        for finding in logs_result.findings:
            if finding.key not in _REPEAT_KEYS:
                continue
            if finding.level == FindingLevel.WARN:
                print_warn(finding.message)
            else:
                print_info(finding.message)

        # Top IP
        if log_report.top_ips:
            top_ip, top_count = log_report.top_ips[0]
            geo = get_ip_geo(top_ip, lang=config.lang)
            geo_str = f" ({geo})" if geo else ""
            print_info(
                f"{t('logs.top_ips')} : {top_ip}{geo_str} "
                f"— {top_count} {t('logs.attempts')}"
            )

        # Top port
        if log_report.top_ports:
            top_port, top_count = log_report.top_ports[0]
            print_info(
                f"{t('logs.top_ports')} : {top_port} "
                f"— {top_count} {t('logs.attempts')}"
            )

        # local_dominance INFO (local IP generating most blocked traffic)
        from bob.scoring import FindingLevel as _FL
        for finding in logs_result.findings:
            if finding.level == _FL.INFO and getattr(finding, "key", "") == "logs.local_dominance":
                print_info(finding.message)

        # Service hits
        if log_report.svc_hits:
            print()
            print_warn(t("logs.svc_hits") + " :")
            for pp, count in log_report.svc_hits.items():
                print_dim(f"  → {pp} — {count} {t('logs.attempts')}")

        print()

    # Detailed report
    if config.detailed:
        report.write_section(
            f"{t('sections.logs')} — {t('logs.period')} : "
            f"{log_report.log_days} {t('logs.days_unit')}"
        )
        report.write_raw(f"{t('logs.total_blocks')} : {total}")
        report.write_raw(f"{t('logs.days_available')}    : {log_report.days_available}")
        report.write_raw("")
        report.write_raw(f"--- {t('logs.top_ips')} ---")
        for ip, count in log_report.top_ips:
            geo = get_ip_geo(ip, lang=config.lang)
            geo_str = f" ({geo})" if geo else ""
            report.write_raw(f"  {ip:<20}{geo_str:<30} {count} {t('logs.attempts')}")
        report.write_raw("")
        report.write_raw(f"--- {t('logs.top_ports')} ---")
        for port, count in log_report.top_ports:
            report.write_raw(f"  {port:<12} {count} {t('logs.attempts')}")
        report.write_raw("")
        report.write_raw(f"--- {t('logs.brute_title')} ---")
        if log_report.brute_hits:
            for hit in log_report.brute_hits:
                geo = get_ip_geo(hit.src_ip, lang=config.lang)
                geo_str = f" ({geo})" if geo else ""
                report.write_raw(
                    f"  {hit.src_ip:<20}{geo_str:<30}"
                    f" {hit.port_proto:<12} {hit.count} {t('logs.attempts')}"
                )
        else:
            report.write_raw(f"  {t('logs.brute_none')}")
        report.write_raw("")
        report.write_raw(f"--- {t('logs.svc_hits')} ---")
        if log_report.svc_hits:
            for pp, count in log_report.svc_hits.items():
                report.write_raw(f"  {pp} {count} {t('logs.attempts')}")
        else:
            report.write_raw(f"  {t('logs.svc_hits_none')}")
        report.write_raw("")


# ---------------------------------------------------------------------------
# Network context display (sections C + E)
# ---------------------------------------------------------------------------

def display_network_context(snapshot, t, output_mod) -> None:
    """
    Print the interface table (E) and connection summary (C).

    Args:
        snapshot:   NetworkContextSnapshot collected from the system.
        t:          Translation function.
        output_mod: The bob.output module (passed to avoid circular import).
    """
    from bob.checks.network_context import top_remote_ips

    # ── Interfaces table ──────────────────────────────────────────────────
    w_name = 14
    w_type = 10
    w_stat = 8
    header = (
        f"  {t('network_context.col_interface'):<{w_name}}"
        f"  {t('network_context.col_type'):<{w_type}}"
        f"  {t('network_context.col_status'):<{w_stat}}"
        f"  {t('network_context.col_address')}"
    )
    sep = (
        f"  {'─' * w_name}"
        f"  {'─' * w_type}"
        f"  {'─' * w_stat}"
        f"  {'─' * 20}"
    )
    output_mod.print_dim(header)
    output_mod.print_dim(sep)

    if not snapshot.interfaces:
        output_mod.print_dim(f"  {t('network_context.no_interfaces')}")
    else:
        for iface in snapshot.interfaces:
            status = t("network_context.up") if iface.is_up else t("network_context.down")
            addr   = iface.address or "—"
            row = (
                f"  {iface.name:<{w_name}}"
                f"  {iface.if_type:<{w_type}}"
                f"  {status:<{w_stat}}"
                f"  {addr}"
            )
            output_mod.print_dim(row)

    print()

    # ── Connections summary ───────────────────────────────────────────────
    # Without a working `ss` the list is empty because nothing was read, not
    # because nothing is connected — say so rather than printing "0".
    total = len(snapshot.connections)
    output_mod.print_dim(
        "  " + (
            t("network_context.connections_total", count=total)
            if snapshot.connections_readable
            else t("network_context.connections_unknown")
        )
    )

    top = top_remote_ips(snapshot.connections, n=3)
    if top:
        top_str = ", ".join(f"{ip} ×{n}" for ip, n in top)
        output_mod.print_dim(
            f"  {t('network_context.top_remotes')} : {top_str}"
        )
    print()


# ---------------------------------------------------------------------------
# Audit summary
# ---------------------------------------------------------------------------

def _compute_posture_annotation(engine, t) -> tuple:
    """M-10 (v0.7.2): consolidated posture-escalation lookup used by both
    ``_summary_header_lines`` (terminal box) and ``print_audit_summary``
    (the on-disk ``.txt`` report). Pre-v0.7.2 the lookup was duplicated
    in two places that landed independently during the v0.7.0 hotfix
    cycle; this helper is the single source of truth.

    Returns a 2-tuple ``(effective_level, annotation)`` where:
      - ``effective_level``: ``engine.effective_level`` if exposed,
        else fall back to ``engine.level`` (legacy callers / test
        mocks that pre-date v0.7.0 don't populate the effective field).
      - ``annotation``: translated reason string when posture
        escalation lifted the displayed level above the score-derived
        level. Empty string when no escalation occurred OR when the
        engine doesn't expose ``effective_level`` (legacy callers).
    """
    effective_level = getattr(engine, "effective_level", engine.level)
    from bob.scoring import unpack_posture_escalation
    posture_floor, posture_key = unpack_posture_escalation(engine)
    annotation = ""
    if posture_floor is not None and effective_level != engine.level:
        annotation = t(posture_key)
    return effective_level, annotation


def _summary_header_lines(engine, network_context, config, t,
                           profile_name: str,
                           prev_score: "int | None") -> list[tuple[str, str]]:
    """Build the score / risk / network / profile / target header lines."""
    from bob.output import _c
    from bob.scoring import RiskLevel

    score = engine.score
    # M-10 (v0.7.2): single source of truth for posture escalation lookup
    # — duplicated v0.7.0 hotfix pattern consolidated into a module helper.
    level, posture_annotation = _compute_posture_annotation(engine, t)
    level_str = t(f"scoring.level.{level.value}")
    ctx_str   = t(f"scoring.context.{network_context}")
    icon = "✔" if level == RiskLevel.LOW else "✖"

    # v0.16.0 — a check that could not read its input did not make deductions
    # that are unknown, not zero, so the number is a ceiling. It is rendered as
    # one, because a caveat printed beside the score is not read by anyone who
    # reads only the score: masking sshd_config moves it from 7 to 8, up, on a
    # host BOB can see less of.
    bounded = engine.score_is_upper_bound
    score_str = f"≤ {score}/10" if bounded else f"{score}/10"

    # The delta is withheld while bounded rather than shown against a ceiling.
    # "↑ +1" on a run that saw less is the same false reassurance one level up.
    if prev_score is not None and not bounded:
        delta = score - prev_score
        if delta > 0:
            score_str += f"  {_c.green}↑ +{delta}{_c.reset}"
        elif delta < 0:
            score_str += f"  {_c.yellow}↓ {delta}{_c.reset}"

    risk_value = f"{icon} {level_str}"
    if bounded:
        # The risk level is derived from the score, so a bounded score yields a
        # best case, not a verdict.
        risk_value = f"{icon} {t('scoring.risk_at_best', level=level_str)}"
    if posture_annotation:
        risk_value = f"{risk_value}  ({posture_annotation})"

    lines: list[tuple[str, str]] = [
        (t("scoring.score_label"),     score_str),
        (t("scoring.risk_label"),      risk_value),
    ]
    if bounded:
        # Beside the score, not in a section further down: this is what makes
        # the ceiling visible to someone who reads only the summary box.
        #
        # The count only. A first version listed the sections and overflowed
        # the 78-column frame on an ordinary unprivileged run, where nine of
        # them are unreadable — and the list was redundant anyway, since each
        # of those sections prints its own "could not read" finding above.
        sections = {section_of(k) for k in engine.unverified}
        lines.append((
            t("scoring.visibility_label"),
            t("scoring.visibility_value", count=len(sections)),
        ))
    lines += [
        (t("scoring.network_context"), ctx_str),
        (t("scoring.profile_label"),   profile_name.capitalize()),
    ]

    target = getattr(config, "target", 0)
    if target:
        gap = target - score
        if gap <= 0 and bounded:
            # v0.16.1 — the exit code has failed closed on a bounded score since
            # v0.16.0 (`score < target or score_is_upper_bound`), and this line
            # was never updated to match. It printed "✔ target reached" while
            # the same run exited 4 (EXIT_TARGET_MISSED): two public surfaces of
            # one audit saying the opposite, with a CI gate reading the code and
            # a human reading the line. The number does clear the bar, but it is
            # a ceiling, so whether the host clears it is unknown — which is
            # exactly what the exit code says.
            target_val = f"{_c.yellow}▲ {t('scoring.target_unverifiable', target=target)}{_c.reset}"
        elif gap <= 0:
            target_val = f"{_c.green}✔ {t('scoring.target_reached', target=target)}{_c.reset}"
        else:
            target_val = f"{_c.yellow}▲ {t('scoring.target_gap', target=target, gap=gap)}{_c.reset}"
        lines.append((t("scoring.target_label"), target_val))

    return lines


def _add_finding_lines(icon_prefix: str, item, inner: int) -> list[tuple[str, str]]:
    """Build the lines for one summary item (message + cmd + note + CIS code + explain hint)."""
    from bob.output import _c as _oc
    from bob.explain import EXPLAIN_KEYS, normalize_key as _norm_key

    lines: list[tuple[str, str]] = []
    lines.extend(_wrap_for_box(icon_prefix, item.message, inner))
    if item.cmd:
        cmd_prefix  = " " * len(icon_prefix) + ("ℹ " if item.cmd_type == "check" else "→ ")
        cont_prefix = " " * len(cmd_prefix)
        for i, cmd_line in enumerate(item.cmd.splitlines()):
            pfx = cmd_prefix if i == 0 else cont_prefix
            for content, val in _wrap_for_box(pfx, cmd_line, inner):
                lines.append((f"{_oc.violet_bold}{content}{_oc.reset}", val))
    if item.note:
        note_prefix = " " * len(icon_prefix) + "ℹ "
        lines.extend(_wrap_for_box(note_prefix, item.note, inner))
    if item.key:
        cis_code = get_cis_code(item.key)
        if cis_code:
            code_prefix = " " * len(icon_prefix)
            lines.append((f"{code_prefix}{_oc.dim}[{cis_code}]{_oc.reset}", ""))
        norm = _norm_key(item.key)
        if norm in EXPLAIN_KEYS:
            hint_prefix = " " * len(icon_prefix) + "? "
            hint = f"bob --explain {norm}"
            lines.extend(_wrap_for_box(hint_prefix, hint, inner))
    return lines


def _summary_findings_lines(engine, t, inner: int) -> list[tuple[str, str]]:
    """Build the action + improvement findings block (with separators and disclaimer)."""
    from bob.output import _c

    action_items      = [f for f in engine.findings if f.nature == "action"]
    improvement_items = [f for f in engine.findings if f.nature == "improvement"]
    structural_items  = [f for f in engine.findings if f.nature == "structural"]

    if not (action_items or improvement_items or structural_items):
        return []

    # F2 (v0.12.0): the per-item bullet reflects the finding's SEVERITY
    # (⚠ WARN / ✖ ALERT), matching how the same finding is printed in the
    # body. Pre-fix the bullet was hardcoded per *nature* section (✖ for every
    # "Action required" item, ⚠ for every "Possible improvements" item), so a
    # WARN-level action item showed ✖ in the summary but ⚠ in the body — the
    # same item with two different severity symbols. The section *header* still
    # groups by nature (what to do); the bullet now agrees with the body.
    from bob.scoring import FindingLevel
    def _sev_bullet(item) -> str:
        return "  ✖  " if item.level == FindingLevel.ALERT else "  ⚠  "

    lines: list[tuple[str, str]] = []
    if action_items:
        lines.append(("---", ""))
        lines.append((f"✖ {t('summary.block_action')}", ""))
        for item in action_items:
            lines.extend(_add_finding_lines(_sev_bullet(item), item, inner))
    if improvement_items:
        lines.append(("---", ""))
        lines.append((f"⚠ {t('summary.block_improve')}", ""))
        for item in improvement_items:
            lines.extend(_add_finding_lines(_sev_bullet(item), item, inner))
        for content, val in _wrap_for_box("  ℹ  ", t("summary.block_improve_disclaimer"), inner):
            lines.append((f"{_c.red}{content}{_c.reset}", val))
    return lines


def _summary_breakdown_lines(engine, t, inner: int) -> list[tuple[str, str]]:
    """Build the score breakdown block (deductions + cap note)."""
    if not (engine.breakdown or engine.cap_info):
        return []
    lines: list[tuple[str, str]] = [
        ("---", ""),
        (t("scoring.breakdown_title"), ""),
    ]
    for ded in engine.breakdown:
        if ded.points == 0:
            continue
        prefix = f"  -{ded.points}  "
        lines.extend(_wrap_for_box(prefix, ded.reason, inner))
    if engine.cap_info:
        cap_note = t("scoring.cap_note", max=engine.cap_info.maximum)
        lines.extend(_wrap_for_box("  ⚠  ", cap_note, inner))
    return lines


def _summary_scope_note(config, degraded_sections, t) -> str:
    """One line saying what the run actually covered, or "" when it covered all.

    The report listed every section it ran and said nothing about the ones it
    did not: a section filtered out by ``--check`` / ``--skip`` and a section
    whose check raised were both simply absent, and indistinguishable from a
    section that ran clean. Reading an archived report, there was no way to
    tell "this host has no Samba findings" from "Samba was never audited".

    Degraded and filtered are named separately because they are different
    facts: one is the operator's choice, the other is BOB failing.
    """
    parts: list[str] = []
    if degraded_sections:
        parts.append(t("scoring.scope_degraded", count=len(degraded_sections),
                       sections=", ".join(sorted(degraded_sections))))
    filtered = getattr(config, "check_only", None) or getattr(config, "skip_checks", None)
    if filtered:
        parts.append(t("scoring.scope_filtered"))
    return " · ".join(parts)


def print_audit_summary(engine, network_context, public_ip, config, t,
                         report, snapshots, profile_name: str = "server",
                         prev_score: "int | None" = None,
                         fw_policy: str = "deny",
                         degraded_sections: "tuple[str, ...] | list[str]" = ()) -> None:
    """Write the audit summary to the report, and print it unless quiet.

    v0.16.0: the terminal half is gated here rather than at the call site. It
    used to be skipped wholesale under ``-q``, so ``bob -q -d`` produced a
    report with no summary block — while this module's own rule says the
    ``report.write_*`` calls always run so the .log file stays complete.
    """
    from bob.output import print_summary_box, _TERM_WIDTH

    # _TERM_WIDTH - 2 = box inner width; - 2 again for the leading indent
    # that print_summary_box prepends to every label ("  " + label)
    inner = _TERM_WIDTH - 4

    lines = _summary_header_lines(engine, network_context, config, t, profile_name, prev_score)
    lines.extend(_summary_findings_lines(engine, t, inner))
    lines.extend(_summary_breakdown_lines(engine, t, inner))

    # Everything below writes to the terminal. `-q` silences it; the
    # report.write_summary() call that follows always runs, which is the
    # rule this module states and `bob -q -d` used to break.
    if not getattr(config, "quiet", False):
        print_summary_box(lines)
        print()

        action_items      = [f for f in engine.findings if f.nature == "action"]
        improvement_items = [f for f in engine.findings if f.nature == "improvement"]
        if not action_items and not improvement_items:
            print(f"  {t('summary.clean')}")
        elif not action_items:
            print(f"  {t('summary.warnings')}")
        else:
            print(f"  {t('summary.alerts')}")

        implicit_svcs = [
            snap.label for snap in snapshots
            if snap.is_active
            and snap.service.is_high_or_critical
            and all(e.value == "no_rule" for e in snap.exposures.values())
        ]
        if implicit_svcs and fw_policy not in ("deny", "reject"):
            print()
            print(f"  ℹ {t('summary.implicit_policy')}")
            print(f"    {t('summary.implicit_svcs')} : {', '.join(implicit_svcs)}")

        print()
        print(f"  ℹ {t('summary.scope_line1')}")
        print(f"  ℹ {t('summary.scope_line2')}")
        # A1 (v0.8.0 drift batch): explicit framing of the verdict — BOB is a
        # hardening auditor whose score is conditioned by the profile and
        # network context shown above, not an autonomous threat-modeling
        # engine. Pre-emptive against "BOB says all good = all good" reads.
        print(f"  ℹ {t('summary.context_disclaimer')}")

    # M-3 (v0.7.0 Phase 2.1): propagate posture annotation to the on-disk
    # .txt report so it stays in sync with the terminal summary box.
    # M-10 (v0.7.2): single source of truth via _compute_posture_annotation.
    #
    # Outside the quiet gate: write_summary below consumes it, and leaving it
    # inside made `bob -q -d` raise UnboundLocalError — the report then lost
    # its summary block again, silently.
    _effective, _r_annotation = _compute_posture_annotation(engine, t)

    report.write_summary(
        score=engine.score,
        # The same qualified string the terminal shows. Passing the bare level
        # left the archived report saying "HIGH" where the screen said "HIGH at
        # best" — the two disagreeing about the same audit.
        risk_level=(
            t("scoring.risk_at_best", level=t(f"scoring.level.{_effective.value}"))
            if engine.score_is_upper_bound
            else t(f"scoring.level.{_effective.value}")
        ),
        network_context=t(f"scoring.context.{network_context}"),
        public_ip=public_ip or "",
        ok_count=engine.ok_count,
        warn_count=engine.warn_count,
        alert_count=engine.alert_count,
        breakdown=engine.breakdown,
        labels={
            "summary":   t("report.summary_title"),
            "breakdown": t("scoring.breakdown_title"),
            # M-5 (v0.7.3): the field labels in the on-disk .txt report
            # are now translatable. Pre-v0.7.3 they were hardcoded English
            # ("OK", "Warning", "Alert", "Score", "Risk", "Context") so a
            # French audit's .log file carried mixed-language content.
            "ok":      t("report.field_ok"),
            "warning": t("report.field_warning"),
            "alert":   t("report.field_alert"),
            "score":   t("report.field_score"),
            "risk":    t("report.field_risk"),
            "context": t("report.field_context"),
            "profile": t("report.field_profile"),
            "visibility": t("scoring.visibility_label"),
            "scope": t("scoring.scope_label"),
            "visibility_value": t(
                "scoring.visibility_value",
                count=len({section_of(k) for k in engine.unverified}),
            ) if engine.unverified else "",
        },
        posture_annotation=_r_annotation,
        score_is_upper_bound=engine.score_is_upper_bound,
        unverified_count=len({section_of(k) for k in engine.unverified}),
        profile_name=profile_name.capitalize() if profile_name else "",
        scope_note=_summary_scope_note(config, degraded_sections, t),
    )


# ---------------------------------------------------------------------------
# Risk context report entries
# ---------------------------------------------------------------------------

def build_risk_context_entries(snapshots, lang: str, t,
                                network_context: str = "") -> list[dict]:
    """Build risk context entries for the report from active services with risk data."""
    is_local = network_context == "local"
    entries = []
    for snap in snapshots:
        if not snap.is_active and not (snap.installed and snap.service.is_high_or_critical):
            continue
        # M-3 (v0.8.1 audit): centralised transform in ``bob.registry``.
        from bob.registry import service_label_to_subkey
        svc_id = service_label_to_subkey(snap.service.label)
        exposure = t(f"service_risk.{svc_id}.exposure")
        threat   = t(f"service_risk.{svc_id}.threat")
        level    = t(f"service_risk.{svc_id}.level")
        if exposure.startswith("["):
            continue
        entries.append({
            "label":          snap.service.label,
            "level":          f"{level} • LAN" if is_local else level,
            "exposure_label": t("risk_context.exposure"),
            "exposure":       exposure,
            "threat_label":   t("risk_context.threat"),
            "threat":         threat,
        })
    return entries


# ---------------------------------------------------------------------------
# GeoIP availability notice
# ---------------------------------------------------------------------------

def display_geoip_notice(geo_status: str, t, output, *, quiet: bool = False) -> None:
    """Print a one-time notice if GeoIP2 is unavailable or has no database.

    I-1 (v0.7.4): ``quiet=True`` suppresses output to honour ``bob -q``
    empty-stdout contract.
    """
    if quiet:
        return
    if geo_status == "unavailable":
        msg = t("logs.geoip2_unavailable")
        cmd = t("logs.geoip2_unavailable_cmd")
        if msg.startswith("["):
            msg = "GeoIP2 library not found in the BOB environment — IP geolocation disabled"
        if cmd.startswith("["):
            cmd = "pipx inject bodyguard-of-bits geoip2"
        output.print_info(msg)
        output.print_info(f"\u2192 {cmd}")
    elif geo_status == "no_database":
        msg = t("logs.geoip2_no_db")
        cmd = t("logs.geoip2_no_db_cmd")
        if msg.startswith("["):
            msg = "GeoIP2 installed but no GeoLite2-Country database found — IP geolocation disabled"
        if cmd.startswith("["):
            cmd = "sudo mkdir -p /usr/share/GeoIP && sudo wget -O /usr/share/GeoIP/GeoLite2-Country.mmdb https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
        output.print_info(msg)
        output.print_info(f"\u2192 {cmd}")


# ---------------------------------------------------------------------------
# Ports overview section
# ---------------------------------------------------------------------------

def display_ports_overview(ports_snapshot, config, t, report, output) -> None:
    """Print the listening ports count and optional ss table.

    I-1 (v0.7.4): when ``config.quiet`` is set, the section is still written
    to the .log report but stdout stays empty (honours ``bob -q`` contract).
    """
    from bob.output import print_section
    from bob.checks.ports import EPHEMERAL_THRESHOLD
    if not config.quiet:
        print_section(t("sections.ports_overview"))
    report.write_section(t("sections.ports_overview"))

    # Exclude ephemeral UDP ports from count and display
    visible_ports = [
        lp for lp in ports_snapshot.ports
        if not (lp.proto == "udp" and lp.port > EPHEMERAL_THRESHOLD)
    ]
    visible_raw = {lp.raw_line for lp in visible_ports}

    # A count of zero is only worth printing when `ss` actually answered;
    # otherwise the overview would contradict the ports section, which reports
    # the read as failed.
    overview = (
        t("ports.listening_count", count=len(visible_ports))
        if ports_snapshot.ports_readable
        else t("ports.unreadable")
    )
    if not config.quiet:
        output.print_info(overview)
    report.write_finding("INFO", overview)

    if ports_snapshot.ss_output:
        # Rebuild filtered table: keep header/blank lines, drop ephemeral data lines
        filtered_lines = [
            line for line in ports_snapshot.ss_output.splitlines()
            if not (line.split() and line.split()[0].lower() in ("tcp", "udp"))
            or line in visible_raw
        ]
        filtered_output = "\n".join(filtered_lines)
        report.write_raw("")
        report.write_raw(filtered_output)
        if not config.quiet:
            if config.verbose:
                output.print_dim(t("ports.listening_detail"))
                print()
                print(filtered_output)
            else:
                output.print_dim(t("ports.listening_verbose_hint"))
    if not config.quiet:
        print()


# ---------------------------------------------------------------------------
# Services panorama section
# ---------------------------------------------------------------------------

def display_services_panorama(registry, ufw_numbered: str,
                               loopback_only_ports: set,
                               all_listening_ports: "set | None",
                               config, t) -> None:
    """Print the compact services panorama table (all 22 known services)."""
    from bob.output import print_section, print_services_panorama
    from bob.checks.services import ServiceSnapshot
    from bob.panorama import build_panorama_rows

    print_section(t("sections.services_panorama"))
    all_snaps = ServiceSnapshot.collect_all(
        registry, ufw_rules=ufw_numbered, loopback_ports=loopback_only_ports,
        all_listening_ports=all_listening_ports,
    )
    panorama_rows = build_panorama_rows(all_snaps)
    panorama_labels = {
        "header_service": t("services.panorama.header_service"),
        "header_status":  t("services.panorama.header_status"),
        "header_ports":   t("services.panorama.header_ports"),
        "header_ufw":     t("services.panorama.header_ufw"),
        "active":         t("services.panorama.active"),
        "inactive":       t("services.panorama.inactive"),
        "not_installed":  t("services.panorama.not_installed"),
        "unknown":        t("services.panorama.unknown"),
    }
    print_services_panorama(panorama_rows, panorama_labels)
    print()


# ---------------------------------------------------------------------------
# Disk partition table
# ---------------------------------------------------------------------------

_BAR_WIDTH = 10


def _disk_bar(pct: int, c) -> str:
    """Return a 10-char block progress bar, coloured by usage level."""
    filled = round(pct * _BAR_WIDTH / 100)
    empty  = _BAR_WIDTH - filled
    if pct >= 90:
        color = c.red
    elif pct >= 70:
        color = c.yellow
    else:
        color = c.green
    return f"{color}{'█' * filled}{'░' * empty}{c.dim}"


def _gb_str(gb: float) -> str:
    """Format a GB value; returns '< 1 GB' when the value rounds to zero."""
    return "< 1 GB" if gb < 0.5 else f"{gb:.0f} GB"


def display_disk_partitions(snapshot, t, output_module) -> None:
    """Print a compact partition usage table (mountpoint / device / size / bar / used% / free)."""
    if not snapshot.partitions:
        return

    c = output_module._c

    # Compute display values
    rows = []
    for p in snapshot.partitions:
        size_str = _gb_str(p.size_gb)
        used_gb  = p.size_gb * p.used_pct / 100
        free_gb  = max(0.0, p.size_gb - used_gb)
        if p.size_gb >= 1.0:
            used_str = f"{_gb_str(used_gb)} ({p.used_pct}%)"
            free_str = _gb_str(free_gb)
        else:
            used_str = f"{p.used_pct}%"
            free_str = "—"
        bar = _disk_bar(p.used_pct, c)
        rows.append((p.mountpoint, p.device, size_str, used_str, bar, free_str))

    # Dynamic column widths (bar column is always _BAR_WIDTH — colour codes excluded)
    h_mount  = t("disk.col_mountpoint")
    h_device = t("disk.col_device")
    h_size   = t("disk.col_size")
    h_used   = t("disk.col_used")
    h_free   = t("disk.col_free")

    w_mount  = max(len(h_mount),  max(len(r[0]) for r in rows))
    w_device = max(len(h_device), max(len(r[1]) for r in rows))
    w_size   = max(len(h_size),   max(len(r[2]) for r in rows))
    w_used   = max(len(h_used),   max(len(r[3]) for r in rows))
    w_free   = max(len(h_free),   max(len(r[5]) for r in rows))

    # Blank line for visual separation from the SMART findings above
    print()

    header = (
        f"  {h_mount:<{w_mount}}  "
        f"{h_device:<{w_device}}  "
        f"{h_size:>{w_size}}  "
        f"{h_used:>{w_used}}  "
        f"{'':>{_BAR_WIDTH}}  "
        f"{h_free:>{w_free}}"
    )
    sep = (
        f"  {'-' * w_mount}  "
        f"{'-' * w_device}  "
        f"{'-' * w_size}  "
        f"{'-' * w_used}  "
        f"{'-' * _BAR_WIDTH}  "
        f"{'-' * w_free}"
    )

    output_module.print_dim(header)
    output_module.print_dim(sep)
    for mountpoint, device, size_str, used_str, bar, free_str in rows:
        # Bar contains ANSI colour codes — print directly so they're not mangled
        prefix = (
            f"  {mountpoint:<{w_mount}}  "
            f"{device:<{w_device}}  "
            f"{size_str:>{w_size}}  "
            f"{used_str:>{w_used}}  "
        )
        suffix = f"  {free_str:>{w_free}}"
        print(f"  {c.dim}{prefix}{bar}{suffix}{c.reset}")
    print()


def print_exposure(items, t, output_mod) -> None:
    """Print the attack-surface table produced by compute_exposure()."""
    if not items:
        return
    from bob.output import _c
    output_mod.print_section(t("exposure.section_title"))
    label_width = max(len(item.label) for item in items)
    for item in items:
        label = item.label.ljust(label_width)
        if item.color == "ok":
            color = _c.green
        elif item.color == "alert":
            color = _c.red
        else:
            color = _c.yellow
        print(f"  {color}{item.icon}{_c.reset}  {_c.dim}{label}{_c.reset}  {item.detail}")
    print()


def print_correlations(correlations, t, output_mod) -> None:
    """Print compound risk findings produced by the correlation engine."""
    if not correlations:
        return
    output_mod.print_section(t("corr.section_title"))
    from bob.scoring import FindingLevel
    for cf in correlations:
        msg = f"[COMPOUND] {cf.message}"
        if cf.level == FindingLevel.ALERT:
            output_mod.print_alert(msg)
        else:
            output_mod.print_warn(msg)
        if cf.triggered_by:
            keys_str = ", ".join(cf.triggered_by)
            output_mod.print_dim(t("corr.triggered_by", keys=keys_str))
    print()
