"""
Display helpers for BOB.

Terminal output and report writing for check results, risk context,
log analysis, and the final audit summary.
"""

from __future__ import annotations

from bob.cis_refs import get_cis_ref, get_cis_code


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
        print_ok, print_warn, print_alert, print_info, print_dim, print_recommendation,
        print_check_cmd, _passes_threshold,
    )

    for finding in result.findings:
        if quiet:
            level_str = finding.level.value.upper()
            report.write_finding(level_str, finding.message)
            continue
        if finding.level == FindingLevel.OK:
            report.write_finding("OK", finding.message)
            if not _passes_threshold("ok"):
                continue
            print_ok(finding.message)
        elif finding.level == FindingLevel.WARN:
            report.write_finding("WARN", finding.message)
            if not _passes_threshold("warn"):
                continue
            print_warn(finding.message)
            if recurrence and finding.key:
                _print_recurrence(recurrence.get(finding.key, 0))
            if verbose:
                detail = finding.detail.splitlines() if finding.detail else []
                if finding.cmd:
                    if finding.cmd_type == "check":
                        if detail:
                            print_recommendation(detail)
                        print_check_cmd(finding.cmd.splitlines())
                    else:
                        print_recommendation(detail, finding.cmd.splitlines())
                elif detail:
                    print_recommendation(detail)
                if finding.key:
                    _cis = get_cis_ref(finding.key)
                    if _cis:
                        print_dim(_cis)
        elif finding.level == FindingLevel.ALERT:
            report.write_finding("ALERT", finding.message)
            if not _passes_threshold("alert"):
                continue
            print_alert(finding.message)
            if recurrence and finding.key:
                _print_recurrence(recurrence.get(finding.key, 0))
            detail = finding.detail.splitlines() if finding.detail else []
            if finding.cmd and verbose:
                if finding.cmd_type == "check":
                    if detail:
                        print_recommendation(detail)
                    print_check_cmd(finding.cmd.splitlines())
                else:
                    print_recommendation(detail, finding.cmd.splitlines())
            elif detail:
                print_recommendation(detail)
            if finding.note and verbose:
                print_info(finding.note)
            if verbose and finding.key:
                _cis = get_cis_ref(finding.key)
                if _cis:
                    print_dim(_cis)
        elif finding.level == FindingLevel.INFO:
            report.write_finding("INFO", finding.message)
            if not _passes_threshold("info"):
                continue
            print_info(finding.message)
            if verbose:
                detail = finding.detail.splitlines() if finding.detail else []
                if finding.cmd:
                    if finding.cmd_type == "check":
                        if detail:
                            print_recommendation(detail)
                        print_check_cmd(finding.cmd.splitlines())
                    else:
                        print_recommendation(detail, finding.cmd.splitlines())
                elif detail:
                    print_recommendation(detail)


# ---------------------------------------------------------------------------
# Risk context display
# ---------------------------------------------------------------------------

def display_risk_context(label: str, lang: str, t, report,
                         context_note: str | None = None,
                         is_local: bool = False) -> None:
    """Display two-axis risk context for a high/critical service."""
    svc_id = (label.lower()
              .replace(" ", "_").replace("/", "_")
              .replace("(", "").replace(")", ""))
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

def display_log_results(logs_result, snapshot, config, t, report) -> None:
    """Display structured log analysis results."""
    from bob.checks.logs import get_ip_geo
    from bob.output import print_ok, print_warn, print_info, print_dim

    if not hasattr(logs_result, "_log_data"):
        display_result(logs_result, report, config.verbose, quiet=config.quiet)
        return

    data = logs_result._log_data

    print_dim(
        f"{t('logs.period')} : {data['log_days']} {t('logs.days_unit')} "
        f"— {data['days_available']} {t('logs.days_available')}"
    )
    print()

    total = data["total"]
    if total == 0:
        print_ok(t("logs.empty"))
        return

    # Verdict line — one clear sentence before the details
    brute_hits = data.get("brute_hits", [])
    if brute_hits:
        print_warn(t("logs.verdict_warn", total=total, days=data["log_days"]))
    else:
        print_ok(t("logs.verdict_ok", total=total, days=data["log_days"]))

    # Bruteforce findings
    for finding in logs_result.findings:
        from bob.scoring import FindingLevel
        if finding.level == FindingLevel.WARN:
            print_warn(finding.message)

    # Top IP
    if data["top_ips"]:
        top_ip, top_count = data["top_ips"][0]
        geo = get_ip_geo(top_ip, lang=config.lang)
        geo_str = f" ({geo})" if geo else ""
        print_info(
            f"{t('logs.top_ips')} : {top_ip}{geo_str} "
            f"— {top_count} {t('logs.attempts')}"
        )

    # Top port
    if data["top_ports"]:
        top_port, top_count = data["top_ports"][0]
        print_info(
            f"{t('logs.top_ports')} : {top_port} "
            f"— {top_count} {t('logs.attempts')}"
        )

    # local_dominance INFO (local IP generating most blocked traffic)
    from bob.scoring import FindingLevel
    for finding in logs_result.findings:
        if finding.level == FindingLevel.INFO and getattr(finding, "key", "") == "logs.local_dominance":
            print_info(finding.message)

    # Service hits
    if data["svc_hits"]:
        print()
        print_warn(t("logs.svc_hits") + " :")
        for pp, count in data["svc_hits"].items():
            print_dim(f"  → {pp} — {count} {t('logs.attempts')}")

    print()

    # Detailed report
    if config.detailed:
        report.write_section(
            f"{t('sections.logs')} — {t('logs.period')} : "
            f"{data['log_days']} {t('logs.days_unit')}"
        )
        report.write_raw(f"{t('logs.total_blocks')} : {total}")
        report.write_raw(f"{t('logs.days_available')}    : {data['days_available']}")
        report.write_raw("")
        report.write_raw(f"--- {t('logs.top_ips')} ---")
        for ip, count in data["top_ips"]:
            geo = get_ip_geo(ip, lang=config.lang)
            geo_str = f" ({geo})" if geo else ""
            report.write_raw(f"  {ip:<20}{geo_str:<30} {count} {t('logs.attempts')}")
        report.write_raw("")
        report.write_raw(f"--- {t('logs.top_ports')} ---")
        for port, count in data["top_ports"]:
            report.write_raw(f"  {port:<12} {count} {t('logs.attempts')}")
        report.write_raw("")
        report.write_raw(f"--- {t('logs.brute_title')} ---")
        if data["brute_hits"]:
            for hit in data["brute_hits"]:
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
        if data["svc_hits"]:
            for pp, count in data["svc_hits"].items():
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
    total = len(snapshot.connections)
    output_mod.print_dim(
        f"  {t('network_context.connections_total', count=total)}"
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

def print_audit_summary(engine, network_context, public_ip, config, t,
                         report, snapshots, profile_name: str = "server",
                         prev_score: "int | None" = None,
                         fw_policy: str = "deny") -> None:
    """Print the audit summary box and write to report."""
    from bob.output import print_summary_box, _TERM_WIDTH, _c
    from bob.scoring import RiskLevel

    # _TERM_WIDTH - 2 = box inner width; - 2 again for the leading indent
    # that print_summary_box prepends to every label ("  " + label)
    inner = _TERM_WIDTH - 4

    score = engine.score
    level = engine.level

    level_str = t(f"scoring.level.{level.value}")
    ctx_str   = t(f"scoring.context.{network_context}")

    icon = "✔" if level == RiskLevel.LOW else "✖"

    # Score trend arrow (only when a previous score is available)
    score_str = f"{score}/10"
    if prev_score is not None:
        delta = score - prev_score
        if delta > 0:
            score_str += f"  {_c.green}↑ +{delta}{_c.reset}"
        elif delta < 0:
            score_str += f"  {_c.yellow}↓ {delta}{_c.reset}"
        else:
            score_str += f"  →"

    lines = [
        (t("scoring.score_label"), score_str),
        (t("scoring.risk_label"),  f"{icon} {level_str}"),
        (t("scoring.network_context"), ctx_str),
        (t("scoring.profile_label"), profile_name.capitalize()),
    ]

    target = getattr(config, "target", 0)
    if target:
        from bob.output import _c
        gap = target - score
        if gap <= 0:
            target_val = f"{_c.green}✔ {t('scoring.target_reached', target=target)}{_c.reset}"
        else:
            target_val = f"{_c.yellow}▲ {t('scoring.target_gap', target=target, gap=gap)}{_c.reset}"
        lines.append((t("scoring.target_label"), target_val))

    action_items      = [f for f in engine.findings if f.nature == "action"]
    improvement_items = [f for f in engine.findings if f.nature == "improvement"]
    structural_items  = [f for f in engine.findings if f.nature == "structural"]

    from bob.explain import EXPLAIN_KEYS, normalize_key as _norm_key

    def _add_finding_lines(icon_prefix: str, item) -> None:
        from bob.output import _c as _oc
        lines.extend(_wrap_for_box(icon_prefix, item.message, inner))
        if item.cmd:
            cmd_prefix = " " * len(icon_prefix) + ("ℹ " if item.cmd_type == "check" else "→ ")
            for content, val in _wrap_for_box(cmd_prefix, item.cmd, inner):
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

    if action_items or improvement_items or structural_items:
        if action_items:
            lines.append(("---", ""))
            lines.append((f"✖ {t('summary.block_action')}", ""))
            for item in action_items:
                _add_finding_lines("  ✖  ", item)
        if improvement_items:
            lines.append(("---", ""))
            lines.append((f"⚠ {t('summary.block_improve')}", ""))
            for item in improvement_items:
                _add_finding_lines("  ⚠  ", item)
            from bob.output import _c
            for content, val in _wrap_for_box("  ℹ  ", t("summary.block_improve_disclaimer"), inner):
                lines.append((f"{_c.red}{content}{_c.reset}", val))

    if engine.breakdown or engine.cap_info:
        lines.append(("---", ""))
        lines.append((t("scoring.breakdown_title"), ""))
        for ded in engine.breakdown:
            if ded.points == 0:
                continue
            prefix = f"  -{ded.points}  "
            lines.extend(_wrap_for_box(prefix, ded.reason, inner))
        if engine.cap_info:
            cap_note = t("scoring.cap_note", max=engine.cap_info.maximum)
            lines.extend(_wrap_for_box("  ⚠  ", cap_note, inner))

    print_summary_box(lines)
    print()

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

    report.write_summary(
        score=score,
        risk_level=level_str,
        network_context=ctx_str,
        public_ip=public_ip or "",
        ok_count=engine.ok_count,
        warn_count=engine.warn_count,
        alert_count=engine.alert_count,
        breakdown=engine.breakdown,
        labels={
            "summary":   "AUDIT SUMMARY",
            "breakdown": t("scoring.breakdown_title"),
        },
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
        svc_id = (snap.service.label.lower()
                  .replace(" ", "_").replace("/", "_")
                  .replace("(", "").replace(")", ""))
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

def display_geoip_notice(geo_status: str, t, output) -> None:
    """Print a one-time notice if GeoIP2 is unavailable or has no database."""
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
    """Print the listening ports count and optional ss table."""
    from bob.output import print_section
    from bob.checks.ports import EPHEMERAL_THRESHOLD
    print_section(t("sections.ports_overview"))
    report.write_section(t("sections.ports_overview"))

    # Exclude ephemeral UDP ports from count and display
    visible_ports = [
        lp for lp in ports_snapshot.ports
        if not (lp.proto == "udp" and lp.port > EPHEMERAL_THRESHOLD)
    ]
    visible_raw = {lp.raw_line for lp in visible_ports}

    output.print_info(t("ports.listening_count", count=len(visible_ports)))
    report.write_finding("INFO", t("ports.listening_count", count=len(visible_ports)))

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
        if config.verbose:
            output.print_dim(t("ports.listening_detail"))
            print()
            print(filtered_output)
        else:
            output.print_dim(t("ports.listening_verbose_hint"))
    print()


# ---------------------------------------------------------------------------
# Services panorama section
# ---------------------------------------------------------------------------

def display_services_panorama(registry, ufw_numbered: str,
                               loopback_only_ports: set, all_listening_ports: set,
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
