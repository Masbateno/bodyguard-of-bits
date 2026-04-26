"""HTML serialization of audit results.

Produces a standalone HTML report (no external dependencies, no JavaScript).
Suitable for saving to a file, attaching to tickets, or serving from a web server.

Usage:
    from bob.html_output import build_html_output
    print(build_html_output(engine, sys_info))
"""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape

from bob.report import SystemInfo
from bob.scoring import FindingLevel, ScoreEngine

_LEVEL_LABEL: dict[FindingLevel, str] = {
    FindingLevel.ALERT: "ALERT",
    FindingLevel.WARN:  "WARN",
    FindingLevel.INFO:  "INFO",
    FindingLevel.OK:    "OK",
}

_LEVEL_COLOR: dict[FindingLevel, str] = {
    FindingLevel.ALERT: "#dc3545",
    FindingLevel.WARN:  "#fd7e14",
    FindingLevel.INFO:  "#0d6efd",
    FindingLevel.OK:    "#198754",
}

_LEVEL_ORDER = [FindingLevel.ALERT, FindingLevel.WARN, FindingLevel.INFO, FindingLevel.OK]


def _score_color(score: int) -> str:
    if score >= 8:
        return "#198754"
    if score >= 5:
        return "#fd7e14"
    return "#dc3545"


def _h(text: str) -> str:
    """HTML-escape a string."""
    return escape(str(text), quote=True)


_CSS = """\
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
         background:#f8f9fa;color:#212529;padding:2rem}
    h1{font-size:1.5rem;margin-bottom:1rem;color:#343a40}
    h2{font-size:1.1rem;margin:1.5rem 0 .5rem;color:#495057;border-bottom:1px solid #dee2e6;
       padding-bottom:.25rem}
    table{width:100%;border-collapse:collapse;font-size:.9rem;background:#fff;
          border-radius:6px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1)}
    th{background:#343a40;color:#fff;padding:.5rem .75rem;text-align:left;font-weight:600}
    td{padding:.45rem .75rem;border-bottom:1px solid #dee2e6;vertical-align:top}
    tr:last-child td{border-bottom:none}
    tr:nth-child(even) td{background:#f8f9fa}
    .score-circle{display:inline-block;width:3.5rem;height:3.5rem;border-radius:50%;
                  line-height:3.5rem;text-align:center;font-size:1.4rem;font-weight:700;
                  color:#fff}
    .badge{display:inline-block;padding:.2em .55em;border-radius:4px;font-size:.75rem;
           font-weight:700;color:#fff;white-space:nowrap}
    code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
         background:#e9ecef;padding:.1em .35em;border-radius:3px;font-size:.82rem;
         word-break:break-all}
    .meta-grid{display:grid;grid-template-columns:auto 1fr;gap:.25rem .75rem;
               font-size:.9rem;margin-bottom:1.5rem}
    .meta-grid dt{font-weight:600;color:#6c757d}
    footer{margin-top:2rem;font-size:.8rem;color:#6c757d}
"""


def build_html_output(engine: ScoreEngine, sys_info: SystemInfo) -> str:
    """Return a standalone HTML string with the full audit report."""
    ts         = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    score      = engine.score
    s_color    = _score_color(score)
    level_label = str(engine.level.value).upper() if engine.level is not None else "UNKNOWN"

    parts: list[str] = []
    a = parts.append

    a("<!DOCTYPE html>")
    a('<html lang="en">')
    a("<head>")
    a('<meta charset="utf-8">')
    a('<meta name="viewport" content="width=device-width,initial-scale=1">')
    a(f"<title>BOB — {_h(sys_info.hostname)} — {_h(ts)}</title>")
    a(f"<style>{_CSS}</style>")
    a("</head>")
    a("<body>")

    a(f"<h1>BOB Report — {_h(sys_info.hostname)}</h1>")

    # --- Summary ---
    a('<dl class="meta-grid">')
    a(f"<dt>Score</dt><dd>"
      f'<span class="score-circle" style="background:{_h(s_color)}">{score}</span>'
      f" / 10 &nbsp; <strong>{_h(level_label)}</strong></dd>")
    a(f"<dt>Alerts</dt><dd>{engine.alert_count}</dd>")
    a(f"<dt>Warnings</dt><dd>{engine.warn_count}</dd>")
    a(f"<dt>Host</dt><dd><code>{_h(sys_info.hostname)}</code></dd>")
    a(f"<dt>OS</dt><dd>{_h(sys_info.os_name)}</dd>")
    a(f"<dt>Kernel</dt><dd>{_h(sys_info.kernel)}</dd>")
    a(f"<dt>Timestamp</dt><dd>{_h(ts)}</dd>")
    a("</dl>")

    # --- Score deductions ---
    deductions = [d for d in engine.breakdown if d.points > 0]
    if deductions:
        a("<h2>Score Deductions</h2>")
        a("<table><thead><tr><th>Points</th><th>Reason</th></tr></thead><tbody>")
        for d in deductions:
            a(f"<tr><td><strong>−{d.points}</strong></td><td>{_h(d.reason)}</td></tr>")
        a("</tbody></table>")

    # --- Findings by severity ---
    findings_by_level: dict[FindingLevel, list] = {lvl: [] for lvl in _LEVEL_ORDER}
    for f in engine.findings:
        if f.level in findings_by_level:
            findings_by_level[f.level].append(f)

    if not engine.findings:
        a("<p>No findings detected.</p>")

    for level in _LEVEL_ORDER:
        group = findings_by_level[level]
        if not group:
            continue
        color = _LEVEL_COLOR[level]
        label = _LEVEL_LABEL[level]
        a(f'<h2><span class="badge" style="background:{_h(color)}">{label}</span>'
          f" &nbsp; {len(group)} finding(s)</h2>")
        a("<table><thead><tr><th>Message</th><th>Fix command</th></tr></thead><tbody>")
        for f in group:
            msg = _h(f.message or "")
            cmd = f"<code>{_h(f.cmd)}</code>" if f.cmd else ""
            a(f"<tr><td>{msg}</td><td>{cmd}</td></tr>")
        a("</tbody></table>")

    a('<footer>Generated by <a href="https://github.com/Masbateno/bodyguard-of-bits">BOB</a>.'
      ' Commands shown are suggestions — review before executing.</footer>')
    a("</body></html>")

    return "\n".join(parts)
