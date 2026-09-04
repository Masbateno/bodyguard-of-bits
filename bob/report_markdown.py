"""
Markdown audit report module for BOB.

Generates markdown-formatted reports optimized for email delivery.
Unlike AuditReport (plain text with ASCII boxes), MarkdownReport
produces clean markdown that converts to readable HTML for email clients.

No external dependencies — HTML conversion is pure Python string operations.

Usage:
    from bob.report_markdown import MarkdownReport
    from pathlib import Path

    report = MarkdownReport.open(directory=Path.cwd(), version="0.12.0")
    report.write_header(system_info)
    report.write_section("UFW RULES ANALYSIS")
    report.write_finding(level="OK", message="No duplicate rules")
    report.write_summary(engine, network_context)

    html_content = report.to_html()
    report.close()
"""

from __future__ import annotations

import html
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bob.report import SystemInfo

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Markdown report writer
# ---------------------------------------------------------------------------

class MarkdownReport:
    """
    Generates markdown-formatted audit reports.

    Similar API to AuditReport, but outputs markdown instead of ASCII boxes.
    Markdown content is stored in memory, then optionally converted to HTML
    for email delivery.

    Attributes:
        path:     Full path where report would be saved (same naming as AuditReport).
        enabled:  Always True for instances created via open().
    """

    def __init__(self, path: Path, created_at: datetime | None = None) -> None:
        self.path: Path = path
        self.enabled: bool = True
        self._lines: list[str] = []
        self.created_at: datetime = created_at or datetime.now()

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def open(cls, directory: Path, version: str) -> "MarkdownReport":
        """
        Create a markdown report instance.

        Args:
            directory: Directory where report would be saved (naming convention only).
            version:   BOB version string (e.g. "0.12.0").

        Returns:
            Open MarkdownReport instance ready for writing.
        """
        now       = datetime.now()
        timestamp = now.strftime("%Y%m%d_%H%M%S")
        filename  = f"bob_{timestamp}.md"
        path      = directory / filename

        instance = cls(path=path, created_at=now)
        logger.debug("Markdown report opened: %s", path)
        return instance

    # ------------------------------------------------------------------
    # Write methods
    # ------------------------------------------------------------------

    def write_header(self, info: SystemInfo, labels: dict[str, str] | None = None) -> None:
        """Write the report header with system info.

        M-5 (v0.7.4): ``labels`` accepted for Protocol parity with
        AuditReport.write_header; currently ignored — the Markdown report
        uses fixed structural English labels ("# BOB Report" etc.) for
        external-tool interoperability. May be honoured in a future
        version if user demand surfaces.
        """
        _ = labels  # intentionally unused for now
        now = self.created_at.strftime("%Y-%m-%d %H:%M:%S")

        self._writeln("# BOB Report")
        self._writeln("")
        self._writeln(f"**Version:** v{info.version} | **Date:** {now}")
        self._writeln(f"**Host:** {info.hostname} | **User:** {info.user}")
        self._writeln("")
        self._writeln("## System Information")
        self._writeln("")
        self._writeln(f"- **OS:** {info.os_name}")
        self._writeln(f"- **Kernel:** {info.kernel}")
        self._writeln(f"- **Firewall (UFW):** v{info.ufw_version}")
        self._writeln(f"- **Language:** {info.language}")
        self._writeln(f"- **Config:** {info.config_path}")
        self._writeln("")

    def write_group(self, title: str) -> None:
        """Write a markdown group header (#)."""
        self._writeln(f"# {title}")
        self._writeln("")

    def write_section(self, title: str) -> None:
        """Write a markdown section header (##)."""
        self._writeln(f"## {title}")
        self._writeln("")

    def write_finding(
        self,
        level: str,
        message: str,
        detail: str = "",
    ) -> None:
        """
        Write a single finding with level and timestamp.

        Args:
            level:   "OK" | "WARN" | "ALERT" | "INFO"
            message: Main finding message.
            detail:  Optional detail on next line.
        """
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Use **bold** for ALERT level, regular for others
        level_marker = f"**{level}**" if level == "ALERT" else level
        self._writeln(f"- `{now}` [{level_marker}] {message}")
        if detail:
            self._writeln(f"  - {detail}")

    def write_raw(self, text: str) -> None:
        """Write a raw text line without any prefix."""
        self._writeln(text)

    def write_indented(self, text: str, indent: int = 4) -> None:
        """Write an indented line (used as nested bullet)."""
        spaces = " " * indent
        self._writeln(f"{spaces}{text}")

    def write_separator(self, thin: bool = False) -> None:
        """Write a markdown horizontal rule."""
        self._writeln("---")

    def write_summary(
        self,
        score: int,
        risk_level: str,
        network_context: str,
        public_ip: str,
        ok_count: int,
        warn_count: int,
        alert_count: int,
        breakdown: list,
        labels: dict[str, str],
        posture_annotation: str = "",
    ) -> None:
        """
        Write the audit summary block.

        Args:
            score:              Final security score (0-10).
            risk_level:         Translated risk level string.
            network_context:    Translated network context string.
            public_ip:          Public IP if detected, empty string otherwise.
            ok_count:           Number of OK findings.
            warn_count:         Number of WARN findings.
            alert_count:        Number of ALERT findings.
            breakdown:          List of Deduction objects.
            labels:             Dict of translated field labels.
            posture_annotation: Translated suffix appended to the Risk row when
                                the v0.7.0 posture floor escalated the risk
                                above the score-derived level. Empty string
                                when no escalation. I-2 (v0.7.1): added to
                                match the Report Protocol + AuditReport.
        """
        context_str = network_context
        if public_ip:
            context_str += f" ({public_ip})"

        risk_str = risk_level
        if posture_annotation:
            risk_str = f"{risk_level} ({posture_annotation})"

        self._writeln("")
        self._writeln("## " + labels.get("summary", "AUDIT SUMMARY"))
        self._writeln("")
        self._writeln("| Metric | Value |")
        self._writeln("|--------|-------|")
        self._writeln(f"| OK | {ok_count} |")
        self._writeln(f"| Warning | {warn_count} |")
        self._writeln(f"| Alert | {alert_count} |")
        self._writeln(f"| Score | {score}/10 |")
        self._writeln(f"| Risk | {risk_str} |")
        self._writeln(f"| Context | {context_str} |")
        self._writeln("")

        if breakdown:
            self._writeln("### " + labels.get("breakdown", "SCORE BREAKDOWN"))
            self._writeln("")
            for deduction in breakdown:
                suffix = f" ({deduction.context})" if deduction.context in ("public", "ddns") else ""
                self._writeln(
                    f"- {deduction.reason:<50} -{deduction.points}{suffix}"
                )
            self._writeln("")

    def write_risk_context_section(
        self,
        section_title: str,
        entries: list[dict],
    ) -> None:
        """
        Write the risk context section for detected high/critical services.

        Args:
            section_title: Translated section title.
            entries:       List of dicts with keys: label, level, exposure_label,
                          exposure, threat_label, threat.
        """
        if not entries:
            return

        self._writeln("---")
        self._writeln(f"## {section_title}")
        self._writeln("")

        for entry in entries:
            self._writeln(f"### {entry['label']} [{entry['level']}]")
            self._writeln("")
            self._writeln(f"**{entry['exposure_label']}:** {entry['exposure']}")
            self._writeln("")
            self._writeln(f"**{entry['threat_label']}:** {entry['threat']}")
            self._writeln("")

    def write_services_panorama(
        self,
        rows: list[dict],
        labels: dict,
    ) -> None:
        """
        Write the services panorama table.

        Args:
            rows:   List of dicts with keys: label, status, ports, ufw.
            labels: Dict with translated strings for headers.
        """
        self._writeln("## " + labels.get("header_service", "SERVICES PANORAMA"))
        self._writeln("")

        h_svc  = labels.get("header_service", "SERVICE")
        h_stat = labels.get("header_status",  "STATUS")
        h_port = labels.get("header_ports",   "PORT(S)")
        h_ufw  = labels.get("header_ufw",     "UFW")

        self._writeln(f"| {h_svc} | {h_stat} | {h_port} | {h_ufw} |")
        self._writeln("|---------|----------|---------|-----|")

        for row in rows:
            label  = row["label"]
            status = row["status"]
            ports  = row["ports"]
            ufw    = row["ufw"]
            self._writeln(f"| {label} | {status} | {ports} | {ufw} |")

        self._writeln("")

    def write_next_steps(self, steps: list[str], title: str = "NEXT STEPS") -> None:
        """Write the next steps block at the end of the report."""
        self._writeln("## Next Steps")
        self._writeln("")
        for i, step in enumerate(steps, start=1):
            self._writeln(f"{i}. {step}")
        self._writeln("")

    # ------------------------------------------------------------------
    # Conversion to HTML
    # ------------------------------------------------------------------

    def to_html(self) -> str:
        """
        Convert markdown content to minimal HTML.

        Returns: Valid HTML string suitable for email multipart/alternative.

        This is a lightweight markdown → HTML converter using pure Python.
        No external dependencies. Supports:
        - Headers: # , ## , ### → <h1>, <h2>, <h3>
        - Lists: - item → <ul><li>
        - Tables: | col | → <table>
        - Bold: **text** → <strong>
        - Code: `text` → <code>
        - Links (basic): [text](url) → <a href>
        - Horizontal rules: --- → <hr />
        """
        markdown_text = "\n".join(self._lines)
        return markdown_to_html(markdown_text)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """No-op for MarkdownReport (no file I/O by default)."""
        logger.debug("Markdown report closed: %s", self.path)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _writeln(self, text: str) -> None:
        """Append a line to internal buffer."""
        self._lines.append(text)

# ---------------------------------------------------------------------------
# HTML Conversion (zero-dependency markdown parser)
# ---------------------------------------------------------------------------

def markdown_to_html(markdown_text: str) -> str:
    """
    Convert markdown to minimal HTML for email clients.

    Pure Python implementation, no external libraries.
    Handles:
    - Headers (#, ##, ###)
    - Horizontal rules (---)
    - Unordered lists (- item)
    - Tables (| col | col |)
    - Bold (**text**)
    - Code backticks (`text`)
    - Inline links [text](url)

    Args:
        markdown_text: Markdown string to convert.

    Returns:
        Valid HTML suitable for email.
    """
    lines = markdown_text.split("\n")
    html_lines: list[str] = []

    i = 0
    while i < len(lines):
        line = lines[i]

        # Skip empty lines (handled separately)
        if not line.strip():
            if html_lines and html_lines[-1] not in ("</ul>", "</table>"):
                html_lines.append("")
            i += 1
            continue

        # Headers
        if line.startswith("### "):
            text = line[4:].strip()
            html_lines.append(f"<h3>{_inline_format(text)}</h3>")
            i += 1
            continue

        if line.startswith("## "):
            text = line[3:].strip()
            html_lines.append(f"<h2>{_inline_format(text)}</h2>")
            i += 1
            continue

        if line.startswith("# "):
            text = line[2:].strip()
            html_lines.append(f"<h1>{_inline_format(text)}</h1>")
            i += 1
            continue

        # Horizontal rule
        if line.strip() == "---":
            html_lines.append("<hr />")
            i += 1
            continue

        # Tables (lines starting with |)
        if line.strip().startswith("|"):
            # Collect all consecutive table lines
            table_lines = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                table_lines.append(lines[i])
                i += 1

            html_lines.append(_parse_markdown_table(table_lines))
            continue

        # Unordered lists (lines starting with -)
        if line.startswith("- ") or line.startswith("  - "):
            list_items = []
            while i < len(lines) and (lines[i].startswith("- ") or lines[i].startswith("  - ")):
                item_line = lines[i].strip()
                if item_line.startswith("- "):
                    item_line = item_line[2:]
                list_items.append(item_line)
                i += 1

            html_lines.append("<ul>")
            for item in list_items:
                html_lines.append(f"<li>{_inline_format(item)}</li>")
            html_lines.append("</ul>")
            continue

        # Regular paragraph
        html_lines.append(f"<p>{_inline_format(line)}</p>")
        i += 1

    # Wrap in HTML structure
    html_body = "\n".join(html_lines)
    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
body {{ font-family: sans-serif; line-height: 1.6; }}
h1 {{ font-size: 24px; margin: 20px 0 10px 0; }}
h2 {{ font-size: 20px; margin: 15px 0 10px 0; color: #333; }}
h3 {{ font-size: 16px; margin: 10px 0 5px 0; color: #555; }}
p {{ margin: 8px 0; }}
code {{ background: #f4f4f4; padding: 2px 4px; border-radius: 3px; font-family: monospace; }}
table {{ border-collapse: collapse; margin: 10px 0; width: 100%; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background-color: #f2f2f2; font-weight: bold; }}
ul {{ margin: 10px 0; padding-left: 20px; }}
li {{ margin: 4px 0; }}
strong {{ font-weight: bold; }}
hr {{ margin: 20px 0; border: none; border-top: 1px solid #ccc; }}
</style>
</head>
<body>
{html_body}
</body>
</html>"""

def _safe_url(url: str) -> str:
    """Return url only if it uses a safe scheme; otherwise return '#'.

    I-3 (v0.5.5): the URL is inserted into ``href="..."`` (attribute
    context). Caller's ``html.escape(text)`` defaults to ``quote=False``,
    which leaves ``"`` and ``'`` raw — a crafted markdown link like
    ``[label](https://x.com" onclick="alert(1))`` would break out of the
    attribute. Re-escape with ``quote=True`` here to plug that vector
    even though current call sites only consume BOB-emitted markdown.
    """
    if url.startswith(("http://", "https://")):
        return html.escape(url, quote=True)
    return "#"

_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")

def _inline_format(text: str) -> str:
    """Apply inline formatting (bold, code, links) to text.

    Order matters: escape HTML entities **first**, then translate markdown
    constructs to HTML tags. The previous order built ``<a>`` tags and then
    escaped them into ``&lt;a&gt;`` literals — links rendered as visible HTML
    source in email reports.
    """
    text = html.escape(text)

    def _replace_link(m: re.Match) -> str:
        # M-6 (v0.7.3): undo the parent ``html.escape`` on the URL before
        # passing it to ``_safe_url``, otherwise the URL gets escaped twice
        # (parent ``html.escape`` + ``_safe_url``'s ``html.escape(quote=True)``)
        # and characters like ``&`` end up as ``&amp;amp;`` in the rendered
        # ``href="..."``. The label part stays escape-once because the
        # ``<a>...</a>`` element's text content is the right place for it.
        raw_url = html.unescape(m.group(2))
        return f'<a href="{_safe_url(raw_url)}">{m.group(1)}</a>'

    text = _LINK_RE.sub(_replace_link, text)

    # Bold: **text** → <strong>text</strong>
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)

    # Code: `text` → <code>text</code>
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)

    return text

def _parse_markdown_table(table_lines: list[str]) -> str:
    """Convert markdown table to HTML table."""
    if len(table_lines) < 2:
        return ""

    # Parse header row
    header_row = table_lines[0].strip()
    header_cells = [cell.strip() for cell in header_row.split("|") if cell.strip()]

    # Skip separator row (table_lines[1] should be |---|---|...)
    # Parse data rows
    data_rows = []
    for line in table_lines[2:]:  # Skip header and separator
        cells = [cell.strip() for cell in line.split("|") if cell.strip()]
        if cells:
            data_rows.append(cells)

    # Generate HTML table
    html = "<table>\n<thead>\n<tr>"
    for cell in header_cells:
        html += f"<th>{_inline_format(cell)}</th>"
    html += "</tr>\n</thead>\n<tbody>\n"

    max_cols = len(header_cells)
    for row in data_rows:
        row = row[:max_cols] + [""] * (max_cols - len(row))
        html += "<tr>"
        for cell in row:
            html += f"<td>{_inline_format(cell)}</td>"
        html += "</tr>\n"

    html += "</tbody>\n</table>"
    return html

# ---------------------------------------------------------------------------
# Email helper (zero-dependency MIME multipart)
# ---------------------------------------------------------------------------

def send_html_email(
    recipient: str,
    subject: str,
    html_content: str,
    plain_text_fallback: str = "",
    from_email: str = "",
) -> bool:
    """
    Send an HTML email via system `mail` with markdown fallback.

    Creates a MIME multipart/alternative email with both HTML and plaintext
    versions. Uses zero external dependencies — just subprocess + Python's
    email module (stdlib).

    Args:
        recipient:           Email address to send to.
        subject:             Email subject line.
        html_content:        HTML content (full document with <html> tags).
        plain_text_fallback: Plaintext version (plain markdown). If empty, uses
                            HTML's <body> text content stripped.
        from_email:          Sender email address. If empty, uses recipient
                            (workaround for local SMTP servers that reject
                            system user addresses like root@hostname).

    Returns:
        True if email was sent successfully, False otherwise.

    Raises:
        OSError: If `mail` command is not found.
    """
    import subprocess
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    import shutil

    # Check if sendmail command exists (used for actual delivery below)
    if not shutil.which("sendmail"):
        logger.error("sendmail command not found")
        return False

    # Use recipient as From if not specified (SMTP workaround)
    if not from_email:
        from_email = recipient

    # M-11 (v0.7.3): defensive CRLF stripping on every MIME header value to
    # close email header injection if a future caller passes a tainted
    # subject / recipient / from_email. ``email.MIMEText`` already encodes
    # well-formed values safely, but an embedded ``\r\nBcc:`` would be
    # accepted on some MTAs. No current caller is tainted (all values are
    # BOB-internal) but defence-in-depth is cheap here.
    def _strip_crlf(s: str) -> str:
        if not isinstance(s, str):
            return s
        return s.replace("\r", "").replace("\n", "")

    from_email = _strip_crlf(from_email)
    recipient  = _strip_crlf(recipient)
    subject    = _strip_crlf(subject)

    # Create MIME multipart message
    msg = MIMEMultipart("alternative")
    msg["From"] = from_email
    msg["To"] = recipient
    msg["Subject"] = subject

    # Plaintext fallback: if not provided, extract from HTML body
    if not plain_text_fallback:
        # Simple text extraction from HTML (strip tags)
        text = re.sub(r"<[^>]+>", "", html_content)
        text = re.sub(r"\s+", " ", text).strip()
        plain_text_fallback = text[:500]  # Limit to 500 chars

    # Attach plaintext version (preferred by email clients for spam filtering)
    part1 = MIMEText(plain_text_fallback, "plain", _charset="utf-8")
    msg.attach(part1)

    # Attach HTML version
    part2 = MIMEText(html_content, "html", _charset="utf-8")
    msg.attach(part2)

    # Convert message to string and send via mail
    email_str = msg.as_string()

    try:
        # Use sendmail directly with -f to force the From address
        # (mail/mailx may ignore From: header when invoked by root)
        proc = subprocess.run(
            ["sendmail", "-t", "-f", from_email],
            input=email_str,
            text=True,
            capture_output=True,
            timeout=10,
        )
        if proc.returncode == 0:
            logger.info(f"Email sent to {recipient}")
            return True
        else:
            logger.error(f"mail command failed: {proc.stderr}")
            return False
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        logger.error(f"Failed to send email: {exc}")
        return False

# ---------------------------------------------------------------------------
# Audit report log → HTML email converter (for cron integration)
# ---------------------------------------------------------------------------

def send_audit_log_as_html_email(
    log_file: str | Path,
    recipient: str,
    subject: str = "",
) -> bool:
    """
    Convert a plaintext AuditReport .log file to HTML and email it.

    This helper is used by the nightly cron script to convert the legacy
    plaintext report (with ASCII art) to an HTML email for readability.

    Args:
        log_file:  Path to the AuditReport .log file generated by the audit.
        recipient: Email address to send to.
        subject:   Email subject. If empty, defaults to "BOB Report".

    Returns:
        True if email was sent, False otherwise.
    """
    from pathlib import Path as PathlibPath

    log_file = PathlibPath(log_file) if isinstance(log_file, str) else log_file

    if not log_file.exists():
        logger.error(f"Log file not found: {log_file}")
        return False

    try:
        log_text = log_file.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.error(f"Cannot read log file: {exc}")
        return False

    # Convert plaintext log to HTML
    html = _audit_log_to_html(log_text)

    # Send email
    if not subject:
        subject = "BOB Report"

    return send_html_email(recipient, subject, html, log_text[:1000])

def _audit_log_to_html(log_text: str) -> str:
    """
    Convert a plaintext AuditReport to readable HTML.

    Converts:
    - ASCII box borders → ignored
    - Section headers (===...===) → <h2>
    - Timestamps [LEVEL] → styled <div>
    - Key: value pairs → <dl>

    Returns: Valid HTML string.
    """
    lines = log_text.split("\n")
    html_lines: list[str] = []

    i = 0
    while i < len(lines):
        line = lines[i]

        # Skip ASCII box borders (╔, ║, ═, ╚, etc.)
        if re.match(r"^[╔╗╚╝║═┌┐└┘─┼ ]+$", line.strip()) and line.strip():
            i += 1
            continue

        # Section headers: === TITLE ===
        if line.strip().startswith("===") and line.strip().endswith("==="):
            title = html.escape(line.strip().replace("=", "").strip())
            if title:
                html_lines.append(f"<h2>{title}</h2>")
            i += 1
            continue

        # Section headers with brackets: [TITLE]
        if line.strip().startswith("[") and line.strip().endswith("]"):
            title = html.escape(line.strip()[1:-1])  # Remove brackets
            if title:
                html_lines.append(f"<h2>{title}</h2>")
            i += 1
            continue

        # Horizontal separator line
        if line.strip().startswith("---") or line.strip().startswith("==="):
            html_lines.append("<hr />")
            i += 1
            continue

        # Timestamped findings: 2024-01-15 12:30:45 [LEVEL] message
        match = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[([A-Z]+)\] (.*)$", line)
        if match:
            timestamp, level, message = match.groups()
            html_lines.append(
                f'<div style="margin: 8px 0; padding: 8px; background: #f9f9f9; '
                f'border-left: 4px solid #ccc;"><code>{html.escape(timestamp)}</code> '
                f'<strong>[{html.escape(level)}]</strong> {html.escape(message)}</div>'
            )
            i += 1
            continue

        # Key-value lines: "Key : Value" or "Key  : Value  "
        if " : " in line and not line.startswith(" "):
            parts = line.split(" : ", 1)
            key = html.escape(parts[0].strip())
            value = html.escape(parts[1].strip()) if len(parts) > 1 else ""
            if key and value:
                html_lines.append(f"<p><strong>{key}:</strong> {value}</p>")
                i += 1
                continue

        # Numbered list (next steps)
        match = re.match(r"^(\d+)\. (.*)$", line)
        if match:
            _num, text = match.groups()
            html_lines.append(f"<li>{html.escape(text)}</li>")
            i += 1
            continue

        # Empty lines — preserve some structure
        if not line.strip():
            if html_lines and html_lines[-1] != "<br />":
                html_lines.append("<br />")
            i += 1
            continue

        # Regular text paragraph
        if line.strip():
            # Indented text (details under findings)
            indent = len(line) - len(line.lstrip())
            if indent > 0:
                html_lines.append(f"<p style='margin-left: {indent * 10}px;'>{html.escape(line.strip())}</p>")
            else:
                html_lines.append(f"<p>{html.escape(line)}</p>")

        i += 1

    # Wrap consecutive <li> items in <ol> blocks
    wrapped: list[str] = []
    in_ol = False
    for tag in html_lines:
        if tag.startswith("<li>"):
            if not in_ol:
                wrapped.append("<ol>")
                in_ol = True
        else:
            if in_ol:
                wrapped.append("</ol>")
                in_ol = False
        wrapped.append(tag)
    if in_ol:
        wrapped.append("</ol>")
    html_lines = wrapped

    # Wrap in HTML template
    html_body = "\n".join(html_lines)
    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
body {{ font-family: sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; }}
h2 {{ font-size: 18px; margin: 15px 0 10px 0; color: #1a5490; border-bottom: 2px solid #1a5490; padding-bottom: 5px; }}
p {{ margin: 6px 0; }}
code {{ background: #f4f4f4; padding: 2px 4px; border-radius: 3px; font-family: monospace; font-size: 12px; }}
strong {{ font-weight: bold; }}
hr {{ margin: 15px 0; border: none; border-top: 1px solid #ddd; }}
li {{ margin: 4px 0; }}
div[style*="border-left"] {{ border-radius: 3px; }}
</style>
</head>
<body>
<h1>BOB Report</h1>
{html_body}
</body>
</html>"""
