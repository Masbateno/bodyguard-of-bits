"""
Audit report module for BOB.

Writes the detailed audit report to a timestamped log file when
the -d / --detailed flag is active. Each write operation flushes
immediately so partial reports are readable if the audit is interrupted.

No terminal output lives here — all display is handled by output.py.

Usage:
    from bob.report import AuditReport
    from pathlib import Path

    report = AuditReport.open(directory=Path.cwd(), version="0.9.0")
    report.write_header(system_info)
    report.write_section("UFW RULES ANALYSIS")
    report.write_finding(level="OK", message="No duplicate rules")
    report.write_raw("arbitrary text line")
    report.write_summary(engine, network_context)
    report.close()

    print(f"Report saved to: {report.path}")
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Protocol

logger = logging.getLogger(__name__)

_SEPARATOR = "=" * 62
_THIN_SEP  = "-" * 62

# ---------------------------------------------------------------------------
# Report — structural type (PEP 544 Protocol)
# ---------------------------------------------------------------------------

class Report(Protocol):
    """Structural type for audit report writers.

    Both :class:`AuditReport` (plain-text) and
    :class:`bob.report_markdown.MarkdownReport` satisfy this Protocol
    without inheriting from it, as does :class:`NullReport`. Use this
    type for parameters that accept any report kind — e.g.
    ``def run_checks(report: Report, ...)``.

    Concrete report classes may expose additional methods beyond this
    Protocol (e.g. ``MarkdownReport.write_services_panorama``); the
    Protocol describes the shared minimum contract that
    :mod:`bob.runner` and :mod:`bob.__main__` rely on.

    Why a Protocol and not an ABC: ``MarkdownReport`` was written
    independently and does not inherit from ``AuditReport``. Forcing
    inheritance now would couple the two implementations; a Protocol
    captures the contract structurally with zero runtime overhead.
    """

    path: Path | None
    enabled: bool

    def write_header(self, info: "SystemInfo", labels: dict[str, str] | None = None) -> None: ...
    def write_group(self, title: str) -> None: ...
    def write_section(self, title: str) -> None: ...
    def write_finding(self, level: str, message: str, detail: str = "") -> None: ...
    def write_raw(self, text: str) -> None: ...
    def write_indented(self, text: str, indent: int = 4) -> None: ...
    def write_separator(self, thin: bool = False) -> None: ...
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
        score_is_upper_bound: bool = False,
        unverified_count: int = 0,
        profile_name: str = "",
    ) -> None: ...
    def write_risk_context_section(
        self,
        section_title: str,
        entries: list[dict],
    ) -> None: ...
    def write_next_steps(self, steps: list[str]) -> None: ...
    def close(self) -> None: ...

# ---------------------------------------------------------------------------
# System info container
# ---------------------------------------------------------------------------

class SystemInfo:
    """
    Snapshot of system information written to the report header.

    Args:
        os_name:     OS / distro string (e.g. "Linux Mint 22.3").
        hostname:    Machine hostname.
        kernel:      Kernel version string.
        ufw_version: UFW version string.
        user:        Real username running the audit.
        config_path: Path to the user config file.
        language:    Language code ("en" or "fr").
        version:     BOB version string.
    """

    def __init__(
        self,
        os_name:          str,
        hostname:         str,
        kernel:           str,
        ufw_version:      str,
        iptables_version: str,
        nftables_version: str,
        user:             str,
        config_path:      str,
        language:         str,
        version:          str,
    ) -> None:
        self.os_name          = os_name
        self.hostname         = hostname
        self.kernel           = kernel
        self.ufw_version      = ufw_version
        self.iptables_version = iptables_version
        self.nftables_version = nftables_version
        self.user             = user
        self.config_path      = config_path
        self.language         = language
        self.version          = version

# ---------------------------------------------------------------------------
# Report writer
# ---------------------------------------------------------------------------

class AuditReport:
    """
    Writes the detailed audit report to a timestamped log file.

    Each write method appends to the file immediately — no buffering.
    The file is created when open() is called and closed via close()
    or the context manager protocol.

    Attributes:
        path:     Full path to the log file.
        enabled:  Always True for instances created via open().
                  A NullReport (disabled) also exposes this interface
                  but discards all writes.
    """

    def __init__(self, path: Path) -> None:
        self.path: Path = path
        self.enabled: bool = True
        # v0.14.1: O_NOFOLLOW. The report name is fully predictable
        # (``bob_%Y%m%d_%H%M%S.log``) and this open runs as root under sudo, so
        # without it anyone able to write in the target directory could
        # pre-plant a symlink and have root truncate + overwrite an arbitrary
        # file. The default directory is the invoking user's own
        # ~/.local/share/bob/logs, but ``--output-dir`` lets an operator point
        # this at a shared location. O_NOFOLLOW makes the open fail instead.
        fd = os.open(str(path),
                     os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                     0o600)
        self._fh = os.fdopen(fd, "w", encoding="utf-8")
        # When invoked under sudo, the report file is owned by root by default
        # and cannot be read/deleted afterwards by the real user. Chown it back
        # so `sudo bob -d` reports land in the user's account, not root's. Same
        # pattern as bob.config / bob.history / bob.ignore / bob.compare /
        # bob.recurrence — see SECURITY.md and v0.3.6 entry for context.
        # chown the descriptor we already hold, not the name — no symlink to
        # follow and no TOCTOU window (v0.14.1).
        from bob.sysinfo import chown_fd_to_sudo_user
        chown_fd_to_sudo_user(self._fh.fileno())

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def open(cls, directory: Path, version: str) -> "AuditReport":
        """
        Create and open a timestamped report file in directory.

        Args:
            directory: Directory where the report file will be created.
            version:   BOB version string (e.g. "0.9.0").

        Returns:
            Open AuditReport instance ready for writing.

        Raises:
            OSError: If the file cannot be created.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename  = f"bob_{timestamp}.log"
        path      = directory / filename

        instance = cls(path=path)
        logger.debug("Report opened: %s", path)
        return instance

    @classmethod
    def null(cls) -> "NullReport":
        """
        Return a no-op report that discards all writes.

        Used when --detailed is not active, so callers never need to
        check whether reporting is enabled before calling write methods.
        """
        return NullReport()

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "AuditReport":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Write methods
    # ------------------------------------------------------------------

    def write_header(self, info: SystemInfo, labels: dict[str, str] | None = None) -> None:
        """Write the report header with ASCII art banner and system info.

        M-5 (v0.7.4): the system-info labels can be overridden via the
        optional ``labels`` dict (keys: ``system_information``, ``system``,
        ``host``, ``kernel``, ``firewall``, ``user``, ``language``,
        ``port_config``). Pre-v0.7.4 these were hardcoded English even when
        ``--french`` was active. Defaults preserve the pre-v0.7.4 English
        wording so untouched callers see no behaviour change.
        """
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _L = labels or {}

        # ASCII art — BOB in Doom block style, plain text, no colour
        _BOX_INNER = 60
        _BAR       = "═" * _BOX_INNER

        B = ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██████╔╝", "╚═════╝ "]
        O = [" ██████╗ ", "██╔═══██╗", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "]

        letter_groups = [B, O, B]

        self._writeln(f"╔{_BAR}╗")
        for i in range(6):
            parts = [grp[i] for grp in letter_groups]
            row   = "  " + " ".join(parts)
            pad   = max(0, _BOX_INNER - len(row))
            self._writeln(f"║{row}{' ' * pad}║")
        self._writeln(f"╠{_BAR}╣")

        v_line = f"  BOB v{info.version}  │  {now}"
        self._writeln(f"║{v_line}{' ' * max(0, _BOX_INNER - len(v_line))}║")
        h_line = f"  {info.hostname}  │  {info.user}"
        self._writeln(f"║{h_line}{' ' * max(0, _BOX_INNER - len(h_line))}║")
        self._writeln(f"╚{_BAR}╝")
        self._writeln("")

        self._writeln(_SEPARATOR)
        self._writeln(f"[{_L.get('system_information', 'SYSTEM INFORMATION')}]")
        self._writeln(f"{_L.get('system',      'System'     ):<12}: {info.os_name}")
        self._writeln(f"{_L.get('host',        'Host'       ):<12}: {info.hostname}")
        self._writeln(f"{_L.get('kernel',      'Kernel'     ):<12}: {info.kernel}")
        self._writeln(f"{_L.get('firewall',    'Firewall'   ):<12}: ufw {info.ufw_version}")
        self._writeln(f"{_L.get('user',        'User'       ):<12}: {info.user}")
        self._writeln(f"{_L.get('language',    'Language'   ):<12}: {info.language}")
        self._writeln(f"{_L.get('port_config', 'Port config'):<12}: {info.config_path}")
        self._writeln("")
        self._writeln(_SEPARATOR)
        self._writeln("")

    def write_group(self, title: str) -> None:
        """Write a group header (above sections)."""
        self._writeln(f"\n{'=' * 80}\n  {title}\n{'=' * 80}\n")

    def write_section(self, title: str) -> None:
        """Write a section header."""
        self._writeln(f"\n=== {title} ===\n")

    def write_finding(
        self,
        level: str,
        message: str,
        detail: str = "",
    ) -> None:
        """
        Write a single timestamped finding line.

        Args:
            level:   "OK" | "WARN" | "ALERT" | "INFO"
            message: Main finding message.
            detail:  Optional detail appended on the next line.
        """
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._writeln(f"{now} [{level}] {message}")
        if detail:
            self._writeln(f"    {detail}")

    def write_raw(self, text: str) -> None:
        """Write a raw text line without timestamp or level prefix."""
        self._writeln(text)

    def write_indented(self, text: str, indent: int = 4) -> None:
        """Write a line with leading spaces."""
        self._writeln(" " * indent + text)

    def write_separator(self, thin: bool = False) -> None:
        """Write a separator line."""
        self._writeln(_THIN_SEP if thin else _SEPARATOR)

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
        score_is_upper_bound: bool = False,
        unverified_count: int = 0,
        profile_name: str = "",
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
            posture_annotation: M-3 (v0.7.0 Phase 2.1) — translated parenthetical
                                hint shown alongside the risk level when posture
                                escalation has lifted it (e.g. "raised by posture:
                                firewall inactive"). Empty when not applicable.
                                Mirrors the terminal summary box behaviour so
                                the on-disk .txt report and the screen stay in
                                sync.
            score_is_upper_bound: v0.16.0 — True when a check could not read
                                its input, so the score is a ceiling. The
                                terminal renders "≤ 7/10" and this block used
                                to render "7/10" from the same audit: the
                                report is the artefact an operator keeps, and
                                it contradicted the screen.
            unverified_count:   Number of sections not fully read.
            profile_name:       The audit profile in force. It changes
                                severities and the exit code, so two reports
                                taken under different profiles are not
                                comparable — and nothing in the file said which
                                one produced it.

        Defaults keep every pre-v0.16.0 caller working, including NullReport
        and the mocks in the test suite.
        """
        context_str = network_context
        if public_ip:
            context_str += f" ({public_ip})"

        risk_str = risk_level
        if posture_annotation:
            risk_str = f"{risk_str}  ({posture_annotation})"

        # M-5 (v0.7.3): the 6 field labels accept i18n via labels= dict.
        # Defaults match the v0.7.2 English output exactly so legacy
        # callers (tests / mocks that pre-date the i18n extraction)
        # produce the same .txt output as before.
        # Column width from the longest label actually used, not a constant:
        # "Visibility" is ten characters and overflowed the hardcoded 8, so the
        # colon sat flush against it while every other row was aligned.
        _used = [
            labels.get("ok", "OK"), labels.get("warning", "Warning"),
            labels.get("alert", "Alert"), labels.get("score", "Score"),
            labels.get("risk", "Risk"), labels.get("context", "Context"),
        ]
        if profile_name:
            _used.append(labels.get("profile", "Profile"))
        if score_is_upper_bound:
            _used.append(labels.get("visibility", "Visible"))
        # Floored at the historical 8 so a summary without the long labels
        # renders byte-identically to every version before this one.
        _w = max(8, max(len(x) for x in _used))

        ok_lbl   = labels.get("ok",      "OK")
        warn_lbl = labels.get("warning", "Warning")
        alert_lbl = labels.get("alert",  "Alert")
        score_lbl = labels.get("score",  "Score")
        risk_lbl  = labels.get("risk",   "Risk")
        ctx_lbl   = labels.get("context", "Context")

        self._writeln("")
        self._writeln(_SEPARATOR)
        self._writeln(f"[{labels.get('summary', 'AUDIT SUMMARY')}]")
        self._writeln(f"{ok_lbl:<{_w}}: {ok_count}")
        self._writeln(f"{warn_lbl:<{_w}}: {warn_count}")
        self._writeln(f"{alert_lbl:<{_w}}: {alert_count}")
        score_str = f"≤ {score}/10" if score_is_upper_bound else f"{score}/10"
        self._writeln(f"{score_lbl:<{_w}}: {score_str}")
        self._writeln(f"{risk_lbl:<{_w}}: {risk_str}")
        self._writeln(f"{ctx_lbl:<{_w}}: {context_str}")
        if profile_name:
            self._writeln(f"{labels.get('profile', 'Profile'):<{_w}}: {profile_name}")
        if score_is_upper_bound:
            self._writeln(
                f"{labels.get('visibility', 'Visible'):<{_w}}: "
                f"{labels.get('visibility_value', '')}"
            )
        self._writeln("")

        if breakdown:
            self._writeln(f"[{labels.get('breakdown', 'SCORE BREAKDOWN')}]")
            for deduction in breakdown:
                suffix = f" ({deduction.context})" if deduction.context in ("public", "ddns") else ""
                self._writeln(
                    f"  {deduction.reason:<50}  -{deduction.points}{suffix}"
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
            entries:       List of dicts with keys:
                           label, level, exposure_label, exposure,
                           threat_label, threat.
        """
        if not entries:
            return

        self._writeln(_SEPARATOR)
        self._writeln(f"[{section_title}]")
        self._writeln("")

        for entry in entries:
            self._writeln(
                f"  {entry['label']:<32}  [{entry['level']}]"
            )
            self._writeln(f"  {entry['exposure_label']} : {entry['exposure']}")
            self._writeln(f"  {entry['threat_label']}   : {entry['threat']}")
            self._writeln("")

    def write_next_steps(self, steps: list[str]) -> None:
        """Write the next steps block at the end of the report."""
        self._writeln("[NEXT STEPS]")
        for i, step in enumerate(steps, start=1):
            self._writeln(f"{i}. {step}")
        self._writeln(_SEPARATOR)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Flush and close the report file — best-effort.

        v0.14.1: the final flush can raise on a full filesystem even when every
        individual write appeared to succeed (buffered data is only pushed out
        here). Unguarded, that cost the whole audit at the very last step,
        after all the work was done. Same rule as ``_writeln``: the report is a
        side artifact and must never take the audit down with it.
        """
        if self._fh and not self._fh.closed:
            try:
                self._fh.flush()
            except (OSError, ValueError) as exc:
                self.enabled = False
                logger.warning("Report flush failed on %s: %s", self.path, exc)
            try:
                self._fh.close()
            except (OSError, ValueError) as exc:
                logger.warning("Report close failed on %s: %s", self.path, exc)
            logger.debug("Report closed: %s", self.path)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _writeln(self, text: str) -> None:
        """Write a line and flush immediately — best-effort.

        v0.14.1: the report is a *side artifact*; the audit result must never
        depend on being able to write it. Pre-v0.14.1 this method had no error
        handling at all, so a single failed write raised ``OSError`` from any
        of the ~200 ``report.write_*`` call sites scattered through the audit
        and cost the operator the ENTIRE run — exit 3, zero bytes of stdout.
        Reproduced on a real 64 KB tmpfs: ``sudo bob -d --output-dir=<full fs>``
        produced no audit at all. A full ``/var`` is precisely the kind of
        situation in which an operator reaches for a hardening audit.

        On the first failure the report disables itself, so one bad write
        cannot produce hundreds of identical log lines, and the operator is
        told once on stderr (stdout stays clean for machine formats).
        """
        if not self.enabled:
            return
        try:
            self._fh.write(text + "\n")
            self._fh.flush()
        except (OSError, ValueError) as exc:
            # ValueError covers "I/O operation on closed file".
            self.enabled = False
            logger.warning("Report writing disabled after an I/O error on %s: %s",
                           self.path, exc)
            import sys as _sys
            print(f"  ! Report writing disabled ({self.path}): {exc}",
                  file=_sys.stderr)

# ---------------------------------------------------------------------------
# Null report — no-op implementation for when --detailed is not active
# ---------------------------------------------------------------------------

class NullReport(AuditReport):
    """
    No-op report that discards all writes.

    Returned by AuditReport.null() when --detailed is not active.
    Callers can always call write_* methods without checking report.enabled.
    """

    def __init__(self) -> None:
        # Deliberately skip AuditReport.__init__ — no file is opened
        self.path: Path | None = None
        self.enabled: bool = False

    def _writeln(self, text: str) -> None:
        pass  # discard

    def close(self) -> None:
        pass  # nothing to close
