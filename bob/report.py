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
from typing import Optional

logger = logging.getLogger(__name__)

_SEPARATOR = "=" * 62
_THIN_SEP  = "-" * 62


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
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        self._fh = os.fdopen(fd, "w", encoding="utf-8")
        # When invoked under sudo, the report file is owned by root by default
        # and cannot be read/deleted afterwards by the real user. Chown it back
        # so `sudo bob -d` reports land in the user's account, not root's. Same
        # pattern as bob.config / bob.history / bob.ignore / bob.compare /
        # bob.recurrence — see SECURITY.md and v0.3.6 entry for context.
        from bob.sysinfo import chown_to_sudo_user
        chown_to_sudo_user(path)

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

    def write_header(self, info: SystemInfo) -> None:
        """Write the report header with ASCII art banner and system info."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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
        self._writeln("[SYSTEM INFORMATION]")
        self._writeln(f"System      : {info.os_name}")
        self._writeln(f"Host        : {info.hostname}")
        self._writeln(f"Kernel      : {info.kernel}")
        self._writeln(f"Firewall    : ufw {info.ufw_version}")
        self._writeln(f"User        : {info.user}")
        self._writeln(f"Language    : {info.language}")
        self._writeln(f"Port config : {info.config_path}")
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
    ) -> None:
        """
        Write the audit summary block.

        Args:
            score:           Final security score (0-10).
            risk_level:      Translated risk level string.
            network_context: Translated network context string.
            public_ip:       Public IP if detected, empty string otherwise.
            ok_count:        Number of OK findings.
            warn_count:      Number of WARN findings.
            alert_count:     Number of ALERT findings.
            breakdown:       List of Deduction objects.
            labels:          Dict of translated field labels.
        """
        context_str = network_context
        if public_ip:
            context_str += f" ({public_ip})"

        self._writeln("")
        self._writeln(_SEPARATOR)
        self._writeln(f"[{labels.get('summary', 'AUDIT SUMMARY')}]")
        self._writeln(f"OK      : {ok_count}")
        self._writeln(f"Warning : {warn_count}")
        self._writeln(f"Alert   : {alert_count}")
        self._writeln(f"Score   : {score}/10")
        self._writeln(f"Risk    : {risk_level}")
        self._writeln(f"Context : {context_str}")
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
        self._writeln(f"[NEXT STEPS]")
        for i, step in enumerate(steps, start=1):
            self._writeln(f"{i}. {step}")
        self._writeln(_SEPARATOR)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Flush and close the report file."""
        if self._fh and not self._fh.closed:
            self._fh.flush()
            self._fh.close()
            logger.debug("Report closed: %s", self.path)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _writeln(self, text: str) -> None:
        """Write a line and flush immediately."""
        self._fh.write(text + "\n")
        self._fh.flush()


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
        self.path: Optional[Path] = None
        self.enabled: bool = False

    def _writeln(self, text: str) -> None:
        pass  # discard

    def close(self) -> None:
        pass  # nothing to close
