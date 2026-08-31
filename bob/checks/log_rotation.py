"""
Log rotation & system journaling audit for BOB (CHECK 39).

Audits three layers of log management:
  1. logrotate     — installed and configured with active rules
  2. systemd-journald — Storage= persistent, SystemMaxUse/SystemKeepFree set
  3. Remote syslog — rsyslog/syslog-ng present with at least one remote target

Split:
  1. LogRotationSnapshot.from_system() — inspects live system. Never raises.
  2. check_log_rotation(snapshot)      — pure logic, returns CheckResult.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from bob.checks._run import TranslationFunc, _command_exists, _identity_t, _run, is_unit_active  # noqa: F401 — `_run` kept in the module namespace as a monkeypatch seam (tests do setattr(module, "_run", ...))
from bob.scoring import CheckResult


_JOURNALD_CONF   = Path("/etc/systemd/journald.conf")
_JOURNALD_CONF_D = Path("/etc/systemd/journald.conf.d")
_LOGROTATE_D     = Path("/etc/logrotate.d")
_RSYSLOG_CONF    = Path("/etc/rsyslog.conf")
_RSYSLOG_CONF_D  = Path("/etc/rsyslog.d")
_SYSLOG_NG_CONF  = Path("/etc/syslog-ng/syslog-ng.conf")

# Matches rsyslog remote targets: @@host, @host, action(type="omfwd" ...)
_RSYSLOG_REMOTE_RE = re.compile(
    r"^\s*(?:@@?[a-zA-Z0-9._:-]+|action\s*\(.*?type\s*=\s*[\"']omfwd[\"'])",
    re.MULTILINE,
)
# Matches syslog-ng tcp/udp destinations
_SYSLOGNG_REMOTE_RE = re.compile(
    r"\btcp\s*\(|\budp\s*\(|\bsyslog\s*\(",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------

@dataclass
class LogRotationSnapshot:
    """
    Log management state from the live system.

    Args:
        logrotate_installed:      True if logrotate binary is present.
        logrotate_rule_count:     Number of files in /etc/logrotate.d/.
        journald_active:          True if systemd-journald is running.
        journald_storage:         Raw value of Storage= (or '' if unset).
        journald_conf_readable:   False when journald.conf exists but would not
                                  open. Storage then reads as '' — the same as
                                  unset, which is treated as journald's "auto"
                                  default and therefore as persistent, so a
                                  config saying Storage=volatile was reported
                                  as persistent.
        journald_max_use:         Raw value of SystemMaxUse= (or '' if unset).
        journald_keep_free:       Raw value of SystemKeepFree= (or '' if unset).
        journal_persistent:       True if /var/log/journal/ exists and is a dir.
        remote_syslog_configured: True if rsyslog/syslog-ng has a remote target.
        syslog_daemon:            Name of detected syslog daemon ('rsyslog',
                                  'syslog-ng', or '').
    """
    logrotate_installed:      bool  = False
    logrotate_rule_count:     int   = 0
    journald_active:          bool  = False
    journald_storage:         str   = ""
    journald_conf_readable:   bool  = True
    journald_max_use:         str   = ""
    journald_keep_free:       str   = ""
    journal_persistent:       bool  = False
    remote_syslog_configured: bool  = False
    syslog_daemon:            str   = ""

    @classmethod
    def from_system(cls) -> "LogRotationSnapshot":
        """Inspect the live system. Never raises."""
        logrotate_installed  = _command_exists("logrotate")
        logrotate_rule_count = _count_logrotate_rules()

        journald_active   = _service_active("systemd-journald")
        storage, max_use, keep_free, journald_readable = _read_journald_conf()
        journal_persistent = Path("/var/log/journal").is_dir()

        syslog_daemon, remote = _detect_remote_syslog()

        return cls(
            logrotate_installed=logrotate_installed,
            logrotate_rule_count=logrotate_rule_count,
            journald_active=journald_active,
            journald_storage=storage,
            journald_conf_readable=journald_readable,
            journald_max_use=max_use,
            journald_keep_free=keep_free,
            journal_persistent=journal_persistent,
            remote_syslog_configured=remote,
            syslog_daemon=syslog_daemon,
        )


# ---------------------------------------------------------------------------
# Check logic
# ---------------------------------------------------------------------------

def check_log_rotation(snapshot: LogRotationSnapshot, t: TranslationFunc | None = None) -> CheckResult:
    """
    Check log rotation and system journaling configuration.

    Deductions:
      - logrotate not installed:          −1 pt
      - journald storage volatile/none:   −1 pt  (logs lost on reboot)

    INFO-only (no deduction):
      - logrotate installed but no rules in logrotate.d
      - SystemMaxUse / SystemKeepFree not configured
      - No remote syslog target configured
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    # ------------------------------------------------------------------ #
    # 1. logrotate                                                         #
    # ------------------------------------------------------------------ #
    if not snapshot.logrotate_installed:
        result.warn_with_deduction(
            key="log_rotation.logrotate_missing",
            message=_t("log_rotation.logrotate_missing"),
            reason=_t("log_rotation.logrotate_missing_reason"),
            points=1,
            detail=_t("log_rotation.logrotate_missing_detail"),
            cmd="sudo apt install logrotate",
            nature="improvement",
        )
    else:
        if snapshot.logrotate_rule_count <= 0:
            result.info(
                message=_t("log_rotation.logrotate_no_rules"),
                detail=_t("log_rotation.logrotate_no_rules_detail"),
                cmd="ls /etc/logrotate.d/",
                cmd_type="check",
                key="log_rotation.logrotate_no_rules",
            )
        else:
            result.ok(
                message=_t(
                    "log_rotation.logrotate_ok",
                    count=snapshot.logrotate_rule_count,
                ),
                key="log_rotation.logrotate_ok",
            )

    # ------------------------------------------------------------------ #
    # 2. journald — persistence                                            #
    # ------------------------------------------------------------------ #
    if snapshot.journald_active:
        storage = snapshot.journald_storage.strip().lower()
        # "auto" is the default: persistent if /var/log/journal exists
        is_volatile = storage in ("volatile", "none")
        is_persistent = (
            storage == "persistent"
            or (storage in ("auto", "") and snapshot.journal_persistent)
        )

        if is_volatile:
            result.warn_with_deduction(
                key="log_rotation.journald_volatile",
                message=_t("log_rotation.journald_volatile", storage=snapshot.journald_storage or "volatile"),
                reason=_t("log_rotation.journald_volatile_reason"),
                points=1,
                detail=_t("log_rotation.journald_volatile_detail"),
                cmd='sudo mkdir -p /var/log/journal && sudo systemd-tmpfiles --create --prefix /var/log/journal && sudo systemctl kill --kill-who=main --signal=SIGUSR1 systemd-journald',
                nature="improvement",
            )
        elif is_persistent and not snapshot.journald_conf_readable and not storage:
            # Persistence was inferred from journald's default, on a config
            # that would not open — and that config may well set volatile.
            result.info(
                message=_t("log_rotation.journald_conf_unreadable"),
                detail=_t("log_rotation.journald_conf_unreadable_detail"),
                key="log_rotation.journald_conf_unreadable",
            )
        elif is_persistent:
            result.ok(
                message=_t("log_rotation.journald_persistent"),
                key="log_rotation.journald_persistent",
            )
        else:
            # Unknown storage value — treat as volatile (worst-case assumption)
            result.warn_with_deduction(
                key="log_rotation.journald_volatile",
                message=_t("log_rotation.journald_volatile", storage="none"),
                reason=_t("log_rotation.journald_volatile_reason"),
                points=1,
                detail=_t("log_rotation.journald_volatile_detail"),
                cmd='sudo mkdir -p /var/log/journal && sudo systemd-tmpfiles --create --prefix /var/log/journal && sudo systemctl kill --kill-who=main --signal=SIGUSR1 systemd-journald',
                nature="improvement",
            )

        # SystemMaxUse / SystemKeepFree — INFO only
        if not snapshot.journald_max_use.strip() and not snapshot.journald_keep_free.strip():
            result.info(
                message=_t("log_rotation.journald_no_limit"),
                detail=_t("log_rotation.journald_no_limit_detail"),
                cmd=f"sudo nano /etc/systemd/journald.conf  # {_t('log_rotation.cmd_comment_maxuse')}",
                cmd_type="fix",
                key="log_rotation.journald_no_limit",
            )
        else:
            parts: list[str] = []
            if snapshot.journald_max_use:
                parts.append(f"SystemMaxUse={snapshot.journald_max_use}")
            if snapshot.journald_keep_free:
                parts.append(f"SystemKeepFree={snapshot.journald_keep_free}")
            result.ok(
                message=_t(
                    "log_rotation.journald_limit_ok",
                    settings=", ".join(parts),
                ),
                key="log_rotation.journald_limit_ok",
            )

    # ------------------------------------------------------------------ #
    # 3. Remote syslog — INFO only                                         #
    # ------------------------------------------------------------------ #
    if snapshot.syslog_daemon:
        if snapshot.remote_syslog_configured:
            result.ok(
                message=_t(
                    "log_rotation.remote_syslog_ok",
                    daemon=snapshot.syslog_daemon,
                ),
                key="log_rotation.remote_syslog_ok",
            )
        else:
            result.info(
                message=_t(
                    "log_rotation.remote_syslog_none",
                    daemon=snapshot.syslog_daemon,
                ),
                detail=_t("log_rotation.remote_syslog_none_detail"),
                key="log_rotation.remote_syslog_none",
            )

    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _count_logrotate_rules() -> int:
    """Return the number of non-hidden regular files in /etc/logrotate.d/."""
    try:
        return sum(
            1 for p in _LOGROTATE_D.iterdir()
            if p.is_file() and not p.name.startswith(".")
        )
    except OSError:
        return 0


def _service_active(name: str) -> bool:
    """Return True if the systemd unit is in the 'active' state."""
    return is_unit_active(name, timeout=5)


def _read_journald_conf() -> tuple[str, str, str]:
    """
    Parse journald.conf (and drop-ins) for Storage=, SystemMaxUse=,
    SystemKeepFree=.  Returns (storage, max_use, keep_free) as raw strings.
    """
    storage   = ""
    max_use   = ""
    keep_free = ""

    def _parse(text: str) -> None:
        nonlocal storage, max_use, keep_free
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip()
            if key == "Storage" and val:
                storage = val
            elif key == "SystemMaxUse" and val:
                max_use = val
            elif key == "SystemKeepFree" and val:
                keep_free = val

    readable = True
    for conf in [_JOURNALD_CONF]:
        try:
            _parse(conf.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            if conf.exists():
                readable = False

    # Drop-ins override the base file
    try:
        for drop in sorted(_JOURNALD_CONF_D.glob("*.conf")):
            try:
                _parse(drop.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                pass
    except OSError:
        pass

    return storage, max_use, keep_free, readable


def _detect_remote_syslog() -> tuple[str, bool]:
    """
    Return (daemon_name, has_remote_target).

    Checks rsyslog first, then syslog-ng.  Returns ('', False) if neither
    is installed.
    """
    # rsyslog
    if _command_exists("rsyslogd"):
        texts: list[str] = []
        for p in [_RSYSLOG_CONF]:
            try:
                texts.append(p.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                pass
        try:
            for drop in sorted(_RSYSLOG_CONF_D.glob("*.conf")):
                try:
                    texts.append(drop.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    pass
        except OSError:
            pass
        combined = "\n".join(texts)
        has_remote = bool(_RSYSLOG_REMOTE_RE.search(combined))
        return "rsyslog", has_remote

    # syslog-ng
    if _command_exists("syslog-ng"):
        try:
            text = _SYSLOG_NG_CONF.read_text(encoding="utf-8", errors="replace")
            has_remote = bool(_SYSLOGNG_REMOTE_RE.search(text))
        except OSError:
            has_remote = False
        return "syslog-ng", has_remote

    return "", False
