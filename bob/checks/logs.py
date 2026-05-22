"""
UFW log analysis check for BOB.

Parses /var/log/ufw.log for BLOCK events over a configurable period,
extracts top source IPs with geolocation, top targeted ports, bruteforce
detection, and attempts on known installed service ports.

Split into two parts:
  1. LogsSnapshot.from_system(log_days) — parses the log file.
  2. check_logs(snapshot, t)            — pure analysis, returns CheckResult.

Usage:
    from bob.checks.logs import LogsSnapshot, check_logs

    snapshot = LogsSnapshot.from_system(log_days=7)
    result = check_logs(snapshot, audited_ports={"22/tcp"}, t=t)
"""

from __future__ import annotations

import logging
import re
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from bob.checks._run import (
    TranslationFunc,
    _C_LOCALE_ENV,
    _identity_t,
    _parse_english_month_day,
)
from bob.scoring import CheckResult

logger = logging.getLogger(__name__)

UFW_LOG_PATH = Path("/var/log/ufw.log")
BRUTEFORCE_THRESHOLD = 10   # attempts from same IP on same port within window
BRUTEFORCE_WINDOW_S  = 60   # seconds
TOP_N = 10                  # number of entries in top IPs / top ports tables

# Private IP ranges — no geolocation needed
_PRIVATE_IP = re.compile(
    r"^(10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1$|fc|fd)"
)

# GeoIP2 optional import — silent fallback if not installed
try:
    import geoip2.database
    import geoip2.errors
    _GEOIP2_AVAILABLE = True
except ImportError:
    _GEOIP2_AVAILABLE = False

# Standard paths for MaxMind GeoLite2 database
_GEOIP2_DB_PATHS = [
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
    "/usr/share/GeoIP/GeoLite2-Country.mmdb",
    "/var/lib/GeoIP/GeoLite2-City.mmdb",
    "/var/lib/GeoIP/GeoLite2-Country.mmdb",
]

# In-memory cache — each IP resolved only once per session
_GEO_CACHE: dict[str, str] = {}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class LogEntry:
    """
    A single parsed UFW BLOCK event.

    Args:
        timestamp: Datetime of the event.
        src_ip:    Source IP address.
        dst_port:  Destination port number.
        proto:     Protocol string ("TCP" or "UDP").
    """
    timestamp: datetime
    src_ip:    str
    dst_port:  int
    proto:     str

    @property
    def port_proto(self) -> str:
        return f"{self.dst_port}/{self.proto.lower()}"


@dataclass
class BruteforceHit:
    """A detected bruteforce pattern."""
    src_ip:    str
    dst_port:  int
    proto:     str
    count:     int

    @property
    def port_proto(self) -> str:
        return f"{self.dst_port}/{self.proto.lower()}"


@dataclass
class LogsSnapshot:
    """
    Parsed UFW log data for the analysis period.

    Args:
        entries:        List of parsed BLOCK events within the period.
        days_available: Number of distinct days found in the full log file.
        log_days:       Requested analysis period in days.
        log_found:      True if a log source (file or journald) was found.
        log_source:     "file" | "journald" | "none"
    """
    entries:        list[LogEntry]
    days_available: int
    log_days:       int
    log_found:      bool = True
    log_source:     str  = "file"

    @property
    def total(self) -> int:
        return len(self.entries)

    @classmethod
    def from_system(
        cls,
        log_days: int = 7,
        log_path: Path = UFW_LOG_PATH,
    ) -> "LogsSnapshot":
        """
        Parse the UFW log file and return a snapshot for the given period.

        Args:
            log_days: Number of days to analyse (counting back from today).
            log_path: Path to the UFW log file. Override in tests.

        Returns:
            Populated LogsSnapshot. Never raises.
        """
        cutoff_dt = datetime.now() - timedelta(days=log_days)

        # --- Primary source: /var/log/ufw.log ---
        if log_path.exists():
            _MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
            try:
                with log_path.open(encoding="utf-8", errors="ignore") as fh:
                    fh.seek(0, 2)
                    file_size = fh.tell()
                    fh.seek(max(file_size - _MAX_LOG_SIZE, 0))
                    content = fh.read()
                days_available = _count_available_days(content)
                entries = _parse_log(content, cutoff_dt)
                return cls(
                    entries=entries,
                    days_available=days_available,
                    log_days=log_days,
                    log_found=True,
                    log_source="file",
                )
            except OSError as exc:
                logger.warning("Cannot read %s: %s", log_path, exc)

        # --- Fallback: journald (Debian/systemd without rsyslog) ---
        content, journald_reachable = _read_from_journald(log_days)
        if content:
            days_available = _count_available_days(content)
            entries = _parse_log(content, cutoff_dt)
            return cls(
                entries=entries,
                days_available=days_available,
                log_days=log_days,
                log_found=True,
                log_source="journald",
            )

        if journald_reachable:
            # journald works but no UFW BLOCK entries yet — not a config problem
            return cls(entries=[], days_available=0,
                       log_days=log_days, log_found=True, log_source="journald")

        return cls(entries=[], days_available=0,
                   log_days=log_days, log_found=False, log_source="none")


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_logs(
    snapshot: LogsSnapshot,
    audited_ports: set[str] | None = None,
    t: TranslationFunc | None = None,
) -> CheckResult:
    """
    Analyse log snapshot and return findings.

    Args:
        snapshot:      LogsSnapshot from the system.
        audited_ports: Set of "port/proto" strings for installed services.
                       Used to flag attempts on known services.
        t:             Translation function.

    Returns:
        CheckResult with log analysis findings.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if not snapshot.log_found:
        result.info(message=_t("logs.no_logfile"))
        return result

    if snapshot.log_source == "journald":
        result.info(message=_t("logs.source_journald"))

    if snapshot.total == 0:
        result.ok(message=_t("logs.empty"))
        return result

    # Top IPs and ports
    top_ips   = _top_sources(snapshot.entries, TOP_N)
    top_ports = _top_ports(snapshot.entries, TOP_N)

    # Bruteforce detection
    brute_hits = _detect_bruteforce(
        snapshot.entries,
        threshold=BRUTEFORCE_THRESHOLD,
        window_s=BRUTEFORCE_WINDOW_S,
    )

    # Service port hits
    svc_hits: dict[str, int] = {}
    if audited_ports:
        svc_hits = _service_hits(snapshot.entries, audited_ports)

    # Store structured data on result for the orchestrator to display
    result.log_data = {
        "total":          snapshot.total,
        "days_available": snapshot.days_available,
        "log_days":       snapshot.log_days,
        "top_ips":        top_ips,
        "top_ports":      top_ports,
        "brute_hits":     brute_hits,
        "svc_hits":       svc_hits,
    }

    # Findings — bruteforce gets a WARN
    for hit in brute_hits:
        result.warn_with_deduction(
            key="logs.brute_found",
            message=_t("logs.brute_found", ip=hit.src_ip, port=hit.port_proto),
            reason=_t("deduction.brute_force", ip=hit.src_ip, port=hit.port_proto),
            points=1,
        )

    # Service hits on high/critical ports get an INFO
    for port_proto, count in svc_hits.items():
        result.info(
            message=_t("logs.svc_hits_detail", count=count, port=port_proto),
            key="logs.svc_hits_detail",
        )

    # Dominant local source — likely IoT mDNS/SSDP/UPnP noise (benign, no deduction)
    local_ip, local_count, local_pct = _dominant_local_source(snapshot.entries)
    if local_ip is not None:
        result.info(
            message=_t(
                "logs.local_dominance",
                ip=local_ip,
                count=local_count,
                total=snapshot.total,
                pct=local_pct,
            ),
            key="logs.local_dominance",
        )

    return result


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------

def _top_sources(entries: list[LogEntry], n: int) -> list[tuple[str, int]]:
    """Return top N source IPs sorted by descending count."""
    counter = Counter(e.src_ip for e in entries)
    return counter.most_common(n)


def _top_ports(entries: list[LogEntry], n: int) -> list[tuple[str, int]]:
    """Return top N destination port/proto sorted by descending count."""
    counter = Counter(e.port_proto for e in entries)
    return counter.most_common(n)


def _detect_bruteforce(
    entries: list[LogEntry],
    threshold: int,
    window_s: int,
) -> list[BruteforceHit]:
    """
    Detect bruteforce patterns: >threshold attempts from the same IP
    on the same port within any window_s second window.

    Returns:
        List of BruteforceHit, sorted by count descending.
    """
    # Group timestamps by (src_ip, dst_port, proto)
    groups: dict[tuple, list[datetime]] = defaultdict(list)
    for entry in entries:
        key = (entry.src_ip, entry.dst_port, entry.proto)
        groups[key].append(entry.timestamp)

    hits: list[BruteforceHit] = []
    for (src_ip, dst_port, proto), timestamps in groups.items():
        timestamps_sorted = sorted(timestamps)
        # Sliding window check
        max_in_window = _max_in_window(timestamps_sorted, window_s)
        if max_in_window > threshold:
            hits.append(BruteforceHit(
                src_ip=src_ip,
                dst_port=dst_port,
                proto=proto,
                count=max_in_window,
            ))

    return sorted(hits, key=lambda h: h.count, reverse=True)


def _max_in_window(timestamps: list[datetime], window_s: int) -> int:
    """Return the maximum number of timestamps within any window_s second window."""
    if not timestamps:
        return 0
    max_count = 1
    left = 0
    for right in range(1, len(timestamps)):
        while (timestamps[right] - timestamps[left]).total_seconds() > window_s:
            left += 1
        max_count = max(max_count, right - left + 1)
    return max_count


def _service_hits(
    entries: list[LogEntry],
    audited_ports: set[str],
) -> dict[str, int]:
    """
    Count BLOCK attempts on ports belonging to installed services.

    Args:
        entries:       Parsed log entries.
        audited_ports: Set of "port/proto" strings (e.g. {"22/tcp", "6379/tcp"}).

    Returns:
        Dict mapping port/proto to attempt count, sorted by count desc.
        Only ports with count > 0 are included.
    """
    counter: Counter = Counter()
    for entry in entries:
        if entry.port_proto in audited_ports:
            counter[entry.port_proto] += 1
    return dict(counter.most_common())


_LOCAL_DOMINANCE_THRESHOLD = 0.70   # fraction of total blocks from one local IP
_LOCAL_DOMINANCE_MIN_COUNT = 50     # ignore very quiet logs (< 50 total blocks)


def _dominant_local_source(
    entries: list[LogEntry],
) -> tuple[Optional[str], int, int]:
    """
    Detect whether a single private IP dominates the block log.

    A dominant local source is almost always benign IoT traffic
    (mDNS, SSDP, UPnP discovery) rather than a real attack.

    Returns:
        (ip, count, pct_int) if a dominant local IP is found, or (None, 0, 0).
    """
    if len(entries) < _LOCAL_DOMINANCE_MIN_COUNT:
        return None, 0, 0

    local_counts: Counter = Counter(
        e.src_ip for e in entries if _PRIVATE_IP.match(e.src_ip)
    )
    if not local_counts:
        return None, 0, 0

    top_ip, top_count = local_counts.most_common(1)[0]
    pct = top_count / len(entries)
    if pct >= _LOCAL_DOMINANCE_THRESHOLD:
        return top_ip, top_count, int(pct * 100)

    return None, 0, 0


def get_ip_geo(ip: str, lang: str = "en") -> str:
    """
    Resolve geolocation for an IP address.

    Uses GeoIP2 (python3-geoip2 + GeoLite2 database) if available.
    Falls back silently to empty string if not installed.
    Private/loopback ranges return a localised "local network" string.
    Results are cached in memory — each IP resolved only once per session.

    Args:
        ip:   IP address string.
        lang: Language code ("en" or "fr").

    Returns:
        Geolocation string e.g. "FR, Orange" or "local network" or "".
    """
    # Cache hit
    cache_key = f"{ip}:{lang}"
    if cache_key in _GEO_CACHE:
        return _GEO_CACHE[cache_key]

    local_label = "réseau local" if lang == "fr" else "local network"

    # Private / loopback
    if _PRIVATE_IP.match(ip):
        _GEO_CACHE[cache_key] = local_label
        return local_label

    # GeoIP2 lookup
    result = ""
    if _GEOIP2_AVAILABLE:
        result = _geo_via_geoip2(ip)

    _GEO_CACHE[cache_key] = result
    return result


def _geo_via_geoip2(ip: str) -> str:
    """
    Look up geolocation via GeoIP2 local database.

    Tries each known database path in order. Returns empty string
    if no database is found or the IP is not in the database.
    """
    for db_path in _GEOIP2_DB_PATHS:
        path = Path(db_path)
        if not path.exists():
            continue
        try:
            with geoip2.database.Reader(str(path)) as reader:
                if "City" in db_path:
                    record = reader.city(ip)
                    country = record.country.iso_code or ""
                    city    = record.city.name or ""
                    org     = city if city else ""
                else:
                    record  = reader.country(ip)
                    country = record.country.iso_code or ""
                    org     = record.country.name or ""

                if country and org:
                    return f"{country}, {org}"
                if country:
                    return country
                return ""
        except (OSError, ValueError, KeyError, AttributeError,
                geoip2.errors.GeoIP2Error):
            continue

    return ""


def geoip2_status() -> str:
    """
    Return a human-readable status string for GeoIP2 availability.

    Used by the orchestrator to display a one-time info message.
    """
    if not _GEOIP2_AVAILABLE:
        return "unavailable"

    for db_path in _GEOIP2_DB_PATHS:
        p = Path(db_path)
        if p.exists() and not p.is_symlink():
            return "available"

    return "no_database"


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _read_from_journald(log_days: int) -> tuple[str, bool]:
    """
    Read UFW kernel log entries from systemd-journald.

    Used as a fallback when /var/log/ufw.log is absent (e.g. Debian 13 with
    journald-only logging, no rsyslog).

    Returns:
        (content, reachable) where content contains UFW BLOCK lines (may be
        empty even when reachable — e.g. fresh system with no blocked traffic),
        and reachable is True if journald responded successfully.
    """
    try:
        result = subprocess.run(
            [
                "journalctl", "-k",
                "--no-pager",
                "--output=short-iso",
                f"--since={log_days} days ago",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            env=_C_LOCALE_ENV,
        )
        if result.returncode == 0 and result.stdout.strip():
            content = result.stdout
            return (content if "[UFW " in content else ""), True
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
        pass
    return "", False


def _count_available_days(content: str) -> int:
    """Count the number of distinct calendar days in the log file."""
    dates: set[str] = set()
    for line in content.splitlines():
        # ISO format: 2026-03-19T...
        iso = re.match(r"^(\d{4}-\d{2}-\d{2})", line)
        if iso:
            dates.add(iso.group(1))
            continue
        # Syslog format: Mar 19 ...
        syslog = re.match(r"^([A-Za-z]+ +\d+)", line)
        if syslog:
            dates.add(syslog.group(1))
    return len(dates)


def _parse_log(content: str, cutoff_dt: datetime) -> list[LogEntry]:
    """
    Parse UFW BLOCK lines from log content, filtering by cutoff_dt.

    Supports:
      - ISO 8601: 2026-03-19T18:20:08.898446+01:00
      - Syslog:   Mar 19 10:23:14

    Args:
        content:   Full log file content.
        cutoff_dt: Datetime — only entries on or after this datetime are included.

    Returns:
        List of parsed LogEntry objects.
    """
    entries: list[LogEntry] = []
    current_year = datetime.now().year

    for line in content.splitlines():
        if "[UFW BLOCK]" not in line:
            continue

        ts = _parse_timestamp(line, current_year)
        if ts is None:
            continue

        # Filter by cutoff
        if ts < cutoff_dt:
            continue

        src_ip   = _extract_field(line, "SRC")
        dpt      = _extract_field(line, "DPT")
        proto    = _extract_field(line, "PROTO")

        if not src_ip or not dpt or not proto:
            continue

        try:
            port_num = int(dpt)
        except ValueError:
            continue

        if not (1 <= port_num <= 65535):
            continue

        entries.append(LogEntry(
            timestamp=ts,
            src_ip=src_ip,
            dst_port=port_num,
            proto=proto,
        ))

    return entries


def _parse_timestamp(line: str, current_year: int) -> Optional[datetime]:
    """Extract and parse the timestamp from a log line."""
    # ISO 8601: 2026-03-19T18:20:08.898+01:00
    iso_match = re.match(
        r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line
    )
    if iso_match:
        try:
            return datetime.strptime(iso_match.group(1), "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return None

    # Syslog: Mar 19 10:23:14
    syslog_match = re.match(
        r"^([A-Za-z]+ +\d+ +\d{2}:\d{2}:\d{2})", line
    )
    if syslog_match:
        # Don't use datetime.strptime("%b ...") here: it depends on the Python
        # process LC_TIME, not the subprocess env. Under fr_FR.UTF-8 "May" fails
        # to parse. _parse_english_month_day is locale-independent.
        parsed = _parse_english_month_day(syslog_match.group(1))
        if parsed is None:
            return None
        month, day, hh, mm, ss = parsed
        try:
            ts = datetime(current_year, month, day, hh, mm, ss)
        except ValueError:
            return None
        # Year-boundary fix: if the parsed timestamp is in the future
        # (e.g. a December entry parsed in January), roll back one year.
        if ts > datetime.now():
            ts = ts.replace(year=ts.year - 1)
        return ts

    return None


def _extract_field(line: str, field_name: str) -> Optional[str]:
    """Extract a KEY=value field from a UFW log line (max 256 chars)."""
    match = re.search(rf"\b{re.escape(field_name)}=(\S{{1,256}})", line)
    return match.group(1) if match else None


