"""
UFW log analysis check for BOB.

Parses /var/log/ufw.log for BLOCK events over a configurable period,
extracts top source IPs with geolocation, top targeted ports, bruteforce
detection, and attempts on known installed service ports.

Split into two parts:
  1. LogsSnapshot.from_system(log_days) — parses the log file.
  2. check_logs(snapshot, t)            — pure analysis, returns
                                          (CheckResult, LogReportData | None).

Usage:
    from bob.checks.logs import LogsSnapshot, check_logs

    snapshot = LogsSnapshot.from_system(log_days=7)
    result, report_data = check_logs(snapshot, audited_ports={"22/tcp"}, t=t)
"""

from __future__ import annotations

import logging
import re
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from bob.checks._run import (
    TranslationFunc,
    _C_LOCALE_ENV,
    _identity_t,
    _parse_english_month_day,
    path_exists,
)
from bob.scoring import CheckResult

logger = logging.getLogger(__name__)

UFW_LOG_PATH = Path("/var/log/ufw.log")
BRUTEFORCE_THRESHOLD = 10   # attempts from same IP on same port within window
BRUTEFORCE_WINDOW_S  = 60   # seconds
TOP_N = 10                  # number of entries in top IPs / top ports tables

# I-1 (v0.5.6): use the canonical helpers from sysinfo.py rather than a
# hand-rolled regex. The old regex missed CGNAT (100.64/10) and IPv6
# link-local (fe80::/10), and had false positives on any string starting
# with "fc" or "fd". Sysinfo's I-4 (v0.5.5) helpers are the single source
# of truth for "is this IP private/loopback/link-local?".
from bob.sysinfo import (
    _is_private_or_loopback_ipv4,
    _is_private_or_loopback_ipv6,
)


def _is_private_ip(ip: str) -> bool:
    """Return True for any private/loopback/link-local IPv4 or IPv6 address.

    Dispatches by ``:`` substring (IPv6 contains ``:``, IPv4 doesn't).
    Invalid input returns False (safe default — caller may geo-lookup
    and discover the bad IP, instead of mis-classifying it as local).
    """
    if ":" in ip:
        return _is_private_or_loopback_ipv6(ip)
    return _is_private_or_loopback_ipv4(ip)

# GeoIP2 optional import — silent fallback if not installed
try:
    import geoip2.database
    import geoip2.errors
    _GEOIP2_AVAILABLE = True
except ImportError:
    _GEOIP2_AVAILABLE = False

# Standard paths for MaxMind GeoLite2 database.
# M-3 (v0.5.6): City entries first across all dirs, then Country across all
# dirs. _geo_via_geoip2 returns on first hit, so City-before-Country wins
# the richer data when both exist in different directories.
_GEOIP2_DB_PATHS = [
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
    "/var/lib/GeoIP/GeoLite2-City.mmdb",
    "/usr/share/GeoIP/GeoLite2-Country.mmdb",
    "/var/lib/GeoIP/GeoLite2-Country.mmdb",
]

# In-memory cache — each IP resolved only once per session.
# M-5 (v0.5.6): bounded (LRU-like). Previously unbounded — fine for a CLI
# one-shot but problematic for any long-lived embedder. The cap at 2048
# entries is well above the TOP_N * unique-host realistic working set.
_GEO_CACHE_MAX = 2048
_GEO_CACHE: dict[str, str] = {}


def _geo_cache_put(key: str, value: str) -> None:
    """Insert into _GEO_CACHE with FIFO eviction at the cap."""
    if len(_GEO_CACHE) >= _GEO_CACHE_MAX:
        # FIFO eviction: drop the oldest insertion (dict preserves order
        # since Python 3.7). Cheaper than full LRU and fine for our usage.
        try:
            del _GEO_CACHE[next(iter(_GEO_CACHE))]
        except (StopIteration, KeyError):
            pass
    _GEO_CACHE[key] = value

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
        src_port:  Source port, or None when the log line carries no SPT.
                   A TCP retransmission reuses its source port, so counting
                   distinct values separates real connection attempts from one
                   client the kernel is retrying.
    """
    timestamp: datetime
    src_ip:    str
    dst_port:  int
    proto:     str
    src_port:  "int | None" = None

    @property
    def port_proto(self) -> str:
        return f"{self.dst_port}/{self.proto.lower()}"

@dataclass
class BruteforceHit:
    """Repeated blocked traffic from one source to one port.

    ``count`` is the packet count, kept for the report. ``attempts`` is the
    number of distinct connection attempts, which is what the threshold is
    tested against — see ``_detect_bruteforce``.
    """
    src_ip:    str
    dst_port:  int
    proto:     str
    count:     int
    attempts:  int = 0

    @property
    def port_proto(self) -> str:
        return f"{self.dst_port}/{self.proto.lower()}"

@dataclass(frozen=True)
class LogReportData:
    """Structured log analysis data passed from check_logs to display_log_results.

    Kept separate from CheckResult so the latter stays focused on findings and
    scoring; the display module reads these aggregations directly.
    """
    log_days:       int
    days_available: int
    total:          int
    brute_hits:     list[BruteforceHit]
    top_ips:        list[tuple[str, int]]
    top_ports:      list[tuple[str, int]]
    svc_hits:       dict[str, int]

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
        if path_exists(log_path):
            _MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
            # M-6 (v0.5.6): binary mode for the seek/tell arithmetic.
            # TextIOBase.tell() returns "an opaque number" per Python
            # docs — arithmetic on it is UB. CPython today returns
            # byte offsets for utf-8 streams (working by accident),
            # but binary mode is the documented contract. Decode the
            # tail with errors="ignore" to preserve the original
            # behaviour on encoding errors.
            try:
                with log_path.open("rb") as fh:
                    fh.seek(0, 2)
                    file_size = fh.tell()
                    fh.seek(max(file_size - _MAX_LOG_SIZE, 0))
                    content = fh.read().decode("utf-8", errors="ignore")
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
) -> "tuple[CheckResult, LogReportData | None]":
    """
    Analyse log snapshot and return findings.

    Args:
        snapshot:      LogsSnapshot from the system.
        audited_ports: Set of "port/proto" strings for installed services.
                       Used to flag attempts on known services.
        t:             Translation function.

    Returns:
        ``(result, report_data)``. ``report_data`` is ``None`` when no log file
        was found or the log is empty (the result still carries an info/ok
        finding); otherwise it carries the aggregations consumed by
        ``display_log_results``.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if not snapshot.log_found:
        result.info(message=_t("logs.no_logfile"), key="logs.no_logfile")
        return result, None

    if snapshot.log_source == "journald":
        result.info(message=_t("logs.source_journald"), key="logs.source_journald")

    if snapshot.total == 0:
        result.ok(message=_t("logs.empty"), key="logs.empty")
        return result, None

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

    report_data = LogReportData(
        log_days=snapshot.log_days,
        days_available=snapshot.days_available,
        total=snapshot.total,
        brute_hits=brute_hits,
        top_ips=top_ips,
        top_ports=top_ports,
        svc_hits=svc_hits,
    )

    # Findings — repeated blocked traffic, classified by what the evidence
    # can actually carry.
    #
    # A UFW BLOCK is a packet the firewall dropped: it never reached a service,
    # so no credential was ever offered. "Brute force" means repeated credential
    # guessing, and that conclusion is out of reach of this data by
    # construction. Two of the three cases below cannot be an authentication
    # attack at all, and both were reproduced on the bench as deductions:
    #
    #   * a private source is a device on the operator's own network — a NAS
    #     remounting a share, a phone, a printer;
    #   * UDP has no handshake and the ports that dominate these logs (1900
    #     SSDP, 5353 mDNS, 137 NetBIOS) have no credential to guess.
    #
    # Both are reported, neither is charged. What stays chargeable is repeated
    # blocked TCP connection attempts from a public address, and even that is
    # now stated as the measurement rather than named as an attack.
    for hit in brute_hits:
        if _is_private_ip(hit.src_ip):
            result.info(
                message=_t("logs.blocked_repeat_local", ip=hit.src_ip,
                           port=hit.port_proto, attempts=hit.attempts),
                key="logs.blocked_repeat_local",
            )
        elif hit.proto != "TCP":
            result.info(
                message=_t("logs.blocked_repeat_udp", ip=hit.src_ip,
                           port=hit.port_proto, attempts=hit.attempts),
                key="logs.blocked_repeat_udp",
            )
        else:
            result.warn_with_deduction(
                key="logs.brute_found",
                message=_t("logs.brute_found", ip=hit.src_ip,
                           port=hit.port_proto, attempts=hit.attempts),
                reason=_t("deduction.brute_force", ip=hit.src_ip,
                          port=hit.port_proto, attempts=hit.attempts),
                points=1,
                nature="action",
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

    return result, report_data

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
    Detect repeated blocked traffic: more than ``threshold`` distinct connection
    attempts from the same IP to the same port within any window_s window.

    **The threshold counts attempts, not packets.** It used to count packets,
    and a packet is not an attempt: with ``tcp_syn_retries`` at its default of
    6, one blocked TCP connect emits SYNs at roughly 0, 1, 3, 7, 15 and 31
    seconds, all from the same source port. Two ordinary attempts from a NAS
    remounting a share therefore produced twelve log lines in one minute and
    crossed a threshold of ten — reproduced on the bench, where a LAN device on
    445/tcp was reported as a brute-force attack worth a deducted point.

    A retransmission reuses its source port and a new attempt does not, so the
    number of distinct SPT values in the window is the number of attempts. When
    the log carries no SPT — an older UFW, or a rule logging ICMP — the packet
    count is used instead: answering "no attempts" because a field is missing
    would be the very substitution this release spent itself removing.

    Returns:
        List of BruteforceHit, sorted by count descending.
    """
    # Group by (src_ip, dst_port, proto), keeping timestamps and source ports
    groups: dict[tuple, list[tuple[datetime, "int | None"]]] = defaultdict(list)
    for entry in entries:
        key = (entry.src_ip, entry.dst_port, entry.proto)
        groups[key].append((entry.timestamp, entry.src_port))

    hits: list[BruteforceHit] = []
    for (src_ip, dst_port, proto), events in groups.items():
        events_sorted = sorted(events, key=lambda e: e[0])
        timestamps_sorted = [ts for ts, _ in events_sorted]
        # Sliding window check
        max_in_window = _max_in_window(timestamps_sorted, window_s)
        attempts = _max_attempts_in_window(events_sorted, window_s)
        if attempts > threshold:
            hits.append(BruteforceHit(
                src_ip=src_ip,
                dst_port=dst_port,
                proto=proto,
                count=max_in_window,
                attempts=attempts,
            ))

    return sorted(hits, key=lambda h: h.count, reverse=True)

def _max_attempts_in_window(
    events: list[tuple[datetime, "int | None"]], window_s: int
) -> int:
    """Largest number of distinct connection attempts in any window_s window.

    Distinct source ports, so the kernel retrying one connection counts once.
    Falls back to the packet count for a window whose lines carry no SPT.
    """
    if not events:
        return 0
    best, left = 0, 0
    for right in range(len(events)):
        while (events[right][0] - events[left][0]).total_seconds() > window_s:
            left += 1
        window = events[left:right + 1]
        ports = {p for _, p in window if p is not None}
        best = max(best, len(ports) if ports else len(window))
    return best


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
) -> tuple[str | None, int, int]:
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
        e.src_ip for e in entries if _is_private_ip(e.src_ip)
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

    # Private / loopback / link-local — no geolocation needed
    if _is_private_ip(ip):
        _geo_cache_put(cache_key, local_label)
        return local_label

    # GeoIP2 lookup
    result = ""
    if _GEOIP2_AVAILABLE:
        result = _geo_via_geoip2(ip)

    _geo_cache_put(cache_key, result)
    return result

def _geo_via_geoip2(ip: str) -> str:
    """
    Look up geolocation via GeoIP2 local database.

    Tries each known database path in order. Returns empty string
    if no database is found or the IP is not in the database.
    """
    for db_path in _GEOIP2_DB_PATHS:
        path = Path(db_path)
        if not path_exists(path):
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

    # M-4 (v0.5.6): accept symlinks — geoipupdate commonly installs the DB
    # as a symlink chain. The previous `not p.is_symlink()` check rejected
    # legitimate setups while `_geo_via_geoip2` accepts them: contradictory.
    # `resolve()` collapses symlinks safely (errors → return "no_database").
    for db_path in _GEOIP2_DB_PATHS:
        try:
            if Path(db_path).resolve(strict=True).is_file():
                return "available"
        except OSError:
            continue

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
    # M-7 (v0.5.6): TimeoutExpired is a SubprocessError subclass — redundant.
    except (OSError, subprocess.SubprocessError):
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
        # M-2 (v0.5.6): restrict to English month names to avoid counting
        # non-date leading tokens (e.g. "mai 23", "Apparmor kernel ...")
        # as a distinct "day". Mirrors _parse_english_month_day's set.
        syslog = re.match(
            r"^((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +\d+)",
            line,
        )
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
    # I-2 (v0.5.6): snapshot now once per parse to avoid year-boundary race
    # where current_year (computed earlier) and the rollback comparison
    # below could disagree on the year if the parse straddles midnight Dec 31.
    now = datetime.now()
    current_year = now.year

    # M-1 (v0.5.6): anchored prefix matcher catches both upstream variants
    # (`[UFW BLOCK]` and `[UFW BLOCK6]`) and rejects spurious substrings
    # (the previous `"[UFW BLOCK]" in line` accepted any junk containing
    # the literal substring, and missed `[UFW BLOCK6]` entirely).
    block_re = re.compile(r"\[UFW BLOCK6?\]")

    for line in content.splitlines():
        if not block_re.search(line):
            continue

        ts = _parse_timestamp(line, current_year, now)
        if ts is None:
            continue

        # Filter by cutoff
        if ts < cutoff_dt:
            continue

        src_ip   = _extract_field(line, "SRC")
        dpt      = _extract_field(line, "DPT")
        proto    = _extract_field(line, "PROTO")
        spt      = _extract_field(line, "SPT")

        if not src_ip or not dpt or not proto:
            continue

        try:
            port_num = int(dpt)
        except ValueError:
            continue

        if not (1 <= port_num <= 65535):
            continue

        # M-8 (v0.5.6): normalise proto to uppercase at parse time. UFW
        # always emits uppercase but a downstream patched build (or future
        # UFW change) emitting lowercase would split a single bruteforce
        # campaign into two sub-groups under the threshold, silencing the
        # detection. Single source of truth: parse-time normalisation.
        try:
            src_port = int(spt) if spt else None
        except ValueError:
            src_port = None

        entries.append(LogEntry(
            timestamp=ts,
            src_ip=src_ip,
            dst_port=port_num,
            proto=proto.upper(),
            src_port=src_port,
        ))

    return entries

def _parse_timestamp(
    line: str,
    current_year: int,
    now: datetime | None = None,
) -> datetime | None:
    """Extract and parse the timestamp from a log line.

    I-2 (v0.5.6): ``now`` may be passed by the caller to avoid (a) a
    re-call to ``datetime.now()`` per line, and (b) silently rolling
    back near-realtime syslog events that appear up to a few seconds
    in the future due to clock skew, log buffering, or NTP jitter.
    """
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
        # Year-boundary fix: roll back one year only if the parsed timestamp
        # is meaningfully in the future. 5-minute tolerance absorbs NTP
        # jitter, log-buffer flush delays, and clock-skew on busy systems.
        # Without the tolerance, an event timestamped 1s ahead of wall-clock
        # silently rolls back a full year and falls outside the cutoff_dt
        # filter — silent data loss.
        ref = now if now is not None else datetime.now()
        if ts > ref + timedelta(minutes=5):
            try:
                ts = ts.replace(year=ts.year - 1)
            except ValueError:
                # v0.15.3: Feb 29 rolled back into a non-leap year. This sat
                # outside the guard above, so ONE such line raised out of
                # _parse_log and the runner's section barrier degraded the
                # whole UFW log analysis — blocked-attempt statistics, top
                # source IPs, bruteforce windows — from a single line.
                #
                # Dropping the line costs nothing that would have been
                # reported. The rollback only ever steps back one year, so it
                # already assumes logs at most a year old; a Feb 29 line that
                # still looks future-dated in a leap year comes from an
                # earlier leap year (4+ years of unrotated logs) or a clock
                # behind, and any date that far back is filtered by cutoff_dt
                # immediately after. It also matches what the same line
                # already gets when the current year is not a leap year: the
                # datetime() guard above returns None.
                return None
        return ts

    return None

def _extract_field(line: str, field_name: str) -> str | None:
    """Extract a KEY=value field from a UFW log line (max 256 chars)."""
    match = re.search(rf"\b{re.escape(field_name)}=(\S{{1,256}})", line)
    return match.group(1) if match else None

