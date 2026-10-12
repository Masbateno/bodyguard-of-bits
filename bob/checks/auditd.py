"""
Linux Audit Framework check for BOB (CHECK 31).

Checks whether auditd is installed, its service is running, and audit rules
are configured for sensitive system files (/etc/passwd, /etc/shadow,
/etc/sudoers).  Without these rules, privilege escalation and credential
dumping go unlogged.

Score impact:
  - Not installed:                    INFO  (no deduction — optional but recommended)
  - Installed, service down:          WARN  −1 pt
  - Running but no rules at all:      WARN  −1 pt
  - Running, rules missing key files: WARN  −1 pt  (server) / INFO (desktop)
  - Running with all key files watched: OK

Split into:
  1. AuditdSnapshot.from_system() — collects state via auditctl / systemctl.
  2. check_auditd(snapshot, t)    — pure analysis, returns CheckResult.
"""

from __future__ import annotations

import gzip
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Set

from bob._atomic import read_text_capped

from bob.checks._run import (
    TranslationFunc,
    _command_exists,
    _identity_t,
    _run,
    append_once,
    install_fix,
    run_result,
    service_enable_cmd,
    unit_active_state,
)
from bob.scoring import CheckResult

# Files we consider essential to watch
_SENSITIVE_FILES = frozenset({
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
})


# auditctl's own wording for a subsystem that is switched off. Matched rather
# than rendered: stderr is untrusted subprocess text like any other.
_AUDIT_DISABLED_RE = re.compile(r"audit system is disabled", re.IGNORECASE)

#: ``auditctl -s`` reports ``enabled 0`` (off), ``1`` (on) or ``2`` (on and
#: locked until reboot — ``-e 2``).
_ENABLED_RE = re.compile(r"^enabled\s+(\d)", re.MULTILINE)
_PID_RE = re.compile(r"^pid\s+(\d+)", re.MULTILINE)


@dataclass
class AuditdSnapshot:
    """
    State collected from the system about auditd.

    Args:
        installed:        True if auditctl is present on the system.
        service_active:   True if the auditd service is running, None when
                          neither systemd nor auditctl could be asked.
        watched_files:    Set of file paths covered by -w watch rules.
        rule_count:       Total number of audit rules loaded.
        rules_readable:   False when `auditctl -l` could not be queried.
        audit_disabled:   True when auditctl says the subsystem is switched
                          off. Distinct from unreadable: the operator's own
                          choice, not a gap in what BOB could see.
    """
    installed:      bool        = False
    service_active: "bool | None" = False
    watched_files:  Set[str]    = field(default_factory=set)
    rule_count:     int         = 0
    # False when `auditctl -l` produced nothing at all, which means the
    # query failed rather than that the rule set is empty.
    rules_readable: bool        = True
    audit_disabled: bool        = False
    #: v0.24.4 — ``enabled 2``: the rules are locked until the next boot, so
    #: ``augenrules --load`` changes nothing (it says so and exits 0).
    immutable:      bool        = False

    @classmethod
    def from_system(cls) -> "AuditdSnapshot":
        """Collect auditd state from the live system. Never raises."""
        snap = cls()

        if not _command_exists("auditctl"):
            return snap

        snap.installed = True

        # Service status via systemctl, falling back to auditd's own answer
        # whenever systemd gives none — a present but failing systemctl used to
        # short-circuit straight to "inactive".
        # v0.24.4: asked through whichever init system answers (OpenRC
        # included) — gated on systemctl, an Alpine host skipped straight to
        # the fallback below, which read the locked state `enabled 2` as
        # stopped (measured: auditd running, BOB "not running", WARN -1).
        state = unit_active_state("auditd")
        status = _run("auditctl", "-s")
        enabled = _ENABLED_RE.search(status or "")
        snap.immutable = bool(enabled) and enabled.group(1) == "2"
        if state is not None:
            snap.service_active = state == "active"
        else:
            # Fallback: auditctl -s shows "enabled 1" when auditd is running.
            #
            # The fallback had the very collapse unit_active_state was written
            # to avoid, one level down: `or ""` turned "auditctl answered
            # nothing" into an absent "enabled 1", so a host where neither
            # systemd nor auditd could be asked — running without sudo is the
            # ordinary case — was reported as auditd stopped, a warning with a
            # deduction and an order to start a service already running. A
            # working `auditctl -s` always prints its status block; empty
            # output is the honest signal that no answer was obtained.
            #
            # v0.24.4: ``enabled`` is the kernel's audit state — 2 means
            # locked — not the daemon's. Measured on a Fedora 43 VM: rules
            # locked, auditd killed, ``auditctl -s`` still said "enabled 2"
            # with "pid 0". The pid is the daemon; ``enabled`` decides only
            # where an older auditctl prints no pid line.
            pid = _PID_RE.search(status or "")
            if not status:
                snap.service_active = None
            elif pid:
                snap.service_active = pid.group(1) != "0"
            else:
                snap.service_active = bool(enabled) and enabled.group(1) in ("1", "2")

        if not snap.service_active:
            return snap

        # Load rules.
        #
        # `auditctl -l` prints the literal "No rules" when the audit system is
        # reachable and holds none, so empty output means the *query* failed —
        # measured on this host, where a non-root call exits 4 with nothing on
        # stdout while auditd is running. `_run` discards the exit code, so
        # before v0.15.0 that was indistinguishable from a configured-but-empty
        # rule set and cost the host a point for rules BOB never saw.
        # `auditctl` reports a switched-off audit subsystem on stderr while
        # exiting 0 with an empty stdout, so stdout and the exit status both
        # look like a reachable system holding no rules. Only stderr separates
        # "the operator turned auditing off" from "BOB was refused" — a real
        # distinction, and the first one is not a gap in the audit at all.
        rules = run_result("auditctl", "-l")
        rules_out = rules.stdout or ""
        snap.audit_disabled = _AUDIT_DISABLED_RE.search(rules.stderr or "") is not None
        snap.rules_readable = bool(rules_out.strip()) or snap.audit_disabled
        snap.watched_files = _parse_watched_files(rules_out, _native_arch(), _compat_arch())
        snap.rule_count = _count_rules(rules_out)

        return snap


def _native_arch() -> str:
    """``b64`` on a 64-bit kernel, ``b32`` otherwise — the arch a syscall rule
    must name to see this kernel's own syscalls."""
    return "b64" if os.uname().machine in _64BIT_MACHINES else "b32"


_64BIT_MACHINES = frozenset({"x86_64", "aarch64", "ppc64", "ppc64le", "s390x",
                             "riscv64", "loongarch64", "mips64", "sparc64"})

#: The only fields a syscall rule may carry and still journal every write to
#: its path: any other ``-F`` narrows what it records. Measured on a Fedora 43
#: VM (path, perm and both arches right): ``success=0`` journalled no write,
#: ``auid>=1000 auid!=unset`` none from a system service, ``exe=`` none from
#: anything else — and BOB had called the file watched.
_NEUTRAL_FIELDS = frozenset({"arch", "path", "dir", "perm", "key"})
_FIELD_NAME = re.compile(r"-F\s+([A-Za-z0-9_]+)")

_IA32_CMDLINE = re.compile(r"(?:^|\s)ia32_emulation=(\S+)")


def _kernel_config() -> "str | None":
    """This kernel's build configuration, or None when it cannot be read."""
    try:
        return read_text_capped(Path(f"/boot/config-{os.uname().release}"), max_bytes=4 << 20)
    except (OSError, ValueError):
        pass
    try:
        with gzip.open("/proc/config.gz", "rt", errors="replace") as fh:
            return fh.read(4 << 20)
    except (OSError, EOFError):
        return None


def _compat_arch() -> "str | None":
    """``b32`` when this 64-bit kernel also runs 32-bit programs, else None.

    v0.24.4 — measured on a Fedora 43 x86_64 VM against the audit log: an
    ``arch=b64`` rule on /etc/shadow journalled a write from a 64-bit process
    and nothing for the same write from a 32-bit (i386) one. A kernel whose
    configuration cannot be read is taken to run them: not knowing is no
    proof that the 32-bit door is shut.
    """
    if _native_arch() != "b64":
        return None
    config = _kernel_config()
    if config is None:
        return "b32"
    if os.uname().machine == "x86_64":
        if not re.search(r"^CONFIG_IA32_EMULATION=y", config, re.MULTILINE):
            return None
        try:
            cmdline = read_text_capped(Path("/proc/cmdline"))
        except (OSError, ValueError):
            cmdline = ""
        m = _IA32_CMDLINE.search(cmdline)
        if m:
            return "b32" if m.group(1).lower() in ("1", "y", "yes", "on", "true") else None
        return None if re.search(r"^CONFIG_IA32_EMULATION_DEFAULT_DISABLED=y", config, re.MULTILINE) else "b32"
    return "b32" if re.search(r"^CONFIG_COMPAT=y", config, re.MULTILINE) else None


def _parse_watched_files(auditctl_output: str, native_arch: "str | None" = None,
                         compat_arch: "str | None" = None) -> Set[str]:
    """
    Extract the paths whose *writes* the loaded rules journal.

    Example input::

        -w /etc/passwd -p rwxa -k identity
        -a always,exit -F arch=b64 -S open,... -F path=/etc/shadow -F perm=wa -F key=x

    v0.24.4 — measured on Alpine (x86_64) against the audit log itself: a rule
    only counts when it journals a write. ``-w … -p r``, ``-a never,exit``, a
    ``-F arch=b32`` rule on a 64-bit kernel, and a ``-F path=`` rule with a
    hand-picked ``-S`` list and no ``perm`` each journalled nothing for a write
    to /etc/shadow — and BOB had called the file watched. *native_arch* (``b64``
    / ``b32``) rejects a syscall rule for the other architecture; None accepts
    any. A syscall rule with no ``arch`` field was resolved against the native
    table only (measured: a 32-bit write went unjournalled). When the kernel
    also runs 32-bit programs (*compat_arch*), a file covered by syscall rules
    alone needs both architectures; a ``-w`` watch covers every one.

    Returns a set of absolute paths (strings).
    """
    watched: Set[str] = set()
    arches: "dict[str, set]" = {}
    for line in auditctl_output.splitlines():
        line = line.strip()
        m = re.match(r"-w\s+(\/\S+)", line)
        if m:
            perm = re.search(r"\s-p\s+(\S+)", line)
            if perm is None or "w" in perm.group(1):  # no -p means rwxa
                watched.add(m.group(1).rstrip("/"))
        elif line.startswith(("-a ", "-A ")):
            # The syscall form of a watch, as `auditctl -l` prints it — but
            # only an `always` rule with a write permission, for this kernel's
            # architecture, journals a write (see above).
            action = line.split()[1] if len(line.split()) > 1 else ""
            if "always" not in action.split(","):
                continue
            perm = re.search(r"-F\s+perm=(\S+)", line)
            if perm is None or "w" not in perm.group(1):
                continue
            if set(_FIELD_NAME.findall(line)) - _NEUTRAL_FIELDS or re.search(r"\s-C\s", line):
                continue
            arch_m = re.search(r"-F\s+arch=(\S+)", line)
            arch = arch_m.group(1) if arch_m else native_arch
            for fm in re.finditer(r"-F\s+(?:path|dir)=(\/\S+)", line):
                arches.setdefault(fm.group(1).rstrip("/"), set()).add(arch)
    for path, seen in arches.items():
        if native_arch is None or (native_arch in seen and (compat_arch is None or compat_arch in seen)):
            watched.add(path)
    return watched


def _covered(path: str, watched: Set[str]) -> bool:
    """*path* is watched itself or sits under a watched directory — measured
    on a Pi, ``-w /etc/`` journals a write to /etc/shadow."""
    return any(path == w or path.startswith(w + "/") for w in watched)


def _count_rules(auditctl_output: str) -> int:
    """Count actual rule lines in ``auditctl -l`` output.

    Only lines starting with ``-w`` (watch rules) or ``-a``/``-A``
    (syscall rules) are counted — other lines (headers, blank, errors)
    are ignored.
    """
    count = 0
    for line in auditctl_output.splitlines():
        line = line.strip()
        if line.startswith(("-w ", "-a ", "-A ")):
            count += 1
    return count


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_auditd(snapshot: AuditdSnapshot, t: TranslationFunc | None = None,
                 profile_name: str = "server") -> CheckResult:
    """
    Analyse AuditdSnapshot and return findings.

    Findings:
      - Not installed:                   INFO  (no deduction)
      - Service not running:             WARN  −1 pt
      - Running, no rules loaded:        WARN  −1 pt (server) / INFO (desktop)
      - Running, sensitive files missing from rules:
            WARN −1 pt on server ; INFO on desktop (profile_name in desktop/workstation)
      - Running with all sensitive files watched: OK
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()
    is_desktop = profile_name.lower() in ("desktop", "workstation")

    if not snapshot.installed:
        _cmd, _detail = install_fix(
            _t, _t("auditd.not_installed_detail"), "auditd", "audit-plugins")
        result.info(
            message=_t("auditd.not_installed"),
            detail=_detail,
            cmd=_cmd,
            key="auditd.not_installed",
        )
        return result

    if snapshot.service_active is None:
        result.info(
            message=_t("auditd.state_unknown"),
            key="auditd.state_unknown",
        )
        return result

    if snapshot.service_active is False:
        result.warn_with_deduction(
            key="auditd.service_inactive",
            message=_t("auditd.service_inactive"),
            reason=_t("auditd.service_inactive_reason"),
            points=1,
            detail=_t("auditd.service_inactive_detail"),
            cmd=service_enable_cmd("auditd"),
            nature="improvement",
        )
        return result

    if snapshot.audit_disabled:
        result.info(
            message=_t("auditd.subsystem_disabled"),
            detail=_t("auditd.subsystem_disabled_detail"),
            key="auditd.subsystem_disabled",
        )
    elif not snapshot.rules_readable:
        # The query failed; the rule set is unknown, not empty. Reporting it as
        # empty cost a point for rules that were never read — and the
        # sensitive-file coverage below is derived from the same empty output,
        # so it has to stop here too rather than deduct a second point for
        # watches it could not see either.
        result.info(
            message=_t("auditd.rules_unreadable"),
            detail=_t("auditd.rules_unreadable_detail"),
            key="auditd.rules_unreadable",
        )
        return result

    # v0.24.4: `-e 2` locks the rules until the next boot. Measured on a Pi:
    # BOB's fix wrote its rules file, `augenrules --load` answered "immutable
    # mode - exiting with no changes" with exit status 0, and the finding came
    # back; after a reboot the rules were loaded. Say so, and do not hand out
    # a reload that cannot happen.
    locked = ""
    if snapshot.immutable:
        result.info(message=_t("auditd.immutable"), key="auditd.immutable")
        locked = " " + _t("auditd.locked_detail")

    if snapshot.rule_count == 0:
        _no_rules_cmd = (
            "sudo tee /etc/audit/rules.d/hardening.rules << 'EOF'\n"
            "-w /etc/passwd -p wa -k identity\n"
            "-w /etc/shadow -p wa -k identity\n"
            "-w /etc/sudoers -p wa -k privilege\n"
            "-w /etc/sudoers.d/ -p wa -k privilege\n"
            "-w /var/log/auth.log -p wa -k auth\n"
            "EOF\n"
            "sudo augenrules --load"
        )
        if snapshot.immutable:
            _no_rules_cmd = _no_rules_cmd.removesuffix("\nsudo augenrules --load")
        if is_desktop:
            result.info(
                message=_t("auditd.no_rules"),
                detail=_t("auditd.no_rules_detail") + locked,
                cmd=_no_rules_cmd,
                cmd_type="fix",
                key="auditd.no_rules",
            )
        else:
            result.warn_with_deduction(
                key="auditd.no_rules",
                message=_t("auditd.no_rules"),
                reason=_t("auditd.no_rules_reason"),
                points=1,
                detail=_t("auditd.no_rules_detail") + locked,
                cmd=_no_rules_cmd,
                nature="improvement",
            )
        return result

    # Check for sensitive file coverage
    missing = sorted(f for f in _SENSITIVE_FILES if not _covered(f, snapshot.watched_files))
    if missing:
        missing_str = ", ".join(missing)
        if is_desktop:
            result.info(
                message=_t("auditd.missing_sensitive_rules"),
                detail=_t("auditd.missing_sensitive_rules_detail", files=missing_str) + locked,
                cmd=_suggest_rules_cmd(missing, snapshot.immutable),
                key="auditd.missing_sensitive_rules",
            )
        else:
            result.warn_with_deduction(
                key="auditd.missing_sensitive_rules",
                message=_t("auditd.missing_sensitive_rules"),
                reason=_t("auditd.missing_sensitive_rules_reason", files=missing_str),
                points=1,
                detail=_t("auditd.missing_sensitive_rules_detail", files=missing_str) + locked,
                cmd=_suggest_rules_cmd(missing, snapshot.immutable),
                nature="improvement",
            )
        return result

    # All sensitive files covered
    result.ok(
        message=_t("auditd.active", count=snapshot.rule_count),
        key="auditd.active",
    )
    result.ok(
        message=_t("auditd.sensitive_files_watched"),
        key="auditd.sensitive_files_watched",
    )
    return result


def _suggest_rules_cmd(missing_files: list[str], immutable: bool = False) -> str:
    """Build a persistent audit rules command for the missing files.

    Appends rules to /etc/audit/rules.d/99-sensitive.rules (survives reboot)
    and reloads via augenrules.
    """
    rules = "/etc/audit/rules.d/99-sensitive.rules"
    # v0.17.1: guarded, because this is advice that gets followed twice. The
    # unguarded form appended a duplicate rule per run — measured on the sysctl
    # twin of this pattern: three runs, three identical lines.
    parts = [
        "{ " + append_once(f"-w {f} -p rwxa -k sensitive_files", rules) + "; }"
        for f in missing_files
    ]
    # Locked (`-e 2`): the rules file is the whole fix; it loads at boot.
    return " && ".join(parts) + ("" if immutable else " && sudo augenrules --load")
