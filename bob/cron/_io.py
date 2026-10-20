"""File-patching helpers for cron entries (atomic writes + in-place patches).

Extracted from bob/cron.py in v0.6.0 (#14 split). All file mutations here go
through ``_atomic_write`` to guarantee crash-safety — power loss between
truncate and write would leave cron files empty and silently drop entries
(see v0.5.7 #I-3 for the apply_cron_schedule fix that closed this).

v0.6.1: ``_atomic_write`` is now a thin alias for ``bob._atomic.atomic_write``
(single source of truth across the codebase). The local name is preserved as
a backwards-compat alias because ``tests/test_cron.py::TestApplyCronScheduleAtomic``
patches ``bob.cron._io._atomic_write`` directly.
"""

from __future__ import annotations

import re
import shlex
from datetime import datetime
from pathlib import Path

from bob._atomic import atomic_write as _atomic_write

def _needs_pythonpath() -> bool:
    """Whether the generated script must put the package on PYTHONPATH.

    Answered by asking a clean interpreter — no PYTHONPATH, no inherited
    environment — whether it can import ``bob`` on its own, which is the
    question cron will face. A pip or distro install says yes and needs no
    injection; a checkout run in place says no and does.

    Fails safe: if the probe cannot run at all, the line is emitted, because a
    cron that cannot import BOB does nothing and says nothing.
    """
    import os
    import subprocess
    import sys

    # Same interpreter, same user, no PYTHONPATH, cwd outside the checkout —
    # which is what cron will face, since --install-cron runs under sudo and
    # the generated entry runs as root too. Deliberately NOT setting
    # PYTHONNOUSERSITE: cron's python reads the user site of the account it
    # runs as, so suppressing it here would make the probe stricter than
    # reality and keep emitting a line that is not needed.
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    try:
        return subprocess.run(
            [sys.executable, "-c", "import bob"],
            cwd="/", env=env, capture_output=True, timeout=30,
        ).returncode != 0
    except (OSError, subprocess.SubprocessError):
        return True


def _audit_suffix(audit_options: str) -> str:
    """Validate wizard-chosen audit options and render them as a suffix."""
    if not audit_options:
        return ""
    from ._options import _OPTIONS_RE
    if not _OPTIONS_RE.match(audit_options):
        raise ValueError(f"refusing to write malformed audit options: {audit_options!r}")
    return f" {audit_options}"


def resolve_audit_binary() -> "tuple[str, bool]":
    """The ``bob`` the scheduled script will run, and whether it exists.

    v0.25.1. The script used ``shutil.which("bob") or "/usr/local/bin/bob"``
    without checking the fallback: an operator who installed the job by the
    full path (``sudo ~/.local/bin/bob --install-cron``, before
    ``--install-completion`` created the link) got a script calling a file
    that did not exist, and every run failed. The program actually running
    comes first: it is the version that writes the script's options, and
    another ``bob`` on root's PATH (a distribution package, an older install)
    may not know them. Then ``which``, then the assumed path — and the caller
    is told when the result does not exist so it can say so.
    """
    import shutil
    import sys
    if sys.argv and sys.argv[0]:
        running = Path(sys.argv[0])
        if running.name == "bob" and running.exists():
            return str(running.absolute()), True
    found = shutil.which("bob")
    if found:
        return found, True
    fallback = Path("/usr/local/bin/bob")
    return str(fallback), fallback.exists()


def build_script_content(notify_email: str, log_dir: "Path | str",
                         audit_options: str = "") -> str:
    """Build the shell script for a BOB cron job.

    v0.26.0 — POSIX ``sh``, its own PATH. It was ``#!/bin/bash`` with ``read
    -ra``, ``<<<`` and arrays: Alpine ships no bash, so a job in root's
    crontab there would have failed on every run. BusyBox crond also sets no
    PATH of its own (the cron.d file did, as an environment line).

    Args:
        notify_email:  Comma-separated notification addresses ("" for none).
        log_dir:       Where the audit writes its ``.log`` (the mail body).
        audit_options: Extra audit flags chosen in the wizard, as produced by
            ``bob.cron._options.build_audit_options``. Empty (the default)
            reproduces the pre-v0.16.1 command line, which is what every
            already-installed script carries.
    """
    audit_bin, _ = resolve_audit_binary()
    now_str   = datetime.now().strftime("%Y-%m-%d")
    try:
        # __file__ resolves to bob/cron/_io.py post-v0.6.0 split → parents[2]
        # walks up two levels (cron/ then bob/) and parent.parent gives the
        # bob package's parent dir (PYTHONPATH-able).
        bob_path = str(Path(__file__).parent.parent.parent)
    except (TypeError, AttributeError):
        bob_path = "/usr/local/lib"
    return (
        "#!/bin/sh\n"
        f"# BOB script — generated {now_str} by bob --install-cron\n"
        "# Re-generate: sudo bob --install-cron\n\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
        "export PATH\n"
        f"NOTIFY_EMAILS={shlex.quote(notify_email)}\n"
        f"LOG_DIR={shlex.quote(str(log_dir))}\n"
        # M-3 (v0.7.4): use ``${PYTHONPATH:+:$PYTHONPATH}`` to avoid a
        # trailing colon when PYTHONPATH is unset (the default under cron).
        # A trailing colon makes Python treat the CWD as a search path —
        # a long-standing footgun that BOB previously generated by default.
        #
        # v0.16.2: emitted only when the package cannot be imported without it.
        # The line exists for installs outside pip, where `bob` lives somewhere
        # `sys.path` does not reach. On a normal install it did something else:
        # `--install-cron` run from a git checkout wrote that checkout onto
        # PYTHONPATH, so the nightly audit executed the working tree rather
        # than the installed package — uncommitted edits shipping to production
        # every night, silently. See _needs_pythonpath for how this is decided.
        + (f"export PYTHONPATH={shlex.quote(bob_path)}${{PYTHONPATH:+:$PYTHONPATH}}\n\n"
           if _needs_pythonpath() else "\n")
        # --quiet and --detailed are structural, not preferences: cron has no
        # terminal, and the notification mail *is* the .log that --detailed
        # writes. The wizard's three dimensions are appended (v0.16.1); they
        # arrive pre-validated against closed sets, and are re-checked here
        # because this string lands in a root-owned script.
        + f"{shlex.quote(str(audit_bin))} --quiet --detailed{_audit_suffix(audit_options)}\n"
        "RC=$?\n\n"
        'if [ "$RC" -gt 0 ] && [ -n "$NOTIFY_EMAILS" ]; then\n'
        '    LOG=$(ls -t "$LOG_DIR"/bob_*.log 2>/dev/null | head -1)\n'
        '    if [ -n "$LOG" ]; then\n'
        '        _OLD_IFS=$IFS; IFS=,; set -f\n'
        '        for _ADDR in $NOTIFY_EMAILS; do\n'
        '            IFS=$_OLD_IFS\n'
        "            export AUDIT_LOG=\"$LOG\"\n"
        "            export AUDIT_EMAIL=\"$_ADDR\"\n"
        "            export AUDIT_RC=\"$RC\"\n"
        "            python3 << 'PYTHON_EOF'\n"
        "import os, re\n"
        "from bob.report_markdown import send_audit_log_as_html_email\n\n"
        "hostname = os.uname().nodename\n"
        "log_file = os.environ.get('AUDIT_LOG')\n"
        "email = os.environ.get('AUDIT_EMAIL')\n"
        "score = 'N/A'\n"
        "if log_file:\n"
        "    try:\n"
        "        content = open(log_file, encoding='utf-8', errors='replace').read()\n"
        # v0.16.0 — the report renders "Score     : ≤ 7/10" when a check could
        # not read its input. The previous pattern did not match that at all
        # (\\s* does not consume the ≤), so the subject silently became
        # "Score N/A" on any host with one unreadable section — which is most
        # hosts audited without full privileges. The bound is kept in the
        # subject: dropping it would put a plain number on an email whose
        # attached report says a ceiling. The prefix is captured as
        # "any non-digit, non-newline run" rather than the ≤ character, so the
        # generated cron script stays pure ASCII and carries no encoding
        # assumption of its own.
        "        m = re.search(r'Score\\s*:\\s*([^\\d\\n]*)(\\d+/10)', content)\n"
        "        if m:\n"
        "            score = m.group(1).strip() + (' ' if m.group(1).strip() else '') + m.group(2)\n"
        "    except OSError:\n"
        "        pass\n"
        "subject = f'[BOB] {hostname} - Score {score}'\n"
        "if log_file and email:\n"
        "    send_audit_log_as_html_email(log_file, email, subject)\n"
        "PYTHON_EOF\n"
        "        done\n"
        "        IFS=$_OLD_IFS; set +f\n"
        "    fi\n"
        "fi\n"
    )

# ---------------------------------------------------------------------------
# Cron-file mutation helpers — shared between the plain-text wizard
# (edit_cron_schedule / edit_cron_email in _manage.py) and the curses TUI
# (bob/tui/cron.py imports these). Centralising avoids drift between the
# two branches — see v0.4.8 cleanup pass.
# ---------------------------------------------------------------------------

def apply_cron_schedule(entry, schedule_expr: str) -> str:
    """Patch *entry.cron_path* in place with *schedule_expr*.

    Replaces the unique `MIN HOUR DOM MONTH DOW root <script>` line of the
    cron file. Returns an empty string on success, or the OSError string on
    read/write failure (caller renders it to the user).
    """
    if getattr(entry, "crontab_slug", ""):
        return _apply_crontab_schedule(entry, schedule_expr)
    try:
        text = entry.cron_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return str(exc)
    new_line = f"{schedule_expr}  root  {entry.script_path}"
    # M-10 (v0.5.5): anchor first field to cron-token shape
    # ([0-9*,\-/]) to skip comment lines that would otherwise match
    # if their text accidentally fits 5 whitespace-separated tokens
    # followed by " root ". The previous `^\S+\s+...` matched any
    # non-whitespace start including `#`.
    new_text = re.sub(
        r"^[0-9*,\-/]\S*\s+\S+\s+\S+\s+\S+\s+\S+\s+root\s+\S+.*$",
        lambda _: new_line,
        text,
        flags=re.MULTILINE,
    )
    try:
        # I-3 (v0.5.7): atomic write — power-loss between open(O_TRUNC) and
        # write would leave cron file empty and silently drop the entry.
        # Cron files in /etc/cron.d/ must be 0o640 or cron skips them.
        _atomic_write(entry.cron_path, new_text, mode=0o640)
    except OSError as exc:
        return str(exc)
    return ""

def apply_cron_email(entry, new_email: str) -> tuple[str, int]:
    """Patch *entry.cron_path* and the associated wrapper script with *new_email*.

    Accepts the legacy `NOTIFY_EMAIL=` form (no S) in the script for
    backward-compat with pre-v0.3 generated wrappers.

    Returns:
        (error_string, script_subst_count)
        - error_string is "" on success, otherwise the OSError message.
        - script_subst_count is the number of replacements done in the
          wrapper script. 0 indicates the NOTIFY_EMAILS= line was missing
          (the caller may want to warn the user).
    """
    try:
        if getattr(entry, "crontab_slug", ""):
            err = _apply_crontab_email(entry, new_email)
            if err:
                return (err, 0)
        else:
            lines = entry.cron_path.read_text(encoding="utf-8", errors="replace").splitlines()
            updated = [
                f"# email: {new_email}" if ln.startswith("# email:") else ln
                for ln in lines
            ]
            # Cron files in /etc/cron.d/ must be 0o640 (root:root) or cron skips them.
            _atomic_write(entry.cron_path, "\n".join(updated) + "\n", mode=0o640)
    except OSError as exc:
        return (str(exc), 0)

    subst_count = 0
    if entry.script_path.exists():
        try:
            text = entry.script_path.read_text(encoding="utf-8", errors="replace")
            # Match both NOTIFY_EMAILS= (current) and NOTIFY_EMAIL= (legacy)
            text, subst_count = re.subn(
                r"^NOTIFY_EMAILS?=.*$",
                lambda _: f"NOTIFY_EMAILS={shlex.quote(new_email)}",
                text,
                flags=re.MULTILINE,
            )
            # Wrapper script must be 0o755 (executable) — cron exec's it directly.
            _atomic_write(entry.script_path, text, mode=0o755)
        except OSError as exc:
            return (str(exc), subst_count)
    return ("", subst_count)


def _crontab_body(slug: str) -> "str | None":
    from bob.cron import _crontab
    return next((body for s, body in _crontab.blocks() if s == slug), None)


def _apply_crontab_schedule(entry, schedule_expr: str) -> str:
    """v0.26.0 — the schedule of a job kept in root's crontab: its block only."""
    from bob.cron import _crontab
    body = _crontab_body(entry.crontab_slug)
    if body is None:
        return f"no BOB block bob-{entry.crontab_slug} in {_crontab.ROOT_CRONTAB}"
    comments = [ln for ln in body.splitlines() if ln.startswith("#")]
    current = _crontab.parse_line(body)
    script = current[1] if current else str(entry.script_path)
    try:
        _crontab.put_block(entry.crontab_slug, _crontab.block_text(
            entry.crontab_slug, comments, schedule_expr, script))
    except OSError as exc:
        return str(exc)
    return ""


def _apply_crontab_email(entry, new_email: str) -> str:
    """v0.26.0 — the ``# email:`` line of a job kept in root's crontab."""
    from bob.cron import _crontab
    body = _crontab_body(entry.crontab_slug)
    if body is None:
        return f"no BOB block bob-{entry.crontab_slug} in {_crontab.ROOT_CRONTAB}"
    comments = [f"# email: {new_email}" if ln.startswith("# email:") else ln
                for ln in body.splitlines() if ln.startswith("#")]
    # The block's own line, not the entry's copy: a schedule changed earlier
    # in the same session must not be put back.
    current = _crontab.parse_line(body)
    schedule_expr, script = current if current else (entry.schedule_expr, str(entry.script_path))
    try:
        _crontab.put_block(entry.crontab_slug, _crontab.block_text(
            entry.crontab_slug, comments, schedule_expr, script))
    except OSError as exc:
        return str(exc)
    return ""


def use_crontab() -> bool:
    """v0.26.0 — root's crontab is where jobs go: no /etc/cron.d, a crontab dir."""
    from bob.cron import _crontab
    from bob.cron._parse import CRON_DIR
    return not CRON_DIR.is_dir() and _crontab.available()


def cron_job_location(slug: str) -> "tuple[Path, bool]":
    """Where the job *slug* lives (a cron.d file or root's crontab), and
    whether it is already there."""
    from bob.cron import _crontab
    from bob.cron._parse import CRON_DIR
    if use_crontab():
        return _crontab.ROOT_CRONTAB, _crontab.has_block(slug)
    path = CRON_DIR / f"bob-{slug}"
    return path, path.exists()


def write_cron_job(slug: str, raw_name: str, notify_email: str, schedule_expr: str,
                   script_path, now_str: str) -> Path:
    """Write the job: /etc/cron.d/bob-<slug>, or its block of root's crontab.
    Raises OSError; returns the path written."""
    from bob.cron import _crontab
    from bob.cron._parse import CRON_DIR
    # The name and the addresses land on comment lines of a root cron file —
    # of root's whole crontab on BusyBox: a newline in either would write a
    # cron line of its own. The wizards strip them already; so does this.
    raw_name = re.sub(r"[\x00-\x1f\x7f]+", " ", raw_name).strip()
    notify_email = re.sub(r"[\x00-\x1f\x7f]+", "", notify_email)
    header = [f"# BOB cron — generated {now_str} by bob --install-cron",
              f"# name: {raw_name}", f"# email: {notify_email}"]
    if use_crontab():
        _crontab.put_block(slug, _crontab.block_text(slug, header, schedule_expr, script_path))
        return _crontab.ROOT_CRONTAB
    cron_path = CRON_DIR / f"bob-{slug}"
    _atomic_write(cron_path, "\n".join(header) + "\n"
                  "SHELL=/bin/sh\n"
                  "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
                  f"{schedule_expr}  root  {script_path}\n", mode=0o640)
    return cron_path


def remove_cron_job(entry) -> None:
    """Delete the job's cron.d file or its block of root's crontab. Raises OSError."""
    from bob.cron import _crontab
    if getattr(entry, "crontab_slug", ""):
        _crontab.remove_block(entry.crontab_slug)
    else:
        entry.cron_path.unlink()
