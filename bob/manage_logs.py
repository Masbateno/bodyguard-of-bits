"""
Log management UI for BOB.

Handles the --manage-logs command: listing, deleting and relocating
saved audit report files, plus log directory configuration helpers.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import datetime as _dt
from pathlib import Path

# v0.16.3 — safe at module level: bob/tui/__init__.py is a docstring and
# _keys.py never imports curses, so a headless build stays importable.
from bob.tui import _keys
from bob.tui._palette import marked_attr
from bob._tty import read_line as _rl

logger = logging.getLogger(__name__)


def _listable(d: Path) -> bool:
    """v0.26.1 — run for another user (sudo, doas), a report directory under
    that user's home that resolves outside it is not listed, so nothing there is
    deleted or moved; the refusal is said when --manage-logs ends."""
    from bob.sysinfo import RedirectedOutOfHome, refuse_if_redirected
    try:
        refuse_if_redirected(d, os.path.realpath(d))
    except RedirectedOutOfHome:
        return False
    return True


#: v0.39.0 — files kept beside a report: its notes and its state. Never listed
#: (every list keeps ``bob_*.log``), moved and deleted with their report.
COMPANION_SUFFIXES = (".note", ".state")


def _companions(name: str) -> "tuple[str, ...]":
    return tuple(name + suffix for suffix in COMPANION_SUFFIXES)


def _move_one(name: str, sfd: int, dfd: int) -> None:
    """Move *name* from the directory *sfd* to *dfd*: a rename, or across
    filesystems a copy from a source opened without following a link, then an
    unlink."""
    import errno
    try:
        os.rename(name, name, src_dir_fd=sfd, dst_dir_fd=dfd)
        return
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
    src = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=sfd)
    try:
        dst = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC,
                      0o600, dir_fd=dfd)
        try:
            while True:
                chunk = os.read(src, 1 << 16)
                if not chunk:
                    break
                view = memoryview(chunk)
                while view:
                    view = view[os.write(dst, view):]
            os.fchmod(dst, os.fstat(src).st_mode & 0o777)
        finally:
            os.close(dst)
    finally:
        os.close(src)
    os.unlink(name, dir_fd=sfd)


def _move_report(f: Path, dest_dir: Path) -> None:
    """Move a report through checked descriptors of both directories (v0.26.1,
    after review): renamed relative to them; across filesystems, copied from a
    source opened without following a link, then unlinked. Either directory
    under the user's home resolving outside it is refused.

    v0.39.0 — its notes and its state go with it, through the same checked
    descriptors; one that is not there is skipped."""
    from bob.sysinfo import fd_real_path, refuse_if_redirected
    _dir = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    sfd = os.open(str(f.parent), _dir)
    try:
        refuse_if_redirected(f.parent, fd_real_path(sfd))
        dfd = os.open(str(dest_dir), _dir)
        try:
            refuse_if_redirected(dest_dir, fd_real_path(dfd))
            _move_one(f.name, sfd, dfd)
            for name in _companions(f.name):
                try:
                    _move_one(name, sfd, dfd)
                except FileNotFoundError:
                    pass
        finally:
            os.close(dfd)
    finally:
        os.close(sfd)


def _unlink_report(f: Path) -> None:
    """Delete a report through a checked descriptor of its directory (v0.26.1):
    the directory swapped for a link after it was listed is refused.

    v0.39.0 — its notes and its state are deleted with it."""
    from bob.sysinfo import fd_real_path, refuse_if_redirected
    dfd = os.open(str(f.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        refuse_if_redirected(f.parent, fd_real_path(dfd))
        os.unlink(f.name, dir_fd=dfd)
        for name in _companions(f.name):
            try:
                os.unlink(name, dir_fd=dfd)
            except FileNotFoundError:
                pass
    finally:
        os.close(dfd)

# ---------------------------------------------------------------------------
# Score history helpers
# ---------------------------------------------------------------------------

_SCORE_RE = re.compile(r"^Score\s*:\s*(\d+)/10", re.MULTILINE)


def _extract_score_from_log(path: Path) -> "int | None":
    """Return the security score recorded in a log file, or None if not found."""
    try:
        text = path.read_text(errors="replace")
        m = _SCORE_RE.search(text)
        if m:
            return int(m.group(1))
    except OSError:
        pass
    return None


def _parse_log_date(path: Path) -> str:
    """Extract a human-readable date from filename bob_YYYYMMDD_HHMMSS.log."""
    parts = path.stem.split("_")  # ['bob', '20260413', '170724']
    if len(parts) >= 3:
        d, h = parts[1], parts[2]
        if len(d) == 8 and len(h) == 6:
            return f"{d[:4]}-{d[4:6]}-{d[6:]} {h[:2]}:{h[2:4]}"
    return path.stem


def _build_score_history(log_files: "list[Path]") -> "list[tuple[str, int]]":
    """Return (date_str, score) pairs sorted oldest-first from the given log files."""
    history = []
    for f in sorted(log_files):  # lexicographic sort = chronological order
        score = _extract_score_from_log(f)
        if score is not None:
            history.append((_parse_log_date(f), score))
    return history


def _render_score_chart(history: "list[tuple[str, int]]", t) -> "list[str]":
    """Return lines of an ASCII bar chart of score history."""
    if not history:
        return []

    shown = history[-20:]  # at most the 20 most recent
    count = len(shown)
    label = t("manage_logs.history_title", count=count)
    sep = "─" * 50
    lines = [f"  {label}", f"  {sep}"]
    from bob.output import score_bar
    for date_str, score in shown:
        lines.append(f"  {date_str}  [{score:2}/10]  {score_bar(score)}")
    lines.append(f"  {sep}")
    return lines


# ---------------------------------------------------------------------------
# Path prompt helper
# ---------------------------------------------------------------------------

def prompt_path(prompt_label: str, default: Path, allow_cancel: bool = False) -> Path | None:
    """Prompt for a filesystem path with TAB autocompletion via readline.

    When *allow_cancel* is True, entering 'q' or 'quit' returns None so
    the caller can abort without modifying anything.
    """
    import glob as _glob

    def _path_completer(text, state):
        options = _glob.glob(text + "*")
        options = [o + "/" if os.path.isdir(o) else o for o in options]
        try:
            return options[state]
        except IndexError:
            return None

    try:
        import readline
        readline.set_completer_delims(" \t\n;")
        readline.set_completer(_path_completer)
        readline.parse_and_bind("tab: complete")
    except ImportError:
        pass

    try:
        raw = input(f"  {prompt_label} [{default}] : ").strip()
    except EOFError:
        # I-2 (v0.5.7): treat Ctrl-D as "use default" so the caller does not
        # crash with a traceback when stdin closes mid-prompt.
        raw = ""
    finally:
        try:
            import readline
            readline.set_completer(None)
        except ImportError:
            pass

    if allow_cancel and raw.lower() in ("q", "quit"):
        return None

    # resolve() normalises ".." components and follows symlinks,
    # preventing path traversal sequences in user-supplied paths.
    return _resolve_path(raw, default)


def _resolve_path(raw: str, default: Path) -> Path:
    """Expand, resolve and return *raw* as a Path, or *default* if empty."""
    return Path(raw).expanduser().resolve() if raw else default


# ---------------------------------------------------------------------------
# Log directory resolution
# ---------------------------------------------------------------------------

def get_or_prompt_log_dir(user_config, config, t) -> Path:
    """Return the configured log directory, prompting at first use.

    Priority: --output-dir CLI flag > saved config > interactive prompt.
    In non-interactive contexts (cron, pipes) the default path is used
    silently so that the process never hangs waiting for input.
    """
    from bob.sysinfo import ensure_user_dir, get_user_home

    # --output-dir takes highest priority — no prompt, no save
    if getattr(config, "output_dir", ""):
        d = Path(config.output_dir)
        try:
            ensure_user_dir(d)
        except OSError as exc:
            print(f"  ✖ {t('manage_logs.cannot_create_dir', path=d, error=exc)}")
            d = Path.cwd()
        return d

    saved = user_config.get("log_dir")
    if saved:
        d = Path(saved)
        try:
            ensure_user_dir(d)
        except OSError:
            pass
        return d

    home = get_user_home()
    default_dir = home / ".local" / "share" / "bob" / "logs"

    # Non-interactive context (cron, piped stdin) — skip the prompt
    if not sys.stdin.isatty():
        # v0.26.1 — refused under a redirected home (ensure_user_dir): the
        # report open then fails and the audit runs on without it.
        try:
            ensure_user_dir(default_dir)
            user_config.set("log_dir", str(default_dir))
        except OSError as exc:
            logger.debug("log directory %s not prepared: %s", default_dir, exc)
        return default_dir

    chosen = prompt_path(t("log_dir.prompt"), default_dir)

    try:
        ensure_user_dir(chosen)
    except OSError as exc:
        print(f"  ✖ Cannot create directory {chosen}: {exc} — falling back to cwd")
        chosen = Path.cwd()

    try:
        user_config.set("log_dir", str(chosen))
    except OSError as exc:
        # v0.26.1 — the choice is used for this run; not saved is not "saved".
        logger.debug("log_dir not saved: %s", exc)
        print()
        return chosen
    print(f"  ✔ {t('log_dir.saved', path=str(chosen))}")
    print()
    return chosen


# ---------------------------------------------------------------------------
# Extra directories helpers
# ---------------------------------------------------------------------------

def _get_extra_dirs(user_config) -> list[Path]:
    """Return the list of previous log directories tracked in user_config."""
    raw = user_config.get("log_dirs_extra")
    if not raw:
        return []
    try:
        return [Path(p) for p in json.loads(raw) if p]
    except (json.JSONDecodeError, ValueError, TypeError):
        return []


def _set_extra_dirs(user_config, dirs: list[Path]) -> None:
    user_config.set("log_dirs_extra", json.dumps([str(d) for d in dirs]))


def _add_extra_dir(user_config, path: Path) -> None:
    """Add *path* to the extras list if not already present."""
    extras = _get_extra_dirs(user_config)
    if path not in extras:
        extras.append(path)
        _set_extra_dirs(user_config, extras)


def _declared_dirs(user_config) -> list[Path]:
    """Every log directory BOB tracks: the current one first, then the
    previously-declared ones, in order, de-duplicated.

    A directory is kept here until the user explicitly forgets it — one that is
    empty, or temporarily missing (an unmounted disk), still appears, so logs
    are never silently dropped from view. This is the opposite of the old
    behaviour, which pruned any extra that was empty or gone.
    """
    dirs: list[Path] = []
    current = user_config.get("log_dir")
    if current:
        dirs.append(Path(current))
    for extra in _get_extra_dirs(user_config):
        if extra not in dirs:
            dirs.append(extra)
    return dirs


def _forget_dir(user_config, path: Path) -> None:
    """Drop *path* from the tracked extras. The current directory is never in
    the extras list, so it cannot be forgotten this way. Files are untouched."""
    extras = [d for d in _get_extra_dirs(user_config) if d != path]
    _set_extra_dirs(user_config, extras)


# ---------------------------------------------------------------------------
# Selection parser
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# --manage-logs
# ---------------------------------------------------------------------------

def _run_manage_logs_plain(user_config, config, t) -> int:
    """Text-mode fallback — used when stdout is not a TTY (tests, pipes)."""
    from bob import output
    output.init(no_color=config.no_color)

    output.print_titled_box(t("manage_logs.title"))
    print()
    # v0.40.0 — the journal of --fix --apply has its own text form.
    print(f"  ℹ {t('manage_logs.plain_fix_journal', cmd=output.command('bob --fix-journal'))}")
    print()

    log_dir_str = user_config.get("log_dir")
    if not log_dir_str:
        print(f"  ℹ {t('manage_logs.no_dir', cmd=output.command('sudo bob -d'))}")
        return 0

    while True:
        # Refresh current directory on every iteration
        log_dir_str = user_config.get("log_dir") or log_dir_str
        log_dir = Path(log_dir_str)

        if not log_dir.exists():
            from bob.sysinfo import ensure_user_dir
            try:
                ensure_user_dir(log_dir, hand_over=False)
            except OSError:
                pass  # listed as empty; refused under a redirected home (v0.26.1)

        cur_logs = sorted(log_dir.glob("bob_*.log"), reverse=True) if _listable(log_dir) else []

        # Show previous directories that still contain logs. They are kept in
        # the tracked list until the user forgets one from the wizard — an
        # empty or temporarily-missing directory is not silently pruned here.
        extra_dirs = _get_extra_dirs(user_config)
        extra_sections: list[tuple[Path, list[Path]]] = []
        for extra in extra_dirs:
            if extra == log_dir:
                continue
            if extra.exists() and _listable(extra):
                ex_logs = sorted(extra.glob("bob_*.log"), reverse=True)
                if ex_logs:
                    extra_sections.append((extra, ex_logs))

        # Flat list for unified index (current dir first, then extras in order)
        all_logs: list[Path] = list(cur_logs)
        for _, ex_logs in extra_sections:
            all_logs.extend(ex_logs)

        # ── Score history chart ───────────────────────────────────────────
        if all_logs:
            history = _build_score_history(all_logs)
            for line in _render_score_chart(history, t):
                print(line)
            print()

        # ── Display ──────────────────────────────────────────────────────
        size_label = t("manage_logs.size_label")
        current_label = t("manage_logs.current_label")
        print(f"  {t('manage_logs.stored_in', path=str(log_dir))}  ({_dir_report_label(log_dir, t)})  [{current_label}]")
        print()

        idx = 1
        if not cur_logs:
            print(f"  ℹ {t('manage_logs.no_logs', path=str(log_dir))}")
        else:
            for f in cur_logs:
                try:
                    size_kb = max(1, f.stat().st_size // 1024)
                    mtime = _dt.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                except OSError:
                    size_kb, mtime = 0, "?"
                print(f"  [{idx:2}]  {f.name}  ({size_kb} {size_label})  {mtime}")
                idx += 1

        for extra_path, ex_logs in extra_sections:
            print()
            print(f"  ─── {t('manage_logs.previous_label')}: {extra_path}  ({_dir_report_label(extra_path, t)}) ───")
            print()
            for f in ex_logs:
                try:
                    size_kb = max(1, f.stat().st_size // 1024)
                    mtime = _dt.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                except OSError:
                    size_kb, mtime = 0, "?"
                print(f"  [{idx:2}]  {f.name}  ({size_kb} {size_label})  {mtime}")
                idx += 1

        print()
        print(f"  {t('manage_logs.prompt_intro')}")
        print()
        print(f"    {'1,3':<8} {t('manage_logs.prompt_ex_single')}")
        print(f"    {'2-4':<8} {t('manage_logs.prompt_ex_range')}")
        print(f"    {'all':<8} {t('manage_logs.prompt_ex_all')}")
        print(f"    {'c':<8} {t('manage_logs.prompt_ex_change')}")
        print()
        print(f"  {t('manage_logs.prompt_quit')}")
        _raw = _rl("  > ")
        if _raw is None:
            return 0
        answer = _raw.strip().lower()

        if answer in ("", "q", "quit"):
            return 0

        elif answer in ("c", "change"):
            chosen = prompt_path(t("manage_logs.change_prompt"), log_dir, allow_cancel=True)
            if chosen is None:
                print(f"  {t('manage_logs.cancelled')}")
            else:
                try:
                    from bob.sysinfo import ensure_user_dir
                    ensure_user_dir(chosen, hand_over=False)
                except OSError as exc:
                    print(f"  ✖ Cannot create directory {chosen}: {exc}")
                    print()
                    continue
                # Register current dir as "previous" before switching
                if chosen != log_dir:
                    _add_extra_dir(user_config, log_dir)
                # Offer to move all visible reports to the new location
                if all_logs and chosen != log_dir:
                    # I-4 (v0.7.3): route through safe_input per project
                    # contract #2 — bare input() was an outlier in this
                    # module. safe_input's EOFError→"" semantic matches the
                    # v0.5.7 I-2 manual handling that previously wrapped this.
                    from bob._tty import safe_input
                    move_confirm = safe_input(
                        f"  {t('manage_logs.move_logs_prompt', count=len(all_logs))} [y/N] "
                    ).strip().lower()
                    if move_confirm == "y":
                        moved = 0
                        for f in all_logs:
                            try:
                                _move_report(f, chosen)
                                moved += 1
                            except OSError as exc:
                                print(f"  ✖ Cannot move {f.name}: {exc}")
                        print(f"  ✔ {t('manage_logs.move_logs_done', count=moved)}")
                user_config.set("log_dir", str(chosen))
                log_dir_str = str(chosen)
                print(f"  ✔ {t('manage_logs.location_updated', path=str(chosen))}")

        elif answer == "all":
            # I-4 (v0.7.3): route through safe_input per project contract #2.
            from bob._tty import safe_input
            confirm = safe_input(
                f"  {t('manage_logs.confirm_all', count=len(all_logs))} [y/N] "
            ).strip().lower()
            if confirm != "y":
                print(f"  {t('manage_logs.cancelled')}")
            else:
                deleted = 0
                for f in all_logs:
                    try:
                        _unlink_report(f)
                        deleted += 1
                    except OSError as exc:
                        print(f"  ✖ Cannot delete {f.name}: {exc}")
                print(f"  ✔ {t('manage_logs.deleted_all', count=deleted)}")

        else:
            from bob.selection import SelectionError, parse_selection
            try:
                selected = parse_selection(answer, range(1, len(all_logs) + 1))
            except SelectionError as exc:
                # v0.39.0 — said, rather than dropped: which number, which range.
                print(f"  ✖ {t('selection.' + exc.kind, **exc.vars)}")
                selected = None
            # v0.39.0 (user, 19 November 2026) — every deletion is confirmed;
            # by number it was not, only "all" was.
            if selected:
                from bob._tty import safe_input
                if safe_input(f"  {t('manage_logs.confirm_prompt', count=len(selected))} [y/N] "
                              ).strip().lower() != "y":
                    print(f"  {t('manage_logs.cancelled')}")
                    selected = None
            if selected is None:
                pass
            elif not selected:
                print(f"  ✖ {t('manage_logs.invalid')}")
            elif len(selected) == 1:
                f = all_logs[selected[0] - 1]
                try:
                    _unlink_report(f)
                    print(f"  ✔ {t('manage_logs.deleted_one', name=f.name)}")
                except OSError as exc:
                    print(f"  ✖ Cannot delete {f.name}: {exc}")
            else:
                deleted = 0
                for sel_idx in selected:
                    f = all_logs[sel_idx - 1]
                    try:
                        _unlink_report(f)
                        deleted += 1
                    except OSError as exc:
                        print(f"  ✖ Cannot delete {f.name}: {exc}")
                print(f"  ✔ {t('manage_logs.deleted_multi', count=deleted)}")

        print()


# ---------------------------------------------------------------------------
# Curses UI helpers
# ---------------------------------------------------------------------------

def _prompt_attr(curses) -> int:
    """v0.39.0 — a prompt on the context line, in the prompts' yellow."""
    from bob.tui import _chrome
    return _chrome.context_attr(curses, curses.has_colors(), _chrome.PROMPT)


def _curses_input(stdscr, row: int, w: int, prompt: str, default: str = "",
                  complete_paths: bool = True) -> str | None:
    """Inline single-line text input drawn on *row* inside a curses window.

    Tab triggers path glob-completion (unless *complete_paths* is False: a
    note is text, not a path — v0.39.0).
    Enter confirms (returns the string).
    Esc cancels (returns None).
    A line longer than the window shows its end, where the cursor is.
    """
    import curses
    import glob as _glob

    try:
        curses.curs_set(1)
    except curses.error:
        pass

    buf: list[str] = list(default)

    while True:
        text    = "".join(buf)
        display = f"  {prompt}: {text}_"
        if len(display) > w - 1:
            display = "…" + display[-(w - 2):]
        try:
            stdscr.move(row, 0)
            stdscr.clrtoeol()
            stdscr.addstr(row, 0, display[:w - 1], _prompt_attr(curses))
        except curses.error:
            pass
        stdscr.refresh()

        try:
            ch = stdscr.get_wch()
        except curses.error:
            continue

        if isinstance(ch, str):
            if ch == "\x1b":                        # Esc = cancel
                break
            elif ch in ("\r", "\n"):                # Enter = confirm
                try:
                    curses.curs_set(0)
                except curses.error:
                    pass
                return text
            elif ch in ("\x7f", "\x08"):            # Backspace
                if buf:
                    buf.pop()
            elif ch == "\t" and complete_paths:    # Tab = path completion
                matches = sorted(_glob.glob(text + "*"))
                if len(matches) == 1:
                    buf = list(matches[0])
                    if os.path.isdir(matches[0]) and not matches[0].endswith("/"):
                        buf.append("/")
                elif len(matches) > 1:
                    common = os.path.commonprefix(matches)
                    if len(common) > len(text):
                        buf = list(common)
            elif ch >= " ":                         # printable
                buf.append(ch)

        else:                                       # int — special key
            if ch == curses.KEY_BACKSPACE:
                if buf:
                    buf.pop()

    try:
        curses.curs_set(0)
    except curses.error:
        pass
    return None


def _init_colors_ml():
    """Initialise curses colour pairs for --manage-logs."""
    import curses

    # v0.16.1: the five pairs live in bob/tui/_palette.py, so --manage-logs,
    # --explain and the cron wizards cannot drift apart. Pair 4 is the one
    # screen-specific slot; here it marks files staged for deletion.
    from bob.tui._palette import init_palette

    return init_palette(curses, notice=curses.COLOR_RED)


def _is_finding_continuation(line: str) -> bool:
    """M-7 (v0.5.8): True if *line* belongs to the previous finding's body.

    Stops the over-greedy 4-space-indent grouping at any boundary that
    obviously belongs to a different finding (markers `[ALERT]`/`[WARN]`/
    `[OK]`/`[INFO]`) or a section delimiter (`┌`/`└`/`━`/`╔`/`╠`/`╚`).
    """
    if not line.startswith("    "):
        return False
    stripped = line.lstrip()
    if any(m in stripped for m in ("[ALERT]", "[WARN]", "[OK]", "[INFO]")):
        return False
    if stripped[:1] in ("┌", "└", "│", "━", "╔", "╠", "╚", "║"):
        return False
    return True


def _extract_summary_view(lines: list[str]) -> list[str]:
    """Return a condensed view: summary block + ALERT/WARN findings."""
    SEP62 = "=" * 62

    # Locate the summary block: last separator followed within 6 lines by 'Score   :'
    # M-6 (v0.5.8): sentinel None handles the (unreachable in practice) case
    # where the separator sits at line 0 — falsy 0 previously short-circuited
    # the break and could mis-detect.
    summary_start: int | None = None
    for i in range(len(lines) - 1, -1, -1):
        if lines[i].strip() == SEP62:
            for j in range(i, min(i + 8, len(lines))):
                if lines[j].startswith("Score   :") or lines[j].startswith("OK      :"):
                    summary_start = i
                    break
            if summary_start is not None:
                break

    summary_block = lines[summary_start:] if summary_start is not None else []

    # Collect ALERT and WARN findings with their continuation lines
    alert_lines: list[str] = []
    warn_lines: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if "[ALERT]" in line:
            group = [line]
            j = i + 1
            while j < len(lines) and _is_finding_continuation(lines[j]):
                group.append(lines[j])
                j += 1
            alert_lines.extend(group)
            alert_lines.append("")
            i = j
        elif "[WARN]" in line:
            group = [line]
            j = i + 1
            while j < len(lines) and _is_finding_continuation(lines[j]):
                group.append(lines[j])
                j += 1
            warn_lines.extend(group)
            warn_lines.append("")
            i = j
        else:
            i += 1

    result: list[str] = []
    if summary_block:
        result.extend(summary_block)
        result.append("")

    if alert_lines:
        result.append(f"{'─' * 20}  ALERTS  {'─' * 20}")
        result.append("")
        result.extend(alert_lines)

    if warn_lines:
        result.append(f"{'─' * 20}  WARNINGS  {'─' * 20}")
        result.append("")
        result.extend(warn_lines)

    if not alert_lines and not warn_lines:
        result.append("  ✔  No alerts or warnings.")

    return result if result else ["  (no summary data found)"]


#: The log preview is nested under the file list, so Esc goes back and ``q``
#: does not quit from here.
#:
#: v0.39.0 — the blocks shown above the report, detached from it: the notes
#: (n), the comparison with the previous report of the same host (c), the
#: history of that host's reports (h); ``a`` opens the notes' own actions, and
#: ``#`` numbers the report's lines (the whole log only: the summary's lines are
#: not consecutive, so a number there would not name a line of the file).
_BLOCK_ACTIONS = (_keys.NOTES, _keys.ANNOTATE, _keys.COMPARE, _keys.HISTORY, _keys.BREAKDOWN)
_PREVIEW_KEYS = _keys.NAVIGATION + (_keys.SUMMARY,) + _BLOCK_ACTIONS + (_keys.NUMBERS,) + _keys.NESTED_EXIT

#: Same screen once the condensed view is showing. `s` still works — it is what
#: goes back to the whole log — so hiding it would break the rule that a screen
#: never acts on a key it does not advertise. What was wrong was the label:
#: the banner read `s summary` to an operator already looking at the summary.
_PREVIEW_KEYS_SUMMARY = _keys.NAVIGATION + (_keys.FULL,) + _BLOCK_ACTIONS + _keys.NESTED_EXIT

#: v0.39.0 — the notes' actions, opened from the preview by ``a``; Esc returns
#: to the preview. Every prompt and confirmation is drawn on the context line.
_NOTES_KEYS = _keys.NAVIGATION + (
    _keys.NOTE_ADD, _keys.NOTE_EDIT, _keys.NOTE_WITHDRAW, _keys.NOTE_PURGE, _keys.NOTE_JOURNAL,
) + _keys.NESTED_EXIT


def _preview_keys(mode: str, peers: bool = False, has_notes: bool = True) -> "tuple[str, ...]":
    """The actions the preview advertises, which depend on what it is showing.

    v0.32.0 — ``peers``: the list it was opened from holds another log, so
    ←/→ reach it. Offered only then: an action with nothing to act on is noise
    on the one line an operator reads to learn the screen.
    """
    base = _PREVIEW_KEYS if mode == "full" else _PREVIEW_KEYS_SUMMARY
    # v0.39.0 — a report with no notes has no block for n to show or hide.
    if not has_notes:
        base = tuple(a for a in base if a != _keys.NOTES)
    if not peers:
        return base
    return base[:-len(_keys.NESTED_EXIT)] + (_keys.PEER,) + _keys.NESTED_EXIT


def _read_log_views(path: "Path") -> "tuple[list[str], list[str]]":
    """A log's whole text and its condensed view, as the preview shows them."""
    try:
        raw = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raw = [f"Cannot read file: {exc}"]
    return raw, _extract_summary_view(raw)


def _peer_index(peers: "list[Path]", idx: int, side: int) -> int:
    """The index ←/→ moves the preview to, in a list sorted newest first.

    ← (side -1) is the older log, the next entry down; → (+1) the newer one,
    the entry above — time runs left to right, as in the score chart. At
    either end the preview stays where it is, as ↑↓ stop at the edges.
    """
    nxt = idx - side
    return nxt if 0 <= nxt < len(peers) else idx


# ---------------------------------------------------------------------------
# v0.39.0 — the detached blocks
# ---------------------------------------------------------------------------

def _note_when(at: str, t) -> str:
    """An action's time, in the reader's local time and the locale's format."""
    try:
        return _dt.fromisoformat(at).astimezone().strftime(t("manage_logs.note_date_fmt"))
    except (TypeError, ValueError):
        return at


#: The bar in front of every line of a block, drawn in the frame's colour.
_BAR = "│ "


def _frame(title: str, body: "list[tuple[str, str]]", width: int) -> "list[tuple[str, str]]":
    """A block: a titled top rule, its lines behind a bar, a bottom rule.

    Each entry is (text, kind): kind "frame" for the rules, else the body's
    own ("body", "warn"). Long body lines are wrapped, never cut."""
    import textwrap
    w = max(20, width - 1)
    out = [("┌─ " + title + " " + "─" * max(0, w - len(title) - 4), "frame")]
    for text, kind in body:
        pieces = textwrap.wrap(text, w - 2, subsequent_indent="   ",
                               replace_whitespace=False, drop_whitespace=False) or [""]
        out.extend((_BAR + p, kind) for p in pieces)
    out.append(("└" + "─" * (w - 1), "frame"))
    return out


def _notes_body(path: "Path", t, journal_view: bool) -> "list[tuple[str, str]] | None":
    """The notes block's lines, or None when the report has no notes at all."""
    from bob import annotations as A
    j = A.load(path)
    if j.unreadable is not None:
        why = j.unreadable
        if why in A._UNREADABLE_KEYS:
            why = t(f"manage_logs.note_err.{why}")
        return [(t("manage_logs.note_unreadable", reason=why), "warn")]
    if not j.events:
        return None
    who = A.who_label
    body: "list[tuple[str, str]]" = []
    if j.foreign_owner is not None:
        body.append((t("manage_logs.note_foreign_owner", owner=j.foreign_owner), "warn"))
    elif not j.intact:
        body.append((t("manage_logs.note_tampered", line=j.broken_at), "warn"))
    for n in j.active:
        body.append((t("manage_logs.note_line", number=n.number, date=_note_when(n.created.at, t),
                       who=who(n.created.who), text=A.clean_text(n.text or "")), "body"))
        if n.edited is not None:
            body.append(("   " + t("manage_logs.note_edited", date=_note_when(n.edited.at, t),
                                    who=who(n.edited.who)), "body"))
    if not j.active:
        body.append((t("manage_logs.note_none_active"), "body"))
    withdrawn = sum(1 for n in j.notes if n.withdrawn is not None and n.purged is None)
    purged = sum(1 for n in j.notes if n.purged is not None)
    if (withdrawn or purged) and not journal_view:
        body.append((t("manage_logs.note_counts", withdrawn=withdrawn, purged=purged), "body"))
    if journal_view:
        number = {n.id: n.number for n in j.notes}
        body.append(("", "body"))
        body.append((t("manage_logs.note_journal_title"), "body"))
        for ev in j.events:
            date = _note_when(str(ev.get("at", "")), t)
            by = who(ev.get("by") if isinstance(ev.get("by"), dict) else {})
            num = number.get(ev.get("id"), "?")
            text = ev.get("text")
            text = A.clean_text(text) if isinstance(text, str) else t("manage_logs.note_text_purged")
            op = ev.get("op")
            if op == "add":
                line = t("manage_logs.note_ev_add", date=date, who=by, number=num, text=text)
            elif op == "edit":
                line = t("manage_logs.note_ev_edit", date=date, who=by, number=num, text=text)
            elif op == "withdraw":
                line = t("manage_logs.note_ev_withdraw", date=date, who=by, number=num)
            elif op == "purge":
                line = t("manage_logs.note_ev_purge", date=date, who=by, number=num,
                         reason=A.clean_text(str(ev.get("reason", ""))))
            else:
                continue
            body.append(("  " + line, "body"))
    if j.intact:
        body.append((t("manage_logs.note_intact", count=len(j.events)), "body"))
    return body


def _preview_content(path: "Path", t, view: dict, report_lines: "list[str]",
                     width: int) -> "list[tuple[str, str]]":
    """Everything the preview scrolls through: the blocks that are open, in
    the order notes, comparison, history, breakdown, then the report itself."""
    from bob import compare
    out: "list[tuple[str, str]]" = []
    if view["notes"]:
        body = _notes_body(path, t, view["journal"])
        if body is not None:
            from bob import annotations as A
            count = len(A.load(path).active)
            out += _frame(t("manage_logs.block_notes", count=count), body, width)
    if view["compare"]:
        out += _frame(t("manage_logs.block_compare"),
                      [(line, "body") for line in compare.comparison_lines(path, t)], width)
    if view["history"]:
        out += _frame(t("manage_logs.block_history"),
                      [(line, "body") for line in compare.history_lines(path, t)], width)
    if view["breakdown"]:
        # v0.40.0 (B-032) — the computation --breakdown printed for this report.
        out += _frame(t("manage_logs.block_breakdown"),
                      [(line, "body") for line in compare.breakdown_block(path, t)], width)
    if out:
        out.append(("", "report"))
    if view["numbers"] and view["mode"] == "full":
        digits = len(str(len(report_lines)))
        out += [(f"{i:>{digits}} │ {line}", "report") for i, line in enumerate(report_lines, 1)]
    else:
        out += [(line, "report") for line in report_lines]
    return out


def _new_view() -> dict:
    """What an opened preview shows (decided with the user, 17 November 2026):
    the notes open, the comparison and the history closed, no line numbers;
    the breakdown closed too (20 November 2026, B-032). ←/→ keep it as it is;
    it starts over only when the preview is opened again."""
    return {"mode": "full", "notes": True, "compare": False, "history": False,
            "breakdown": False, "numbers": False, "journal": False}


#: v0.39.0 (user, 19 November 2026: a screen announces exactly the keys it
#: answers to) — the banner under a text field. A field kept the screen's
#: banner (a e r p v, c d…), none of whose keys did anything while typing.
#: Typing and Backspace are the field itself.
_INPUT_KEYS = (_keys.SUBMIT,) + _keys.NESTED_EXIT
_PATH_INPUT_KEYS = (_keys.SUBMIT, _keys.COMPLETE) + _keys.NESTED_EXIT


def _input_banner(stdscr, t, actions) -> int:
    """Draw a text field's own banner; the row the field is typed on."""
    import curses
    from bob.tui import _chrome
    h, w = stdscr.getmaxyx()
    _chrome.draw(stdscr, curses, t, actions, curses.has_colors())
    return _chrome.context_row(t, actions, h, w)


def _context_input(stdscr, t, actions, prompt: str, default: str = "") -> "str | None":
    """A line typed on the bottom chrome's context row, over the field's own
    banner (*actions* is the screen's, kept for the callers' symmetry)."""
    row = _input_banner(stdscr, t, _INPUT_KEYS)
    return _curses_input(stdscr, row, stdscr.getmaxyx()[1], prompt, default,
                         complete_paths=False)


def _context_confirm(stdscr, t, actions, question: str) -> bool:
    """y/n on the bottom chrome's context row: y confirms, any other key
    cancels — the shared wording (:func:`bob.tui._chrome.ask_confirm`)."""
    import curses
    from bob.tui import _chrome
    return _chrome.ask_confirm(stdscr, curses, t, question)


def _note_selection(raw: str, candidates: "list[int]") -> "list[int]":
    """The notes an action is for: ``3``, ``1,3``, ``2-5``, a mix, or ``all``.

    v0.39.0 (user, 19 November 2026) — read before anything else is asked: a
    purge asked for its reason, then its confirmation, and only then said there
    was no such note. Read by the rule every selection follows
    (:mod:`bob.selection`): a range takes the notes there are between its
    bounds — "2-4" over notes 1, 2 and 4 refused, saying "no note 3", and a run
    of notes with holes had to be withdrawn piece by piece — while a number
    given alone must be a note."""
    from bob import annotations as A
    from bob.selection import SelectionError, parse_selection
    try:
        return parse_selection(raw, candidates)
    except SelectionError as exc:
        key = {"bad": "bad_selection", "missing": "no_note", "empty_range": "empty_range",
               "none": "none_left"}[exc.kind]
        raise A.NoteError(key, **exc.vars) from None


def _ask_number(stdscr, t, actions) -> "int | None":
    raw = _context_input(stdscr, t, actions, t("manage_logs.note_prompt_number"))
    if raw is None:
        return None
    raw = raw.strip()
    return int(raw) if raw.isdigit() else -1


def _notes_action(stdscr, path: "Path", t, action: str) -> str:
    """Carry out one of the notes' actions on *path*; the status line to show."""
    from bob import annotations as A
    from bob.sysinfo import RedirectedOutOfHome
    from bob.tui._chrome import done, info, refused
    keys = _NOTES_KEYS
    try:
        if action == _keys.NOTE_ADD:
            text = _context_input(stdscr, t, keys, t("manage_logs.note_prompt_add"))
            if text is None:
                return info(t("manage_logs.note_cancelled"))
            j = A.add(path, text)
            return done(t("manage_logs.note_added", number=j.notes[-1].number))
        if action in (_keys.NOTE_WITHDRAW, _keys.NOTE_PURGE):
            prompt = ("manage_logs.note_prompt_select_withdraw" if action == _keys.NOTE_WITHDRAW
                      else "manage_logs.note_prompt_select_purge")
            number = _context_input(stdscr, t, keys, t(prompt))
        else:
            number = _ask_number(stdscr, t, keys)
        if number is None:
            return info(t("manage_logs.note_cancelled"))
        if action == _keys.NOTE_EDIT:
            current = next((n for n in A.load(path).active if n.number == number), None)
            if current is None:
                raise A.NoteError("no_note", number=number)
            text = _context_input(stdscr, t, keys, t("manage_logs.note_prompt_edit", number=number),
                                  default=current.text or "")
            if text is None:
                return info(t("manage_logs.note_cancelled"))
            A.edit(path, number, text)
            return done(t("manage_logs.note_edited_ok", number=number))
        if action == _keys.NOTE_WITHDRAW:
            chosen = _note_selection(number, [n.number for n in A.load(path).active])
            listed = ", ".join(map(str, chosen))
            question = (t("manage_logs.note_confirm_withdraw", number=chosen[0]) if len(chosen) == 1 else
                        t("manage_logs.note_confirm_withdraw_many", count=len(chosen), numbers=listed))
            if not _context_confirm(stdscr, t, keys, question):
                return info(t("manage_logs.note_cancelled"))
            A.withdraw_many(path, chosen)
            return done(t("manage_logs.note_withdrawn_ok", number=chosen[0]) if len(chosen) == 1 else
                        t("manage_logs.note_withdrawn_many", count=len(chosen), numbers=listed))
        if action == _keys.NOTE_PURGE:
            chosen = _note_selection(number, [n.number for n in A.load(path).notes if n.purged is None])
            listed = ", ".join(map(str, chosen))
            reason = _context_input(stdscr, t, keys, t("manage_logs.note_prompt_reason"))
            if reason is None:
                return info(t("manage_logs.note_cancelled"))
            if not A.clean_text(reason):
                raise A.NoteError("no_reason")
            question = (t("manage_logs.note_confirm_purge", number=chosen[0]) if len(chosen) == 1 else
                        t("manage_logs.note_confirm_purge_many", count=len(chosen), numbers=listed))
            if not _context_confirm(stdscr, t, keys, question):
                return info(t("manage_logs.note_cancelled"))
            A.purge_many(path, chosen, reason)
            return done(t("manage_logs.note_purged_ok", number=chosen[0]) if len(chosen) == 1 else
                        t("manage_logs.note_purged_many", count=len(chosen), numbers=listed))
    except A.NoteError as exc:
        return refused(t(f"manage_logs.note_err.{exc.key}", **exc.vars))
    except RedirectedOutOfHome:
        return refused(t("manage_logs.note_err.redirected"))
    except OSError as exc:
        return refused(t("manage_logs.note_err.os", error=exc.strerror or exc))
    return ""


def _draw_preview(stdscr, path: "Path", t, view: dict, content, scroll: int, body_h: int,
                  actions, banner: str, status: str, has_color: bool) -> None:
    import curses
    from bob.tui import _chrome
    from bob.tui._palette import ACCENT, NOTICE
    h, w = stdscr.getmaxyx()
    stdscr.erase()
    _chrome.draw_header(stdscr, curses, banner, has_color)
    attrs = {"frame": (curses.color_pair(ACCENT) | curses.A_BOLD) if has_color else curses.A_BOLD,
             "warn": curses.color_pair(NOTICE) if has_color else curses.A_BOLD,
             "body": curses.A_NORMAL, "report": curses.A_NORMAL}
    for row in range(body_h):
        i = scroll + row
        if i >= len(content):
            break
        text, kind = content[i]
        try:
            # v0.39.0 (user, 19 November 2026) — a block's bar keeps the frame's
            # colour; it took the colour of each line's text ("body", "warn").
            if kind in ("body", "warn") and text.startswith(_BAR):
                stdscr.addstr(row + 1, 0, _BAR[:w - 1], attrs["frame"])
                stdscr.addstr(row + 1, len(_BAR), text[len(_BAR):][:max(0, w - 1 - len(_BAR))],
                              attrs[kind])
            else:
                stdscr.addstr(row + 1, 0, text[:w - 1], attrs.get(kind, curses.A_NORMAL))
        except curses.error:
            pass
    _chrome.draw(stdscr, curses, t, actions, has_color, context=status)
    stdscr.refresh()


def _curses_preview_log(stdscr, path: "Path", t, peers: "list[Path] | None" = None) -> "Path":
    """Scrollable read-only viewer for a log file.  Esc returns to list.

    v0.32.0 — *peers* is the list the preview was opened from, newest first:
    ←/→ show the older/newer log without going back to it, keeping the full or
    summary view. Returns the log shown last, so the list can put its cursor
    on it.

    v0.39.0 — blocks detached from the report above it (notes, comparison,
    history), each opened or closed by its key and kept as it is across ←/→;
    ``a`` opens the notes' actions; ``#`` numbers the lines of the whole log.
    """
    import curses

    peers = list(peers) if peers and path in peers else [path]
    idx = peers.index(path)
    full_lines, summary_lines = _read_log_views(path)

    has_color = curses.has_colors()
    scroll = 0
    view = _new_view()
    status = ""
    notes_mode = False

    while True:
        lines = full_lines if view["mode"] == "full" else summary_lines
        from bob import annotations as A
        _actions = _NOTES_KEYS if notes_mode else _preview_keys(
            view["mode"], peers=len(peers) > 1, has_notes=bool(A.load(path).events))

        h, w = stdscr.getmaxyx()
        from bob.tui import _chrome as _ch
        body_h = max(1, h - 1 - _ch.chrome_height(t, _actions, w))
        content = _preview_content(path, t, view, lines, w)
        max_scroll = max(0, len(content) - body_h)
        scroll = max(0, min(scroll, max_scroll))

        # Top banner — v0.16.3: title and context only; the keys moved to the
        # footer, where every other screen puts them. The mode tag and the line
        # range were English literals on a screen whose body is translated.
        mode_tag = t("tui.mode_notes") if notes_mode else (
            t("tui.mode_full") if view["mode"] == "full" else t("tui.mode_summary"))
        _rng = t("tui.range", first=scroll + 1,
                 last=min(scroll + body_h, len(content)), total=len(content))
        _pos = f"{idx + 1}/{len(peers)}  " if len(peers) > 1 else ""
        banner = f"  {path.name}  {_pos}{mode_tag}   {_rng}"
        _draw_preview(stdscr, path, t, view, content, scroll, body_h, _actions, banner, status, has_color)

        ch = _keys.complete_escape(stdscr, curses, stdscr.getch())
        status = ""
        action = _keys.resolve(curses, ch, _actions)

        if notes_mode:
            if action == _keys.BACK:
                notes_mode = False
            elif action == _keys.NOTE_JOURNAL:
                view["journal"] = not view["journal"]
            elif action in (_keys.NOTE_ADD, _keys.NOTE_EDIT, _keys.NOTE_WITHDRAW, _keys.NOTE_PURGE):
                status = _notes_action(stdscr, path, t, action)
            elif action == _keys.MOVE:
                scroll = max(0, min(max_scroll, scroll + _keys.direction(curses, ch)))
            elif action == _keys.PAGE:
                scroll = max(0, min(max_scroll, scroll + body_h * _keys.direction(curses, ch)))
            elif action == _keys.EDGE:
                scroll = 0 if _keys.is_top(ch) else max_scroll
            continue

        if action == _keys.BACK:                        # nested screen: Esc goes back
            return path
        elif action == _keys.PEER:                      # ← older / → newer log
            nxt = _peer_index(peers, idx, _keys.side(curses, ch))
            if nxt != idx:
                idx, path = nxt, peers[nxt]
                full_lines, summary_lines = _read_log_views(path)
                scroll = 0
        elif action in (_keys.SUMMARY, _keys.FULL):     # toggle summary / full
            view["mode"] = "summary" if view["mode"] == "full" else "full"
            scroll = 0
        elif action == _keys.NOTES:
            view["notes"] = not view["notes"]
        elif action == _keys.ANNOTATE:                  # the notes' actions; the block opens
            notes_mode, view["notes"] = True, True
        elif action == _keys.COMPARE:
            view["compare"] = not view["compare"]
        elif action == _keys.HISTORY:
            view["history"] = not view["history"]
        elif action == _keys.BREAKDOWN:
            view["breakdown"] = not view["breakdown"]
        elif action == _keys.NUMBERS:
            view["numbers"] = not view["numbers"]
        elif action == _keys.MOVE:
            scroll = max(0, min(max_scroll, scroll + _keys.direction(curses, ch)))
        elif action == _keys.PAGE:
            scroll = max(0, min(max_scroll, scroll + body_h * _keys.direction(curses, ch)))
        elif action == _keys.EDGE:
            scroll = 0 if _keys.is_top(ch) else max_scroll


#: The file list is a wizard's first page: ``q`` exits and ``l`` switches the
#: language here, and nowhere deeper. UNMARK only appears once something is
#: marked — an action with nothing to act on is noise on the one line an
#: operator reads to learn the screen.
_DIR_FOLDER = "\U0001F4C1"

#: v0.40.0 — the landing screen: two choices, the audit reports and the
#: journal of --fix --apply, kept apart (decided with the user, 20 November
#: 2026). q exits, l switches language.
_HOME_KEYS = _keys.NAVIGATION + (_keys.SELECT, _keys.pick(2)) + _keys.LANDING_EXIT

#: The directory picker, under the landing screen since v0.40.0: Esc goes back.
#: Enter browses the selected directory, c changes/adds the write directory,
#: d forgets a tracked (non-current) directory (its files are kept).
_DIR_KEYS = _keys.NAVIGATION + (
    _keys.SELECT, _keys.CHANGE, _keys.DELETE,
) + _keys.NESTED_EXIT

#: The per-directory report list is nested: Esc goes back to the picker.
_LIST_KEYS = _keys.NAVIGATION + (
    _keys.SELECT, _keys.TOGGLE, _keys.ALL, _keys.DELETE,
) + _keys.NESTED_EXIT
_MARKED_KEYS = _keys.NAVIGATION + (
    _keys.TOGGLE, _keys.DELETE, _keys.UNMARK,
) + _keys.NESTED_EXIT


#: statx(2): the mask bit for the birth time, and AT_FDCWD.
_STATX_BTIME = 0x800
_AT_FDCWD = -100


def _dir_birth_time(path: Path) -> "float | None":
    """When *path* was created, as the filesystem recorded it, or None.

    0.28.1 — Python's ``os.stat`` has no birth time on Linux, so BOB asks
    statx(2) through the C library. Measured (30 October 2026): ext4 and tmpfs
    record it (it matched ``stat -c %W``); /proc and /sys do not (0); BusyBox's
    ``stat`` does not know ``%W`` and prints "W" with exit 0, so the command is
    not used. A filesystem that does not return the birth-time bit, a C library
    without statx, or any error gives None: never the modification or change
    time in its place, which would be a creation date BOB did not measure."""
    try:
        import ctypes
        import struct
        statx = ctypes.CDLL(None, use_errno=True).statx
        buf = ctypes.create_string_buffer(256)
        if statx(_AT_FDCWD, os.fsencode(str(path)), 0, _STATX_BTIME, buf) != 0:
            return None
        if not struct.unpack_from("I", buf, 0)[0] & _STATX_BTIME:
            return None
        sec = struct.unpack_from("q", buf, 80)[0]
        return float(sec) if sec > 0 else None
    except (AttributeError, OSError, TypeError, ValueError):
        return None


def _reports_size(path: Path) -> "tuple[int, int | None] | None":
    """(number of BOB reports, their total size in bytes) in *path*.

    None when the directory cannot be listed — ``glob`` would have answered an
    empty list for a directory BOB may not read, and that would read "empty".
    The size is None when one report's size could not be read: a partial sum
    is not shown as the total."""
    try:
        names = [e for e in path.iterdir() if e.name.startswith("bob_") and e.name.endswith(".log")]
    except OSError:
        return None
    total: "int | None" = 0
    for f in names:
        try:
            total += f.stat().st_size
        except (OSError, TypeError):
            total = None
            break
    return len(names), total


def _format_size(size: int, t) -> str:
    """A report-size total in KB, or MB from 1024 KB (one decimal)."""
    kb = max(1, size // 1024) if size else 0
    if kb < 1024:
        return f"{kb} {t('manage_logs.size_label')}"
    mb = f"{size / (1024 * 1024):.1f}"
    from bob import i18n
    if i18n.current_lang() == "fr":
        mb = mb.replace(".", ",")
    return f"{mb} {t('manage_logs.size_label_mb')}"


def _dir_report_label(path: Path, t) -> str:
    """A short description of what a tracked directory holds right now: its
    reports, their total size and when the directory was created (0.28.1)."""
    if not path.exists():
        return t("manage_logs.dir_missing")
    parts = []
    found = _reports_size(path)
    if found is None:
        parts.append(t("manage_logs.dir_unreadable"))
    elif found[0] == 0:
        parts.append(t("manage_logs.dir_empty"))
    else:
        count, size = found
        parts.append(t("manage_logs.dir_reports", count=count))
        parts.append(_format_size(size, t) if size is not None else t("manage_logs.dir_size_unknown"))
    born = _dir_birth_time(path)
    if born is None:
        parts.append(t("manage_logs.dir_created_unknown"))
    else:
        from bob import i18n
        from bob._python_support import display_date
        day = _dt.fromtimestamp(born).strftime("%Y-%m-%d")
        parts.append(t("manage_logs.dir_created", date=display_date(day, i18n.current_lang())))
    return ", ".join(parts)


def _dir_picker(stdscr, user_config, config, t) -> "tuple[str, Path | None]":
    """The landing screen: one folder row per tracked log directory.

    Returns ``("select", dir)`` when the operator opens a directory, or
    ``("quit", None)``. Changing the write directory (``c``) and forgetting a
    tracked directory (``d``) are handled here and loop; language toggles here
    too, so nothing deeper redraws in another language.
    """
    import curses

    try:
        curses.curs_set(0)
    except curses.error:
        pass
    has_color = _init_colors_ml()

    cursor = 0
    scroll = 0
    status = ""

    while True:
        dirs = _declared_dirs(user_config)
        current = dirs[0] if dirs else None
        n = len(dirs)
        if n == 0:
            return ("quit", None)
        cursor = max(0, min(cursor, n - 1))

        h, w = stdscr.getmaxyx()
        from bob.tui import _chrome as _ch
        body_h = max(1, h - 1 - _ch.chrome_height(t, _DIR_KEYS, w))
        if cursor - scroll >= body_h:
            scroll = cursor - body_h + 1
        if cursor < scroll:
            scroll = cursor
        scroll = max(0, scroll)

        stdscr.erase()
        header = ("  bob --manage-logs    "
                  + t("manage_logs.dir_picker_header", count=n))
        _ch.draw_header(stdscr, curses, header, has_color)

        cur_lbl = t("manage_logs.current_label")
        for row in range(body_h):
            idx = scroll + row
            if idx >= n:
                break
            path = dirs[idx]
            tag = f"  [{cur_lbl}]" if path == current else ""
            # 0.28.1 — the current tag right after the path: the label grew
            # (size, creation date) and a long path pushed the tag off screen.
            line = f"  {_DIR_FOLDER} {path}{tag}  ({_dir_report_label(path, t)})"
            if idx == cursor:
                attr = (curses.color_pair(1) | curses.A_BOLD) if has_color else curses.A_REVERSE
                try:
                    stdscr.addstr(row + 1, 0, line[:w - 1].ljust(w - 1), attr)
                except curses.error:
                    pass
            else:
                attr = (curses.color_pair(2) | curses.A_BOLD) if has_color else curses.A_BOLD
                try:
                    stdscr.addstr(row + 1, 0, line[:w - 1], attr)
                except curses.error:
                    pass

        _transient = f"  {status}" if status else ""
        status = ""
        _ch.draw(stdscr, curses, t, _DIR_KEYS, has_color, context=_transient)
        stdscr.refresh()

        ch = _keys.complete_escape(stdscr, curses, stdscr.getch())
        act = _keys.resolve(curses, ch, _DIR_KEYS)

        if act == _keys.BACK:
            return ("quit", None)
        elif act == _keys.MOVE:
            cursor = max(0, min(n - 1, cursor + _keys.direction(curses, ch)))
        elif act == _keys.PAGE:
            cursor = max(0, min(n - 1, cursor + body_h * _keys.direction(curses, ch)))
        elif act == _keys.EDGE:
            cursor = 0 if _keys.is_top(ch) else n - 1
        elif act == _keys.SELECT:
            return ("select", dirs[cursor])
        elif act == _keys.CHANGE:
            _change_log_dir(stdscr, user_config, t, current, has_color)
            cursor = 0
        elif act == _keys.DELETE:
            chosen = dirs[cursor]
            if chosen == current:
                status = _ch.refused(t("manage_logs.forget_current_blocked"))
            elif _confirm_inline(stdscr, t, _DIR_KEYS, t("manage_logs.forget_confirm")):
                _forget_dir(user_config, chosen)
                status = _ch.done(t("manage_logs.forgot", path=str(chosen)))
                cursor = max(0, cursor - 1)


def _confirm_inline(stdscr, t, actions, prompt: str) -> bool:
    """A one-line y/n confirmation on the context line, in the prompts' colour.

    v0.39.0 — it was drawn on the bottom row, over the key banner the bottom
    chrome keeps for the keys (a prompt never covers them since 0.16.3); it
    now asks in the shared wording (:func:`bob.tui._chrome.ask_confirm`)."""
    import curses
    from bob.tui import _chrome
    return _chrome.ask_confirm(stdscr, curses, t, prompt)


def _change_log_dir(stdscr, user_config, t, log_dir, has_color) -> None:
    """Ask for a new write directory, remember the old one, optionally move
    its reports across. Shared by the picker's ``c`` action."""
    h, w = stdscr.getmaxyx()
    new_path_str = _curses_input(
        stdscr, _input_banner(stdscr, t, _PATH_INPUT_KEYS), w,
        t("manage_logs.change_prompt"),
        str(log_dir) if log_dir else "",
    )
    if new_path_str is None:
        return
    chosen = _resolve_path(new_path_str.strip(), log_dir or Path.cwd())
    try:
        from bob.sysinfo import ensure_user_dir
        ensure_user_dir(chosen, hand_over=False)
    except OSError:
        return
    if log_dir is not None and chosen != log_dir:
        cur_logs = sorted(log_dir.glob("bob_*.log")) if log_dir.exists() and _listable(log_dir) else []
        if cur_logs:
            # v0.39.0 — on the context line, in the prompts' colour: it was
            # drawn on the bottom row, over the key banner.
            move_prompt = t('manage_logs.move_logs_prompt', count=len(cur_logs))
            if _confirm_inline(stdscr, t, _DIR_KEYS, move_prompt):
                for fp in cur_logs:
                    try:
                        _move_report(fp, chosen)
                    except OSError:
                        pass
        _add_extra_dir(user_config, log_dir)
    user_config.set("log_dir", str(chosen))


def _browse_dir(stdscr, browse_dir: Path, user_config, config, t) -> None:
    """The report list of a single directory. Nested: Esc returns to the
    picker. Mark (Spc), select all (a), delete (d), and Enter previews."""
    import curses

    try:
        curses.curs_set(0)
    except curses.error:
        pass
    has_color = _init_colors_ml()
    size_label = t("manage_logs.size_label")

    cursor = 0
    scroll = 0
    marked: set[int] = set()
    status = ""
    confirm_delete = False
    pending_delete: list[int] = []

    while True:
        if browse_dir.exists() and _listable(browse_dir):
            logs = sorted(browse_dir.glob("bob_*.log"), reverse=True)
        else:
            logs = []
        marked = {m for m in marked if m < len(logs)}
        n = len(logs)

        h, w = stdscr.getmaxyx()
        from bob.tui import _chrome as _ch
        # This screen has *two* header rows — the title bar (row 0) and the dim
        # directory path (row 1) — so the body starts at row 2. Every other list
        # reserves one header row (`h - 1 - chrome`); reserving only one here
        # made body_h one larger than the rows actually drawn, and the scroll
        # math believed the last item was visible while the draw loop never
        # painted it: the bottom report sat hidden behind the footer, reachable
        # by cursor but never shown. body_h is now the true number of visible
        # body rows, so the scroll window and the draw loop agree.
        body_h = max(1, h - 2 - _ch.chrome_height(t, _MARKED_KEYS, w))
        _last = max(0, n - 1)
        cursor = max(0, min(cursor, _last))
        if cursor - scroll >= body_h:
            scroll = cursor - body_h + 1
        if cursor < scroll:
            scroll = cursor
        scroll = max(0, scroll)

        stdscr.erase()
        n_sel = len(marked)
        if confirm_delete:
            header = f"  bob --manage-logs    {t('tui.confirm_below')}"
        elif n_sel:
            header = ("  bob --manage-logs    "
                      + t("manage_logs.banner_selected", count=n_sel, total=n))
        else:
            header = ("  bob --manage-logs    "
                      + t("manage_logs.banner_total", total=n))
        _ch.draw_header(stdscr, curses, header, has_color)

        # A dim path line under the banner names the directory being browsed.
        try:
            stdscr.addstr(1, 0, f"  {t('manage_logs.stored_in', path=str(browse_dir))}"[:w - 1],
                          curses.A_DIM)
        except curses.error:
            pass

        if n == 0:
            try:
                stdscr.addstr(3, 2, t("manage_logs.no_logs", path=str(browse_dir))[:w - 3],
                              curses.A_DIM)
            except curses.error:
                pass
        else:
            for row in range(body_h):
                idx = scroll + row
                if idx >= n:
                    break
                f = logs[idx]
                try:
                    size_kb = max(1, f.stat().st_size // 1024)
                    mtime = _dt.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                except OSError:
                    size_kb, mtime = 0, "?"
                is_cursor = (idx == cursor)
                is_marked = idx in marked
                ind = ("→✓" if (is_cursor and is_marked) else
                       "→ " if is_cursor else
                       " ✓" if is_marked else
                       "  ")
                num_col = f"[{idx + 1:2}]"
                suffix = f"  {size_kb:4} {size_label}  {mtime}"
                max_name = max(8, w - 2 - len(ind) - 1 - len(num_col) - 2 - len(suffix) - 1)
                name_str = f.name[:max_name].ljust(max_name)
                line = f" {ind} {num_col}  {name_str}{suffix}"
                if is_cursor:
                    attr = (curses.color_pair(1) | curses.A_BOLD) if has_color else curses.A_REVERSE
                elif is_marked:
                    attr = marked_attr(curses, has_color)
                else:
                    attr = curses.color_pair(3) if has_color else 0
                try:
                    if is_cursor:
                        stdscr.addstr(row + 2, 0, line[:w - 1].ljust(w - 1)[:w - 1], attr)
                    else:
                        stdscr.addstr(row + 2, 0, line[:w - 1], attr)
                except curses.error:
                    pass

        _tone = None
        if confirm_delete:
            _transient = f"  {_ch.confirm_text(t, t('manage_logs.confirm_prompt', count=len(pending_delete)))}"
            _tone = _ch.PROMPT
        elif status:
            _transient = f"  {status}"
            status = ""
        else:
            _transient = ""
        _actions = _MARKED_KEYS if n_sel else _LIST_KEYS
        if confirm_delete:                  # y, or any other key to cancel
            _actions = _ch.CONFIRM_ACTIONS
        _ch.draw(stdscr, curses, t, _actions, has_color, context=_transient, tone=_tone)
        stdscr.refresh()

        ch = _keys.complete_escape(stdscr, curses, stdscr.getch())

        if confirm_delete:
            confirm_delete = False
            if ch in (ord("y"), ord("Y")):
                deleted = 0
                deleted_name = None
                deleted_before_cursor = 0
                for li in sorted(pending_delete, reverse=True):
                    try:
                        name = logs[li].name
                        _unlink_report(logs[li])
                        deleted += 1
                        if li <= cursor:
                            deleted_before_cursor += 1
                        if deleted_name is None:
                            deleted_name = name
                    except OSError:
                        pass
                marked.clear()
                cursor = max(0, cursor - deleted_before_cursor)
                if deleted == 1 and deleted_name is not None:
                    status = _ch.done(t("manage_logs.deleted_one", name=deleted_name))
                elif deleted:
                    status = _ch.done(t("manage_logs.deleted_multi", count=deleted))
            else:
                status = _ch.info(t("manage_logs.cancelled"))
            pending_delete = []
            continue

        _act = _keys.resolve(curses, ch, _MARKED_KEYS if n_sel else _LIST_KEYS)

        if _act == _keys.BACK:                      # nested screen: Esc goes back
            return
        elif _act == _keys.MOVE:
            cursor = max(0, min(_last, cursor + _keys.direction(curses, ch)))
        elif _act == _keys.PAGE:
            cursor = max(0, min(_last, cursor + body_h * _keys.direction(curses, ch)))
        elif _act == _keys.EDGE:
            cursor = 0 if _keys.is_top(ch) else _last
        elif _act == _keys.TOGGLE:
            if n:
                marked.discard(cursor) if cursor in marked else marked.add(cursor)
        elif _act == _keys.ALL:
            marked = set(range(n))
        elif _act == _keys.UNMARK:
            marked.clear()
        elif _act == _keys.DELETE:
            if n:
                pending_delete = sorted(marked) if marked else [cursor]
                if pending_delete:
                    confirm_delete = True
        elif _act == _keys.SELECT:
            if n and not n_sel:
                # v0.32.0 — the list follows the preview: ←/→ may have moved it.
                shown = _curses_preview_log(stdscr, logs[cursor], t, logs)
                cursor = logs.index(shown) if shown in logs else cursor


def _home_rows(user_config, t) -> "list[tuple[str, str]]":
    """The landing screen's two rows: the audit reports, the journal of
    --fix --apply with its verdict in its own colour."""
    from bob import fix_journal as FJ
    from bob import fix_witness as W
    n = len(_declared_dirs(user_config)) if user_config.get("log_dir") else 0
    reports = (t("manage_logs.home_reports", count=n) if n else t("manage_logs.home_no_reports"))
    journal = FJ.load()
    verdict = W.verify(journal)
    if journal.entries or verdict.removed or verdict.overall != "intact":
        state = verdict.overall
    else:
        state = "empty"
    kind = {"tampered": "alert", "unproven": "warn", "intact": "ok"}.get(state, "body")
    fixes = t("manage_logs.home_fixes", count=len(journal.entries),
              verdict=t(f"manage_logs.home_verdict.{state}"))
    return [(f"1  {_DIR_FOLDER} {reports}", "body"), (f"2  {_FIX_SHIELD} {fixes}", kind)]


#: The journal's row on the landing screen.
_FIX_SHIELD = "\U0001f6e1"


def _home(stdscr, user_config, config, t) -> str:
    """The landing screen (v0.40.0): ``reports``, ``fixes`` or ``quit``."""
    import curses
    from bob.tui import _chrome as _ch
    from bob.tui import fixlog as _fl
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    has_color = _init_colors_ml()
    cursor, status = 0, ""
    while True:
        rows = _home_rows(user_config, t)
        title = "  bob --manage-logs    " + t("manage_logs.home_header")
        body = [("", "body")] + [("  " + text, kind) for text, kind in rows]
        _fl._draw(stdscr, curses, t, title, body, _HOME_KEYS, has_color, 0, cursor + 1, status)
        status = ""
        ch = _keys.complete_escape(stdscr, curses, stdscr.getch())
        act = _keys.resolve(curses, ch, _HOME_KEYS)
        if act == _keys.QUIT:
            return "quit"
        if act == _keys.LANG:
            _keys.toggle_language(config)
        elif act in (_keys.MOVE, _keys.PAGE, _keys.EDGE):
            cursor = _fl._move(curses, act, ch, cursor, [0, 1], 2)
        elif act == _keys.SELECT or (act and act.startswith("pick:")):
            choice = cursor if act == _keys.SELECT else ch - ord("1")
            if choice == 0 and not user_config.get("log_dir"):
                status = _ch.refused(t("manage_logs.home_no_reports"))
                continue
            return "reports" if choice == 0 else "fixes"


def _run_manage_logs_curses(stdscr, user_config, config, t) -> int:
    """Curses --manage-logs: the landing screen's two choices (v0.40.0).

    The audit reports: pick a tracked directory, then browse its reports;
    tracked directories persist until the operator forgets one, so changing
    where reports are written never loses sight of the old ones. The journal
    of --fix --apply: its verdict, then day by day (bob/tui/fixlog.py).
    """
    import curses
    from bob.tui import fixlog as _fl
    while True:
        choice = _home(stdscr, user_config, config, t)
        if choice == "quit":
            return 0
        if choice == "fixes":
            _fl.run(stdscr, curses, t, _init_colors_ml())
            continue
        while True:
            action, chosen = _dir_picker(stdscr, user_config, config, t)
            if action == "quit":
                break
            if action == "select" and chosen is not None:
                _browse_dir(stdscr, chosen, user_config, config, t)


# ---------------------------------------------------------------------------
# Public entry point — dispatches to curses or plain depending on TTY
# ---------------------------------------------------------------------------

def run_manage_logs(user_config, config, t) -> int:
    """Manage audit report files; a directory refused under a redirected home
    is said when it ends (v0.26.1)."""
    try:
        return _run_manage_logs_dispatch(user_config, config, t)
    finally:
        from bob.sysinfo import say_refused_redirects
        say_refused_redirects(t, key="manage_logs.dir_redirected")


def _run_manage_logs_dispatch(user_config, config, t) -> int:
    """Manage audit report files.

    Uses a curses TUI when stdout is a TTY; falls back to the text-mode
    implementation otherwise (tests, pipes, cron).
    """
    if not sys.stdout.isatty():
        return _run_manage_logs_plain(user_config, config, t)

    # Nothing to manage yet (fresh install — no audit has created a log
    # directory, and --fix --apply never ran): route to the plain path, which
    # prints the "run an audit first" guidance, rather than a landing screen
    # with nothing behind either choice.
    from bob import fix_journal as _FJ
    if not user_config.get("log_dir") and not _FJ.path().exists():
        return _run_manage_logs_plain(user_config, config, t)

    import curses
    import os as _os
    _os.environ.setdefault("ESCDELAY", "25")
    try:
        return curses.wrapper(
            lambda scr: _run_manage_logs_curses(scr, user_config, config, t)
        )
    except (curses.error, OSError):
        return _run_manage_logs_plain(user_config, config, t)
