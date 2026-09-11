"""
Log management UI for BOB.

Handles the --manage-logs command: listing, deleting and relocating
saved audit report files, plus log directory configuration helpers.
"""

from __future__ import annotations

import json
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
    from bob.sysinfo import chown_to_sudo_user, get_user_home

    # --output-dir takes highest priority — no prompt, no save
    if getattr(config, "output_dir", ""):
        d = Path(config.output_dir)
        try:
            d.mkdir(parents=True, exist_ok=True)
            chown_to_sudo_user(d)
        except OSError as exc:
            print(f"  ✖ Cannot create directory {d}: {exc} — falling back to cwd")
            d = Path.cwd()
        return d

    saved = user_config.get("log_dir")
    if saved:
        d = Path(saved)
        try:
            d.mkdir(parents=True, exist_ok=True)
            chown_to_sudo_user(d)
        except OSError:
            pass
        return d

    home = get_user_home()
    default_dir = home / ".local" / "share" / "bob" / "logs"

    # Non-interactive context (cron, piped stdin) — skip the prompt
    if not sys.stdin.isatty():
        default_dir.mkdir(parents=True, exist_ok=True)
        chown_to_sudo_user(default_dir)
        user_config.set("log_dir", str(default_dir))
        return default_dir

    chosen = prompt_path(t("log_dir.prompt"), default_dir)

    try:
        chosen.mkdir(parents=True, exist_ok=True)
        chown_to_sudo_user(chosen)
    except OSError as exc:
        print(f"  ✖ Cannot create directory {chosen}: {exc} — falling back to cwd")
        chosen = Path.cwd()

    user_config.set("log_dir", str(chosen))
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

def parse_log_selection(answer: str, max_idx: int) -> list[int]:
    """Parse user input into a sorted list of 1-based indices.

    Accepted formats:
        1          → [1]
        1,3,5      → [1, 3, 5]
        2-4        → [2, 3, 4]
        1,3-5      → [1, 3, 4, 5]
    """
    indices: set[int] = set()
    for part in answer.split(","):
        part = part.strip()
        if "-" in part:
            lo, _, hi = part.partition("-")
            if lo.isdigit() and hi.isdigit():
                lo_i, hi_i = int(lo), int(hi)
                if 1 <= lo_i <= hi_i <= max_idx:
                    indices.update(range(lo_i, hi_i + 1))
        elif part.isdigit():
            n = int(part)
            if 1 <= n <= max_idx:
                indices.add(n)
    return sorted(indices)


# ---------------------------------------------------------------------------
# --manage-logs
# ---------------------------------------------------------------------------

def _run_manage_logs_plain(user_config, config, t) -> int:
    """Text-mode fallback — used when stdout is not a TTY (tests, pipes)."""
    from bob import output
    output.init(no_color=config.no_color)

    output.print_titled_box(t("manage_logs.title"))
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
            log_dir.mkdir(parents=True, exist_ok=True)

        cur_logs = sorted(log_dir.glob("bob_*.log"), reverse=True)

        # Show previous directories that still contain logs. They are kept in
        # the tracked list until the user forgets one from the wizard — an
        # empty or temporarily-missing directory is not silently pruned here.
        extra_dirs = _get_extra_dirs(user_config)
        extra_sections: list[tuple[Path, list[Path]]] = []
        for extra in extra_dirs:
            if extra == log_dir:
                continue
            if extra.exists():
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
        print(f"  {t('manage_logs.stored_in', path=str(log_dir))}  [{current_label}]")
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
            print(f"  ─── {t('manage_logs.previous_label')}: {extra_path} ───")
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
                    chosen.mkdir(parents=True, exist_ok=True)
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
                        import shutil as _shutil
                        moved = 0
                        for f in all_logs:
                            try:
                                _shutil.move(str(f), str(chosen / f.name))
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
                        f.unlink()
                        deleted += 1
                    except OSError as exc:
                        print(f"  ✖ Cannot delete {f.name}: {exc}")
                print(f"  ✔ {t('manage_logs.deleted_all', count=deleted)}")

        else:
            selected = parse_log_selection(answer, len(all_logs))
            if not selected:
                print(f"  ✖ {t('manage_logs.invalid')}")
            elif len(selected) == 1:
                f = all_logs[selected[0] - 1]
                try:
                    f.unlink()
                    print(f"  ✔ {t('manage_logs.deleted_one', name=f.name)}")
                except OSError as exc:
                    print(f"  ✖ Cannot delete {f.name}: {exc}")
            else:
                deleted = 0
                for sel_idx in selected:
                    f = all_logs[sel_idx - 1]
                    try:
                        f.unlink()
                        deleted += 1
                    except OSError as exc:
                        print(f"  ✖ Cannot delete {f.name}: {exc}")
                print(f"  ✔ {t('manage_logs.deleted_multi', count=deleted)}")

        print()


# ---------------------------------------------------------------------------
# Curses UI helpers
# ---------------------------------------------------------------------------

def _curses_input(stdscr, row: int, w: int, prompt: str, default: str = "") -> str | None:
    """Inline single-line text input drawn on *row* inside a curses window.

    Tab triggers path glob-completion.
    Enter confirms (returns the string).
    Esc cancels (returns None).
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
        try:
            stdscr.move(row, 0)
            stdscr.clrtoeol()
            stdscr.addstr(row, 0, display[:w - 1], curses.A_BOLD)
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
            elif ch == "\t":                        # Tab = path completion
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
_PREVIEW_KEYS = _keys.NAVIGATION + (_keys.SUMMARY,) + _keys.NESTED_EXIT

#: Same screen once the condensed view is showing. `s` still works — it is what
#: goes back to the whole log — so hiding it would break the rule that a screen
#: never acts on a key it does not advertise. What was wrong was the label:
#: the banner read `s summary` to an operator already looking at the summary.
_PREVIEW_KEYS_SUMMARY = _keys.NAVIGATION + (_keys.FULL,) + _keys.NESTED_EXIT


def _preview_keys(mode: str) -> "tuple[str, ...]":
    """The actions the preview advertises, which depend on what it is showing."""
    return _PREVIEW_KEYS if mode == "full" else _PREVIEW_KEYS_SUMMARY


def _curses_preview_log(stdscr, path: "Path", t) -> None:
    """Scrollable read-only viewer for a log file.  Esc returns to list."""
    import curses

    try:
        raw = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raw = [f"Cannot read file: {exc}"]

    full_lines    = raw
    summary_lines = _extract_summary_view(raw)

    has_color = curses.has_colors()
    scroll = 0
    mode   = "full"   # "full" | "summary"

    while True:
        lines = full_lines if mode == "full" else summary_lines

        h, w = stdscr.getmaxyx()
        from bob.tui import _chrome as _ch
        body_h = max(1, h - 1 - _ch.chrome_height(t, _preview_keys(mode), w))
        max_scroll = max(0, len(lines) - body_h)
        scroll = max(0, min(scroll, max_scroll))

        stdscr.erase()

        # Top banner — v0.16.3: title and context only; the keys moved to the
        # footer, where every other screen puts them. The mode tag and the line
        # range were English literals on a screen whose body is translated.
        mode_tag = t("tui.mode_full") if mode == "full" else t("tui.mode_summary")
        _rng = t("tui.range", first=scroll + 1,
                 last=min(scroll + body_h, len(lines)), total=len(lines))
        banner = f"  {path.name}  {mode_tag}   {_rng}"
        from bob.tui import _chrome
        _chrome.draw_header(stdscr, curses, banner, has_color)

        # Body
        for row in range(body_h):
            line_idx = scroll + row
            if line_idx >= len(lines):
                break
            try:
                stdscr.addstr(row + 1, 0, lines[line_idx][:w - 1])
            except curses.error:
                pass

        # Bottom chrome — the shared key contract, translated.
        from bob.tui import _chrome
        _actions = _preview_keys(mode)
        _chrome.draw(stdscr, curses, t, _actions, has_color)

        stdscr.refresh()

        ch = stdscr.getch()

        action = _keys.resolve(curses, ch, _actions)
        if action == _keys.BACK:                        # nested screen: Esc goes back
            break
        elif action in (_keys.SUMMARY, _keys.FULL):     # toggle summary / full
            mode = "summary" if mode == "full" else "full"
            scroll = 0
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

#: The directory picker is the landing screen: q exits, l switches language.
#: Enter browses the selected directory, c changes/adds the write directory,
#: d forgets a tracked (non-current) directory (its files are kept).
_DIR_KEYS = _keys.NAVIGATION + (
    _keys.SELECT, _keys.CHANGE, _keys.DELETE,
) + _keys.LANDING_EXIT

#: The per-directory report list is nested: Esc goes back to the picker.
_LIST_KEYS = _keys.NAVIGATION + (
    _keys.SELECT, _keys.TOGGLE, _keys.ALL, _keys.DELETE,
) + _keys.NESTED_EXIT
_MARKED_KEYS = _keys.NAVIGATION + (
    _keys.TOGGLE, _keys.DELETE, _keys.UNMARK,
) + _keys.NESTED_EXIT


def _dir_report_label(path: Path, t) -> str:
    """A short description of what a tracked directory holds right now."""
    if not path.exists():
        return t("manage_logs.dir_missing")
    try:
        logs = sorted(path.glob("bob_*.log"))
    except OSError:
        return t("manage_logs.dir_missing")
    if not logs:
        return t("manage_logs.dir_empty")
    return t("manage_logs.dir_reports", count=len(logs))


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
            line = f"  {_DIR_FOLDER} {path}  ({_dir_report_label(path, t)}){tag}"
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

        ch = stdscr.getch()
        act = _keys.resolve(curses, ch, _DIR_KEYS)

        if act == _keys.QUIT:
            return ("quit", None)
        elif act == _keys.LANG:
            _keys.toggle_language(config)
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
                status = t("manage_logs.forget_current_blocked")
            elif _confirm_inline(stdscr, t("manage_logs.forget_confirm"), h, w):
                _forget_dir(user_config, chosen)
                status = t("manage_logs.forgot", path=str(chosen))
                cursor = max(0, cursor - 1)


def _confirm_inline(stdscr, prompt: str, h: int, w: int) -> bool:
    """A one-line y/n confirmation drawn on the bottom row. y confirms."""
    import curses
    try:
        stdscr.move(h - 1, 0)
        stdscr.clrtoeol()
        stdscr.addstr(h - 1, 0, f"  {prompt}"[:w - 1], curses.A_BOLD)
    except curses.error:
        pass
    stdscr.refresh()
    return stdscr.getch() in (ord("y"), ord("Y"))


def _change_log_dir(stdscr, user_config, t, log_dir, has_color) -> None:
    """Ask for a new write directory, remember the old one, optionally move
    its reports across. Shared by the picker's ``c`` action."""
    import curses
    h, w = stdscr.getmaxyx()
    from bob.tui import _chrome as _ch2
    new_path_str = _curses_input(
        stdscr, _ch2.context_row(t, _DIR_KEYS, h, w), w,
        t("manage_logs.change_prompt"),
        str(log_dir) if log_dir else "",
    )
    if new_path_str is None:
        return
    chosen = _resolve_path(new_path_str.strip(), log_dir or Path.cwd())
    try:
        chosen.mkdir(parents=True, exist_ok=True)
    except OSError:
        return
    if log_dir is not None and chosen != log_dir:
        cur_logs = sorted(log_dir.glob("bob_*.log")) if log_dir.exists() else []
        if cur_logs:
            move_prompt = (f"  {t('manage_logs.move_logs_prompt', count=len(cur_logs))}"
                           "  [y/N]")
            try:
                stdscr.move(h - 1, 0)
                stdscr.clrtoeol()
                stdscr.addstr(h - 1, 0, move_prompt[:w - 1], curses.A_BOLD)
            except curses.error:
                pass
            stdscr.refresh()
            if stdscr.getch() in (ord("y"), ord("Y")):
                import shutil as _shutil
                for fp in cur_logs:
                    try:
                        _shutil.move(str(fp), str(chosen / fp.name))
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
        if browse_dir.exists():
            logs = sorted(browse_dir.glob("bob_*.log"), reverse=True)
        else:
            logs = []
        marked = {m for m in marked if m < len(logs)}
        n = len(logs)

        h, w = stdscr.getmaxyx()
        from bob.tui import _chrome as _ch
        body_h = max(1, h - 1 - _ch.chrome_height(t, _MARKED_KEYS, w))
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
            for row in range(body_h - 1):
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

        if confirm_delete:
            _transient = f"  {t('manage_logs.confirm_prompt', count=len(pending_delete))}"
        elif status:
            _transient = f"  {status}"
            status = ""
        else:
            _transient = ""
        _actions = _MARKED_KEYS if n_sel else _LIST_KEYS
        _ch.draw(stdscr, curses, t, _actions, has_color, context=_transient)
        stdscr.refresh()

        ch = stdscr.getch()

        if confirm_delete:
            confirm_delete = False
            if ch in (ord("y"), ord("Y")):
                deleted = 0
                deleted_name = None
                deleted_before_cursor = 0
                for li in sorted(pending_delete, reverse=True):
                    try:
                        name = logs[li].name
                        logs[li].unlink()
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
                    status = t("manage_logs.deleted_one", name=deleted_name)
                elif deleted:
                    status = t("manage_logs.deleted_multi", count=deleted)
            else:
                status = t("manage_logs.cancelled")
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
                _curses_preview_log(stdscr, logs[cursor], t)


def _run_manage_logs_curses(stdscr, user_config, config, t) -> int:
    """Curses --manage-logs: pick a tracked directory, then browse its reports.

    The directory picker is the landing screen; a directory opens into its own
    report list. Tracked directories persist until the operator forgets one, so
    changing where reports are written never loses sight of the old ones.
    """
    if not user_config.get("log_dir"):
        return 0
    while True:
        action, chosen = _dir_picker(stdscr, user_config, config, t)
        if action == "quit":
            return 0
        if action == "select" and chosen is not None:
            _browse_dir(stdscr, chosen, user_config, config, t)


# ---------------------------------------------------------------------------
# Public entry point — dispatches to curses or plain depending on TTY
# ---------------------------------------------------------------------------

def run_manage_logs(user_config, config, t) -> int:
    """Manage audit report files.

    Uses a curses TUI when stdout is a TTY; falls back to the text-mode
    implementation otherwise (tests, pipes, cron).
    """
    if not sys.stdout.isatty():
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
