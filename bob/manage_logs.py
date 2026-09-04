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
        print(f"  ℹ {t('manage_logs.no_dir')}")
        return 0

    while True:
        # Refresh current directory on every iteration
        log_dir_str = user_config.get("log_dir") or log_dir_str
        log_dir = Path(log_dir_str)

        if not log_dir.exists():
            log_dir.mkdir(parents=True, exist_ok=True)

        cur_logs = sorted(log_dir.glob("bob_*.log"), reverse=True)

        # Collect extra (previous) directories that still contain logs;
        # auto-drop those that are empty or no longer exist.
        extra_dirs = _get_extra_dirs(user_config)
        extra_sections: list[tuple[Path, list[Path]]] = []
        live_extras: list[Path] = []
        for extra in extra_dirs:
            if extra == log_dir:
                continue
            if extra.exists():
                ex_logs = sorted(extra.glob("bob_*.log"), reverse=True)
                if ex_logs:
                    extra_sections.append((extra, ex_logs))
                    live_extras.append(extra)
        if live_extras != extra_dirs:
            _set_extra_dirs(user_config, live_extras)

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
        body_h = max(1, h - 2)
        max_scroll = max(0, len(lines) - body_h)
        scroll = max(0, min(scroll, max_scroll))

        stdscr.erase()

        # Top banner
        mode_tag = "[FULL]" if mode == "full" else "[SUMMARY]"
        banner = (f"  {path.name}  {mode_tag}   "
                  f"↑↓ / PgUp/PgDn: scroll   g/G: top/bottom   "
                  f"s: {'summary' if mode == 'full' else 'full log'}   Esc: back")
        try:
            attr = (curses.color_pair(5) | curses.A_BOLD) if has_color else curses.A_REVERSE
            stdscr.addstr(0, 0, banner.ljust(w - 1)[:w - 1], attr)
        except curses.error:
            pass

        # Body
        for row in range(body_h):
            line_idx = scroll + row
            if line_idx >= len(lines):
                break
            try:
                stdscr.addstr(row + 1, 0, lines[line_idx][:w - 1])
            except curses.error:
                pass

        # Footer
        total_lines = len(lines)
        footer = (f"  line {scroll + 1}–{min(scroll + body_h, total_lines)}"
                  f" / {total_lines}")
        try:
            stdscr.addstr(h - 1, 0, footer[:w - 1], curses.A_DIM)
        except curses.error:
            pass

        stdscr.refresh()

        ch = stdscr.getch()

        if ch == 27:                                    # Esc → back
            break
        elif ch in (ord("s"), ord("S")):               # toggle summary / full
            mode = "summary" if mode == "full" else "full"
            scroll = 0
        elif ch == curses.KEY_UP:
            scroll = max(0, scroll - 1)
        elif ch == curses.KEY_DOWN:
            scroll = min(max_scroll, scroll + 1)
        elif ch == curses.KEY_PPAGE:
            scroll = max(0, scroll - body_h)
        elif ch == curses.KEY_NPAGE:
            scroll = min(max_scroll, scroll + body_h)
        elif ch in (curses.KEY_HOME, ord("g")):
            scroll = 0
        elif ch in (curses.KEY_END, ord("G")):
            scroll = max_scroll


def _run_manage_logs_curses(stdscr, user_config, config, t) -> int:
    """Curses interactive file manager for --manage-logs."""
    import curses

    try:
        curses.curs_set(0)
    except curses.error:
        pass

    has_color = _init_colors_ml()
    size_label = t("manage_logs.size_label")

    cursor          = 0             # position in file_indices
    scroll          = 0             # first visible item index in items list
    marked: set[int] = set()        # 0-based indices into all_logs
    status          = ""            # one-shot footer message
    confirm_delete  = False         # True = waiting for y/n
    pending_delete: list[int] = []  # log indices to delete on confirmation

    while True:
        # ── Refresh file list ─────────────────────────────────────────────
        log_dir_str = user_config.get("log_dir") or ""
        if not log_dir_str:
            return 0

        log_dir = Path(log_dir_str)
        if not log_dir.exists():
            try:
                log_dir.mkdir(parents=True, exist_ok=True)
            except OSError:
                pass

        cur_logs = sorted(log_dir.glob("bob_*.log"), reverse=True)
        extra_dirs = _get_extra_dirs(user_config)
        extra_sections: list[tuple[Path, list[Path]]] = []
        live_extras: list[Path] = []
        for extra in extra_dirs:
            if extra == log_dir:
                continue
            if extra.exists():
                ex_logs = sorted(extra.glob("bob_*.log"), reverse=True)
                if ex_logs:
                    extra_sections.append((extra, ex_logs))
                    live_extras.append(extra)
        if live_extras != extra_dirs:
            _set_extra_dirs(user_config, live_extras)

        all_logs: list[Path] = list(cur_logs)
        for _, ex_logs in extra_sections:
            all_logs.extend(ex_logs)

        marked = {m for m in marked if m < len(all_logs)}

        # ── Build display items ───────────────────────────────────────────
        # item types: ("dir_header", path, is_current)
        #             ("file",       log_index)
        #             ("empty",      path)
        items: list[tuple] = []
        file_indices: list[int] = []   # positions of "file" items in items[]
        log_idx = 0

        items.append(("dir_header", log_dir, True))
        if not cur_logs:
            items.append(("empty", log_dir))
        for _ in cur_logs:
            file_indices.append(len(items))
            items.append(("file", log_idx))
            log_idx += 1
        for extra_path, ex_logs in extra_sections:
            items.append(("dir_header", extra_path, False))
            for _ in ex_logs:
                file_indices.append(len(items))
                items.append(("file", log_idx))
                log_idx += 1

        # ── Clamp cursor / scroll ─────────────────────────────────────────
        if file_indices:
            cursor = max(0, min(cursor, len(file_indices) - 1))
            cur_item_pos = file_indices[cursor]
        else:
            cursor = 0
            cur_item_pos = 0

        h, w = stdscr.getmaxyx()
        body_h = max(1, h - 2)

        if file_indices:
            if cur_item_pos - scroll >= body_h:
                scroll = cur_item_pos - body_h + 1
            if cur_item_pos < scroll:
                scroll = cur_item_pos
                if scroll > 0 and items[scroll - 1][0] == "dir_header":
                    scroll = max(0, scroll - 1)
        scroll = max(0, scroll)

        # ── Render ────────────────────────────────────────────────────────
        stdscr.erase()

        # Header
        n_sel = len(marked)
        if confirm_delete:
            header = "  bob --manage-logs    Confirm deletion below  "
        elif n_sel:
            header = (f"  bob --manage-logs    "
                      f"↑↓: move   Spc: toggle   d: delete ({n_sel})   "
                      f"u: unmark all   q: quit")
        else:
            header = ("  bob --manage-logs    "
                      "↑↓: move   Enter: preview   Spc: mark   a: all   "
                      "d: delete   c: change dir   q: quit")
        try:
            banner_attr = (curses.color_pair(5) | curses.A_BOLD) if has_color else curses.A_REVERSE
            stdscr.addstr(0, 0, header.ljust(w - 1)[:w - 1], banner_attr)
        except curses.error:
            pass

        # Body
        for row in range(body_h):
            item_idx = scroll + row
            if item_idx >= len(items):
                break
            item = items[item_idx]
            y = row + 1

            if item[0] == "dir_header":
                _, path, is_current = item
                cur_lbl  = t("manage_logs.current_label")
                prev_lbl = t("manage_logs.previous_label")
                if is_current:
                    line = f"  {t('manage_logs.stored_in', path=str(path))}  [{cur_lbl}]"
                else:
                    line = f"  ─── {prev_lbl}: {path} ───"
                attr = (curses.color_pair(2) | curses.A_BOLD) if has_color else curses.A_BOLD
                try:
                    stdscr.addstr(y, 0, line[:w - 1], attr)
                except curses.error:
                    pass

            elif item[0] == "empty":
                _, path = item
                line = f"    ℹ {t('manage_logs.no_logs', path=str(path))}"
                try:
                    stdscr.addstr(y, 0, line[:w - 1], curses.A_DIM)
                except curses.error:
                    pass

            elif item[0] == "file":
                _, log_i = item
                f = all_logs[log_i]
                try:
                    size_kb = max(1, f.stat().st_size // 1024)
                    mtime   = _dt.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                except OSError:
                    size_kb, mtime = 0, "?"

                is_cursor = bool(file_indices) and file_indices[cursor] == item_idx
                is_marked = log_i in marked

                ind = ("→✓" if (is_cursor and is_marked) else
                       "→ " if is_cursor else
                       " ✓" if is_marked else
                       "  ")

                num_col  = f"[{log_i + 1:2}]"
                suffix   = f"  {size_kb:4} {size_label}  {mtime}"
                max_name = max(8, w - 2 - len(ind) - 1 - len(num_col) - 2 - len(suffix) - 1)
                name_str = f.name[:max_name].ljust(max_name)
                line     = f" {ind} {num_col}  {name_str}{suffix}"

                if is_cursor:
                    attr = (curses.color_pair(1) | curses.A_BOLD) if has_color else curses.A_REVERSE
                elif is_marked:
                    attr = (curses.color_pair(4) | curses.A_BOLD) if has_color else curses.A_UNDERLINE
                else:
                    attr = curses.color_pair(3) if has_color else 0

                try:
                    if is_cursor:
                        stdscr.addstr(y, 0, line[:w - 1].ljust(w - 1)[:w - 1], attr)
                    else:
                        stdscr.addstr(y, 0, line[:w - 1], attr)
                except curses.error:
                    pass

        # Footer
        total = len(all_logs)
        if confirm_delete:
            footer = f"  {t('manage_logs.confirm_prompt', count=len(pending_delete))}"
        elif status:
            footer = f"  {status}"
            status = ""
        elif n_sel:
            footer = (f"  {total} report(s)   {n_sel} selected   "
                      "d: delete selected   u: unmark all")
        else:
            footer = f"  {total} report(s)"
        try:
            stdscr.addstr(h - 1, 0, footer[:w - 1], curses.A_DIM)
        except curses.error:
            pass

        stdscr.refresh()

        # ── Input ─────────────────────────────────────────────────────────
        ch = stdscr.getch()

        if confirm_delete:
            confirm_delete = False
            if ch in (ord("y"), ord("Y")):
                deleted = 0
                deleted_name = None  # M-1 (v0.5.7): track which file actually succeeded
                deleted_before_cursor = 0  # M-2 (v0.5.8): only shift for items <= cursor
                for li in sorted(pending_delete, reverse=True):
                    try:
                        name = all_logs[li].name
                        all_logs[li].unlink()
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

        if ch in (ord("q"), ord("Q")):
            return 0

        elif ch == curses.KEY_UP:
            if cursor > 0:
                cursor -= 1

        elif ch == curses.KEY_DOWN:
            if cursor < len(file_indices) - 1:
                cursor += 1

        elif ch == curses.KEY_PPAGE:
            cursor = max(0, cursor - body_h)

        elif ch == curses.KEY_NPAGE:
            cursor = min(max(0, len(file_indices) - 1), cursor + body_h)

        elif ch == ord(" "):
            if file_indices:
                log_i = items[file_indices[cursor]][1]
                if log_i in marked:
                    marked.discard(log_i)
                else:
                    marked.add(log_i)

        elif ch in (ord("a"), ord("A")):
            marked = set(range(len(all_logs)))

        elif ch in (ord("u"), ord("U")):
            marked.clear()

        elif ch in (ord("d"), ord("D")):
            if all_logs:
                if marked:
                    pending_delete = sorted(marked)
                elif file_indices:
                    pending_delete = [items[file_indices[cursor]][1]]
                if pending_delete:
                    confirm_delete = True

        elif ch in (10, 13, curses.KEY_ENTER):
            if file_indices and not n_sel:
                log_i = items[file_indices[cursor]][1]
                _curses_preview_log(stdscr, all_logs[log_i], t)

        elif ch in (ord("c"), ord("C")):
            # Inline path input — stays fully inside curses
            new_path_str = _curses_input(
                stdscr, h - 1, w,
                t("manage_logs.change_prompt"),
                str(log_dir),
            )
            if new_path_str is None:
                status = t("manage_logs.cancelled")
            else:
                raw = new_path_str.strip()
                chosen = _resolve_path(raw, log_dir)
                try:
                    chosen.mkdir(parents=True, exist_ok=True)
                except OSError as exc:
                    status = f"✖ {exc}"
                else:
                    do_move = False
                    if all_logs and chosen != log_dir:
                        move_prompt = (
                            f"  {t('manage_logs.move_logs_prompt', count=len(all_logs))}"
                            "  [y/N]"
                        )
                        try:
                            stdscr.move(h - 1, 0)
                            stdscr.clrtoeol()
                            stdscr.addstr(h - 1, 0, move_prompt[:w - 1], curses.A_BOLD)
                        except curses.error:
                            pass
                        stdscr.refresh()
                        mv_ch = stdscr.getch()
                        do_move = mv_ch in (ord("y"), ord("Y"))
                    if do_move:
                        import shutil as _shutil
                        moved = 0
                        for fp in all_logs:
                            try:
                                _shutil.move(str(fp), str(chosen / fp.name))
                                moved += 1
                            except OSError:
                                pass
                        status = t("manage_logs.move_logs_done", count=moved)
                    if chosen != log_dir:
                        _add_extra_dir(user_config, log_dir)
                    user_config.set("log_dir", str(chosen))
                    marked.clear()
                    cursor = 0
                    scroll = 0
                    if not do_move:
                        status = t("manage_logs.location_updated", path=str(chosen))


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
