"""Terminal input helpers for BOB.

- :func:`read_line` — raw-mode line reader with Esc-to-cancel (used by
  curses-adjacent menus; falls back to :func:`input` in non-TTY contexts).
- :func:`prompt_wizard` — uniform ``input()`` wrapper for plain-text wizards:
  strips, handles ``q``/``quit`` cancel, and applies a default on bare Enter.
- :func:`safe_input` — thin :func:`input` wrapper that swallows ``EOFError``
  (Ctrl+D) and returns ``""`` instead of crashing. v0.6.1 #I-2 contract.
"""
from __future__ import annotations

import sys


def safe_input(prompt: str = "") -> str:
    """I-2 (v0.6.1): :func:`input` wrapper that treats Ctrl+D (EOF) as
    empty input rather than letting :exc:`EOFError` propagate as a
    traceback. Use at any site where the next code path can sensibly
    handle an empty answer (most y/N confirmations, email entry that
    will fail the regex, menu prompts that recurse).

    Sites that need EOF → None semantics (cancel, not empty) should use
    :func:`prompt_wizard` (which returns ``None`` on EOF) instead.
    """
    try:
        return input(prompt)
    except EOFError:
        return ""


def prompt_wizard(label: str, *, default: str = "") -> "str | None":
    """Plain-text wizard prompt with uniform cancel + default handling.

    Use ``label="  > "`` when the question has already been printed via
    :func:`print` (multi-line wizards). Use a full inline label
    (``"  Foo [{default}]: "``) for single-line prompts.

    Returns:
        ``None`` — user typed ``q`` / ``quit`` (case-insensitive) OR pressed
                   Ctrl+D (EOFError). I-2 (v0.6.1): EOF is treated as cancel,
                   not crash. Aligns with :func:`read_line` and the v0.5.7
                   #I-2 contract applied to manage_logs.py.
        ``str``  — trimmed input, or ``default`` when Enter was pressed bare.
    """
    try:
        raw = input(label).strip()
    except EOFError:
        return None
    if raw.lower() in ("q", "quit"):
        return None
    return raw or default


def read_line(prompt: str = "") -> str | None:
    """Interactive line reader with Esc-to-cancel.

    Returns:
        None  — Esc pressed or Ctrl+D (cancel / go back)
        ""    — bare Enter (confirm / quit)
        str   — the typed text

    Falls back to input() when stdin is not a TTY (tests, pipes),
    which keeps existing ``patch("builtins.input", ...)`` mocks working.
    """
    if not sys.stdin.isatty():
        try:
            return input(prompt)
        except EOFError:
            return None

    try:
        import select
        import termios
        import tty
    except ImportError:
        try:
            return input(prompt)
        except EOFError:
            return None

    if prompt:
        sys.stdout.write(prompt)
        sys.stdout.flush()

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    buf: list[str] = []

    try:
        tty.setraw(fd)
        while True:
            ch = sys.stdin.read(1)

            if ch == "\x1b":
                # Drain escape sequence tail (arrow keys → \x1b[A, \x1b[B, etc.)
                # 50 ms window distinguishes standalone Esc from sequences.
                rlist, _, _ = select.select([sys.stdin], [], [], 0.05)
                if rlist:
                    tail = sys.stdin.read(1)
                    if tail in ("[", "O"):
                        r2, _, _ = select.select([sys.stdin], [], [], 0.02)
                        if r2:
                            sys.stdin.read(1)
                    # Escape sequence (arrow key etc.) — ignore and continue
                else:
                    sys.stdout.write("\r\n")
                    sys.stdout.flush()
                    return None  # standalone Esc = cancel / back

            elif ch in ("\r", "\n"):
                sys.stdout.write("\r\n")
                sys.stdout.flush()
                return "".join(buf)

            elif ch in ("\x7f", "\x08"):  # DEL / backspace
                if buf:
                    buf.pop()
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()

            elif ch == "\x03":  # Ctrl+C
                sys.stdout.write("\r\n")
                sys.stdout.flush()
                raise KeyboardInterrupt

            elif ch in ("\x04", "\x1c"):  # Ctrl+D / Ctrl+backslash
                sys.stdout.write("\r\n")
                sys.stdout.flush()
                return None

            elif ch >= " ":  # printable (ASCII + UTF-8 lead bytes)
                buf.append(ch)
                sys.stdout.write(ch)
                sys.stdout.flush()

    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
