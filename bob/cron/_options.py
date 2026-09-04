"""The three audit dimensions a scheduled run carries into its command line.

``--install-cron`` writes a bash script to ``/usr/local/bin`` as root, so the
option string interpolated into that script is built here and *only* from
closed sets. ``build_audit_options`` refuses a value it does not recognise
rather than passing it through — the wizard already constrains the choice to
a menu, but a hardening tool must not rely on the UI as the sole guard for a
root write (same reasoning as the control-character strip on the cron name,
v0.12.2).

Why every dimension is emitted explicitly, even at its default value:

- ``--profile``  a cron runs as root, so it would otherwise read *root's*
  saved config, not the operator's. Before v0.16.1 that made the scheduled
  audit silently different from the interactive one — and the profile drives
  the deductions, hence ``warning_count``, hence the exit code, hence whether
  the notification mail is sent at all.
- ``--english`` / ``--french``  cron runs with a bare environment; ``$LANG``
  is usually unset, so locale auto-detection would answer English whatever
  the operator chose at install time.
- ``--offline``  emitted only when selected; its absence *is* the other value.
"""

from __future__ import annotations

import re

#: Shipped profiles (``bob/data/profiles/*.conf``). Kept as a literal because
#: the wizard needs a stable presentation order; a drift guard asserts it
#: still matches what is actually shipped.
CRON_PROFILES: tuple[str, ...] = ("server", "desktop", "workstation", "container")

#: Interface languages BOB ships. Mirrors ``bob/locales/*.json``.
CRON_LANGS: tuple[str, ...] = ("en", "fr")

_LANG_FLAG = {"en": "--english", "fr": "--french"}

#: The only shape ``build_audit_options`` may ever produce. Anything else is a
#: programming error and must not reach a root-owned script.
_OPTIONS_RE = re.compile(
    r"^--profile (?:server|desktop|workstation|container)"
    r" --(?:english|french)"
    r"(?: --offline)?$"
)


def build_audit_options(profile: str, lang: str, offline: bool) -> str:
    """Render the three cron audit dimensions as a CLI option string.

    Args:
        profile: One of :data:`CRON_PROFILES`.
        lang:    One of :data:`CRON_LANGS`.
        offline: Whether the scheduled audit skips outbound probes.

    Returns:
        A space-separated option string, e.g. ``--profile desktop --french``.

    Raises:
        ValueError: If ``profile`` or ``lang`` is outside its closed set, or
            if the rendered string does not match the expected shape.
    """
    if profile not in CRON_PROFILES:
        raise ValueError(f"unknown profile: {profile!r}")
    if lang not in CRON_LANGS:
        raise ValueError(f"unknown language: {lang!r}")

    opts = f"--profile {profile} {_LANG_FLAG[lang]}"
    if offline:
        opts += " --offline"

    if not _OPTIONS_RE.match(opts):   # unreachable — defence in depth
        raise ValueError(f"refusing to emit malformed audit options: {opts!r}")
    return opts


def default_dimensions(config) -> "tuple[str, str, bool]":
    """Pick the wizard's pre-selected values from the installing session.

    The operator running ``sudo bob --install-cron`` has already expressed a
    profile, a language and a network stance on that very command line (or in
    their saved config); the wizard opens on those rather than on BOB's own
    defaults, so the common case is three times Enter.
    """
    profile = getattr(config, "profile", "") or "server"
    if profile in ("default", ""):
        profile = "server"
    if profile not in CRON_PROFILES:
        profile = "server"

    lang = getattr(config, "lang", "") or "en"
    if lang not in CRON_LANGS:
        lang = "en"

    return profile, lang, bool(getattr(config, "offline", False))
