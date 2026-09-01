"""
User configuration module for BOB.

Manages persistent key=value settings stored between runs, primarily
used to remember port numbers for services that require manual input.

Configuration file location: ~/.config/bob/config.conf

File format (plain key=value, one per line):
    nginx_web_server_port=8080
    ssh_port=2222

No section headers, no comments written by the application.
The file is human-readable and human-editable.

Usage:
    from bob.config import UserConfig

    config = UserConfig.load()
    port = config.get("nginx_web_server_port")   # "8080" or None
    config.set("nginx_web_server_port", "8080")  # persists immediately
    config.delete("nginx_web_server_port")
    config.clear()
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from bob._atomic import atomic_write
from bob.sysinfo import chown_to_sudo_user, get_user_home

logger = logging.getLogger(__name__)

# Default config directory follows XDG Base Directory spec — resolved via SUDO_USER under sudo
_DEFAULT_CONFIG_DIR = get_user_home() / ".config" / "bob"
_CONFIG_FILENAME = "config.conf"
_EMAILS_FILENAME = "emails"

# Minimal email sanity check — rejects obvious non-addresses before persisting
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

# T10 (v0.8.1): English fallback for ValueError messages emitted by
# EmailStore.add() and UserConfig.set() / set_webhook_url() /
# set_webhook_format(). Mirrors the v0.7.2 M-4 pattern used in
# markdown_output.py / html_output.py — public API accepts an optional
# ``t`` parameter; when absent, ``_fallback_t`` substitutes the English
# strings below. Production caller (bob/__main__.py) passes the audit's
# bound ``t`` so the error messages match the operator's locale.
# v0.8.2: hand-rolled ``_fallback_t`` consolidated to
# ``bob._i18n_safe.make_fallback_t`` (single source of truth across the 4
# modules that grew this pattern — config/webhook/markdown_output/html_output).
from bob._i18n_safe import make_fallback_t
from bob.checks._run import path_exists

_FALLBACK_LABELS = {
    "config.error.invalid_email":           "Invalid email address: {email}",
    "config.error.invalid_config_key":      "Invalid config key: {config_key}",
    "config.error.invalid_webhook_url":     "Webhook URL must start with http:// or https://: {url}",
    "config.error.invalid_webhook_format":  "Webhook format must be 'auto', 'generic', or 'slack': {fmt}",
}

_fallback_t = make_fallback_t(_FALLBACK_LABELS)

# ---------------------------------------------------------------------------
# Email store
# ---------------------------------------------------------------------------

class EmailStore:
    """
    Persistent list of saved notification email addresses.

    Stored one address per line in ~/.config/bob/emails.
    Duplicates are silently ignored on add.

    Usage:
        store = EmailStore.load()
        store.add("admin@example.com")   # persists immediately
        store.remove("admin@example.com")
        emails = store.all()             # list[str], insertion order
    """

    def __init__(self, path: Path | None = None) -> None:
        self._path: Path = path or (_DEFAULT_CONFIG_DIR / _EMAILS_FILENAME)
        self._emails: list[str] = []

    @classmethod
    def load(cls, path: Path | None = None) -> "EmailStore":
        """Load existing emails from disk. Missing file → empty list."""
        instance = cls(path=path)
        instance._ensure_dir()
        instance._load()
        return instance

    def all(self) -> list[str]:
        """Return all saved emails in insertion order."""
        return list(self._emails)

    def add(self, email: str, t=None) -> None:
        """Add email if not already present and persist to disk.

        Args:
            email: Email address to add (whitespace-stripped first).
            t:     Optional translation function ``t(key, **kwargs) -> str``
                   used to format the ValueError message. When ``None``,
                   the English fallback dict ``_FALLBACK_LABELS`` is used.
        """
        if t is None:
            t = _fallback_t
        email = email.strip()
        if not email:
            return
        if not _EMAIL_RE.match(email):
            raise ValueError(t("config.error.invalid_email", email=repr(email)))
        if email not in self._emails:
            self._emails.append(email)
            self._save()

    def remove(self, email: str) -> None:
        """Remove email if present and persist to disk."""
        email = email.strip()
        if email in self._emails:
            self._emails.remove(email)
            self._save()

    def _ensure_dir(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            self._path.parent.chmod(0o700)
            chown_to_sudo_user(self._path.parent)
        except OSError as exc:
            logger.warning("Could not create config directory %s: %s", self._path.parent, exc)

    def _load(self) -> None:
        if not path_exists(self._path):
            return
        try:
            with self._path.open(encoding="utf-8") as fh:
                for line in fh:
                    addr = line.strip()
                    if addr and addr not in self._emails:
                        self._emails.append(addr)
        except (OSError, UnicodeDecodeError) as exc:
            # Same reasoning as UserConfig._load: a corrupt file must not be
            # worse than an absent one.
            logger.warning("Could not read emails file %s: %s", self._path, exc)

    def _save(self) -> None:
        self._ensure_dir()
        try:
            atomic_write(
                self._path,
                "".join(f"{addr}\n" for addr in self._emails),
                mode=0o600,
            )
            chown_to_sudo_user(self._path)
        except OSError as exc:
            logger.error("Could not write emails file %s: %s", self._path, exc)
            raise

class UserConfig:
    """
    Persistent key=value store for BOB user settings.

    All write operations (set, delete, clear) persist to disk immediately.
    The in-memory dict is always kept in sync with the file.

    Args:
        path: Full path to the config file. Defaults to
              ~/.config/bob/config.conf.
    """

    def __init__(self, path: Path | None = None) -> None:
        self._path: Path = path or (_DEFAULT_CONFIG_DIR / _CONFIG_FILENAME)
        self._data: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, path: Path | None = None) -> "UserConfig":
        """
        Create a UserConfig instance and load existing settings from disk.

        Creates the config directory if it does not exist.
        Missing config file is treated as an empty configuration (no error).

        Args:
            path: Override the default config file path. Useful in tests.

        Returns:
            Populated UserConfig instance.
        """
        instance = cls(path=path)
        instance._ensure_dir()
        instance._load()
        return instance

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, key: str) -> str | None:
        """
        Return the value for key, or None if not set.

        Args:
            key: Configuration key (e.g. "nginx_web_server_port").

        Returns:
            Stored string value, or None.
        """
        return self._data.get(key)

    def set(self, key: str, value: str, t=None) -> None:
        """
        Store a key=value pair and persist to disk immediately.

        Args:
            key:   Configuration key (must be a valid identifier, e.g. "ssh_port").
            value: String value to store.
            t:     Optional translation function ``t(key, **kwargs) -> str``
                   used to format the ValueError message. When ``None``,
                   the English fallback dict ``_FALLBACK_LABELS`` is used.

        Raises:
            ValueError: If key is not a valid identifier.
            OSError:    If the config file cannot be written.
        """
        if t is None:
            t = _fallback_t
        if not key.isidentifier():
            # Note: kwarg name is ``config_key`` not ``key`` — the latter would
            # shadow the first positional of ``t(key, **kwargs)`` and raise
            # TypeError "got multiple values for argument 'key'".
            raise ValueError(t("config.error.invalid_config_key", config_key=repr(key)))
        self._data[key] = value
        self._save()
        logger.debug("Config set: %s=%s", key, value)

    def delete(self, key: str) -> None:
        """
        Remove a key from the configuration and persist to disk.

        No-op if the key does not exist.

        Args:
            key: Configuration key to remove.
        """
        if key in self._data:
            del self._data[key]
            self._save()
            logger.debug("Config deleted: %s", key)

    def clear(self) -> None:
        """
        Remove all stored configuration and persist an empty file to disk.
        """
        self._data.clear()
        self._save()
        logger.debug("Config cleared")

    def all_keys(self) -> list[str]:
        """Return a sorted list of all stored keys."""
        return sorted(self._data.keys())

    def exists(self) -> bool:
        """Return True if a usable config file exists on disk.

        A path that cannot be reached answers False rather than raising: BOB
        runs as root, but root is squashed on an NFS home and confined under
        SELinux, and `Path.exists()` re-raises EACCES. One such raise from here
        cost the entire audit — no report, no findings, exit 3.
        """
        return path_exists(self._path)

    # ------------------------------------------------------------------
    # Profile helpers
    # ------------------------------------------------------------------

    def get_profile(self) -> str:
        """Return the saved audit profile name, or empty string if not set."""
        return self._data.get("audit_profile", "")

    def set_profile(self, name: str) -> None:
        """Persist the active audit profile name."""
        self.set("audit_profile", name)

    # ------------------------------------------------------------------
    # Webhook helpers
    # ------------------------------------------------------------------

    def get_webhook_url(self) -> str:
        """Return the saved webhook URL, or empty string if not set."""
        return self._data.get("webhook_url", "")

    def set_webhook_url(self, url: str, t=None) -> None:
        """
        Persist the webhook URL.

        Args:
            url: The webhook URL (case-insensitive scheme check).
            t:   Optional translation function ``t(key, **kwargs) -> str``
                 used to format the ValueError message. When ``None``, the
                 English fallback dict is used.

        Raises:
            ValueError: If the URL does not start with http:// or https://.
        """
        if t is None:
            t = _fallback_t
        # I-4 (v0.7.4): scheme match is case-insensitive (RFC 3986), mirroring
        # the v0.7.3 I-5 fix in webhook.py::send_webhook. Without this,
        # `bob --webhook HTTPS://...` succeeded at send time but the persist
        # path raised ValueError (swallowed by __main__) → silent config drop.
        url = url.strip()
        if url and not url.lower().startswith(("http://", "https://")):
            raise ValueError(t("config.error.invalid_webhook_url", url=repr(url)))
        if url:
            self.set("webhook_url", url)
        else:
            self.delete("webhook_url")

    def get_webhook_format(self) -> str:
        """Return the saved webhook format ('auto', 'generic', or 'slack'), default 'auto'."""
        return self._data.get("webhook_format", "auto")

    def set_webhook_format(self, fmt: str, t=None) -> None:
        """
        Persist the webhook format.

        Args:
            fmt: One of 'auto', 'generic', 'slack'.
            t:   Optional translation function ``t(key, **kwargs) -> str``
                 used to format the ValueError message. When ``None``, the
                 English fallback dict is used.

        Raises:
            ValueError: If fmt is not one of 'auto', 'generic', 'slack'.
        """
        if t is None:
            t = _fallback_t
        if fmt not in ("auto", "generic", "slack"):
            raise ValueError(t("config.error.invalid_webhook_format", fmt=repr(fmt)))
        self.set("webhook_format", fmt)

    # ------------------------------------------------------------------
    # SUID whitelist helpers
    # ------------------------------------------------------------------

    def get_suid_whitelist(self) -> list[str]:
        """Return user-configured SUID whitelist patterns (glob, matched on basename).

        Reads the ``suid_whitelist`` key from config.conf as a comma-separated
        list of glob patterns, e.g. ``suid_whitelist = kismet_cap_*, my_tool``.
        Returns an empty list when the key is absent or empty.
        """
        raw = self._data.get("suid_whitelist", "")
        if not raw:
            return []
        return [p.strip() for p in raw.split(",") if p.strip()]

    @property
    def path(self) -> Path:
        """Path to the config file."""
        return self._path

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_dir(self) -> None:
        """Create the config directory if it does not exist (mode 0700)."""
        try:
            self._path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            self._path.parent.chmod(0o700)
            chown_to_sudo_user(self._path.parent)
        except OSError as exc:
            logger.warning("Could not create config directory %s: %s", self._path.parent, exc)

    def _load(self) -> None:
        """
        Parse the config file into _data.

        Silently ignores missing files and malformed lines.
        Lines starting with # are treated as comments and skipped.
        """
        if not path_exists(self._path):
            logger.debug("Config file not found at %s — starting empty", self._path)
            return

        try:
            with self._path.open(encoding="utf-8") as fh:
                for line_number, raw in enumerate(fh, start=1):
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" not in line:
                        logger.debug(
                            "Config line %d malformed (no '='): %r — skipped",
                            line_number,
                            line,
                        )
                        continue
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip()
                    if key:
                        self._data[key] = value
        except (OSError, UnicodeDecodeError) as exc:
            # A file that is not valid UTF-8 is the extreme case of the
            # "malformed lines" this loader already promises to ignore, and it
            # was the one case it did not: UnicodeDecodeError is a ValueError,
            # so it slipped past `except OSError` and reached the top-level
            # handler as "Fatal error: 'utf-8' codec can't decode byte 0xfa" —
            # no audit, no findings, and no mention of which file was at fault.
            # A corrupt config is treated like an absent one, which is what the
            # rest of this method already does for every other kind of damage.
            logger.warning("Could not read config file %s: %s", self._path, exc)
            self._data.clear()

    def _save(self) -> None:
        """
        Write _data to disk as key=value lines, sorted by key.

        Uses an atomic write (temp file + replace) to prevent corruption
        if the process is interrupted mid-write.

        Raises:
            OSError: If the file cannot be written.
        """
        self._ensure_dir()
        try:
            atomic_write(
                self._path,
                "".join(f"{key}={self._data[key]}\n" for key in sorted(self._data.keys())),
                mode=0o600,
            )
            chown_to_sudo_user(self._path)
        except OSError as exc:
            logger.error("Could not write config file %s: %s", self._path, exc)
            raise
