"""v0.15.3 — the `exists()` trap was only fenced off inside bob/checks/.

v0.15.2 established that `Path.exists()` re-raises EACCES — it swallows only
ENOENT, ENOTDIR, EBADF and ELOOP — and that one such raise from an unguarded
collection cost the entire audit. The guard it shipped covered `bob/checks/`
and nothing else.

`bob/config.py` was outside it. A `~/.config/bob` that cannot be traversed made
`UserConfig._load` raise before any check ran: exit 3, no report, no findings,
a bare `[Errno 13] Permission denied` on stderr. BOB runs as root, but root is
squashed on an NFS home and confined under SELinux, so this is an ordinary
corporate setup rather than an exotic one.

This guard covers the modules that run during an audit. The rest of the package
is listed below with the reason each is exempt, so the exemption is a decision
on record rather than an oversight.
"""

import ast
from pathlib import Path

import pytest

# Modules reached by an ordinary audit. A bare `Path.exists()` in any of these
# can end the run before a single finding is produced.
_AUDIT_PATH_MODULES = (
    "bob/config.py",
    "bob/ignore.py",
    "bob/history.py",
    "bob/__main__.py",
    "bob/runner.py",
    "bob/compare.py",
    "bob/exposure.py",
    "bob/display.py",
)

# Receivers whose `.exists()` is not `Path.exists()` — a class of BOB's own
# that already answers safely.
_SAFE_RECEIVERS = {"user_config", "config", "self"}

# Deliberately outside the guard, each for a stated reason.
_EXEMPT = {
    "bob/_atomic.py":
        "read_text_capped must raise FileNotFoundError for a missing file and "
        "PermissionError for an unreadable one: bob.compare.load_baseline "
        "branches on the difference, and v0.9.2 shipped distinct localised "
        "messages for the two. Collapsing them here would undo that.",
    "bob/completion.py":
        "runs only during `--install-completion`, never during an audit.",
    "bob/manage_logs.py":
        "interactive log management, reached from the TUI rather than a run.",
    "bob/cron/_parse.py":
        "reached only by --install-cron / --manage-cron.",
    "bob/cron/_manage.py":
        "same: cron subcommands, not the audit path.",
}


def _bare_exists_calls(path: Path) -> "list[tuple[int, str]]":
    """Every `<something>.exists()` in *path*, with its receiver name."""
    found = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "exists"
                and not node.args):
            receiver = node.func.value
            name = getattr(receiver, "id", None) or getattr(receiver, "attr", "")
            found.append((node.lineno, name))
    return found


class TestTheAuditPathIsFenced:
    @pytest.mark.parametrize("module", _AUDIT_PATH_MODULES)
    def test_no_bare_path_exists(self, module):
        path = Path(module)
        if not path.exists():  # the guard's own lookup, not the audited code
            pytest.skip(f"{module} not present")
        offenders = [
            f"{module}:{line} ({name or 'unnamed'}.exists())"
            for line, name in _bare_exists_calls(path)
            if name not in _SAFE_RECEIVERS
        ]
        assert not offenders, (
            "these call Path.exists() directly during an audit; EACCES there "
            "ends the run before any finding is produced — call path_exists() "
            "instead: " + ", ".join(offenders)
        )


class TestTheExemptionsAreDeliberate:
    """An exemption without a reason is an oversight wearing a badge."""

    @pytest.mark.parametrize("module,reason", sorted(_EXEMPT.items()))
    def test_each_exemption_states_why(self, module, reason):
        assert len(reason) > 40, f"{module}: the reason is too thin to be one"

    def test_an_exempt_module_is_not_silently_gone(self):
        missing = [m for m in _EXEMPT if not Path(m).exists()]
        assert not missing, (
            "these modules no longer exist; drop their exemption rather than "
            "leaving it to excuse a file that may come back: " + ", ".join(missing)
        )

    def test_atomic_still_distinguishes_the_two_errors(self, tmp_path):
        """The reason `_atomic` is exempt, asserted rather than asserted-to."""
        from bob._atomic import read_text_capped
        with pytest.raises(FileNotFoundError):
            read_text_capped(tmp_path / "absent")
