"""v0.9.1 regression — ``parse_args`` must not call ``i18n.t()``.

v0.9.0 F-3 (--json-v1 retrait) added a CLIError raise that called
``i18n.t("cli.error.json_v1_retired")`` from inside ``parse_args``. But
``parse_args`` runs BEFORE ``i18n.init()`` is called in ``bob/__main__.py``,
so the lookup hit ``i18n.t()`` pre-init and surfaced the bracketed-fallback
``[cli.error.json_v1_retired]`` to the user instead of the real message:

    so6@so6desktop:~$ bob --json-v1
    i18n.t() called before i18n.init() — returning key 'cli.error.json_v1_retired'
    Error: [cli.error.json_v1_retired]

The fix (this release) inlines a plain English string in the raise, matching
the convention used by every other ``CLIError`` in ``bob/cli.py``. The user
sees an actionable message regardless of i18n init state.

This static guard prevents the bug class from recurring: scan ``parse_args``
via ``ast`` and assert no call to ``i18n.t`` (or any ``t(...)`` call routed
through the i18n module) lives inside its body. A future contributor who
adds another i18n.t() call inside ``parse_args`` will fail this test
before the user-facing error message degrades.
"""
from __future__ import annotations

import ast
import importlib.util
from pathlib import Path


def _cli_module_path() -> Path:
    spec = importlib.util.find_spec("bob.cli")
    assert spec is not None and spec.origin is not None
    return Path(spec.origin)


def _find_parse_args(tree: ast.Module) -> ast.FunctionDef:
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "parse_args":
            return node
    raise AssertionError("bob/cli.py defines no top-level parse_args() function")


def _calls_i18n_t(func: ast.FunctionDef) -> list[tuple[int, str]]:
    """Return [(lineno, call_source)] for every ``i18n.t(...)`` invocation."""
    hits: list[tuple[int, str]] = []
    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            fn = node.func
            # ``i18n.t(...)``
            if (
                isinstance(fn, ast.Attribute)
                and fn.attr == "t"
                and isinstance(fn.value, ast.Name)
                and fn.value.id == "i18n"
            ):
                hits.append((node.lineno, "i18n.t(...)"))
    return hits


def test_parse_args_does_not_call_i18n_t() -> None:
    """The bug fixed in v0.9.1: ``i18n.t()`` inside ``parse_args`` surfaces
    a bracketed-fallback to the user because parsing runs pre-init."""
    source = _cli_module_path().read_text(encoding="utf-8")
    tree = ast.parse(source)
    parse_args = _find_parse_args(tree)
    hits = _calls_i18n_t(parse_args)

    assert not hits, (
        "parse_args() contains i18n.t(...) call(s) — these run BEFORE "
        "i18n.init() and surface a bracketed-fallback (e.g. "
        "``Error: [cli.error.X]``) to the user instead of the real "
        f"message. Offenders: {hits}. Either inline a plain English "
        "string in the raise, or route through bob._i18n_safe."
        "t_or_hardcoded(key, fallback) which falls back to the English "
        "baseline when i18n is not initialised."
    )


def test_json_v1_retired_emits_actionable_message() -> None:
    """Direct guard: ``bob --json-v1`` must emit a plain message containing
    the version and at least one of ``json-v1`` / ``schema`` so users see
    actionable text instead of the locale key path."""
    from bob.cli import CLIError, parse_args

    try:
        parse_args(["--json-v1"])
    except CLIError as exc:
        msg = str(exc)
    else:
        raise AssertionError("--json-v1 must raise CLIError (retired in v0.9.0)")

    # No bracketed-fallback (would look like "[cli.error.json_v1_retired]")
    assert not (msg.startswith("[") and msg.endswith("]")), (
        f"Bracketed-fallback surfaced: {msg!r}. parse_args is calling "
        "i18n.t() pre-init again."
    )
    # Actionable content
    assert "v0.9.0" in msg, (
        f"Migration message must reference v0.9.0 retrait window: {msg!r}"
    )
    assert "json-v1" in msg.lower() or "schema" in msg.lower(), (
        f"Migration message must mention the retired flag or its schema: {msg!r}"
    )
