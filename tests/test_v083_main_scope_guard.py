"""v0.8.3 regression — main() must not shadow module-scope imports.

v0.8.2 ship landed a ``--test-webhook`` handler that did
``from bob.config import UserConfig`` *inside* ``main()``. Python's local
scope analyzer saw the local ``from`` statement and treated ``UserConfig``
as a function-local name for the entire body — even on code paths that
never reached the local import. The audit path (line 298 at ship time)
then raised ``UnboundLocalError: cannot access local variable 'UserConfig'
where it is not associated with a value`` on every non ``--test-webhook``
invocation. CI's smoke-plugin-on-CI guard caught it, but only after the
v0.8.2 tag was already published.

This static guard prevents the bug class from recurring: for each name
imported at ``bob.__main__`` module scope, scan ``main()`` and assert no
local ``from``/``import`` statement re-binds the same name. A future
contributor who adds another defensive re-import inside ``main()`` will
fail this test before the audit path crashes for users.
"""
from __future__ import annotations

import ast
import importlib.util
from pathlib import Path


def _main_module_path() -> Path:
    spec = importlib.util.find_spec("bob.__main__")
    assert spec is not None and spec.origin is not None
    return Path(spec.origin)


def _module_level_imported_names(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                names.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names.add((alias.asname or alias.name).split(".", 1)[0])
    return names


def _find_main_function(tree: ast.Module) -> ast.FunctionDef:
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "main":
            return node
    raise AssertionError("bob/__main__.py defines no top-level main() function")


def _local_imported_names(func: ast.FunctionDef) -> dict[str, int]:
    """Return {imported_name: lineno} for every import inside ``func``."""
    found: dict[str, int] = {}
    for node in ast.walk(func):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                name = alias.asname or alias.name
                found.setdefault(name, node.lineno)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                name = (alias.asname or alias.name).split(".", 1)[0]
                found.setdefault(name, node.lineno)
    return found


def test_main_function_does_not_shadow_module_scope_imports() -> None:
    """The bug fixed in v0.8.3: ``from bob.config import UserConfig`` inside
    ``main()`` shadowed the module-level import and crashed the audit path
    with ``UnboundLocalError``."""
    source = _main_module_path().read_text(encoding="utf-8")
    tree = ast.parse(source)

    module_names = _module_level_imported_names(tree)
    main_func = _find_main_function(tree)
    local_names = _local_imported_names(main_func)

    shadowed = {name: lineno for name, lineno in local_names.items() if name in module_names}

    assert not shadowed, (
        "main() re-imports name(s) already imported at module scope — this "
        "creates an UnboundLocalError trap on code paths that don't reach "
        f"the local import. Offenders: {shadowed}. Move the import to "
        "module scope, or remove it (the module-level binding is already "
        "visible inside main())."
    )


def test_user_config_resolves_at_module_scope() -> None:
    """Direct guard: ``UserConfig`` must be importable from ``bob.__main__``
    namespace (proves it survives import-time as a module-level binding)."""
    from bob import __main__ as bob_main

    assert hasattr(bob_main, "UserConfig"), (
        "UserConfig is no longer imported at bob.__main__ module scope — "
        "the audit path at runner.UserConfig.load() will UnboundLocalError "
        "unless every caller path goes through a local import first."
    )
