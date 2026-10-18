"""v0.25.1 — the French locale lists its keys in the English order.

Key-set parity was guarded (test_i18n); the order was not. 0.25.0 rebuilt
fr.json so that its 3610 nested paths follow en.json one for one, because a
reviewer comparing the two files line by line, or a diff of a translation,
only works when the same key sits at the same place. Nothing stopped a later
edit from appending a French key at the end of its block again.
"""

import json
import pathlib

_LOCALES = pathlib.Path(__file__).resolve().parent.parent / "bob" / "locales"


def _paths(node, prefix=""):
    out = []
    for key, value in node.items():
        path = f"{prefix}.{key}" if prefix else key
        out.append(path)
        if isinstance(value, dict):
            out.extend(_paths(value, path))
    return out


def test_fr_keys_follow_the_en_order():
    en = _paths(json.loads((_LOCALES / "en.json").read_text(encoding="utf-8")))
    fr = _paths(json.loads((_LOCALES / "fr.json").read_text(encoding="utf-8")))
    assert set(en) == set(fr), "key sets differ — test_i18n reports which"
    first = next((i for i, (a, b) in enumerate(zip(en, fr)) if a != b), None)
    assert first is None, (
        f"fr.json leaves the English order at position {first}: "
        f"en has {en[first]!r}, fr has {fr[first]!r}")
