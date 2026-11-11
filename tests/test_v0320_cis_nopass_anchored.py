"""v0.32.0 — `file_perms.nopass_root_equivalent` is anchored in the CIS generator.

Its CIS references were typed by hand in 0.27.0, copied from
`file_perms.sudoers_nopasswd_all`, outside scripts/gen_cis_benchmarks.py, the
only path by which a CIS number may enter cis_refs.json (from ComplianceAsCode,
never from memory). The key is now mapped on the same CAC rule; this test
holds the map and the published entry together.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("gen_cis", _ROOT / "scripts" / "gen_cis_benchmarks.py")
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)


def test_the_key_is_mapped_on_the_sudo_rule():
    assert gen.MAP["file_perms.nopass_root_equivalent"] == ["sudo_require_authentication"]
    assert gen.MAP["file_perms.sudoers_nopasswd_all"] == ["sudo_require_authentication"]


def test_one_rule_one_published_reference():
    """Two keys on one CAC rule must carry what one generator run writes for it."""
    cis = json.loads((_ROOT / "bob" / "data" / "cis_refs.json").read_text(encoding="utf-8"))
    a, b = cis["file_perms.nopass_root_equivalent"], cis["file_perms.sudoers_nopasswd_all"]
    assert (a["ref"], a["code"], a["benchmarks"]) == (b["ref"], b["code"], b["benchmarks"])
