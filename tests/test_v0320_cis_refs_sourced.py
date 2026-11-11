"""v0.32.0 — every CIS Ubuntu number BOB shows comes from ComplianceAsCode.

Read against CAC's controls/cis_ubuntu2204.yml (v2.0.0, the version the
generator re-bases onto) on 11 November 2026: 55 references typed by hand under
the "CIS Ubuntu 22.04" label matched no v2.0.0 control. About a dozen were
v1.0.0 numbers (CAC replaced v1 with v2 on 16 September 2025), others section
numbers (3.5, 1.1, 6.1) or other controls — `ssh.rsa_weak` cited 5.2.2, which
is "Ensure sudo commands use pty" in v2.0.0 and the private host key
permissions in v1.0.0, under a title no version has. BOB printed them in the
summary box as [CIS:x.y.z].

25 are now anchored in scripts/gen_cis_benchmarks.py on the CAC rule their
finding fails, so a regeneration writes the number and title; the 30 with no
such rule are best-practice references, with no code. The guard: no
"CIS Ubuntu" reference outside the generator's MAP.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
REFS = json.loads((ROOT / "bob" / "data" / "cis_refs.json").read_text(encoding="utf-8"))


def _map() -> dict:
    spec = importlib.util.spec_from_file_location("gen_cis", ROOT / "scripts" / "gen_cis_benchmarks.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.MAP


def _entries():
    return {k: v for k, v in REFS.items() if isinstance(v, dict)}


def test_every_cis_ubuntu_reference_comes_from_the_generator():
    """A number typed by hand drifts from the benchmark it names: it must come
    from a CAC rule (or exact CAC title) in the generator's MAP."""
    mapped = _map()
    stray = sorted(k for k, v in _entries().items()
                   if v.get("ref", "").startswith("CIS Ubuntu") and k not in mapped)
    assert not stray, f"CIS Ubuntu references written by hand, not generated: {stray}"


def test_a_best_practice_carries_no_cis_code():
    coded = sorted(k for k, v in _entries().items()
                   if v.get("ref", "").startswith("Best practice") and v.get("code"))
    assert not coded, f"best-practice references with a CIS code: {coded}"


def test_a_cis_code_sits_only_on_a_cis_reference():
    stray = sorted(k for k, v in _entries().items()
                   if (v.get("code") or "").startswith("CIS:") and not v.get("ref", "").startswith("CIS "))
    assert not stray, f"a CIS code without a CIS reference: {stray}"


@pytest.mark.parametrize("key, code", [
    ("ssh.rsa_weak", None),
    ("ssh.strict_modes_disabled", None),
    ("ssh.x11.forwarding.server", None),
    ("secure_boot.disabled", None),
    ("ports.uncovered", "CIS:4.1.6"),
    ("grub.cfg_perms", "CIS:1.4.2"),
    ("faillock.not_configured", "CIS:5.3.2.2"),
    ("updates.security_pending", "CIS:1.2.2.1"),
], ids=lambda x: str(x))
def test_as_read_in_cac(key, code):
    """A sample of the corrections, as CAC v2.0.0 reads (11 November 2026)."""
    assert REFS[key]["code"] == code


def test_the_new_best_practices_are_bilingual():
    for key in ("ssh.rsa_weak", "ssh.host_key_dsa", "kernel_modules.risky_net", "user_accounts.no_shadow"):
        assert REFS[key]["ref"].startswith("Best practice — ")
        assert REFS[key]["ref_fr"].startswith("Bonne pratique — ")
