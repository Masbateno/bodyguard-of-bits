"""v0.25.1 — the cap note names what it caps: the firewall domain.

`set_cap(maximum=3)` from an inactive UFW bounds the *Firewall & Network*
domain (domain_scores.compute_domain_scores); the headline is the average of
the domains. The breakdown said "Score capped at 3" over a summary reading
"≤ 7/10" in the same box.
"""

import json
from pathlib import Path

_LOC = Path(__file__).resolve().parent.parent / "bob" / "locales"


def test_the_note_names_the_domain_in_both_languages():
    en = json.loads((_LOC / "en.json").read_text(encoding="utf-8"))["scoring"]["cap_note"]
    fr = json.loads((_LOC / "fr.json").read_text(encoding="utf-8"))["scoring"]["cap_note"]
    assert "Firewall & Network" in en and not en.startswith("Score capped")
    assert "Pare-feu & Réseau" in fr and not fr.startswith("Score plafonné")


def test_the_cap_bounds_the_domain_not_the_headline():
    from bob.domain_scores import apply_domain_score_override
    from bob.profiles import load_profile
    from bob.scoring import CheckResult, ScoreEngine
    eng = ScoreEngine(profile=load_profile("server"))
    fw = CheckResult()
    fw.alert(message="UFW inactive", key="firewall.inactive", nature="action")
    fw.set_cap(maximum=3, reason="UFW inactive", key="firewall.inactive")
    eng.apply(fw, "firewall")
    other = CheckResult()
    other.ok(message="ok", key="ssh.config_ok")
    eng.apply(other, "ssh")
    eng.finalize()
    apply_domain_score_override(eng)
    assert eng.domain_scores["firewall_network"]["score"] == 3
    assert eng.score > 3
