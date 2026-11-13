"""v0.35.0 — the documents' per-profile counts are the profile files'.

"desktop downgrades 36 findings to INFO" stood in the README, the tutorial and
bob-profile(5), and "workstation: the same 31, without the five on backup,
auditd and AppArmor enforcement". 0.35.0 moved desktop's AppArmor "no profile
loaded" relaxation from a branch on the profile's name into desktop.conf
(37 overrides, six that workstation does not take); no guard read these
sentences. Each count is derived here from the loaded profiles.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from bob.profiles import load_profile

_ROOT = Path(__file__).resolve().parent.parent
_WORDS = {"five": 5, "six": 6, "seven": 7, "cinq": 5, "sept": 7}


def _counts():
    desktop = {k for k, v in load_profile("desktop").overrides.items() if str(v) == "info"}
    workstation = {k for k, v in load_profile("workstation").overrides.items() if str(v) == "info"}
    assert workstation <= desktop
    return {"desktop": len(desktop), "workstation": len(workstation),
            "not_in_workstation": len(desktop - workstation),
            "container_skips": len(load_profile("container").skip_sections)}


_CLAIMS = [
    ("README.md", r"downgrades (\d+) findings to INFO", "desktop"),
    ("README_FR.md", r"ramène (\d+) constats en INFO", "desktop"),
    ("DOCUMENTS/TUTORIAL.md", r"(\d+) findings downgraded to INFO", "desktop"),
    ("DOCUMENTS/TUTORIAL_FR.md", r"(\d+) constats ramenés en INFO", "desktop"),
    ("man/bob-profile.5", r"downgrades (\d+) findings to INFO", "desktop"),
    ("DOCUMENTS/TUTORIAL.md", r"the same (\d+) downgrades as `desktop`", "workstation"),
    ("DOCUMENTS/TUTORIAL_FR.md", r"les mêmes (\d+) assouplissements que `desktop`", "workstation"),
    ("DOCUMENTS/TUTORIAL.md", r"downgrades as `desktop`, without the (\w+)", "not_in_workstation"),
    ("DOCUMENTS/TUTORIAL_FR.md", r"assouplissements que `desktop`, sans les (\w+)", "not_in_workstation"),
    ("README.md", r"skips (\d+) host-level sections", "container_skips"),
    ("README_FR.md", r"(\d+) sections propres à l'hôte", "container_skips"),
    ("DOCUMENTS/TUTORIAL.md", r"skips (\d+) host-level sections", "container_skips"),
    ("DOCUMENTS/TUTORIAL_FR.md", r"(\d+) sections propres à l'hôte", "container_skips"),
    ("man/bob-profile.5", r"skips (\d+) host-level sections", "container_skips"),
]


@pytest.mark.parametrize("rel, pattern, what", _CLAIMS,
                         ids=[f"{r}:{w}" for r, _p, w in _CLAIMS])
def test_the_stated_count_is_the_profiles(rel, pattern, what):
    m = re.search(pattern, (_ROOT / rel).read_text(encoding="utf-8"))
    assert m, f"{rel}: the {what} sentence is gone or reshaped ({pattern})"
    raw = m.group(1)
    said = int(raw) if raw.isdigit() else _WORDS.get(raw.lower())
    assert said == _counts()[what], f"{rel}: says {raw} for {what}; the profiles give {_counts()[what]}"
