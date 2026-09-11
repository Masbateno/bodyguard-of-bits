"""`--explain list` groups its keys by CIS benchmark family.

Requested for v0.18.1: separate the key list into families — CIS Ubuntu,
CIS Docker, Best practice — each a folder heading in a vertical list, so the
reader sees which benchmark a key comes from. v0.19.x will add more CIS
distributions (Fedora, openSUSE, Alpine); a new family slots in by name.

The family a key belongs to is derived from its canonical English reference
(bob.cis_refs.cis_family), stable across locales — CIS benchmark names are
proper nouns kept verbatim, only "Best practice" is translated.
"""

from __future__ import annotations

import io
import sys

import pytest

from bob import i18n
from bob.cis_refs import BEST_PRACTICE_FAMILY, cis_family, cis_family_sort_key
from bob.explain import EXPLAIN_KEYS, run_explain


def _list(lang="en"):
    i18n.init(lang=lang)
    buf, old = io.StringIO(), sys.stdout
    sys.stdout = buf
    try:
        run_explain("list", i18n.t)
    finally:
        sys.stdout = old
    return buf.getvalue()


# ---------------------------------------------------------------------------
# The classifier
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("key,family", [
    ("hardening.rp_filter_disabled", "CIS Ubuntu 22.04"),
    ("suid_audit.unowned_suid", "CIS Ubuntu 22.04"),
    ("docker.exposed_port", "CIS Docker 1.6"),
    ("mac_policy.selinux_disabled", "CIS Red Hat 8/9"),
    ("suid_audit.unowned_suid", "CIS Ubuntu 22.04"),
])
def test_cis_family_reads_the_benchmark_from_the_reference(key, family):
    assert cis_family(key) == family


def test_the_level_is_stripped_so_l1_and_l2_group_together():
    # rp_filter is L1, and there are L2 keys; both must land in one family.
    fams = {cis_family(k) for k in EXPLAIN_KEYS if cis_family(k) and "Ubuntu" in cis_family(k)}
    assert fams == {"CIS Ubuntu 22.04"}, f"Ubuntu split into {fams}"


def test_every_explain_key_has_a_family():
    missing = [k for k in EXPLAIN_KEYS if cis_family(k) is None]
    assert not missing, f"keys with no benchmark family: {missing}"


def test_ubuntu_is_first_and_best_practice_is_last():
    fams = sorted({cis_family(k) for k in EXPLAIN_KEYS}, key=cis_family_sort_key)
    assert fams[0] == "CIS Ubuntu 22.04"
    assert fams[-1] == BEST_PRACTICE_FAMILY


# ---------------------------------------------------------------------------
# The rendered list
# ---------------------------------------------------------------------------

def test_every_key_still_appears():
    out = _list()
    for k in EXPLAIN_KEYS:
        assert k in out


def test_each_family_has_a_folder_heading():
    out = _list()
    assert "\U0001F4C1 CIS Ubuntu 22.04" in out
    assert "\U0001F4C1 CIS Docker 1.6" in out
    assert "\U0001F4C1 Best practice" in out


def test_headings_are_in_the_declared_order():
    out = _list()
    ubuntu = out.index("CIS Ubuntu 22.04")
    docker = out.index("CIS Docker 1.6")
    best = out.index("Best practice")
    assert ubuntu < docker < best


def test_a_key_appears_under_its_own_family_heading():
    """docker.exposed_port sits after the Docker heading and before the next."""
    out = _list()
    docker_hdr = out.index("\U0001F4C1 CIS Docker 1.6")
    best_hdr = out.index("\U0001F4C1 Best practice")
    key_pos = out.index("docker.exposed_port")
    assert docker_hdr < key_pos < best_hdr


def test_each_family_heading_shows_its_count():
    out = _list()
    from collections import Counter
    counts = Counter(cis_family(k) for k in EXPLAIN_KEYS)
    assert f"CIS Docker 1.6  ({counts['CIS Docker 1.6']})" in out
    assert f"CIS Ubuntu 22.04  ({counts['CIS Ubuntu 22.04']})" in out


def test_the_header_counts_every_key():
    assert f"({len(EXPLAIN_KEYS)})" in _list()


# ---------------------------------------------------------------------------
# Locale: CIS names verbatim, best practice translated
# ---------------------------------------------------------------------------

def test_best_practice_heading_is_translated_in_french():
    out = _list("fr")
    assert "\U0001F4C1 Bonne pratique" in out
    assert "\U0001F4C1 Best practice" not in out


def test_cis_benchmark_names_are_verbatim_in_french():
    out = _list("fr")
    assert "\U0001F4C1 CIS Ubuntu 22.04" in out, "a benchmark name is a proper noun"
