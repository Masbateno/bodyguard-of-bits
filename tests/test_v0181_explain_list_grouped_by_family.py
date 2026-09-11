"""`--explain list` groups its keys distro → version → type (folders).

Requested for v0.18.1 and refined into a three-level tree: the key list is
split by CIS distribution (CIS Ubuntu, CIS Debian, CIS Docker, CIS Red Hat,
Best practice), each a folder heading in a vertical list; a distribution that
carries several benchmark versions opens onto version sub-folders (CIS Ubuntu
22.04 and 24.04, CIS Debian 12 and 13); inside a version the keys keep their
type sub-sections (SSH — …, ClamAV, …), alphabetical. The same shape drives the
interactive wizard.

A key is placed under every benchmark it cites — the ``benchmarks`` field of
``bob/data/cis_refs.json`` lists the CIS control number the same control carries
in each distribution's benchmark — so a control shared by Ubuntu 22.04/24.04 and
Debian 12/13 appears in all four. Grouping is derived from the canonical English
references, so it is locale-stable; CIS benchmark names are proper nouns kept
verbatim, only "Best practice" is translated.
"""

from __future__ import annotations

import io
import sys

import pytest

from bob import i18n
from bob.cis_refs import (
    BEST_PRACTICE_FAMILY, benchmark_labels, cis_family, cis_family_sort_key,
    split_benchmark,
)
from bob.explain import EXPLAIN_KEYS, _grouped_families, run_explain

_FOLDER = "\U0001F4C1"


@pytest.fixture(autouse=True)
def _english():
    i18n.init("en")


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
# The classifier: cis_family reads the *primary* reference, at the distro level
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("key,distro", [
    ("hardening.rp_filter_disabled", "CIS Ubuntu"),
    ("suid_audit.unowned_suid", "CIS Ubuntu"),
    ("docker.exposed_port", "CIS Docker"),
    ("mac_policy.selinux_disabled", "CIS Red Hat"),
])
def test_cis_family_reads_the_distro_from_the_primary_reference(key, distro):
    assert cis_family(key) == distro


def test_the_level_is_stripped_so_l1_and_l2_group_under_one_distro():
    fams = {cis_family(k) for k in EXPLAIN_KEYS
            if cis_family(k) and "Ubuntu" in cis_family(k)}
    assert fams == {"CIS Ubuntu"}, f"Ubuntu split into {fams}"


def test_every_explain_key_has_a_family():
    missing = [k for k in EXPLAIN_KEYS if cis_family(k) is None]
    assert not missing, f"keys with no benchmark family: {missing}"


def test_ubuntu_is_first_and_best_practice_is_last():
    fams = sorted({cis_family(k) for k in EXPLAIN_KEYS}, key=cis_family_sort_key)
    assert fams[0] == "CIS Ubuntu"
    assert fams[-1] == BEST_PRACTICE_FAMILY


# ---------------------------------------------------------------------------
# The benchmark labels: one key can cite several distributions
# ---------------------------------------------------------------------------

def test_split_benchmark_separates_distro_from_version():
    assert split_benchmark("CIS Ubuntu 22.04") == ("CIS Ubuntu", "22.04")
    assert split_benchmark("CIS Red Hat 8/9") == ("CIS Red Hat", "8/9")
    assert split_benchmark(BEST_PRACTICE_FAMILY) == (BEST_PRACTICE_FAMILY, "")


def test_a_shared_control_cites_every_benchmark_it_appears_in():
    labels = benchmark_labels("hardening.rp_filter_disabled")
    # rp_filter carries a CIS number in Ubuntu 22.04/24.04 and Debian 12/13.
    assert "CIS Ubuntu 22.04" in labels
    assert "CIS Ubuntu 24.04" in labels
    assert "CIS Debian 12" in labels
    assert "CIS Debian 13" in labels


# ---------------------------------------------------------------------------
# The three-level tree: distro -> version -> type -> keys
# ---------------------------------------------------------------------------

def test_the_tree_is_distro_then_version_then_section():
    tree = {distro: benches for distro, _lbl, benches in _grouped_families(i18n.t)}
    assert set(tree) == {"CIS Ubuntu", "CIS Debian", "CIS Docker",
                         "CIS Red Hat", BEST_PRACTICE_FAMILY}
    ubuntu = dict(tree["CIS Ubuntu"])
    assert set(ubuntu) == {"CIS Ubuntu 22.04", "CIS Ubuntu 24.04"}
    debian = dict(tree["CIS Debian"])
    assert set(debian) == {"CIS Debian 12", "CIS Debian 13"}


def test_distros_are_ordered_ubuntu_first_best_practice_last():
    distros = [distro for distro, _lbl, _benches in _grouped_families(i18n.t)]
    assert distros[0] == "CIS Ubuntu"
    assert distros[-1] == BEST_PRACTICE_FAMILY


def test_best_practice_carries_a_single_node_equal_to_the_distro():
    """No version folder under Best practice: its one node is the distro
    itself, which the list renders without a sub-folder and the wizard opens
    straight into keys."""
    tree = {distro: benches for distro, _lbl, benches in _grouped_families(i18n.t)}
    benches = tree[BEST_PRACTICE_FAMILY]
    assert len(benches) == 1
    assert benches[0][0] == BEST_PRACTICE_FAMILY


def test_a_version_holds_typed_sub_sections():
    tree = {distro: benches for distro, _lbl, benches in _grouped_families(i18n.t)}
    ubuntu_2204 = dict(dict(tree["CIS Ubuntu"])["CIS Ubuntu 22.04"])
    assert "SSH — Authentication" in ubuntu_2204
    assert all(k.startswith("ssh.") for k in ubuntu_2204["SSH — Authentication"])


def test_sub_sections_are_sorted_alphabetically_within_a_version():
    for _distro, _lbl, benches in _grouped_families(i18n.t):
        for _bench_label, sections in benches:
            labels = [s for s, _ in sections]
            assert labels == sorted(labels), f"not alphabetical: {labels}"


def test_every_key_lands_under_at_least_one_benchmark():
    seen = set()
    for _distro, _lbl, benches in _grouped_families(i18n.t):
        for _bench_label, sections in benches:
            for _section, keys in sections:
                seen.update(keys)
    assert seen == set(EXPLAIN_KEYS)


def test_a_shared_control_appears_under_each_benchmark_folder():
    """rp_filter carries a number in four benchmarks, so it is listed four
    times — once under each version folder that cites it."""
    where = []
    for _distro, _lbl, benches in _grouped_families(i18n.t):
        for bench_label, sections in benches:
            for _section, keys in sections:
                if "hardening.rp_filter_disabled" in keys:
                    where.append(bench_label)
    assert set(where) >= {"CIS Ubuntu 22.04", "CIS Ubuntu 24.04",
                          "CIS Debian 12", "CIS Debian 13"}


# ---------------------------------------------------------------------------
# The rendered list
# ---------------------------------------------------------------------------

def test_every_key_still_appears():
    out = _list()
    for k in EXPLAIN_KEYS:
        assert k in out


def test_each_distro_has_a_folder_heading():
    out = _list()
    for distro in ("CIS Ubuntu", "CIS Debian", "CIS Docker", "CIS Red Hat",
                   "Best practice"):
        assert f"{_FOLDER} {distro}  (" in out


def test_versioned_distros_show_version_sub_folders():
    out = _list()
    for version in ("CIS Ubuntu 22.04", "CIS Ubuntu 24.04",
                    "CIS Debian 12", "CIS Debian 13"):
        assert f"{_FOLDER} {version}  (" in out


def test_best_practice_has_no_version_sub_folder():
    """Its node equals the distro, so the list shows the distro folder and its
    sections directly — no redundant "Best practice" folder nested inside."""
    out = _list()
    assert out.count(f"{_FOLDER} Best practice") == 1


def test_the_headings_are_in_the_declared_order():
    out = _list()
    ubuntu = out.index(f"{_FOLDER} CIS Ubuntu ")
    debian = out.index(f"{_FOLDER} CIS Debian ")
    best = out.index(f"{_FOLDER} Best practice")
    assert ubuntu < debian < best


def test_a_key_appears_under_its_own_distro_heading():
    out = _list()
    docker_hdr = out.index(f"{_FOLDER} CIS Docker ")
    redhat_hdr = out.index(f"{_FOLDER} CIS Red Hat ")
    key_pos = out.index("docker.exposed_port")
    assert docker_hdr < key_pos < redhat_hdr


def test_each_version_heading_shows_its_key_count():
    out = _list()
    tree = {distro: benches for distro, _lbl, benches in _grouped_families(i18n.t)}
    for version, sections in dict(tree["CIS Ubuntu"]).items():
        count = sum(len(ks) for _s, ks in sections)
        assert f"{version}  ({count})" in out


def test_the_distro_heading_counts_keys_across_its_versions():
    out = _list()
    # CIS Ubuntu (131) = 22.04 (104) + 24.04 (27), a control shared by both
    # counted in each, matching the version folders below it.
    tree = {distro: benches for distro, _lbl, benches in _grouped_families(i18n.t)}
    for distro, benches in tree.items():
        total = sum(len(ks) for _b, secs in benches for _s, ks in secs)
        label = ("Best practice" if distro == BEST_PRACTICE_FAMILY else distro)
        assert f"{_FOLDER} {label}  ({total})" in out


def test_the_header_counts_every_key():
    assert f"({len(EXPLAIN_KEYS)})" in _list()


def test_the_list_shows_section_sub_headings_under_a_version():
    out = _list()
    ubuntu = out.index(f"{_FOLDER} CIS Ubuntu 22.04")
    debian = out.index(f"{_FOLDER} CIS Debian")
    assert "── SSH — Authentication " in out[ubuntu:debian]
    best = out.index(f"{_FOLDER} Best practice")
    assert "── ClamAV " in out[best:], "ClamAV is a best-practice section"


# ---------------------------------------------------------------------------
# Locale: CIS names verbatim, best practice translated
# ---------------------------------------------------------------------------

def test_best_practice_heading_is_translated_in_french():
    out = _list("fr")
    assert f"{_FOLDER} Bonne pratique" in out
    assert f"{_FOLDER} Best practice" not in out


def test_cis_benchmark_names_are_verbatim_in_french():
    out = _list("fr")
    assert f"{_FOLDER} CIS Ubuntu  (" in out, "a distro name is a proper noun"
    assert f"{_FOLDER} CIS Ubuntu 22.04  (" in out, "a version name is a proper noun"


# ---------------------------------------------------------------------------
# Per-key detail: the completed collection surfaces where the operator reads it
# ---------------------------------------------------------------------------

def _explain(key, lang="en"):
    i18n.init(lang=lang)
    buf, old = io.StringIO(), sys.stdout
    sys.stdout = buf
    try:
        run_explain(key, i18n.t)
    finally:
        sys.stdout = old
    return buf.getvalue()


def test_benchmark_rows_are_sorted_and_carry_code_and_title():
    from bob.explain import _benchmark_rows

    rows = _benchmark_rows("hardening.rp_filter_disabled")
    labels = [label for label, _c, _t in rows]
    assert labels == sorted(labels)
    assert ("CIS Debian 12", "3.3.7",
            "Ensure reverse path filtering is enabled (Automated)") in rows


def test_a_shared_control_lists_its_other_benchmarks_in_the_detail():
    out = _explain("hardening.rp_filter_disabled")
    assert "Also cited in" in out
    assert "CIS Debian 12" in out and "3.3.7" in out
    assert "CIS Ubuntu 24.04" in out


def test_a_key_with_no_extra_benchmarks_shows_no_citation_block():
    """A control cited by only its primary benchmark has nothing to add."""
    from bob.explain import _benchmark_rows

    barren = next(k for k in EXPLAIN_KEYS if not _benchmark_rows(k))
    assert "Also cited in" not in _explain(barren)


def test_the_citation_label_is_translated_in_french():
    out = _explain("hardening.rp_filter_disabled", "fr")
    assert "Aussi référencé dans" in out
    assert "CIS Debian 12" in out, "a benchmark name stays verbatim in French"
