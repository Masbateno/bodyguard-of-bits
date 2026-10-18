"""v0.25.1 — a release named on a line no longer hides the line's other figures.

The counter guards skipped every line that named a version. SNAPSHOT tags most
rows with the release that introduced something, so "EXPLAIN_KEYS (218 keys,
61 prefixes) + alias map (emptied v0.9.0 D-3)" was never read while the code
held 226 keys and 62 prefixes. The unit is the segment now.
"""

from tests._doc_dating import undated_segments


def test_a_figure_beside_a_dated_note_is_still_read():
    line = "| `explain.py` | 1587 | `EXPLAIN_KEYS` (218 keys, 61 prefixes) + alias map (emptied v0.9.0 D-3) |"
    segs = undated_segments(line)
    assert any("218 keys, 61 prefixes" in s for s in segs)
    assert not any("v0.9.0" in s for s in segs)


def test_a_segment_that_dates_its_own_figure_is_left_alone():
    assert not any("168" in s for s in undated_segments(
        "baseline EXPLAIN_KEYS 117 keys → 168 keys; today see the code"))
    assert not any("47" in s for s in undated_segments(
        "core_dumps became the 47th section in v0.21.0"))


def test_a_history_blockquote_is_history_as_a_whole():
    assert undated_segments("> **v0.13.3 (this snapshot).** 38 filterable sections") == []


def test_a_blockquote_naming_no_release_states_the_present():
    line = ("> Note on `--check=list`: pass `list` as the value of `--check` to print "
            "the 57 filterable + 10 always-on section names.")
    assert any("57 filterable" in seg for seg in undated_segments(line))
