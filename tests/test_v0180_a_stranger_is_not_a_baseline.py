"""A JSON file that is not a baseline must not be compared against.

``load_baseline`` read every field with ``raw.get(name, default)``, so any
JSON object at all loaded as a baseline of zero: no timestamp, score 0, no
ports, no services, no finding keys. The diff then read the *current* audit
back against that nothing and announced it as change.

Measured before the fix, diffing a real audit against ``{"unrelated": 1}``:

    Previous audit:
    ✔ [OK] Score improved by 72 point(s)
    ⚠ [WARNING] New open port detected: 22/tcp
    ℹ [INFO] Service became active: ssh

Not one of those was measured against anything. The blank date is the tell:
BOB had no previous run to compare with and said so nowhere.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from bob.compare import (
    AuditBaseline,
    BaselineLoadError,
    compute_delta,
    display_delta,
    load_baseline,
    save_baseline,
)


def _current() -> AuditBaseline:
    return AuditBaseline(
        timestamp="2026-09-10T20:00:00+00:00",
        score=72,
        alert_count=2,
        warn_count=9,
        info_count=14,
        open_ports=["22/tcp", "80/tcp"],
        active_services=["ssh", "nginx"],
        finding_keys=["ssh.root_login", "firewall.inactive"],
        deduction_total=28,
        hostname="bench",
        unverified=[],
    )


STRANGERS = {
    "unrelated-object": {"unrelated": {"nested": 1}},
    "empty-object": {},
    "config-file": {"profile": "server", "lang": "fr"},
    "score-without-timestamp": {"score": 40},
    "timestamp-without-score": {"timestamp": "2026-09-10T20:00:00+00:00"},
}


@pytest.mark.parametrize("name", sorted(STRANGERS))
def test_a_stranger_is_refused_out_loud(tmp_path, name):
    """--diff PATH on a foreign JSON file says so instead of inventing a run."""
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(STRANGERS[name]), encoding="utf-8")

    with pytest.raises(BaselineLoadError):
        load_baseline(path, strict=True)


@pytest.mark.parametrize("name", sorted(STRANGERS))
def test_a_stranger_is_refused_quietly_too(tmp_path, name):
    """The auto-managed path returns None rather than a baseline of zero."""
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(STRANGERS[name]), encoding="utf-8")

    assert load_baseline(path, strict=False) is None


def test_a_real_baseline_still_round_trips(tmp_path):
    """The opposite polarity — the gate must not refuse BOB's own writing.

    ``save_baseline`` serialises through ``asdict``, so every field is
    present. If this test ever fails, the gate is rejecting real baselines.
    """
    path = tmp_path / "last_baseline.json"
    original = _current()
    save_baseline(original, path)

    assert load_baseline(path, strict=True) == original


def test_a_baseline_with_a_zero_score_is_still_a_baseline(tmp_path):
    """``score: 0`` is a measurement, not a missing field.

    A membership test is used rather than a truthiness test precisely so a
    machine that scored zero keeps its baseline.
    """
    path = tmp_path / "zero.json"
    floor = AuditBaseline(
        timestamp="2026-09-10T20:00:00+00:00",
        score=0,
        alert_count=11,
        warn_count=3,
        info_count=0,
        open_ports=[],
        active_services=[],
        finding_keys=[],
        deduction_total=100,
        hostname="wide-open",
        unverified=[],
    )
    save_baseline(floor, path)

    assert load_baseline(path, strict=True) == floor


def _english(key: str, **kwargs) -> str:
    """Render a locale key through the real English catalogue.

    Deliberately *not* ``i18n.init`` — that mutates process-wide state and
    leaks the locale into whatever test pytest runs next. Reading the
    catalogue here keeps the render real and the test isolated.
    """
    node = json.loads(Path("bob/locales/en.json").read_text(encoding="utf-8"))
    for part in key.split("."):
        node = node[part]
    return str(node).format(**kwargs)


def test_no_comparison_is_rendered_from_a_stranger(tmp_path):
    """The render, not the helper: the invented sentences must be unreachable.

    Guarding ``load_baseline`` alone would leave this green while a caller
    that skipped the loader still printed "Score improved by 72". So drive
    ``display_delta`` itself and look for the blank-date line — the
    fingerprint of a comparison against a document that recorded nothing.
    """
    lines: list[str] = []
    sink = SimpleNamespace(
        print_ok=lambda msg, **kw: lines.append(msg),
        print_warn=lambda msg, **kw: lines.append(msg),
        print_info=lambda msg, **kw: lines.append(msg),
        print_dim=lambda msg, **kw: lines.append(msg),
        print_section=lambda msg: lines.append(msg),
        print_alert=lambda msg, **kw: lines.append(msg),
    )

    path = tmp_path / "stranger.json"
    path.write_text(json.dumps({"unrelated": {"nested": 1}}), encoding="utf-8")
    assert load_baseline(path, strict=False) is None, (
        "the stranger must not become a baseline"
    )

    # A genuine previous run renders the date it compares against. The
    # defect produced this same block with that line blank.
    real_prev = AuditBaseline(
        timestamp="2026-09-09T20:00:00+00:00",
        score=60,
        alert_count=2,
        warn_count=9,
        info_count=14,
        open_ports=["22/tcp", "80/tcp"],
        active_services=["ssh", "nginx"],
        finding_keys=["ssh.root_login", "firewall.inactive"],
        deduction_total=40,
        hostname="bench",
        unverified=[],
    )
    display_delta(compute_delta(real_prev, _current()), _english, sink)
    rendered = "\n".join(lines)

    assert "2026-09-09T20:00:00+00:00" in rendered, (
        "a real comparison names the run it compares against"
    )
    previous_line = next(
        line for line in lines if line.startswith("Previous audit:")
    )
    assert previous_line.split(":", 1)[1].strip(), (
        "a blank date is what a comparison against nothing looks like"
    )


def test_both_locales_carry_the_refusal():
    """Two distinct failures need two distinct sentences, in both languages."""
    for locale in ("en", "fr"):
        data = json.loads(
            Path(f"bob/locales/{locale}.json").read_text(encoding="utf-8")
        )
        entries = data["compare"]["baseline_load"]
        stranger = entries["not_a_baseline"]

        assert "{path}" in stranger, f"{locale}: the refusal must name the file"
        assert stranger != entries["invalid_json"], (
            f"{locale}: 'not JSON' and 'JSON but not a baseline' are "
            "different findings and must not share one sentence"
        )
        assert stranger != entries["bad_shape"]


def test_the_cli_refuses_a_stranger_with_the_error_exit(tmp_path, monkeypatch, capsys):
    """End to end through ``_run``: the refusal is a technical error, exit 3.

    AUTOMATION.md states the exit code, so it is measured here rather than
    read off ``EXIT_ERROR`` — a script that gates on ``--diff`` needs to know
    a refused file does not look like a clean comparison.
    """
    import bob.__main__ as main_mod

    stranger = tmp_path / "stranger.json"
    stranger.write_text('{"unrelated": {"nested": 1}}', encoding="utf-8")
    monkeypatch.setattr(main_mod, "require_root", lambda: None)
    monkeypatch.setenv("HOME", str(tmp_path))

    code = main_mod._run(["--english", f"--diff={stranger}"])

    assert code == 3
    assert "not a BOB baseline" in capsys.readouterr().err
