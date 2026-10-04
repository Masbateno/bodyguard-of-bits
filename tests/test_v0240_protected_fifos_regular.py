"""fs.protected_fifos / fs.protected_regular — completing the fs.protected_* family.

``hardening`` already audited fs.protected_hardlinks and fs.protected_symlinks;
the two siblings that block the /tmp O_CREAT race against an attacker-planted
FIFO or regular file were missing. Unlike their siblings they take 0/1/2
(2 strengthens 1), so the guard pins three things:

  1. 0 is a WARN with a deduction, 1 and 2 are both OK — "2" must never be read
     as disabled (the bool sysctl reader treats only "1" as set);
  2. an unreadable value is reported as unavailable, never as OK;
  3. from_system() really reads "2" as 2 from /proc/sys.
"""

from __future__ import annotations

import pathlib

import pytest

from bob.checks import hardening
from bob.checks.hardening import HardeningSnapshot, check_hardening
from tests.helpers import _t
from tests.test_hardening import make_snapshot


def _keys(result):
    return [f.key for f in result.findings]


@pytest.mark.parametrize("field", ["protected_fifos", "protected_regular"])
class TestLevels:
    def test_zero_is_a_deducting_warning(self, field):
        result = check_hardening(make_snapshot(**{field: 0}), t=_t)
        assert f"hardening.{field}_disabled" in _keys(result)
        assert any(d.key == f"hardening.{field}_disabled" for d in result.deductions)

    @pytest.mark.parametrize("level", [1, 2])
    def test_one_and_two_are_ok(self, field, level):
        result = check_hardening(make_snapshot(**{field: level}), t=_t)
        assert f"hardening.{field}_ok" in _keys(result)
        assert f"hardening.{field}_disabled" not in _keys(result)

    def test_unreadable_is_unavailable_not_ok(self, field):
        result = check_hardening(make_snapshot(**{field: None}), t=_t)
        assert f"hardening.{field}_ok" not in _keys(result)
        assert "hardening.params_unavailable" in _keys(result)


class TestFromSystemReadsTwoAsTwo:
    def test_level_two_survives_the_read(self, tmp_path, monkeypatch):
        fs = tmp_path / "fs"
        fs.mkdir()
        (fs / "protected_fifos").write_text("2\n")
        (fs / "protected_regular").write_text("2\n")
        real = pathlib.Path
        monkeypatch.setattr(
            hardening, "Path",
            lambda p, *a: tmp_path if str(p) == "/proc/sys" else real(p, *a),
        )
        snap = HardeningSnapshot.from_system()
        assert snap.protected_fifos == 2
        assert snap.protected_regular == 2
        keys = _keys(check_hardening(snap, t=_t))
        assert "hardening.protected_fifos_ok" in keys
        assert "hardening.protected_regular_ok" in keys
