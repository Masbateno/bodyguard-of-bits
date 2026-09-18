"""A timed-out `apt-get -s dist-upgrade` must not be read as "no updates".

On a mechanical-disk Linux Mint with 468 pending packages, `apt-get -s
dist-upgrade` took 47 s — past the fixed 30 s timeout. `_run` returned an empty
string, indistinguishable from "nothing pending", so `_collect_pending_updates`
returned ([], []) and the host's 322 pending *security* updates were scored as
if it were fully patched. The "absence of an answer read as a negative" class.

The fix runs dist-upgrade through `run_result` (which reports real success) with
a longer timeout, and on any failure falls back to `apt list --upgradable`
(fast, and carrying the same `-security` suite tag), so a slow machine still
gets its security updates counted. Found on a real Mint 22.3 during the v0.20.x
stress pass.
"""

from __future__ import annotations

import bob.checks.updates as U
from bob.checks._run import CommandResult

# --- real output shapes captured on Mint 22.3 (Ubuntu noble base) ----------

_DIST_UPGRADE = """\
Inst accountsservice [23.13.9-2ubuntu6] (23.13.9-2ubuntu6.1 Ubuntu:24.04/noble-security, Ubuntu:24.04/noble-updates [amd64])
Inst amd64-microcode [3.x] (3.y Ubuntu:24.04/noble-security [amd64])
Inst alsa-ucm-conf [1.2.10] (1.2.10-1ubuntu5.14 Ubuntu:24.04/noble-updates [all])
"""

_APT_LIST = """\
Listing...
accountsservice/noble-updates,noble-security 23.13.9-2ubuntu6.1 amd64 [upgradable from: 23.13.9-2ubuntu6]
amd64-microcode/noble-security 3.y amd64 [upgradable from: 3.x]
alsa-ucm-conf/noble-updates 1.2.10-1ubuntu5.14 all [upgradable from: 1.2.10-1ubuntu5.8]
"""


def _fake_run_result(mapping):
    """Return a run_result stand-in keyed on the joined argv.

    A key mapped to None (or absent) simulates a timeout/failure:
    CommandResult(ok=False, code=None) — exactly what run_result yields when
    subprocess.run raises TimeoutExpired.
    """
    def rr(*args, **kwargs):
        entry = mapping.get(" ".join(args))
        if entry is None:
            return CommandResult("", False, "", None)
        return CommandResult(entry, True, "", 0)
    return rr


def test_dist_upgrade_timeout_falls_back_to_apt_list(monkeypatch):
    """The regression: timeout must not zero out the security count."""
    monkeypatch.setattr(U, "run_result", _fake_run_result({
        # "apt-get -s dist-upgrade" absent from the map → timeout
        "apt list --upgradable": _APT_LIST,
    }))
    security, regular = U._collect_pending_updates()
    assert "accountsservice" in security and "amd64-microcode" in security
    assert "alsa-ucm-conf" in regular
    assert len(security) == 2, f"expected 2 security via fallback, got {security}"


def test_dist_upgrade_success_uses_inst_lines(monkeypatch):
    """Primary path unchanged: a fast machine parses dist-upgrade directly."""
    monkeypatch.setattr(U, "run_result", _fake_run_result({
        "apt-get -s dist-upgrade": _DIST_UPGRADE,
    }))
    security, regular = U._collect_pending_updates()
    assert set(security) == {"accountsservice", "amd64-microcode"}
    assert regular == ["alsa-ucm-conf"]


def test_both_sources_failing_is_empty_not_a_lie(monkeypatch):
    """When neither command runs, return empty — genuinely undetermined.
    (The caller's upgradable_count cross-check then reports it honestly.)"""
    monkeypatch.setattr(U, "run_result", _fake_run_result({}))
    assert U._collect_pending_updates() == ([], [])


def test_pkg_from_inst_and_list_parsers():
    assert U._pkg_from_inst("Inst foo [1] (2 Ubuntu:24.04/noble-security [amd64])") == "foo"
    assert U._pkg_from_inst("Reading package lists...") is None
    assert U._pkg_from_list("foo/noble-security 1 amd64 [upgradable from: 0]") == "foo"
    assert U._pkg_from_list("Listing...") is None
    assert U._pkg_from_list("WARNING: apt does not have a stable CLI interface") is None


def test_security_classification_matches_the_security_suite():
    lines = [
        "foo/noble-updates,noble-security 1 amd64 [upgradable from: 0]",
        "bar/noble-updates 1 amd64 [upgradable from: 0]",
    ]
    sec, reg = U._classify_apt_lines(lines, U._pkg_from_list)
    assert sec == ["foo"] and reg == ["bar"]
