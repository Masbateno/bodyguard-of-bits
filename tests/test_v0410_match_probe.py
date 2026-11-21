"""v0.41.0 — a Match setting an earlier block may override: sshd asked (B-001).

Decided with the user (21 November 2026), after a measurement on OpenSSH 9.6p1:
with ``Match Address 192.0.2.0/24,!192.0.2.5`` setting ``PasswordAuthentication
no`` then ``Match Address 192.0.2.0/25`` setting ``yes``, ``sshd -T -C`` gives
``no`` from 192.0.2.1 and ``yes`` from 192.0.2.5. One representative connection
would have called the later block covered and hidden that password login. So
sshd's answer never removes a setting: BOB looks for a witness — a connection
where the later value applies — and says it; found or not, the setting is
counted, exactly as in 0.40.0.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from bob import i18n
from bob.checks.ssh import _probe as P


@pytest.fixture(autouse=True)
def _english():
    before = i18n.current_lang()
    i18n.init("en")
    yield
    i18n.init(before)


class TestTheConnectionsTried:
    def test_the_earlier_blocks_exclusion_is_tried(self):
        specs = P.connections("Address 192.0.2.0/25", ["Address 192.0.2.0/24,!192.0.2.5"])
        addrs = [s["addr"] for s in specs]
        assert "192.0.2.5" in addrs and addrs[0] == "192.0.2.1"
        assert all(a.startswith("192.0.2.") and int(a.rsplit(".", 1)[1]) < 128 for a in addrs)

    def test_the_edges_of_an_earlier_range(self):
        specs = P.connections("Address 192.0.2.0/24", ["Address 192.0.2.0/25"])
        assert "192.0.2.128" in [s["addr"] for s in specs]          # just past the earlier range

    def test_a_negated_entry_of_the_later_block_is_never_tried(self):
        specs = P.connections("Address 192.0.2.0/24,!192.0.2.1", ["Address 192.0.2.0/25"])
        assert "192.0.2.1" not in [s["addr"] for s in specs]

    def test_an_account_the_earlier_block_leaves_out(self):
        specs = P.connections("User alice,bob", ["User *,!bob"])
        assert {s["user"] for s in specs} >= {"alice", "bob"}

    def test_a_criterion_only_the_earlier_block_has(self):
        """The later block takes every address; the earlier one some: an
        address outside it is tried."""
        specs = P.connections("User alice", ["User alice Address 192.0.2.0/24"])
        assert P.NEUTRAL["addr"] in [s["addr"] for s in specs]

    def test_bounded(self):
        many = ",".join(f"!192.0.2.{i}" for i in range(1, 60))
        assert len(P.connections("Address 192.0.2.0/24", [f"Address 192.0.2.0/24,{many}"])) <= P.MAX_TRIES

    def test_unreadable_criteria_try_nothing(self):
        assert P.connections("Address", ["User a"]) == []


class TestWhatIsRecorded:
    def _config(self):
        return {"_match_blocks": [
            {"criteria": "Address 192.0.2.0/24,!192.0.2.5", "settings": {"passwordauthentication": "no"}, "file": "f"},
            {"criteria": "Address 192.0.2.0/25", "settings": {"passwordauthentication": "yes"}, "file": "f"}]}

    def test_a_witness_is_kept(self, monkeypatch):
        monkeypatch.setattr(P.os, "geteuid", lambda: 0)
        monkeypatch.setattr(P, "ask_sshd", lambda s, c, spec: {"passwordauthentication":
                                                               "yes" if spec["addr"] == "192.0.2.5" else "no"})
        cfg = self._config()
        P.probe_blocks(cfg, Path("x"), "/usr/sbin/sshd")
        probe = cfg["_match_blocks"][1]["probe"]["passwordauthentication"]
        assert probe["applies"] == "addr=192.0.2.5" and probe["earlier"] == "Address 192.0.2.0/24,!192.0.2.5"

    def test_no_witness_is_said_unproven(self, monkeypatch):
        monkeypatch.setattr(P.os, "geteuid", lambda: 0)
        monkeypatch.setattr(P, "ask_sshd", lambda s, c, spec: {"passwordauthentication": "no"})
        cfg = self._config()
        P.probe_blocks(cfg, Path("x"), "/usr/sbin/sshd")
        probe = cfg["_match_blocks"][1]["probe"]["passwordauthentication"]
        assert probe["applies"] is None and probe["tried"] >= 3

    @pytest.mark.parametrize("sshd, euid, answer, reason", [(None, 0, {}, "sshd"),
                                                            ("/usr/sbin/sshd", 0, None, "answer")])
    def test_sshd_that_cannot_answer_is_said(self, monkeypatch, sshd, euid, answer, reason):
        monkeypatch.setattr(P.os, "geteuid", lambda: euid)
        monkeypatch.setattr(P, "ask_sshd", lambda *a: answer)
        cfg = self._config()
        P.probe_blocks(cfg, Path("x"), sshd)
        assert cfg["_match_probe_unavailable"] == {"reason": reason, "count": 1}

    def test_nothing_asked_when_nothing_conflicts(self, monkeypatch):
        asked = []
        monkeypatch.setattr(P.os, "geteuid", lambda: 0)
        monkeypatch.setattr(P, "ask_sshd", lambda *a: asked.append(a))
        cfg = {"_match_blocks": [{"criteria": "User a", "settings": {"x11forwarding": "yes"}, "file": "f"}]}
        P.probe_blocks(cfg, Path("x"), "/usr/sbin/sshd")
        assert asked == [] and "_match_probe_unavailable" not in cfg


class TestTheFindingStaysCounted:
    """The decision itself: sshd's answer adds a proof or a doubt, never
    removes the deduction."""

    def _run(self, probe, monkeypatch):
        from bob.checks.ssh import _subchecks as S
        from bob.checks.ssh import check_ssh
        from tests.test_ssh import base_snapshot
        monkeypatch.setattr(S, "_match_reaches_an_account", lambda c: True)
        cfg = {"passwordauthentication": "no", "maxauthtries": "3", "permitrootlogin": "no", "_match_blocks": [
            {"criteria": "Address 192.0.2.0/24,!192.0.2.5", "settings": {"passwordauthentication": "no"}, "file": "f"},
            {"criteria": "Address 192.0.2.0/25", "settings": {"passwordauthentication": "yes"}, "file": "f",
             **({"probe": {"passwordauthentication": probe}} if probe else {})}]}
        return check_ssh(base_snapshot(sshd_config=cfg))

    @pytest.mark.parametrize("applies", ["addr=192.0.2.5", None])
    def test_counted_with_or_without_a_witness(self, applies, monkeypatch):
        probe = {"applies": applies, "tried": 5, "earlier": "Address 192.0.2.0/24,!192.0.2.5", "value": "yes"}
        with_probe, without = self._run(probe, monkeypatch), self._run(None, monkeypatch)
        assert [(d.key, d.points) for d in with_probe.deductions] == [(d.key, d.points) for d in without.deductions]
        assert "ssh.password_auth" in {d.key for d in with_probe.deductions}
        key = "ssh.match_block_probe_applies" if applies else "ssh.match_block_probe_unproven"
        said = [f for f in with_probe.findings if f.key == key]
        assert len(said) == 1
        assert said[0].template_vars["connection"] == (applies or "") and said[0].template_vars["count"] == 5


@pytest.mark.skipif(not shutil.which("sshd") and not Path("/usr/sbin/sshd").exists(), reason="no sshd here")
def test_the_measured_case_with_this_hosts_sshd(tmp_path, monkeypatch):
    """The case of the decision, asked of the real sshd: the witness is found."""
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(tmp_path / "hk")], check=True)
    cfg = tmp_path / "sshd_config"
    cfg.write_text(f"HostKey {tmp_path / 'hk'}\nPasswordAuthentication no\n"
                   "Match Address 192.0.2.0/24,!192.0.2.5\n    PasswordAuthentication no\n"
                   "Match Address 192.0.2.0/25\n    PasswordAuthentication yes\n")
    if P.ask_sshd(sshd, cfg, dict(P.NEUTRAL)) is None:
        pytest.skip("this sshd does not answer -T here")
    monkeypatch.setattr(P.os, "geteuid", lambda: 0)
    config = {"_match_blocks": [
        {"criteria": "Address 192.0.2.0/24,!192.0.2.5", "settings": {"passwordauthentication": "no"}, "file": str(cfg)},
        {"criteria": "Address 192.0.2.0/25", "settings": {"passwordauthentication": "yes"}, "file": str(cfg)}]}
    P.probe_blocks(config, cfg, sshd)
    assert config["_match_blocks"][1]["probe"]["passwordauthentication"]["applies"] == "addr=192.0.2.5"


def test_end_to_end_no_witness_keeps_the_deduction(monkeypatch):
    """The sshd answer recorded by the snapshot, then the check: without a
    witness the setting is still weighed."""
    from bob.checks.ssh import _subchecks as S
    from bob.checks.ssh import check_ssh
    from tests.test_ssh import base_snapshot
    monkeypatch.setattr(S, "_match_reaches_an_account", lambda c: True)
    monkeypatch.setattr(P.os, "geteuid", lambda: 0)
    monkeypatch.setattr(P, "ask_sshd", lambda *a: {"passwordauthentication": "no"})
    cfg = {"passwordauthentication": "no", "maxauthtries": "3", "permitrootlogin": "no", "_match_blocks": [
        {"criteria": "Address 192.0.2.0/24,!192.0.2.5", "settings": {"passwordauthentication": "no"}, "file": "f"},
        {"criteria": "Address 192.0.2.0/25", "settings": {"passwordauthentication": "yes"}, "file": "f"}]}
    P.probe_blocks(cfg, Path("x"), "/usr/sbin/sshd")
    r = check_ssh(base_snapshot(sshd_config=cfg))
    assert "ssh.password_auth" in {d.key for d in r.deductions}
    assert any(f.key == "ssh.match_block_probe_unproven" for f in r.findings)


@pytest.mark.parametrize("reason, said", [("sshd", True), ("answer", True), ("root", False)])
def test_sshd_unavailable_is_said(monkeypatch, reason, said):
    """Said when sshd is missing or silent; not for a run without root, which
    BOB refuses for an audit anyway (only the test suite gets there)."""
    from bob.checks.ssh import _subchecks as S
    from bob.checks.ssh import check_ssh
    from tests.test_ssh import base_snapshot
    monkeypatch.setattr(S, "_match_reaches_an_account", lambda c: True)
    cfg = {"passwordauthentication": "no", "_match_probe_unavailable": {"reason": reason, "count": 2},
           "_match_blocks": [{"criteria": "User a", "settings": {"x11forwarding": "yes"}, "file": "f"}]}
    r = check_ssh(base_snapshot(sshd_config=cfg))
    assert any(f.key == "ssh.match_block_probe_unavailable" for f in r.findings) is said
