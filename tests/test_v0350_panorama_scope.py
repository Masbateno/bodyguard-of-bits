"""v0.35.0 — the panorama names the reach the services section concluded.

A field audit (Mint desktop, 12 November 2026) showed ✔ in the SCOPE column
beside Avahi, CUPS, Ollama, OpenVPN, Samba and SMTP. ✔ stood for any raw
exposure but OPEN_WORLD, read before the firewall context: a port no rule
covers was ✔ on a host with no firewall, where the services section said "no
active firewall protection", and at UFW default allow, where it said everyone
reaches it.
"""

from __future__ import annotations

import re

import pytest

from bob.checks.services import Exposure, PORT_SCOPES, _port_scope, check_services
from bob.panorama import build_panorama_rows
from tests.test_services import make_service, make_snapshot
from bob.checks.services import ServiceState


@pytest.mark.parametrize("args, want", [
    ((Exposure.OPEN_WORLD, "services.exposure.open_world", None, None, False, False), "anyone"),
    ((Exposure.OPEN_LOCAL, "services.exposure.open_local", None, None, False, False), "lan"),
    ((Exposure.OPEN_LOCAL, "services.exposure.open_local", None, None, False, True), "host"),
    ((Exposure.OPEN_LOCAL, "services.exposure.open_local", None, None, True, True), "unknown"),
    ((Exposure.DENY, "services.exposure.deny", None, None, False, False), "denied"),
    ((Exposure.NO_RULE, "services.exposure.no_rule", None, None, False, False), "denied"),
    ((Exposure.NO_RULE, "services.exposure.no_rule_ufw_inactive", None, None, False, False), "unfiltered"),
    ((Exposure.NO_RULE, "services.exposure.no_rule_netfilter", None, None, False, False), "unknown"),
    ((Exposure.NO_RULE, "services.exposure.no_rule_netfilter", "ports.netfilter_port.drop_default", None, False, False), "denied"),
    ((Exposure.NO_RULE, "services.exposure.no_rule_netfilter", "ports.netfilter_port.accept_rule", None, False, False), "accepted"),
    ((Exposure.NO_RULE, "services.exposure.no_rule_policy_unread", None, None, False, False), "unknown"),
    ((Exposure.NO_RULE, "services.exposure.deny", None, None, False, False), "unknown"),
    ((Exposure.LOOPBACK, "services.exposure.loopback", None, None, False, False), "this_host"),
    ((Exposure.LOOPBACK_NO_RULE, "services.exposure.loopback_localnet", None, "on", False, False), "unknown"),
    ((Exposure.LOOPBACK, "services.exposure.loopback_localnet_unread", None, "unread", False, False), "unknown"),
    ((Exposure.NOT_LISTENING, "services.exposure.not_listening", None, None, False, False), "no_listener"),
])
def test_each_reach(args, want):
    assert _port_scope(*args) == want


def _checked(exposure, **kw):
    snap = make_snapshot(state=ServiceState.ACTIVE_ENABLED, exposures={"631/tcp": exposure})
    check_services([snap], **kw)
    return snap.port_scope["631/tcp"]


def test_no_rule_without_any_firewall_is_unfiltered_not_a_tick():
    assert _checked(Exposure.NO_RULE, ufw_active=False) == "unfiltered"


def test_no_rule_at_ufw_default_allow_is_anyone():
    assert _checked(Exposure.NO_RULE, ufw_active=True, ufw_incoming_policy="allow") == "anyone"


def test_no_rule_at_ufw_default_deny_is_denied():
    assert _checked(Exposure.NO_RULE, ufw_active=True, ufw_incoming_policy="deny") == "denied"


def test_the_widest_reach_of_a_service_is_shown():
    snap = make_snapshot(service=make_service(ports=("445/tcp", "139/tcp")), state=ServiceState.ACTIVE_ENABLED,
                         ports=["445/tcp", "139/tcp"],
                         exposures={"445/tcp": Exposure.OPEN_LOCAL, "139/tcp": Exposure.DENY})
    rows = build_panorama_rows([snap], {snap.service.id: {"445/tcp": "lan", "139/tcp": "denied"}})
    assert rows[0]["scope"] == "lan"
    rows = build_panorama_rows([snap], {snap.service.id: {"445/tcp": "denied", "139/tcp": "unfiltered"}})
    assert (rows[0]["scope"], rows[0]["ufw"]) == ("unfiltered", "warn")


def test_scopes_are_ordered_widest_first():
    assert PORT_SCOPES.index("anyone") < PORT_SCOPES.index("lan") < PORT_SCOPES.index("denied")


def _printed(capsys, rows, lang):
    import json
    from pathlib import Path
    from bob import output
    pan = json.loads(Path(f"bob/locales/{lang}.json").read_text())["services"]["panorama"]
    pan = dict(pan, **{f"scope_{k}": v for k, v in pan["scope"].items()})
    output.print_services_panorama(rows, pan)
    return re.sub(r"\x1b\[[0-9;]*m", "", capsys.readouterr().out)


@pytest.mark.parametrize("lang", ["en", "fr"])
def test_the_word_is_printed_and_the_line_fits(capsys, lang):
    rows = [dict(label="Avahi (local network discovery)", status="active", ports="445/tcp, 139/tcp",
                 ufw="ok", scope=s, risk="") for s in PORT_SCOPES]
    rows.append(dict(label="Gitea", status="not_installed", ports="—", ufw="na", scope="na", risk=""))
    out = _printed(capsys, rows, lang)
    lines = out.splitlines()
    assert "✔" not in out
    for s, line in zip(PORT_SCOPES, lines[2:]):
        assert line.rstrip().endswith(__import__("json").loads(
            __import__("pathlib").Path(f"bob/locales/{lang}.json").read_text())["services"]["panorama"]["scope"][s])
    assert max(len(ln) for ln in lines) <= 80


def test_a_cut_port_list_says_so(capsys):
    rows = [dict(label="X", status="active", ports="8080/tcp, 8443/tcp, 9000/tcp", ufw="ok", scope="lan", risk="")]
    assert "8080/tcp, 8443/tcp,…" in _printed(capsys, rows, "en")


def test_run_checks_hands_the_concluded_reach_to_the_panorama(tmp_path, monkeypatch):
    import contextlib
    import io

    from bob import i18n, runner
    from bob.cli import parse_args
    from bob.config import UserConfig
    from bob.profiles import load_profile
    from bob.registry import ServiceRegistry
    from bob.scoring import ScoreEngine

    snap = make_snapshot(state=ServiceState.ACTIVE_ENABLED, exposures={"631/tcp": Exposure.NOT_LISTENING})
    monkeypatch.setattr(runner.ServiceSnapshot, "collect", classmethod(lambda cls, registry, **kw: [snap]))
    seen = {}
    monkeypatch.setattr(runner, "display_services_panorama",
                        lambda *a, port_scopes=None, **kw: seen.setdefault("scopes", port_scopes))
    i18n.init("en")
    config = parse_args(["--offline"])
    user_config = UserConfig(path=tmp_path / "config.conf")
    profile = load_profile("server")
    engine = ScoreEngine(profile=profile)
    report = runner.init_report(config, user_config, i18n.t, "0.0.0-test")
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        runner.run_checks(config, i18n.t, engine, report, ServiceRegistry.load(), "local",
                          profile=profile, prev_recurrence={}, user_config=user_config)
    assert seen["scopes"] == {snap.service.id: {"631/tcp": "no_listener"}}


def test_the_display_shows_the_handed_reach(monkeypatch, capsys):
    from bob import i18n
    from bob.checks.services import ServiceSnapshot
    from bob.display import display_services_panorama
    snap = make_snapshot(state=ServiceState.ACTIVE_ENABLED, exposures={"631/tcp": Exposure.NO_RULE})
    monkeypatch.setattr(ServiceSnapshot, "collect_all", classmethod(lambda cls, registry, **kw: [snap]))
    i18n.init("fr")
    display_services_panorama(None, "", set(), set(), None, i18n.t,
                              port_scopes={snap.service.id: {"631/tcp": "unfiltered"}})
    out = re.sub(r"\x1b\[[0-9;]*m", "", capsys.readouterr().out)
    assert "⚠ non filtré" in out


def test_not_installed_keeps_the_dash_and_not_examined_is_said(capsys):
    """Decided after review: "—" for a service that is not installed, "not
    examined" for an installed one the services section did not examine."""
    from bob.checks.services import ServiceState
    absent = make_snapshot(state=ServiceState.INACTIVE_DISABLED, exposures={})
    absent.installed = False
    assert build_panorama_rows([absent])[0]["scope"] == "na"
    rows = [dict(label="X", status="inactive", ports="631/tcp", ufw="na", scope="not_examined", risk="")]
    assert _printed(capsys, rows, "fr").rstrip().endswith("non examiné")


def test_the_dash_means_not_installed_and_nothing_else():
    """After review 3: an installed service with no recorded reach and no port
    is "not examined", not the "—" of a service that is not installed."""
    from bob.checks.services import ServiceState
    snap = make_snapshot(state=ServiceState.ACTIVE_ENABLED, exposures={})
    assert build_panorama_rows([snap])[0]["scope"] == "not_examined"
