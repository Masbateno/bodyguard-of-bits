"""v0.37.0 — a k3s agent (second node): its kubelet asked, its API server named.

Measured on openSUSE Leap 15.6 joined as an agent to a Fedora 43 k3s server,
k3s v1.37.2+k3s1 (binary sha256 265b3ee6…; a10370, 14 November 2026):

- the kubelet runs in a root process named `k3s-agent` on *:10250; its
  certificate is issued by k3s-server-ca (SAN 127.0.0.1), verified by
  /var/lib/rancher/k3s/agent/server-ca.crt — not by client-ca.crt;
- anonymous GET /pods: 401 by default; 200 with --kubelet-arg=anonymous-auth=true
  --kubelet-arg=authorization-mode=AlwaysAllow;
- no API server on the node: 127.0.0.1:6444 is the agent's proxy to the
  server's, whose address k3s keeps in agent/etc/k3s-agent-load-balancer.json.

0.36.0 knew no authority for `k3s-agent`: "the kubelet was not asked", a ceiling
— and with the kubelet open to anyone (200) it said exactly the same. 0.37.0:
401 → OK; 200 → ALERT kubernetes.kubelet_anonymous −3; the API server named on
the node it runs on (a ceiling here, as before).
"""

from __future__ import annotations

import json

from bob.checks import kubernetes as k


def test_the_agents_kubelet_is_checked_against_the_agents_copy_of_the_server_ca():
    assert k._kubelet_ca("k3s-agent") == k._K3S_AGENT_CA
    assert str(k._K3S_AGENT_CA) == "/var/lib/rancher/k3s/agent/server-ca.crt"


def _lb(tmp_path, monkeypatch, content, server_running=False):
    f = tmp_path / "k3s-agent-load-balancer.json"
    f.write_text(content)
    monkeypatch.setattr(k, "_K3S_AGENT_LB", f)
    monkeypatch.setattr(k, "_pids_named", lambda name: ["1"] if server_running and name == "k3s-server" else [])
    return k._k3s_agent_server()


def test_the_server_it_joins_is_read_from_k3s_state(tmp_path, monkeypatch):
    content = json.dumps({"ServerURL": "https://192.0.2.10:6443", "ServerAddresses": ["192.0.2.10:6443"]})
    assert _lb(tmp_path, monkeypatch, content) == "https://192.0.2.10:6443"


def test_a_url_that_is_not_a_plain_https_address_is_not_shown(tmp_path, monkeypatch):
    for url in ("https://192.0.2.10:6443/x", "http://192.0.2.10:6443", "https://a b", "https://x\u001b[2J"):
        assert _lb(tmp_path, monkeypatch, json.dumps({"ServerURL": url})) == "", url


def test_a_node_that_runs_a_server_is_not_an_agent(tmp_path, monkeypatch):
    content = json.dumps({"ServerURL": "https://192.0.2.10:6443"})
    assert _lb(tmp_path, monkeypatch, content, server_running=True) == ""


def test_read_apiserver_names_it_on_an_agent(monkeypatch):
    monkeypatch.setattr(k, "_microk8s_runs", lambda: False)
    monkeypatch.setattr(k, "_read_k3s_apiserver", lambda snap: None)
    monkeypatch.setattr(k, "_read_kube_apiserver_process", lambda snap: None)
    monkeypatch.setattr(k, "_k3s_agent_server", lambda: "https://192.0.2.10:6443")
    snap = k.KubernetesSnapshot(kubelet_listener="k3s-agent")
    k._read_apiserver(snap)
    assert snap.apiserver_elsewhere == "https://192.0.2.10:6443"
    other = k.KubernetesSnapshot(kubelet_listener="kubelet")
    k._read_apiserver(other)
    assert other.apiserver_elsewhere == ""


def test_the_check_names_the_server_and_keeps_the_ceiling():
    from bob.visibility import VISIBILITY_KEYS
    snap = k.KubernetesSnapshot(kubelet_running=True, kubelet_listener="k3s-agent", anonymous_status=401,
                                apiserver_elsewhere="https://192.0.2.10:6443")
    r = k.check_kubernetes(snap, t=lambda key, **v: f"{key} {v}")
    keys = {f.key for f in r.findings}
    assert "kubernetes.apiserver_elsewhere" in keys and "kubernetes.apiserver_unread" not in keys
    f = next(f for f in r.findings if f.key == "kubernetes.apiserver_elsewhere")
    assert "192.0.2.10" in f.message
    assert "kubernetes.apiserver_elsewhere" in VISIBILITY_KEYS
