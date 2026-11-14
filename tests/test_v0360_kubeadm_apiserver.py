"""v0.36.0 — kubeadm's API server read from its process.

Until 0.36.0 BOB read the API server's arguments on MicroK8s (its args file)
and on a k3s server (its journal); on kubeadm it said "the API server is not
read", the score a ceiling. Measured on kubeadm 1.37.2 (Debian 13, a10360,
14 November 2026): one `kube-apiserver` process, uid 0, its command line
`--authorization-mode=Node,RBAC --secure-port=6443
--client-ca-file=/etc/kubernetes/pki/ca.crt`; the certificate on 6443
verified by that client CA; an anonymous GET /api/v1/namespaces → 403;
`kubectl --kubeconfig=/etc/kubernetes/admin.conf get clusterrolebindings` → 62.
"""

from __future__ import annotations

from pathlib import Path

from bob.checks import kubernetes as k

_ARGV = ["kube-apiserver", "--advertise-address=192.168.1.12", "--allow-privileged=true",
         "--authorization-mode=Node,RBAC", "--client-ca-file=/etc/kubernetes/pki/ca.crt",
         "--secure-port=6443", "--tls-cert-file=/etc/kubernetes/pki/apiserver.crt"]


def _proc(tmp_path, monkeypatch, procs):
    proc = tmp_path / "proc"
    for pid, comm, argv, uid in procs:
        d = proc / pid
        d.mkdir(parents=True)
        (d / "comm").write_text(comm + "\n")
        (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
        (d / "status").write_text(f"Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
    monkeypatch.setattr(k, "_PROC", proc)
    monkeypatch.setattr(k, "_host_user_ids", lambda: True)


def _read(monkeypatch, probe_calls):
    monkeypatch.setattr(k, "_probe_apiserver", lambda snap, ca: probe_calls.append(ca))
    monkeypatch.setattr(k, "_command_exists", lambda n: False)
    snap = k.KubernetesSnapshot()
    k._read_kube_apiserver_process(snap)
    return snap


def test_the_measured_process(tmp_path, monkeypatch):
    _proc(tmp_path, monkeypatch, [("27145", "kube-apiserver", _ARGV, 0)])
    calls = []
    snap = _read(monkeypatch, calls)
    assert snap.authorization_modes == ("Node", "RBAC") and snap.apiserver_port == 6443
    assert calls == [Path("/etc/kubernetes/pki/ca.crt")]


def test_a_process_not_run_by_root_is_not_read(tmp_path, monkeypatch):
    _proc(tmp_path, monkeypatch, [("27145", "kube-apiserver", _ARGV, 1000)])
    calls = []
    snap = _read(monkeypatch, calls)
    assert snap.authorization_modes is None and calls == []


def test_two_api_servers_are_not_told_apart(tmp_path, monkeypatch):
    _proc(tmp_path, monkeypatch, [("1", "kube-apiserver", _ARGV, 0), ("2", "kube-apiserver", _ARGV, 0)])
    calls = []
    assert _read(monkeypatch, calls).authorization_modes is None


def test_always_allow_is_read_as_written(tmp_path, monkeypatch):
    argv = [a.replace("Node,RBAC", "AlwaysAllow") for a in _ARGV]
    _proc(tmp_path, monkeypatch, [("9", "kube-apiserver", argv, 0)])
    assert _read(monkeypatch, []).authorization_modes == ("AlwaysAllow",)


def test_it_is_read_after_microk8s_and_k3s(monkeypatch):
    order = []
    monkeypatch.setattr(k, "_microk8s_runs", lambda: False)
    monkeypatch.setattr(k, "_read_k3s_apiserver", lambda snap: order.append("k3s"))
    monkeypatch.setattr(k, "_read_kube_apiserver_process", lambda snap: order.append("process"))
    k._read_apiserver(k.KubernetesSnapshot())
    assert order == ["k3s", "process"]


def test_a_read_k3s_server_is_not_read_twice(monkeypatch):
    order = []
    monkeypatch.setattr(k, "_microk8s_runs", lambda: False)

    def k3s(snap):
        snap.authorization_modes = ("Node", "RBAC")
    monkeypatch.setattr(k, "_read_k3s_apiserver", k3s)
    monkeypatch.setattr(k, "_read_kube_apiserver_process", lambda snap: order.append("process"))
    k._read_apiserver(k.KubernetesSnapshot())
    assert order == []
