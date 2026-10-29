"""v0.28.0 — the cluster beyond the node (lot 1): API server, RBAC, runtime socket.

Measured on the Ubuntu Server 26.04 (MicroK8s 1.35.6, 25 October 2026):

  - the API server's args file (/var/snap/microk8s/current/args/kube-apiserver)
    gave --authorization-mode=AlwaysAllow and --secure-port=16443; `microk8s
    enable rbac` set it to RBAC,Node and a default service account could no
    longer list secrets;
  - an anonymous GET /api/v1/namespaces answered 401 under AlwaysAllow (the
    stock --anonymous-auth=false) and 403 under RBAC,Node — both refusals;
  - the stock cluster-admin binding is to Group/system:masters (not broad); a
    binding to Group/system:authenticated was flagged −3, then deleted;
  - the containerd socket was /var/snap/microk8s/common/run/containerd.sock,
    mode 0660, group microk8s with no members.

The anonymous-read 2xx branch (apiserver answers an anonymous request) could
not be produced on this node (--anonymous-auth did not take effect) and is
covered here by a built snapshot, not claimed as measured.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.checks.kubernetes import KubernetesSnapshot, check_kubernetes


def _snap(**kw):
    base = dict(kubelet_running=True, workloads_read=True, anonymous_status=401, run_probed=False)
    base.update(kw)
    return KubernetesSnapshot(**base)


def _check(snap, lang="en"):
    i18n.init(lang)
    try:
        r = check_kubernetes(snap, t=i18n.t)
    finally:
        i18n.init("en")
    return {f.key: f for f in r.findings}, {d.key: d.points for d in r.deductions}


class TestApiServer:

    def test_always_allow_is_an_alert(self):
        f, d = _check(_snap(authorization_modes=("AlwaysAllow",), apiserver_port=16443,
                            apiserver_anonymous_status=401))
        assert f["kubernetes.apiserver_always_allow"].level.value == "alert"
        assert d["kubernetes.apiserver_always_allow"] == 2
        assert "kubernetes.apiserver_anonymous_refused" in f

    def test_anonymous_2xx_is_a_warning_for_what_it_establishes(self):
        """After review (round 1): a 2xx on GET /api/v1/namespaces establishes
        anonymous namespace listing, not every read — WARN −1, as the kubelet's
        anonymous read. Under AlwaysAllow the two findings add up (−3)."""
        f, d = _check(_snap(authorization_modes=("RBAC", "Node"), apiserver_port=16443,
                            apiserver_anonymous_status=200, broad_admin_bindings=[]))
        assert f["kubernetes.apiserver_anonymous"].level.value == "warn"
        assert d["kubernetes.apiserver_anonymous"] == 1
        f2, d2 = _check(_snap(authorization_modes=("AlwaysAllow",), apiserver_port=16443,
                              apiserver_anonymous_status=200))
        assert d2["kubernetes.apiserver_anonymous"] + d2["kubernetes.apiserver_always_allow"] == 3

    @pytest.mark.parametrize("lang, words", [("en", "lets anonymous requests list namespaces"),
                                             ("fr", "laisse des requêtes anonymes lister les namespaces")])
    def test_the_anonymous_text_says_what_is_established(self, lang, words):
        f, _ = _check(_snap(authorization_modes=("RBAC", "Node"), apiserver_port=16443,
                            apiserver_anonymous_status=200, broad_admin_bindings=[]), lang)
        assert words in f["kubernetes.apiserver_anonymous"].message

    @pytest.mark.parametrize("status", [401, 403])
    def test_a_refused_read_is_ok_not_scored(self, status):
        f, d = _check(_snap(authorization_modes=("RBAC", "Node"), apiserver_port=16443,
                            apiserver_anonymous_status=status, broad_admin_bindings=[]))
        assert f["kubernetes.apiserver_anonymous_refused"].level.value == "ok"
        assert "kubernetes.apiserver_anonymous" not in d

    def test_an_unprobed_read_is_inconclusive(self):
        f, _ = _check(_snap(authorization_modes=("RBAC", "Node"), apiserver_port=16443,
                            apiserver_anonymous_status=None, broad_admin_bindings=[]))
        assert "kubernetes.apiserver_anonymous_unprobed" in f

    def test_an_unread_args_file_says_nothing(self):
        f, d = _check(_snap(authorization_modes=None))
        assert not any(k.startswith("kubernetes.apiserver") or k.startswith("kubernetes.cluster") for k in f)

    def test_a_mode_bob_does_not_weigh_is_said(self):
        f, _ = _check(_snap(authorization_modes=("Webhook", "Node"), apiserver_port=16443,
                            apiserver_anonymous_status=403))
        assert "kubernetes.apiserver_authz_unread" in f


class TestClusterAdmin:

    def test_stock_masters_binding_is_ok(self):
        f, d = _check(_snap(authorization_modes=("RBAC", "Node"), apiserver_anonymous_status=403,
                            broad_admin_bindings=[]))
        assert f["kubernetes.cluster_admin_ok"].level.value == "ok" and not d

    def test_a_broad_binding_is_an_alert(self):
        f, d = _check(_snap(authorization_modes=("RBAC", "Node"), apiserver_anonymous_status=403,
                            broad_admin_bindings=["x: Group/system:authenticated"]))
        assert f["kubernetes.cluster_admin_broad"].level.value == "alert"
        assert d["kubernetes.cluster_admin_broad"] == 3
        assert "system:authenticated" in f["kubernetes.cluster_admin_broad"].message

    def test_unread_bindings_say_so(self):
        f, _ = _check(_snap(authorization_modes=("RBAC", "Node"), apiserver_anonymous_status=403,
                            broad_admin_bindings=None))
        assert "kubernetes.cluster_admin_unread" in f

    def test_the_broad_subjects_set(self):
        import json
        from bob.checks.kubernetes import _broad_admin_bindings
        raw = json.dumps({"items": [
            {"metadata": {"name": "a"}, "roleRef": {"name": "cluster-admin"},
             "subjects": [{"kind": "Group", "name": "system:masters"}]},
            {"metadata": {"name": "b"}, "roleRef": {"name": "cluster-admin"},
             "subjects": [{"kind": "Group", "name": "system:authenticated"}]},
            {"metadata": {"name": "c"}, "roleRef": {"name": "view"},
             "subjects": [{"kind": "User", "name": "system:anonymous"}]},
        ]})
        assert _broad_admin_bindings(raw) == ["b: Group/system:authenticated"]


class TestRuntimeSocket:

    def test_world_writable_is_an_alert(self):
        f, d = _check(_snap(runtime_socket=("/run/containerd/containerd.sock", 0o666, "root", ())))
        assert f["kubernetes.runtime_socket_open"].level.value == "alert"
        assert d["kubernetes.runtime_socket_open"] == 3

    def test_group_writable_with_members_is_info(self):
        f, d = _check(_snap(runtime_socket=("/x.sock", 0o660, "microk8s", ("so6",))))
        assert f["kubernetes.runtime_socket_group"].level.value == "info"
        assert "so6" in f["kubernetes.runtime_socket_group"].message and not d

    def test_group_writable_no_member_says_so(self):
        f, _ = _check(_snap(runtime_socket=("/x.sock", 0o660, "microk8s", ())))
        assert "no member" in f["kubernetes.runtime_socket_group"].message

    def test_owner_only_is_ok(self):
        f, d = _check(_snap(runtime_socket=("/x.sock", 0o600, "root", ())))
        assert f["kubernetes.runtime_socket_ok"].level.value == "ok" and not d


def test_the_cis_refs_are_present():
    import json
    from pathlib import Path
    refs = json.loads((Path(__file__).resolve().parent.parent / "bob" / "data" / "cis_refs.json").read_text())
    for key, code in [("kubernetes.apiserver_anonymous", "CIS Kubernetes:1.2.1"),
                      ("kubernetes.apiserver_always_allow", "CIS Kubernetes:1.2.6"),
                      ("kubernetes.cluster_admin_broad", "CIS Kubernetes:5.1.1")]:
        assert refs[key]["code"] == code


class TestReadApiserver:
    """_read_apiserver parses MicroK8s' args file. An absent --authorization-mode
    must read as () ("not measured"), never an assumed default."""

    def _read(self, tmp_path, monkeypatch, text):
        from bob.checks import kubernetes as k
        args = tmp_path / "kube-apiserver"
        args.write_text(text, encoding="utf-8")
        monkeypatch.setattr(k, "_MICROK8S_APISERVER_ARGS", args)
        monkeypatch.setattr(k, "_probe", lambda url: 401)
        monkeypatch.setattr(k, "_command_exists", lambda c: False)
        snap = k.KubernetesSnapshot(kubelet_running=True)
        k._read_apiserver(snap)
        return snap

    def test_modes_and_port_are_parsed(self, tmp_path, monkeypatch):
        snap = self._read(tmp_path, monkeypatch,
                          "--authorization-mode=RBAC,Node\n--secure-port=16443\n")
        assert snap.authorization_modes == ("RBAC", "Node") and snap.apiserver_port == 16443

    def test_an_absent_mode_is_empty_not_a_default(self, tmp_path, monkeypatch):
        snap = self._read(tmp_path, monkeypatch, "--secure-port=16443\n")
        assert snap.authorization_modes == ()

    def test_an_unreadable_file_leaves_none(self, tmp_path, monkeypatch):
        from bob.checks import kubernetes as k
        monkeypatch.setattr(k, "_MICROK8S_APISERVER_ARGS", tmp_path / "nope")
        snap = k.KubernetesSnapshot(kubelet_running=True)
        k._read_apiserver(snap)
        assert snap.authorization_modes is None
