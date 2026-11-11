"""v0.32.0 — the kubelet and the API server are asked only once their certificate
is checked against the authority their distribution uses.

pkgradar flagged ``ssl.CERT_NONE`` in the probes (decision of 9 November 2026:
check the certificate with the node's local authority). Measured
(~/.cache/bob-fieldtest/netnsbench/tls0320): MicroK8s 1.35.6 signs both with
certs/ca.crt; k3s v1.37.2+k3s1 with server/tls/server-ca.crt; kubeadm 1.37.2
signs the API server with /etc/kubernetes/pki/ca.crt and lets the kubelet
self-sign, its authority kept in /var/lib/kubelet/pki/kubelet.crt. The name
127.0.0.1 is not checked: it was missing from three of those six certificates.
No authority known, its file unread, or a certificate it does not sign: no
probe, and the section says so (a visibility finding: the score is a ceiling).
"""

from __future__ import annotations

import ssl
from pathlib import Path

import pytest

from bob import i18n
from bob.checks import kubernetes as k
from bob.checks.kubernetes import KubernetesSnapshot, TLS_MISMATCH, TLS_UNCHECKED, check_kubernetes
from bob.visibility import VISIBILITY_KEYS
from tests.helpers import _t


class TestWhichAuthority:
    @pytest.mark.parametrize("owner, ca", [
        ("kubelite", k._MICROK8S_CA), ("k3s-server", k._K3S_SERVER_CA),
        ("k3s-agent", None), ("k3s", None),
    ])
    def test_by_distribution(self, owner, ca):
        assert k._kubelet_ca(owner) == ca

    def test_the_paths_measured(self):
        assert str(k._MICROK8S_CA) == "/var/snap/microk8s/current/certs/ca.crt"
        assert str(k._K3S_SERVER_CA) == "/var/lib/rancher/k3s/server/tls/server-ca.crt"


@pytest.fixture
def kubelet(tmp_path, monkeypatch):
    """One process named kubelet, its command line and its configuration file."""
    proc = tmp_path / "proc"
    monkeypatch.setattr(k, "_PROC", proc)

    def make(argv, config="kind: KubeletConfiguration\nclientCAFile: /etc/kubernetes/pki/ca.crt\n", pids=("4242",)):
        cfg = tmp_path / "config.yaml"
        cfg.write_text(config)
        for pid in pids:
            d = proc / pid
            d.mkdir(parents=True, exist_ok=True)
            (d / "comm").write_text("kubelet\n")
            (d / "cmdline").write_bytes(b"\0".join(a.replace("{cfg}", str(cfg)).encode() for a in argv) + b"\0")
        return k._upstream_kubelet_ca()
    return make


class TestTheKubeadmKubelet:
    def test_its_own_certificate_by_default(self, kubelet):
        assert kubelet(["/usr/bin/kubelet", "--config={cfg}"]) == Path("/var/lib/kubelet/pki/kubelet.crt")

    def test_cert_dir_given_with_a_space(self, kubelet):
        assert kubelet(["/usr/bin/kubelet", "--config", "{cfg}", "--cert-dir", "/srv/pki"]) == Path("/srv/pki/kubelet.crt")

    @pytest.mark.parametrize("config", ["tlsCertFile: /etc/x.crt\n", "serverTLSBootstrap: true\n"],
                             ids=["tlsCertFile", "serverTLSBootstrap"])
    def test_another_certificate_is_not_measured(self, kubelet, config):
        assert kubelet(["/usr/bin/kubelet", "--config={cfg}"], config=config) is None

    def test_tls_cert_file_flag_is_not_measured(self, kubelet):
        assert kubelet(["/usr/bin/kubelet", "--config={cfg}", "--tls-cert-file=/etc/x.crt"]) is None

    def test_no_config_is_not_read(self, kubelet):
        assert kubelet(["/usr/bin/kubelet"]) is None

    def test_two_kubelets_are_not_told_apart(self, kubelet):
        assert kubelet(["/usr/bin/kubelet", "--config={cfg}"], pids=("1", "2")) is None


class _Ctx:
    check_hostname = True
    verify_mode = ssl.CERT_REQUIRED


class TestTheContext:
    def test_the_chain_is_checked_not_the_name(self, monkeypatch):
        monkeypatch.setattr(k.ssl, "create_default_context", lambda cafile: _Ctx())
        ctx = k._tls_context(Path("/ca.crt"))
        assert ctx.check_hostname is False and ctx.verify_mode == ssl.CERT_REQUIRED

    def test_no_authority_no_context(self):
        assert k._tls_context(None) is None

    def test_an_unreadable_authority_no_context(self, tmp_path):
        assert k._tls_context(tmp_path / "missing.crt") is None


class _Sock:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestTheState:
    def _ctx(self, monkeypatch, wrap):
        ctx = _Ctx()
        ctx.wrap_socket = wrap
        monkeypatch.setattr(k, "_tls_context", lambda ca: ctx)
        monkeypatch.setattr(k.socket, "create_connection", lambda addr, timeout: _Sock())

    def test_a_certificate_the_authority_signs(self, monkeypatch):
        self._ctx(monkeypatch, lambda s, server_hostname: _Sock())
        assert k._tls_state(10250, Path("/ca.crt")) == ""

    def test_one_it_does_not_sign(self, monkeypatch):
        def refuse(s, server_hostname):
            raise ssl.SSLCertVerificationError("certificate verify failed")
        self._ctx(monkeypatch, refuse)
        assert k._tls_state(10250, Path("/ca.crt")) == TLS_MISMATCH

    def test_no_authority(self):
        assert k._tls_state(10250, None) == TLS_UNCHECKED

    def test_nothing_answering_is_left_to_the_probe(self, monkeypatch):
        monkeypatch.setattr(k, "_tls_context", lambda ca: _Ctx())

        def refuse(addr, timeout):
            raise ConnectionRefusedError()
        monkeypatch.setattr(k.socket, "create_connection", refuse)
        assert k._tls_state(10250, Path("/ca.crt")) == ""


def test_no_authority_no_request(monkeypatch):
    sent = []
    monkeypatch.setattr(k.urllib.request, "urlopen", lambda *a, **kw: sent.append(a))
    assert k._request("https://127.0.0.1:10250/pods", ca=None) == (None, "") and sent == []


class TestNotAsked:
    def _snap(self, monkeypatch, state):
        asked = []
        monkeypatch.setattr(k, "kubelet_running", lambda: True)
        monkeypatch.setattr(k, "_ctr_command", lambda: None)
        monkeypatch.setattr(k, "_command_exists", lambda n: False)
        monkeypatch.setattr(k, "_read_apiserver", lambda snap: None)
        monkeypatch.setattr(k, "_runtime_socket", lambda: None)
        monkeypatch.setattr(k, "_loopback_listener", lambda port: ["kubelite"] if port == 10250 else [])
        monkeypatch.setattr(k, "_tls_state", lambda port, ca: state)
        monkeypatch.setattr(k, "_probe", lambda url, ca=None: asked.append(url) or 401)
        monkeypatch.setattr(k, "_probe_run", lambda ca=None: asked.append("run") or (404, ""))
        monkeypatch.setattr(k, "_probe_exec", lambda ca=None: asked.append("exec") or (404, ""))
        return KubernetesSnapshot.from_system(), asked

    @pytest.mark.parametrize("state", [TLS_MISMATCH, TLS_UNCHECKED])
    def test_the_kubelet(self, monkeypatch, state):
        snap, asked = self._snap(monkeypatch, state)
        assert asked == [] and not snap.run_probed and snap.anonymous_status is None
        assert snap.kubelet_tls == state and snap.kubelet_ca == str(k._MICROK8S_CA)

    def test_checked_is_asked(self, monkeypatch):
        snap, asked = self._snap(monkeypatch, "")
        assert asked == ["https://127.0.0.1:10250/pods"] and snap.anonymous_status == 401

    def test_the_api_server(self, monkeypatch):
        monkeypatch.setattr(k, "_loopback_listener", lambda port: ["kubelite"])
        monkeypatch.setattr(k, "_tls_state", lambda port, ca: TLS_MISMATCH)
        asked = []
        monkeypatch.setattr(k, "_probe", lambda url, ca=None: asked.append(url) or 401)
        snap = KubernetesSnapshot(kubelet_running=True, apiserver_port=16443)
        k._probe_apiserver(snap, k._MICROK8S_CA)
        assert asked == [] and snap.apiserver_tls == TLS_MISMATCH and snap.apiserver_anonymous_status is None


def _finding(**kw):
    snap = KubernetesSnapshot(kubelet_running=True, workloads_read=True, kubelet_listener="kubelite",
                              authorization_modes=("Node", "RBAC"), apiserver_port=16443,
                              apiserver_listener="kubelite", broad_admin_bindings=[], **kw)
    return {f.key: f for f in check_kubernetes(snap, t=_t).findings}


class TestWhatTheSectionSays:
    def test_kubelet_mismatch(self):
        f = _finding(kubelet_tls=TLS_MISMATCH, kubelet_ca="/ca.crt")["kubernetes.kubelet_tls_mismatch"]
        assert f.template_vars == {"ca": "/ca.crt"}

    def test_kubelet_no_authority_known(self):
        f = _finding(kubelet_tls=TLS_UNCHECKED, kubelet_ca="")["kubernetes.kubelet_tls_unchecked"]
        assert f.template_vars == {"why": "kubernetes.tls_why.not_measured"}

    def test_kubelet_authority_unread(self):
        f = _finding(kubelet_tls=TLS_UNCHECKED, kubelet_ca="/ca.crt")["kubernetes.kubelet_tls_unchecked"]
        assert f.template_vars == {"why": "kubernetes.tls_why.unreadable"}

    def test_api_server_mismatch(self):
        f = _finding(apiserver_tls=TLS_MISMATCH, apiserver_ca="/ca.crt")["kubernetes.apiserver_tls_mismatch"]
        assert f.template_vars == {"port": 16443, "ca": "/ca.crt"}

    @pytest.mark.parametrize("key", ["kubernetes.kubelet_tls_unchecked", "kubernetes.kubelet_tls_mismatch",
                                     "kubernetes.apiserver_tls_unchecked", "kubernetes.apiserver_tls_mismatch"])
    def test_the_score_is_a_ceiling(self, key):
        assert key in VISIBILITY_KEYS


@pytest.mark.parametrize("lang, words", [
    ("en", "does not present a certificate signed by /var/snap/microk8s/current/certs/ca.crt, so it was not asked"),
    ("fr", "ne présente pas un certificat signé par /var/snap/microk8s/current/certs/ca.crt : il n'a donc pas été interrogé"),
], ids=["en", "fr"])
def test_the_rendered_line(lang, words):
    i18n.init(lang)
    try:
        snap = KubernetesSnapshot(kubelet_running=True, workloads_read=True, kubelet_listener="kubelite",
                                  kubelet_tls=TLS_MISMATCH, kubelet_ca=str(k._MICROK8S_CA))
        msgs = [f.message for f in check_kubernetes(snap, t=i18n.t).findings]
    finally:
        i18n.init(lang="en")
    assert any(words in m for m in msgs)
