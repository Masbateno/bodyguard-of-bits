"""v0.36.0 — a kubelet under serverTLSBootstrap is checked against its clientCAFile.

Measured on kubeadm 1.37.2 (Debian 13, containerd 1.7.24, a10360, 14 November
2026), KubeletConfiguration serverTLSBootstrap: true:

| moment                    | /var/lib/kubelet/pki                 | 127.0.0.1:10250                                  |
|---------------------------|--------------------------------------|--------------------------------------------------|
| CSR pending               | kubelet-client only, no kubelet.crt  | TLS alert "internal error": no certificate        |
| CSR approved              | kubelet-server-current.pem           | issuer CN=kubernetes, verified by /etc/kubernetes/pki/ca.crt (= authentication.x509.clientCAFile) |

0.32.0 to 0.35.0 did not ask such a kubelet ("not measured"). A kubelet with
its own tlsCertFile still is not: nothing says which authority signed it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bob.checks import kubernetes as k

_KUBEADM = """apiVersion: kubelet.config.k8s.io/v1beta1
authentication:
  anonymous:
    enabled: false
  webhook:
    cacheTTL: 0s
    enabled: true
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt
cgroupDriver: systemd
kind: KubeletConfiguration
rotateCertificates: true
serverTLSBootstrap: true
"""


@pytest.fixture
def kubelet(tmp_path, monkeypatch):
    proc = tmp_path / "proc"
    monkeypatch.setattr(k, "_PROC", proc)

    def make(config):
        cfg = tmp_path / "config.yaml"
        cfg.write_text(config)
        d = proc / "4242"
        d.mkdir(parents=True, exist_ok=True)
        (d / "comm").write_text("kubelet\n")
        (d / "cmdline").write_bytes(b"/usr/bin/kubelet\0--config=" + str(cfg).encode() + b"\0")
        return k._upstream_kubelet_ca()
    return make


def test_the_measured_kubeadm_configuration(kubelet):
    assert kubelet(_KUBEADM) == Path("/etc/kubernetes/pki/ca.crt")


def test_quoted_values(kubelet):
    cfg = _KUBEADM.replace("serverTLSBootstrap: true", 'serverTLSBootstrap: "true"').replace(
        "clientCAFile: /etc/kubernetes/pki/ca.crt", "clientCAFile: '/srv/ca.crt'")
    assert kubelet(cfg) == Path("/srv/ca.crt")


def test_bootstrap_off_is_the_self_signed_default(kubelet):
    assert kubelet(_KUBEADM.replace("serverTLSBootstrap: true", "serverTLSBootstrap: false")) == \
        Path("/var/lib/kubelet/pki/kubelet.crt")


def test_bootstrap_without_a_client_ca_is_not_checked(kubelet):
    assert kubelet(_KUBEADM.replace("    clientCAFile: /etc/kubernetes/pki/ca.crt\n", "")) is None


def test_its_own_tls_cert_file_still_is_not(kubelet):
    assert kubelet(_KUBEADM + "tlsCertFile: /etc/kubelet/serving.crt\n") is None
