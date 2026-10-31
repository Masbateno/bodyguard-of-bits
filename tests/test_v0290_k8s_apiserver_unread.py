"""v0.29.0 — a Kubernetes node whose API server BOB does not read says so.

0.28.0 reads the API server where MicroK8s keeps its arguments, and wrote the
limit in its changelog: kubeadm and k3s are not read. At run time nothing was
said: on a k3s node (measured 31 October 2026: the server's process is `k3s`,
command line `k3s server`, a kubelet name BOB knows, so the section runs) the
section ended with no word on the API server, and the score read as if the
cluster had been weighed. Now an INFO, and the score is a ceiling. Measured end
to end in a container, a process named k3s running: `bob --check=kubernetes -J`
carries kubernetes.apiserver_unread.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.checks.kubernetes import KubernetesSnapshot, check_kubernetes
from bob.visibility import is_visibility_key

KEY = "kubernetes.apiserver_unread"


def _snap(**kw):
    base = dict(kubelet_running=True, workloads_read=True, anonymous_status=401, run_probed=False)
    base.update(kw)
    return KubernetesSnapshot(**base)


def _keys(snap):
    return [f.key for f in check_kubernetes(snap, t=lambda k, **kw: k).findings]


def test_not_read_is_said():
    assert KEY in _keys(_snap(authorization_modes=None))


@pytest.mark.parametrize("modes", [("RBAC", "Node"), ("AlwaysAllow",), ()])
def test_read_says_nothing_of_it(modes):
    assert KEY not in _keys(_snap(authorization_modes=modes))


def test_the_score_reads_as_a_ceiling():
    assert is_visibility_key(KEY)
    res = check_kubernetes(_snap(authorization_modes=None), t=lambda k, **kw: k)
    assert not res.deductions


@pytest.mark.parametrize("lang, words", [("en", "BOB reads its arguments on MicroK8s only"),
                                         ("fr", "BOB lit ses arguments sous MicroK8s seulement")])
def test_what_is_said(lang, words):
    i18n.init(lang)
    try:
        res = check_kubernetes(_snap(authorization_modes=None), t=i18n.t)
    finally:
        i18n.init(lang="en")
    said = [f for f in res.findings if f.key == KEY]
    assert len(said) == 1 and words in said[0].message and said[0].level.name == "INFO"


def test_k3s_runs_the_section():
    """The section runs on a k3s server: its process name is one BOB knows."""
    from bob.checks._run import _KUBELET_NAMES
    assert "k3s" in _KUBELET_NAMES
