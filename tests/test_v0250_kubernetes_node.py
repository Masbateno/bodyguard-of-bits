"""v0.25.0 — the Kubernetes node: what its pods may do, how its kubelet answers.

Measured on a real MicroK8s 1.35 node (Ubuntu Server 26.04) with five test
pods: plain, privileged, hostNetwork+hostPID+hostIPC, hostPath ``/``, and
containerd's own socket mounted. ``microk8s.ctr containers info`` gave each
container's OCI spec: the privileged one held 41 bounding capabilities
(cap_last_cap 40), the others 14; the pod in the host's namespaces had a
sandbox listing no network / pid / ipc namespace; calico-node in kube-system
was privileged and in the host network. The kubelet answered an anonymous
``GET /pods`` with 401; port 10255 refused the connection.

A first pass, minutes after MicroK8s restarted under load, missed the rights
of two containers that the next pass read — so a container whose spec does
not come back is counted, and the section no longer says "nothing to report".
"""

from __future__ import annotations

import inspect
import json

import pytest

from bob.checks import kubernetes as k8s
from bob.checks._run import CommandResult
from bob.checks.kubernetes import KubernetesSnapshot, PodFacts, check_kubernetes
from bob.scoring import FindingLevel
from tests.helpers import _t


def _keys(result):
    return {f.key: f for f in result.findings}


def _points(result, key):
    return [d.points for d in result.deductions if d.key == key]


def _snap(pods=(), **kw):
    base = dict(kubelet_running=True, workloads_read=True, pods=list(pods), anonymous_status=401)
    base.update(kw)
    return KubernetesSnapshot(**base)


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

class TestWhatThePodsMayDo:
    def test_a_privileged_workload(self):
        r = check_kubernetes(_snap([PodFacts("bobtest", "privileged", privileged=True)]), t=_t)
        f = _keys(r)["kubernetes.privileged_pod"]
        assert f.level == FindingLevel.WARN and "bobtest/privileged" in f.template_vars["pods"]
        assert _points(r, "kubernetes.privileged_pod") == [1]

    def test_the_platform_is_said_not_deducted(self):
        """calico-node: privileged and in the host network, by design."""
        r = check_kubernetes(_snap([PodFacts("kube-system", "calico-node-6dswr",
                                             privileged=True, host_network=True)]), t=_t)
        keys = _keys(r)
        assert keys["kubernetes.system_pods_elevated"].level == FindingLevel.INFO
        assert "kubernetes.privileged_pod" not in keys
        assert not r.deductions

    def test_a_node_handing_host_path(self):
        r = check_kubernetes(_snap([PodFacts("bobtest", "hostroot", sensitive_mounts=["/"]),
                                    PodFacts("bobtest", "runtimesock",
                                             sensitive_mounts=["/var/snap/microk8s/common/run/containerd.sock"])]),
                             t=_t)
        f = _keys(r)["kubernetes.host_mount"]
        assert f.level == FindingLevel.WARN
        assert "bobtest/hostroot: /" in f.template_vars["mounts"]
        assert "containerd.sock" in f.template_vars["mounts"]
        assert _points(r, "kubernetes.host_mount") == [1]

    def test_host_namespaces_are_said(self):
        r = check_kubernetes(_snap([PodFacts("bobtest", "hostns", host_network=True,
                                             host_pid=True, host_ipc=True)]), t=_t)
        assert _keys(r)["kubernetes.host_namespaces"].level == FindingLevel.INFO
        assert not r.deductions

    def test_plain_workloads(self):
        r = check_kubernetes(_snap([PodFacts("bobtest", "plain")]), t=_t)
        assert _keys(r)["kubernetes.workloads_ok"].level == FindingLevel.OK


class TestWhatWasNotSeen:
    def test_unlisted_containers_are_not_clean(self):
        r = check_kubernetes(_snap(workloads_read=False), t=_t)
        keys = _keys(r)
        assert "kubernetes.workloads_unread" in keys and "kubernetes.workloads_ok" not in keys

    def test_uninspected_containers_withhold_the_ok(self):
        r = check_kubernetes(_snap([PodFacts("bobtest", "plain")], unread=2), t=_t)
        keys = _keys(r)
        assert "kubernetes.workloads_partial" in keys and "kubernetes.workloads_ok" not in keys
        assert keys["kubernetes.workloads_partial"].template_vars == {"count": 2}

    @pytest.mark.parametrize("key", ["kubernetes.workloads_unread", "kubernetes.workloads_partial",
                                     "kubernetes.kubelet_unprobed"])
    def test_each_blind_spot_counts_as_reduced_visibility(self, key):
        from bob.visibility import VISIBILITY_KEYS
        assert key in VISIBILITY_KEYS


class TestTheKubelet:
    """Reads (nodes/pods) and commands (nodes/proxy) are different permissions:
    the command request is asked whatever GET /pods answered, except a 401.
    Measured on MicroK8s 1.35.6 (v0.25.0 review, round 4): a grant on create
    nodes/proxy alone gave /pods 403 and the command request 404."""

    @pytest.mark.parametrize("pods, run, text, key, level", [
        (200, 404, "pod does not exist", "kubernetes.kubelet_anonymous", FindingLevel.ALERT),
        (200, 403, "Forbidden", "kubernetes.kubelet_anonymous", FindingLevel.WARN),
        (403, 404, "pod does not exist", "kubernetes.kubelet_anonymous", FindingLevel.ALERT),
        (403, 403, "Forbidden", "kubernetes.kubelet_anonymous_denied", FindingLevel.INFO),
        (401, None, "", "kubernetes.kubelet_auth_ok", FindingLevel.OK),
        (None, 404, "pod does not exist", "kubernetes.kubelet_anonymous", FindingLevel.ALERT),
        (None, None, "", "kubernetes.kubelet_unprobed", FindingLevel.INFO),
        (500, 500, "Authorization error", "kubernetes.kubelet_anonymous_inconclusive", FindingLevel.INFO),
    ])
    def test_the_verdict_per_answer(self, pods, run, text, key, level):
        r = check_kubernetes(_snap(anonymous_status=pods, anonymous_run_status=run,
                                   anonymous_run_text=text, run_probed=pods != 401), t=_t)
        assert _keys(r)[key].level == level

    def test_a_refused_read_does_not_hide_authorised_commands(self):
        """The review's case, measured: /pods 403, the command request 404."""
        r = check_kubernetes(_snap(anonymous_status=403, anonymous_run_status=404,
                                   anonymous_run_text="pod does not exist", run_probed=True), t=_t)
        f = _keys(r)["kubernetes.kubelet_anonymous"]
        assert f.level == FindingLevel.ALERT
        assert f.message == "kubernetes.kubelet_anonymous_run_only"
        assert _points(r, "kubernetes.kubelet_anonymous") == [3]
        assert "kubernetes.kubelet_anonymous_denied" not in _keys(r)

    def test_one_level_per_exposure(self):
        """Commands authorised: the −3 alone, the reads they come with not counted again."""
        r = check_kubernetes(_snap(anonymous_status=200, anonymous_run_status=404,
                                   anonymous_run_text="pod does not exist", run_probed=True), t=_t)
        assert [d.points for d in r.deductions if d.key == "kubernetes.kubelet_anonymous"] == [3]

    def test_a_404_without_the_sentence_is_not_an_authorisation(self):
        """Not the command handler's answer: nothing is concluded about commands."""
        r = check_kubernetes(_snap(anonymous_status=200, anonymous_run_status=404,
                                   anonymous_run_text="404 page not found", run_probed=True), t=_t)
        assert _points(r, "kubernetes.kubelet_anonymous") == [1]
        assert "kubernetes.kubelet_run_indeterminate" in _keys(r)

    @pytest.mark.parametrize("status, text", [
        (405, "Debug endpoints are disabled."),
        (500, "Authorization error (user=system:anonymous, verb=create, resource=nodes, subresource=proxy)"),
    ])
    def test_405_and_5xx_are_inconclusive_not_scored_as_commands(self, status, text):
        r = check_kubernetes(_snap(anonymous_status=200, anonymous_run_status=status,
                                   anonymous_run_text=text, run_probed=True), t=_t)
        assert _points(r, "kubernetes.kubelet_anonymous") == [1]
        assert "kubernetes.kubelet_run_indeterminate" in _keys(r)

    def test_the_inconclusive_answers_are_an_upper_bound(self):
        from bob.visibility import VISIBILITY_KEYS
        assert "kubernetes.kubelet_run_indeterminate" in VISIBILITY_KEYS
        assert "kubernetes.kubelet_anonymous_inconclusive" in VISIBILITY_KEYS

    @pytest.mark.parametrize("status, text, verdict", [
        (404, "pod does not exist", k8s.RUN_AUTHORISED),
        (404, "404 page not found", k8s.RUN_INCONCLUSIVE),
        (403, "Forbidden (user=system:anonymous, verb=create)", k8s.RUN_REFUSED),
        (401, "Unauthorized", k8s.RUN_UNAUTHENTICATED),
        (405, "Debug endpoints are disabled.", k8s.RUN_INCONCLUSIVE),
        (500, "Authorization error (user=system:anonymous)", k8s.RUN_INCONCLUSIVE),
        (200, "", k8s.RUN_INCONCLUSIVE),
        (None, "", k8s.RUN_INCONCLUSIVE),
    ])
    def test_the_command_answer_classes(self, status, text, verdict):
        assert k8s._run_verdict(status, text) == verdict

    def test_the_probe_waits_long_enough_for_a_slow_first_answer(self):
        """Measured on a loaded node: the first GET /pods after a kubelet restart
        took 9.5 s; a 5 s limit read that 403-or-200 as no answer."""
        from bob.checks import kubernetes as k8s_module
        assert k8s_module._PROBE_TIMEOUT >= 10

    def test_the_read_only_port(self):
        r = check_kubernetes(_snap(readonly_status=200), t=_t)
        assert _keys(r)["kubernetes.kubelet_readonly_port"].level == FindingLevel.WARN
        assert _points(r, "kubernetes.kubelet_readonly_port") == [1]

    def test_a_closed_read_only_port_says_nothing(self):
        r = check_kubernetes(_snap(readonly_status=None), t=_t)
        assert "kubernetes.kubelet_readonly_port" not in _keys(r)

    def test_nothing_is_commanded(self):
        """Which workload needs which right, and how the kubelet is configured
        on this distribution, is the operator's: no command is printed."""
        r = check_kubernetes(_snap([PodFacts("a", "p", privileged=True, sensitive_mounts=["/"])],
                                   anonymous_status=200, readonly_status=200), t=_t)
        assert not [f for f in r.findings if f.cmd]


class TestTheCommandProbe:
    def _offline(self, monkeypatch):
        monkeypatch.setattr(k8s, "kubelet_running", lambda: True)
        monkeypatch.setattr(k8s, "_ctr_command", lambda: ())
        monkeypatch.setattr(k8s, "_command_exists", lambda c: False)

    def test_it_is_sent_whatever_the_read_answered(self, monkeypatch):
        """A refused read says nothing about a command: the probe is still sent."""
        self._offline(monkeypatch)
        monkeypatch.setattr(k8s, "_probe", lambda url: 403)
        monkeypatch.setattr(k8s, "_probe_run", lambda: (404, "pod does not exist"))
        monkeypatch.setattr(k8s, "_probe_exec", lambda: (403, "Forbidden"))
        snap = KubernetesSnapshot.from_system()
        assert snap.run_probed and snap.anonymous_run_status == 404

    def test_not_sent_when_the_request_is_not_authenticated(self, monkeypatch):
        self._offline(monkeypatch)
        sent = []
        monkeypatch.setattr(k8s, "_probe", lambda url: 401)
        monkeypatch.setattr(k8s, "_probe_run", lambda: sent.append("run") or (None, ""))
        snap = KubernetesSnapshot.from_system()
        assert not snap.run_probed and not sent

    def test_the_name_is_random_and_names_no_pod(self, monkeypatch):
        import re
        urls = []
        monkeypatch.setattr(k8s, "_request",
                            lambda url, method="GET": urls.append((method, url)) or (404, ""))
        k8s._probe_run()
        k8s._probe_run()
        assert all(method == "POST" for method, _ in urls)
        names = []
        for _, url in urls:
            name = url.split("/run/")[1].split("/")[0]
            assert url.endswith(f"/run/{name}/{name}/probe")
            names.append(name)
        assert names[0] != names[1]
        assert all(re.fullmatch(r"BOB-PROBE-[0-9A-F]{16}", n) for n in names)


    def test_both_command_requests_are_sent_whatever_the_read_answered(self, monkeypatch):
        """POST /run (create) and GET /exec (get) are different verbs: both are asked."""
        self._offline(monkeypatch)
        monkeypatch.setattr(k8s, "_probe", lambda url: 403)
        monkeypatch.setattr(k8s, "_probe_run", lambda: (403, "Forbidden"))
        monkeypatch.setattr(k8s, "_probe_exec", lambda: (404, "pod does not exist"))
        snap = KubernetesSnapshot.from_system()
        assert snap.run_probed
        assert snap.anonymous_run_status == 403 and snap.anonymous_exec_status == 404

    def test_the_exec_probe_carries_the_stream_parameters_and_a_random_name(self, monkeypatch):
        import re
        urls = []
        monkeypatch.setattr(k8s, "_request",
                            lambda url, method="GET": urls.append((method, url)) or (404, ""))
        k8s._probe_exec()
        k8s._probe_exec()
        assert all(method == "GET" for method, _ in urls)
        names = []
        for _, url in urls:
            assert url.endswith("?command=true&input=0&output=1&tty=0&stdout=1")
            name = url.split("/exec/")[1].split("/")[0]
            assert url.split("?")[0].endswith(f"/exec/{name}/{name}/probe")
            names.append(name)
        assert names[0] != names[1]
        assert all(re.fullmatch(r"BOB-PROBE-[0-9A-F]{16}", n) for n in names)


class TestTheCommandVerbs:
    """The kubelet authorises create (POST /run) and get (GET /exec) on nodes/proxy
    separately. Measured on MicroK8s 1.35.6: a get grant alone gave /pods 200 (reads
    by the fallback), POST /run 403 and GET /exec 404: commands authorised. A probe
    of POST /run alone reported that as a read exposure."""

    @pytest.mark.parametrize("post, get, verdict", [
        (k8s.RUN_AUTHORISED, k8s.RUN_REFUSED, k8s.RUN_AUTHORISED),
        (k8s.RUN_REFUSED, k8s.RUN_AUTHORISED, k8s.RUN_AUTHORISED),
        (k8s.RUN_REFUSED, k8s.RUN_REFUSED, k8s.RUN_REFUSED),
        (k8s.RUN_REFUSED, k8s.RUN_INCONCLUSIVE, k8s.RUN_INCONCLUSIVE),
        (k8s.RUN_INCONCLUSIVE, k8s.RUN_REFUSED, k8s.RUN_INCONCLUSIVE),
        (k8s.RUN_UNAUTHENTICATED, k8s.RUN_UNAUTHENTICATED, k8s.RUN_UNAUTHENTICATED),
        (k8s.RUN_UNAUTHENTICATED, k8s.RUN_REFUSED, k8s.RUN_INCONCLUSIVE),
        (k8s.RUN_INCONCLUSIVE, k8s.RUN_INCONCLUSIVE, k8s.RUN_INCONCLUSIVE),
    ])
    def test_the_combined_verdict(self, post, get, verdict):
        assert k8s._commands_verdict(post, get) == verdict

    def test_a_get_alone_authorises_commands(self):
        r = check_kubernetes(_snap(anonymous_status=200,
                                   anonymous_run_status=403, anonymous_run_text="Forbidden (verb=create)",
                                   anonymous_exec_status=404, anonymous_exec_text="pod does not exist",
                                   run_probed=True), t=_t)
        assert _points(r, "kubernetes.kubelet_anonymous") == [3]
        assert _keys(r)["kubernetes.kubelet_anonymous"].message == "kubernetes.kubelet_anonymous"

    def test_a_get_alone_with_reads_refused_is_run_only(self):
        r = check_kubernetes(_snap(anonymous_status=403,
                                   anonymous_run_status=403, anonymous_run_text="Forbidden",
                                   anonymous_exec_status=404, anonymous_exec_text="pod does not exist",
                                   run_probed=True), t=_t)
        assert _keys(r)["kubernetes.kubelet_anonymous"].message == "kubernetes.kubelet_anonymous_run_only"
        assert _points(r, "kubernetes.kubelet_anonymous") == [3]

    def test_a_refusal_of_one_verb_is_not_a_refusal_of_both(self):
        r = check_kubernetes(_snap(anonymous_status=200,
                                   anonymous_run_status=403, anonymous_run_text="Forbidden",
                                   anonymous_exec_status=405, anonymous_exec_text="Debug endpoints are disabled.",
                                   run_probed=True), t=_t)
        assert _points(r, "kubernetes.kubelet_anonymous") == [1]
        assert "kubernetes.kubelet_run_indeterminate" in _keys(r)

    def test_both_refused_is_a_read_exposure_only(self):
        r = check_kubernetes(_snap(anonymous_status=200,
                                   anonymous_run_status=403, anonymous_run_text="Forbidden",
                                   anonymous_exec_status=403, anonymous_exec_text="Forbidden",
                                   run_probed=True), t=_t)
        assert _points(r, "kubernetes.kubelet_anonymous") == [1]
        assert "kubernetes.kubelet_run_indeterminate" not in _keys(r)

# ---------------------------------------------------------------------------
# Reading the containers' specs
# ---------------------------------------------------------------------------

def _info(ns, pod, kind, *, caps=14, namespaces=("pid", "ipc", "uts", "mount", "network"), mounts=()):
    spec = {"process": {"capabilities": {"bounding": [f"CAP_{i}" for i in range(caps)]}},
            "linux": {"namespaces": [{"type": t} for t in namespaces]},
            "mounts": [{"type": "bind", "source": s, "destination": "/x"} for s in mounts]}
    return json.dumps({"Labels": {"io.kubernetes.pod.namespace": ns, "io.kubernetes.pod.name": pod,
                                  "io.cri-containerd.kind": kind}, "Spec": spec})


@pytest.fixture
def fake_ctr(monkeypatch):
    """Answers ``ctr containers ls -q`` / ``info <id>`` from a dict."""
    infos: "dict[str, CommandResult]" = {}

    def run(*args, timeout=0):
        if args[-2:] == ("ls", "-q"):
            return CommandResult("\n".join(infos) + "\n", True)
        return infos[args[-1]]
    monkeypatch.setattr(k8s, "run_result", run)
    monkeypatch.setattr(k8s, "_cap_last_cap", lambda: 40)
    return infos


class TestReadingTheSpecs:
    def test_the_measured_node(self, fake_ctr):
        fake_ctr.update({
            "s1": CommandResult(_info("bobtest", "hostns", "sandbox", namespaces=("uts", "mount")), True),
            "c1": CommandResult(_info("bobtest", "hostns", "container"), True),
            "c2": CommandResult(_info("bobtest", "privileged", "container", caps=41), True),
            "c3": CommandResult(_info("bobtest", "hostroot", "container", mounts=("/",)), True),
            "c4": CommandResult(_info("bobtest", "runtimesock", "container",
                                      mounts=("/var/snap/microk8s/common/run/containerd.sock",)), True),
            "c5": CommandResult(_info("bobtest", "plain", "container",
                                      mounts=("/var/snap/microk8s/common/var/lib/containerd/x/hostname",)), True),
        })
        pods, unread = k8s._read_pods(("microk8s.ctr",))
        by = {p.name: p for p in pods}
        assert unread == 0
        assert (by["hostns"].host_network, by["hostns"].host_pid, by["hostns"].host_ipc) == (True, True, True)
        assert by["privileged"].privileged and not by["hostns"].privileged
        assert by["hostroot"].sensitive_mounts == ["/"]
        assert by["runtimesock"].sensitive_mounts == ["/var/snap/microk8s/common/run/containerd.sock"]
        assert by["plain"] == PodFacts("bobtest", "plain")

    def test_a_pod_s_own_sandbox_keeps_its_namespaces(self, fake_ctr):
        fake_ctr["s"] = CommandResult(_info("bobtest", "plain", "sandbox"), True)
        (pod,), _ = k8s._read_pods(("ctr",))
        assert not (pod.host_network or pod.host_pid or pod.host_ipc)

    def test_a_spec_that_does_not_come_back_is_counted(self, fake_ctr):
        fake_ctr.update({"ok": CommandResult(_info("bobtest", "plain", "container"), True),
                         "failed": CommandResult("", False),
                         "garbled": CommandResult("{not json", True)})
        pods, unread = k8s._read_pods(("ctr",))
        assert unread == 2 and [p.name for p in pods] == ["plain"]

    def test_a_container_outside_kubernetes_is_not_a_pod(self, fake_ctr):
        fake_ctr["x"] = CommandResult(json.dumps({"Labels": {}, "Spec": {}}), True)
        assert k8s._read_pods(("ctr",)) == ([], 0)

    def test_an_unlistable_runtime(self, monkeypatch):
        monkeypatch.setattr(k8s, "run_result", lambda *a, **k: CommandResult("", False))
        assert k8s._read_pods(("ctr",)) is None


def _cri_pod(ns, name, *, host="POD"):
    return json.dumps({"status": {"metadata": {"name": name, "namespace": ns, "uid": "u", "attempt": 0},
                                  "linux": {"namespaces": {"options": {"network": host, "pid": host,
                                                                       "ipc": host, "targetId": ""}}}}})


def _cri_ctr(sandbox, *, caps=9, host_paths=()):
    return json.dumps({"status": {"labels": {}, "mounts": [{"hostPath": h, "containerPath": "/host"}
                                                           for h in host_paths]},
                       "info": {"sandboxID": sandbox,
                                "runtimeSpec": {"process": {"capabilities": {"bounding": ["C"] * caps}}}}})


@pytest.fixture
def fake_crictl(monkeypatch):
    """Answers ``crictl pods -q`` / ``ps -q`` / ``inspectp`` / ``inspect``."""
    pods: "dict[str, CommandResult]" = {}
    ctrs: "dict[str, CommandResult]" = {}

    def run(*args, timeout=0):
        if "pods" in args:
            return CommandResult("\n".join(pods) + "\n", True)
        if "ps" in args:
            return CommandResult("\n".join(ctrs) + "\n", True)
        return (pods if "inspectp" in args else ctrs)[args[-1]]
    monkeypatch.setattr(k8s, "run_result", run)
    monkeypatch.setattr(k8s, "_cap_last_cap", lambda: 40)
    return pods, ctrs


class TestReadingThroughTheCri:
    """Shapes measured on CRI-O 1.35 (Fedora 43) with crictl-created pods."""

    def test_the_measured_cri_o_pods(self, fake_crictl):
        pods, ctrs = fake_crictl
        for name, host in (("plain", "POD"), ("privileged", "POD"), ("hostns", "NODE"), ("hostroot", "POD")):
            pods["p-" + name] = CommandResult(_cri_pod("bobtest", name, host=host), True)
        ctrs.update({"c1": CommandResult(_cri_ctr("p-plain"), True),
                     "c2": CommandResult(_cri_ctr("p-privileged", caps=41), True),
                     "c3": CommandResult(_cri_ctr("p-hostns"), True),
                     "c4": CommandResult(_cri_ctr("p-hostroot", host_paths=("/",)), True)})
        read, unread = k8s._read_pods_cri(("crictl",))
        by = {p.name: p for p in read}
        assert unread == 0
        assert by["privileged"].privileged and not by["plain"].privileged
        assert (by["hostns"].host_network, by["hostns"].host_pid, by["hostns"].host_ipc) == (True, True, True)
        assert not by["plain"].host_network
        assert by["hostroot"].sensitive_mounts == ["/"]
        assert by["plain"] == PodFacts("bobtest", "plain")

    def test_an_unread_pod_or_container_is_counted(self, fake_crictl):
        pods, ctrs = fake_crictl
        pods["p"] = CommandResult(_cri_pod("bobtest", "plain"), True)
        pods["gone"] = CommandResult("", False)
        ctrs["c"] = CommandResult(_cri_ctr("p"), True)
        ctrs["orphan"] = CommandResult(_cri_ctr("gone"), True)
        read, unread = k8s._read_pods_cri(("crictl",))
        assert unread == 2 and [p.name for p in read] == ["plain"]

    @pytest.mark.parametrize("raw, seen", [("", ""), (None, ""), ("/", "/"), ("/etc/", "/etc")])
    def test_an_empty_host_path_is_not_the_root(self, raw, seen):
        assert k8s._host_path(raw) == seen

    def test_cri_o_is_read_when_no_ctr_answers(self, monkeypatch):
        monkeypatch.setattr(k8s, "kubelet_running", lambda: True)
        monkeypatch.setattr(k8s, "_ctr_command", lambda: ())
        monkeypatch.setattr(k8s, "_command_exists", lambda c: c == "crictl")
        monkeypatch.setattr(k8s, "_read_pods_cri", lambda c: ([PodFacts("a", "b", privileged=True)], 0))
        monkeypatch.setattr(k8s, "_probe", lambda url: None)
        snap = KubernetesSnapshot.from_system()
        assert snap.workloads_read and snap.pods[0].privileged


class TestWhichCtr:
    def test_microk8s(self, monkeypatch):
        monkeypatch.setattr(k8s, "_command_exists", lambda c: c in ("microk8s.ctr", "ctr"))
        assert k8s._ctr_command() == ("microk8s.ctr",)

    def test_k3s(self, monkeypatch):
        monkeypatch.setattr(k8s, "_command_exists", lambda c: c == "k3s")
        monkeypatch.setattr(k8s, "path_exists", lambda p: False)
        assert k8s._ctr_command() == ("k3s", "ctr", "-n", "k8s.io")

    def test_upstream_containerd(self, monkeypatch):
        monkeypatch.setattr(k8s, "_command_exists", lambda c: c == "ctr")
        monkeypatch.setattr(k8s, "path_exists", lambda p: str(p) == "/run/containerd/containerd.sock")
        assert k8s._ctr_command() == ("ctr", "-a", "/run/containerd/containerd.sock", "-n", "k8s.io")

    def test_nothing_to_ask(self, monkeypatch):
        monkeypatch.setattr(k8s, "_command_exists", lambda c: False)
        monkeypatch.setattr(k8s, "path_exists", lambda p: False)
        assert k8s._ctr_command() == ()


class TestTheProbe:
    def test_an_http_error_is_an_answer(self, monkeypatch):
        import urllib.error

        def deny(*a, **k):
            raise urllib.error.HTTPError("u", 401, "Unauthorized", {}, None)
        monkeypatch.setattr(k8s.urllib.request, "urlopen", deny)
        assert k8s._probe("https://127.0.0.1:10250/pods") == 401

    def test_a_refused_connection_is_no_answer(self, monkeypatch):
        import urllib.error

        def refuse(*a, **k):
            raise urllib.error.URLError(ConnectionRefusedError())
        monkeypatch.setattr(k8s.urllib.request, "urlopen", refuse)
        assert k8s._probe("http://127.0.0.1:10255/pods") is None


def test_the_section_runs_only_where_a_kubelet_runs():
    from bob import runner
    src = inspect.getsource(runner)
    assert ('_sec("kubernetes", KubernetesSnapshot.from_system, check_kubernetes,\n'
            '         skip_if=lambda s: not s.kubelet_running)') in src


def test_no_kubelet_no_probing(monkeypatch):
    monkeypatch.setattr(k8s, "kubelet_running", lambda: False)
    monkeypatch.setattr(k8s, "_probe", lambda url: pytest.fail("probed without a kubelet"))
    assert KubernetesSnapshot.from_system() == KubernetesSnapshot()


@pytest.mark.parametrize("lang, needle", [("en", "every Linux capability"), ("fr", "toutes les capabilities Linux")])
def test_the_rendered_message(lang, needle):
    from bob import i18n
    i18n.init(lang)
    try:
        r = check_kubernetes(_snap([PodFacts("bobtest", "privileged", privileged=True)]), t=i18n.t)
    finally:
        i18n.init(lang="en")
    msg = _keys(r)["kubernetes.privileged_pod"].message
    assert needle in msg and "bobtest/privileged" in msg
