"""
Kubernetes node audit for BOB (v0.25.0) — the node, not the cluster.

``docker_hardening`` audits Docker and Podman containers; a Kubernetes node
runs its workloads through containerd (upstream kubelet, MicroK8s, k3s), and
BOB saw none of them. This section reads what runs on *this* node and how its
kubelet answers, with no cluster credentials:

  - the containers, through ``ctr`` (``microk8s.ctr``, ``k3s ctr``, or ``ctr``
    on containerd's socket), else ``crictl`` (CRI-O): a container with every
    capability in its bounding set (what ``privileged: true`` grants, and what
    ``capabilities.add: [ALL]`` grants without the rest of privileged mode), a pod in the host's network / PID
    / IPC namespace (its sandbox holds no namespace of that type; for crictl,
    the CRI status says NODE), a host path that hands over the node (``/``,
    ``/etc``, ``/root``, the kubelet's directory, a container runtime's
    socket);
  - the kubelet, asked on localhost with no credentials: ``GET /pods`` on
    10250 and on the read-only port 10255, then ``POST /run`` for a random pod
    name Kubernetes cannot give to a pod (upper case, see ``_probe_run``) — whatever ``/pods`` answered, except a 401. Reads
    (``nodes/pods``, with a fallback to ``nodes/proxy``) and commands
    (``nodes/proxy``) are different permissions, and the verb matters: a
    ``POST /run`` is the create verb, a ``GET /exec`` the get verb. Both are
    asked and the commands verdict combines them (see ``_commands_verdict``).
    Nothing can run: there is no such pod.

``kube-system`` runs the platform itself: a CNI agent (calico-node,
measured on MicroK8s 1.35) is privileged and in the host network by design.
Those are said, not deducted; workloads elsewhere are.

Findings:
  - pod with every capability outside kube-system           : WARN −1
  - host path handing over the node, outside kube-system    : WARN −1
  - host namespaces outside kube-system                     : INFO
  - platform pods with elevated rights (kube-system)        : INFO
  - anonymous commands authorised (POST /run or GET /exec answers 404, no such pod): ALERT −3
    (the highest established severity applies: the read and command levels are
    not cumulative; a refused read does not hide authorised commands, and a
    refused create does not hide a permitted get)
  - anonymous reads of pod specifications, no command shown authorised: WARN −1
  - anonymous requests refused (403), no command shown authorised: INFO
  - command answer inconclusive (405, 5xx, no answer): INFO, not scored
  - anonymous read answered otherwise (5xx, 405): INFO, inconclusive, not a refused read
    (visibility: the command permission is not established)
  - kubelet read-only port answers (10255)                  : WARN −1
  - containers could not be listed, or some not inspected   : INFO (visibility)

The section only runs where a kubelet process runs.
"""

from __future__ import annotations

import json
import secrets
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from bob.checks._run import (
    TranslationFunc,
    _command_exists,
    _identity_t,
    kubelet_running,
    path_exists,
    run_result,
)
from bob.scoring import CheckResult

_SYSTEM_NAMESPACE = "kube-system"

#: Host paths whose bind mount hands the node to the container.
_RUNTIME_SOCKETS = (
    "/run/containerd/containerd.sock", "/var/run/containerd/containerd.sock",
    "/var/snap/microk8s/common/run/containerd.sock", "/run/k3s/containerd/containerd.sock",
    "/var/run/docker.sock", "/run/docker.sock", "/var/run/crio/crio.sock", "/run/crio/crio.sock",
)
_SENSITIVE_PATHS = frozenset({"/", "/etc", "/root", "/var/lib/kubelet", *_RUNTIME_SOCKETS})

_CTR_SOCKETS = ("/run/containerd/containerd.sock", "/var/run/containerd/containerd.sock")
# v0.25.0 — 15 s, not 5: measured on a loaded MicroK8s node, the first answer
# after a kubelet restart took 9.5 s; 5 s read a 403 as "did not answer".
_PROBE_TIMEOUT = 15
#: How much of an answer body is kept: enough for the kubelet's own sentence.
_BODY_BYTES = 256
_CTR_TIMEOUT = 15
_MAX_CONTAINERS = 400


@dataclass
class PodFacts:
    namespace: str
    name: str
    privileged: bool = False          # every capability in the bounding set
    host_network: bool = False
    host_pid: bool = False
    host_ipc: bool = False
    sensitive_mounts: "list[str]" = field(default_factory=list)


@dataclass
class KubernetesSnapshot:
    """What runs on this node and how its kubelet answers.

    Args:
        kubelet_running:   a kubelet process runs (kubelet, kubelite, k3s).
        workloads_read:    the containers were listed and inspected.
        pods:              per pod, the elevated rights its containers hold.
        unread:            containers listed whose spec could not be read
                           — their rights unknown. Measured on MicroK8s just
                           restarted under load: a first pass missed the rights
                           of two containers that a second pass read.
        anonymous_status:  HTTP status of an anonymous ``GET /pods`` on 10250,
                           None when the kubelet could not be reached.
        readonly_status:   the same on the read-only port 10255, None when
                           nothing answered.
        run_probed:        whether the command request was sent: not when
                           ``/pods`` answered 401 (the request is not
                           authenticated, so commands are not possible either).
        anonymous_run_status: HTTP status of an anonymous ``POST /run`` for a
                           random pod name; None when not sent or no answer.
        anonymous_run_text: the start of that answer's body, the kubelet's own
                           sentence (e.g. "pod does not exist").
    """
    kubelet_running:  bool = False
    workloads_read:   bool = False
    pods:             "list[PodFacts]" = field(default_factory=list)
    unread:           int = 0
    anonymous_status: "int | None" = None
    readonly_status:  "int | None" = None
    run_probed:           bool = False
    anonymous_run_status: "int | None" = None
    anonymous_run_text:   str = ""
    anonymous_exec_status: "int | None" = None
    anonymous_exec_text:   str = ""

    @classmethod
    def from_system(cls) -> "KubernetesSnapshot":
        snap = cls(kubelet_running=kubelet_running())
        if not snap.kubelet_running:
            return snap
        ctr = _ctr_command()
        if ctr:
            read = _read_pods(ctr)
        elif _command_exists("crictl"):
            read = _read_pods_cri(("crictl", f"--timeout={_CTR_TIMEOUT}s"))
        else:
            read = None
        if read is not None:
            snap.workloads_read = True
            snap.pods, snap.unread = read
        snap.anonymous_status = _probe("https://127.0.0.1:10250/pods")
        snap.readonly_status = _probe("http://127.0.0.1:10255/pods")
        # Asked whatever GET /pods answered: a refused read says nothing about a
        # command, the kubelet checks them as different permissions (nodes/pods,
        # nodes/proxy). A 401 closes the question: the request is not authenticated.
        if snap.anonymous_status != 401:
            snap.run_probed = True
            snap.anonymous_run_status, snap.anonymous_run_text = _probe_run()
            snap.anonymous_exec_status, snap.anonymous_exec_text = _probe_exec()
        return snap


def _ctr_command() -> "tuple[str, ...]":
    """The ``ctr`` invocation that reaches this node's Kubernetes containers."""
    for wrapper in ("microk8s.ctr", "/snap/bin/microk8s.ctr"):
        if _command_exists(wrapper) or (wrapper.startswith("/") and path_exists(Path(wrapper))):
            return (wrapper,)                     # namespace k8s.io set by the wrapper
    if _command_exists("k3s"):
        return ("k3s", "ctr", "-n", "k8s.io")
    if _command_exists("ctr"):
        for sock in _CTR_SOCKETS:
            if path_exists(Path(sock)):
                return ("ctr", "-a", sock, "-n", "k8s.io")
    return ()


def _read_pods(ctr: "tuple[str, ...]") -> "tuple[list[PodFacts], int] | None":
    """Every pod's elevated rights, from each container's OCI spec, and how
    many listed containers could not be read. None when the containers could
    not be listed."""
    listing = run_result(*ctr, "containers", "ls", "-q", timeout=_CTR_TIMEOUT)
    if not listing.ok:
        return None
    pods: "dict[tuple[str, str], PodFacts]" = {}
    unread = 0
    for cid in [line.strip() for line in listing.stdout.splitlines() if line.strip()][:_MAX_CONTAINERS]:
        info = run_result(*ctr, "containers", "info", cid, timeout=_CTR_TIMEOUT)
        try:
            spec_doc = json.loads(info.stdout) if info.ok else None
        except ValueError:
            spec_doc = None
        if not isinstance(spec_doc, dict):
            unread += 1
            continue
        labels = spec_doc.get("Labels") or {}
        ns, name = labels.get("io.kubernetes.pod.namespace"), labels.get("io.kubernetes.pod.name")
        if not ns or not name:
            continue                               # not a Kubernetes container
        pod = pods.setdefault((ns, name), PodFacts(namespace=ns, name=name))
        spec = spec_doc.get("Spec") or {}
        kind = labels.get("io.cri-containerd.kind")
        if kind == "sandbox":
            types = {n.get("type") for n in (spec.get("linux") or {}).get("namespaces") or []}
            pod.host_network = "network" not in types
            pod.host_pid = "pid" not in types
            pod.host_ipc = "ipc" not in types
            continue
        caps = ((spec.get("process") or {}).get("capabilities") or {}).get("bounding") or []
        if len(caps) > _cap_last_cap():
            pod.privileged = True
        for mount in spec.get("mounts") or []:
            src = _host_path(mount.get("source"))
            if mount.get("type") == "bind" and src in _SENSITIVE_PATHS and src not in pod.sensitive_mounts:
                pod.sensitive_mounts.append(src)
    return sorted(pods.values(), key=lambda p: (p.namespace, p.name)), unread


def _read_pods_cri(crictl: "tuple[str, ...]") -> "tuple[list[PodFacts], int] | None":
    """The same, through the CRI (``crictl``) — CRI-O ships no ``ctr``.

    Measured on CRI-O 1.35 (Fedora 43): ``inspectp`` gives the pod's name and
    namespace and, under ``status.linux.namespaces.options``, ``NODE`` for a
    namespace shared with the host; ``inspect`` gives the sandbox id, the OCI
    spec's capabilities (41 privileged, 9 by default) and the requested host
    paths under ``status.mounts``. Pod names come from the sandbox: without the
    kubelet's labels, ``crictl ps`` shows "unknown".
    """
    listing = run_result(*crictl, "pods", "-q", "--state", "ready", timeout=_CTR_TIMEOUT + 5)
    if not listing.ok:
        return None
    pods: "dict[str, PodFacts]" = {}
    unread = 0
    for pid in [line.strip() for line in listing.stdout.splitlines() if line.strip()][:_MAX_CONTAINERS]:
        doc = _cri_json(crictl, "inspectp", pid)
        meta = ((doc or {}).get("status") or {}).get("metadata") or {}
        if not meta.get("namespace") or not meta.get("name"):
            unread += 1
            continue
        opts = ((doc["status"].get("linux") or {}).get("namespaces") or {}).get("options") or {}
        pods[pid] = PodFacts(namespace=meta["namespace"], name=meta["name"],
                             host_network=opts.get("network") == "NODE",
                             host_pid=opts.get("pid") == "NODE",
                             host_ipc=opts.get("ipc") == "NODE")
    containers = run_result(*crictl, "ps", "-q", timeout=_CTR_TIMEOUT + 5)
    if not containers.ok:
        return None
    for cid in [line.strip() for line in containers.stdout.splitlines() if line.strip()][:_MAX_CONTAINERS]:
        doc = _cri_json(crictl, "inspect", cid)
        info = (doc or {}).get("info") or {}
        pod = pods.get(info.get("sandboxID", ""))
        if pod is None:
            unread += 1
            continue
        spec = info.get("runtimeSpec") or {}
        caps = ((spec.get("process") or {}).get("capabilities") or {}).get("bounding") or []
        if len(caps) > _cap_last_cap():
            pod.privileged = True
        for mount in (doc.get("status") or {}).get("mounts") or []:
            src = _host_path(mount.get("hostPath"))
            if src in _SENSITIVE_PATHS and src not in pod.sensitive_mounts:
                pod.sensitive_mounts.append(src)
    return sorted(pods.values(), key=lambda p: (p.namespace, p.name)), unread


def _host_path(raw: object) -> str:
    """A mount source as compared with the sensitive paths: ``/etc/`` is
    ``/etc``, ``/`` stays ``/``, and nothing stays nothing."""
    if not isinstance(raw, str) or not raw:
        return ""
    return raw.rstrip("/") or "/"


def _cri_json(crictl: "tuple[str, ...]", *args: str) -> "dict | None":
    out = run_result(*crictl, *args, timeout=_CTR_TIMEOUT + 5)
    if not out.ok:
        return None
    try:
        doc = json.loads(out.stdout)
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


def _cap_last_cap() -> int:
    """The kernel's highest capability number: a bounding set longer than this
    holds every capability — what ``privileged: true`` grants, and
    ``capabilities.add: [ALL]`` too (v0.25.0 review: the finding says so)."""
    try:
        return int(Path("/proc/sys/kernel/cap_last_cap").read_text().strip())
    except (OSError, ValueError):
        return 40


def _request(url: str, method: str = "GET") -> "tuple[int | None, str]":
    """HTTP status and the start of the body of an anonymous request, or
    ``(None, "")`` when nothing answered."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE                # the kubelet's own certificate
    request = urllib.request.Request(url, data=b"" if method == "POST" else None, method=method)
    try:
        with urllib.request.urlopen(request, timeout=_PROBE_TIMEOUT,
                                    context=ctx if url.startswith("https") else None) as resp:
            return resp.status, _body(resp)
    except urllib.error.HTTPError as exc:
        return exc.code, _body(exc)
    except (urllib.error.URLError, OSError, ValueError):
        return None, ""


def _body(response) -> str:
    """The start of a response body; empty when the response carries none."""
    try:
        return response.read(_BODY_BYTES).decode("utf-8", "replace")
    except (OSError, AttributeError, ValueError):
        return ""


def _probe(url: str) -> "int | None":
    """HTTP status of an anonymous GET, None when nothing answered."""
    return _request(url)[0]


def _probe_exec() -> "tuple[int | None, str]":
    """``GET /exec`` for an upper-case pod name, with the stream parameters: the
    kubelet's sentence is then the pod lookup's, after the access check, so
    nothing can run. Pod, namespace and container names must use lowercase DNS-compatible
    syntax, so an upper-case namespace and pod name cannot identify a valid pod. A GET is the get verb on
    nodes/proxy, which is not the create verb a POST needs: a grant of one
    does not show the other.
    """
    name = "BOB-PROBE-" + secrets.token_hex(8).upper()
    return _request(f"https://127.0.0.1:10250/exec/{name}/{name}/probe"
                    "?command=true&input=0&output=1&tty=0&stdout=1")


def _probe_run() -> "tuple[int | None, str]":
    """``POST /run`` for an upper-case pod name: no pod can carry it, since
    pod names must use lowercase DNS-compatible syntax.

    The kubelet checks the request's access before it looks the pod up, so the
    answer shows whether anonymous commands are allowed, and nothing can run.
    """
    name = "BOB-PROBE-" + secrets.token_hex(8).upper()
    return _request(f"https://127.0.0.1:10250/run/{name}/{name}/probe", method="POST")


#: What the answer to a command request shows (see ``_run_verdict``).
RUN_AUTHORISED = "authorised"
RUN_REFUSED = "refused"
RUN_UNAUTHENTICATED = "unauthenticated"
RUN_INCONCLUSIVE = "inconclusive"


def _run_verdict(status: "int | None", text: str) -> str:
    """What the answer to a command request for a pod that does not exist shows.

    Measured on MicroK8s 1.35.6, with the kubelet's anonymous access on:

    - 404 saying the pod does not exist: the request passed the access check and
      reached the command handler, so anonymous commands are authorised. The
      sentence is required: a 404 without it is not the handler's answer.
    - 403: the access check refused the request: commands are refused.
    - 401: the request was not authenticated: nothing is concluded.
    - anything else is inconclusive. 405 "Debug endpoints are disabled": the
      check passed, but no command can run on this kubelet. 500 "Authorization
      error": the kubelet could not ask the API server, so nothing was decided.
      No answer. None of them shows that commands are allowed, so none is
      scored as if it did.
    """
    if status == 403:
        return RUN_REFUSED
    if status == 401:
        return RUN_UNAUTHENTICATED
    if status == 404 and "does not exist" in text.lower():
        return RUN_AUTHORISED
    return RUN_INCONCLUSIVE


def _commands_verdict(post: str, get: str) -> str:
    """One command verdict from the two command requests (verbs create and get).

    Authorised when either verb is: a get alone reaches /exec. Refused only when
    both are refused, since a refused create says nothing about a get. Otherwise
    inconclusive, unless both requests were unauthenticated.
    """
    if RUN_AUTHORISED in (post, get):
        return RUN_AUTHORISED
    if post == get == RUN_REFUSED:
        return RUN_REFUSED
    if post == get == RUN_UNAUTHENTICATED:
        return RUN_UNAUTHENTICATED
    return RUN_INCONCLUSIVE


def _answer(status: "int | None") -> str:
    """How an answer's status reads in a sentence."""
    return "no answer" if status is None else f"HTTP {status}"


def _names(pods: "list[PodFacts]") -> str:
    shown = ", ".join(f"{p.namespace}/{p.name}" for p in pods[:8])
    return shown + (f" (+{len(pods) - 8})" if len(pods) > 8 else "")


def _say_run_inconclusive(result: CheckResult, run: "str | None", answer: str, _t) -> None:
    """Say it when the command answer neither allows nor refuses: commands are
    then not established, and the score is an upper bound on that exposure."""
    if run in (RUN_INCONCLUSIVE, RUN_UNAUTHENTICATED):
        result.info(message=_t("kubernetes.kubelet_run_indeterminate", answer=answer),
                    detail=_t("kubernetes.kubelet_run_indeterminate_detail"),
                    key="kubernetes.kubelet_run_indeterminate",
                    template_vars={"answer": answer})


def check_kubernetes(snapshot: KubernetesSnapshot, t: "TranslationFunc | None" = None) -> CheckResult:
    """Classify what runs on the node and how the kubelet answers."""
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if not snapshot.workloads_read:
        result.info(message=_t("kubernetes.workloads_unread"), key="kubernetes.workloads_unread")
    else:
        apps = [p for p in snapshot.pods if p.namespace != _SYSTEM_NAMESPACE]
        system = [p for p in snapshot.pods if p.namespace == _SYSTEM_NAMESPACE]
        privileged = [p for p in apps if p.privileged]
        mounted = [p for p in apps if p.sensitive_mounts]
        host_ns = [p for p in apps if p.host_network or p.host_pid or p.host_ipc]
        if privileged:
            result.warn_with_deduction(
                key="kubernetes.privileged_pod",
                message=_t("kubernetes.privileged_pod", count=len(privileged), pods=_names(privileged)),
                reason=_t("kubernetes.privileged_pod_reason", count=len(privileged)),
                detail=_t("kubernetes.privileged_pod_detail"),
                points=1, nature="action",
                template_vars={"count": len(privileged), "pods": _names(privileged)},
            )
        if mounted:
            detail = ", ".join(f"{p.namespace}/{p.name}: {' '.join(p.sensitive_mounts)}" for p in mounted[:8])
            result.warn_with_deduction(
                key="kubernetes.host_mount",
                message=_t("kubernetes.host_mount", count=len(mounted), mounts=detail),
                reason=_t("kubernetes.host_mount_reason", count=len(mounted)),
                detail=_t("kubernetes.host_mount_detail"),
                points=1, nature="action",
                template_vars={"count": len(mounted), "mounts": detail},
            )
        if host_ns:
            result.info(
                message=_t("kubernetes.host_namespaces", count=len(host_ns), pods=_names(host_ns)),
                key="kubernetes.host_namespaces",
                template_vars={"count": len(host_ns), "pods": _names(host_ns)},
            )
        elevated = [p for p in system if p.privileged or p.sensitive_mounts
                    or p.host_network or p.host_pid or p.host_ipc]
        if elevated:
            result.info(
                message=_t("kubernetes.system_pods_elevated", count=len(elevated), pods=_names(elevated)),
                key="kubernetes.system_pods_elevated",
                template_vars={"count": len(elevated), "pods": _names(elevated)},
            )
        if snapshot.unread:
            result.info(
                message=_t("kubernetes.workloads_partial", count=snapshot.unread),
                key="kubernetes.workloads_partial",
                template_vars={"count": snapshot.unread},
            )
        elif not (privileged or mounted or host_ns):
            result.ok(message=_t("kubernetes.workloads_ok", count=len(apps)),
                      key="kubernetes.workloads_ok", template_vars={"count": len(apps)})

    status = snapshot.anonymous_status
    run = (_commands_verdict(_run_verdict(snapshot.anonymous_run_status, snapshot.anonymous_run_text),
                             _run_verdict(snapshot.anonymous_exec_status, snapshot.anonymous_exec_text))
           if snapshot.run_probed else None)
    answer = (f"POST /run: {_answer(snapshot.anonymous_run_status)}, "
              f"GET /exec: {_answer(snapshot.anonymous_exec_status)}")
    if run == RUN_AUTHORISED:
        # One exposure, one level: anonymous commands are the −3, and the reads
        # they come with are not counted again. A refused read does not hide it.
        if status is not None and 200 <= status < 300:
            result.alert_with_deduction(
                key="kubernetes.kubelet_anonymous",
                message=_t("kubernetes.kubelet_anonymous"),
                reason=_t("kubernetes.kubelet_anonymous_reason"),
                detail=_t("kubernetes.kubelet_anonymous_detail"),
                points=3, nature="action",
            )
        else:
            result.alert_with_deduction(
                key="kubernetes.kubelet_anonymous",
                message=_t("kubernetes.kubelet_anonymous_run_only"),
                reason=_t("kubernetes.kubelet_anonymous_run_only_reason"),
                detail=_t("kubernetes.kubelet_anonymous_detail"),
                points=3, nature="action",
            )
    elif status is not None and 200 <= status < 300:
        result.warn_with_deduction(
            key="kubernetes.kubelet_anonymous",
            message=_t("kubernetes.kubelet_anonymous_read"),
            reason=_t("kubernetes.kubelet_anonymous_read_reason"),
            detail=_t("kubernetes.kubelet_anonymous_detail"),
            points=1, nature="action",
        )
        _say_run_inconclusive(result, run, answer, _t)
    elif status == 403:
        result.info(message=_t("kubernetes.kubelet_anonymous_denied"), key="kubernetes.kubelet_anonymous_denied")
        _say_run_inconclusive(result, run, answer, _t)
    elif status == 401:
        result.ok(message=_t("kubernetes.kubelet_auth_ok"), key="kubernetes.kubelet_auth_ok")
    elif status is None:
        result.info(message=_t("kubernetes.kubelet_unprobed"), key="kubernetes.kubelet_unprobed")
        _say_run_inconclusive(result, run, answer, _t)
    else:
        result.info(message=_t("kubernetes.kubelet_anonymous_inconclusive", answer=_answer(status)),
                    key="kubernetes.kubelet_anonymous_inconclusive",
                    template_vars={"answer": _answer(status)})
        _say_run_inconclusive(result, run, answer, _t)

    ro = snapshot.readonly_status
    if ro is not None and 200 <= ro < 300:
        result.warn_with_deduction(
            key="kubernetes.kubelet_readonly_port",
            message=_t("kubernetes.kubelet_readonly_port"),
            reason=_t("kubernetes.kubelet_readonly_port_reason"),
            detail=_t("kubernetes.kubelet_readonly_port_detail"),
            points=1, nature="action",
        )
    return result
