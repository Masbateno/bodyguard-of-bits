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
import os
import re
import secrets
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from bob.checks._run import (
    _KUBELET_NAMES,
    TranslationFunc,
    _command_exists,
    _identity_t,
    kubelet_running,
    path_exists,
    run_result,
)
from bob.checks.mount_hardening import _hidepid_level
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
    #: v0.28.0 — the API server, where this node runs it (MicroK8s: its args
    #: file). None: not read. ``apiserver_anonymous_status`` is the HTTP status
    #: of an anonymous ``GET /api/v1/namespaces`` on localhost.
    apiserver_port:             "int | None" = None
    apiserver_anonymous_status: "int | None" = None
    authorization_modes:        "tuple[str, ...] | None" = None
    #: cluster-admin bindings to a subject every identity (or none) belongs to,
    #: as "binding: Kind/name"; None when the bindings were not read.
    broad_admin_bindings:       "list[str] | None" = None
    #: the container runtime's socket: (path, mode, group, members) or None.
    runtime_socket:             "tuple[str, int, str, tuple[str, ...]] | None" = None
    #: v0.31.0 — the process holding the socket 127.0.0.1:10250 reaches, and
    #: the API server's port (:func:`_loopback_listener`, :func:`_deciding`):
    #: its name when run by root, "name (uid N)" when not, "name (uid ?)" when
    #: its user could not be read; "" when nothing listens, None when it could
    #: not be told. With several owners, the first that is not a kubelet (an
    #: API server) run by root. Only a kubelet (an API server) run by root is
    #: sent the anonymous probes.
    kubelet_listener:           "str | None" = "kubelet"
    apiserver_listener:         "str | None" = "kube-apiserver"

    @classmethod
    def from_system(cls) -> "KubernetesSnapshot":
        snap = cls(kubelet_running=kubelet_running())
        if not snap.kubelet_running:
            return snap
        ctr = _ctr_command()
        if ctr:
            read = _read_pods(ctr)
        elif ctr is None:
            read = None                           # a k3s server, its ctr not found
        elif _command_exists("crictl"):
            read = _read_pods_cri(("crictl", f"--timeout={_CTR_TIMEOUT}s"))
        else:
            read = None
        if read is not None:
            snap.workloads_read = True
            snap.pods, snap.unread = read
        # v0.31.0 — the probes go to whatever holds the port; only the
        # kubelet's answer says anything about the kubelet (`_loopback_listener`).
        snap.kubelet_listener = _deciding(_loopback_listener(10250), _KUBELET_NAMES)
        if snap.kubelet_listener in _KUBELET_NAMES:
            snap.anonymous_status = _probe("https://127.0.0.1:10250/pods")
        if _deciding(_loopback_listener(10255), _KUBELET_NAMES) in _KUBELET_NAMES:
            snap.readonly_status = _probe("http://127.0.0.1:10255/pods")
        # Asked whatever GET /pods answered: a refused read says nothing about a
        # command, the kubelet checks them as different permissions (nodes/pods,
        # nodes/proxy). A 401 closes the question: the request is not authenticated.
        if snap.kubelet_listener in _KUBELET_NAMES and snap.anonymous_status != 401:
            snap.run_probed = True
            snap.anonymous_run_status, snap.anonymous_run_text = _probe_run()
            snap.anonymous_exec_status, snap.anonymous_exec_text = _probe_exec()
        _read_apiserver(snap)
        snap.runtime_socket = _runtime_socket()
        return snap


#: v0.28.0 — where MicroK8s keeps the API server's arguments (measured on
#: Ubuntu 26.04, MicroK8s 1.35.6: `--authorization-mode=AlwaysAllow` and
#: `--secure-port=16443`; with the rbac addon, `RBAC,Node`). Other
#: distributions are not read: not measured.
_MICROK8S_APISERVER_ARGS = Path("/var/snap/microk8s/current/args/kube-apiserver")
#: Subjects every request, or every authenticated one, carries.
_BROAD_SUBJECTS = frozenset({("Group", "system:authenticated"), ("Group", "system:unauthenticated"),
                             ("Group", "system:serviceaccounts"), ("User", "system:anonymous")})


#: v0.31.3 — k3s runs the API server inside its ``k3s server`` process, and that
#: process blanks its own command line: measured on Kali, k3s v1.37.2+k3s1,
#: ``/proc/<pid>/cmdline`` reads ``k3s server`` and NUL bytes whatever flags,
#: ``config.yaml`` or ``config.yaml.d`` set. What the API server runs with is
#: in the line k3s logs as it starts it, ``Running kube-apiserver --…`` (under
#: systemd, in the journal, attached to that process); the port its clients
#: reach, in the kubeconfig it writes for its own kubectl. Not
#: ``--advertise-port`` in that line: measured ``--advertise-port=7000`` while
#: k3s listened on 6443, and the kubeconfig said 6443.
_K3S_SERVER = "k3s-server"
_K3S_KUBECONFIG = Path("/etc/rancher/k3s/k3s.yaml")
_K3S_APISERVER_LINE = "Running kube-apiserver "
_K3S_CONTAINERD_SOCKET = "/run/k3s/containerd/containerd.sock"
_PROC = Path("/proc")


def _parse_args(text: str) -> "dict[str, str]":
    """``--name=value`` (or ``--name value``) arguments, one per line or
    separated by spaces, the last of a name winning."""
    args = {}
    for line in text.splitlines():
        m = re.match(r"^\s*(--[\w-]+)(?:[=\s]+(.*))?$", line)
        if m:
            args[m.group(1)] = (m.group(2) or "").strip().strip('"')
    return args


def _modes(args: "dict[str, str]") -> "tuple[str, ...]":
    modes = args.get("--authorization-mode")
    # Absent: the upstream default is not assumed (not measured) — "not read".
    return tuple(x.strip() for x in modes.split(",") if x.strip()) if modes else ()


def _read_apiserver(snap: "KubernetesSnapshot") -> None:
    """The API server's authorization mode and port, its answer to an
    anonymous read, and the cluster-admin bindings (read-only, through the
    distribution's own kubectl): MicroK8s' args file, else a k3s server's
    journal (v0.31.3). Leaves the fields None where not read."""
    try:
        text = _MICROK8S_APISERVER_ARGS.read_text(encoding="utf-8", errors="replace")
    except OSError:
        _read_k3s_apiserver(snap)
        return
    args = _parse_args(text)
    port = args.get("--secure-port", "6443")
    snap.apiserver_port = int(port) if port.isdigit() else None
    snap.authorization_modes = _modes(args)
    _probe_apiserver(snap)
    if "RBAC" in snap.authorization_modes and _command_exists("microk8s"):
        res = run_result("microk8s", "kubectl", "get", "clusterrolebindings", "-o", "json", timeout=_CTR_TIMEOUT)
        if res.ok:
            snap.broad_admin_bindings = _broad_admin_bindings(res.stdout)


def _probe_apiserver(snap: "KubernetesSnapshot") -> None:
    """The anonymous read, sent only to an API server run by root on the port."""
    if snap.apiserver_port:
        snap.apiserver_listener = _deciding(_loopback_listener(snap.apiserver_port), _APISERVER_NAMES)
        if snap.apiserver_listener in _APISERVER_NAMES:
            snap.apiserver_anonymous_status = _probe(f"https://127.0.0.1:{snap.apiserver_port}/api/v1/namespaces")


def _read_k3s_apiserver(snap: "KubernetesSnapshot") -> None:
    """v0.31.3 — the API server of the one running k3s server, from the line it
    logged when it started it. k3s started outside systemd (OpenRC, by hand)
    logs elsewhere: not read, said as before (``kubernetes.apiserver_unread``)."""
    pid = _k3s_server_pid()
    line = _k3s_apiserver_line(pid) if pid else None
    if line is None:
        return
    args = _parse_args(line.split(_K3S_APISERVER_LINE, 1)[1].split('"', 1)[0].replace(" --", "\n--"))
    snap.authorization_modes = _modes(args)
    snap.apiserver_port = _k3s_port()
    _probe_apiserver(snap)
    kubectl = _k3s_tool(pid, "kubectl") if "RBAC" in snap.authorization_modes else None
    if kubectl:
        # The kubeconfig is named: a KUBECONFIG in BOB's environment would
        # otherwise point k3s's kubectl at another cluster.
        res = run_result(kubectl, f"--kubeconfig={_K3S_KUBECONFIG}", "get", "clusterrolebindings",
                         "-o", "json", timeout=_CTR_TIMEOUT)
        if res.ok:
            snap.broad_admin_bindings = _broad_admin_bindings(res.stdout)


def _k3s_tool(pid: str, name: str) -> "str | None":
    """The ``kubectl`` or ``ctr`` link beside the binary the k3s server runs
    (measured: ``/var/lib/rancher/k3s/data/<hash>/bin/kubectl -> k3s``, and
    ``ctr``), when it is that very file. Not ``k3s`` from PATH: k3s installs
    in /usr/local/bin, which sudo's secure_path leaves out on Kali (measured),
    so ``sudo bob`` would not find it."""
    try:
        exe = Path(os.readlink(_PROC / pid / "exe"))
        tool = exe.parent / name
        return str(tool) if os.path.samefile(tool, exe) else None
    except (OSError, ValueError):
        return None


def _k3s_server_pid() -> "str | None":
    """The one process named ``k3s-server`` (measured: the server's name under
    systemd and started by hand); None when there is none, or more than one."""
    try:
        pids = [d for d in _PROC.iterdir() if d.name.isdigit()]
    except OSError:
        return None
    found = []
    for pid in pids:
        try:
            if (pid / "comm").read_text(errors="replace").strip() == _K3S_SERVER:
                found.append(pid.name)
        except OSError:
            continue
    return found[0] if len(found) == 1 else None


def _process_start(pid: str) -> "int | None":
    """When ``pid`` started, in seconds since the epoch, rounded down (its
    start in clock ticks after boot, plus the boot time)."""
    try:
        ticks = int((_PROC / pid / "stat").read_text().rsplit(")", 1)[1].split()[19])
        boot = next(int(x.split()[1]) for x in (_PROC / "stat").read_text().splitlines() if x.startswith("btime "))
    except (OSError, ValueError, IndexError, StopIteration):
        return None
    return boot + ticks // os.sysconf("SC_CLK_TCK")


def _k3s_apiserver_line(pid: str) -> "str | None":
    """The last ``Running kube-apiserver`` line this very process wrote to the
    journal: its PID and name, this boot, since it started — not a line an
    earlier k3s left."""
    start = _process_start(pid)
    if start is None:
        return None
    res = run_result("journalctl", f"_PID={pid}", f"_COMM={_K3S_SERVER}", "-b", f"--since=@{start}",
                     "-o", "cat", "--no-pager", "--grep", _K3S_APISERVER_LINE.strip(), timeout=_CTR_TIMEOUT)
    lines = [x for x in res.stdout.splitlines() if _K3S_APISERVER_LINE in x]
    return lines[-1] if lines else None


def _k3s_port() -> "int | None":
    """The port in the kubeconfig k3s writes for its own kubectl, when it names
    one local address; None otherwise (not read, nothing probed)."""
    try:
        text = _K3S_KUBECONFIG.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    ports = set(re.findall(r'^\s*server:\s*"?https://(?:127\.0\.0\.1|localhost|\[::1\]):(\d+)/?"?\s*$', text, re.M))
    servers = re.findall(r"^\s*server:", text, re.M)
    return int(ports.pop()) if len(ports) == 1 and len(servers) == 1 else None


def _broad_admin_bindings(raw: str) -> "list[str] | None":
    """The cluster-admin bindings naming a subject in ``_BROAD_SUBJECTS``.
    MicroK8s with RBAC ships one binding to cluster-admin, to Group
    system:masters (measured): not flagged."""
    try:
        items = json.loads(raw).get("items", [])
    except (ValueError, AttributeError):
        return None
    out = []
    for item in items:
        if (item.get("roleRef") or {}).get("name") != "cluster-admin":
            continue
        for subj in item.get("subjects") or []:
            if (subj.get("kind"), subj.get("name")) in _BROAD_SUBJECTS:
                out.append(f"{(item.get('metadata') or {}).get('name', '?')}: {subj.get('kind')}/{subj.get('name')}")
    return out


def _runtime_socket() -> "tuple[str, int, str, tuple[str, ...]] | None":
    """The first container-runtime socket present: its mode, group and the
    group's members (v0.28.0; measured on MicroK8s 1.35.6:
    /var/snap/microk8s/common/run/containerd.sock, 0660 root:microk8s).

    v0.31.3 — on a running k3s server, its own socket only (measured on
    Kali: /run/k3s/containerd/containerd.sock, 0660 root:root), as for its
    ``ctr``: the first socket present was Docker's containerd."""
    import grp
    import os
    import stat
    for path in (_K3S_CONTAINERD_SOCKET,) if _k3s_server_pid() else _RUNTIME_SOCKETS:
        try:
            st = os.stat(path)
        except OSError:
            continue
        if not stat.S_ISSOCK(st.st_mode):
            continue
        try:
            g = grp.getgrgid(st.st_gid)
            group, members = g.gr_name, tuple(g.gr_mem)
        except KeyError:
            group, members = str(st.st_gid), ()
        return path, stat.S_IMODE(st.st_mode), group, members
    return None


def _ctr_command() -> "tuple[str, ...] | None":
    """The ``ctr`` invocation that reaches this node's Kubernetes containers;
    None when a k3s server runs and its own ``ctr`` was not found.

    v0.31.3 — a running k3s server is asked through the ``ctr`` beside the
    binary it runs, on its own socket. Measured on Kali (k3s v1.37.2, Docker
    running): ``k3s`` was not in sudo's PATH, so BOB fell through to
    ``/usr/bin/ctr`` on ``/run/containerd/containerd.sock`` — Docker's
    containerd — listed 0 containers and called them read, while k3s's
    containerd ran 4 (coredns among them). Nothing else is that server's
    runtime: without its ``ctr``, nothing is read (and said)."""
    pid = _k3s_server_pid()
    if pid:
        ctr = _k3s_tool(pid, "ctr")
        return (ctr, "-a", _K3S_CONTAINERD_SOCKET, "-n", "k8s.io") if ctr else None
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


#: v0.31.0 — an API server, by process name: upstream ``kube-apiserver``,
#: MicroK8s' ``kubelite``, k3s.
_APISERVER_NAMES = frozenset({"kube-apiserver", "kubelite", "k3s", "k3s-server"})


def _loopback_listener(port: int) -> "list[str] | None":
    """v0.31.0 — the owners of the TCP sockets a connection to 127.0.0.1:*port*
    may reach: those bound to 127.0.0.1 itself when there are any, else those
    bound to every IPv4 address — ``0.0.0.0``, or ``*``, which is how ss shows
    a ``[::]`` socket that takes IPv4 too; ``[::]`` is one that does not
    (measured, 4 November 2026, `ssforms.txt`: 127.0.0.1 reached the first,
    was refused by the second). Every owner of every such socket counts: with
    SO_REUSEPORT several sockets share the port (measured: two lines; the
    kernel refused a uid 1000 socket joining a root one). [] when none
    listens; None when it could not be told whom they all belong to.

    ss gives each socket's address and inode (``-e``), not its owners (``-p``):
    it writes a process's name as it is, and a name is anyone's to choose —
    measured (`kspoof-comm.txt`), a uid 1000 server named ``kubelet",pid=1``
    showed as ``users:(("kubelet",pid=1",pid=10,fd=3))``, read as pid 1, run
    by root, and was asked. The holders are found in /proc/<pid>/fd instead;
    the cgroup path ss writes after the inode is not read.

    The probes below do not verify the server's certificate — the kubelet's
    own is self-signed — so whatever holds the port is answered: measured in a
    network namespace (4 November 2026, `kspoof.sh`), a python3 process on
    127.0.0.1:10250 with a self-signed certificate answering 401 made 0.30.0
    read "the kubelet requires authentication". Only a kubelet (or an API
    server) is now asked — a process of that name run by root: the name alone
    is anyone's to take (measured: the same server, its binary named kubelet,
    run by uid 1000, was asked). That the kubelet, kubelite, k3s and
    kube-apiserver show these names and run with every uid 0 is the
    expectation, measured in namespaces only, not yet on a MicroK8s or a k3s
    node. The name is a sign the process is recognised by, not a proof of
    which binary it runs; with the user it identifies the local process, it
    does not authenticate the TLS server, and a socket may change hands — a
    process end, its pid be taken again — between the check and the probe (a
    race BOB does not close)."""
    res = run_result("ss", "-Htlne", "sport", "=", f":{port}")
    if not res.ok:
        return None
    exact: "list[str | None]" = []
    wild: "list[str | None]" = []
    for line in (res.stdout or "").splitlines():
        parts = line.split()
        if not parts:
            continue
        if len(parts) < 5:
            return None
        addr = parts[3].rsplit(":", 1)[0].split("%", 1)[0]
        if addr in ("127.0.0.1", "[::ffff:127.0.0.1]"):
            bucket = exact
        elif addr in ("0.0.0.0", "*"):
            bucket = wild
        else:
            continue
        # Measured (iproute2 6.1.0, `review4.txt`): after the peer, "uid:N"
        # when the socket's user is not root, then "ino:N"; the inode is read
        # there and nowhere else — the cgroup path further on is a delegated
        # user's to name.
        extra = parts[5:]
        if extra and extra[0].startswith("uid:"):
            extra = extra[1:]
        ino = extra[0][4:] if extra and extra[0].startswith("ino:") else ""
        bucket.append(ino if ino.isdigit() and ino != "0" else None)
    inodes = exact or wild
    if not inodes:
        return []
    if None in inodes:
        return None
    holders = _socket_holders(set(inodes))
    if holders is None or any(not holders.get(i) for i in inodes):
        return None
    owners = [_owner(pid) for i in inodes for pid in holders[i]]
    return None if None in owners else owners


def _socket_holders(inodes: "set[str]") -> "dict[str, list[str]] | None":
    """The pids holding each socket inode (/proc/<pid>/fd), or None when a
    process's descriptors could not be read, or /proc is not the initial pid
    namespace's: a holder may be there, unseen."""
    if not _whole_proc():
        return None
    links = {f"socket:[{i}]": i for i in inodes}
    found: "dict[str, list[str]]" = {i: [] for i in inodes}
    try:
        pids = [d for d in os.listdir("/proc") if d.isdigit()]
    except OSError:
        return None
    for pid in pids:
        try:
            fds = os.listdir(f"/proc/{pid}/fd")
        except FileNotFoundError:
            continue
        except OSError:
            return None
        for fd in fds:
            try:
                inode = links.get(os.readlink(f"/proc/{pid}/fd/{fd}"))
            except FileNotFoundError:
                continue
            except OSError:
                return None
            if inode is not None and pid not in found[inode]:
                found[inode].append(pid)
    return found


#: the inode numbers of the initial pid and user namespaces, set once to
#: fixed values since Linux 3.8 (PROC_PID_INIT_INO 0xEFFFFFFC and
#: PROC_USER_INIT_INO 0xEFFFFFFD, assigned to init_pid_ns and init_user_ns;
#: part of the kernel's user-space interface, uapi/linux/nsfs.h, since 6.17).
#: Before 3.8 these two entries, ns/pid and ns/user, do not exist (namespaces(7)):
#: not read, not known. Measured on Linux
#: 7.0.0-34 and 7.0.0-42 (`review4.txt`, `k8sbob-microk8s.txt`).
_INIT_PID_NS = "pid:[4026531836]"
_INIT_USER_NS = "user:[4026531837]"


def _whole_proc() -> bool:
    """True when /proc lists BOB every process, and a process BOB may not read
    says so: it belongs to the initial pid namespace (its pid 1's), it does not
    hide processes (hidepid off or noaccess), and BOB may read any process
    (CAP_SYS_PTRACE). In another pid namespace — a container's — the
    processes outside it are not there (measured: 3 seen, 500 on the host).
    With hidepid=2 or 4, the processes BOB may not read are left out with no
    error (measured, `hidepid.txt`: without CAP_SYS_PTRACE, a root holder
    without it was seen, its uid 1000 child sharing the socket was not) —
    whatever denies the read, the capabilities or a security policy, which
    BOB cannot list; with hidepid off or noaccess every process was listed
    and a refused read was an error (`hidepid1.txt`, and on a real AppArmor
    node, a confined BOB, `lsmhide.txt`)."""
    try:
        if os.readlink("/proc/1/ns/pid") != _INIT_PID_NS:
            return False
    except OSError:
        return False
    if _proc_hidepid() not in ("off", "noaccess"):
        return False
    return _ptrace_capable()


def _proc_hidepid() -> str:
    """The hidepid level of what BOB reads at /proc: the filesystem that path
    reaches (its device, ``os.stat("/proc").st_dev``), found by that device in
    BOB's own /proc/self/mountinfo, its options read from the filesystem's own
    (super) options, which every mount of it shares. Not the last mount
    listed at /proc: the table follows the order the mounts were made, and one
    moved over /proc stays where it was (measured, `procstack.txt`: a procfs
    with hidepid=2 moved over one without it was the one seen and was listed
    first). "unknown" when either could not be read, no line has that device,
    one that has it cannot be read whole, none of them is mounted at /proc,
    the filesystem is not a procfs, names hidepid twice, or its lines
    disagree: a line of the device seen is never skipped."""
    try:
        dev = os.stat("/proc").st_dev
        lines = Path("/proc/self/mountinfo").read_text(errors="replace").splitlines()
    except OSError:
        return "unknown"
    want = f"{os.major(dev)}:{os.minor(dev)}"
    levels = set()
    at_proc = False
    for line in lines:
        head, sep, tail = line.partition(" - ")
        fields, fs = head.split(), tail.split()
        if len(fields) < 3 or fields[2] != want:
            continue
        if not sep or len(fields) < 5 or len(fs) < 3 or fs[0] != "proc":
            return "unknown"
        at_proc = at_proc or fields[4] == "/proc"
        opts = fs[2].split(",")
        if sum(o.startswith("hidepid=") for o in opts) > 1:
            return "unknown"
        levels.add(_hidepid_level(frozenset(opts)))
    return levels.pop() if len(levels) == 1 and at_proc else "unknown"


def _ptrace_capable() -> bool:
    """True when CAP_SYS_PTRACE (bit 19) is among BOB's effective
    capabilities (``CapEff:`` of /proc/self/status)."""
    try:
        status = Path("/proc/self/status").read_text(errors="replace")
    except OSError:
        return False
    m = re.search(r"^CapEff:\s+([0-9a-fA-F]+)\s*$", status, re.MULTILINE)
    return bool(m) and bool(int(m.group(1), 16) >> 19 & 1)


def _host_user_ids() -> bool:
    """True when the user ids /proc shows are the host's: BOB is in the
    initial user namespace. In another, uid 0 is that namespace's root only
    (measured: the benches' namespace root is uid 1000 outside it), the
    host's root shows as the overflow uid (``Uid: 65534 65534 65534 65534``),
    and a map that looks like the identity may be one to the parent only
    (measured, nested: ``0 0 1``)."""
    try:
        return os.readlink("/proc/self/ns/user") == _INIT_USER_NS
    except OSError:
        return False


def _owner(pid: str) -> "str | None":
    """The process's name (/proc/<pid>/comm) when every user id of it is root
    (real, effective, saved, filesystem: the ``Uid:`` line of
    /proc/<pid>/status); otherwise "name (uid N)" when the four are N, "name
    (uids R E S F)" when they differ — one alone could read "uid 0" for a
    process not run by root; "name (uid ?)" when they could not be read (the
    line missing or malformed, the process gone, BOB in a user namespace).
    None when the name could not be read."""
    try:
        name = Path(f"/proc/{pid}/comm").read_text(errors="replace").rstrip("\n")
    except OSError:
        return None
    if not _host_user_ids():
        return f"{name} (uid ?)"
    try:
        status = Path(f"/proc/{pid}/status").read_text(errors="replace")
    except OSError:
        return f"{name} (uid ?)"
    m = re.search(r"^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$", status, re.MULTILINE)
    if not m:
        return f"{name} (uid ?)"
    uids = m.groups()
    if uids == ("0", "0", "0", "0"):
        return name
    if len(set(uids)) == 1:
        return f"{name} (uid {uids[0]})"
    return f"{name} (uids {' '.join(uids)})"


def _deciding(owners: "list[str] | None", names: frozenset) -> "str | None":
    """v0.31.0 — the owner that decides whether a port is asked: None when not
    known, "" when none listens, the first one not among *names* (run by root),
    else the first: every owner must be one."""
    if owners is None:
        return None
    if not owners:
        return ""
    return next((o for o in owners if o not in names), owners[0])


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
    # v0.31.0 — the port held by another process: its answer says nothing
    # about the kubelet, and none was asked (`_loopback_listener`).
    listener = snapshot.kubelet_listener
    if listener not in _KUBELET_NAMES and listener != "":
        if listener is None:
            result.info(message=_t("kubernetes.kubelet_listener_unknown"), key="kubernetes.kubelet_listener_unknown")
        elif listener.endswith(" (uid ?)"):
            result.info(message=_t("kubernetes.kubelet_listener_unverified", process=listener[:-len(" (uid ?)")]),
                        key="kubernetes.kubelet_listener_unverified",
                        template_vars={"process": listener[:-len(" (uid ?)")]})
        else:
            result.info(message=_t("kubernetes.kubelet_listener_foreign", process=listener),
                        key="kubernetes.kubelet_listener_foreign", template_vars={"process": listener})
    elif run == RUN_AUTHORISED:
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
    _check_apiserver(snapshot, result, _t)
    _check_runtime_socket(snapshot, result, _t)
    return result


def _check_apiserver(snapshot: "KubernetesSnapshot", result: CheckResult, _t) -> None:
    """v0.28.0 — the cluster beyond the node, as far as this node reads it."""
    if snapshot.authorization_modes is None:
        # v0.29.0 — not read is said, not left silent: BOB reads the API
        # server where MicroK8s keeps its arguments; on k3s (measured: its
        # process is `k3s server`, a kubelet name BOB knows) and kubeadm
        # nothing was said, and the score read as if the cluster were clean.
        # v0.31.3 — a k3s server under systemd is read from its journal
        # (`_read_k3s_apiserver`); one whose start line is not there is not.
        result.info(message=_t("kubernetes.apiserver_unread"),
                    detail=_t("kubernetes.apiserver_unread_detail"),
                    key="kubernetes.apiserver_unread")
        return
    anon = snapshot.apiserver_anonymous_status
    owner = snapshot.apiserver_listener
    if owner not in _APISERVER_NAMES and owner != "":
        if owner is None:
            result.info(message=_t("kubernetes.apiserver_listener_unknown", port=snapshot.apiserver_port),
                        key="kubernetes.apiserver_listener_unknown", template_vars={"port": snapshot.apiserver_port})
        elif owner.endswith(" (uid ?)"):
            result.info(message=_t("kubernetes.apiserver_listener_unverified", port=snapshot.apiserver_port,
                                   process=owner[:-len(" (uid ?)")]),
                        key="kubernetes.apiserver_listener_unverified",
                        template_vars={"port": snapshot.apiserver_port, "process": owner[:-len(" (uid ?)")]})
        else:
            result.info(message=_t("kubernetes.apiserver_listener_foreign", port=snapshot.apiserver_port,
                                   process=owner),
                        key="kubernetes.apiserver_listener_foreign",
                        template_vars={"port": snapshot.apiserver_port, "process": owner})
    elif anon is not None and 200 <= anon < 300:
        # After review: a 2xx here establishes that anonymous requests may list
        # namespaces, not what else they may do — WARN −1, as the kubelet's
        # anonymous read (0.25.0). v0.31.3 — not under AlwaysAllow: the API
        # server then turns anonymous authentication off (measured on k3s
        # v1.37.2: "AnonymousAuth is not allowed with the AlwaysAllow
        # authorizer. Resetting AnonymousAuth to false.", and a 401; MicroK8s
        # 1.35.6 answered 401 there too).
        result.warn_with_deduction(
            key="kubernetes.apiserver_anonymous",
            message=_t("kubernetes.apiserver_anonymous", port=snapshot.apiserver_port),
            reason=_t("kubernetes.apiserver_anonymous_reason"),
            points=1, nature="action",
        )
    elif anon in (401, 403):
        result.ok(message=_t("kubernetes.apiserver_anonymous_refused", status=anon,
                             port=snapshot.apiserver_port),
                  key="kubernetes.apiserver_anonymous_refused")
    else:
        result.info(message=_t("kubernetes.apiserver_anonymous_unprobed", answer=_answer(anon)),
                    key="kubernetes.apiserver_anonymous_unprobed")
    if "AlwaysAllow" in snapshot.authorization_modes:
        result.alert_with_deduction(
            key="kubernetes.apiserver_always_allow",
            message=_t("kubernetes.apiserver_always_allow"),
            reason=_t("kubernetes.apiserver_always_allow_reason"),
            detail=_t("kubernetes.apiserver_always_allow_detail"),
            points=2, nature="action",
        )
    elif "RBAC" in snapshot.authorization_modes:
        if snapshot.broad_admin_bindings:
            result.alert_with_deduction(
                key="kubernetes.cluster_admin_broad",
                message=_t("kubernetes.cluster_admin_broad", bindings=", ".join(snapshot.broad_admin_bindings)),
                reason=_t("kubernetes.cluster_admin_broad_reason"),
                points=3, nature="action",
            )
        elif snapshot.broad_admin_bindings is None:
            result.info(message=_t("kubernetes.cluster_admin_unread"), key="kubernetes.cluster_admin_unread")
        else:
            result.ok(message=_t("kubernetes.cluster_admin_ok"), key="kubernetes.cluster_admin_ok")
    else:
        result.info(message=_t("kubernetes.apiserver_authz_unread",
                               modes=",".join(snapshot.authorization_modes) or "—"),
                    key="kubernetes.apiserver_authz_unread")


def _check_runtime_socket(snapshot: "KubernetesSnapshot", result: CheckResult, _t) -> None:
    sock = snapshot.runtime_socket
    if sock is None:
        return
    path, mode, group, members = sock
    if mode & 0o002:
        result.alert_with_deduction(
            key="kubernetes.runtime_socket_open",
            message=_t("kubernetes.runtime_socket_open", path=path, mode=f"{mode:04o}"),
            reason=_t("kubernetes.runtime_socket_open_reason"),
            points=3, nature="action",
        )
    elif mode & 0o020:
        result.info(message=_t("kubernetes.runtime_socket_group", path=path, mode=f"{mode:04o}", group=group,
                               members=", ".join(members) or _t("kubernetes.runtime_socket_no_member")),
                    key="kubernetes.runtime_socket_group")
    else:
        result.ok(message=_t("kubernetes.runtime_socket_ok", path=path, mode=f"{mode:04o}"),
                  key="kubernetes.runtime_socket_ok")
