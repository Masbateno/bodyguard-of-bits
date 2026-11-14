"""v0.36.0 — rootless containers examined from their OCI configuration.

0.33.0 (podman) and 0.35.0 (rootless dockerd) counted rootless containers and
left the score an upper bound: not examined. Measured on two real hosts
(a10360, 14 November 2026), nothing run as the user:

| host, runtime                                | where root reads config.json                         | owner |
|----------------------------------------------|------------------------------------------------------|-------|
| Linux Mint 22.3, docker 29.1.3 + rootlesskit | /proc/<shim>/cwd/config.json (bundle path absent from root's mount namespace) | user |
| Fedora 44, podman 5.8.1                      | conmon -b <bundle> (in the user's home), through /proc/<conmon>/root | user |

| shape (both hosts)            | config.json                         | measured on the host                                   |
|-------------------------------|-------------------------------------|--------------------------------------------------------|
| plain                         | 14 caps (docker) / 11 (podman)      | runs as the user (uid 1001), runtime's user namespace  |
| --privileged                  | 41 caps = cap_last_cap + 1          | /dev/sda, /dev/mem refused; kernel sysctl refused      |
| --network host                | no network namespace                | docker: rootlesskit's net (tap0); podman: the host's   |
| --pid host                    | no pid namespace, /proc -> /proc    | the host's PID namespace                               |
| -v /:/host                    | bind / -> /host                     | /host/etc/shadow refused                               |

Every shape stays within the user's rights: INFO, no point, no upper bound.
"""

from __future__ import annotations

import json
import os

import pytest

from bob.checks import _rootless_oci as R
from bob.checks import docker_audit as D
from bob.visibility import VISIBILITY_KEYS

_INTERNAL = [
    {"type": "bind", "source": "/run/user/1001/containers/x/userdata/resolv.conf", "destination": "/etc/resolv.conf", "options": ["bind"]},
    {"type": "bind", "source": "/run/user/1001/containers/x/userdata/hosts", "destination": "/etc/hosts", "options": ["bind"]},
    {"source": "/home/u/.local/share/containers/x/userdata/shm", "destination": "/dev/shm", "options": ["bind"]},
    {"type": "proc", "source": "proc", "destination": "/proc"},
]
_ALL_NS = ["pid", "network", "ipc", "uts", "mount", "cgroup"]
_CAPS14 = [f"CAP_X{i}" for i in range(14)]
_CAPS41 = [f"CAP_X{i}" for i in range(40)] + ["CAP_SYS_ADMIN"]


def _cfg(caps=_CAPS14, ns=_ALL_NS, extra=()):
    return {"process": {"capabilities": {"bounding": list(caps)}},
            "linux": {"namespaces": [{"type": n} for n in ns]},
            "mounts": _INTERNAL + list(extra)}


SHAPES = {
    "plain": (_cfg(), dict(privileged=False, sys_admin=False, host_net=False, host_pid=False, host_paths=())),
    "privileged": (_cfg(caps=_CAPS41, extra=[{"type": "bind", "source": "/dev/sda", "destination": "/dev/sda"}]),
                   dict(privileged=True, sys_admin=False, host_paths=())),
    "hostnet-podman": (_cfg(ns=["pid", "ipc", "uts", "mount", "cgroup"],
                            extra=[{"type": "bind", "source": "/sys", "destination": "/sys", "options": ["rbind"]}]),
                       dict(host_net=True, host_paths=())),
    "rootmount": (_cfg(extra=[{"type": "bind", "source": "/", "destination": "/host", "options": ["rbind", "ro"]}]),
                  dict(host_paths=("/ -> /host",))),
    "capadd-pidhost": (_cfg(caps=_CAPS14 + ["CAP_SYS_ADMIN"], ns=["network", "ipc", "uts", "mount", "cgroup"],
                            extra=[{"type": "bind", "source": "/proc", "destination": "/proc", "options": ["rbind"]}]),
                       dict(sys_admin=True, host_pid=True, host_paths=())),
    "socket": (_cfg(extra=[{"type": "bind", "source": "/run/user/1001/docker.sock", "destination": "/var/run/docker.sock"}]),
               dict(host_paths=("/run/user/1001/docker.sock -> /var/run/docker.sock",))),
}


@pytest.mark.parametrize("name", SHAPES)
def test_each_measured_shape(name):
    cfg, want = SHAPES[name]
    got = R.shape(cfg, cap_total=41)
    for k, v in want.items():
        assert got[k] == v, (name, k, got)


def test_privileged_needs_the_kernels_count():
    assert R.shape(_cfg(caps=_CAPS41), cap_total=None)["privileged"] is False
    assert R.shape(_cfg(caps=_CAPS41), cap_total=42)["privileged"] is False


def test_a_malformed_config_is_shapeless_not_a_crash():
    for cfg in ({}, {"process": "x", "linux": [], "mounts": "y"}, {"mounts": [1, None, {"type": "bind"}]}):
        got = R.shape(cfg, cap_total=41)
        assert got["host_paths"] == () and got["privileged"] is False


# --- reading the file safely ---------------------------------------------------

def test_a_regular_file_of_the_user_is_read(tmp_path):
    f = tmp_path / "config.json"
    f.write_text(json.dumps(_cfg()))
    assert R.read_config(f, os.getuid())["linux"]


def test_another_owner_is_refused(tmp_path):
    f = tmp_path / "config.json"
    f.write_text(json.dumps(_cfg()))
    assert R.read_config(f, os.getuid() + 1) is None


def test_a_final_symlink_is_refused(tmp_path):
    real = tmp_path / "real.json"
    real.write_text(json.dumps(_cfg()))
    link = tmp_path / "config.json"
    link.symlink_to(real)
    assert R.read_config(link, os.getuid()) is None


def test_a_fifo_is_refused_without_blocking(tmp_path):
    fifo = tmp_path / "config.json"
    os.mkfifo(fifo)
    assert R.read_config(fifo, os.getuid()) is None


def test_too_big_or_not_an_object_is_refused(tmp_path):
    f = tmp_path / "config.json"
    f.write_text("[" + "1," * (R._MAX_CONFIG // 2) + "1]")
    assert R.read_config(f, os.getuid()) is None
    f.write_text("[1, 2]")
    assert R.read_config(f, os.getuid()) is None
    f.write_text("{not json")
    assert R.read_config(f, os.getuid()) is None


# --- finding them in /proc -----------------------------------------------------

def _proc(tmp_path, pid, argv, uid, cwd=None, root=None):
    d = tmp_path / "proc" / str(pid)
    d.mkdir(parents=True)
    (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
    (d / "status").write_text(f"Name:\tx\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
    if cwd is not None:
        os.symlink(cwd, d / "cwd")
    if root is not None:
        os.symlink(root, d / "root")


def test_rootless_containers_from_proc(tmp_path, monkeypatch):
    me = os.getuid()
    shim_bundle = tmp_path / "bundle-docker"
    shim_bundle.mkdir()
    (shim_bundle / "config.json").write_text(json.dumps(SHAPES["rootmount"][0]))
    pod_bundle = tmp_path / "home" / "userdata"
    pod_bundle.mkdir(parents=True)
    (pod_bundle / "config.json").write_text(json.dumps(SHAPES["hostnet-podman"][0]))
    _proc(tmp_path, 10, ["/usr/bin/containerd-shim-runc-v2", "-namespace", "moby", "-id", "56c06c248a4acdef", "-address", "x"],
          me, cwd=shim_bundle)
    _proc(tmp_path, 11, ["/usr/bin/conmon", "--api-version", "1", "-c", "4000add725ca", "-b", str(pod_bundle), "-n", "pd-hostnet"],
          me, root="/")
    _proc(tmp_path, 12, ["/usr/bin/conmon", "-c", "aaaa", "-b", str(tmp_path / "gone"), "-n", "pd-gone"], me, root="/")
    _proc(tmp_path, 13, ["/usr/bin/containerd-shim-runc-v2", "-namespace", "moby", "-id", "rootshim"], 0, cwd=shim_bundle)
    _proc(tmp_path, 14, ["/usr/bin/containerd-shim-runc-v2", "-namespace", "k8s.io", "-id", "pod"], me, cwd=shim_bundle)
    monkeypatch.setattr(R, "_PROC", tmp_path / "proc")
    monkeypatch.setattr(R, "_cap_total", lambda: 41)
    got = {c.name: c for c in R.rootless_containers()}
    assert set(got) == {"56c06c248a4a", "pd-hostnet", "pd-gone"}
    assert got["56c06c248a4a"].runtime == "docker" and got["56c06c248a4a"].host_paths == ("/ -> /host",)
    assert got["pd-hostnet"].runtime == "podman" and got["pd-hostnet"].host_net and got["pd-hostnet"].read
    assert got["pd-gone"].read is False


# --- what the check says -------------------------------------------------------

def _t(key, **kw):
    from bob import i18n
    i18n.init("en")
    return i18n.t(key, **kw)


def _c(name, runtime="podman", user="alice", read=True, **kw):
    return R.RootlessContainer(user=user, runtime=runtime, name=name, read=read, **kw)


def _findings(**kw):
    snap = D.DockerAuditSnapshot(**kw)
    return {f.key: f for f in D.check_docker_audit(snap, t=_t).findings}


def test_examined_containers_are_said_and_no_longer_a_ceiling():
    f = _findings(rootless_containers={"alice": 2}, rootless_oci=[_c("a"), _c("b")])
    assert "docker_hardening.rootless_examined" in f
    assert "alice (podman, 2)" in f["docker_hardening.rootless_examined"].message
    assert "docker_hardening.rootless_unexamined" not in f
    assert "docker_hardening.rootless_examined" not in VISIBILITY_KEYS
    assert "docker_hardening.rootless_shapes" not in VISIBILITY_KEYS


def test_an_unread_container_keeps_the_ceiling_for_itself():
    f = _findings(rootless_containers={"alice": 2}, rootless_oci=[_c("a"), _c("b", read=False)])
    assert "alice (1)" in f["docker_hardening.rootless_unexamined"].message
    assert "docker_hardening.rootless_examined" in f


def test_a_rootless_dockerd_read_in_full_is_examined():
    f = _findings(rootless_dockerd={"bob": 2}, rootless_oci=[_c("x", runtime="docker", user="bob"),
                                                            _c("y", runtime="docker", user="bob")])
    assert "docker_hardening.rootless_dockerd" not in f
    assert "bob (docker, 2)" in f["docker_hardening.rootless_examined"].message


def test_a_rootless_dockerd_with_an_unread_container_stays_unexamined():
    f = _findings(rootless_dockerd={"bob": 2}, rootless_oci=[_c("x", runtime="docker", user="bob")])
    assert "bob (1)" in f["docker_hardening.rootless_dockerd"].message


def test_an_idle_rootless_dockerd_is_said_without_a_ceiling():
    f = _findings(rootless_dockerd={"bob": 0})
    assert "docker_hardening.rootless_dockerd" not in f
    assert "bob (docker, 0)" in f["docker_hardening.rootless_examined"].message


def test_wider_shapes_are_named_without_a_point():
    oci = [_c("pd-priv", privileged=True), _c("rl-hostnet", runtime="docker", user="bob", host_net=True),
           _c("pd-hostnet", host_net=True), _c("rl-root", runtime="docker", user="bob", host_paths=("/ -> /host",)),
           _c("pd-cap", sys_admin=True, host_pid=True), _c("plain")]
    snap = D.DockerAuditSnapshot(rootless_containers={"alice": 4}, rootless_dockerd={"bob": 2}, rootless_oci=oci)
    r = D.check_docker_audit(snap, t=_t)
    f = next(x for x in r.findings if x.key == "docker_hardening.rootless_shapes")
    for part in ("pd-priv (alice, podman: privileged in its user namespace)",
                 "rl-hostnet (bob, docker: rootlesskit's network (--network host))",
                 "pd-hostnet (alice, podman: the host's network)",
                 "rl-root (bob, docker: host paths: / -> /host)",
                 "pd-cap (alice, podman: CAP_SYS_ADMIN in its user namespace; the host's PID namespace)"):
        assert part in f.message, part
    assert "plain" not in f.message
    assert sum(d.points for d in r.deductions) == 0
    assert not f.cmd


def test_from_system_reads_them_only_when_rootless_containers_run(monkeypatch):
    calls = []
    monkeypatch.setattr(D, "_rootless_oci", lambda: calls.append(1) or [_c("a")])
    monkeypatch.setattr(D, "_command_exists", lambda c: False)
    monkeypatch.setattr(D, "_docker_group", lambda: ([], False, [], []))
    monkeypatch.setattr(D, "_group_socket", lambda *a: ([], False, [], []))
    monkeypatch.setattr(D, "containerd_elsewhere", lambda: {})
    monkeypatch.setattr(D, "rootless_dockerd", lambda: {})
    monkeypatch.setattr(D, "_rootless_podman", lambda: {})
    assert D.DockerAuditSnapshot.from_system().rootless_oci == [] and calls == []
    monkeypatch.setattr(D, "_rootless_podman", lambda: {"alice": 1})
    assert len(D.DockerAuditSnapshot.from_system().rootless_oci) == 1


# --- a podman exec session is not a container ----------------------------------

_EXEC = ["/usr/bin/conmon", "--api-version", "1", "-c", "48c81c6e6645", "-b", "/x/userdata/4cb8", "-n", "pd-hostnet",
         "-e", "--exec-attach", "--exec-process-spec", "/x/userdata/4cb8/exec-process-1", "--exec"]


def test_an_exec_conmon_is_not_a_container(tmp_path, monkeypatch):
    _proc(tmp_path, 20, _EXEC, os.getuid(), root="/")
    monkeypatch.setattr(R, "_PROC", tmp_path / "proc")
    assert R.rootless_containers() == []


def test_an_exec_conmon_is_not_counted_by_the_podman_count(tmp_path, monkeypatch):
    for pid, argv in ((30, _EXEC), (31, ["/usr/bin/conmon", "-c", "4000add725ca", "-b", "/y", "-n", "pd-plain"])):
        d = tmp_path / "proc" / str(pid)
        d.mkdir(parents=True)
        (d / "comm").write_text("conmon\n")
        (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
        (d / "status").write_text("Uid:\t1001\t1001\t1001\t1001\n")
    monkeypatch.setattr(D, "_PROC", tmp_path / "proc")
    assert sum(D._rootless_podman().values()) == 1
